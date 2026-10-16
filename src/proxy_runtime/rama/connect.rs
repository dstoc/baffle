//! CONNECT admission, authority parsing, and explicit tunnel forwarding.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

use crate::{
    config::RuleMode,
    policy::{Destination, SessionPolicy},
    proxy_runtime::TestUpstreamTrust,
    secrets::ResolvedSecrets,
    telemetry::Metrics,
};

use super::{ProxyRuntimeError, tls};

const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;

pub(super) async fn handle_client<S>(
    mut client: S,
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
    tls_relay: Arc<tls::CachedRelay>,
    test_upstream_trust: TestUpstreamTrust,
    metrics: Arc<Metrics>,
    io_timeout: Duration,
) -> Result<(), ProxyRuntimeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut parsed = match tokio::time::timeout(io_timeout, read_connect_request(&mut client)).await
    {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(error)) => {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Err(ProxyRuntimeError::Run(error.to_string()));
        }
        Err(_) => {
            let _ = client
                .write_all(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    let mut client = BufferedConnectIo::new(client, std::mem::take(&mut parsed.read_ahead));

    let host_headers = parsed.host.as_deref().into_iter().collect::<Vec<_>>();
    let (mode, destination) =
        match policy.authorize_connect_authority(&parsed.authority, &host_headers) {
            Ok(authorized) => authorized,
            Err(_) => {
                metrics.denied_request();
                let _ = client
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    .await;
                return Ok(());
            }
        };
    if parsed.has_body {
        metrics.denied_request();
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }

    if mode == RuleMode::Tunnel {
        return handle_tunnel(client, destination, io_timeout, &metrics).await;
    }

    tls::intercept_client(
        client,
        policy,
        secrets,
        tls_relay,
        test_upstream_trust,
        parsed.authority,
        destination,
        metrics,
        io_timeout,
    )
    .await
}
async fn handle_tunnel<S>(
    mut client: S,
    destination: Destination,
    io_timeout: Duration,
    metrics: &Metrics,
) -> Result<(), ProxyRuntimeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let upstream = match tokio::time::timeout(
        io_timeout,
        TcpStream::connect((destination.host.as_str(), destination.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            metrics.upstream_failure();
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Err(ProxyRuntimeError::Run(error.to_string()));
        }
        Err(_) => {
            metrics.upstream_failure();
            let _ = client
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))?;
    let mut upstream = upstream;
    copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))
}

async fn copy_bidirectional<A, B>(left: &mut A, right: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (left_reader, left_writer) = tokio::io::split(left);
    let (right_reader, right_writer) = tokio::io::split(right);
    tokio::try_join!(
        copy_until_eof(left_reader, right_writer),
        copy_until_eof(right_reader, left_writer)
    )
}

async fn copy_until_eof<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0; 8 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buffer[..read]).await?;
        copied = copied.saturating_add(read as u64);
    }
}

struct ParsedConnect {
    authority: String,
    host: Option<String>,
    has_body: bool,
    read_ahead: Vec<u8>,
}

async fn read_connect_request<S>(stream: &mut S) -> io::Result<ParsedConnect>
where
    S: AsyncRead + Unpin,
{
    const READ_BUFFER_BYTES: usize = 4096;

    let mut bytes = Vec::with_capacity(1024);
    let mut read_buffer = [0; READ_BUFFER_BYTES];
    let header_end = loop {
        let remaining = MAX_CONNECT_HEADER_BYTES
            .saturating_add(read_buffer.len())
            .saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT headers too large",
            ));
        }

        let read_size = remaining.min(READ_BUFFER_BYTES);
        let read = stream.read(&mut read_buffer[..read_size]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "early EOF while reading CONNECT headers",
            ));
        }
        bytes.extend_from_slice(&read_buffer[..read]);

        match bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            Some(position) if position + 4 <= MAX_CONNECT_HEADER_BYTES => break position + 4,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CONNECT headers too large",
                ));
            }
            None if bytes.len() >= MAX_CONNECT_HEADER_BYTES => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "CONNECT headers too large",
                ));
            }
            None => {}
        }
    };
    let read_ahead = bytes.split_off(header_end);
    let headers = match std::str::from_utf8(&bytes) {
        Ok(headers) if headers.is_ascii() => headers,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT headers are not ASCII",
            ));
        }
    };
    let mut lines = headers[..headers.len() - 4].split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_ascii_whitespace();
    let (Some("CONNECT"), Some(authority), Some("HTTP/1.1"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only HTTP/1.1 CONNECT is supported",
        ));
    };
    let authority = authority.to_owned();
    let mut host = None;
    let mut has_body = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid header"))?;
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value.trim().to_owned()).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Host header",
                ));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_body = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if value.trim() != "0" {
                has_body = true;
            }
        } else if name.eq_ignore_ascii_case("expect") {
            has_body = true;
        }
    }
    Ok(ParsedConnect {
        authority,
        host,
        has_body,
        read_ahead,
    })
}

struct BufferedConnectIo<S> {
    inner: S,
    read_ahead: Vec<u8>,
    read_ahead_offset: usize,
}

impl<S> BufferedConnectIo<S> {
    fn new(inner: S, read_ahead: Vec<u8>) -> Self {
        Self {
            inner,
            read_ahead,
            read_ahead_offset: 0,
        }
    }
}

impl<S> AsyncRead for BufferedConnectIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_ahead_offset < this.read_ahead.len() {
            let remaining = &this.read_ahead[this.read_ahead_offset..];
            let read = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..read]);
            this.read_ahead_offset += read;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}

impl<S> AsyncWrite for BufferedConnectIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    struct TestReader {
        bytes: Vec<u8>,
        offset: usize,
        max_read: usize,
        read_calls: usize,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>, max_read: usize) -> Self {
            Self {
                bytes,
                offset: 0,
                max_read,
                read_calls: 0,
            }
        }
    }

    impl AsyncRead for TestReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.read_calls += 1;
            let remaining = &this.bytes[this.offset..];
            let read = remaining.len().min(this.max_read).min(buffer.remaining());
            buffer.put_slice(&remaining[..read]);
            this.offset += read;
            Poll::Ready(Ok(()))
        }
    }

    async fn parse(bytes: Vec<u8>, max_read: usize) -> io::Result<ParsedConnect> {
        read_connect_request(&mut TestReader::new(bytes, max_read)).await
    }

    #[tokio::test]
    async fn parses_a_complete_request() {
        let mut reader = TestReader::new(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec(),
            4096,
        );
        let parsed = read_connect_request(&mut reader).await.unwrap();

        assert_eq!(parsed.authority, "example.com:443");
        assert_eq!(parsed.host.as_deref(), Some("example.com:443"));
        assert!(!parsed.has_body);
        assert!(parsed.read_ahead.is_empty());
        assert_eq!(reader.read_calls, 1);
    }

    #[tokio::test]
    async fn parses_a_fragmented_request() {
        let parsed = parse(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec(),
            3,
        )
        .await
        .unwrap();

        assert_eq!(parsed.authority, "example.com:443");
    }

    #[tokio::test]
    async fn rejects_extra_request_line_tokens() {
        let result = parse(
            b"CONNECT example.com:443 HTTP/1.1 extra\r\nHost: example.com:443\r\n\r\n".to_vec(),
            4096,
        )
        .await;

        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn rejects_malformed_versions() {
        let result = parse(
            b"CONNECT example.com:443 HTTP/2\r\nHost: example.com:443\r\n\r\n".to_vec(),
            4096,
        )
        .await;

        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn rejects_non_ascii_and_invalid_utf8_headers_with_the_same_error() {
        for value in [vec![0xc3, 0xa9], vec![0xff]] {
            let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
            request.extend_from_slice(&value);
            request.extend_from_slice(b"\r\n\r\n");

            let error = parse(request, 4096)
                .await
                .err()
                .expect("non-ASCII headers must fail");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "CONNECT headers are not ASCII");
        }
    }

    #[tokio::test]
    async fn accepts_headers_at_the_limit_and_rejects_larger_headers() {
        fn request_with_header_size(size: usize) -> Vec<u8> {
            let prefix = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX: ";
            let ending = b"\r\n\r\n";
            assert!(size >= prefix.len() + ending.len());
            let mut request = prefix.to_vec();
            request.extend(std::iter::repeat_n(
                b'a',
                size - prefix.len() - ending.len(),
            ));
            request.extend_from_slice(ending);
            request
        }

        let parsed = parse(request_with_header_size(MAX_CONNECT_HEADER_BYTES), 4096)
            .await
            .unwrap();
        assert_eq!(parsed.authority, "example.com:443");

        let result = parse(request_with_header_size(MAX_CONNECT_HEADER_BYTES + 1), 4096).await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn preserves_bytes_read_after_the_header_terminator() {
        let mut bytes =
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec();
        bytes.extend_from_slice(b"TLS payload");
        let parsed = read_connect_request(&mut TestReader::new(bytes, usize::MAX))
            .await
            .unwrap();
        let mut stream =
            BufferedConnectIo::new(TestReader::new(Vec::new(), usize::MAX), parsed.read_ahead);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();

        assert_eq!(payload, b"TLS payload");
    }
}
