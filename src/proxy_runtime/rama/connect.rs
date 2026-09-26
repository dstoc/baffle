//! CONNECT admission, authority parsing, and explicit tunnel forwarding.

use std::{io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    ca::ManagedCa,
    config::RuleMode,
    policy::{Destination, SessionPolicy},
    secrets::ResolvedSecrets,
    telemetry::Metrics,
};

use super::{ProxyRuntimeError, tls};

const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;

pub(super) async fn handle_client<S>(
    mut client: S,
    policy: Arc<SessionPolicy>,
    secrets: Arc<ResolvedSecrets>,
    ca: Arc<ManagedCa>,
    metrics: Arc<Metrics>,
    io_timeout: Duration,
) -> Result<(), ProxyRuntimeError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let parsed = match tokio::time::timeout(io_timeout, read_connect_request(&mut client)).await {
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
        ca,
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
    copy_bidirectional_with_timeout(&mut client, &mut upstream, io_timeout)
        .await
        .map(|_| ())
        .map_err(|error| ProxyRuntimeError::Run(error.to_string()))
}

async fn copy_bidirectional_with_timeout<A, B>(
    left: &mut A,
    right: &mut B,
    io_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (left_reader, left_writer) = tokio::io::split(left);
    let (right_reader, right_writer) = tokio::io::split(right);
    tokio::try_join!(
        copy_with_timeout(left_reader, right_writer, io_timeout),
        copy_with_timeout(right_reader, left_writer, io_timeout)
    )
}

async fn copy_with_timeout<R, W>(
    mut reader: R,
    mut writer: W,
    io_timeout: Duration,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0; 8 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = tokio::time::timeout(io_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy read timed out"))??;
        if read == 0 {
            tokio::time::timeout(io_timeout, writer.shutdown())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "proxy write shutdown timed out")
                })??;
            return Ok(copied);
        }
        tokio::time::timeout(io_timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy write timed out"))??;
        copied = copied.saturating_add(read as u64);
    }
}

struct ParsedConnect {
    authority: String,
    host: Option<String>,
    has_body: bool,
}

async fn read_connect_request<S>(stream: &mut S) -> io::Result<ParsedConnect>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    while bytes.len() < MAX_CONNECT_HEADER_BYTES {
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !bytes.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT headers too large",
        ));
    }
    let headers = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "CONNECT headers are not ASCII"))?;
    if !headers.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT headers are not ASCII",
        ));
    }
    let mut lines = headers[..headers.len() - 4].split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut parts = request_line.split_ascii_whitespace();
    if parts.next() != Some("CONNECT") || parts.next().is_none() || parts.next() != Some("HTTP/1.1")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "only HTTP/1.1 CONNECT is supported",
        ));
    }
    let authority = request_line
        .split_ascii_whitespace()
        .nth(1)
        .expect("CONNECT request line was checked")
        .to_owned();
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
    })
}
