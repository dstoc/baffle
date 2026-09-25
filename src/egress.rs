use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use hudsucker::{TcpConnector, hyper_util::client::legacy::connect::dns::Name};
use tower_service::Service;

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'static>>;

trait HostResolver: Send + Sync + 'static {
    fn lookup(&self, host: String) -> LookupFuture;
}

#[derive(Clone)]
pub(crate) struct EgressConnector {
    resolver: Arc<dyn HostResolver>,
}

impl EgressConnector {
    pub(crate) fn system() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
        }
    }

    async fn resolve_addresses(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses = match host.parse::<IpAddr>() {
            Ok(address) => vec![address],
            Err(_) => self.resolver.lookup(host.to_owned()).await?,
        };

        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(is_public_destination)
            .map(|address| SocketAddr::new(address, port))
            .collect();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DNS returned no permitted destination addresses",
            ));
        }
        Ok(addresses)
    }
}

impl Service<Name> for EgressConnector {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send + 'static>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let connector = self.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            connector
                .resolve_addresses(&host, 0)
                .await
                .map(Vec::into_iter)
        })
    }
}

impl TcpConnector for EgressConnector {
    fn connect(
        &self,
        authority: hudsucker::hyper::http::uri::Authority,
    ) -> Pin<Box<dyn Future<Output = io::Result<tokio::net::TcpStream>> + Send + 'static>> {
        let connector = self.clone();
        Box::pin(async move {
            let port = authority.port_u16().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "destination port is required")
            })?;
            let addresses = connector.resolve_addresses(authority.host(), port).await?;
            let mut last_error = None;
            for address in addresses {
                match tokio::net::TcpStream::connect(address).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "no destination address")
            }))
        })
    }
}

struct SystemResolver;

impl HostResolver for SystemResolver {
    fn lookup(&self, host: String) -> LookupFuture {
        Box::pin(async move {
            tokio::net::lookup_host((host, 0))
                .await
                .map(|addresses| addresses.map(|address| address.ip()).collect())
        })
    }
}

fn is_public_destination(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(*address),
        IpAddr::V6(address) => is_public_ipv6(*address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_private()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
        && a != 0
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 192 && b == 0 && c == 2)
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
        && a < 240
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }

    let segments = address.segments();
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_unique_local()
        && !address.is_unicast_link_local()
        && !address.is_multicast()
        // Global unicast space. Exclude special, documentation, and 6to4 ranges.
        && (0x2000..=0x3fff).contains(&segments[0])
        && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x2002)
        && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    struct QueueResolver(Mutex<VecDeque<Vec<IpAddr>>>);

    impl HostResolver for QueueResolver {
        fn lookup(&self, _host: String) -> LookupFuture {
            let addresses = self.0.lock().expect("resolver queue lock").pop_front();
            Box::pin(async move {
                addresses
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no mock DNS response"))
            })
        }
    }

    fn mock_connector(responses: Vec<Vec<IpAddr>>) -> EgressConnector {
        EgressConnector {
            resolver: Arc::new(QueueResolver(Mutex::new(responses.into()))),
        }
    }

    #[test]
    fn filters_prohibited_ipv4_and_ipv6_destinations() {
        let cases = [
            ("8.8.8.8", true),
            ("1.1.1.1", true),
            ("10.0.0.1", false),
            ("172.16.0.1", false),
            ("192.168.1.1", false),
            ("127.0.0.1", false),
            ("169.254.169.254", false),
            ("100.64.0.1", false),
            ("192.0.2.1", false),
            ("198.18.0.1", false),
            ("224.0.0.1", false),
            ("240.0.0.1", false),
            ("2606:4700:4700::1111", true),
            ("2001:4860:4860::8888", true),
            ("::1", false),
            ("fe80::1", false),
            ("fc00::1", false),
            ("ff02::1", false),
            ("2001:db8::1", false),
            ("2001::1", false),
            ("::ffff:127.0.0.1", false),
        ];

        for (address, expected) in cases {
            let address = address.parse().expect("test address should parse");
            assert_eq!(is_public_destination(&address), expected, "{address}");
        }
    }

    #[tokio::test]
    async fn filters_mixed_dns_answers_and_rechecks_rebinding_answers() {
        let mut connector = mock_connector(vec![
            vec!["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            vec!["169.254.169.254".parse().unwrap()],
        ]);

        let name = "api.example"
            .parse::<Name>()
            .expect("test DNS name should parse");
        let first = connector
            .call(name.clone())
            .await
            .expect("public DNS answer should remain usable")
            .collect::<Vec<_>>();
        assert_eq!(first, vec!["8.8.8.8:0".parse().unwrap()]);

        let rebound = connector.call(name).await;
        assert_eq!(
            rebound.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "a later private DNS answer must be rejected"
        );
    }

    #[tokio::test]
    async fn rejects_dns_answers_with_only_prohibited_destinations() {
        let connector = mock_connector(vec![vec!["10.1.2.3".parse().unwrap()]]);

        let authority = "api.example:443"
            .parse()
            .expect("test CONNECT authority should parse");
        let result = connector.connect(authority).await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
