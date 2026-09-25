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

use crate::policy::SessionPolicy;

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'static>>;

trait HostResolver: Send + Sync + 'static {
    fn lookup(&self, host: String) -> LookupFuture;
}

#[derive(Clone)]
pub(crate) struct EgressConnector {
    resolver: Arc<dyn HostResolver>,
    policy: Arc<SessionPolicy>,
}

impl EgressConnector {
    pub(crate) fn system(policy: Arc<SessionPolicy>) -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            policy,
        }
    }

    #[cfg(test)]
    fn with_resolver(policy: Arc<SessionPolicy>, resolver: Arc<dyn HostResolver>) -> Self {
        Self { resolver, policy }
    }

    async fn resolve_addresses(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses = match host.parse::<IpAddr>() {
            Ok(address) => vec![address],
            Err(_) => self.resolver.lookup(host.to_owned()).await?,
        };

        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|address| {
                is_public_destination(address)
                    || self.policy.permits_private_address(
                        host,
                        (port != 0).then_some(port),
                        *address,
                    )
            })
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
        // Azure WireServer is a VM platform endpoint, despite being in public address space.
        && address != Ipv4Addr::new(168, 63, 129, 16)
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

    use crate::{config::ControlRequest, policy::SessionPolicy};

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

    struct FailingResolver;

    impl HostResolver for FailingResolver {
        fn lookup(&self, _host: String) -> LookupFuture {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "mock DNS lookup failed",
                ))
            })
        }
    }

    fn policy(host: &str, ports: &str, private_addresses: &str) -> Arc<SessionPolicy> {
        let input = format!(
            "version = 1\noperation = \"create\"\n\n[session]\n\n[[rules]]\nhost = \"{host}\"\nmode = \"tunnel\"\n{ports}\n{private_addresses}\n"
        );
        let ControlRequest::Create { session, .. } =
            ControlRequest::from_toml(&input).expect("test session policy should parse")
        else {
            panic!("test request should create a session");
        };
        Arc::new(SessionPolicy::compile(&session))
    }

    fn mock_connector(responses: Vec<Vec<IpAddr>>, policy: Arc<SessionPolicy>) -> EgressConnector {
        EgressConnector::with_resolver(
            policy,
            Arc::new(QueueResolver(Mutex::new(responses.into()))),
        )
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
            ("168.63.129.16", false),
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
        let mut connector = mock_connector(
            vec![
                vec!["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()],
                vec!["169.254.169.254".parse().unwrap()],
            ],
            policy("api.example", "ports = [443]", ""),
        );

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
        let connector = mock_connector(
            vec![vec!["10.1.2.3".parse().unwrap()]],
            policy("api.example", "ports = [443]", ""),
        );

        let authority = "api.example:443"
            .parse()
            .expect("test CONNECT authority should parse");
        let result = connector.connect(authority).await;

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn rejects_azure_wireserver_resolution_before_connecting() {
        let connector = mock_connector(
            vec![vec!["168.63.129.16".parse().unwrap()]],
            policy("allowed.example", "ports = [80]", ""),
        );

        let result = connector
            .connect("allowed.example:80".parse().unwrap())
            .await;

        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "Azure WireServer must be denied before the connector attempts a TCP dial"
        );
    }

    #[tokio::test]
    async fn rejects_private_cname_result_unless_that_exact_address_is_allowed() {
        let mut connector = mock_connector(
            vec![vec!["10.1.2.4".parse().unwrap()]],
            policy(
                "public-alias.example",
                "ports = [443]",
                "private_addresses = [\"10.1.2.3\"]",
            ),
        );
        let alias = "public-alias.example"
            .parse::<Name>()
            .expect("test CNAME alias should parse");

        let result = connector.call(alias).await;

        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "the resolved CNAME address must be checked against the exact exception"
        );
    }

    #[tokio::test]
    async fn rejects_ipv6_loopback_for_an_authorized_connect_host() {
        let connector = mock_connector(
            vec![vec!["::1".parse().unwrap()]],
            policy("allowed.example", "ports = [443]", ""),
        );

        let result = connector
            .connect("allowed.example:443".parse().unwrap())
            .await;

        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "an allowed hostname must not tunnel to IPv6 loopback"
        );
    }

    #[tokio::test]
    async fn failed_resolution_fails_closed_for_http_and_connect() {
        let policy = policy("allowed.example", "ports = [443]", "");
        let mut http_connector =
            EgressConnector::with_resolver(Arc::clone(&policy), Arc::new(FailingResolver));
        let name = "allowed.example"
            .parse::<Name>()
            .expect("test DNS name should parse");
        let http_result = http_connector.call(name).await;
        assert_eq!(http_result.unwrap_err().kind(), io::ErrorKind::NotFound);

        let tcp_connector = EgressConnector::with_resolver(policy, Arc::new(FailingResolver));
        let connect_result = tcp_connector
            .connect("allowed.example:443".parse().unwrap())
            .await;
        assert_eq!(connect_result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn http_dns_resolution_allows_only_the_sessions_explicit_private_address() {
        let private_address = "10.1.2.3".parse().unwrap();
        let mut connector = mock_connector(
            vec![vec![private_address, "10.1.2.4".parse().unwrap()]],
            policy(
                "api.internal.example",
                "ports = [8443]",
                "private_addresses = [\"10.1.2.3\"]",
            ),
        );
        let name = "api.internal.example"
            .parse::<Name>()
            .expect("test DNS name should parse");

        let resolved = connector
            .call(name.clone())
            .await
            .expect("explicitly permitted private DNS answer should remain usable")
            .collect::<Vec<_>>();
        assert_eq!(resolved, vec!["10.1.2.3:0".parse().unwrap()]);

        let mut other_session = mock_connector(
            vec![vec![private_address]],
            policy("api.internal.example", "ports = [8443]", ""),
        );
        let denied = other_session
            .call(name)
            .await
            .expect_err("a second session must not inherit the private address exception");
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn connect_dials_an_explicit_private_address_only_on_the_rule_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test destination should bind");
        let port = listener
            .local_addr()
            .expect("test destination address should be available")
            .port();
        let connector = mock_connector(
            vec![
                vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()],
                vec!["127.0.0.1".parse().unwrap()],
            ],
            policy(
                "internal.example",
                &format!("ports = [{port}]"),
                "private_addresses = [\"127.0.0.1\"]",
            ),
        );

        let stream = connector
            .connect(format!("internal.example:{port}").parse().unwrap())
            .await
            .expect("explicit CONNECT exception should dial the permitted address");
        let (accepted, _) = listener
            .accept()
            .await
            .expect("permitted private destination should receive the connection");
        assert_eq!(
            stream.local_addr().unwrap().ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        drop(accepted);
        drop(stream);

        let wrong_port = if port == 443 { 444 } else { 443 };
        let denied = connector
            .connect(format!("internal.example:{wrong_port}").parse().unwrap())
            .await
            .expect_err("the exception must not permit another destination port");
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);

        let other_session = mock_connector(
            vec![vec!["127.0.0.1".parse().unwrap()]],
            policy("internal.example", &format!("ports = [{port}]"), ""),
        );
        let denied = other_session
            .connect(format!("internal.example:{port}").parse().unwrap())
            .await
            .expect_err("a second session must not inherit the private address exception");
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn connect_retries_only_the_validated_addresses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test destination should bind");
        let port = listener
            .local_addr()
            .expect("test destination address should be available")
            .port();
        let connector = mock_connector(
            vec![vec![
                "127.0.0.2".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ]],
            policy(
                "internal.example",
                &format!("ports = [{port}]"),
                "private_addresses = [\"127.0.0.1\", \"127.0.0.2\"]",
            ),
        );

        let stream = connector
            .connect(format!("internal.example:{port}").parse().unwrap())
            .await
            .expect("connector should try the next validated address after a refused dial");
        let (accepted, _) = listener
            .accept()
            .await
            .expect("the validated fallback address should receive the connection");

        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        drop(accepted);
        drop(stream);
    }
}
