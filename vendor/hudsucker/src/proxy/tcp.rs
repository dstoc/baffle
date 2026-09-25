use std::{future::Future, io, pin::Pin};

use http::uri::Authority;
use tokio::net::TcpStream;

/// A connector for outbound TCP streams used by CONNECT tunnels and WebSockets.
///
/// The connector receives the original authority so it can enforce destination
/// policy and pin a validated DNS result to the socket it opens.
pub trait TcpConnector: Send + Sync + 'static {
    /// Connect to an authorized destination.
    fn connect(
        &self,
        authority: Authority,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>>;
}

#[derive(Clone, Default)]
pub struct DirectTcpConnector;

impl TcpConnector for DirectTcpConnector {
    fn connect(
        &self,
        authority: Authority,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + 'static>> {
        Box::pin(async move { TcpStream::connect(authority.as_ref()).await })
    }
}
