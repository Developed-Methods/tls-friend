use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::async_io::AsyncIO;
use crate::client_connector::ClientConnector;
use crate::tls_streams::ClientStream;

pub trait ConnectionBuilder: Sync + Send + 'static {
    type IO: AsyncIO;

    fn connect(&self, addr: SocketAddr) -> impl std::future::Future<Output = std::io::Result<Self::IO>> + Send;
}

impl ConnectionBuilder for ClientConnector {
    type IO = ClientStream<TcpStream>;

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::IO> {
        let stream = TcpStream::connect(addr).await?;
        self.connect(stream).await
    }
}

