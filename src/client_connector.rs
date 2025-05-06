use tokio_rustls::{
    rustls::pki_types::{DnsName, ServerName},
    TlsAcceptor, TlsConnector,
};

use crate::{async_io::AsyncIO, tls_streams::{ClientStream, ServerStream}};

#[derive(Clone)]
pub struct ClientConnector {
    tls_connector: Option<(ServerName<'static>, TlsConnector)>,
}

impl ClientConnector {
    pub fn tls(name: &str, connector: TlsConnector) -> Result<Self, std::io::Error> {
        let domain = DnsName::try_from(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname"))?
            .to_owned();

        Ok(ClientConnector {
            tls_connector: Some((ServerName::DnsName(domain), connector)),
        })
    }

    pub fn plain() -> Self {
        ClientConnector {
            tls_connector: None,
        }
    }

    pub async fn connect<IO: AsyncIO>(&self, io: IO) -> Result<ClientStream<IO>, std::io::Error> {
        match &self.tls_connector {
            Some((name, connector)) => Ok(ClientStream::TlsStream(
                connector.connect(name.clone(), io).await?,
            )),
            None => Ok(ClientStream::TcpStream(io)),
        }
    }
}

#[derive(Clone)]
pub struct ClientAcceptor {
    tls_acceptor: Option<TlsAcceptor>,
}

impl ClientAcceptor {
    pub fn tls(acceptor: TlsAcceptor) -> Self {
        ClientAcceptor {
            tls_acceptor: Some(acceptor),
        }
    }

    pub fn plain() -> Self {
        ClientAcceptor { tls_acceptor: None }
    }

    pub async fn accept<IO: AsyncIO>(&self, io: IO) -> Result<ServerStream<IO>, std::io::Error> {
        match &self.tls_acceptor {
            Some(acceptor) => Ok(ServerStream::TlsStream(acceptor.accept(io).await?)),
            None => Ok(ServerStream::TcpStream(io)),
        }
    }
}
