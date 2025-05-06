use std::fmt::Debug;
use std::io::Cursor;
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore},
    TlsAcceptor, TlsConnector,
};
use tracing::Instrument;

pub struct TlsSetup;

#[derive(Clone)]
pub struct MutualTls {
    trust: RootCertStore,
    cert: Certificate,
}

#[derive(Clone)]
pub struct OpenServerTls {
    cert: Certificate,
}

#[derive(Clone)]
pub struct ClientVerifyServerTls {
    trust: RootCertStore,
}

#[derive(Clone)]
pub enum ClientTls {
    Mutual(MutualTls),
    VerifyServer(ClientVerifyServerTls),
}

#[derive(Clone)]
pub enum ServerTls {
    Mutual(MutualTls),
    OpenServer(OpenServerTls),
}

impl Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mutual(_) => write!(f, "ClientTls::Mutual"),
            Self::VerifyServer(_) => write!(f, "ClientTls::VerifyServer"),
        }
    }
}

impl Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mutual(_) => write!(f, "ServerTls::Mutual"),
            Self::OpenServer(_) => write!(f, "ServerTls::OpenServer"),
        }
    }
}

impl From<MutualTls> for ClientTls {
    fn from(value: MutualTls) -> Self {
        ClientTls::Mutual(value)
    }
}

impl From<MutualTls> for ServerTls {
    fn from(value: MutualTls) -> Self {
        ServerTls::Mutual(value)
    }
}

impl From<OpenServerTls> for ServerTls {
    fn from(value: OpenServerTls) -> Self {
        ServerTls::OpenServer(value)
    }
}

impl From<ClientVerifyServerTls> for ClientTls {
    fn from(value: ClientVerifyServerTls) -> Self {
        ClientTls::VerifyServer(value)
    }
}

struct Certificate {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl Clone for Certificate {
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl TlsSetup {
    pub async fn load_mutal(ca_path: &str, key_path: &str) -> Result<MutualTls, std::io::Error> {
        async {
            let ca_bytes = tokio::fs::read(ca_path).await?;
            let crt = Self::load_key(key_path).await?;
            Self::build_mutual(&ca_bytes, &crt.key, &crt.crt)
        }.instrument(tracing::info_span!("load_mutal", ca_path, key_path)).await
    }

    pub async fn load_server(key_path: &str) -> Result<OpenServerTls, std::io::Error> {
        async {
            let crt = Self::load_key(key_path).await?;
            Self::build_server(&crt.key, &crt.crt)
        }.instrument(tracing::info_span!("load_server", key_path)).await
    }

    pub async fn load_client(ca_path: &str) -> Result<ClientVerifyServerTls, std::io::Error> {
        async {
            let ca_bytes = tokio::fs::read(ca_path).await?;
            Self::build_client(&ca_bytes)
        }.instrument(tracing::info_span!("load_client", ca_path)).await
    }

    async fn load_key(mut key_path: &str) -> Result<CertData, std::io::Error> {
        if key_path.ends_with(".pem") {
            let key_bytes = tokio::fs::read(key_path).await?;

            return Ok(CertData {
                crt: key_bytes.clone(),
                key: key_bytes,
            });
        }

        if key_path.ends_with(".crt") || key_path.ends_with(".key") {
            let len = key_path.len();
            key_path = &key_path[..len - 4];
        }

        let key_data = tokio::fs::read(format!("{}.key", key_path)).await?;
        let cert_data = tokio::fs::read(format!("{}.crt", key_path)).await?;

        Ok(CertData {
            key: key_data,
            crt: cert_data,
        })
    }

    pub fn build_mutual(
        trust_ca_pem: &[u8],
        key_data: &[u8],
        cert_data: &[u8],
    ) -> Result<MutualTls, std::io::Error> {
        let mut root_cert_store = RootCertStore::empty();

        for cert in parse_certificates(trust_ca_pem)? {
            if let Err(error) = root_cert_store.add(cert) {
                tracing::error!(?error, "failed to add CA certificate");
            }
        }

        if root_cert_store.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no CA certificate found",
            ));
        }

        let cert_chain = parse_certificates(if cert_data.is_empty() {
            key_data
        } else {
            cert_data
        })?;
        let private_key = parse_key(key_data)?;

        Ok(MutualTls {
            trust: root_cert_store,
            cert: Certificate {
                cert_chain,
                private_key,
            },
        })
    }

    pub fn build_server(
        key_data: &[u8],
        cert_data: &[u8],
    ) -> Result<OpenServerTls, std::io::Error> {
        let cert_chain = parse_certificates(cert_data)?;
        let private_key = parse_key(key_data)?;

        Ok(OpenServerTls {
            cert: Certificate {
                cert_chain,
                private_key,
            },
        })
    }

    pub fn build_client(trust_ca_pem: &[u8]) -> Result<ClientVerifyServerTls, std::io::Error> {
        let mut root_cert_store = RootCertStore::empty();

        for cert in parse_certificates(trust_ca_pem)? {
            if let Err(error) = root_cert_store.add(cert) {
                tracing::error!(?error, "failed to add CA certificate");
            }
        }

        if root_cert_store.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no CA certificate found",
            ));
        }

        Ok(ClientVerifyServerTls {
            trust: root_cert_store,
        })
    }
}

struct CertData {
    crt: Vec<u8>,
    key: Vec<u8>,
}

impl MutualTls {
    pub fn into_connector(self) -> Result<TlsConnector, std::io::Error> {
        Ok(TlsConnector::from(Arc::new(self.into_client_config()?)))
    }

    pub fn into_client_config(self) -> Result<ClientConfig, std::io::Error> {
        ClientConfig::builder()
            .with_root_certificates(self.trust)
            .with_client_auth_cert(self.cert.cert_chain, self.cert.private_key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }

    pub fn into_acceptor(self) -> Result<TlsAcceptor, std::io::Error> {
        Ok(TlsAcceptor::from(Arc::new(self.into_server_config()?)))
    }

    pub fn into_server_config(self) -> Result<ServerConfig, std::io::Error> {
        let verifier = match WebPkiClientVerifier::builder(Arc::new(self.trust)).build() {
            Ok(v) => v,
            Err(error) => {
                tracing::error!(?error, "failed to build client verifier");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid client certs",
                ));
            }
        };

        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.cert.cert_chain, self.cert.private_key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

impl OpenServerTls {
    pub fn into_acceptor(self) -> Result<TlsAcceptor, std::io::Error> {
        Ok(TlsAcceptor::from(Arc::new(self.into_server_config()?)))
    }

    pub fn into_server_config(self) -> Result<ServerConfig, std::io::Error> {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert.cert_chain, self.cert.private_key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

impl ClientVerifyServerTls {
    pub fn into_connector(self) -> Result<TlsConnector, std::io::Error> {
        Ok(TlsConnector::from(Arc::new(self.into_client_config()?)))
    }

    pub fn into_client_config(self) -> Result<ClientConfig, std::io::Error> {
        Ok(ClientConfig::builder()
            .with_root_certificates(self.trust)
            .with_no_client_auth())
    }
}

impl ClientTls {
    pub fn into_connector(self) -> Result<TlsConnector, std::io::Error> {
        match self {
            ClientTls::Mutual(v) => v.into_connector(),
            ClientTls::VerifyServer(v) => v.into_connector(),
        }
    }

    pub fn into_client_config(self) -> Result<ClientConfig, std::io::Error> {
        match self {
            ClientTls::Mutual(v) => v.into_client_config(),
            ClientTls::VerifyServer(v) => v.into_client_config(),
        }
    }
}

impl ServerTls {
    pub fn into_acceptor(self) -> Result<TlsAcceptor, std::io::Error> {
        match self {
            ServerTls::Mutual(v) => v.into_acceptor(),
            ServerTls::OpenServer(v) => v.into_acceptor(),
        }
    }

    pub fn into_server_config(self) -> Result<ServerConfig, std::io::Error> {
        match self {
            ServerTls::Mutual(v) => v.into_server_config(),
            ServerTls::OpenServer(v) => v.into_server_config(),
        }
    }
}

fn parse_certificates(ca_binary: &[u8]) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    let _span = tracing::info_span!("parse_certificates").entered();

    let mut cursor = Cursor::new(ca_binary);
    let mut certificates = Vec::new();

    let mut invalid = None;

    loop {
        let Some(pem) = rustls_pemfile::read_one(&mut cursor)
            .expect("failed to parse certificate") else { break; };

        let cert = match pem {
            rustls_pemfile::Item::X509Certificate(cert) => cert,
            found => {
                invalid = Some(found);
                continue;
            }
        };

        certificates.push(cert);
    }

    if certificates.is_empty() {
        tracing::error!("found no certificates, but got: {:?}", invalid);

        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no certifiates in file",
        ));
    }

    Ok(certificates)
}

fn parse_key(bytes: &[u8]) -> Result<PrivateKeyDer<'static>, std::io::Error> {
    let _span = tracing::info_span!("parse_key").entered();

    let mut cursor = Cursor::new(bytes);

    let pems = rustls_pemfile::read_all(&mut cursor);
    let mut invalid = None;

    for pem in pems {
        match pem? {
            rustls_pemfile::Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
            other => {
                invalid = Some(other);
            }
        }
    }

    if let Some(invalid) = invalid {
        tracing::warn!(?invalid, "got invalid key type");
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "could not find valid private key",
    ))
}
