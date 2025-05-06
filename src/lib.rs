use std::sync::atomic::{AtomicBool, Ordering};

pub mod async_io;
pub mod client_connector;
pub mod connection_builder;
pub mod tls_setup;
pub mod tls_streams;

static CRYPTO_SETUP: AtomicBool = AtomicBool::new(false);

pub fn install_crypto() {
    if CRYPTO_SETUP.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        tracing::info!("Crypto already setup");
        return;
    }

    tracing::info!("Install Crypto");
    if rustls::crypto::aws_lc_rs::default_provider().install_default().is_err() {
        tracing::error!("failed to install crypto");
    }
}

pub type ClientTlsStream<IO> = tokio_rustls::client::TlsStream<IO>;
pub type ServerTlsStream<IO> = tokio_rustls::server::TlsStream<IO>;

#[cfg(test)]
mod test;
