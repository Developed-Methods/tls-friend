use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use crate::{client_connector::ClientConnector, tls_setup::TlsSetup};

#[tokio::test]
async fn simple_tls_connection_test() {
    let server = TlsSetup::build_mutual(
        include_bytes!("./res/client_ca.crt"),
        include_bytes!("./res/server.key"),
        include_bytes!("./res/server.crt"),
    )
    .unwrap();

    let client = TlsSetup::build_mutual(
        include_bytes!("./res/server_ca.crt"),
        include_bytes!("./res/client.key"),
        include_bytes!("./res/client.crt"),
    )
    .unwrap();

    let acceptor = server.into_acceptor().unwrap();
    let connector = client.into_connector().unwrap();

    let (server_io, client_io) = duplex(1024);

    let server_accept_task = tokio::spawn(acceptor.accept(server_io));
    let client_connector =
        ClientConnector::tls("s1.testing-server.playit.cloud", connector).unwrap();

    let mut client_io = client_connector.connect(client_io).await.unwrap();
    let mut server_io = server_accept_task.await.unwrap().unwrap();

    let client_send = "hello world".as_bytes();
    client_io.write_all(client_send).await.unwrap();

    let mut recv_buffer = Vec::with_capacity(1024);
    recv_buffer.resize(client_send.len(), 0u8);

    server_io.read_exact(&mut recv_buffer).await.unwrap();
    assert_eq!(&recv_buffer, client_send);

    let server_send = "i feel welcome, i am world".as_bytes();
    server_io.write_all(server_send).await.unwrap();
    recv_buffer.resize(server_send.len(), 0u8);
    client_io.read_exact(&mut recv_buffer).await.unwrap();
    assert_eq!(&recv_buffer, server_send);

    server_io.write_all("I'm done".as_bytes()).await.unwrap();
    server_io.shutdown().await.unwrap();

    recv_buffer.clear();
    client_io.read_to_end(&mut recv_buffer).await.unwrap();
    assert_eq!("I'm done".as_bytes(), &recv_buffer);
}

