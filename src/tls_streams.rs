use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_io::AsyncIO;
use crate::{ClientTlsStream, ServerTlsStream};

#[allow(clippy::large_enum_variant)]
pub enum MaybeTlsStream<IO: AsyncIO> {
    Client(ClientStream<IO>),
    Server(ServerStream<IO>),
}

#[allow(clippy::large_enum_variant)]
pub enum ClientStream<IO: AsyncIO> {
    TcpStream(IO),
    TlsStream(ClientTlsStream<IO>),
}

#[allow(clippy::large_enum_variant)]
pub enum ServerStream<IO: AsyncIO> {
    TcpStream(IO),
    TlsStream(ServerTlsStream<IO>),
}

impl<IO: AsyncIO> AsyncRead for MaybeTlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        unsafe {
            match self.get_mut() {
                Self::Client(io) => Pin::new_unchecked(io).poll_read(cx, buf),
                Self::Server(io) => Pin::new_unchecked(io).poll_read(cx, buf),
            }
        }
    }
}

impl<IO: AsyncIO> AsyncWrite for MaybeTlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unsafe {
            match self.get_mut() {
                Self::Client(io) => Pin::new_unchecked(io).poll_write(cx, buf),
                Self::Server(io) => Pin::new_unchecked(io).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe {
            match self.get_mut() {
                Self::Client(io) => Pin::new_unchecked(io).poll_flush(cx),
                Self::Server(io) => Pin::new_unchecked(io).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe {
            match self.get_mut() {
                Self::Client(io) => Pin::new_unchecked(io).poll_shutdown(cx),
                Self::Server(io) => Pin::new_unchecked(io).poll_shutdown(cx),
            }
        }
    }
}


impl<IO: AsyncIO> AsyncRead for ClientStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_read(cx, buf),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_read(cx, buf),
            }
        }
    }
}

impl<IO: AsyncIO> AsyncWrite for ClientStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_write(cx, buf),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_flush(cx),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_shutdown(cx),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_shutdown(cx),
            }
        }
    }
}

impl<IO: AsyncIO> AsyncRead for ServerStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_read(cx, buf),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_read(cx, buf),
            }
        }
    }
}

impl<IO: AsyncIO> AsyncWrite for ServerStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_write(cx, buf),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_flush(cx),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe {
            match self.get_mut() {
                Self::TcpStream(io) => Pin::new_unchecked(io).poll_shutdown(cx),
                Self::TlsStream(io) => Pin::new_unchecked(io).poll_shutdown(cx),
            }
        }
    }
}

