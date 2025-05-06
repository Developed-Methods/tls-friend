use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

pub trait AsyncIO: AsyncRead + AsyncWrite + Sized + Send + Sync + Unpin + 'static {
    type ReadSide: AsyncRead + Sized + Send + Sync + Unpin;
    type WriteSide: AsyncWrite + Sized + Send + Sync + Unpin;

    fn into_split(self) -> (Self::ReadSide, Self::WriteSide);

    fn try_join(
        read: Self::ReadSide,
        write: Self::WriteSide,
    ) -> Result<Self, (Self::ReadSide, Self::WriteSide)>;
}

impl<T: AsyncRead + AsyncWrite + Sized + Send + Sync + Unpin + 'static> AsyncIO for T {
    type ReadSide = ReadHalf<Self>;
    type WriteSide = WriteHalf<Self>;

    fn into_split(self) -> (Self::ReadSide, Self::WriteSide) {
        tokio::io::split(self)
    }

    fn try_join(
        read: Self::ReadSide,
        write: Self::WriteSide,
    ) -> Result<Self, (Self::ReadSide, Self::WriteSide)> {
        if !read.is_pair_of(&write) {
            return Err((read, write));
        }
        Ok(read.unsplit(write))
    }
}

#[cfg(test)]
mod test {
    use tokio::net::{TcpListener, TcpStream};

    use crate::async_io::AsyncIO;

    #[tokio::test]
    async fn test() {
        let listen = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let tcp = TcpStream::connect(listen.local_addr().unwrap())
            .await
            .unwrap();

        let (read, write) = AsyncIO::into_split(tcp);
        let _v: TcpStream = AsyncIO::try_join(read, write).ok().unwrap();
    }
}
