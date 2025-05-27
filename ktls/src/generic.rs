use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::stream::{DynConn, KTlsStreamImpl};
use crate::{KTlsClientStream, KTlsServerStream, Side};

pin_project_lite::pin_project! {
    /// A wrapper around an `IO` that takes care of managing kTLS state for
    /// its underlying fd.
    /// 
    /// This is the generic version of [`KTlsClientStream`] and [`KTlsServerStream`].
    /// It cannot be constructed directly. Instead, construct on of the two more
    /// specific streams above and then convert them into [`KTlsStream`].
    pub struct KTlsStream<IO> {
        #[pin]
        stream: KTlsStreamImpl<IO, dyn DynConn>
    }
}

impl<IO> KTlsStream<IO> {
    pub fn into_side(self) -> Side<KTlsClientStream<IO>, KTlsServerStream<IO>> {
        match self.stream.into_side() {
            Side::Client(stream) => Side::Client(KTlsClientStream { stream }),
            Side::Server(stream) => Side::Server(KTlsServerStream { stream }),
        }
    }
}

impl<IO> From<KTlsClientStream<IO>> for KTlsStream<IO> {
    fn from(value: KTlsClientStream<IO>) -> Self {
        Self {
            stream: value.stream.into_dyn(),
        }
    }
}

impl<IO> From<KTlsServerStream<IO>> for KTlsStream<IO> {
    fn from(value: KTlsServerStream<IO>) -> Self {
        Self {
            stream: value.stream.into_dyn(),
        }
    }
}

impl<IO> AsyncRead for KTlsStream<IO>
where
    IO: AsyncWrite + AsyncRead + AsRawFd,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl<IO> AsyncWrite for KTlsStream<IO>
where
    IO: AsyncWrite + AsyncRead + AsRawFd,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

impl<IO> AsRawFd for KTlsStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}
