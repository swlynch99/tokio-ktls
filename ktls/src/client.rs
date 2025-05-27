use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::kernel::KernelConnection;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ffi::Direction;
use crate::stream::KTlsStreamImpl;
use crate::CryptoInfo;
use crate::{ConnectError, TryConnectError};

pin_project_lite::pin_project! {
    pub struct KTlsClientStream<IO> {
        #[pin]
        pub(crate) stream: KTlsStreamImpl<IO, KernelConnection<ClientConnectionData>>
    }
}

impl<IO> KTlsClientStream<IO>
where
    IO: AsyncWrite + AsyncRead + AsRawFd,
{
    pub fn from_unbuffered_connnection(
        socket: IO,
        conn: UnbufferedClientConnection,
    ) -> Result<Self, TryConnectError<IO, UnbufferedClientConnection>> {
        // We attempt to set up the TLS ULP before doing anything else so that
        // we can indicate that the kernel doesn't support kTLS before returning
        // any other error.
        if let Err(e) = crate::ffi::setup_ulp(socket.as_raw_fd()) {
            let error = if e.raw_os_error() == Some(libc::ENOENT) {
                ConnectError::KTlsUnsupported
            } else {
                ConnectError::IO(e)
            };

            return Err(TryConnectError {
                error,
                socket: Some(socket),
                conn: Some(conn),
            });
        }

        // TODO: Validate that the negotiated connection is actually
        //       supported by kTLS on the current machine.

        Ok(Self::from_unbuffered_connnection_with_tls_ulp_enabled(
            socket, conn,
        )?)
    }

    /// Create a new `KTlsClientStream` from a socket that already has had the TLS ULP
    /// enabled on it.
    fn from_unbuffered_connnection_with_tls_ulp_enabled(
        socket: IO,
        conn: UnbufferedClientConnection,
    ) -> Result<Self, ConnectError> {
        let (secrets, kconn) = match conn.dangerous_into_kernel_connection() {
            Ok(secrets) => secrets,
            Err(e) => return Err(ConnectError::ExtractSecrets(e)),
        };

        let suite = kconn.negotiated_cipher_suite();
        let tx = CryptoInfo::from_rustls(suite, secrets.tx)
            .map_err(|_| ConnectError::UnsupportedCipherSuite)?;
        let rx = CryptoInfo::from_rustls(suite, secrets.rx)
            .map_err(|_| ConnectError::UnsupportedCipherSuite)?;

        crate::ffi::setup_tls_info(socket.as_raw_fd(), Direction::Tx, tx)
            .map_err(ConnectError::IO)?;
        crate::ffi::setup_tls_info(socket.as_raw_fd(), Direction::Rx, rx)
            .map_err(ConnectError::IO)?;

        Ok(Self {
            stream: KTlsStreamImpl::new(socket, Vec::new(), kconn),
        })
    }
}

impl<IO> AsyncRead for KTlsClientStream<IO>
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

impl<IO> AsyncWrite for KTlsClientStream<IO>
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

impl<IO> AsRawFd for KTlsClientStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}
