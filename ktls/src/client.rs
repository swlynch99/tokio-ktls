use std::os::fd::AsRawFd;
use std::{fmt, io};

use rustls::client::{ClientConnectionData, UnbufferedClientConnection};
use rustls::kernel::KernelConnection;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ffi::Direction;
use crate::stream::KTlsStreamImpl;
use crate::CryptoInfo;

pub struct KTlsClientStream<IO>(KTlsStreamImpl<IO, KernelConnection<ClientConnectionData>>);

impl<IO> KTlsClientStream<IO>
where
    IO: AsyncWrite + AsyncRead + AsRawFd,
{
    pub fn from_unbuffered_connnection(
        socket: IO,
        conn: UnbufferedClientConnection,
    ) -> Result<Self, TryConnectError<IO>> {
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

        todo!()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// kTLS is not supported by the current kernel
    #[error("kTLS is not supported by the current kernel")]
    KTlsUnsupported,

    #[error("the negotiated cipher suite is not supported by kTLS")]
    UnsupportedCipherSuite,

    #[error("the peer closed the connection before the TLS handshake could be completed")]
    PeerClosedBeforeHandshakeCompleted,

    #[error("{0}")]
    IO(#[source] io::Error),

    #[error("failed to create rustls client connection: {0}")]
    Config(#[source] rustls::Error),

    #[error("an error occurred during the handshake: {0}")]
    Handshake(#[source] rustls::Error),

    #[error("unable to extract connection secrets from rustls connection: {0}")]
    ExtractSecrets(#[source] rustls::Error),
}

#[derive(thiserror::Error)]
#[error("{error}")]
pub struct TryConnectError<IO> {
    #[source]
    pub error: ConnectError,
    pub socket: Option<IO>,
    pub conn: Option<UnbufferedClientConnection>,
}

impl<IO> fmt::Debug for TryConnectError<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TryConnectError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<IO> From<ConnectError> for TryConnectError<IO> {
    fn from(error: ConnectError) -> Self {
        Self {
            error,
            socket: None,
            conn: None,
        }
    }
}
