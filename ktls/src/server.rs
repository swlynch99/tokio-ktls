use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::kernel::KernelConnection;
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::ffi::Direction;
use crate::protocol::read_record;
use crate::stream::KTlsStreamImpl;
use crate::{CompatibleCiphers, ConnectError, CryptoInfo, TryConnectError};

/// A wrapper around [`rustls::ServerConfig`] which provides an async `accept`
/// method using kTLS.
///
/// # Cipher Support
/// kTLS only has supposrt for a limited set of TLS ciphers. These can differ
/// based on the current kernel version and whether support for kTLS was
/// compiled in to the running kernel. If cipher negotiation selects a cipher
/// which is not supported by the current kernel, then you will get an error
/// when accepting the connection.
pub struct KTlsAcceptor {
    config: Arc<ServerConfig>,
}

impl KTlsAcceptor {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    pub async fn accept<IO>(&self, socket: IO) -> Result<KTlsServerStream<IO>, ConnectError>
    where
        IO: AsyncWrite + AsyncRead + AsRawFd + Unpin,
    {
        Ok(self.try_accept(socket).await?)
    }

    pub async fn try_accept<IO>(
        &self,
        mut socket: IO,
    ) -> Result<KTlsServerStream<IO>, TryConnectError<IO, UnbufferedServerConnection>>
    where
        IO: AsyncWrite + AsyncRead + AsRawFd + Unpin,
    {
        let mut conn = match UnbufferedServerConnection::new(self.config.clone()) {
            Ok(conn) => conn,
            Err(e) => {
                return Err(TryConnectError {
                    error: ConnectError::Config(e),
                    socket: Some(socket),
                    conn: None,
                })
            }
        };

        // We attempt to set up the TLS ULP before doing anything else so that
        // we can indicate that the kernel doesn't support kTLS before returning
        // any other error.
        //
        // This is also needed to prevent errors in one specific case: if we set
        // up the ULP after the handshake has completed then a peer connected on
        // localhost can immediately send its data and close the connection
        // before we can call setsockopt. In this case we would get an error, even
        // though no error has actually occurred.
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

        let mut incoming = Vec::with_capacity(1024);
        let mut outgoing = Vec::with_capacity(1024);
        let mut outgoing_used = 0usize;
        let mut early = Vec::new();

        loop {
            let UnbufferedStatus { mut discard, state } = conn.process_tls_records(&mut incoming);
            let state = match state {
                Ok(state) => state,
                Err(e) => return Err(ConnectError::Handshake(e).into()),
            };

            match state {
                ConnectionState::BlockedHandshake => {
                    read_record(&mut socket, &mut incoming)
                        .await
                        .map_err(ConnectError::IO)?;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Err(TryConnectError {
                        error: ConnectError::ConnectionClosedBeforeHandshakeCompleted,
                        socket: Some(socket),
                        conn: None,
                    })
                }
                ConnectionState::ReadEarlyData(mut data) => {
                    while let Some(record) = data.next_record() {
                        let record = record.map_err(ConnectError::Handshake)?;
                        discard += record.discard;
                        early.extend_from_slice(record.payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut data) => {
                    match data.encode(&mut outgoing[outgoing_used..]) {
                        Ok(count) => outgoing_used += count,
                        Err(EncodeError::AlreadyEncoded) => unreachable!(),
                        Err(EncodeError::InsufficientSize(e)) => {
                            outgoing.resize(outgoing_used + e.required_size, 0u8);

                            match data.encode(&mut outgoing[outgoing_used..]) {
                                Ok(count) => outgoing_used += count,
                                Err(e) => unreachable!("encode failed after resizing buffer: {e}"),
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(data) => {
                    socket
                        .write_all(&outgoing[..outgoing_used])
                        .await
                        .map_err(ConnectError::IO)?;
                    outgoing_used = 0;
                    data.done();
                }
                ConnectionState::WriteTraffic(_) => {
                    incoming.drain(..discard);
                    break;
                }
                ConnectionState::ReadTraffic(_) => unreachable!(
                    "ReadTraffic should not be encountered during the handshake process"
                ),
                _ => unreachable!("unexpected connection state"),
            }

            incoming.drain(..discard);
        }

        // We validate ciphers here as a convenience to produce better errors.
        // We explicitly don't want to fail to create a kTLS cipher if probing
        // fails, since the probe failing doesn't necessarily mean that creating
        // this connection will fail.
        if let Ok(support) = CompatibleCiphers::new().await {
            let suite = conn.negotiated_cipher_suite().ok_or_else(|| {
                ConnectError::Handshake(rustls::Error::General(
                    "handshake completed but no negotiated cipher suite is present".into(),
                ))
            })?;

            if !support.is_compatible(suite) {
                return Err(TryConnectError {
                    error: ConnectError::UnsupportedCipherSuite(suite),
                    socket: Some(socket),
                    conn: Some(conn),
                });
            }
        }

        KTlsServerStream::from_unbuffered_connection_validate(socket, early, conn).await
    }
}

pin_project_lite::pin_project! {
    /// The server half of a kTLS stream.
    pub struct KTlsServerStream<IO> {
        #[pin]
        pub(crate) stream: KTlsStreamImpl<IO, KernelConnection<ServerConnectionData>>
    }
}

impl<IO> KTlsServerStream<IO>
where
    IO: AsyncWrite + AsyncRead + AsRawFd,
{
    pub async fn from_unbuffered_connnection(
        socket: IO,
        conn: UnbufferedServerConnection,
    ) -> Result<Self, TryConnectError<IO, UnbufferedServerConnection>> {
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

        Self::from_unbuffered_connection_validate(socket, Vec::new(), conn).await
    }

    async fn from_unbuffered_connection_validate(
        socket: IO,
        early_data: Vec<u8>,
        conn: UnbufferedServerConnection,
    ) -> Result<Self, TryConnectError<IO, UnbufferedServerConnection>> {
        // We validate ciphers here as a convenience to produce better errors.
        // We explicitly don't want to fail to create a kTLS cipher if probing
        // fails, since the probe failing doesn't necessarily mean that creating
        // this connection will fail.
        if let Ok(support) = CompatibleCiphers::new().await {
            let suite = conn.negotiated_cipher_suite().ok_or_else(|| {
                ConnectError::Handshake(rustls::Error::General(
                    "handshake completed but no negotiated cipher suite is present".into(),
                ))
            })?;

            if !support.is_compatible(suite) {
                return Err(TryConnectError {
                    error: ConnectError::UnsupportedCipherSuite(suite),
                    socket: Some(socket),
                    conn: Some(conn),
                });
            }
        }

        Ok(Self::from_unbuffered_connnection_with_tls_ulp_enabled(
            socket, early_data, conn,
        )?)
    }

    /// Create a new `KTlsServerStream` from a socket that already has had the TLS ULP
    /// enabled on it.
    fn from_unbuffered_connnection_with_tls_ulp_enabled(
        socket: IO,
        early_data: Vec<u8>,
        conn: UnbufferedServerConnection,
    ) -> Result<Self, ConnectError> {
        let (secrets, kconn) = match conn.dangerous_into_kernel_connection() {
            Ok(secrets) => secrets,
            Err(e) => return Err(ConnectError::ExtractSecrets(e)),
        };

        let suite = kconn.negotiated_cipher_suite();
        let tx = CryptoInfo::from_rustls(suite, secrets.tx)
            .map_err(|_| ConnectError::UnsupportedCipherSuite(suite))?;
        let rx = CryptoInfo::from_rustls(suite, secrets.rx)
            .map_err(|_| ConnectError::UnsupportedCipherSuite(suite))?;

        crate::ffi::setup_tls_info(socket.as_raw_fd(), Direction::Tx, tx)
            .map_err(ConnectError::IO)?;
        crate::ffi::setup_tls_info(socket.as_raw_fd(), Direction::Rx, rx)
            .map_err(ConnectError::IO)?;

        Ok(Self {
            stream: KTlsStreamImpl::new(socket, early_data, kconn),
        })
    }
}

impl<IO> AsyncRead for KTlsServerStream<IO>
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

impl<IO> AsyncWrite for KTlsServerStream<IO>
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

impl<IO> AsRawFd for KTlsServerStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}
