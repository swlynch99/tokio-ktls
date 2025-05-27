use std::{fmt, io};

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
pub struct TryConnectError<IO, Conn> {
    #[source]
    pub error: ConnectError,
    pub socket: Option<IO>,
    pub conn: Option<Conn>,
}

impl<IO, Conn> fmt::Debug for TryConnectError<IO, Conn> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TryConnectError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<IO, Conn> From<ConnectError> for TryConnectError<IO, Conn> {
    fn from(error: ConnectError) -> Self {
        Self {
            error,
            socket: None,
            conn: None,
        }
    }
}
