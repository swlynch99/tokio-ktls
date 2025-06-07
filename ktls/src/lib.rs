use rustls::{SupportedCipherSuite, SupportedProtocolVersion};

#[cfg(all(not(feature = "ring"), not(feature = "aws_lc_rs")))]
compile_error!("This crate needs wither the 'ring' or 'aws_lc_rs' feature enabled");
#[cfg(all(feature = "ring", feature = "aws_lc_rs"))]
compile_error!("The 'ring' and 'aws_lc_rs' features are mutually exclusive");
#[cfg(feature = "aws_lc_rs")]
use rustls::crypto::aws_lc_rs::cipher_suite;
#[cfg(feature = "ring")]
use rustls::crypto::ring::cipher_suite;

mod ffi;
pub use crate::ffi::CryptoInfo;

mod async_read_ready;
pub use async_read_ready::AsyncReadReady;

mod ktls_stream;
pub use ktls_stream::KtlsStream;

mod cork_stream;
pub use cork_stream::CorkStream;

mod client;
mod error;
mod generic;
mod protocol;
mod server;
mod stream;
mod suite;

pub use crate::client::KTlsClientStream;
pub use crate::error::{ConnectError, TryConnectError};
pub use crate::generic::KTlsStream;
pub use crate::server::{KTlsAcceptor, KTlsServerStream};
pub use crate::stream::{KTlsStreamError, Side};
pub use crate::suite::{CipherProbeError, CompatibleCiphers, CompatibleCiphersForVersion};

/// TLS versions supported by this crate
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum KtlsVersion {
    TLS12,
    TLS13,
}

impl KtlsVersion {
    /// Converts into the equivalent rustls [SupportedProtocolVersion]
    pub fn as_supported_version(&self) -> &'static SupportedProtocolVersion {
        match self {
            KtlsVersion::TLS12 => &rustls::version::TLS12,
            KtlsVersion::TLS13 => &rustls::version::TLS13,
        }
    }
}

/// A TLS cipher suite. Used mostly internally.
#[derive(Clone, Copy)]
pub struct KtlsCipherSuite {
    /// The TLS version
    pub version: KtlsVersion,

    /// The cipher type
    pub typ: KtlsCipherType,
}

/// Cipher types supported by this crate
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum KtlsCipherType {
    AesGcm128,
    AesGcm256,
    Chacha20Poly1305,
}

#[derive(Debug, thiserror::Error)]
pub enum CipherSuiteError {
    #[error("TLS 1.2 support not built in")]
    Tls12NotBuiltIn,

    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite(SupportedCipherSuite),
}

impl TryFrom<SupportedCipherSuite> for KtlsCipherSuite {
    type Error = CipherSuiteError;

    fn try_from(#[allow(unused)] suite: SupportedCipherSuite) -> Result<Self, Self::Error> {
        {
            let version = match suite {
                SupportedCipherSuite::Tls12(..) => {
                    if !cfg!(feature = "tls12") {
                        return Err(CipherSuiteError::Tls12NotBuiltIn);
                    }
                    KtlsVersion::TLS12
                }
                SupportedCipherSuite::Tls13(..) => KtlsVersion::TLS13,
            };

            let family = {
                if suite == cipher_suite::TLS13_AES_128_GCM_SHA256 {
                    KtlsCipherType::AesGcm128
                } else if suite == cipher_suite::TLS13_AES_256_GCM_SHA384 {
                    KtlsCipherType::AesGcm256
                } else if suite == cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 {
                    KtlsCipherType::Chacha20Poly1305
                } else if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
                    KtlsCipherType::AesGcm128
                } else if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
                    KtlsCipherType::AesGcm256
                } else if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
                    KtlsCipherType::Chacha20Poly1305
                } else {
                    return Err(CipherSuiteError::UnsupportedCipherSuite(suite));
                }
            };

            Ok(Self {
                typ: family,
                version,
            })
        }
    }
}

impl KtlsCipherSuite {
    pub fn as_supported_cipher_suite(&self) -> SupportedCipherSuite {
        match self.version {
            KtlsVersion::TLS12 => match self.typ {
                KtlsCipherType::AesGcm128 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                KtlsCipherType::AesGcm256 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                KtlsCipherType::Chacha20Poly1305 => {
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                }
            },
            KtlsVersion::TLS13 => match self.typ {
                KtlsCipherType::AesGcm128 => cipher_suite::TLS13_AES_128_GCM_SHA256,
                KtlsCipherType::AesGcm256 => cipher_suite::TLS13_AES_256_GCM_SHA384,
                KtlsCipherType::Chacha20Poly1305 => cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            },
        }
    }
}
