use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicU32;
use std::sync::OnceLock;

use ktls_sys::bindings as sys;
use rustls::CipherSuite;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OnceCell;

use crate::ffi::{CryptoInfo, Direction};
use crate::{KtlsCipherSuite, KtlsCipherType, KtlsVersion};

#[derive(Debug, Default)]
pub struct CompatibleCiphers {
    pub tls12: CompatibleCiphersForVersion,
    pub tls13: CompatibleCiphersForVersion,
}

#[derive(Debug, Default)]
pub struct CompatibleCiphersForVersion {
    pub aes_gcm_128: bool,
    pub aes_gcm_256: bool,
    pub chacha20_poly1305: bool,
}

static COMPATIBLE: OnceCell<CompatibleCiphers> = OnceCell::new();

impl CompatibleCiphers {
    /// List compatible ciphers. This listens on a TCP socket and blocks for a
    /// little while. Do once at the very start of a program. Should probably be
    /// behind a lazy_static / once_cell
    pub async fn new() -> Result<Self, CipherProbeError> {
        COMPATIBLE.get_or_try_init(Self::probe()).await
    }

    /// Returns true if we're reasonably confident that functions like
    /// [config_ktls_client] and [config_ktls_server] will succeed.
    pub fn is_compatible(&self, suite: SupportedCipherSuite) -> bool {
        let kcs = match KtlsCipherSuite::try_from(suite) {
            Ok(kcs) => kcs,
            Err(_) => return false,
        };

        let fields = match kcs.version {
            KtlsVersion::TLS12 => &self.tls12,
            KtlsVersion::TLS13 => &self.tls13,
        };

        match kcs.typ {
            KtlsCipherType::AesGcm128 => fields.aes_gcm_128,
            KtlsCipherType::AesGcm256 => fields.aes_gcm_256,
            KtlsCipherType::Chacha20Poly1305 => fields.chacha20_poly1305,
        }
    }

    async fn probe() -> Result<Self, CipherProbeError> {
        let mut listener =
            TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .map_err(CipherProbeError::Listener)?;
        let local_addr = listener.local_addr().map_err(CipherProbeError::Listener)?;

        Ok(Self {
            tls12: CompatibleCiphersForVersion {
                aes_gcm_128: Self::probe_suite(
                    &mut listener,
                    local_addr,
                    KtlsVersion::TLS12,
                    KtlsCipherType::AesGcm128,
                )
                .await?,
                aes_gcm_256: Self::probe_suite(
                    &mut listener,
                    local_addr,
                    KtlsVersion::TLS12,
                    KtlsCipherType::AesGcm256,
                )
                .await?,
                chacha20_poly1305: Self::probe_suite(
                    &mut listener,
                    local_addr,
                    KtlsVersion::TLS12,
                    KtlsCipherType::Chacha20Poly1305,
                )
                .await?,
            },
            tls13: CompatibleCiphersForVersion {
                aes_gcm_128: Self::probe_suite(
                    &mut listener,
                    local_addr,
                    KtlsVersion::TLS13,
                    KtlsCipherType::AesGcm128,
                )
                .await?,
                aes_gcm_256: Self::probe_suite(
                    &mut listener,
                    local_addr,
                    KtlsVersion::TLS13,
                    KtlsCipherType::AesGcm256,
                )
                .await?,
                chacha20_poly1305: Self::probe_suite(
                    &mut listener,
                    local_addr,
                    KtlsVersion::TLS13,
                    KtlsCipherType::Chacha20Poly1305,
                )
                .await?,
            },
        })
    }

    async fn probe_suite(
        listener: &mut TcpListener,
        local_addr: SocketAddr,
        version: KtlsVersion,
        suite: KtlsCipherType,
    ) -> Result<bool, CipherProbeError> {
        let stream = TcpStream::connect(local_addr)
            .await
            .map_err(CipherProbeError::Connect)?;
        let _other = listener
            .accept()
            .await
            .map_err(CipherProbeError::Listener)?;

        let version = match version {
            KtlsVersion::TLS12 => crate::ffi::TLS_1_2_VERSION_NUMBER,
            KtlsVersion::TLS13 => crate::ffi::TLS_1_3_VERSION_NUMBER,
        };

        let crypto_info = match kcs.typ {
            KtlsCipherType::AesGcm128 => {
                CryptoInfo::AesGcm128(sys::tls12_crypto_info_aes_gcm_128 {
                    info: sys::tls_crypto_info {
                        version: ffi_version,
                        cipher_type: sys::TLS_CIPHER_AES_GCM_128 as _,
                    },
                    ..Default::default()
                })
            }
            KtlsCipherType::AesGcm256 => {
                CryptoInfo::AesGcm256(sys::tls12_crypto_info_aes_gcm_256 {
                    info: sys::tls_crypto_info {
                        version: ffi_version,
                        cipher_type: sys::TLS_CIPHER_AES_GCM_256 as _,
                    },
                    ..Default::default()
                })
            }
            KtlsCipherType::Chacha20Poly1305 => {
                CryptoInfo::Chacha20Poly1305(sys::tls12_crypto_info_chacha20_poly1305 {
                    info: sys::tls_crypto_info {
                        version: ffi_version,
                        cipher_type: sys::TLS_CIPHER_CHACHA20_POLY1305 as _,
                    },
                    ..Default::default()
                })
            }
        };

        let fd = stream.as_raw_fd();

        match crate::ffi::setup_ulp(fd) {
            Ok(()) => (),
            // Interpret the kernel not supporting kTLS as the suite not being supported.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
            Err(e) => return Err(CipherProbeError::Ulp(e)),
        }

        Ok(crate::ffi::setup_tls_info(fd, Direction::Tx, crypto_info).is_ok())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CipherProbeError {
    #[error("failed to listen on a local socket: {0}")]
    Listener(#[source] io::Error),

    #[error("failed to connect to the local socket: {0}")]
    Connect(#[source] io::Error),

    #[error("failed to set up the TLS upper-level-protocol on the socket: {0}")]
    Ulp(#[source] io::Error),
}

fn sample_cipher_setup(sock: &TcpStream, cipher_suite: SupportedCipherSuite) -> Result<(), Error> {
    let kcs = match KtlsCipherSuite::try_from(cipher_suite) {
        Ok(kcs) => kcs,
        Err(_) => panic!("unsupported cipher suite"),
    };

    let ffi_version = match kcs.version {
        KtlsVersion::TLS12 => ffi::TLS_1_2_VERSION_NUMBER,
        KtlsVersion::TLS13 => ffi::TLS_1_3_VERSION_NUMBER,
    };

    let crypto_info = match kcs.typ {
        KtlsCipherType::AesGcm128 => CryptoInfo::AesGcm128(sys::tls12_crypto_info_aes_gcm_128 {
            info: sys::tls_crypto_info {
                version: ffi_version,
                cipher_type: sys::TLS_CIPHER_AES_GCM_128 as _,
            },
            iv: Default::default(),
            key: Default::default(),
            salt: Default::default(),
            rec_seq: Default::default(),
        }),
        KtlsCipherType::AesGcm256 => CryptoInfo::AesGcm256(sys::tls12_crypto_info_aes_gcm_256 {
            info: sys::tls_crypto_info {
                version: ffi_version,
                cipher_type: sys::TLS_CIPHER_AES_GCM_256 as _,
            },
            iv: Default::default(),
            key: Default::default(),
            salt: Default::default(),
            rec_seq: Default::default(),
        }),
        KtlsCipherType::Chacha20Poly1305 => {
            CryptoInfo::Chacha20Poly1305(sys::tls12_crypto_info_chacha20_poly1305 {
                info: sys::tls_crypto_info {
                    version: ffi_version,
                    cipher_type: sys::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: Default::default(),
                key: Default::default(),
                salt: Default::default(),
                rec_seq: Default::default(),
            })
        }
    };
    let fd = sock.as_raw_fd();

    setup_ulp(fd).map_err(Error::UlpError)?;

    setup_tls_info(fd, ffi::Direction::Tx, crypto_info).map_err(Error::TlsCryptoInfoError)?;

    Ok(())
}
