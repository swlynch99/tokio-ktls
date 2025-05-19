use std::{ffi::c_void, io, os::unix::prelude::RawFd};

use ktls_sys::bindings as ktls;
use rustls::{
    internal::msgs::{enums::AlertLevel, message::Message},
    AlertDescription, ConnectionTrafficSecrets, SupportedCipherSuite,
};

pub(crate) const TLS_1_2_VERSION_NUMBER: u16 = (((ktls::TLS_1_2_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_2_VERSION_MINOR & 0xFF) as u16);

pub(crate) const TLS_1_3_VERSION_NUMBER: u16 = (((ktls::TLS_1_3_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_3_VERSION_MINOR & 0xFF) as u16);

/// `setsockopt` level constant: TCP
const SOL_TCP: libc::c_int = 6;

/// `setsockopt` SOL_TCP name constant: "upper level protocol"
const TCP_ULP: libc::c_int = 31;

/// `setsockopt` level constant: TLS
const SOL_TLS: libc::c_int = 282;

/// `setsockopt` SOL_TLS level constant: transmit (write)
const TLS_TX: libc::c_int = 1;

/// `setsockopt` SOL_TLS level constant: receive (read)
const TLX_RX: libc::c_int = 2;

pub fn setup_ulp(fd: RawFd) -> std::io::Result<()> {
    unsafe {
        if libc::setsockopt(
            fd,
            SOL_TCP,
            TCP_ULP,
            "tls".as_ptr() as *const libc::c_void,
            3,
        ) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    // Transmit
    Tx,
    // Receive
    Rx,
}

impl From<Direction> for libc::c_int {
    fn from(val: Direction) -> Self {
        match val {
            Direction::Tx => TLS_TX,
            Direction::Rx => TLX_RX,
        }
    }
}

#[allow(dead_code)]
pub enum CryptoInfo {
    AesGcm128(ktls::tls12_crypto_info_aes_gcm_128),
    AesGcm256(ktls::tls12_crypto_info_aes_gcm_256),
    AesCcm128(ktls::tls12_crypto_info_aes_ccm_128),
    Chacha20Poly1305(ktls::tls12_crypto_info_chacha20_poly1305),
    Sm4Gcm(ktls::tls12_crypto_info_sm4_gcm),
    Sm4Ccm(ktls::tls12_crypto_info_sm4_ccm),
}

impl CryptoInfo {
    /// Return the system struct as a pointer.
    pub fn as_ptr(&self) -> *const libc::c_void {
        match self {
            CryptoInfo::AesGcm128(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::AesGcm256(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::AesCcm128(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::Chacha20Poly1305(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::Sm4Gcm(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::Sm4Ccm(info) => info as *const _ as *const libc::c_void,
        }
    }

    /// Return the system struct size.
    pub fn size(&self) -> usize {
        match self {
            CryptoInfo::AesGcm128(_) => std::mem::size_of::<ktls::tls12_crypto_info_aes_gcm_128>(),
            CryptoInfo::AesGcm256(_) => std::mem::size_of::<ktls::tls12_crypto_info_aes_gcm_256>(),
            CryptoInfo::AesCcm128(_) => std::mem::size_of::<ktls::tls12_crypto_info_aes_ccm_128>(),
            CryptoInfo::Chacha20Poly1305(_) => {
                std::mem::size_of::<ktls::tls12_crypto_info_chacha20_poly1305>()
            }
            CryptoInfo::Sm4Gcm(_) => std::mem::size_of::<ktls::tls12_crypto_info_sm4_gcm>(),
            CryptoInfo::Sm4Ccm(_) => std::mem::size_of::<ktls::tls12_crypto_info_sm4_ccm>(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KtlsCompatibilityError {
    #[error("cipher suite not supported with kTLS: {0:?}")]
    UnsupportedCipherSuite(SupportedCipherSuite),

    #[error("wrong size key")]
    WrongSizeKey,

    #[error("wrong size iv")]
    WrongSizeIv,
}

impl CryptoInfo {
    /// Try to convert rustls cipher suite and secrets into a `CryptoInfo`.
    pub fn from_rustls(
        cipher_suite: SupportedCipherSuite,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> Result<CryptoInfo, KtlsCompatibilityError> {
        let version = match cipher_suite {
            SupportedCipherSuite::Tls12(..) => TLS_1_2_VERSION_NUMBER,
            SupportedCipherSuite::Tls13(..) => TLS_1_3_VERSION_NUMBER,
        };

        Ok(match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                // see https://github.com/rustls/rustls/issues/1833, between
                // rustls 0.21 and 0.22, the extract_keys codepath was changed,
                // so, for TLS 1.2, both GCM-128 and GCM-256 return the
                // Aes128Gcm variant.

                match key.as_ref().len() {
                    16 => CryptoInfo::AesGcm128(ktls::tls12_crypto_info_aes_gcm_128 {
                        info: ktls::tls_crypto_info {
                            version,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_128 as _,
                        },
                        iv: iv
                            .as_ref()
                            .get(4..)
                            .expect("AES-GCM-128 iv is 8 bytes")
                            .try_into()
                            .expect("AES-GCM-128 iv is 8 bytes"),
                        key: key
                            .as_ref()
                            .try_into()
                            .expect("AES-GCM-128 key is 16 bytes"),
                        salt: iv
                            .as_ref()
                            .get(..4)
                            .expect("AES-GCM-128 salt is 4 bytes")
                            .try_into()
                            .expect("AES-GCM-128 salt is 4 bytes"),
                        rec_seq: seq.to_be_bytes(),
                    }),
                    32 => CryptoInfo::AesGcm256(ktls::tls12_crypto_info_aes_gcm_256 {
                        info: ktls::tls_crypto_info {
                            version,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_256 as _,
                        },
                        iv: iv
                            .as_ref()
                            .get(4..)
                            .expect("AES-GCM-256 iv is 8 bytes")
                            .try_into()
                            .expect("AES-GCM-256 iv is 8 bytes"),
                        key: key
                            .as_ref()
                            .try_into()
                            .expect("AES-GCM-256 key is 32 bytes"),
                        salt: iv
                            .as_ref()
                            .get(..4)
                            .expect("AES-GCM-256 salt is 4 bytes")
                            .try_into()
                            .expect("AES-GCM-256 salt is 4 bytes"),
                        rec_seq: seq.to_be_bytes(),
                    }),
                    _ => unreachable!("GCM key length is not 16 or 32"),
                }
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                CryptoInfo::AesGcm256(ktls::tls12_crypto_info_aes_gcm_256 {
                    info: ktls::tls_crypto_info {
                        version,
                        cipher_type: ktls::TLS_CIPHER_AES_GCM_256 as _,
                    },
                    iv: iv
                        .as_ref()
                        .get(4..)
                        .expect("AES-GCM-256 iv is 8 bytes")
                        .try_into()
                        .expect("AES-GCM-256 iv is 8 bytes"),
                    key: key
                        .as_ref()
                        .try_into()
                        .expect("AES-GCM-256 key is 32 bytes"),
                    salt: iv
                        .as_ref()
                        .get(..4)
                        .expect("AES-GCM-256 salt is 4 bytes")
                        .try_into()
                        .expect("AES-GCM-256 salt is 4 bytes"),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                CryptoInfo::Chacha20Poly1305(ktls::tls12_crypto_info_chacha20_poly1305 {
                    info: ktls::tls_crypto_info {
                        version,
                        cipher_type: ktls::TLS_CIPHER_CHACHA20_POLY1305 as _,
                    },
                    iv: iv
                        .as_ref()
                        .try_into()
                        .expect("Chacha20-Poly1305 iv is 12 bytes"),
                    key: key
                        .as_ref()
                        .try_into()
                        .expect("Chacha20-Poly1305 key is 32 bytes"),
                    salt: ktls::__IncompleteArrayField::new(),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            _ => {
                return Err(KtlsCompatibilityError::UnsupportedCipherSuite(cipher_suite));
            }
        })
    }
}

pub fn setup_tls_info(fd: RawFd, dir: Direction, info: CryptoInfo) -> io::Result<()> {
    let ret = unsafe { libc::setsockopt(fd, SOL_TLS, dir.into(), info.as_ptr(), info.size() as _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const ALERT: u8 = 0x15;

// Yes, really. cmsg components are aligned to [libc::c_long]
pub(crate) struct Cmsg<const N: usize> {
    _align: [libc::c_ulong; 0],
    hdr: libc::cmsghdr,
    data: [u8; N],
}

impl<const N: usize> Cmsg<N> {
    pub(crate) fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
        Self {
            hdr: libc::cmsghdr {
                // on Linux this is a usize, on macOS this is a u32
                #[allow(clippy::unnecessary_cast)]
                cmsg_len: (memoffset::offset_of!(Self, data) + N) as _,
                cmsg_level: level,
                cmsg_type: typ,
            },
            data,
            _align: [],
        }
    }

    pub(crate) fn level(&self) -> i32 {
        self.hdr.cmsg_level
    }

    pub(crate) fn typ(&self) -> i32 {
        self.hdr.cmsg_type
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data[..self.hdr.cmsg_len.min(N)]
    }
}

pub fn send_close_notify(fd: RawFd) -> std::io::Result<()> {
    let mut data = vec![];
    Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
        .payload
        .encode(&mut data);

    let mut cmsg = Cmsg::new(SOL_TLS, TLS_SET_RECORD_TYPE, [ALERT]);

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut libc::iovec {
            iov_base: data.as_mut_ptr() as _,
            iov_len: data.len(),
        },
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as *mut _,
        msg_controllen: cmsg.hdr.cmsg_len,
        msg_flags: 0,
    };

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A wrapper around [`libc::sendmsg`].
pub(crate) fn sendmsg<const N: usize>(
    fd: RawFd,
    data: &[io::IoSlice<'_>],
    cmsg: Option<&Cmsg<N>>,
    flags: i32,
) -> io::Result<usize> {
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    if let Some(cmsg) = cmsg {
        msg.msg_control = cmsg as *const _ as *mut c_void;
        msg.msg_controllen = std::mem::size_of_val(cmsg);
    }

    msg.msg_iov = data.as_ptr() as *const _ as *mut libc::iovec;
    msg.msg_iovlen = data.len();

    let ret = unsafe { libc::sendmsg(fd, &msg, flags) };
    match ret {
        -1 => Err(io::Error::last_os_error()),
        len => Ok(len as usize),
    }
}

/// Use [`libc::recvmsg`] to receive a whole message (with optional control
/// message).
///
/// This will repeatedly call `recvmsg` until it reaches the end of the current
/// record.
pub(crate) fn recvmsg_whole<const N: usize>(
    fd: RawFd,
    data: &mut Vec<u8>,
    mut cmsg: Option<&mut Cmsg<N>>,
    flags: i32,
) -> io::Result<i32> {
    if data.capacity() < 16 {
        data.reserve(16);
    }

    loop {
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        if let Some(cmsg) = cmsg.as_deref_mut() {
            msg.msg_control = cmsg as *mut _ as *mut c_void;
            msg.msg_controllen = std::mem::size_of_val(cmsg);
        }

        if data.spare_capacity_mut().is_empty() {
            data.reserve(128);
        }

        let spare = data.spare_capacity_mut();
        let mut iov = libc::iovec {
            iov_base: spare.as_mut_ptr() as *mut c_void,
            iov_len: spare.len(),
        };

        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        // SAFETY: We have made sure to initialize msg with valid pointers (or NULL).
        let ret = unsafe { libc::recvmsg(fd, &mut msg, flags) };
        let count = match ret {
            -1 => return Err(io::Error::last_os_error()),
            len => len as usize,
        };

        // SAFETY: recvmsg has just written count to the bytes in the spare capacity of
        //         the vector.
        unsafe { data.set_len(data.len() + count) };

        if msg.msg_flags & libc::MSG_EOR != 0 {
            break Ok(msg.msg_flags);
        }
    }
}
