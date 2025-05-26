//! TLS protocol enums that are not publically exposed by rustls.

#![allow(non_upper_case_globals)]

use std::{fmt, io};

use tokio::io::{AsyncRead, ReadBuf};

macro_rules! c_enum {
    {
        $( #[$attr:meta] )*
        $vis:vis enum $name:ident: $repr:ty {
            $(
                $( #[$vattr:meta] )*
                $variant:ident = $value:expr
            ),* $(,)?
        }
    } => {
        $( #[$attr] )*
        #[repr(transparent)]
        $vis struct $name(pub $repr);

        impl $name {
            $(
                $( #[$vattr] )*
                pub const $variant: Self = Self($value);
            )*
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                $( const $variant: $repr = $name::$variant.0; )*

                let text = match self.0 {
                    $( $variant => concat!(stringify!($name), "::", stringify!($variant)), )*
                    _ => return f.debug_tuple(stringify!($name)).field(&self.0).finish()
                };

                f.write_str(text)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                $( const $variant: $repr = $name::$variant.0; )*

                let text = match self.0 {
                    $( $variant => stringify!($variant), )*
                    _ => return <$repr as fmt::Display>::fmt(&self.0, f)
                };

                f.write_str(text)
            }
        }

        impl From<$repr> for $name {
            fn from(value: $repr) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $repr {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    }
}

c_enum! {
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub(crate) enum AlertLevel: u8 {
        Warning = 1,
        Fatal = 2,
    }
}

c_enum! {
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub(crate) enum KeyUpdateRequest: u8 {
        UpdateNotRequested = 0,
        UpdateRequested = 1
    }
}

pub(crate) async fn read_record<IO>(stream: &mut IO, buf: &mut Vec<u8>) -> io::Result<()>
where
    IO: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let bytes: [u8; 5] = header.try_into().unwrap();
    buf.extend_from_slice(&header);

    let header = TlsHeader::decode(bytes);

    buf.reserve(header.len as usize);
    let new_len = buf.len() + header.len as usize;
    let mut rdbuf = ReadBuf::uninit(&mut buf.spare_capacity_mut()[..header.len as usize]);
  
    loop {
        let remaining = rdbuf.remaining();
        if remaining == 0 {
            break;
        }

        stream.read_buf(&mut rdbuf).await?;
        if rdbuf.remaining() == remaining {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }

    // SAFETY: If we get here we guarantee that rdbuf.remaining() == 0.
    //         ReadBuf's contract means that we can assume that it has
    //         been fully initialized under those conditions.
    unsafe { buf.set_len(new_len) };

    Ok(())
}

#[allow(dead_code)]
struct TlsHeader {
    ty: rustls::ContentType,
    version: rustls::ProtocolVersion,
    len: u16,
}

impl TlsHeader {
    pub fn decode(bytes: [u8; 5]) -> Self {
        let ty = rustls::ContentType::from(bytes[0]);
        let version = rustls::ProtocolVersion::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        let len = u16::from_be_bytes([bytes[3], bytes[4]]);

        Self { ty, version, len }
    }
}
