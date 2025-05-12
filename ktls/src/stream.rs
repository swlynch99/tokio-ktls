use rustls::{
    AlertDescription, ConnectionTrafficSecrets, ContentType, HandshakeType, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, SupportedCipherSuite,
};
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use rustls::kernel::KernelConnection;

use crate::ffi::{setup_tls_info, Cmsg, Direction};
use crate::protocol::{AlertLevel, KeyUpdateRequest};
use crate::CryptoInfo;

type KernelClientConnection = KernelConnection<rustls::client::ClientConnectionData>;
type KernelServerConnection = KernelConnection<rustls::server::ServerConnectionData>;

struct ConnectionData<Conn: ?Sized> {
    rx_messages_since_last_key_update: u64,
    tx_messages_since_last_key_update: u64,

    awaiting_key_update: bool,

    confidentiality_limit: u64,

    conn: Conn,
}

type ClientConnectionData = ConnectionData<KernelClientConnection>;
type ServerConnectionData = ConnectionData<KernelServerConnection>;

enum Side<Client, Server> {
    Client(Client),
    Server(Server),
}

enum BufferedData {
    EarlyData(OffsetVec),
    Scratch(Vec<u8>),
}

#[derive(Default)]
struct KTlsStreamState {
    write_closed: bool,
    read_closed: bool,
}

trait KTlsConnection: Send + Sync + 'static {
    fn as_side(&self) -> Side<&KernelClientConnection, &KernelServerConnection>;
    fn as_side_mut(&mut self) -> Side<&mut KernelClientConnection, &mut KernelServerConnection>;

    fn protocol_version(&self) -> ProtocolVersion {
        match self.as_side() {
            Side::Client(client) => client.protocol_version(),
            Side::Server(server) => server.protocol_version(),
        }
    }

    fn update_rx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), rustls::Error> {
        match self.as_side_mut() {
            Side::Client(client) => client.update_rx_secret(),
            Side::Server(server) => server.update_rx_secret(),
        }
    }

    fn update_tx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), rustls::Error> {
        match self.as_side_mut() {
            Side::Client(client) => client.update_tx_secret(),
            Side::Server(server) => server.update_tx_secret(),
        }
    }

    fn negotiated_cipher_suite(&self) -> SupportedCipherSuite {
        match self.as_side() {
            Side::Client(client) => client.negotiated_cipher_suite(),
            Side::Server(server) => server.negotiated_cipher_suite(),
        }
    }
}

impl KTlsConnection for KernelClientConnection {
    fn as_side(&self) -> Side<&KernelClientConnection, &KernelServerConnection> {
        Side::Client(self)
    }

    fn as_side_mut(&mut self) -> Side<&mut KernelClientConnection, &mut KernelServerConnection> {
        Side::Client(self)
    }
}

impl KTlsConnection for KernelServerConnection {
    fn as_side(&self) -> Side<&KernelClientConnection, &KernelServerConnection> {
        Side::Server(self)
    }

    fn as_side_mut(&mut self) -> Side<&mut KernelClientConnection, &mut KernelServerConnection> {
        Side::Server(self)
    }
}

pin_project_lite::pin_project! {
    #[project = KTlsStreamProject]
    pub(crate) struct KTlsStreamInner<IO, Conn: ?Sized> {
        #[pin]
        socket: IO,
        data: BufferedData,
        state: KTlsStreamState,

        // KernelConnection is quite large so we box it here to avoid excessively
        // increasing the size of `KTlsStream`.
        conn: Box<ConnectionData<Conn>>,
    }
}

/// Everything in [`KTlsStreamProject`] except `data`.
///
/// Due to the way we reuse the buffer in `data` we frequently need to be able
/// to borrow "everything except `data`" when implementing handling for control
/// messages.
struct KTlsStreamCoreProject<'a, IO, Conn: ?Sized> {
    socket: Pin<&'a mut IO>,
    state: &'a mut KTlsStreamState,
    conn: &'a mut Box<ConnectionData<Conn>>,
}

impl<IO> KTlsStreamInner<IO, KernelClientConnection> {
    /// Create a new client stream from a socket and [`KernelConnection`].
    ///
    /// This assumes that `socket` has already been initialized as a kTLS
    /// socket.
    pub(crate) fn new_client(socket: IO, conn: KernelClientConnection) -> Self {
        Self::new_inner(socket, Vec::new(), conn)
    }
}

impl<IO> KTlsStreamInner<IO, KernelServerConnection> {
    /// Create a new client stream from a socket and [`KernelConnection`].
    ///
    /// This assumes that `socket` has already been initialized as a kTLS
    /// socket. If early data was recieved in the handshake, then it should be
    /// passed in `early`, otherwise it should be empty.
    pub(crate) fn new_server(socket: IO, early: Vec<u8>, conn: KernelServerConnection) -> Self {
        Self::new_inner(socket, early, conn)
    }
}

impl<IO, Data> KTlsStreamInner<IO, KernelConnection<Data>> {
    fn new_inner(socket: IO, early: Vec<u8>, conn: KernelConnection<Data>) -> Self {
        let suite_common = match conn.negotiated_cipher_suite() {
            #[cfg(feature = "tls12")]
            rustls::SupportedCipherSuite::Tls12(suite) => &suite.common,
            rustls::SupportedCipherSuite::Tls13(suite) => &suite.common,
            _ => panic!("rustls has feature tls12 enabled but ktls does not"),
        };

        let data = if early.is_empty() {
            BufferedData::Scratch(early)
        } else {
            BufferedData::EarlyData(OffsetVec::new(early))
        };

        Self {
            socket,
            data,
            state: KTlsStreamState::default(),
            conn: Box::new(ConnectionData {
                // Use 16 as a safety margin to deal with messages that have
                // been sent after the handshake has been established.
                rx_messages_since_last_key_update: 16,
                tx_messages_since_last_key_update: 16,
                awaiting_key_update: false,
                confidentiality_limit: suite_common.confidentiality_limit,

                conn,
            }),
        }
    }
}

impl<IO, Conn: ?Sized> KTlsStreamInner<IO, Conn> {
    fn read_early_data(buffer: &mut BufferedData, buf: &mut ReadBuf<'_>) -> usize {
        let cursor = match buffer {
            BufferedData::EarlyData(cursor) => cursor,
            _ => return 0,
        };

        let count = cursor.read_buf(buf);
        if cursor.is_empty() {
            let mut scratch = std::mem::take(cursor).into_cleared_vec();
            scratch.shrink_to(DEFAULT_SCRATCH_CAPACITY);

            *buffer = BufferedData::Scratch(scratch);
        }

        count
    }
}

impl<IO, Conn: ?Sized> KTlsStreamInner<IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: KTlsConnection,
{
    pub(crate) fn handle_control_message(self: Pin<&mut Self>) -> io::Result<()> {
        let mut this = self.project();
        let (mut core, data) = this.as_core_parts();
        core.handle_control_message(data)
    }
}

impl<IO, Conn: ?Sized> KTlsStreamProject<'_, IO, Conn> {
    fn as_core_parts<'a>(
        &'a mut self,
    ) -> (KTlsStreamCoreProject<'a, IO, Conn>, &'a mut BufferedData) {
        (
            KTlsStreamCoreProject {
                socket: self.socket.as_mut(),
                state: self.state,
                conn: self.conn,
            },
            self.data,
        )
    }
}

impl<IO, Conn: ?Sized> KTlsStreamCoreProject<'_, IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: KTlsConnection,
{
    fn key_update(&mut self, request: KeyUpdateRequest) -> io::Result<()> {
        #[rustfmt::skip]
        let message = [
            HandshakeType::KeyUpdate.into(), //typ
            0, 0, 1, // length
            request.into()
        ];

        self.send_cmsg(ContentType::Handshake, &[io::IoSlice::new(&message)])?;

        if request == KeyUpdateRequest::UpdateRequested {
            self.conn.awaiting_key_update = true;
        }

        self.conn.tx_messages_since_last_key_update = 1;

        let (seq, secrets) = match self.conn.update_tx_secret() {
            Ok(secrets) => secrets,
            Err(e) => {
                return Err(self.abort_with_alert(
                    AlertDescription::InternalError,
                    KTlsError::KeyUpdateFailed(e),
                ));
            }
        };

        let crypto =
            match CryptoInfo::from_rustls(self.conn.conn.negotiated_cipher_suite(), (seq, secrets))
            {
                Ok(crypto) => crypto,
                Err(e) => {
                    let _ = self.abort(AlertDescription::InternalError);

                    // This should be impossible. We have already validated
                    // that the cipher is compatible during connection setup
                    // so it should not fail now.
                    panic!("negotiated TLS cipher is no longer compatible for key update: {e}")
                }
            };

        if let Err(e) = setup_tls_info(self.socket.as_raw_fd(), Direction::Tx, crypto) {
            // The other side of the connection won't be able to decrypt this but it will
            // cause them to abort the connection, which is good enough.
            let _ = self.abort(AlertDescription::InternalError);

            return Err(e);
        }

        Ok(())
    }

    fn handle_read_complete(&mut self, bytes: usize) -> io::Result<()> {
        let count = written.div_ceil(TLS_MAX_MESSAGE_LEN);
        self.conn.rx_messages_since_last_key_update += count;

        if self.conn.confidentiality_limit == u64::MAX {
            return Ok(());
        }

        let hard_limit = self.conn.confidentiality_limit - self.conn.confidentiality_limit / 32;
        let soft_limit = self.conn.confidentiality_limit / 2;

        if self.conn.rx_messages_since_last_key_update > hard_limit {
            let _ = self.abort(AlertDescription::InternalError);
            return Err(io::Error::other(
                KTlsStreamError::ConfidentialityLimitReached,
            ));
        }

        if !self.conn.awaiting_key_update
            && self.conn.rx_messages_since_last_key_update > soft_limit
        {
            // We actually need the peer to update their keys
            self.key_update(KeyUpdateRequest::UpdateRequested)?;
        }

        Ok(())
    }

    fn handle_write_complete(&mut self, bytes: usize) -> io::Result<()> {
        let count = written.div_ceil(TLS_MAX_MESSAGE_LEN);
        self.conn.tx_messages_since_last_key_update += count;

        if self.conn.confidentiality_limit == u64::MAX {
            return Ok(());
        }

        let hard_limit = self.conn.confidentiality_limit - self.conn.confidentiality_limit / 32;
        let soft_limit = self.conn.confidentiality_limit / 2;

        if self.conn.tx_messages_since_last_key_update > hard_limit {
            let _ = self.abort(AlertDescription::InternalError);
            return Err(io::Error::other(
                KTlsStreamError::ConfidentialityLimitReached,
            ));
        }

        if self.conn.rx_messages_since_last_key_update > soft_limit {
            let request = if self.conn.rx_messages_since_last_key_update > soft_limit / 2 {
                KeyUpdateRequest::UpdateRequested
            } else {
                KeyUpdateRequest::UpdateNotRequested
            };

            self.key_update(request)?;
        }

        Ok(())
    }

    fn handle_control_message(&mut self, buffered_data: &mut BufferedData) -> io::Result<()> {
        if self.state.read_closed {
            return Err(io::Error::other(KTlsStreamError::ConnectionShutDown));
        }

        let mut data = match buffered_data {
            BufferedData::EarlyData(_) => {
                panic!("all buffered application data must be handled before processing control messages")
            }
            BufferedData::Scratch(data) => ClearOnDrop(data),
        };

        let mut cmsg = Cmsg::new(0, 0, [0]);

        let flags = match crate::ffi::recvmsg_whole(
            self.socket.as_raw_fd(),
            &mut data,
            Some(&mut cmsg),
            libc::MSG_DONTWAIT,
        ) {
            Ok(flags) => flags,
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                // We should only ever get EAGAIN if there is no message available.
                assert!(
                    data.is_empty(),
                    "recvmsg returned EAGAIN after reading a partial record"
                );
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        if cmsg.level() != libc::SOL_TLS || cmsg.typ() != libc::TLS_GET_RECORD_TYPE {
            panic!(
                "recvmsg returned an unexpected control message (level = {}, type = {})",
                cmsg.level(),
                cmsg.typ()
            );
        }

        // This should never happen, since TLS_GET_RECORD_TYPE messages are always 1
        // byte
        debug_assert!(
            flags & libc::MSG_CTRUNC == 0,
            "recvmsg control message was truncated"
        );

        match ContentType::from(cmsg.data()[0]) {
            ContentType::ApplicationData => {
                // This shouldn't happen in normal operation but can happen when
                // users are directly calling handle_control_message.
                //
                // It's not ideal, but we can handle it.

                let buffer = std::mem::take(&mut *data);
                drop(data);
                *buffered_data = BufferedData::EarlyData(OffsetVec::new(buffer));
                return Ok(());
            }

            ContentType::Alert => {
                let (level, desc) = match &data[..] {
                    &[level, desc] => (level.into(), desc.into()),
                    _ => {
                        // The peer sent an invalid alert. We send back an error
                        // and close the connection.
                        return Err(self.abort_with_error(
                            AlertDescription::DecodeError,
                            InvalidMessage::MessageTooLarge,
                        ));
                    }
                };

                self.handle_alert(level, desc)?;
            }

            ContentType::Handshake => {
                self.handle_handshake(&data)?;
            }

            ContentType::ChangeCipherSpec => {
                // ChangeCipherSpec should only be sent under the following conditions:
                // - TLS 1.2: during a handshake or a rehandshake
                // - TLS 1.3: during a handshake
                //
                // We don't have to worry about handling messages during a handshake
                // and rustls does not support TLS 1.2 rehandshakes so we just emit
                // an error here and abort the connection.
                return Err(self.abort_with_error(
                    AlertDescription::UnexpectedMessage,
                    PeerMisbehaved::IllegalMiddleboxChangeCipherSpec,
                ));
            }

            // Any other message results in an error
            _ => {
                return Err(self.abort_with_error(
                    AlertDescription::UnexpectedMessage,
                    InvalidMessage::InvalidContentType,
                ))
            }
        }

        Ok(())
    }

    fn handle_alert(&mut self, level: AlertLevel, desc: AlertDescription) -> io::Result<()> {
        match desc {
            // The peer has closed their end of the connection. We close the read half
            // of the connection since we will receive no more data frames.
            AlertDescription::CloseNotify => {
                self.state.read_closed = true;
            }

            // TLS 1.2 allows alerts to be sent with a warning level without terminating
            // the connection. In this case we ignore the alert.
            _ if self.conn.conn.protocol_version() == ProtocolVersion::TLSv1_2
                && level == AlertLevel::Warning => {}

            // All other alerts are treated as fatal and result in us immediately shutting
            // down the connection and emitting an error.
            _ => {
                self.state.read_closed = true;
                self.state.write_closed = true;

                return Err(io::Error::other(KTlsStreamError::Alert(desc)));
            }
        }

        Ok(())
    }

    fn handle_handshake(&mut self, mut data: &[u8]) -> io::Result<()> {
        let mut first = true;

        while !data.is_empty() {
            let (ty, len, rest) = match data {
                &[ty, a, b, c, ref rest @ ..] => (
                    HandshakeType::from(ty),
                    u32::from_be_bytes([0, a, b, c]) as usize,
                    rest,
                ),
                _ => {
                    return Err(self.abort_with_error(
                        AlertDescription::DecodeError,
                        InvalidMessage::MessageTooShort,
                    ))
                }
            };

            if len > rest.len() {
                return Err(self.abort_with_error(
                    AlertDescription::DecodeError,
                    InvalidMessage::MessageTooShort,
                ));
            }

            let (msg, rest) = rest.split_at(len);
            data = rest;

            // KeyUpdate messages must be the only sub-message within their message.
            if ty == HandshakeType::KeyUpdate
                && self.conn.protocol_version() == ProtocolVersion::TLSv1_3
            {
                if !first || !data.is_empty() {
                    return Err(self.abort_with_alert(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::KeyEpochWithPendingFragment,
                    ));
                }
            }

            self.handle_single_handshake(typ, msg)?;
            first = false;
        }

        Ok(())
    }

    fn handle_single_handshake(&mut self, typ: HandshakeType, data: &[u8]) -> io::Result<()> {
        match typ {
            HandshakeType::KeyUpdate
                if self.conn.conn.protocol_version() == ProtocolVersion::TLSv1_3 =>
            {
                let req = match data {
                    &[req] => KeyUpdateRequest::from(req),
                    _ => {
                        return Err(self.abort_with_error(
                            AlertDescription::DecodeError,
                            InvalidMessage::InvalidKeyUpdate,
                        ))
                    }
                };

                let (seq, secrets) = match self.conn.conn.update_rx_secret() {
                    Ok(secrets) => secrets,
                    Err(e) => {
                        return Err(self.abort_with_error(
                            AlertDescription::InternalError,
                            KTlsStreamError::KeyUpdateFailed(e),
                        ))
                    }
                };

                let crypto = match CryptoInfo::from_rustls(
                    self.conn.conn.negotiated_cipher_suite(),
                    (seq, secrets),
                ) {
                    Ok(crypto) => crypto,
                    Err(e) => {
                        let _ = self.abort(AlertDescription::InternalError);

                        // This should be impossible. We have already validated
                        // that the cipher is compatible during connection setup
                        // so it should not fail now.
                        panic!("negotiated TLS cipher is no longer compatible for key update: {e}")
                    }
                };

                if let Err(e) = setup_tls_info(self.socket.as_raw_fd(), Direction::Rx, crypto) {
                    // If setup_tls_info fails then the connection is done for,
                    // so we just an alert.
                    let _ = self.abort(AlertDescription::InternalError);
                    return Err(e);
                }

                match req {
                    KeyUpdateRequest::UpdateNotRequested => return Ok(()),
                    KeyUpdateRequest::UpdateRequested => (),
                    _ => {
                        return Err(self.abort_with_error(
                            AlertDescription::IllegalParameter,
                            InvalidMessage::InvalidKeyUpdate,
                        ));
                    }
                }

                self.key_update(KeyUpdateRequest::UpdateNotRequested)?;
            }

            HandshakeType::NewSessionTicket
                if self.conn.conn.protocol_version() == ProtocolVersion::TLSv1_3 =>
            {
                match self.conn.conn.as_side() {
                    Side::Client(conn) => match conn.handle_new_session_ticket(data) {
                        Ok(()) => (),
                        // Convert some messages into their higher-level equivalents
                        Err(rustls::Error::InvalidMessage(err)) => {
                            return Err(self.abort_with_error(AlertDescription::DecodeError, err));
                        }
                        Err(rustls::Error::PeerMisbehaved(err)) => {
                            return Err(
                                self.abort_with_error(AlertDescription::UnexpectedMessage, err)
                            );
                        }

                        // Other errors are not necessarily fatal
                        Err(e) => return Err(KTlsStreamError::SessionTicketFailed(e)),
                    },
                    Side::Server(_) => {
                        return Err(self.abort_with_error(
                            AlertDescription::UnexpectedMessage,
                            InvalidMessage::UnexpectedMessage(
                                "TLS 1.2 peer sent a TLS 1.3 NewSessionTicket message",
                            ),
                        ))
                    }
                }
            }

            _ => {
                return match self.conn.conn.protocol_version() {
                    ProtocolVersion::TLSv1_3 => self.abort_with_error(
                        AlertDescription::UnexpectedMessage,
                        InvalidMessage::UnexpectedMessage(
                            "expected KeyUpdate or NewSessionTicket handshake messages only",
                        ),
                    ),
                    _ => self.abort_with_error(
                        AlertDescription::UnexpectedMessage,
                        InvalidMessage::UnexpectedMessage(
                            "handshake messages are not expected on TLS 1.2 connections",
                        ),
                    ),
                }
            }
        }

        Ok(())
    }

    fn abort(&mut self, alert: AlertDescription) -> io::Result<()> {
        let write_closed = self.state.write_closed;

        self.state.read_closed = true;
        self.state.write_closed = true;

        if !write_closed {
            self.send_alert(AlertLevel::Fatal, alert)?;
        }

        Ok(())
    }

    fn abort_with_error(
        &mut self,
        alert: AlertDescription,
        error: impl Into<KTlsStreamError>,
    ) -> io::Error {
        // We don't propagate any errors here since we already have an existing error.
        let _ = self.abort(alert);

        io::Error::other(error.into())
    }

    fn send_alert(&self, level: AlertLevel, desc: AlertDescription) -> io::Result<()> {
        let message = [level.into(), desc.into()];
        let iov = [io::IoSlice::new(&message)];

        self.send_cmsg(ContentType::Alert, &iov)
    }

    fn shutdown(&self) -> io::Result<()> {
        self.state.write_closed = true;
        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify)?;
        Ok(())
    }

    fn send_cmsg(&self, typ: ContentType, data: &[io::IoSlice<'_>]) -> io::Result<()> {
        self.conn.tx_messages_since_last_key_update += 1;

        let cmsg = Cmsg::new(libc::SOL_TLS, libc::TLS_SET_RECORD_TYPE, [typ.into()]);
        // TODO: Should an error here abort the whole connection?
        crate::ffi::sendmsg(self.socket.as_raw_fd(), data, Some(&cmsg), 0)?;
        Ok(())
    }
}

impl<IO, Conn: ?Sized> AsyncRead for KTlsStreamInner<IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: KTlsConnection,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        if matches!(this.data, BufferedData::EarlyData(_)) {
            match Self::read_early_data(this.data, buf) {
                0 => (),
                _ => return Poll::Ready(Ok(())),
            }
        }

        // We want to gracefully handle control messages, but we don't want to
        // hold up the task if there are lots of them.
        for _ in 0..4 {
            if this.state.read_closed {
                return Poll::Ready(Ok(()));
            }

            let start = buf.filled().len();
            match this.socket.as_mut().poll_read(cx, buf) {
                // Linux returns EIO when there is a control message to be read
                // but there is no CMsg space to write to.
                //
                // If we get this as an error it means there is a control message
                // that we need to handle.
                Poll::Ready(Err(e)) if e.raw_os_error() == Some(libc::EIO) => (),
                poll @ Poll::Ready(Ok(())) => {
                    let end = buf.filled().len();
                    let written = end.checked_sub(start).unwrap_or(buf.capacity());

                    this.as_core_parts().0.handle_read_complete(written)?;
                }
                poll => return poll,
            }

            let (mut core, data) = this.as_core_parts();
            core.handle_control_message(data)?;
        }

        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<IO, Conn: ?Sized> AsyncWrite for KTlsStreamInner<IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: KTlsConnection,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        if this.state.write_closed {
            return Poll::Ready(Ok(0));
        }

        match this.socket.poll_write(cx, buf) {
            poll @ Poll::Ready(Ok(bytes)) => {
                this.as_core_parts().0.handle_write_complete(bytes)?;
            }
            poll => poll,
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        if this.state.write_closed {
            return Poll::Ready(Ok(0));
        }

        match this.socket.poll_write_vectored(cx, buf) {
            poll @ Poll::Ready(Ok(bytes)) => {
                this.as_core_parts().0.handle_write_complete(bytes)?;
            }
            poll => poll,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        this.socket.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        if !this.state.write_closed {
            if let Err(e) = this.as_core_parts().0.shutdown() {
                return Poll::Ready(Err(e));
            }
        }

        this.socket.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }
}

#[derive(Default)]
struct OffsetVec {
    data: Vec<u8>,
    offset: usize,
}

impl OffsetVec {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.offset == self.data.len()
    }

    pub fn into_cleared_vec(mut self) -> Vec<u8> {
        self.data.clear();
        self.data
    }

    pub fn read_buf(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let tail = &self.data[self.offset..];
        let removed = &tail[..tail.len().min(buf.remaining())];
        buf.put_slice(removed);
        self.offset += removed.len();
        removed.len()
    }
}

struct ClearOnDrop<'a>(&'a mut Vec<u8>);

impl Deref for ClearOnDrop<'_> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl DerefMut for ClearOnDrop<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

const DEFAULT_SCRATCH_CAPACITY: usize = 256;
const TLS_MAX_MESSAGE_LEN: usize = 1 << 14;

#[derive(Debug, thiserror::Error)]
enum KTlsStreamError {
    #[error("received corrupt message of type {0:?}")]
    InvalidMessage(InvalidMessage),

    #[error("peer misbehaved: {0:?}")]
    PeerMisbehaved(PeerMisbehaved),

    #[error("{0}")]
    KeyUpdateFailed(#[source] rustls::Error),

    #[error("failed to handle a provided session ticket: {0}")]
    SessionTicketFailed(#[source] rustls::Error),

    #[error("the connection has been shut down")]
    ConnectionShutDown,

    #[error("the connection has reached its confidentiality limit and has been shut down")]
    ConfidentialityLimitReached,

    #[error("connection peer closed the connection with an alert: {0:?}")]
    Alert(AlertDescription),
}

impl From<InvalidMessage> for KTlsStreamError {
    fn from(error: InvalidMessage) -> Self {
        Self::InvalidMessage(error)
    }
}

impl From<PeerMisbehaved> for KTlsStreamError {
    fn from(error: PeerMisbehaved) -> Self {
        Self::PeerMisbehaved(error)
    }
}
