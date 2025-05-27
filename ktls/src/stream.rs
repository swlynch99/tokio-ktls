use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use rustls::kernel::KernelConnection;
use rustls::{
    AlertDescription, ConnectionTrafficSecrets, ContentType, HandshakeType, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, SupportedCipherSuite,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ffi::{setup_tls_info, Cmsg, Direction};
use crate::protocol::{AlertLevel, KeyUpdateRequest};
use crate::CryptoInfo;

type KernelClientConnection = KernelConnection<rustls::client::ClientConnectionData>;
type KernelServerConnection = KernelConnection<rustls::server::ServerConnectionData>;

pin_project_lite::pin_project! {
    /// A generic kTLS stream.
    ///
    /// Most of the behaviour is identical between client and server streams so
    /// this type allows either. In the cases where there is a difference, the
    /// [`StreamSide`] trait is used to get the correct side of the stream.
    #[project = KTlsStreamProject]
    pub(crate) struct KTlsStreamImpl<IO, Conn: ?Sized> {
        #[pin]
        socket: IO,
        state: StreamState,
        data: Box<StreamData<Conn>>,
    }
}

impl<IO, Conn> KTlsStreamImpl<IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: ?Sized,
    StreamData<Conn>: StreamSide,
{
    pub(crate) fn new(socket: IO, early_data: Vec<u8>, conn: Conn) -> Self
    where
        Conn: Sized,
    {
        let (state, buffer) = match () {
            _ if !early_data.is_empty() => (StreamState::EARLY_DATA, early_data),
            _ if early_data.capacity() != 0 => (StreamState::default(), early_data),
            _ => (
                StreamState::default(),
                Vec::with_capacity(DEFAULT_SCRATCH_CAPACITY),
            ),
        };

        Self {
            socket,
            state,
            data: Box::new(StreamData {
                buffer,
                offset: 0,
                conn,
            }),
        }
    }
}

impl<IO, Conn> KTlsStreamProject<'_, IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: ?Sized,
    StreamData<Conn>: StreamSide,
{
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.state.early_data() {
            if self.poll_read_early_data(buf) != 0 {
                return Poll::Ready(Ok(()));
            }
        }

        for _ in 0..4 {
            if self.state.read_closed() {
                return Poll::Ready(Ok(()));
            }

            match self.socket.as_mut().poll_read(cx, buf) {
                // Linux returns EIO when there is a control message to be read
                // but there is no CMsg space to write to.
                //
                // If we get this as an error it means there is a control message
                // that we need to handle.
                Poll::Ready(Err(e)) if e.raw_os_error() == Some(libc::EIO) => (),
                poll => return poll,
            }

            self.handle_control_message()?;
        }

        // We've already handled multiple control messages with this poll, yield
        // for now but arrange to be woken up right away.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_read_early_data(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let data = &self.data.buffer[self.data.offset..];

        let available = buf.remaining();
        let data = &data[..available.min(data.len())];
        buf.put_slice(data);

        let len = data.len();
        self.data.offset += data.len();
        if self.data.offset == self.data.buffer.len() {
            self.data.buffer.clear();
            self.data.offset = 0;
            *self.state &= !StreamState::EARLY_DATA;

            self.data.buffer.shrink_to(MAX_SCRATCH_CAPACITY);
        }

        len
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.state.contains(StreamState::PENDING_CLOSE) {
            std::task::ready!(self.poll_do_close(cx))?;
        }

        if self.state.write_closed() {
            return Poll::Ready(Ok(0));
        }

        self.socket.as_mut().poll_write(cx, buf)
    }

    fn poll_write_vectored(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.state.contains(StreamState::PENDING_CLOSE) {
            std::task::ready!(self.poll_do_close(cx))?;
        }

        if self.state.write_closed() {
            return Poll::Ready(Ok(0));
        }

        self.socket.as_mut().poll_write_vectored(cx, bufs)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.contains(StreamState::PENDING_CLOSE) {
            std::task::ready!(self.poll_do_close(cx))?;
        }

        if self.state.write_closed() {
            return Poll::Ready(Ok(()));
        }

        self.socket.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.contains(StreamState::PENDING_CLOSE) {
            std::task::ready!(self.poll_do_close(cx))?;
        }

        *self.state |= StreamState::WRITE_CLOSED;
        self.socket.as_mut().poll_shutdown(cx)
    }

    fn poll_do_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.socket.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                *self.state &= !StreamState::PENDING_CLOSE;

                if result.is_ok() {
                    if let Err(e) =
                        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
                    {
                        return Poll::Ready(Err(e));
                    }
                }

                *self.state |= StreamState::WRITE_CLOSED;
                Poll::Ready(result)
            }
        }
    }

    fn key_update(&mut self, request: KeyUpdateRequest) -> io::Result<()> {
        #[rustfmt::skip]
        let message = [
            HandshakeType::KeyUpdate.into(), //typ
            0, 0, 1, // length
            request.into()
        ];

        self.send_cmsg(ContentType::Handshake, &[io::IoSlice::new(&message)])?;

        let (seq, secrets) = match self.data.update_tx_secret() {
            Ok(secrets) => secrets,
            Err(e) => {
                return Err(self.abort_with_error(
                    AlertDescription::InternalError,
                    KTlsStreamError::KeyUpdateFailed(e),
                ));
            }
        };

        let crypto =
            match CryptoInfo::from_rustls(self.data.negotiated_cipher_suite(), (seq, secrets)) {
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

    fn handle_control_message(&mut self) -> io::Result<()> {
        let mut take = TakeBuffer::new(self);
        let (this, data) = take.as_parts_mut();

        this.handle_control_message_impl(data)
    }

    fn handle_control_message_impl(&mut self, buffer: &mut Vec<u8>) -> io::Result<()> {
        if self.state.read_closed() {
            return Err(io::Error::other(KTlsStreamError::Closed));
        }

        // We reuse the early data buffer to read the control message so it is
        // an error to attempt to do so without having handled all the early
        // data beforehand.
        if self.state.early_data() {
            return Err(io::Error::other(
                KTlsStreamError::ControlMessageWithBufferedData,
            ));
        }

        let mut data = ClearOnDrop(buffer);

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

                std::mem::forget(data);
                *self.state |= StreamState::EARLY_DATA;

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
                *self.state |= StreamState::READ_CLOSED;
            }

            // TLS 1.2 allows alerts to be sent with a warning level without terminating
            // the connection. In this case we ignore the alert.
            _ if self.data.protocol_version() == ProtocolVersion::TLSv1_2
                && level == AlertLevel::Warning => {}

            // All other alerts are treated as fatal and result in us immediately shutting
            // down the connection and emitting an error.
            _ => {
                *self.state = StreamState::CLOSED;
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
                && self.data.protocol_version() == ProtocolVersion::TLSv1_3
            {
                if !first || !data.is_empty() {
                    return Err(self.abort_with_error(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::KeyEpochWithPendingFragment,
                    ));
                }
            }

            self.handle_single_handshake(ty, msg)?;
            first = false;
        }

        Ok(())
    }

    fn handle_single_handshake(&mut self, typ: HandshakeType, data: &[u8]) -> io::Result<()> {
        match typ {
            HandshakeType::KeyUpdate
                if self.data.protocol_version() == ProtocolVersion::TLSv1_3 =>
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

                let (seq, secrets) = match self.data.update_rx_secret() {
                    Ok(secrets) => secrets,
                    Err(e) => {
                        return Err(self.abort_with_error(
                            AlertDescription::InternalError,
                            KTlsStreamError::KeyUpdateFailed(e),
                        ))
                    }
                };

                let crypto = match CryptoInfo::from_rustls(
                    self.data.negotiated_cipher_suite(),
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
                if self.data.protocol_version() == ProtocolVersion::TLSv1_3 =>
            {
                match self.data.as_side_mut() {
                    Side::Client(conn) => match conn.conn.handle_new_session_ticket(data) {
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
                        Err(e) => {
                            return Err(io::Error::other(KTlsStreamError::SessionTicketFailed(e)))
                        }
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
                return Err(match self.data.protocol_version() {
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
                })
            }
        }

        Ok(())
    }

    fn abort(&mut self, alert: AlertDescription) -> io::Result<()> {
        let write_closed = self.state.write_closed();
        *self.state = StreamState::WRITE_CLOSED | StreamState::READ_CLOSED;

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

    fn send_cmsg(&self, typ: ContentType, data: &[io::IoSlice<'_>]) -> io::Result<()> {
        let cmsg = Cmsg::new(libc::SOL_TLS, libc::TLS_SET_RECORD_TYPE, [typ.into()]);
        // TODO: Should an error here abort the whole connection?
        crate::ffi::sendmsg(self.socket.as_raw_fd(), data, Some(&cmsg), 0)?;
        Ok(())
    }
}

impl<IO, Conn> AsyncRead for KTlsStreamImpl<IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: ?Sized,
    StreamData<Conn>: StreamSide,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().poll_read(cx, buf)
    }
}

impl<IO, Conn> AsyncWrite for KTlsStreamImpl<IO, Conn>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    Conn: ?Sized,
    StreamData<Conn>: StreamSide,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }
}

impl<IO, Conn> AsRawFd for KTlsStreamImpl<IO, Conn>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

pub(crate) struct StreamData<Conn: ?Sized> {
    /// This buffer is used to store early data and also as a buffer to store
    /// received control messages.
    buffer: Vec<u8>,
    offset: usize,

    conn: Conn,
}

impl<Conn> StreamData<Conn>
where
    Self: StreamSide,
    Conn: ?Sized,
{
    fn protocol_version(&self) -> ProtocolVersion {
        match self.as_side() {
            Side::Client(client) => client.conn.protocol_version(),
            Side::Server(server) => server.conn.protocol_version(),
        }
    }

    fn negotiated_cipher_suite(&self) -> SupportedCipherSuite {
        match self.as_side() {
            Side::Client(client) => client.conn.negotiated_cipher_suite(),
            Side::Server(server) => server.conn.negotiated_cipher_suite(),
        }
    }

    fn update_tx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), rustls::Error> {
        match self.as_side_mut() {
            Side::Client(client) => client.conn.update_tx_secret(),
            Side::Server(server) => server.conn.update_tx_secret(),
        }
    }

    fn update_rx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), rustls::Error> {
        match self.as_side_mut() {
            Side::Client(client) => client.conn.update_rx_secret(),
            Side::Server(server) => server.conn.update_rx_secret(),
        }
    }
}

pub(crate) trait StreamSide: 'static {
    fn as_side(
        &self,
    ) -> Side<&StreamData<KernelClientConnection>, &StreamData<KernelServerConnection>>;

    fn as_side_mut(
        &mut self,
    ) -> Side<&mut StreamData<KernelClientConnection>, &mut StreamData<KernelServerConnection>>;
}

impl StreamSide for StreamData<KernelClientConnection> {
    fn as_side(
        &self,
    ) -> Side<&StreamData<KernelClientConnection>, &StreamData<KernelServerConnection>> {
        Side::Client(self)
    }

    fn as_side_mut(
        &mut self,
    ) -> Side<&mut StreamData<KernelClientConnection>, &mut StreamData<KernelServerConnection>>
    {
        Side::Client(self)
    }
}

impl StreamSide for StreamData<KernelServerConnection> {
    fn as_side(
        &self,
    ) -> Side<&StreamData<KernelClientConnection>, &StreamData<KernelServerConnection>> {
        Side::Server(self)
    }

    fn as_side_mut(
        &mut self,
    ) -> Side<&mut StreamData<KernelClientConnection>, &mut StreamData<KernelServerConnection>>
    {
        Side::Server(self)
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
    struct StreamState : u8 {
        const READ_CLOSED   = 0b00001;
        const WRITE_CLOSED  = 0b00010;
        const CLOSED        = 0b00011;
        const EARLY_DATA    = 0b00100;
        const PENDING_CLOSE = 0b01000;
    }
}

impl StreamState {
    fn read_closed(self) -> bool {
        self.contains(Self::READ_CLOSED)
    }

    fn write_closed(self) -> bool {
        self.contains(Self::WRITE_CLOSED)
    }

    fn early_data(self) -> bool {
        self.contains(Self::EARLY_DATA)
    }
}

const DEFAULT_SCRATCH_CAPACITY: usize = 64;
const MAX_SCRATCH_CAPACITY: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum KTlsStreamError {
    #[error("received corrupt message of type {0:?}")]
    InvalidMessage(InvalidMessage),

    #[error("peer misbehaved: {0:?}")]
    PeerMisbehaved(PeerMisbehaved),

    #[error("{0}")]
    KeyUpdateFailed(#[source] rustls::Error),

    #[error("failed to handle a provided session ticket: {0}")]
    SessionTicketFailed(#[source] rustls::Error),

    #[error("the connection has been closed by the peer")]
    Closed,

    #[error("cannot handle control messages while there is buffered data to read")]
    ControlMessageWithBufferedData,

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

pub(crate) enum Side<Client, Server> {
    Client(Client),
    Server(Server),
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

struct TakeBuffer<'a, 'b, IO, Conn: ?Sized> {
    stream: &'a mut KTlsStreamProject<'b, IO, Conn>,
    buffer: Vec<u8>,
}

impl<'a, 'b, IO, Conn: ?Sized> TakeBuffer<'a, 'b, IO, Conn> {
    pub fn new(stream: &'a mut KTlsStreamProject<'b, IO, Conn>) -> Self {
        Self {
            buffer: std::mem::take(&mut stream.data.buffer),
            stream,
        }
    }

    pub fn as_parts_mut(&mut self) -> (&mut KTlsStreamProject<'b, IO, Conn>, &mut Vec<u8>) {
        (&mut *self.stream, &mut self.buffer)
    }
}

impl<'a, 'b, IO, Conn: ?Sized> Drop for TakeBuffer<'a, 'b, IO, Conn> {
    fn drop(&mut self) {
        self.stream.data.buffer = std::mem::take(&mut self.buffer);
    }
}
