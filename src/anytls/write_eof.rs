//! Private, opt-in write-eof/1. See docs/anytls-write-eof-v1.md.
//!
//! Separate from the legacy queue/FIN path: at most 8 streams, 4 incoming frames
//! each, and 16 outgoing operations shared by the whole session. Payloads are at
//! most 65535 bytes. No per-stream forwarding task or unbounded queue exists here.
//! Each stream has at most one flush acknowledgement and one EOF acknowledgement.
//! EOF completion acknowledges actual ordered transport write AND flush.
use super::anytls_client_session::AnyTlsClientSession;
use super::anytls_padding::{CHECK_MARK, PaddingFactory};
use super::anytls_stream::AnyTlsStream;
use super::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, StringMap};
use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::socks_handler::write_location_to_vec;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Future, ready, task::AtomicWaker};
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    fmt, io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, PollSender, WaitForCancellationFutureOwned};

pub(super) const MAX_STREAMS: usize = 8;
const INCOMING_FRAMES: usize = 4;
const OUTGOING_OPERATIONS: usize = 16;
pub(super) const FEATURE: &str = "x-write-eof";

/// Development extension policy. Existing constructors do not enable it.
#[derive(Debug, Clone, Copy)]
pub struct WriteEofOptions {
    /// Before any SYN/destination/application payload. Maximum 5s; drop cancels it.
    pub negotiation_timeout: Duration,
    /// Starts only on shutdown, never on live IO. Maximum 5s; may be narrower.
    pub eof_timeout: Duration,
}
impl Default for WriteEofOptions {
    fn default() -> Self {
        Self {
            negotiation_timeout: Duration::from_secs(5),
            eof_timeout: Duration::from_secs(5),
        }
    }
}

/// Sanitized, downcastable failure reasons; never includes peer/application text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteEofError {
    Unsupported,
    Negotiation,
    Timeout,
    Closed,
    Protocol,
    Capacity,
}
impl fmt::Display for WriteEofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "write-eof/1 unsupported",
            Self::Negotiation => "write-eof/1 negotiation failed",
            Self::Timeout => "write-eof/1 control timed out",
            Self::Closed => "write-eof/1 stream or session closed",
            Self::Protocol => "write-eof/1 protocol error",
            Self::Capacity => "write-eof/1 capacity exceeded",
        })
    }
}
impl std::error::Error for WriteEofError {}
fn error(reason: WriteEofError) -> io::Error {
    let kind = match reason {
        WriteEofError::Unsupported => io::ErrorKind::Unsupported,
        WriteEofError::Negotiation | WriteEofError::Protocol => io::ErrorKind::InvalidData,
        WriteEofError::Timeout => io::ErrorKind::TimedOut,
        WriteEofError::Closed => io::ErrorKind::BrokenPipe,
        WriteEofError::Capacity => io::ErrorKind::WouldBlock,
    };
    io::Error::new(kind, reason)
}
pub(super) fn negotiation_error() -> io::Error {
    error(WriteEofError::Negotiation)
}
pub(super) fn protocol_error() -> io::Error {
    error(WriteEofError::Protocol)
}
fn closed() -> io::Error {
    error(WriteEofError::Closed)
}

type Ack = oneshot::Sender<io::Result<()>>;
type AckRx = oneshot::Receiver<io::Result<()>>;

pub(super) struct Operation {
    pub frame: Option<Frame>,
    ack: Option<Ack>,
    state: Option<Arc<DirectionState>>,
}
impl Operation {
    fn frame(frame: Frame, state: Option<Arc<DirectionState>>, ack: Option<Ack>) -> Self {
        Self {
            frame: Some(frame),
            ack,
            state,
        }
    }
    /// A reset invalidates queued data, not the explicit full-FIN reset itself.
    pub fn invalidated(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.cancel.is_cancelled())
    }
    pub fn begin(&self, core: &Registry) -> bool {
        core.writing_id.store(
            self.state
                .as_ref()
                .map_or_else(|| self.frame.as_ref().map_or(0, |f| f.stream_id), |s| s.id),
            Ordering::SeqCst,
        );
        // Pair with reset's in-flight check, including cancellation racing begin.
        if self.invalidated() {
            core.writing_id.store(0, Ordering::SeqCst);
            false
        } else {
            true
        }
    }
    pub fn finish(self, core: &Registry, result: io::Result<()>) {
        core.writing_id.store(0, Ordering::SeqCst);
        let success = result.is_ok();
        if success
            && self
                .frame
                .as_ref()
                .is_some_and(|f| f.cmd == Command::WriteEof)
            && let Some(state) = &self.state
        {
            state.local_eof.store(true, Ordering::SeqCst);
            core.retire(state);
        }
        // Publish the settled wire state before waking the caller. Caller success
        // still requires receiving this acknowledgement; a lost ack is failure.
        if let Some(ack) = self.ack
            && ack.send(result).is_err()
            && let Some(state) = &self.state
        {
            core.reset_and_notify(state);
        }
    }
}

struct DirectionState {
    id: u32,
    incoming: mpsc::Sender<Bytes>,
    local_eof: AtomicBool,
    remote_eof: AtomicBool,
    drained: AtomicBool,
    cancel: CancellationToken,
    reader: AtomicWaker,
    synack: Mutex<Option<oneshot::Sender<io::Result<()>>>>,
}

pub(super) struct Registry {
    streams: Mutex<HashMap<u32, Arc<DirectionState>>>,
    pub cancel: CancellationToken,
    pub outgoing: mpsc::Sender<Operation>,
    eof_timeout: Duration,
    writing_id: AtomicU32,
}
impl Registry {
    #[cfg(test)]
    pub(super) fn stream_count_for_test(&self) -> usize {
        self.streams.lock().len()
    }
    pub fn new(eof_timeout: Duration) -> (Arc<Self>, mpsc::Receiver<Operation>) {
        let (outgoing, rx) = mpsc::channel(OUTGOING_OPERATIONS);
        (
            Arc::new(Self {
                streams: Mutex::new(HashMap::new()),
                cancel: CancellationToken::new(),
                outgoing,
                eof_timeout: eof_timeout.min(Duration::from_secs(5)),
                writing_id: AtomicU32::new(0),
            }),
            rx,
        )
    }
    pub fn close(&self) {
        self.cancel.cancel();
        self.streams.lock().clear();
    }
    fn retire(&self, state: &DirectionState) {
        if state.local_eof.load(Ordering::SeqCst)
            && state.remote_eof.load(Ordering::SeqCst)
            && state.drained.load(Ordering::SeqCst)
        {
            let mut streams = self.streams.lock();
            if streams
                .get(&state.id)
                .is_some_and(|registered| std::ptr::eq(registered.as_ref(), state))
            {
                streams.remove(&state.id);
            }
        }
    }
    fn reset(&self, id: u32) {
        let state = self.streams.lock().remove(&id);
        if let Some(state) = state {
            state.cancel.cancel();
            if self.writing_id.load(Ordering::SeqCst) == id {
                self.close();
            }
        }
    }
    fn reset_and_notify(&self, state: &DirectionState) {
        state.cancel.cancel();
        let removed = {
            let mut streams = self.streams.lock();
            if streams
                .get(&state.id)
                .is_some_and(|registered| std::ptr::eq(registered.as_ref(), state))
            {
                streams.remove(&state.id);
                true
            } else {
                false
            }
        };
        if !removed {
            return;
        }
        if self.writing_id.load(Ordering::SeqCst) == state.id {
            // Cancelling a partially serialized frame must fail the transport;
            // continuing that frame or injecting FIN mid-frame would be unsafe.
            self.close();
            return;
        }
        if self.cancel.is_cancelled() {
            return;
        }
        // Drop cannot wait. Failure to queue a full close cancels the session;
        // it is never re-labelled as successful graceful EOF.
        if self
            .outgoing
            .try_send(Operation::frame(
                Frame::control(Command::Fin, state.id),
                None,
                None,
            ))
            .is_err()
        {
            self.close();
        }
    }
    pub fn open(
        self: &Arc<Self>,
        id: u32,
        wait_synack: bool,
    ) -> io::Result<(EofStream, Option<AckRx>)> {
        if self.cancel.is_cancelled() {
            return Err(closed());
        }
        let mut streams = self.streams.lock();
        if id == 0 || streams.contains_key(&id) {
            return Err(protocol_error());
        }
        if streams.len() >= MAX_STREAMS {
            return Err(error(WriteEofError::Capacity));
        }
        let (tx, rx) = mpsc::channel(INCOMING_FRAMES);
        let (synack, ack_rx) = if wait_synack {
            let (tx, rx) = oneshot::channel();
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let state = Arc::new(DirectionState {
            id,
            incoming: tx,
            local_eof: AtomicBool::new(false),
            remote_eof: AtomicBool::new(false),
            drained: AtomicBool::new(false),
            cancel: self.cancel.child_token(),
            reader: AtomicWaker::new(),
            synack: Mutex::new(synack),
        });
        streams.insert(id, state.clone());
        let cancelled = Box::pin(state.cancel.clone().cancelled_owned());
        Ok((
            EofStream {
                state,
                core: self.clone(),
                incoming: rx,
                buffer: Bytes::new(),
                sender: PollSender::new(self.outgoing.clone()),
                cancelled,
                flush_ack: None,
                eof_ack: None,
                eof_sent: false,
                shutting_down: false,
                shutdown_done: false,
                deadline: None,
                keepalive: None,
            },
            ack_rx,
        ))
    }
    pub async fn send(&self, frame: Frame) -> io::Result<()> {
        self.send_operation(Operation::frame(frame, None, None))
            .await
    }
    async fn send_for(&self, state: &Arc<DirectionState>, frame: Frame) -> io::Result<()> {
        tokio::select! {
            biased;
            _ = state.cancel.cancelled() => Err(closed()),
            result = self.send_operation(Operation::frame(frame,Some(state.clone()),None)) => result,
        }
    }
    async fn send_operation(&self, op: Operation) -> io::Result<()> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(closed()),
            result = self.outgoing.send(op) => result.map_err(|_| closed()),
        }
    }
    /// Called serially by the transport reader, preserving PSH-before-EOF order.
    pub async fn receive(&self, frame: Frame) -> io::Result<()> {
        if frame.cmd == Command::WriteEof && (frame.stream_id == 0 || !frame.data.is_empty()) {
            return Err(protocol_error());
        }
        let state = self.streams.lock().get(&frame.stream_id).cloned();
        let Some(state) = state else {
            return Ok(());
        }; // No tombstones or allocation.
        match frame.cmd {
            Command::Psh => {
                if state.remote_eof.load(Ordering::SeqCst) {
                    self.reset(frame.stream_id);
                    let result = tokio::time::timeout(
                        self.eof_timeout,
                        self.send(Frame::control(Command::Fin, frame.stream_id)),
                    )
                    .await;
                    if !matches!(result, Ok(Ok(()))) {
                        self.close();
                    }
                    return Ok(());
                }
                if frame.data.is_empty() {
                    return Ok(());
                }
                tokio::select! {
                    biased;
                    _ = state.cancel.cancelled() => {},
                    _ = state.incoming.send(frame.data) => {},
                }
            }
            Command::WriteEof => {
                state.remote_eof.store(true, Ordering::SeqCst);
                state.reader.wake();
                self.retire(&state);
            }
            Command::Fin => self.reset(frame.stream_id),
            Command::SynAck => {
                if let Some(ack) = state.synack.lock().take() {
                    let _ = ack.send(if frame.data.is_empty() {
                        Ok(())
                    } else {
                        Err(closed())
                    });
                } else if !frame.data.is_empty() {
                    self.reset(frame.stream_id);
                }
            }
            _ => return Err(protocol_error()),
        }
        Ok(())
    }
}

pub(super) struct EofStream {
    state: Arc<DirectionState>,
    core: Arc<Registry>,
    incoming: mpsc::Receiver<Bytes>,
    buffer: Bytes,
    sender: PollSender<Operation>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    flush_ack: Option<AckRx>,
    eof_ack: Option<AckRx>,
    eof_sent: bool,
    shutting_down: bool,
    shutdown_done: bool,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    keepalive: Option<Arc<dyn std::any::Any + Send + Sync>>,
}
impl EofStream {
    pub fn id(&self) -> u32 {
        self.state.id
    }
    fn poll_closed(&mut self, cx: &mut Context<'_>) -> bool {
        self.cancelled.as_mut().poll(cx).is_ready()
    }
    fn failed(&self) {
        self.core.reset_and_notify(&self.state);
    }
    fn poll_flush_ack(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = ready!(Self::poll_ack(&mut self.flush_ack, cx));
        if result.is_err() {
            self.failed();
        }
        Poll::Ready(result)
    }
    fn poll_ack(ack: &mut Option<AckRx>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(rx) = ack {
            let result = ready!(Pin::new(rx).poll(cx)).unwrap_or_else(|_| Err(closed()));
            *ack = None;
            Poll::Ready(result)
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn enqueue(
        &mut self,
        cx: &mut Context<'_>,
        frame: Option<Frame>,
        ack: Option<Ack>,
    ) -> Poll<io::Result<()>> {
        ready!(self.sender.poll_reserve(cx)).map_err(|_| closed())?;
        self.sender
            .send_item(Operation {
                frame,
                ack,
                state: Some(self.state.clone()),
            })
            .map_err(|_| closed())?;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for EofStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        self.state.reader.register(cx.waker());
        if self.buffer.is_empty() {
            match self.incoming.poll_recv(cx) {
                Poll::Ready(Some(data)) => self.buffer = data,
                Poll::Ready(None) => return Poll::Ready(Err(closed())),
                Poll::Pending => {
                    if self.state.remote_eof.load(Ordering::SeqCst) {
                        self.state.drained.store(true, Ordering::SeqCst);
                        self.core.retire(&self.state);
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }
        let count = buf.remaining().min(self.buffer.len());
        buf.put_slice(&self.buffer[..count]);
        self.buffer.advance(count);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for EofStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutting_down || self.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        ready!(self.poll_flush_ack(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Reserve before copying so blocked writers do not each retain a payload.
        ready!(self.sender.poll_reserve(cx)).map_err(|_| closed())?;
        let count = data.len().min(u16::MAX as usize);
        let op = Operation::frame(
            Frame::data(self.id(), Bytes::copy_from_slice(&data[..count])),
            Some(self.state.clone()),
            None,
        );
        self.sender.send_item(op).map_err(|_| closed())?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if self.shutting_down {
            return self.poll_shutdown(cx);
        }
        if self.flush_ack.is_none() {
            ready!(self.sender.poll_reserve(cx)).map_err(|_| closed())?;
            let (tx, rx) = oneshot::channel();
            ready!(self.enqueue(cx, None, Some(tx)))?;
            self.flush_ack = Some(rx);
        }
        self.poll_flush_ack(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        self.shutting_down = true;
        if self.deadline.is_none() {
            self.deadline = Some(Box::pin(tokio::time::sleep(self.core.eof_timeout)));
        }
        if self.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        if self.deadline.as_mut().unwrap().as_mut().poll(cx).is_ready() {
            self.failed();
            // A partially written frame cannot be safely cancelled in isolation.
            // Stop the writer too; a queued reset alone is not settlement.
            self.core.close();
            return Poll::Ready(Err(error(WriteEofError::Timeout)));
        }
        ready!(self.poll_flush_ack(cx))?;
        if !self.eof_sent {
            ready!(self.sender.poll_reserve(cx)).map_err(|_| closed())?;
            let (tx, rx) = oneshot::channel();
            let frame = Frame::control(Command::WriteEof, self.id());
            ready!(self.enqueue(cx, Some(frame), Some(tx)))?;
            self.eof_ack = Some(rx);
            self.eof_sent = true;
        }
        if let Err(e) = ready!(Self::poll_ack(&mut self.eof_ack, cx)) {
            self.failed();
            return Poll::Ready(Err(e));
        }
        self.shutdown_done = true;
        self.deadline = None;
        Poll::Ready(Ok(()))
    }
}
impl Drop for EofStream {
    fn drop(&mut self) {
        if !(self.shutdown_done
            && self.state.remote_eof.load(Ordering::SeqCst)
            && self.state.drained.load(Ordering::SeqCst))
        {
            self.failed();
        }
    }
}
impl AsyncPing for EofStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for EofStream {}

/// A strict session. Connect does not return until v2/write-eof/1 is agreed.
/// The existing AnyTlsClientSession and all old handler constructors remain legacy.
pub struct WriteEofClientSession {
    core: Arc<Registry>,
    next_id: AtomicU32,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>, // exactly two, never per-stream
    next_padding: Arc<Mutex<Arc<PaddingFactory>>>,
}
impl Drop for WriteEofClientSession {
    fn drop(&mut self) {
        self.core.close();
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}
impl WriteEofClientSession {
    #[cfg(test)]
    pub(super) fn registered_streams(&self) -> usize {
        self.core.streams.lock().len()
    }
    #[cfg(test)]
    pub(super) async fn inject_frame_for_test(&self, frame: Frame) -> io::Result<()> {
        self.core.send(frame).await
    }
    pub async fn connect(
        mut transport: Box<dyn AsyncStream>,
        password: &str,
        padding: Arc<PaddingFactory>,
        options: WriteEofOptions,
    ) -> io::Result<Arc<Self>> {
        let mut pad = ClientPadding {
            factory: padding.clone(),
            packet: 0,
        };
        let next_padding = Arc::new(Mutex::new(padding.clone()));
        let negotiation = async {
            AnyTlsClientSession::send_auth(&mut transport, &aws_password(password), &padding)
                .await?;
            let mut settings = StringMap::new();
            settings.insert("v", "2");
            settings.insert("client", "shoes-anytls/1.0");
            settings.insert("padding-md5", padding.md5());
            settings.insert(FEATURE, "1");
            let mut buf = BytesMut::new();
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()))
                .encode_into(&mut buf);
            pad.write(&mut transport, &buf).await?;
            // Mandatory: offer must leave TLS before waiting; never coalesce a SYN here.
            transport.flush().await?;
            loop {
                let frame = read_frame(&mut transport).await?;
                match frame.cmd {
                    Command::ServerSettings if frame.stream_id == 0 => {
                        let settings = StringMap::negotiation(&frame.data)?;
                        if settings.get("v").map(String::as_str) != Some("2")
                            || settings.get(FEATURE).map(String::as_str) != Some("1")
                        {
                            return Err(error(WriteEofError::Unsupported));
                        }
                        return Ok(());
                    }
                    Command::UpdatePaddingScheme if frame.stream_id == 0 => {
                        *next_padding.lock() = Arc::new(
                            PaddingFactory::new(&frame.data).map_err(|_| negotiation_error())?,
                        );
                    }
                    Command::Waste => {}
                    _ => return Err(negotiation_error()),
                }
            }
        };
        match tokio::time::timeout(
            options.negotiation_timeout.min(Duration::from_secs(5)),
            negotiation,
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.get_ref().is_some_and(|e| e.is::<WriteEofError>()) => return Err(e),
            Ok(Err(_)) => return Err(negotiation_error()),
            Err(_) => return Err(error(WriteEofError::Timeout)),
        }
        let (core, rx) = Registry::new(options.eof_timeout);
        let session = Arc::new(Self {
            core: core.clone(),
            next_id: AtomicU32::new(0),
            tasks: Mutex::new(Vec::with_capacity(2)),
            next_padding: next_padding.clone(),
        });
        let (reader, writer) = tokio::io::split(transport);
        let w = core.clone();
        let writer_task = tokio::spawn(async move {
            tokio::select! { biased; _ = w.cancel.cancelled() => {}, _ = client_writer(&w, writer, rx, pad) => {} }
            w.close();
        });
        let r = core.clone();
        let reader_task = tokio::spawn(async move {
            tokio::select! { biased; _ = r.cancel.cancelled() => {}, _ = client_reader(&r, reader, next_padding) => {} }
            r.close();
        });
        session.tasks.lock().extend([writer_task, reader_task]);
        Ok(session)
    }
    /// Current session keeps its original scheme, per AnyTLS update semantics.
    pub fn padding_for_next_session(&self) -> Arc<PaddingFactory> {
        self.next_padding.lock().clone()
    }
    pub async fn open_stream(
        self: &Arc<Self>,
        destination: NetLocation,
    ) -> io::Result<AnyTlsStream> {
        let id = self
            .next_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| error(WriteEofError::Capacity))?
            + 1;
        // UoT requires its ordinary setup header AFTER the magic destination and
        // BEFORE SYNACK. Feature agreement is already complete, independently.
        let uot_setup = matches!(destination.address(), crate::address::Address::Hostname(host)
            if host == crate::uot::UOT_V1_MAGIC_ADDRESS || host == crate::uot::UOT_V2_MAGIC_ADDRESS);
        let (mut stream, synack) = self.core.open(id, !uot_setup)?;
        // Stream's Drop is the cancellation guard even while SYN/SYNACK is pending.
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            self.core
                .send_for(&stream.state, Frame::control(Command::Syn, id))
                .await?;
            self.core
                .send_for(
                    &stream.state,
                    Frame::data(id, Bytes::from(write_location_to_vec(&destination))),
                )
                .await?;
            if let Some(synack) = synack {
                tokio::select! {
                    biased;
                    _ = self.core.cancel.cancelled() => Err(closed()),
                    _ = stream.state.cancel.cancelled() => Err(closed()),
                    result = synack => result.unwrap_or_else(|_| Err(closed())),
                }
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|_| error(WriteEofError::Timeout))?;
        result?;
        stream.keepalive = Some(self.clone());
        Ok(AnyTlsStream::from_write_eof(stream))
    }
    /// Explicit full session cancellation. Pending operations cannot succeed.
    pub async fn close(&self) -> io::Result<()> {
        self.core.close();
        let mut tasks = std::mem::take(&mut *self.tasks.lock());
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            for task in &mut tasks {
                task.await.map_err(|_| closed())?;
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(error(WriteEofError::Timeout)));
        if result.is_err() {
            for task in tasks {
                task.abort();
            }
        }
        result
    }
}

fn aws_password(password: &str) -> [u8; 32] {
    let mut result = [0; 32];
    result.copy_from_slice(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, password.as_bytes()).as_ref(),
    );
    result
}
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    let mut header = [0; FRAME_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let (cmd, stream_id, len) = Frame::decode_header(&header)?;
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data).await?;
    Ok(Frame::with_data(cmd, stream_id, Bytes::from(data)))
}
async fn client_reader<R: AsyncRead + Unpin>(
    core: &Registry,
    mut reader: R,
    next_padding: Arc<Mutex<Arc<PaddingFactory>>>,
) -> io::Result<()> {
    loop {
        let frame = read_frame(&mut reader).await?;
        match frame.cmd {
            Command::Psh | Command::Fin | Command::WriteEof | Command::SynAck => {
                core.receive(frame).await?
            }
            Command::Waste | Command::HeartResponse => {}
            Command::HeartRequest => tokio::time::timeout(
                Duration::from_secs(5),
                core.send(Frame::control(Command::HeartResponse, frame.stream_id)),
            )
            .await
            .map_err(|_| error(WriteEofError::Timeout))??,
            Command::UpdatePaddingScheme if frame.stream_id == 0 => {
                *next_padding.lock() =
                    Arc::new(PaddingFactory::new(&frame.data).map_err(|_| protocol_error())?);
            }
            _ => return Err(protocol_error()), // includes repeated/conflicting settings
        }
    }
}
async fn client_writer<W: AsyncWrite + Unpin>(
    core: &Registry,
    mut writer: W,
    mut rx: mpsc::Receiver<Operation>,
    mut padding: ClientPadding,
) -> io::Result<()> {
    let mut buf = BytesMut::with_capacity(65542);
    while let Some(op) = rx.recv().await {
        if !op.begin(core) {
            op.finish(core, Err(closed()));
            continue;
        }
        buf.clear();
        if let Some(frame) = &op.frame {
            frame.encode_into(&mut buf);
        }
        let result = async {
            if !buf.is_empty() {
                padding.write(&mut writer, &buf).await?;
            }
            writer.flush().await
        }
        .await;
        let failed = result.is_err();
        op.finish(core, result);
        if failed {
            return Err(closed());
        }
    }
    Err(closed())
}

/// Same packet numbering, WASTE framing and padding factory as the legacy client.
struct ClientPadding {
    factory: Arc<PaddingFactory>,
    packet: u32,
}
impl ClientPadding {
    async fn write<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        mut data: &[u8],
    ) -> io::Result<()> {
        self.packet = self.packet.saturating_add(1);
        if self.packet >= self.factory.stop() {
            return writer.write_all(data).await;
        }
        for size in self.factory.generate_record_payload_sizes(self.packet) {
            if size == CHECK_MARK {
                if data.is_empty() {
                    break;
                }
                continue;
            }
            let size = size as usize;
            if data.len() > size {
                writer.write_all(&data[..size]).await?;
                data = &data[size..];
            } else {
                let padding = if data.is_empty() {
                    size
                } else {
                    size.saturating_sub(data.len() + FRAME_HEADER_SIZE)
                };
                // Padding payload length is u16, just as ordinary frames.
                if padding > u16::MAX as usize {
                    return Err(protocol_error());
                }
                let mut buf = BytesMut::with_capacity(data.len() + padding + FRAME_HEADER_SIZE);
                buf.extend_from_slice(data);
                if padding > 0 {
                    buf.put_u8(0);
                    buf.put_u32(0);
                    buf.put_u16(padding as u16);
                    buf.put_bytes(0, padding);
                }
                writer.write_all(&buf).await?;
                data = &[];
            }
        }
        if !data.is_empty() {
            writer.write_all(data).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::anytls_types::FrameCodec;
    use super::*;
    use tokio::time::timeout;

    #[test]
    fn codec_vectors_and_unambiguous_settings() {
        for wire in [
            &b"\x04\0\0\0\0\0\x11v=2\nx-write-eof=1"[..],
            &b"\x0a\0\0\0\0\0\x11v=2\nx-write-eof=1"[..],
        ] {
            let mut b = BytesMut::from(wire);
            let frame = FrameCodec::decode(&mut b).unwrap().unwrap();
            assert_eq!(
                StringMap::negotiation(&frame.data)
                    .unwrap()
                    .get(FEATURE)
                    .unwrap(),
                "1"
            );
            let mut encoded = BytesMut::new();
            frame.encode_into(&mut encoded);
            assert_eq!(encoded.as_ref(), wire);
        }
        let eof = Frame::control(Command::WriteEof, 1);
        assert_eq!(&eof.encode()[..], &[240, 0, 0, 0, 1, 0, 0]);
        for invalid in [
            b"v=2\nx-write-eof=1\nx-write-eof=1".as_slice(),
            b"v=2\nx-write-eof=0\nx-write-eof=1",
            b"v=2\nx-write-eof=1\nx=\xff",
        ] {
            assert!(StringMap::negotiation(invalid).is_err());
        }
    }

    #[derive(Default)]
    struct Recording {
        wire: Mutex<Vec<u8>>,
        eof_written: AtomicBool,
        allow_eof_flush: AtomicBool,
        flush_waker: AtomicWaker,
    }
    struct Writer(Arc<Recording>);
    impl AsyncWrite for Writer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            if data.first() == Some(&240) {
                self.0.eof_written.store(true, Ordering::SeqCst);
            }
            self.0.wire.lock().extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.flush_waker.register(cx.waker());
            if self.0.eof_written.load(Ordering::SeqCst)
                && !self.0.allow_eof_flush.load(Ordering::SeqCst)
            {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn shutdown_requires_actual_ordered_write_and_flush_ack_once() {
        let (core, rx) = Registry::new(Duration::from_secs(1));
        let (mut stream, _) = core.open(1, false).unwrap();
        let recording = Arc::new(Recording::default());
        let task_core = core.clone();
        let record = recording.clone();
        let task = tokio::spawn(async move {
            client_writer(
                &task_core,
                Writer(record),
                rx,
                ClientPadding {
                    factory: Arc::new(PaddingFactory::new(b"stop=0").unwrap()),
                    packet: 0,
                },
            )
            .await
        });
        stream.write_all(b"abc").await.unwrap();
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        assert!(
            timeout(Duration::from_millis(20), stream.shutdown())
                .await
                .is_err()
        );
        assert!(recording.eof_written.load(Ordering::SeqCst));
        assert!(
            !stream.shutdown_done,
            "queued/written but unflushed EOF is not success"
        );
        recording.allow_eof_flush.store(true, Ordering::SeqCst);
        recording.flush_waker.wake();
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        core.receive(Frame::data(1, Bytes::from_static(b"response")))
            .await
            .unwrap();
        core.receive(Frame::control(Command::WriteEof, 1))
            .await
            .unwrap();
        core.receive(Frame::control(Command::WriteEof, 1))
            .await
            .unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"response");
        assert!(core.streams.lock().is_empty());
        drop(stream);
        let mut wire = BytesMut::from(recording.wire.lock().as_slice());
        assert_eq!(
            FrameCodec::decode(&mut wire).unwrap().unwrap().cmd,
            Command::Psh
        );
        assert_eq!(
            FrameCodec::decode(&mut wire).unwrap().unwrap().cmd,
            Command::WriteEof
        );
        assert!(
            wire.is_empty(),
            "no duplicate EOF or auto-appended full FIN"
        );
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn lost_ack_is_failure_on_every_retry() {
        let (core, mut rx) = Registry::new(Duration::from_millis(100));
        let (mut stream, _) = core.open(1, false).unwrap();
        let (result, _) = tokio::join!(stream.shutdown(), async {
            drop(rx.recv().await.unwrap());
        });
        assert!(result.is_err());
        assert!(stream.shutdown().await.is_err());
        assert!(stream.flush().await.is_err());
        assert!(stream.write(b"x").await.is_err());
        assert!(core.streams.lock().is_empty());
    }

    #[tokio::test]
    async fn cancelled_open_discards_queued_syn_and_destination() {
        let (core, mut rx) = Registry::new(Duration::from_secs(1));
        let (stream, _) = core.open(1, false).unwrap();
        core.send_for(&stream.state, Frame::control(Command::Syn, 1))
            .await
            .unwrap();
        core.send_for(
            &stream.state,
            Frame::data(1, Bytes::from_static(b"destination")),
        )
        .await
        .unwrap();
        drop(stream);
        for _ in 0..2 {
            let op = rx.recv().await.unwrap();
            assert!(
                !op.begin(&core),
                "cancelled open must not activate a peer stream"
            );
            op.finish(&core, Err(closed()));
        }
        assert_eq!(rx.recv().await.unwrap().frame.unwrap().cmd, Command::Fin);
        assert!(!core.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn dropped_writer_during_unflushed_eof_cancels_transport() {
        let (core, rx) = Registry::new(Duration::from_secs(1));
        let (mut stream, _) = core.open(1, false).unwrap();
        let recording = Arc::new(Recording::default());
        let task_core = core.clone();
        let record = recording.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = task_core.cancel.cancelled() => {},
                _ = client_writer(&task_core,Writer(record),rx,ClientPadding { factory:Arc::new(PaddingFactory::new(b"stop=0").unwrap()), packet:0 }) => {},
            }
        });
        assert!(
            timeout(Duration::from_millis(20), stream.shutdown())
                .await
                .is_err()
        );
        assert!(recording.eof_written.load(Ordering::SeqCst));
        assert!(!stream.shutdown_done);
        drop(stream);
        assert!(core.cancel.is_cancelled());
        timeout(Duration::from_millis(100), task)
            .await
            .unwrap()
            .unwrap();
        assert!(core.streams.lock().is_empty());
    }

    #[tokio::test]
    async fn bounded_queue_stalled_eof_times_out_not_success() {
        let (core, _rx) = Registry::new(Duration::from_millis(40));
        let (mut stream, _) = core.open(1, false).unwrap();
        for _ in 0..OUTGOING_OPERATIONS {
            stream.write_all(b"x").await.unwrap();
        }
        let result = timeout(Duration::from_millis(200), stream.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(result.kind(), io::ErrorKind::TimedOut);
        assert!(
            core.cancel.is_cancelled(),
            "a full reset queue cannot strand the peer"
        );
        assert!(stream.shutdown().await.is_err());
        assert!(core.streams.lock().is_empty());
    }

    #[tokio::test]
    async fn actual_stalled_writer_and_session_cancellation_unblock_operations() {
        let (core, rx) = Registry::new(Duration::from_millis(40));
        let (mut stream, _) = core.open(1, false).unwrap();
        let (mut reader, _) = core.open(2, false).unwrap();
        let (writer, _unread_peer) = tokio::io::duplex(1);
        let task_core = core.clone();
        let task = tokio::spawn(async move {
            tokio::select! { _ = task_core.cancel.cancelled() => {}, _ = client_writer(&task_core, writer,rx,ClientPadding { factory: PaddingFactory::default_factory(), packet: 0 }) => {} }
        });
        stream.write_all(b"accepted").await.unwrap();
        assert_eq!(
            stream.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(core.cancel.is_cancelled());
        let read = tokio::spawn(async move { reader.read(&mut [0; 1]).await });
        core.close();
        assert!(
            timeout(Duration::from_millis(100), read)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        timeout(Duration::from_millis(100), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_duplicate_invalid_eof_and_post_eof_psh_isolation() {
        let (core, mut rx) = Registry::new(Duration::from_millis(100));
        for id in 1..10_000 {
            core.receive(Frame::control(Command::WriteEof, id))
                .await
                .unwrap();
        }
        assert!(core.streams.lock().is_empty());
        assert!(
            core.receive(Frame::control(Command::WriteEof, 0))
                .await
                .is_err()
        );
        assert!(
            core.receive(Frame::with_data(
                Command::WriteEof,
                1,
                Bytes::from_static(b"x")
            ))
            .await
            .is_err()
        );
        let (mut a, _) = core.open(1, false).unwrap();
        let (mut b, _) = core.open(2, false).unwrap();
        core.receive(Frame::data(1, Bytes::from_static(b"prior")))
            .await
            .unwrap();
        core.receive(Frame::control(Command::WriteEof, 1))
            .await
            .unwrap();
        core.receive(Frame::control(Command::WriteEof, 1))
            .await
            .unwrap();
        let mut data = Vec::new();
        a.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"prior");
        core.receive(Frame::data(1, Bytes::from_static(b"illegal")))
            .await
            .unwrap();
        assert!(a.read(&mut [0; 1]).await.is_err());
        assert_eq!(rx.recv().await.unwrap().frame.unwrap().cmd, Command::Fin);
        core.receive(Frame::data(2, Bytes::from_static(b"healthy")))
            .await
            .unwrap();
        let mut data = [0; 7];
        b.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"healthy");
        b.write_all(b"still writable").await.unwrap();
        assert!(!core.cancel.is_cancelled());
        core.receive(Frame::control(Command::Fin, 2)).await.unwrap();
        assert!(b.read(&mut [0; 1]).await.is_err());
        assert!(b.shutdown().await.is_err());
    }

    #[tokio::test]
    async fn finite_stream_and_waiter_budget() {
        let (core, _rx) = Registry::new(Duration::from_secs(5));
        let mut streams = Vec::new();
        for id in 1..=MAX_STREAMS {
            streams.push(core.open(id as u32, true).unwrap());
        }
        assert!(core.open(100, true).is_err());
        assert_eq!(core.streams.lock().len(), MAX_STREAMS);
        core.close();
        for (mut stream, _) in streams {
            assert!(stream.shutdown().await.is_err());
        }
        assert!(core.streams.lock().is_empty());
    }
}
