use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::NetLocation;

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;

    // Write a ping message to the stream, if supported.
    // This should end up calling the highest level stream abstraction that supports
    // pings, and should only result in a single message.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncReadMessage {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncWriteMessage {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncFlushMessage {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;
}

pub trait AsyncShutdownMessage {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>;
}

/// Extension trait that provides an async `shutdown_message()` method for types
/// implementing `AsyncShutdownMessage`. Similar to `AsyncWriteExt::shutdown()`.
pub trait AsyncShutdownMessageExt: AsyncShutdownMessage {
    /// Shuts down the message stream, signaling that no more messages will be sent.
    fn shutdown_message(&mut self) -> ShutdownMessageFuture<'_, Self>
    where
        Self: Unpin,
    {
        ShutdownMessageFuture { stream: self }
    }
}

/// Future returned by `AsyncShutdownMessageExt::shutdown_message()`.
pub struct ShutdownMessageFuture<'a, T: ?Sized> {
    stream: &'a mut T,
}

impl<T: AsyncShutdownMessage + Unpin + ?Sized> Future for ShutdownMessageFuture<'_, T> {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.stream).poll_shutdown_message(cx)
    }
}

// Blanket implementation for all types that implement AsyncShutdownMessage
impl<T: AsyncShutdownMessage + ?Sized> AsyncShutdownMessageExt for T {}

pub trait AsyncReadTargetedMessage {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>>;
}

pub trait AsyncWriteTargetedMessage {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncReadSourcedMessage {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>>;
}

pub trait AsyncWriteSourcedMessage {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

/// Session-based message reading trait. Used by protocols like XUDP that have session IDs.
/// Returns (session_id, data, source_addr) tuples.
pub type MessageSessionId = u64;

pub trait AsyncReadSessionMessage {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(MessageSessionId, SocketAddr)>>;

    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        None
    }
}

/// Session-based message writing trait. Used by protocols like XUDP that have session IDs.
/// Writes data for a specific session ID to a target address.
pub trait AsyncWriteSessionMessage {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: MessageSessionId,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {}

pub trait AsyncMessageStream:
    AsyncReadMessage
    + AsyncWriteMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
    /// Consult after a successful read whose message payload is empty.
    /// The default preserves legacy streams' zero-length EOF convention.
    /// Streams carrying empty datagrams override this with their actual EOF state.
    fn is_message_eof(&self) -> bool {
        true
    }
}

/// Server stream trait connected to proxy clients, where received messages have a target address,
/// and we write forwarded messages along with the source address we received them from.
pub trait AsyncTargetedMessageStream:
    AsyncReadTargetedMessage
    + AsyncWriteSourcedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
    /// Consult after a successful read whose message payload is empty.
    /// The default preserves legacy streams' zero-length EOF convention.
    /// Streams carrying empty datagrams override this with their actual EOF state.
    fn is_message_eof(&self) -> bool {
        true
    }

    /// Whether the stream's framing can carry an empty datagram at all,
    /// whichever direction has ended. The default preserves the legacy
    /// convention, where a zero-length message means end of stream.
    fn carries_empty_messages(&self) -> bool {
        false
    }
}

/// Client stream trait connected directly to targets or to proxy servers, where received messages
/// come with a source address, and we write where we want messages to be sent.
pub trait AsyncSourcedMessageStream:
    AsyncReadSourcedMessage
    + AsyncWriteTargetedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Session-based stream trait for protocols like XUDP that multiplex sessions over a single connection.
/// Reads return (session_id, data, source_addr) and writes target (session_id, data, target_addr).
pub trait AsyncSessionMessageStream:
    AsyncReadSessionMessage
    + AsyncWriteSessionMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

mod boxed;
mod sockets;
mod targeted;
