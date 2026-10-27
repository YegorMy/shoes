use super::{
    AsyncReadSessionMessage, AsyncReadSourcedMessage, AsyncReadTargetedMessage,
    AsyncSessionMessageStream, AsyncSourcedMessageStream, AsyncTargetedMessageStream,
    AsyncWriteSessionMessage, AsyncWriteSourcedMessage, AsyncWriteTargetedMessage,
    MessageSessionId,
};
use crate::address::NetLocation;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for Box<T> {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for &mut T {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteTargetedMessage + Unpin> AsyncWriteTargetedMessage for Box<T> {
    fn poll_write_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_targeted_message(cx, buf, target)
    }
}

impl<T: ?Sized + AsyncWriteTargetedMessage + Unpin> AsyncWriteTargetedMessage for &mut T {
    fn poll_write_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_targeted_message(cx, buf, target)
    }
}

impl<T: ?Sized + AsyncReadSourcedMessage + Unpin> AsyncReadSourcedMessage for Box<T> {
    fn poll_read_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        Pin::new(&mut **self).poll_read_sourced_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadSourcedMessage + Unpin> AsyncReadSourcedMessage for &mut T {
    fn poll_read_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        Pin::new(&mut **self).poll_read_sourced_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for Box<T> {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for &mut T {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for Box<T> {
    fn is_message_eof(&self) -> bool {
        (**self).is_message_eof()
    }
}
impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for &mut T {
    fn is_message_eof(&self) -> bool {
        (**self).is_message_eof()
    }
}

impl<T: ?Sized + AsyncSourcedMessageStream + Unpin> AsyncSourcedMessageStream for Box<T> {}
impl<T: ?Sized + AsyncSourcedMessageStream + Unpin> AsyncSourcedMessageStream for &mut T {}

impl<T: ?Sized + AsyncReadSessionMessage + Unpin> AsyncReadSessionMessage for Box<T> {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(MessageSessionId, SocketAddr)>> {
        Pin::new(&mut **self).poll_read_session_message(cx, buf)
    }

    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        (**self).take_closed_session()
    }
}

impl<T: ?Sized + AsyncReadSessionMessage + Unpin> AsyncReadSessionMessage for &mut T {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(MessageSessionId, SocketAddr)>> {
        Pin::new(&mut **self).poll_read_session_message(cx, buf)
    }

    fn take_closed_session(&mut self) -> Option<MessageSessionId> {
        (**self).take_closed_session()
    }
}

impl<T: ?Sized + AsyncWriteSessionMessage + Unpin> AsyncWriteSessionMessage for Box<T> {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: MessageSessionId,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_message(cx, session_id, buf, target)
    }
}

impl<T: ?Sized + AsyncWriteSessionMessage + Unpin> AsyncWriteSessionMessage for &mut T {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: MessageSessionId,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_message(cx, session_id, buf, target)
    }
}

impl<T: ?Sized + AsyncSessionMessageStream + Unpin> AsyncSessionMessageStream for Box<T> {}
impl<T: ?Sized + AsyncSessionMessageStream + Unpin> AsyncSessionMessageStream for &mut T {}
