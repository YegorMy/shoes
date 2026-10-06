use super::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for Box<T> {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for &mut T {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for Box<T> {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for &mut T {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for Box<T> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for &mut T {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for Box<T> {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for &mut T {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for Box<T> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for &mut T {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for Box<T> {}
impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for &mut T {}

impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for Box<T> {
    fn is_message_eof(&self) -> bool {
        (**self).is_message_eof()
    }
}
impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for &mut T {
    fn is_message_eof(&self) -> bool {
        (**self).is_message_eof()
    }
}
