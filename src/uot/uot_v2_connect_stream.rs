//! Client side of a connect-mode UoT v2 session.

use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

/// Wraps the client-facing stream of a connect-mode UoT v2 session so that an
/// empty destination reply is dropped instead of written: stock sing-box
/// clients (sing v0.7.0-beta.2) stop relaying replies after a zero-length one.
/// Dropping it is not end of stream; later replies are written normally.
/// Reads, including empty client datagrams, pass through unchanged.
pub struct UotV2ConnectStream<S> {
    inner: S,
}

impl<S> UotV2ConnectStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncReadMessage + Unpin> AsyncReadMessage for UotV2ConnectStream<S> {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_read_message(cx, buf)
    }
}

impl<S: AsyncWriteMessage + Unpin> AsyncWriteMessage for UotV2ConnectStream<S> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<()>> {
        if buf.is_empty() {
            log::debug!("UoT connect: dropped an empty reply");
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_write_message(cx, buf)
    }
}

impl<S: AsyncFlushMessage + Unpin> AsyncFlushMessage for UotV2ConnectStream<S> {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush_message(cx)
    }
}

impl<S: AsyncShutdownMessage + Unpin> AsyncShutdownMessage for UotV2ConnectStream<S> {
    fn poll_shutdown_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown_message(cx)
    }
}

impl<S: AsyncPing + Unpin> AsyncPing for UotV2ConnectStream<S> {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl<S: AsyncMessageStream> AsyncMessageStream for UotV2ConnectStream<S> {
    fn is_message_eof(&self) -> bool {
        self.inner.is_message_eof()
    }
}
