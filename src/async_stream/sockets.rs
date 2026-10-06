use super::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
#[cfg(target_family = "unix")]
use tokio::net::UnixStream;
use tokio::net::{TcpStream, UdpSocket};

impl AsyncReadMessage for UdpSocket {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_recv(cx, buf)
    }
}

impl AsyncWriteMessage for UdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        // TODO: send back an error if the whole buf.len() wasn't sent?
        self.poll_send(cx, buf).map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for TcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncStream for TcpStream {}

#[cfg(target_family = "unix")]
impl AsyncPing for UnixStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

#[cfg(target_family = "unix")]
impl AsyncStream for UnixStream {}

impl AsyncPing for UdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncMessageStream for UdpSocket {
    fn is_message_eof(&self) -> bool {
        false
    }
}

// pattern copied from deref_async_read macro: https://docs.rs/tokio/latest/src/tokio/io/async_read.rs.html#60
