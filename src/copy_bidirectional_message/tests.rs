use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadMessage, AsyncShutdownMessage, AsyncWriteMessage,
};
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;
use crate::vless::VlessMessageStream;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct ScriptedMessages {
    reads: Option<VecDeque<Vec<u8>>>,
    eof: bool,
    write_pending_once: bool,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AsyncReadMessage for ScriptedMessages {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(reads) = self.reads.as_mut() else {
            return Poll::Pending;
        };
        if let Some(bytes) = reads.pop_front() {
            buf.put_slice(&bytes);
        } else {
            self.eof = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWriteMessage for ScriptedMessages {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<()>> {
        if self.write_pending_once {
            assert!(
                bytes.is_empty(),
                "the first empty datagram must reach the writer"
            );
            self.write_pending_once = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.writes.lock().unwrap().push(bytes.to_vec());
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for ScriptedMessages {
    fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncShutdownMessage for ScriptedMessages {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for ScriptedMessages {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncMessageStream for ScriptedMessages {
    fn is_message_eof(&self) -> bool {
        self.eof
    }
}

#[tokio::test]
async fn pending_empty_write_is_retained_once_before_the_following_payload() {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let mut reader = ScriptedMessages {
        reads: Some(VecDeque::from([Vec::new(), b"tail".to_vec()])),
        eof: false,
        write_pending_once: false,
        writes: Arc::new(Mutex::new(Vec::new())),
    };
    let mut writer = ScriptedMessages {
        reads: None,
        eof: false,
        write_pending_once: true,
        writes: writes.clone(),
    };
    tokio::time::timeout(
        Duration::from_secs(2),
        copy_bidirectional_message(&mut reader, &mut writer, false, false),
    )
    .await
    .expect("pending write wakes and finishes")
    .unwrap();
    assert_eq!(
        *writes.lock().unwrap(),
        vec![Vec::<u8>::new(), b"tail".to_vec()]
    );
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, accepted) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), accepted.unwrap().0)
}

async fn recv(stream: &mut dyn AsyncMessageStream, bytes: &mut [u8]) -> std::io::Result<usize> {
    let mut buf = ReadBuf::new(bytes);
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| Pin::new(&mut *stream).poll_read_message(cx, &mut buf)),
    )
    .await
    .expect("message read must finish")?;
    Ok(buf.filled().len())
}

async fn send(stream: &mut dyn AsyncMessageStream, bytes: &[u8]) {
    poll_fn(|cx| Pin::new(&mut *stream).poll_write_message(cx, bytes))
        .await
        .unwrap();
    poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx))
        .await
        .unwrap();
}

#[tokio::test]
async fn boxed_uot_empty_message_then_payload_then_peer_eof_are_distinct() {
    let (mut peer, stream) = tcp_pair().await;
    peer.write_all(&[0, 0, 0, 3, b'a', b'b', b'c'])
        .await
        .unwrap();
    peer.shutdown().await.unwrap();
    let mut stream: Box<dyn AsyncMessageStream> = Box::new(VlessMessageStream::new(stream));
    let mut bytes = [0; 8];
    assert_eq!(recv(&mut stream, &mut bytes).await.unwrap(), 0);
    assert!(!stream.is_message_eof(), "empty frame is a datagram");
    assert_eq!(recv(&mut stream, &mut bytes).await.unwrap(), 3);
    assert_eq!(&bytes[..3], b"abc");
    assert!(!stream.is_message_eof());
    assert_eq!(recv(&mut stream, &mut bytes).await.unwrap(), 0);
    assert!(stream.is_message_eof(), "peer FIN is EOF");
    assert_eq!(recv(&mut stream, &mut bytes).await.unwrap(), 0);
    assert!(stream.is_message_eof(), "EOF stays terminal");
}

#[tokio::test]
async fn empty_datagrams_reach_real_udp_and_do_not_end_the_uot_relay() {
    let origin = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let mut bytes = [0; 32];
        for expected in [b"".as_slice(), b"first", b"", b"next"] {
            let (n, peer) = origin.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], expected);
            assert_eq!(origin.send_to(&bytes[..n], peer).await.unwrap(), n);
        }
    });
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let connector = SocketConnectorImpl::new_tcp(None, true);
    let target = ResolvedLocation::with_resolved(
        NetLocation::from_ip_addr(origin_address.ip(), origin_address.port()),
        origin_address,
    );
    let mut udp = connector
        .connect_udp_bidirectional(&resolver, target)
        .await
        .unwrap();
    let (client, server) = tcp_pair().await;
    let relay = tokio::spawn(async move {
        let mut framed = VlessMessageStream::new(server);
        copy_bidirectional_message(&mut framed, &mut udp, false, false).await
    });
    let mut client: Box<dyn AsyncMessageStream> = Box::new(VlessMessageStream::new(client));
    let mut bytes = [0; 32];
    for expected in [b"".as_slice(), b"first", b"", b"next"] {
        send(&mut client, expected).await;
        let n = recv(&mut client, &mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], expected);
        assert!(!client.is_message_eof());
    }
    origin_task.await.unwrap();
    poll_fn(|cx| Pin::new(&mut *client).poll_shutdown_message(cx))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .expect("real EOF must terminate the relay")
        .unwrap()
        .unwrap();
    assert_eq!(recv(&mut client, &mut bytes).await.unwrap(), 0);
    assert!(client.is_message_eof());
}

#[tokio::test]
async fn full_frame_survives_small_buffer_and_partial_frame_eof_stays_an_error() {
    let (mut peer, stream) = tcp_pair().await;
    peer.write_all(&[0, 3, b'a', b'b', b'c', 0, 2, b'z'])
        .await
        .unwrap();
    peer.shutdown().await.unwrap();
    let mut stream: Box<dyn AsyncMessageStream> = Box::new(VlessMessageStream::new(stream));
    assert!(recv(&mut stream, &mut [0; 2]).await.is_err());
    assert!(!stream.is_message_eof());
    let mut bytes = [0; 3];
    assert_eq!(recv(&mut stream, &mut bytes).await.unwrap(), 3);
    assert_eq!(&bytes, b"abc");
    assert_eq!(
        recv(&mut stream, &mut bytes).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert!(stream.is_message_eof());
}
