//! UoT v2 through the real AnyTLS server over real TLS to a real UDP
//! destination, in non-connect mode as stock sing-box v1.12.0 sends it and in
//! connect mode.
//!
//! sing-box terminates a client's UoT stream itself and re-dials with
//! `isConnect = 0`: one PSH carries the request and first record, and every
//! later datagram is one PSH of `[family 0x00][IPv4][port][u16 length][payload]`.
//! With a `udp_connect` route it dials `isConnect = 1` instead, and every
//! datagram is `[u16 length][payload]`. Either way an empty datagram is a
//! record with length zero.
//!
//! Empty client datagrams reach the destination. Empty destination replies are
//! dropped, also after a negotiated client sends WRITE_EOF: stock sing-box
//! (sing v0.7.0-beta.2) stalls after relaying one.
use super::anytls_types::{Command, Frame, FrameCodec};
use super::write_eof_offer_tests::{Io, PASSWORD, client_tls, direct_selector, tls};
use super::*;
use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::resolver::NativeResolver;
use crate::socks_handler::write_location_to_vec;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::uot::UOT_V2_MAGIC_ADDRESS;
use crate::uot::reply_test_support::{Destination, take_uot_records, uot_record, uot_request};
use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

/// How the AnyTLS session is set up.
#[derive(Clone, Copy, Debug)]
enum Session {
    /// Server without write-eof/1.
    Legacy,
    /// Server with write-eof/1 enabled, client without the offer.
    Enabled,
    /// Server and client agree on write-eof/1.
    Negotiated,
}

const SESSIONS: [Session; 3] = [Session::Legacy, Session::Enabled, Session::Negotiated];

/// A raw AnyTLS client with one UoT stream (stream 1) open.
struct UotClient {
    transport: Box<dyn AsyncStream>,
    connect: bool,
    received: BytesMut,
    stream_bytes: Vec<u8>,
    replies: Vec<Vec<u8>>,
}

impl UotClient {
    async fn open(session: Session, connect: bool) -> Self {
        let tls = tls();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tls.acceptor.clone();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let transport = acceptor.accept(tcp).await.unwrap();
            AnyTlsServerHandler::new(
                vec![("public-test".into(), PASSWORD.into())],
                PaddingFactory::default_factory(),
                Arc::new(NativeResolver),
                direct_selector(),
                true,
                None,
            )
            .with_write_eof(!matches!(session, Session::Legacy))
            .setup_server_stream(Box::new(Io(transport)))
            .await
            .unwrap();
        });
        let mut transport = client_tls(&tls, TcpStream::connect(addr).await.unwrap()).await;
        let mut password = [0; 32];
        password.copy_from_slice(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, PASSWORD.as_bytes()).as_ref(),
        );
        AnyTlsClientSession::send_auth(
            &mut transport,
            &password,
            &PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        let settings: &'static [u8] = match session {
            Session::Negotiated => b"v=2\nx-write-eof=1",
            Session::Legacy | Session::Enabled => b"v=2",
        };
        let magic = NetLocation::new(Address::from(UOT_V2_MAGIC_ADDRESS).unwrap(), 0);
        let mut head = BytesMut::new();
        Frame::with_data(Command::Settings, 0, Bytes::from_static(settings)).encode_into(&mut head);
        Frame::control(Command::Syn, 1).encode_into(&mut head);
        Frame::with_data(Command::Psh, 1, write_location_to_vec(&magic).into())
            .encode_into(&mut head);
        transport.write_all(&head).await.unwrap();
        transport.flush().await.unwrap();
        Self {
            transport,
            connect,
            received: BytesMut::new(),
            stream_bytes: Vec::new(),
            replies: Vec::new(),
        }
    }

    async fn send(&mut self, data: Vec<u8>) {
        self.transport
            .write_all(&Frame::with_data(Command::Psh, 1, data.into()).encode())
            .await
            .unwrap();
        self.transport.flush().await.unwrap();
    }

    /// Ends the client's write side of stream 1 (write-eof/1 only).
    async fn write_eof(&mut self) {
        self.transport
            .write_all(&Frame::control(Command::WriteEof, 1).encode())
            .await
            .unwrap();
        self.transport.flush().await.unwrap();
    }

    /// Reads for up to 20 ms and splits off complete reply records.
    async fn read_some(&mut self) {
        let read = timeout(
            Duration::from_millis(20),
            self.transport.read_buf(&mut self.received),
        );
        if let Ok(read) = read.await {
            read.unwrap();
        }
        while let Some(frame) = FrameCodec::decode(&mut self.received).unwrap() {
            if frame.cmd == Command::Psh && frame.stream_id == 1 {
                self.stream_bytes.extend_from_slice(&frame.data);
            }
        }
        take_uot_records(self.connect, &mut self.stream_bytes, &mut self.replies);
    }

    /// Reads until `count` replies arrived (bounded), then for 300 ms more,
    /// where a late empty reply would show up.
    async fn collect(&mut self, count: usize) {
        let _ = timeout(Duration::from_secs(2), async {
            while self.replies.len() < count {
                self.read_some().await;
            }
        })
        .await;
        let _ = timeout(Duration::from_millis(300), async {
            loop {
                self.read_some().await;
            }
        })
        .await;
    }
}

/// Sends `payloads` to an echo destination, one datagram in flight at a time
/// as the downstream exchange does, and returns the datagram lengths the
/// destination saw and the replies the client received.
async fn replay(session: Session, connect: bool, payloads: &[&[u8]]) -> (Vec<usize>, Vec<Vec<u8>>) {
    let destination = Destination::echo().await;
    let mut client = UotClient::open(session, connect).await;
    for (index, payload) in payloads.iter().enumerate() {
        let mut data = Vec::new();
        if index == 0 {
            data = uot_request(connect, destination.target);
        }
        data.extend(uot_record(connect, destination.target, payload));
        client.send(data).await;
        // An empty datagram has no reply to wait for: wait for its delivery.
        let expected = client.replies.len() + usize::from(!payload.is_empty());
        destination.wait_seen(index + 1).await;
        let _ = timeout(Duration::from_secs(2), async {
            while client.replies.len() < expected {
                client.read_some().await;
            }
        })
        .await;
    }
    client.collect(0).await;
    (destination.seen(), client.replies)
}

fn lengths(replies: &[Vec<u8>]) -> Vec<usize> {
    replies.iter().map(Vec::len).collect()
}

#[tokio::test]
async fn stock_non_connect_uot_delivers_empty_datagram_and_drops_empty_reply() {
    for session in SESSIONS {
        let payloads: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];
        let (seen, replies) = replay(session, false, &payloads).await;
        eprintln!(
            "non-connect UoT session={session:?}: destination datagram lengths={seen:?} reply lengths={:?}",
            lengths(&replies)
        );
        assert_eq!(seen, vec![12, 0, 11], "destination datagrams");
        // The empty reply is dropped; the session and the reply after it live on.
        assert_eq!(
            replies,
            [b"before-empty".to_vec(), b"after-empty".to_vec()],
            "client replies"
        );
    }
}

#[tokio::test]
async fn stock_non_connect_uot_delivers_empty_first_datagram_and_drops_its_reply() {
    let payloads: [&[u8]; 2] = [b"", b"after-empty"];
    let (seen, replies) = replay(Session::Legacy, false, &payloads).await;
    eprintln!(
        "non-connect UoT empty first: destination datagram lengths={seen:?} reply lengths={:?}",
        lengths(&replies)
    );
    assert_eq!(seen, vec![0, 11], "destination datagrams");
    assert_eq!(replies, [b"after-empty".to_vec()], "client replies");
}

#[tokio::test]
async fn connect_uot_delivers_empty_datagram_and_drops_empty_reply() {
    for session in SESSIONS {
        let payloads: [&[u8]; 4] = [b"before-empty", b"", b"after-empty", b"still-alive"];
        let (seen, replies) = replay(session, true, &payloads).await;
        eprintln!(
            "connect UoT session={session:?}: destination datagram lengths={seen:?} reply lengths={:?}",
            lengths(&replies)
        );
        assert_eq!(seen, vec![12, 0, 11, 11], "destination datagrams");
        // The empty reply is dropped; the session relays the replies after it.
        assert_eq!(
            replies,
            [
                b"before-empty".to_vec(),
                b"after-empty".to_vec(),
                b"still-alive".to_vec()
            ],
            "client replies"
        );
    }
}

#[tokio::test]
async fn negotiated_non_connect_uot_drops_empty_reply_after_write_eof() {
    let (go, script) = oneshot::channel();
    let destination = Destination::scripted(script).await;
    let mut client = UotClient::open(Session::Negotiated, false).await;
    let mut data = uot_request(false, destination.target);
    data.extend(uot_record(false, destination.target, b"start"));
    client.send(data).await;
    destination.wait_seen(1).await;
    // The client ends its write side and keeps reading replies.
    client.write_eof().await;
    // Let the server reach the stream's end before any reply.
    sleep(Duration::from_millis(300)).await;
    go.send(()).unwrap();
    client.collect(2).await;
    eprintln!(
        "negotiated non-connect UoT after WRITE_EOF: destination datagram lengths={:?} reply lengths={:?}",
        destination.seen(),
        lengths(&client.replies)
    );
    assert_eq!(destination.seen(), vec![5], "destination datagrams");
    assert_eq!(
        client.replies,
        [b"before-empty".to_vec(), b"after-empty".to_vec()],
        "client replies after WRITE_EOF"
    );
}
