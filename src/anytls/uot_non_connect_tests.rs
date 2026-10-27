//! UoT v2 non-connect mode as stock sing-box v1.12.0 sends it, replayed over
//! real TLS through the real AnyTLS server to a real UDP destination.
//!
//! sing-box terminates a client's UoT stream itself and re-dials with
//! `isConnect = 0`: one PSH carries the request and first record, and every
//! later datagram is one PSH of `[family 0x00][IPv4][port][u16 length][payload]`.
//! An empty datagram is therefore a 9-byte record with length zero.
//!
//! Empty client datagrams reach the destination. Empty destination replies are
//! dropped: stock sing-box (sing v0.7.0-beta.2) stalls after relaying one.
use super::anytls_types::{Command, Frame, FrameCodec};
use super::write_eof_offer_tests::{Io, PASSWORD, client_tls, direct_selector, tls};
use super::*;
use crate::address::{Address, NetLocation};
use crate::resolver::NativeResolver;
use crate::socks_handler::write_location_to_vec;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::uot::UOT_V2_MAGIC_ADDRESS;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// One non-connect record in sing-box's address layout (IPv4 family is 0x00).
fn record(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x00];
    bytes.extend(target.ip().octets());
    bytes.extend(target.port().to_be_bytes());
    bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend(payload);
    bytes
}

/// Splits complete records off the stream's reply bytes.
fn take_records(buffer: &mut Vec<u8>, replies: &mut Vec<Vec<u8>>) {
    loop {
        // family + IPv4 + port + length
        if buffer.len() < 9 {
            return;
        }
        assert_eq!(buffer[0], 0x00, "reply record family");
        let len = usize::from(u16::from_be_bytes([buffer[7], buffer[8]]));
        if buffer.len() < 9 + len {
            return;
        }
        replies.push(buffer[9..9 + len].to_vec());
        buffer.drain(..9 + len);
    }
}

/// Sends `payloads` the way sing-box does and returns the datagram lengths the
/// destination saw and the replies the client received.
async fn replay(enabled: bool, payloads: &[&[u8]]) -> (Vec<usize>, Vec<Vec<u8>>) {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let std::net::SocketAddr::V4(target) = echo.local_addr().unwrap() else {
        unreachable!()
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let counted = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            counted.lock().unwrap().push(n);
            echo.send_to(&buf[..n], peer).await.unwrap();
        }
    });

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
        .with_write_eof(enabled)
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
    let magic = NetLocation::new(Address::from(UOT_V2_MAGIC_ADDRESS).unwrap(), 0);
    let mut head = BytesMut::new();
    Frame::with_data(Command::Settings, 0, Bytes::from_static(b"v=2")).encode_into(&mut head);
    Frame::control(Command::Syn, 1).encode_into(&mut head);
    Frame::with_data(Command::Psh, 1, write_location_to_vec(&magic).into()).encode_into(&mut head);
    transport.write_all(&head).await.unwrap();
    transport.flush().await.unwrap();
    let mut received = BytesMut::new();
    let mut stream_bytes = Vec::new();
    let mut replies = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let mut data = Vec::new();
        if index == 0 {
            // Request: isConnect = 0, then a SOCKS address (ATYP IPv4).
            data.extend([0x00, 0x01]);
            data.extend(target.ip().octets());
            data.extend(target.port().to_be_bytes());
        }
        data.extend(record(target, payload));
        transport
            .write_all(&Frame::with_data(Command::Psh, 1, data.into()).encode())
            .await
            .unwrap();
        transport.flush().await.unwrap();
        // One datagram in flight at a time, as the downstream exchange does.
        // An empty datagram has no reply to wait for: wait for its delivery.
        let delivered = index + 1;
        let expected = replies.len() + usize::from(!payload.is_empty());
        let _ = timeout(Duration::from_secs(2), async {
            while seen.lock().unwrap().len() < delivered || replies.len() < expected {
                let read = timeout(Duration::from_millis(20), transport.read_buf(&mut received));
                if let Ok(read) = read.await
                    && read.unwrap() == 0
                {
                    return;
                }
                while let Some(frame) = FrameCodec::decode(&mut received).unwrap() {
                    if frame.cmd == Command::Psh && frame.stream_id == 1 {
                        stream_bytes.extend_from_slice(&frame.data);
                    }
                }
                take_records(&mut stream_bytes, &mut replies);
            }
        })
        .await;
    }
    // A late empty reply would arrive here.
    let _ = timeout(Duration::from_millis(300), async {
        while transport.read_buf(&mut received).await.unwrap() > 0 {
            while let Some(frame) = FrameCodec::decode(&mut received).unwrap() {
                if frame.cmd == Command::Psh && frame.stream_id == 1 {
                    stream_bytes.extend_from_slice(&frame.data);
                }
            }
            take_records(&mut stream_bytes, &mut replies);
        }
    })
    .await;
    let seen = seen.lock().unwrap().clone();
    (seen, replies)
}

#[tokio::test]
async fn stock_non_connect_uot_delivers_empty_datagram_and_drops_empty_reply() {
    for enabled in [false, true] {
        let payloads: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];
        let (seen, replies) = replay(enabled, &payloads).await;
        eprintln!(
            "non-connect UoT enabled={enabled}: destination datagram lengths={seen:?} reply lengths={:?}",
            replies.iter().map(Vec::len).collect::<Vec<_>>()
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
    let (seen, replies) = replay(false, &payloads).await;
    eprintln!(
        "non-connect UoT empty first: destination datagram lengths={seen:?} reply lengths={:?}",
        replies.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(seen, vec![0, 11], "destination datagrams");
    assert_eq!(replies, [b"after-empty".to_vec()], "client replies");
}
