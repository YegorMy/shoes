//! Empty-datagram rules on Shoes' SOCKS and VLESS UDP server paths, each built
//! from YAML config and driven by a raw client against a real UDP destination.
//!
//! - UoT through the SOCKS server, in non-connect (packet-address) and in
//!   connect mode: empty client datagrams reach the destination, and empty
//!   destination replies are dropped.
//! - VLESS UDP, another `run_udp_copy` caller, still forwards an empty reply.
use super::UOT_V2_MAGIC_ADDRESS;
use super::reply_test_support::{
    Destination, serve_config, take_uot_records, uot_record, uot_request,
};
use crate::uuid_util::parse_uuid;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const SOCKS: &str = "    type: socks\n    udp_enabled: true\n";
// A public test identity, not a credential.
const VLESS_USER: &str = "6f1c5e7a-2b4d-4c8e-9a0f-3d5b7e9c1a2f";

/// SOCKS5 CONNECT to the UoT v2 magic host.
async fn socks_uot(server: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut connect = vec![5, 1, 0, 3, UOT_V2_MAGIC_ADDRESS.len() as u8];
    connect.extend(UOT_V2_MAGIC_ADDRESS.as_bytes());
    connect.extend([0, 0]);
    stream.write_all(&connect).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS CONNECT refused");
    stream
}

/// Reads for up to 20 ms and splits off complete records.
async fn read_records(
    stream: &mut TcpStream,
    connect: bool,
    buffer: &mut Vec<u8>,
    replies: &mut Vec<Vec<u8>>,
) {
    let mut chunk = [0; 1024];
    if let Ok(Ok(n)) = timeout(Duration::from_millis(20), stream.read(&mut chunk)).await {
        buffer.extend_from_slice(&chunk[..n]);
        take_uot_records(connect, buffer, replies);
    }
}

/// Reads records until `count` replies arrived (bounded), then for 300 ms
/// more, where a late empty reply would show up.
async fn collect(
    stream: &mut TcpStream,
    connect: bool,
    buffer: &mut Vec<u8>,
    replies: &mut Vec<Vec<u8>>,
    count: usize,
) {
    let _ = timeout(Duration::from_secs(2), async {
        while replies.len() < count {
            read_records(stream, connect, buffer, replies).await;
        }
    })
    .await;
    let _ = timeout(Duration::from_millis(300), async {
        loop {
            read_records(stream, connect, buffer, replies).await;
        }
    })
    .await;
}

/// Sends `payloads` over SOCKS UoT to an echo destination, one datagram in
/// flight at a time, and returns the destination's datagram lengths and the
/// client's replies.
async fn socks_uot_exchange(connect: bool, payloads: &[&[u8]]) -> (Vec<usize>, Vec<Vec<u8>>) {
    let destination = Destination::echo().await;
    let (server, serving) = serve_config(SOCKS).await;
    let mut stream = socks_uot(server).await;
    let mut buffer = Vec::new();
    let mut replies = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let mut data = Vec::new();
        if index == 0 {
            data = uot_request(connect, destination.target);
        }
        data.extend(uot_record(connect, destination.target, payload));
        stream.write_all(&data).await.unwrap();
        // An empty datagram has no reply to wait for: wait for its delivery.
        let expected = replies.len() + usize::from(!payload.is_empty());
        destination.wait_seen(index + 1).await;
        let _ = timeout(Duration::from_secs(2), async {
            while replies.len() < expected {
                read_records(&mut stream, connect, &mut buffer, &mut replies).await;
            }
        })
        .await;
    }
    collect(&mut stream, connect, &mut buffer, &mut replies, 0).await;
    serving.abort();
    (destination.seen(), replies)
}

fn lengths(replies: &[Vec<u8>]) -> Vec<usize> {
    replies.iter().map(Vec::len).collect()
}

#[tokio::test]
async fn socks_non_connect_uot_delivers_empty_datagram_and_drops_empty_reply() {
    let payloads: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];
    let (seen, replies) = socks_uot_exchange(false, &payloads).await;
    eprintln!(
        "SOCKS non-connect UoT: destination datagram lengths={seen:?} reply lengths={:?}",
        lengths(&replies)
    );
    assert_eq!(seen, vec![12, 0, 11], "destination datagrams");
    assert_eq!(
        replies,
        [b"before-empty".to_vec(), b"after-empty".to_vec()],
        "client replies"
    );
}

#[tokio::test]
async fn socks_connect_uot_delivers_empty_datagram_and_drops_empty_reply() {
    let payloads: [&[u8]; 4] = [b"before-empty", b"", b"after-empty", b"still-alive"];
    let (seen, replies) = socks_uot_exchange(true, &payloads).await;
    eprintln!(
        "SOCKS connect UoT: destination datagram lengths={seen:?} reply lengths={:?}",
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

#[tokio::test]
async fn vless_udp_still_forwards_empty_reply() {
    let destination = Destination::echo().await;
    let (server, serving) =
        serve_config(&format!("    type: vless\n    user_id: {VLESS_USER}\n")).await;
    let mut stream = TcpStream::connect(server).await.unwrap();
    // version, user id, no addons, command UDP, port, ATYP IPv4, address
    let mut request = vec![0];
    request.extend(parse_uuid(VLESS_USER).unwrap());
    request.extend([0, 2]);
    request.extend(destination.target.port().to_be_bytes());
    request.push(1);
    request.extend(destination.target.ip().octets());
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 0], "VLESS response header");
    let mut buffer = Vec::new();
    let mut replies = Vec::new();
    let payloads: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];
    for (index, payload) in payloads.iter().enumerate() {
        stream
            .write_all(&uot_record(true, destination.target, payload))
            .await
            .unwrap();
        destination.wait_seen(index + 1).await;
        let _ = timeout(Duration::from_secs(2), async {
            while replies.len() <= index {
                read_records(&mut stream, true, &mut buffer, &mut replies).await;
            }
        })
        .await;
    }
    collect(&mut stream, true, &mut buffer, &mut replies, 0).await;
    eprintln!(
        "VLESS UDP: destination datagram lengths={:?} reply lengths={:?}",
        destination.seen(),
        lengths(&replies)
    );
    assert_eq!(destination.seen(), vec![12, 0, 11], "destination datagrams");
    // Not a UoT path: the empty reply is still relayed as a zero-length frame.
    assert_eq!(
        replies,
        payloads.map(<[u8]>::to_vec),
        "client replies, unchanged"
    );
    serving.abort();
}
