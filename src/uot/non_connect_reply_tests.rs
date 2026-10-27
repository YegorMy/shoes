//! UoT v2 non-connect mode through Shoes' SOCKS server (a packet-address UoT
//! server path other than AnyTLS), configured and started as the binary does,
//! to a real UDP destination.
//!
//! Empty client datagrams reach the destination. Empty destination replies are
//! dropped, and the session keeps relaying the replies after them.
use super::UOT_V2_MAGIC_ADDRESS;
use crate::config::{Config, create_server_configs};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_server::start_servers;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// One non-connect record in AddrParser layout (IPv4 family is 0x00).
fn record(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x00];
    bytes.extend(target.ip().octets());
    bytes.extend(target.port().to_be_bytes());
    bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend(payload);
    bytes
}

/// Splits complete reply records off the received bytes.
fn take_records(buffer: &mut Vec<u8>, replies: &mut Vec<Vec<u8>>) {
    // family + IPv4 + port + length
    while buffer.len() >= 9 {
        assert_eq!(buffer[0], 0x00, "reply record family");
        let len = usize::from(u16::from_be_bytes([buffer[7], buffer[8]]));
        if buffer.len() < 9 + len {
            return;
        }
        replies.push(buffer[9..9 + len].to_vec());
        buffer.drain(..9 + len);
    }
}

async fn read_replies(stream: &mut TcpStream, buffer: &mut Vec<u8>, replies: &mut Vec<Vec<u8>>) {
    let mut chunk = [0; 1024];
    if let Ok(Ok(n)) = timeout(Duration::from_millis(20), stream.read(&mut chunk)).await {
        buffer.extend_from_slice(&chunk[..n]);
        take_records(buffer, replies);
    }
}

#[tokio::test]
async fn socks_non_connect_uot_delivers_empty_datagram_and_drops_empty_reply() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(target) = echo.local_addr().unwrap() else {
        unreachable!()
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let counted = seen.clone();
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            counted.lock().unwrap().push(n);
            echo.send_to(&buf[..n], peer).await.unwrap();
        }
    });

    let bind = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let yaml =
        format!("- address: '{bind}'\n  protocol:\n    type: socks\n    udp_enabled: true\n");
    let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut servers = Vec::new();
    for config in create_server_configs(configs).unwrap().configs {
        servers.extend(start_servers(config, resolver.clone()).await.unwrap());
    }
    let mut stream = timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(bind).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap();

    // SOCKS5 CONNECT to the UoT v2 magic host.
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

    let payloads: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];
    let mut buffer = Vec::new();
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
        stream.write_all(&data).await.unwrap();
        // An empty datagram has no reply to wait for: wait for its delivery.
        let expected = replies.len() + usize::from(!payload.is_empty());
        let _ = timeout(Duration::from_secs(2), async {
            while seen.lock().unwrap().len() <= index || replies.len() < expected {
                read_replies(&mut stream, &mut buffer, &mut replies).await;
            }
        })
        .await;
    }
    // A late empty reply would arrive here.
    let _ = timeout(Duration::from_millis(300), async {
        loop {
            read_replies(&mut stream, &mut buffer, &mut replies).await;
        }
    })
    .await;

    let seen = seen.lock().unwrap().clone();
    eprintln!(
        "SOCKS non-connect UoT: destination datagram lengths={seen:?} reply lengths={:?}",
        replies.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(seen, vec![12, 0, 11], "destination datagrams");
    assert_eq!(
        replies,
        [b"before-empty".to_vec(), b"after-empty".to_vec()],
        "client replies"
    );
    echo_task.abort();
    for server in servers {
        server.abort();
    }
}
