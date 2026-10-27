//! Pinned stock sing-box v1.12.0 client relaying an empty UDP datagram over
//! UoT v2 to the Shoes AnyTLS server. sing-box terminates the client's UoT
//! stream and re-dials Shoes in non-connect mode, which is the path tested.
//!
//! The pinned client cannot relay an empty reply: sing v0.7.0-beta.2
//! `common/bufio/vectorised_unix.go` never consumes the zero-length payload
//! iovec, so its writer spins and later replies never leave it (reproduced
//! without Shoes, with sing-box as both client and server). Shoes therefore
//! drops empty destination replies on packet-address UoT paths: the empty
//! datagram still reaches the destination, and the reply after it reaches the
//! SOCKS client.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shoes::config::{Config, convert_cert_paths, create_server_configs};
use shoes::resolver::{NativeResolver, Resolver};
use shoes::tcp::tcp_server::start_servers;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const PEER: &str = "ghcr.io/sagernet/sing-box:v1.12.0@sha256:3c1ee82d450df9b336b6f63b1d272cf86e3835392d99596ef8c35f206a457999";
const PASSWORD: &str = "anytls-uot-peer-public-test";
const MAGIC: &[u8] = b"sp.v2.udp-over-tcp.arpa";
const LIMIT: Duration = Duration::from_secs(10);

struct PeerGuard(String);

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

async fn exact(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// SOCKS5 CONNECT to the UoT v2 magic host, then a connect-mode request.
async fn uot_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[5, 1, 0]).await?;
    if exact(&mut stream, 2).await? != [5, 0] {
        return Err(std::io::Error::other("SOCKS greeting refused"));
    }
    let mut connect = vec![5, 1, 0, 3, MAGIC.len() as u8];
    connect.extend_from_slice(MAGIC);
    connect.extend_from_slice(&[0, 0]);
    stream.write_all(&connect).await?;
    let reply = exact(&mut stream, 4).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other("SOCKS CONNECT refused"));
    }
    let bound = match reply[3] {
        1 => 6,
        4 => 18,
        _ => usize::from(exact(&mut stream, 1).await?[0]) + 2,
    };
    exact(&mut stream, bound).await?;
    let SocketAddr::V4(target) = target else {
        unreachable!()
    };
    let mut request = vec![1, 1];
    request.extend(target.ip().octets());
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;
    Ok(stream)
}

async fn uot_send(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(&u16::try_from(payload.len()).unwrap().to_be_bytes())
        .await?;
    stream.write_all(payload).await
}

async fn uot_exchange(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    uot_send(stream, payload).await?;
    let len = u16::from_be_bytes(exact(stream, 2).await?.try_into().unwrap());
    exact(stream, usize::from(len)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn container_singbox_uot_relays_empty_datagram_to_anytls() {
    let version = Command::new("docker")
        .args(["run", "--rm", PEER, "version"])
        .output()
        .expect("Docker is required for this optional peer test");
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("sing-box version 1.12.0"));

    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, identity.cert.pem()).unwrap();
    std::fs::write(&key, identity.signing_key.serialize_pem()).unwrap();
    let port = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let yaml = format!(
        r#"
- address: "0.0.0.0:{port}"
  protocol:
    type: tls
    tls_targets:
      "localhost":
        cert: "{}"
        key: "{}"
        protocol:
          type: anytls
          udp_enabled: true
          users:
            - name: public-test
              password: "{PASSWORD}"
"#,
        cert.display(),
        key.display()
    );
    let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
    let (configs, _) = convert_cert_paths(configs).await.unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut servers = Vec::new();
    for config in create_server_configs(configs).unwrap().configs {
        servers.extend(start_servers(config, resolver.clone()).await.unwrap());
    }

    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = echo.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let counted = seen.clone();
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            counted.lock().unwrap().push(n);
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    let config = serde_json::json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "0.0.0.0", "listen_port": 1080}],
        "outbounds": [{
            "type": "anytls", "tag": "proxy", "server": "host.docker.internal",
            "server_port": port, "password": PASSWORD,
            "tls": {"enabled": true, "server_name": "localhost",
                    "certificate": [identity.cert.pem()]}
        }]
    });
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mount = format!("{}:/etc/sing-box/config.json:ro", config_path.display());
    let started = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--add-host",
            "host.docker.internal:host-gateway",
            "-p",
            "127.0.0.1::1080",
            "-v",
            &mount,
            PEER,
            "run",
            "-c",
            "/etc/sing-box/config.json",
        ])
        .output()
        .unwrap();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let peer = PeerGuard(String::from_utf8(started.stdout).unwrap().trim().to_owned());
    let published = Command::new("docker")
        .args(["port", &peer.0, "1080/tcp"])
        .output()
        .unwrap();
    let socks: SocketAddr = String::from_utf8(published.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // The published port accepts before sing-box listens: retry the handshake.
    let deadline = tokio::time::Instant::now() + LIMIT;
    let mut stream = loop {
        match uot_connect(socks, target).await {
            Ok(stream) => break stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await
            }
            Err(error) => panic!("sing-box SOCKS inbound unavailable: {error}"),
        }
    };
    let payloads: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];
    let mut replies = Vec::new();
    for (index, payload) in payloads.into_iter().enumerate() {
        if payload.is_empty() {
            // No reply is expected: wait until the destination has the datagram.
            uot_send(&mut stream, payload).await.unwrap();
            let _ = tokio::time::timeout(LIMIT, async {
                while seen.lock().unwrap().len() <= index {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
            continue;
        }
        match tokio::time::timeout(LIMIT, uot_exchange(&mut stream, payload)).await {
            Ok(Ok(reply)) => replies.push(reply),
            other => {
                eprintln!(
                    "sing-box UoT exchange for a {}-byte datagram failed: {other:?}",
                    payload.len()
                );
                break;
            }
        }
    }
    // Every datagram must reach the destination, whatever the replies were.
    let _ = tokio::time::timeout(LIMIT, async {
        while seen.lock().unwrap().len() < payloads.len() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let seen = seen.lock().unwrap().clone();
    eprintln!(
        "sing-box UoT destination datagram lengths={seen:?} reply lengths={:?}",
        replies.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert_eq!(seen, vec![12, 0, 11], "destination datagrams");
    assert_eq!(
        replies,
        [b"before-empty".to_vec(), b"after-empty".to_vec()],
        "client replies"
    );
    drop(peer);
    echo_task.abort();
    for server in servers {
        server.abort();
    }
}
