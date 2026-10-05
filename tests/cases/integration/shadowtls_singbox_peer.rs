use super::*;
use rustls::pki_types::pem::PemObject;
use std::process::Command;
use tokio_rustls::TlsAcceptor;

const PEER: &str = "ghcr.io/sagernet/sing-box:v1.12.0@sha256:3c1ee82d450df9b336b6f63b1d272cf86e3835392d99596ef8c35f206a457999";

struct PeerGuard(String);

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn container_singbox_v3_peer_accepts_verified_wire_and_rejects_bad_pin() {
    let version = Command::new("docker")
        .args(["run", "--rm", PEER, "version"])
        .output()
        .expect("Docker is required for this optional peer test");
    assert!(
        version.status.success(),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).contains("sing-box version 1.12.0"));
    let cert = generate_handshake_cert(SNI);
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
        .map(Result::unwrap)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .unwrap();
    let handshake_port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let host = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    let mut byte = [0u8; 1];
                    let _ = tls.read(&mut byte).await;
                }
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    // These public fixture constants are synthetic; no user credentials,
    // private keys, source directories or production configuration are mounted.
    let ss_key_b64 = ss_key();
    let config = serde_json::json!({
        "log": {"level":"error"},
        "inbounds": [
            {"type":"shadowtls", "tag":"st-in", "listen":"0.0.0.0", "listen_port":1080,
             "version":3, "users":[{"password":SHADOWTLS_PASSWORD}],
             "handshake":{"server":"host.docker.internal","server_port":handshake_port}, "detour":"ss-in"},
            {"type":"shadowsocks", "tag":"ss-in", "listen":"127.0.0.1", "listen_port":1081,
             "method":"2022-blake3-aes-128-gcm", "password":ss_key_b64}
        ], "outbounds":[{"type":"direct","tag":"direct"}], "route":{"final":"direct"}
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
    assert!(published.status.success());
    let address: std::net::SocketAddr = String::from_utf8(published.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let ready_deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionRefused
                    && tokio::time::Instant::now() < ready_deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
            Err(error) => panic!("reference listener unavailable: {error}"),
        }
    }
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    let echo = tokio::spawn(async move {
        while let Ok((mut socket, _)) = origin.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let target = NetLocation::new(Address::from("host.docker.internal").unwrap(), origin_port);
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let bad_pin = "00".repeat(32);
    for (pin, allowed) in [(&cert.sha256_hex, true), (&bad_pin, false)] {
        let chain = build_chain(
            address.port(),
            &ss_key_b64,
            &format!("  verify: false\n  server_fingerprints: [\"{pin}\"]\n"),
        );
        let result = tokio::time::timeout(
            CONNECT_TIMEOUT,
            chain.connect_tcp(ResolvedLocation::from(target.clone()), &resolver),
        )
        .await
        .expect("reference handshake timed out");
        if allowed {
            let mut stream = result
                .expect("independent v3 peer must accept verified client")
                .client_stream;
            stream.write_all(b"verified-v3-wire").await.unwrap();
            stream.flush().await.unwrap();
            let mut bytes = [0u8; 16];
            tokio::time::timeout(CONNECT_TIMEOUT, stream.read_exact(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes, b"verified-v3-wire");
            assert_eq!(count.load(Ordering::SeqCst), 1);
        } else {
            assert!(result.is_err(), "bad pin reached the reference origin");
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }
    }
    host.abort();
    echo.abort();
}
