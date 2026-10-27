//! Engine-wide diagnostics at TRACE with a global, unfiltered Shoes logger: the
//! default and DNS resolvers, TCP and UDP client chains, the QUIC server,
//! REALITY client and server, and the platform certificate verifier.
//! Fixture servers run in a separate, logger-free process; everything the
//! engine process writes (stdout, stderr, the engine log and tracing) is under
//! test and must not contain a protected value. A canary run pushes known
//! disclosures through the same channels to prove the checks are not vacuous.
//! Dependency records (quinn, hickory) are never filtered: they are tallied
//! and written to the capture directory, and Shoes' own records must be clean.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine;
use log::LevelFilter;
use parking_lot::Mutex;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use shoes::config::{Config, create_server_configs};
use shoes::logging::{Directive, FileLogWriter, init_multi_logger};
use shoes::resolver::Resolver;
use shoes::tcp::tcp_server::start_servers;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use super::super::{LIMIT, Tasks};
use super::client::{
    FixtureProcess, MapResolver, Violation, block, pem_certificate, pin, protect,
    protect_certificate, summary,
};
use super::guard::Event;
use super::{Policy, QUIC_FAILURES, TERMINALS, Writer, trace};

// Every protected canary contains MARKER, so partial renderings are caught too.
const MARKER: &str = "engine-privacy";
const CA_NAME: &str = "engine-privacy-ca-canary";
const TLS_NAME: &str = "tls.engine-privacy.invalid";
const SHADOWTLS_NAME: &str = "shadowtls.engine-privacy.invalid";
const TCP_DESTINATION: &str = "tcp-destination.engine-privacy.invalid";
const UDP_DESTINATION: &str = "udp-destination.engine-privacy.invalid";
// Not a special-use name, so the DNS resolver really queries the stub server.
const DNS_DESTINATION: &str = "dns-destination.engine-privacy.internal";
const MISSING: &str = "missing.engine-privacy.invalid";
const TLS_TARGET: &str = "tls-target.engine-privacy.invalid";
const SS_HOP: &str = "ss-hop.engine-privacy.invalid";
const REALITY_HOP: &str = "reality-hop.engine-privacy.invalid";
const REALITY_DEST: &str = "reality-dest.engine-privacy.invalid";
const SHADOWTLS_HOP: &str = "shadowtls-hop.engine-privacy.invalid";
// The default resolver resolves this real name: it is protected as a value.
const LOCALHOST: &str = "localhost";
const SHORT_ID: &str = "e9a1c3d5b7f90a2c";
const WRONG_SHORT_ID: &str = "0123456789abcdef";
const USER_ID: &str = "e9a1c3d5-0000-4000-8000-0123456789ab";
const PASSWORD: &str = "engine-privacy-shadowtls-password";
const SS_KEY_BYTES: &[u8] = b"engine-privacy-k";
const PAYLOAD: &[u8] = b"engine-privacy-payload-canary";
const ROLE: &str = "SHOES_ENGINE_PRIVACY_ROLE";
const DIR: &str = "SHOES_ENGINE_PRIVACY_DIR";
const FIXTURE: &str = "SHOES_ENGINE_PRIVACY_FIXTURE";
const TEST: &str = "tls::engine::engine_diagnostics_are_private";
// Dependency targets: their records are tallied and reported, never filtered.
const DEPENDENCIES: &[&str] = &["quinn", "hickory"];

fn ss_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(SS_KEY_BYTES)
}

/// Server-side material and addresses, published by the fixture process.
#[derive(Serialize, Deserialize)]
struct Fixture {
    ca: Vec<u8>,
    tls_leaf: Vec<u8>,
    shadowtls_leaf: Vec<u8>,
    servers: BTreeMap<String, SocketAddr>,
}

struct Material {
    ca: rcgen::Certificate,
    leaf: rcgen::Certificate,
    leaf_key: rcgen::KeyPair,
    shadowtls: rcgen::Certificate,
    shadowtls_key: rcgen::KeyPair,
}

impl Material {
    fn new() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, CA_NAME);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let issue = |name: &str| {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
            params.distinguished_name.push(DnType::CommonName, name);
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            (params.signed_by(&key, &issuer).unwrap(), key)
        };
        let (leaf, leaf_key) = issue(TLS_NAME);
        let (shadowtls, shadowtls_key) = issue(SHADOWTLS_NAME);
        Self {
            ca,
            leaf,
            leaf_key,
            shadowtls,
            shadowtls_key,
        }
    }
}

async fn serve_tls(listener: TcpListener, acceptor: TlsAcceptor) {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut tls) = acceptor.accept(socket).await {
                let mut payload = vec![0; PAYLOAD.len()];
                if tls.read_exact(&mut payload).await.is_ok() {
                    let _ = tls.write_all(&payload).await;
                    let _ = tls.shutdown().await;
                }
            }
        });
    }
}

async fn serve_echo(listener: TcpListener) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut payload = vec![0; PAYLOAD.len()];
            if socket.read_exact(&mut payload).await.is_ok() {
                let _ = socket.write_all(&payload).await;
                let _ = socket.shutdown().await;
            }
        });
    }
}

async fn serve_udp_echo(socket: UdpSocket) {
    let mut buf = vec![0; 65535];
    while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
        let _ = socket.send_to(&buf[..n], peer).await;
    }
}

/// A minimal DNS responder: an A record for DNS_DESTINATION, nothing else.
async fn serve_dns(socket: UdpSocket) {
    let mut buf = [0u8; 512];
    while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
        let query = &buf[..n];
        if n < 12 {
            continue;
        }
        let mut i = 12;
        let mut labels = Vec::new();
        while i < n && query[i] != 0 {
            let len = usize::from(query[i]);
            if i + 1 + len > n {
                break;
            }
            labels.push(String::from_utf8_lossy(&query[i + 1..i + 1 + len]).to_lowercase());
            i += 1 + len;
        }
        if i + 5 > n {
            continue;
        }
        let qtype = u16::from_be_bytes([query[i + 1], query[i + 2]]);
        let known = labels.join(".") == DNS_DESTINATION;
        let answer = known && qtype == 1;
        let mut response = query[..2].to_vec();
        response.extend([0x81, if known { 0x80 } else { 0x83 }]);
        response.extend([0, 1, 0, u8::from(answer), 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..i + 5]);
        if answer {
            response.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        }
        let _ = socket.send_to(&response, peer).await;
    }
}

/// Fixture process: no logger is installed, so none of its output is captured.
fn fixture(dir: &Path) {
    let material = Material::new();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut tasks = Tasks(Vec::new());
            let mut servers = BTreeMap::new();
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![material.leaf.der().clone(), material.ca.der().clone()],
                PrivatePkcs8KeyDer::from(material.leaf_key.serialize_der()).into(),
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            servers.insert("tls13".to_owned(), listener.local_addr().unwrap());
            tasks.0.push(tokio::spawn(serve_tls(
                listener,
                TlsAcceptor::from(Arc::new(config)),
            )));
            // The default resolver may return either loopback first for
            // localhost: serve the same port on both where IPv6 exists (the
            // engine tries every resolved address in turn).
            let (echo4, echo6) = loop {
                let v4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = v4.local_addr().unwrap().port();
                match TcpListener::bind(("::1", port)).await {
                    Ok(v6) => break (v4, Some(v6)),
                    Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                        break (v4, None);
                    }
                    Err(_) => continue,
                }
            };
            servers.insert("echo4".to_owned(), echo4.local_addr().unwrap());
            tasks.0.push(tokio::spawn(serve_echo(echo4)));
            if let Some(echo6) = echo6 {
                servers.insert("echo6".to_owned(), echo6.local_addr().unwrap());
                tasks.0.push(tokio::spawn(serve_echo(echo6)));
            }
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            servers.insert("udp".to_owned(), udp.local_addr().unwrap());
            tasks.0.push(tokio::spawn(serve_udp_echo(udp)));
            let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            servers.insert("dns".to_owned(), dns.local_addr().unwrap());
            tasks.0.push(tokio::spawn(serve_dns(dns)));
            // A closed UDP port: the first DNS server of the composite fails.
            let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            servers.insert("dead-dns".to_owned(), dead.local_addr().unwrap());
            drop(dead);

            // A ShadowTLS v3 server with a local handshake identity issued by
            // the fixture CA, which no platform trust store contains.
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let bind = reserved.local_addr().unwrap();
            let yaml = format!(
                r#"
- address: '{bind}'
  protocol:
    type: tls
    shadowtls_targets:
      '{SHADOWTLS_NAME}':
        password: '{PASSWORD}'
        handshake:
          cert: |
{cert}          key: |
{key}        protocol:
          type: shadowsocks
          cipher: '2022-blake3-aes-128-gcm'
          password: '{ss_key}'
"#,
                cert = block(&material.shadowtls.pem(), 12),
                key = block(&material.shadowtls_key.serialize_pem(), 12),
                ss_key = ss_key(),
            );
            let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
            let config = create_server_configs(configs).unwrap().configs.remove(0);
            drop(reserved);
            let resolver = MapResolver(BTreeMap::new());
            tasks
                .0
                .extend(start_servers(config, Arc::new(resolver)).await.unwrap());
            servers.insert("shadowtls".to_owned(), bind);

            let fixture = Fixture {
                ca: material.ca.der().to_vec(),
                tls_leaf: material.leaf.der().to_vec(),
                shadowtls_leaf: material.shadowtls.der().to_vec(),
                servers,
            };
            let staged = dir.join("fixture.json.tmp");
            std::fs::write(&staged, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
            std::fs::rename(staged, dir.join("fixture.json")).unwrap();
            // Serve until the parent closes stdin (or kills this process).
            tokio::task::spawn_blocking(|| std::io::stdin().read_to_end(&mut Vec::new()))
                .await
                .unwrap()
                .unwrap();
        });
}

fn fixture_material(path: &Path) -> Fixture {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Engine-process material: the QUIC server identity and the REALITY keys.
struct EngineMaterial {
    quic_cert: rcgen::CertifiedKey<rcgen::KeyPair>,
    reality_private: String,
    reality_public: String,
}

impl EngineMaterial {
    fn new() -> Self {
        let quic_cert = rcgen::generate_simple_self_signed(vec![TLS_NAME.to_owned()]).unwrap();
        let keys = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .arg("generate-reality-keypair")
            .output()
            .unwrap();
        let keys = String::from_utf8(keys.stdout).unwrap();
        let key = |prefix: &str| {
            keys.lines()
                .find_map(|line| line.strip_prefix(prefix))
                .unwrap()
                .trim()
                .to_owned()
        };
        Self {
            quic_cert,
            reality_private: key("REALITY private key:"),
            reality_public: key("REALITY public key:"),
        }
    }
}

/// `protect`, plus the `{:02x?}` list rendering REALITY diagnostics use.
fn protect_bytes(policy: &mut Policy, bytes: &[u8]) {
    protect(policy, bytes);
    let listed = format!("{bytes:02x?}");
    policy
        .protected
        .push(listed.trim_matches(['[', ']']).to_owned());
}

fn protected_policy(fixture: &Fixture, engine: &EngineMaterial) -> Policy {
    let mut policy = Policy::default();
    policy.protected.push(MARKER.to_owned());
    for value in [
        CA_NAME,
        TLS_NAME,
        SHADOWTLS_NAME,
        TCP_DESTINATION,
        UDP_DESTINATION,
        DNS_DESTINATION,
        MISSING,
        TLS_TARGET,
        SS_HOP,
        REALITY_HOP,
        REALITY_DEST,
        SHADOWTLS_HOP,
        LOCALHOST,
        SHORT_ID,
        WRONG_SHORT_ID,
        USER_ID,
        PASSWORD,
        &engine.reality_private,
        &engine.reality_public,
    ] {
        protect_bytes(&mut policy, value.as_bytes());
    }
    for bytes in [SS_KEY_BYTES, ss_key().as_bytes(), PAYLOAD] {
        protect_bytes(&mut policy, bytes);
    }
    let base64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    for key in [&engine.reality_private, &engine.reality_public] {
        protect_bytes(&mut policy, &base64url.decode(key).unwrap());
    }
    for short_id in [SHORT_ID, WRONG_SHORT_ID] {
        let bytes: Vec<u8> = (0..short_id.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&short_id[i..i + 2], 16).unwrap())
            .collect();
        protect_bytes(&mut policy, &bytes);
    }
    for der in [
        &fixture.ca,
        &fixture.tls_leaf,
        &fixture.shadowtls_leaf,
        &engine.quic_cert.cert.der().to_vec(),
    ] {
        protect_certificate(&mut policy, der);
    }
    for address in fixture.servers.values() {
        policy.peer(*address);
    }
    policy
}

fn reserve_tcp(policy: &mut Policy) -> SocketAddr {
    let bind = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    policy.binds.push(bind.to_string());
    bind
}

fn reserve_udp(policy: &mut Policy) -> SocketAddr {
    let bind = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    policy.binds.push(bind.to_string());
    bind
}

/// Validated configs from YAML, as the binary loads them.
fn validated(yaml: &str) -> shoes::config::ValidatedConfigs {
    let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
    create_server_configs(configs).unwrap()
}

async fn start(yaml: &str, resolver: Arc<dyn Resolver>, tasks: &mut Tasks) {
    for config in validated(yaml).configs {
        tasks
            .0
            .extend(start_servers(config, resolver.clone()).await.unwrap());
    }
}

/// Unhooked startup binds in its own task: retry only refusals.
async fn connect(bind: SocketAddr) -> TcpStream {
    timeout(LIMIT, async {
        loop {
            match TcpStream::connect(bind).await {
                Ok(stream) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => panic!("engine listener connect failed: {e}"),
            }
        }
    })
    .await
    .expect("engine listener did not start")
}

async fn socks_greeting(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
}

/// Reads a SOCKS5 reply and its bound address; returns the reply code.
async fn socks_reply(stream: &mut TcpStream) -> Option<(u8, SocketAddr)> {
    let mut reply = [0; 4];
    timeout(LIMIT * 3, stream.read_exact(&mut reply))
        .await
        .ok()?
        .ok()?;
    let address = match reply[3] {
        1 => {
            let mut bound = [0; 6];
            stream.read_exact(&mut bound).await.ok()?;
            SocketAddr::from((
                [bound[0], bound[1], bound[2], bound[3]],
                u16::from_be_bytes([bound[4], bound[5]]),
            ))
        }
        4 => {
            let mut bound = [0; 18];
            stream.read_exact(&mut bound).await.ok()?;
            let ip: [u8; 16] = bound[..16].try_into().unwrap();
            SocketAddr::from((ip, u16::from_be_bytes([bound[16], bound[17]])))
        }
        _ => return None,
    };
    Some((reply[1], address))
}

async fn relay(stream: &mut TcpStream) -> bool {
    let mut payload = vec![0; PAYLOAD.len()];
    let exchange = async {
        stream.write_all(PAYLOAD).await?;
        stream.flush().await?;
        stream.read_exact(&mut payload).await
    };
    let echoed = timeout(LIMIT, exchange)
        .await
        .is_ok_and(|result| result.is_ok());
    echoed && payload == PAYLOAD
}

/// Waits for the listener's terminal record, not a timing guess.
async fn terminal(before: usize) {
    timeout(LIMIT, async {
        while TERMINALS.load(Ordering::SeqCst) <= before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("missing listener terminal diagnostic");
}

/// SOCKS5 CONNECT to a named destination; relays the payload when it connects.
async fn socks_flight(bind: SocketAddr, host: &str, port: u16, success: bool) {
    let before = TERMINALS.load(Ordering::SeqCst);
    let mut stream = connect(bind).await;
    socks_greeting(&mut stream).await;
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let connected = matches!(socks_reply(&mut stream).await, Some((0, _)));
    let relayed = connected && relay(&mut stream).await;
    assert_eq!(relayed, success, "SOCKS flight outcome");
    if !success {
        log::debug!(target: "tls_privacy_control", "engine rejection observed");
    }
    drop(stream);
    terminal(before).await;
}

/// SOCKS5 UDP ASSOCIATE, then one datagram to a named destination and back.
async fn udp_flight(bind: SocketAddr, host: &str, port: u16) {
    let before = TERMINALS.load(Ordering::SeqCst);
    let mut control = connect(bind).await;
    socks_greeting(&mut control).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let (code, relay) = socks_reply(&mut control)
        .await
        .expect("UDP ASSOCIATE reply");
    assert_eq!(code, 0);
    let relay = if relay.ip().is_unspecified() {
        SocketAddr::from(([127, 0, 0, 1], relay.port()))
    } else {
        relay
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut datagram = vec![0, 0, 0, 3, host.len() as u8];
    datagram.extend(host.as_bytes());
    datagram.extend(port.to_be_bytes());
    datagram.extend(PAYLOAD);
    socket.send_to(&datagram, relay).await.unwrap();
    let mut reply = vec![0; 1024];
    let n = timeout(LIMIT, socket.recv(&mut reply))
        .await
        .expect("UDP chain reply timed out")
        .unwrap();
    assert!(reply[..n].ends_with(PAYLOAD), "UDP chain must relay");
    drop(control);
    terminal(before).await;
}

/// Accepts the engine's own QUIC identity: this client only opens the stream.
#[derive(Debug)]
struct AnyServer(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// SOCKS5 CONNECT over one QUIC stream to the engine's QUIC server; the
/// server's chain fails, and its stream-failure record is awaited.
async fn quic_flight(server: SocketAddr, host: &str, port: u16) {
    let before = QUIC_FAILURES.load(Ordering::SeqCst);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer(provider)))
        .with_no_client_auth();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    )));
    let connection = timeout(LIMIT, endpoint.connect(server, "quic.test").unwrap())
        .await
        .expect("QUIC handshake timed out")
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut request = vec![5, 1, 0, 5, 1, 0, 3, host.len() as u8];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    send.write_all(&request).await.unwrap();
    // The chain fails: the stream ends without a successful CONNECT reply.
    let reply = timeout(LIMIT * 3, recv.read_to_end(64))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    assert!(reply.len() < 4 || reply[3] != 0, "QUIC chain must fail");
    timeout(LIMIT, async {
        while QUIC_FAILURES.load(Ordering::SeqCst) <= before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("missing QUIC stream failure diagnostic");
    connection.close(0u32.into(), b"");
    endpoint.wait_idle().await;
}

async fn exercise(fixture: &Fixture, engine: &EngineMaterial, policy: &mut Policy, canary: bool) {
    tokio::spawn(async {
        log::debug!(target: "tls_privacy_control", "debug collector active");
        log::trace!(target: "tls_privacy_control", "trace collector active");
        tracing::debug!(target: "tls_privacy_control", "debug collector active");
        tracing::trace!(target: "tls_privacy_control", "trace collector active");
    })
    .await
    .unwrap();
    let servers = &fixture.servers;
    let mut tasks = Tasks(Vec::new());

    // 1. A named destination resolved by the real default resolver, then a
    //    name that cannot resolve.
    let mut registry = shoes::dns::build_dns_registry(Vec::new()).await.unwrap();
    let default_resolver = registry.get_for_server(None);
    let direct = reserve_tcp(policy);
    start(
        &format!("- address: '{direct}'\n  protocol:\n    type: socks\n"),
        default_resolver,
        &mut tasks,
    )
    .await;
    socks_flight(direct, LOCALHOST, servers["echo4"].port(), true).await;
    if canary {
        return;
    }
    socks_flight(direct, MISSING, 443, false).await;

    // 2. DNS through two UDP servers: the first is closed, the second answers.
    let dns_bind = reserve_tcp(policy);
    let dns_yaml = format!(
        r#"
- address: '{dns_bind}'
  dns:
    servers:
      - url: 'udp://{dead}'
        timeout_secs: 1
        attempts: 1
      - url: 'udp://{dns}'
        timeout_secs: 2
        attempts: 1
  protocol:
    type: socks
"#,
        dead = servers["dead-dns"],
        dns = servers["dns"],
    );
    let validated_dns = validated(&dns_yaml);
    let mut dns_registry = shoes::dns::build_dns_registry(validated_dns.dns_groups)
        .await
        .unwrap();
    for config in validated_dns.configs {
        let Config::Server(server) = config else {
            unreachable!()
        };
        let resolver = dns_registry.get_for_server(server.dns.as_ref());
        tasks.0.extend(
            start_servers(Config::Server(server), resolver)
                .await
                .unwrap(),
        );
    }
    socks_flight(dns_bind, DNS_DESTINATION, servers["echo4"].port(), true).await;

    // Named hops and destinations for the chain scenarios.
    let quic = reserve_udp(policy);
    let ss = reserve_tcp(policy);
    let reality = reserve_tcp(policy);
    let map: Arc<dyn Resolver> = Arc::new(MapResolver(
        [
            (TCP_DESTINATION.to_owned(), servers["echo4"]),
            (UDP_DESTINATION.to_owned(), servers["udp"]),
            (TLS_TARGET.to_owned(), servers["tls13"]),
            (REALITY_DEST.to_owned(), servers["tls13"]),
            (SHADOWTLS_HOP.to_owned(), servers["shadowtls"]),
            (SS_HOP.to_owned(), ss),
            (REALITY_HOP.to_owned(), reality),
        ]
        .into(),
    ));
    for hop in [quic, ss, reality] {
        policy.peer(hop);
    }

    // 3. A failing TLS client chain (pin mismatch) behind the QUIC server.
    //    The library cannot run a Shoes QUIC client (its endpoint count is set
    //    only by the binary), so a plain quinn client opens the stream.
    start(
        &format!(
            r#"
- address: '{quic}'
  transport: quic
  quic_settings:
    cert: |
{cert}    key: |
{key}    num_endpoints: 1
  protocol:
    type: socks
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        address: '{TLS_TARGET}:{port}'
        protocol:
          type: tls
          verify: false
          server_fingerprints: ['{wrong}']
          sni_hostname: '{TLS_NAME}'
          protocol:
            type: socks
"#,
            cert = block(&engine.quic_cert.cert.pem(), 6),
            key = block(&engine.quic_cert.signing_key.serialize_pem(), 6),
            port = servers["tls13"].port(),
            wrong = pin(&fixture.ca),
        ),
        map.clone(),
        &mut tasks,
    )
    .await;
    quic_flight(quic, TCP_DESTINATION, 443).await;

    // 4. UDP to a named destination: direct, then through a Shadowsocks hop.
    let udp_direct = reserve_tcp(policy);
    start(
        &format!(
            "- address: '{udp_direct}'\n  protocol:\n    type: socks\n    udp_enabled: true\n"
        ),
        map.clone(),
        &mut tasks,
    )
    .await;
    udp_flight(udp_direct, UDP_DESTINATION, servers["udp"].port()).await;
    let udp_chain = reserve_tcp(policy);
    start(
        &format!(
            r#"
- address: '{ss}'
  protocol:
    type: shadowsocks
    cipher: '2022-blake3-aes-128-gcm'
    password: '{key}'
    udp_enabled: true
- address: '{udp_chain}'
  protocol:
    type: socks
    udp_enabled: true
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        address: '{SS_HOP}:{port}'
        protocol:
          type: shadowsocks
          cipher: '2022-blake3-aes-128-gcm'
          password: '{key}'
          udp_enabled: true
"#,
            key = ss_key(),
            port = ss.port(),
        ),
        map.clone(),
        &mut tasks,
    )
    .await;
    udp_flight(udp_chain, UDP_DESTINATION, servers["udp"].port()).await;

    // 5. REALITY: the engine's server and client, then a wrong short id.
    start(
        &format!(
            r#"
- address: '{reality}'
  protocol:
    type: tls
    reality_targets:
      '{TLS_NAME}':
        private_key: '{private}'
        short_ids: ['{SHORT_ID}']
        dest: '{REALITY_DEST}:{port}'
        max_time_diff: 60000
        protocol:
          type: vless
          user_id: '{USER_ID}'
"#,
            private = engine.reality_private,
            port = servers["tls13"].port(),
        ),
        map.clone(),
        &mut tasks,
    )
    .await;
    for (short_id, success) in [(SHORT_ID, true), (WRONG_SHORT_ID, false)] {
        let bind = reserve_tcp(policy);
        start(
            &format!(
                r#"
- address: '{bind}'
  protocol:
    type: socks
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        address: '{REALITY_HOP}:{port}'
        protocol:
          type: reality
          public_key: '{public}'
          short_id: '{short_id}'
          sni_hostname: '{TLS_NAME}'
          protocol:
            type: vless
            user_id: '{USER_ID}'
"#,
                port = reality.port(),
                public = engine.reality_public,
            ),
            map.clone(),
            &mut tasks,
        )
        .await;
        socks_flight(bind, TCP_DESTINATION, 443, success).await;
    }

    // 6. ShadowTLS with platform verification against an untrusted identity.
    let shadowtls = reserve_tcp(policy);
    start(
        &format!(
            r#"
- address: '{shadowtls}'
  protocol:
    type: socks
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        address: '{SHADOWTLS_HOP}:{port}'
        protocol:
          type: shadowtls
          password: '{PASSWORD}'
          sni_hostname: '{SHADOWTLS_NAME}'
          protocol:
            type: shadowsocks
            cipher: '2022-blake3-aes-128-gcm'
            password: '{key}'
            udp_enabled: false
"#,
            port = servers["shadowtls"].port(),
            key = ss_key(),
        ),
        map.clone(),
        &mut tasks,
    )
    .await;
    socks_flight(shadowtls, TCP_DESTINATION, 443, false).await;
    // Server-side QUIC and REALITY records can trail the client's terminal.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// Distinct values carried only by the injected canaries, so the parent can
// tell a detected canary from a disclosure by the live flights.
const CANARY_HOST: &str = "canary-host.engine-privacy.invalid";
const CANARY_KEY: [u8; 8] = [0xe9, 0xa1, 0xc3, 0xd5, 0x0b, 0x1e, 0x55, 0xed];

// Known disclosures, in their pre-fix message shapes, through the same
// collector and process channels. The parent must detect every one.
fn inject_canaries(fixture: &Fixture) {
    log::debug!(
        target: "shoes::resolver",
        "CachingNativeResolver resolved {CANARY_HOST}:443 -> [127.0.0.1:443]"
    );
    log::error!(
        target: "shoes::quic_server",
        "Failed to process streams: failed to setup client stream to {CANARY_HOST}:443: TLS error: unexpected error: unknown server fingerprint: {}",
        pin(&fixture.tls_leaf)
    );
    log::debug!(
        target: "shoes::reality::reality_client_connection",
        "  auth_key={:02x?}",
        CANARY_KEY
    );
    log::trace!(
        target: "shoes::client_proxy_chain",
        "Chain UDP connect\n  target={CANARY_HOST}:53"
    );
    tracing::debug!(target: "quinn_proto::connection", server_name = CANARY_HOST, "handshake");
    println!("{CANARY_HOST}");
    eprint!("{}", pem_certificate(&fixture.shadowtls_leaf));
}

/// Engine process: every byte it writes is under test.
fn engine(dir: &Path, level: &str) {
    trace::install(dir);
    init_multi_logger(
        vec![Box::new(Writer {
            file: FileLogWriter::new(dir.join("engine.log").to_str().unwrap()).unwrap(),
            serial: Mutex::new(()),
        })],
        vec![Directive {
            name: None,
            level: LevelFilter::Trace,
        }],
    );
    let fixture = fixture_material(Path::new(&std::env::var(FIXTURE).unwrap()));
    let material = EngineMaterial::new();
    let mut policy = protected_policy(&fixture, &material);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(
                LIMIT * 24,
                exercise(&fixture, &material, &mut policy, level == "CANARY"),
            )
            .await
            .expect("engine privacy scenarios timed out")
        });
    if level == "CANARY" {
        inject_canaries(&fixture);
    }
    log::logger().flush();
    std::fs::write(
        dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
}

/// Bounded records that must arrive: the capture is live and the scenarios
/// really reached these paths, with the fixed (payload-free) wording. Targets
/// match by prefix (the platform verifier logs per platform); `*` in a message
/// stands for a count, duration or kind.
fn controls(canary: bool) -> Vec<(&'static str, &'static str)> {
    let mut controls = vec![
        ("tls_privacy_control", "debug collector active"),
        ("tls_privacy_control", "trace collector active"),
        (
            "shoes::resolver",
            "CachingNativeResolver resolved * addresses",
        ),
    ];
    if canary {
        return controls;
    }
    controls.extend([
        ("tls_privacy_control", "engine rejection observed"),
        (
            "shoes::dns::hickory_resolver",
            "DNS lookup failed via udp resolver in * (timeout)",
        ),
        (
            "shoes::dns::hickory_resolver",
            "DNS lookup via udp resolver: 1 addresses in *",
        ),
        (
            "shoes::dns::composite_resolver",
            "CompositeResolver: resolved via resolver #1 after 1 failures",
        ),
        (
            "shoes::quic_server",
            "Failed to process streams (kind=InvalidData)",
        ),
        (
            "shoes::socks5_udp_relay",
            "SOCKS5 UDP relay: parsed packet, payload_len=*",
        ),
        (
            "shoes::client_proxy_chain",
            "Chain UDP: Direct connection (native UDP)",
        ),
        (
            "shoes::client_proxy_chain",
            "Chain UDP: Proxy (UDP, no subsequent)",
        ),
        (
            "shoes::reality::reality_client_connection",
            "REALITY CLIENT: Handshake complete, application keys derived",
        ),
        (
            "shoes::reality::reality_server_connection",
            "REALITY: Client authentication successful",
        ),
        (
            "shoes::reality::reality_server_connection",
            "REALITY: Client short_id not in configured list",
        ),
        (
            "shoes::reality::reality_server_handler",
            "REALITY: Auth failed (kind=PermissionDenied), forwarding to dest transparently",
        ),
        (
            "rustls_platform_verifier::verification",
            "failed to verify TLS certificate (invalid certificate: unknown issuer)",
        ),
    ]);
    controls
}

/// `pattern` with each `*` standing for any text (anchored at both ends).
fn matches(pattern: &str, message: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = message.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<_> = parts.collect();
    for (i, part) in parts.iter().enumerate() {
        if i + 1 == parts.len() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.is_empty()
}

fn dependency(target: &str) -> bool {
    DEPENDENCIES.iter().any(|prefix| target.starts_with(prefix))
}

/// Keys, secrets, nonces and handshake bytes the test cannot predict still
/// have a shape: eight or more byte values in a list (any radix, possibly
/// truncated), or a hex string of 32 or more digits.
fn byte_rendering(message: &str) -> bool {
    let byte = |token: &str| {
        let token = token.trim().trim_start_matches("0x");
        (1..=3).contains(&token.len()) && token.chars().all(|c| c.is_ascii_hexdigit())
    };
    let listed = message.split('[').skip(1).any(|list| {
        let list = list.split(']').next().unwrap_or_default();
        list.split(',').filter(|token| byte(token)).count() >= 8
    });
    let mut run = 0;
    let hex = message.chars().any(|c| {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        run >= 32
    });
    listed || hex
}

fn record_violation(event: &Event, protected: &[String]) -> Option<&'static str> {
    if protected
        .iter()
        .any(|value| event.message.contains(value.as_str()))
    {
        return Some("protected disclosure");
    }
    if event.message.contains(['\r', '\n']) {
        return Some("multiline record");
    }
    if !dependency(&event.target) && byte_rendering(&event.message) {
        return Some("byte rendering");
    }
    None
}

/// Every violation in the complete capture. Dependency records are tallied
/// separately, so Shoes' own records are proven clean without filtering them.
fn inspect(
    dir: &Path,
    stdout: &[u8],
    stderr: &[u8],
    dependencies: &mut Vec<String>,
) -> Vec<Violation> {
    let policy: Policy =
        serde_json::from_slice(&std::fs::read(dir.join("policy.json")).unwrap()).unwrap();
    let protected = &policy.protected;
    let mut violations = Vec::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let harness = matches!(line, "" | "running 1 test" | ".")
            || line
                .strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
                .is_some();
        // Startup lines name their own configured bind once, nothing else.
        let startup = policy.binds.iter().find(|bind| {
            line.starts_with("Starting ") && line.ends_with(&format!(" server at {bind}"))
        });
        let scanned = match startup {
            Some(bind) => line.replace(bind.as_str(), ""),
            None => line.to_owned(),
        };
        if !harness && startup.is_none() {
            violations.push(Violation::new(
                "stdout",
                "line",
                "unclassified stdout",
                line,
            ));
        }
        if protected
            .iter()
            .any(|value| scanned.contains(value.as_str()))
        {
            violations.push(Violation::new(
                "stdout",
                "line",
                "protected disclosure",
                line,
            ));
        }
    }
    let mut events = Vec::new();
    for line in String::from_utf8_lossy(stderr).lines() {
        match serde_json::from_str::<Event>(line) {
            Ok(event) => events.push(event),
            Err(_) => violations.push(Violation::new(
                "stderr",
                "line",
                "stderr byte outside a complete diagnostic record",
                line,
            )),
        }
    }
    let original: String = events
        .iter()
        .map(|e| format!("{}\n", e.formatted))
        .collect();
    if std::fs::read(dir.join("engine.log")).unwrap() != original.as_bytes() {
        violations.push(Violation::new(
            "engine.log",
            "file",
            "complete engine channel must match the unfiltered records",
            "",
        ));
    }
    for event in &events {
        let record = format!("{} {}", event.level, event.target);
        if let Some(reason) = record_violation(event, protected) {
            if dependency(&event.target) {
                dependencies.push(format!("log {record} ({reason}): {}", event.message));
            } else {
                violations.push(Violation::new("log", &record, reason, &event.message));
            }
        }
    }
    for (target, message) in controls(dir.ends_with("CANARY")) {
        if !events
            .iter()
            .any(|e| e.target.starts_with(target) && matches(message, &e.message))
        {
            violations.push(Violation::new(
                "control",
                target,
                "missing positive control",
                message,
            ));
        }
    }
    // Tracing: complete, every raw record scanned, dependency records tallied.
    let bytes = std::fs::read(dir.join("tracing.jsonl")).unwrap();
    let mut forwarded = 0;
    let mut native_controls = 0;
    for line in String::from_utf8_lossy(&bytes).lines() {
        let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
            violations.push(Violation::new(
                "tracing",
                "record",
                "malformed tracing record",
                line,
            ));
            continue;
        };
        let target = record["target"].as_str().unwrap_or_default();
        if target == "tls_privacy_engine_log" {
            forwarded += 1;
        }
        if target == "tls_privacy_control" {
            native_controls += 1;
        }
        let disclosed = protected.iter().any(|value| line.contains(value.as_str()));
        if disclosed && dependency(target) {
            dependencies.push(format!("tracing {target}: {line}"));
        } else if disclosed {
            violations.push(Violation::new(
                "tracing",
                target,
                "protected disclosure",
                line,
            ));
        }
    }
    if forwarded != events.len() {
        violations.push(Violation::new(
            "tracing",
            "record",
            "every original log must reach tracing",
            &format!("{forwarded} forwarded, {} logged", events.len()),
        ));
    }
    if native_controls < 2 {
        violations.push(Violation::new(
            "tracing",
            "tls_privacy_control",
            "missing native tracing control",
            "",
        ));
    }
    violations
}

fn child(role: &str, dir: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1",
            "--quiet",
        ])
        .env(ROLE, role)
        .env(DIR, dir);
    command
}

#[test]
fn engine_diagnostics_are_private() {
    if let Ok(role) = std::env::var(ROLE) {
        let dir = std::env::var(DIR).unwrap();
        if role == "fixture" {
            fixture(Path::new(&dir));
        } else {
            engine(Path::new(&dir), &role);
        }
        return;
    }
    let _ports = super::super::PORTS.blocking_lock();
    let root = std::env::var_os("SHOES_TLS_PRIVACY_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&root).unwrap();
    let root = tempfile::Builder::new()
        .prefix("engine-diagnostics-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    let fixture_dir = root.join("fixture");
    std::fs::create_dir(&fixture_dir).unwrap();
    let mut fixture = FixtureProcess(
        child("fixture", &fixture_dir)
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(fixture_dir.join("stdout.capture")).unwrap())
            .stderr(std::fs::File::create(fixture_dir.join("stderr.capture")).unwrap())
            .spawn()
            .unwrap(),
    );
    let published = fixture_dir.join("fixture.json");
    let deadline = std::time::Instant::now() + LIMIT * 4;
    while !published.exists() {
        assert!(
            fixture.0.try_wait().unwrap().is_none(),
            "fixture process exited; captures at {}",
            fixture_dir.display()
        );
        assert!(
            std::time::Instant::now() < deadline,
            "fixture servers did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut failures = Vec::new();
    for level in ["TRACE", "CANARY"] {
        let dir = root.join(level);
        std::fs::create_dir(&dir).unwrap();
        let output = child(level, &dir)
            .env(FIXTURE, &published)
            .output()
            .unwrap();
        std::fs::write(dir.join("stdout.capture"), &output.stdout).unwrap();
        std::fs::write(dir.join("stderr.capture"), &output.stderr).unwrap();
        std::fs::write(dir.join("exit.txt"), output.status.to_string()).unwrap();
        println!(
            "Complete {level} engine privacy captures: {}",
            dir.display()
        );
        assert!(
            output.status.success(),
            "engine child failed: {}; complete captures at {}",
            output.status,
            dir.display()
        );
        let mut dependencies = Vec::new();
        let violations = inspect(&dir, &output.stdout, &output.stderr, &mut dependencies);
        std::fs::write(dir.join("violations.txt"), format!("{violations:#?}\n")).unwrap();
        std::fs::write(
            dir.join("dependency-disclosures.txt"),
            dependencies.join("\n") + "\n",
        )
        .unwrap();
        // Reported, not filtered: the count is visible in every run.
        println!(
            "{level} dependency records carrying protected values: {}",
            dependencies.len()
        );
        if level != "CANARY" {
            if !violations.is_empty() {
                failures.push(format!(
                    "{level} engine diagnostics rejected (details in {}):\n{}",
                    dir.display(),
                    summary(&violations)
                ));
            }
            continue;
        }
        let detected = |channel: &str, record: &str, reason: &str, detail: &str| {
            violations.iter().any(|v| {
                v.channel == channel
                    && v.record == record
                    && v.reason == reason
                    && v.detail.contains(detail)
            })
        };
        let fixture = fixture_material(&published);
        let fingerprint = pin(&fixture.tls_leaf);
        let key = format!("{CANARY_KEY:02x?}");
        for (channel, record, reason, detail) in [
            ("stdout", "line", "protected disclosure", CANARY_HOST),
            (
                "stderr",
                "line",
                "stderr byte outside a complete diagnostic record",
                "BEGIN CERTIFICATE",
            ),
            (
                "log",
                "DEBUG shoes::resolver",
                "protected disclosure",
                CANARY_HOST,
            ),
            (
                "log",
                "ERROR shoes::quic_server",
                "protected disclosure",
                &fingerprint,
            ),
            (
                "log",
                "DEBUG shoes::reality::reality_client_connection",
                "byte rendering",
                &key,
            ),
            (
                "log",
                "TRACE shoes::client_proxy_chain",
                "protected disclosure",
                CANARY_HOST,
            ),
        ] {
            if !detected(channel, record, reason, detail) {
                failures.push(format!(
                    "canary {channel}/{record}/{reason} was not detected (details in {})",
                    dir.display()
                ));
            }
        }
        if !dependencies
            .iter()
            .any(|d| d.starts_with("tracing quinn_proto::connection") && d.contains(CANARY_HOST))
        {
            failures.push(format!(
                "canary dependency tracing record was not tallied (details in {})",
                dir.display()
            ));
        }
        // Everything else in the canary run, including its live flight, is clean.
        let pem = pem_certificate(&fixture.shadowtls_leaf);
        let unexpected: Vec<_> = violations
            .into_iter()
            .filter(|v| {
                let injected = if v.channel == "stderr" {
                    pem.lines().any(|line| line == v.detail)
                } else {
                    [CANARY_HOST, fingerprint.as_str(), key.as_str()]
                        .iter()
                        .any(|signature| v.detail.contains(signature))
                };
                !injected
            })
            .collect();
        if !unexpected.is_empty() {
            failures.push(format!(
                "CANARY run has violations beyond the injected canaries (details in {}):\n{}",
                dir.display(),
                summary(&unexpected)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    drop(fixture.0.stdin.take());
}
