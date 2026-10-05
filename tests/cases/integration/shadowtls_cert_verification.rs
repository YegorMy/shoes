//! Real ShadowTLS v3 certificate flights and traffic through the engine.
//! Valid pins relay; bad pins and untrusted certificates fail before origin IO.
//! Optional pinned sing-box proof verifies independent wire interoperability.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;
use shoes::config::create_server_configs;
use shoes::config::{ClientChainHop, ClientConfig, Config, ConfigSelection};
use shoes::resolver::{NativeResolver, Resolver};
use shoes::tcp::chain_builder::build_client_proxy_chain;
use shoes::tcp::tcp_server::start_servers;
use shoes::{Address, NetLocation, OneOrSome, ResolvedLocation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

#[cfg(feature = "optional-peer-tests")]
#[path = "shadowtls_singbox_peer.rs"]
mod singbox_peer;

const SHADOWTLS_PASSWORD: &str = "shadowtls-verification-password-6f1c9b";
const SNI: &str = "handshake.test";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

struct HandshakeCert {
    cert_pem: String,
    key_pem: String,
    sha256_hex: String,
}

fn generate_handshake_cert(hostname: &str) -> HandshakeCert {
    let key_pair = rcgen::KeyPair::generate().expect("failed to generate key");
    let params = rcgen::CertificateParams::new(vec![hostname.to_string()])
        .expect("failed to create certificate params");
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to self-sign certificate");
    let sha256_hex: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert.der())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    HandshakeCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        sha256_hex,
    }
}

fn indent(pem: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    pem.lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Reserves an ephemeral loopback port, releasing it so the engine can bind.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

struct ServerGuard {
    handles: Vec<JoinHandle<()>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

/// Starts a real in-process ShadowTLS v3 server whose handshake host presents
/// `handshake_cert`. The inner protocol is Shadowsocks 2022 with `ss_key_b64`.
async fn start_shadowtls_server(
    port: u16,
    handshake_cert: &HandshakeCert,
    ss_key_b64: &str,
) -> ServerGuard {
    let server_yaml = format!(
        r#"- address: "127.0.0.1:{port}"
  protocol:
    type: tls
    shadowtls_targets:
      "{SNI}":
        password: "{SHADOWTLS_PASSWORD}"
        handshake:
          cert: |
{cert}
          key: |
{key}
        protocol:
          type: shadowsocks
          cipher: "2022-blake3-aes-128-gcm"
          password: "{ss_key_b64}"
"#,
        cert = indent(&handshake_cert.cert_pem, 12),
        key = indent(&handshake_cert.key_pem, 12),
    );

    let configs: Vec<Config> = serde_yaml::from_str(&server_yaml).expect("server YAML must parse");
    let validated = create_server_configs(configs).expect("server config must validate");

    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut handles = Vec::new();
    for config in validated.configs {
        handles.extend(
            start_servers(config, resolver.clone())
                .await
                .expect("server must start"),
        );
    }
    let guard = ServerGuard { handles };
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        let connected = tokio::time::timeout_at(
            deadline,
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)),
        )
        .await
        .expect("ShadowTLS listener readiness timed out");
        match connected {
            Ok(stream) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "ShadowTLS listener readiness exceeded its deadline"
                );
                drop(stream);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                assert!(
                    guard.handles.iter().all(|handle| !handle.is_finished()),
                    "ShadowTLS listener stopped before accepting connections"
                );
                tokio::time::sleep_until(
                    deadline.min(tokio::time::Instant::now() + Duration::from_millis(20)),
                )
                .await;
            }
            Err(error) => panic!("ShadowTLS listener unavailable: {error}"),
        }
    }
    guard
}

/// Starts a loopback echo server and returns (port, connection counter).
async fn start_origin_echo_server() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, connections)
}

/// Builds the engine client chain for one ShadowTLS trust configuration.
/// `trust_yaml` is inserted at the shadowtls hop indentation level (2 spaces).
fn build_chain(
    port: u16,
    ss_key_b64: &str,
    trust_yaml: &str,
) -> shoes::client_proxy_chain::ClientProxyChain {
    let client_yaml = format!(
        r#"address: "127.0.0.1:{port}"
protocol:
  type: shadowtls
  password: "{SHADOWTLS_PASSWORD}"
  sni_hostname: "{SNI}"
{trust_yaml}  protocol:
    type: shadowsocks
    cipher: "2022-blake3-aes-128-gcm"
    password: "{ss_key_b64}"
    udp_enabled: false
"#
    );
    let client: ClientConfig = serde_yaml::from_str(&client_yaml).expect("client YAML must parse");
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
        resolver,
    )
}

async fn connect_to_origin(
    chain: &shoes::client_proxy_chain::ClientProxyChain,
    origin_port: u16,
) -> std::io::Result<shoes::tcp::tcp_handler::TcpClientSetupResult> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), origin_port);
    chain
        .connect_tcp(ResolvedLocation::from(target), &resolver)
        .await
}

fn expect_connect_failure(
    result: Result<
        std::io::Result<shoes::tcp::tcp_handler::TcpClientSetupResult>,
        tokio::time::error::Elapsed,
    >,
    message: &str,
) -> std::io::Error {
    match result.expect("connect timed out") {
        Ok(_) => panic!("{message}"),
        Err(err) => err,
    }
}

fn ss_key() -> String {
    base64::engine::general_purpose::STANDARD.encode([0x42u8; 16])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_pin_completes_handshake_and_carries_traffic() {
    let cert = generate_handshake_cert(SNI);
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, origin_connections) = start_origin_echo_server().await;

    let trust = format!(
        "  verify: false\n  server_fingerprints: [\"{}\"]\n",
        cert.sha256_hex
    );
    let chain = build_chain(server_port, &ss_key_b64, &trust);

    let setup = tokio::time::timeout(CONNECT_TIMEOUT, connect_to_origin(&chain, origin_port))
        .await
        .expect("connect timed out")
        .expect("matching pin must allow the handshake");

    let mut stream = setup.client_stream;
    stream.write_all(b"ping-through-shadowtls").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; 22];
    tokio::time::timeout(CONNECT_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("echo read failed");
    assert_eq!(&buf, b"ping-through-shadowtls");

    // Give the origin a moment to register the accepted connection.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        origin_connections.load(Ordering::SeqCst),
        1,
        "exactly one origin connection after a verified handshake"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_pin_fails_before_application_traffic() {
    let cert = generate_handshake_cert(SNI);
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, origin_connections) = start_origin_echo_server().await;

    // A pin for a different certificate (freshly generated here).
    let other = generate_handshake_cert(SNI);
    let trust = format!(
        "  verify: false\n  server_fingerprints: [\"{}\"]\n",
        other.sha256_hex
    );
    let chain = build_chain(server_port, &ss_key_b64, &trust);

    let err = expect_connect_failure(
        tokio::time::timeout(CONNECT_TIMEOUT, connect_to_origin(&chain, origin_port)).await,
        "mismatched pin must fail the handshake",
    );

    assert!(
        err.to_string().contains("fingerprint"),
        "unexpected error: {err}"
    );
    assert!(
        !err.to_string().contains(SHADOWTLS_PASSWORD),
        "error must not leak the ShadowTLS password: {err}"
    );
    assert_eq!(
        origin_connections.load(Ordering::SeqCst),
        0,
        "no application traffic may reach the origin when the pin mismatches"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn system_roots_reject_untrusted_handshake_certificate() {
    let cert = generate_handshake_cert(SNI);
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, origin_connections) = start_origin_echo_server().await;

    // verify: true routes through WebPKI against the engine's root store,
    // which cannot contain our self-signed test certificate.
    let chain = build_chain(server_port, &ss_key_b64, "  verify: true\n");

    let err = expect_connect_failure(
        tokio::time::timeout(CONNECT_TIMEOUT, connect_to_origin(&chain, origin_port)).await,
        "untrusted handshake certificate must fail under verify: true",
    );

    assert!(
        err.to_string().contains("UnknownIssuer"),
        "unexpected error: {err}"
    );
    assert!(
        !err.to_string().contains(SHADOWTLS_PASSWORD),
        "error must not leak the ShadowTLS password: {err}"
    );
    assert_eq!(
        origin_connections.load(Ordering::SeqCst),
        0,
        "no application traffic may reach the origin when verification fails"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn system_roots_reject_wrong_name_certificate_before_traffic() {
    // The server target presents a certificate whose identity does not match
    // the client's SNI. The certificate is also self-signed, so WebPKI
    // rejects it at path validation (UnknownIssuer) before name validation;
    // the name-validation-specific proof lives in the verifier-level unit
    // tests (rustls_config_util::tests::webpki_branch_rejects_certificate_for_wrong_name),
    // where a test CA can stand in for the system roots.
    let cert = generate_handshake_cert("other.test");
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, origin_connections) = start_origin_echo_server().await;

    let chain = build_chain(server_port, &ss_key_b64, "  verify: true\n");

    let err = expect_connect_failure(
        tokio::time::timeout(CONNECT_TIMEOUT, connect_to_origin(&chain, origin_port)).await,
        "a wrong-name handshake host certificate must fail under verify: true",
    );

    assert!(
        err.to_string().contains("UnknownIssuer"),
        "unexpected error: {err}"
    );
    assert!(
        !err.to_string().contains(SHADOWTLS_PASSWORD),
        "error must not leak the ShadowTLS password: {err}"
    );
    assert_eq!(
        origin_connections.load(Ordering::SeqCst),
        0,
        "no application traffic may reach the origin when verification fails"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pin_only_mode_authenticates_the_pinned_certificate_itself() {
    // Pin-only verification authenticates the exact pinned certificate; it
    // does not re-check the server name. Pins therefore pin the exact
    // handshake-host certificate, and a matching pin completes even when the
    // presented name differs from the configured SNI.
    let cert = generate_handshake_cert("other.test");
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, origin_connections) = start_origin_echo_server().await;

    let trust = format!(
        "  verify: false\n  server_fingerprints: [\"{}\"]\n",
        cert.sha256_hex
    );
    let chain = build_chain(server_port, &ss_key_b64, &trust);

    let setup = tokio::time::timeout(CONNECT_TIMEOUT, connect_to_origin(&chain, origin_port))
        .await
        .expect("connect timed out")
        .expect("matching pin must allow the handshake");
    drop(setup);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        origin_connections.load(Ordering::SeqCst),
        1,
        "the pinned certificate must carry traffic even with a different name"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_handshake_does_not_leak_credentials() {
    let cert = generate_handshake_cert(SNI);
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, _origin_connections) = start_origin_echo_server().await;

    let cases = [
        format!(
            "  verify: false\n  server_fingerprints: [\"{}\"]\n",
            "ab".repeat(32)
        ),
        "  verify: true\n".to_string(),
    ];
    for trust_yaml in cases {
        let chain = build_chain(server_port, &ss_key_b64, &trust_yaml);
        let err = expect_connect_failure(
            tokio::time::timeout(CONNECT_TIMEOUT, connect_to_origin(&chain, origin_port)).await,
            "verification failure expected",
        );
        let message = format!("{err:?}");
        assert!(
            !message.contains(SHADOWTLS_PASSWORD),
            "error must not leak the ShadowTLS password: {message}"
        );
        assert!(
            !message.contains(&ss_key_b64),
            "error must not leak the Shadowsocks key: {message}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_sni_is_refused_before_application_traffic() {
    // Client SNI does not match any configured server target and there is no
    // default target: the server refuses during target selection.
    let cert = generate_handshake_cert(SNI);
    let ss_key_b64 = ss_key();
    let server_port = free_port();
    let _server = start_shadowtls_server(server_port, &cert, &ss_key_b64).await;
    let (origin_port, origin_connections) = start_origin_echo_server().await;

    let client_yaml = format!(
        r#"address: "127.0.0.1:{server_port}"
protocol:
  type: shadowtls
  password: "{SHADOWTLS_PASSWORD}"
  sni_hostname: "unknown.test"
  verify: false
  server_fingerprints: ["{pin}"]
  protocol:
    type: shadowsocks
    cipher: "2022-blake3-aes-128-gcm"
    password: "{ss_key_b64}"
    udp_enabled: false
"#,
        pin = cert.sha256_hex,
        ss_key_b64 = ss_key_b64,
    );
    let client: ClientConfig = serde_yaml::from_str(&client_yaml).unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chain = build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
        resolver.clone(),
    );
    let target = NetLocation::new(Address::Ipv4(Ipv4Addr::LOCALHOST), origin_port);
    let _err = expect_connect_failure(
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            chain.connect_tcp(ResolvedLocation::from(target), &resolver),
        )
        .await,
        "unknown SNI must be refused",
    );
    assert_eq!(
        origin_connections.load(Ordering::SeqCst),
        0,
        "no application traffic may reach the origin for an unknown SNI"
    );
}
