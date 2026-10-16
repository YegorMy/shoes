//! Real TLS flights with a global, unfiltered Shoes logger. Fixture-client work
//! is explicitly task-scoped; everything else (including unknown targets) is
//! treated as server output. Raw records and both process channels are retained.
#[path = "tls_guard.rs"]
mod guard;

use std::io::Cursor;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::{LevelFilter, Record};
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, HandshakeKind, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use shoes::logging::{Directive, FileLogWriter, LogWriter, init_multi_logger};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use super::{Hooks, LIMIT, LocalResolver, Tasks};
use guard::Event;

const SNI: &str = "device-sni.tls-privacy.invalid";
const ALPN: &[u8] = b"private-alpn-credential-canary";
const PAYLOAD: &[u8] = b"tls-application-payload-canary";
const PASSWORD: &str = "tls-shadow-credential-canary";
const SS_KEY: &str = "cHJpdmFjeS1rZXktY2FuYQ==";
const REMOTE_SNI: &str = "fallback-device.tls-privacy.invalid";
const FAILED_REMOTE_SNI: &str = "failed-fallback-device.tls-privacy.invalid";
const ERROR_TEXT: &str = "arbitrary-verifier-error-canary device=private-device dns=private-query.invalid credential=private-password";
const CHILD: &str = "SHOES_TLS_PRIVACY_CHILD";

tokio::task_local! { static FIXTURE_CLIENT: (); }
static TERMINALS: AtomicUsize = AtomicUsize::new(0);
static FALLBACK_TERMINALS: AtomicUsize = AtomicUsize::new(0);

struct Writer {
    file: FileLogWriter,
    serial: Mutex<()>,
}

impl LogWriter for Writer {
    fn write_log(&self, record: &Record<'_>, formatted: &str) {
        let _serial = self.serial.lock();
        self.file.write_log(record, formatted);
        // Keep the entire original record, including multiline formatting. This
        // is attribution, not redaction: fixture bytes remain in both captures.
        eprintln!(
            "{}",
            serde_json::to_string(&Event {
                fixture_client: FIXTURE_CLIENT.try_with(|_| ()).is_ok(),
                level: record.level().to_string(),
                target: record.target().into(),
                message: record.args().to_string(),
                formatted: formatted.into(),
            })
            .unwrap()
        );
        if record.target() == "shoes::tcp::tcp_server::listener" {
            TERMINALS.fetch_add(1, Ordering::SeqCst);
        }
        if record.target() == "shoes::shadow_tls::shadow_tls_server_handler"
            && record.args().to_string() == "SHADOWTLS FALLBACK: Connection completed"
        {
            FALLBACK_TERMINALS.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn flush(&self) {
        self.file.flush();
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Policy {
    protected: Vec<String>,
    binds: Vec<String>,
}

impl Policy {
    fn protect(&mut self, bytes: &[u8]) {
        self.protected
            .push(String::from_utf8_lossy(bytes).into_owned());
        self.protected
            .push(bytes.iter().map(|b| format!("{b:02x}")).collect());
        self.protected.push(format!("{bytes:?}"));
    }
    fn peer(&mut self, address: SocketAddr) {
        self.protected.push(address.to_string());
    }
}

struct Certificate {
    der: CertificateDer<'static>,
    key: Vec<u8>,
    pem: String,
    key_pem: String,
}

impl Certificate {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![SNI.into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Self {
            der: cert.der().clone(),
            key: key.serialize_der(),
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }
    fn configs(
        &self,
        version: &'static rustls::SupportedProtocolVersion,
        stateless: bool,
        client_auth: bool,
    ) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap();
        let builder = if client_auth {
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone()))
                    .build()
                    .unwrap(),
            )
        } else {
            builder.with_no_client_auth()
        };
        let mut server = builder
            .with_single_cert(
                vec![self.der.clone()],
                PrivatePkcs8KeyDer::from(self.key.clone()).into(),
            )
            .unwrap();
        server.alpn_protocols = vec![ALPN.to_vec()];
        if stateless {
            server.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
        }
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots);
        let mut client = if client_auth {
            builder
                .with_client_auth_cert(
                    vec![self.der.clone()],
                    PrivatePkcs8KeyDer::from(self.key.clone()).into(),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        client.alpn_protocols = vec![ALPN.to_vec()];
        (Arc::new(server), Arc::new(client))
    }
}

// Both sides run in spawned tasks on a multithread runtime. Lazy acceptance also
// exercises Accepted::client_hello(), not just ServerConnection's direct path.
async fn flight(
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    name: &'static str,
    policy: &mut Policy,
    success: bool,
) -> Option<HandshakeKind> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    policy.peer(address);
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let accepted = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), socket)
            .await
            .unwrap();
        assert!(accepted.client_hello().server_name().is_some());
        match accepted.into_stream(server).await {
            Ok(mut tls) => {
                assert!(
                    success,
                    "server unexpectedly authenticated a rejected client"
                );
                let kind = tls.get_ref().1.handshake_kind().unwrap();
                let mut payload = vec![0; PAYLOAD.len()];
                tls.read_exact(&mut payload).await.unwrap();
                assert!(payload == PAYLOAD);
                tls.write_all(&payload).await.unwrap();
                tls.shutdown().await.unwrap();
                Some(kind)
            }
            Err(_) => {
                assert!(!success, "valid TLS flight rejected");
                log::debug!(target: "tls_privacy_control", "server rejection observed");
                None
            }
        }
    });
    let socket = TcpStream::connect(address).await.unwrap();
    policy.peer(socket.local_addr().unwrap());
    let client = tokio::spawn(FIXTURE_CLIENT.scope((), async move {
        let result = TlsConnector::from(client)
            .connect(ServerName::try_from(name).unwrap(), socket)
            .await;
        if success {
            let mut tls = result.expect("trusted TLS client must connect");
            tls.write_all(PAYLOAD).await.unwrap();
            tls.flush().await.unwrap();
            let mut payload = vec![0; PAYLOAD.len()];
            tls.read_exact(&mut payload).await.unwrap();
            assert!(payload == PAYLOAD);
            // Consume the complete post-handshake ticket/close_notify flight.
            assert_eq!(tls.read(&mut [0; 1]).await.unwrap(), 0);
        } else {
            assert!(
                result.is_err(),
                "untrusted/wrong-name server must be rejected"
            );
        }
    }));
    client.await.unwrap();
    server.await.unwrap()
}

async fn malformed_sni(
    client: Arc<ClientConfig>,
    from: &'static str,
    to: &'static [u8],
    policy: &mut Policy,
) {
    assert_eq!(from.len(), to.len());
    policy.protect(to);
    let mut bytes = FIXTURE_CLIENT
        .scope((), async move {
            let mut client =
                rustls::ClientConnection::new(client, ServerName::try_from(from).unwrap()).unwrap();
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            bytes
        })
        .await;
    let offset = bytes
        .windows(from.len())
        .position(|b| b == from.as_bytes())
        .unwrap();
    bytes[offset..offset + from.len()].copy_from_slice(to);
    let server = tokio::spawn(async move {
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor.read_tls(&mut Cursor::new(bytes)).unwrap();
        if to == b"127.0.0.1" {
            let accepted = acceptor.accept().unwrap().unwrap();
            assert!(
                accepted.client_hello().server_name().is_none(),
                "literal IP SNI must still be ignored"
            );
        } else {
            assert!(
                acceptor.accept().is_err(),
                "invalid SNI must remain rejected"
            );
        }
    });
    server.await.unwrap();
}

fn indent(pem: &str) -> String {
    pem.lines().map(|s| format!("            {s}\n")).collect()
}

async fn shadowtls(cert: &Certificate, policy: &mut Policy) {
    use shoes::config::{Config, create_server_configs};
    use shoes::embedding::start_servers_with_hooks;
    use shoes::resolver::NativeResolver;
    use shoes::tcp::tcp_client_handler_factory::create_tcp_client_handler;

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = echo.local_addr().unwrap();
    policy.peer(origin);
    let fallback = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fallback_address = fallback.local_addr().unwrap();
    policy.peer(fallback_address);
    let refused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let resolver = Arc::new(LocalResolver {
        echo: origin,
        refused: refused.local_addr().unwrap(),
        error: Mutex::new(format!("{ERROR_TEXT} {} {PASSWORD}", super::QUERY)),
    });
    let hooks = Arc::new(Hooks {
        accept: true.into(),
        block: false.into(),
    });
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = reserved.local_addr().unwrap();
    policy.binds.push(bind.to_string());
    let yaml = format!(
        r#"
- address: '{bind}'
  protocol:
    type: tls
    shadowtls_targets:
      '{SNI}':
        password: '{PASSWORD}'
        handshake:
          cert: |
{cert}          key: |
{key}        protocol: &inner
          type: shadowsocks
          cipher: '2022-blake3-aes-128-gcm'
          password: '{SS_KEY}'
      '{REMOTE_SNI}':
        password: '{PASSWORD}'
        handshake:
          address: '{fallback_address}'
        protocol: *inner
      '{FAILED_REMOTE_SNI}':
        password: '{PASSWORD}'
        handshake:
          address: '{query}:443'
        protocol: *inner
"#,
        cert = indent(&cert.pem),
        key = indent(&cert.key_pem),
        query = super::QUERY,
    );
    let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
    let config = create_server_configs(configs).unwrap().configs.remove(0);
    drop(reserved);
    let mut tasks = Tasks(
        start_servers_with_hooks(config, resolver, hooks.clone())
            .await
            .unwrap(),
    );
    tasks.0.push(tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await.unwrap();
        let mut bytes = vec![0; PAYLOAD.len()];
        socket.read_exact(&mut bytes).await.unwrap();
        assert!(bytes == PAYLOAD);
        socket.write_all(&bytes).await.unwrap();
        socket.shutdown().await.unwrap();
    }));
    let fallback_task = tokio::spawn(async move {
        let (mut socket, _) = fallback.accept().await.unwrap();
        let mut header = [0; 5];
        socket.read_exact(&mut header).await.unwrap();
        let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
        socket.read_exact(&mut hello).await.unwrap();
        assert!(
            hello
                .windows(REMOTE_SNI.len())
                .any(|b| b == REMOTE_SNI.as_bytes())
        );
        socket.write_all(PAYLOAD).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let pin: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &cert.der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    policy.protected.push(pin.clone());
    // Success, embedder rejection, DNS error and invalid ShadowTLS credential.
    for scenario in 0..4 {
        hooks.accept.store(scenario != 1, Ordering::SeqCst);
        let socket = TcpStream::connect(bind).await.unwrap(); // no readiness retry
        policy.peer(socket.local_addr().unwrap());
        let pin = pin.clone();
        tokio::spawn(FIXTURE_CLIENT.scope((), async move {
            let password = if scenario == 3 {
                "wrong-tls-credential-canary"
            } else {
                PASSWORD
            };
            let client = create_tcp_client_handler(
                serde_yaml::from_str(&format!(
                    r#"
type: shadowtls
password: '{password}'
sni_hostname: '{SNI}'
verify: false
server_fingerprints: ['{pin}']
protocol:
  type: shadowsocks
  cipher: '2022-blake3-aes-128-gcm'
  password: '{SS_KEY}'
  udp_enabled: false
"#
                ))
                .unwrap(),
                None,
                Arc::new(NativeResolver::new()),
            );
            let hostname = if scenario == 2 {
                super::QUERY
            } else {
                super::DESTINATION
            };
            let result = client
                .setup_client_tcp_stream(
                    Box::new(socket),
                    shoes::NetLocation::from_str(&format!("{hostname}:{}", origin.port()), None)
                        .unwrap()
                        .into(),
                )
                .await;
            if scenario == 3 {
                assert!(result.is_err());
                return;
            }
            let mut stream = result.unwrap().client_stream;
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            let mut bytes = vec![0; PAYLOAD.len()];
            let read = stream.read_exact(&mut bytes).await;
            if scenario == 0 {
                read.unwrap();
                assert!(bytes == PAYLOAD);
            } else {
                assert!(read.is_err());
            }
            let _ = stream.shutdown().await;
        }))
        .await
        .unwrap();
    }
    // A malformed frame takes the listener's bounded protocol-error boundary.
    let mut socket = TcpStream::connect(bind).await.unwrap();
    policy.peer(socket.local_addr().unwrap());
    socket.write_all(&[0; 128]).await.unwrap();
    socket.shutdown().await.unwrap();
    let _ = socket.read(&mut [0; 1]).await;
    // Real unauthenticated probes exercise the existing remote fallback and its
    // resolver-error branch. Forwarded handshake bytes must never become logs.
    for name in [REMOTE_SNI, FAILED_REMOTE_SNI] {
        let (_, config) = cert.configs(&rustls::version::TLS13, false, false);
        let hello = FIXTURE_CLIENT
            .scope((), async move {
                let mut client =
                    rustls::ClientConnection::new(config, ServerName::try_from(name).unwrap())
                        .unwrap();
                let mut bytes = Vec::new();
                client.write_tls(&mut bytes).unwrap();
                bytes
            })
            .await;
        let mut socket = TcpStream::connect(bind).await.unwrap();
        policy.peer(socket.local_addr().unwrap());
        socket.write_all(&hello).await.unwrap();
        socket.shutdown().await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        if name == REMOTE_SNI {
            assert!(response == PAYLOAD);
        } else {
            assert!(response.is_empty());
        }
    }
    fallback_task.await.unwrap();
    // Wait for every terminal diagnostic, not a timing-based guess, before
    // aborting the owned listener. The collector itself counts complete writes.
    timeout(LIMIT, async {
        while TERMINALS.load(Ordering::SeqCst) < 7 || FALLBACK_TERMINALS.load(Ordering::SeqCst) < 1
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("missing ShadowTLS terminal diagnostics");
}

async fn exercise(policy: &mut Policy) {
    tokio::spawn(async {
        log::debug!(target: "tls_privacy_control", "debug collector active");
        log::trace!(target: "tls_privacy_control", "trace collector active");
    })
    .await
    .unwrap();
    for value in [
        SNI,
        PASSWORD,
        SS_KEY,
        REMOTE_SNI,
        FAILED_REMOTE_SNI,
        ERROR_TEXT,
        "wrong-tls-credential-canary",
        super::DESTINATION,
        super::QUERY,
        "wrong-name.tls-privacy.invalid",
    ] {
        policy.protect(value.as_bytes());
    }
    policy.protect(ALPN);
    policy.protect(PAYLOAD);
    policy.protect(
        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, SS_KEY).unwrap(),
    );
    let cert = Certificate::new();
    policy.protect(&cert.key);
    policy.protected.push(cert.key_pem.clone());
    policy.protect(cert.der.as_ref());
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        for stateless in [false, true] {
            let (server, client) = cert.configs(version, stateless, false);
            assert_eq!(
                flight(server.clone(), client.clone(), SNI, policy, true).await,
                Some(HandshakeKind::Full)
            );
            assert_eq!(
                flight(server.clone(), client.clone(), SNI, policy, true).await,
                Some(HandshakeKind::Resumed)
            );
            assert!(
                flight(
                    server.clone(),
                    client,
                    "wrong-name.tls-privacy.invalid",
                    policy,
                    false
                )
                .await
                .is_none()
            );
            let (_, mut untrusted) = cert.configs(version, stateless, false);
            Arc::get_mut(&mut untrusted)
                .unwrap()
                .dangerous()
                .set_certificate_verifier(
                    rustls::client::WebPkiServerVerifier::builder(Arc::new({
                        let other = Certificate::new();
                        let mut roots = RootCertStore::empty();
                        roots.add(other.der).unwrap();
                        roots
                    }))
                    .build()
                    .unwrap(),
                );
            assert!(
                flight(server, untrusted, SNI, policy, false)
                    .await
                    .is_none()
            );
        }
    }
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let (server, client) = cert.configs(version, false, true);
        assert_eq!(
            flight(server, client, SNI, policy, true).await,
            Some(HandshakeKind::Full)
        );
    }
    let (_, client) = cert.configs(&rustls::version::TLS13, false, false);
    malformed_sni(client.clone(), "okbad.invalid", b"!!bad.invalid", policy).await;
    malformed_sni(client, "127.0.0.x", b"127.0.0.1", policy).await;
    let invalid_root = b"invalid-root-payload-canary";
    policy.protect(invalid_root);
    assert_eq!(
        RootCertStore::empty()
            .add_parsable_certificates([CertificateDer::from(invalid_root.to_vec())]),
        (0, 1)
    );
    shadowtls(&cert, policy).await;
}

fn inspect(dir: &Path, stdout: &[u8], stderr: &[u8], trace: bool) {
    let policy: Policy =
        serde_json::from_slice(&std::fs::read(dir.join("policy.json")).unwrap()).unwrap();
    let stdout = std::str::from_utf8(stdout).unwrap();
    for bind in &policy.binds {
        assert_eq!(
            stdout
                .lines()
                .filter(|line| guard::startup(line, bind))
                .count(),
            1,
            "each configured bind is allowed only once, at startup"
        );
    }
    for line in stdout.lines() {
        let harness = matches!(line, "" | "running 1 test" | ".")
            || line
                .strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
                .and_then(|s| s.split_once(" filtered out; finished in "))
                .is_some_and(|(n, time)| {
                    n.parse::<u32>().is_ok()
                        && time
                            .strip_suffix('s')
                            .is_some_and(|t| t.parse::<f64>().is_ok())
                });
        assert!(
            harness || policy.binds.iter().any(|bind| guard::startup(line, bind)),
            "unclassified stdout: {line:?}"
        );
    }
    let events: Vec<Event> = std::str::from_utf8(stderr)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .expect("every stderr byte must belong to a complete diagnostic record")
        })
        .collect();
    let original: String = events
        .iter()
        .map(|e| format!("{}\n", e.formatted))
        .collect();
    assert_eq!(
        std::fs::read(dir.join("engine.log")).unwrap(),
        original.as_bytes(),
        "complete engine channel must match the unfiltered records, including multiline fixture dumps"
    );
    for event in &events {
        let suffix = format!(" {} {}] {}", event.level, event.target, event.message);
        let timestamp = event.formatted.strip_prefix('[').and_then(|s| s.strip_suffix(&suffix))
            .expect("the complete formatted channel may contain only timestamp, level, target and message");
        chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.3f").unwrap();
        if event.fixture_client {
            assert!(
                !event.target.starts_with("rustls::server"),
                "server record misattributed to fixture"
            );
            assert!(
                event.target.starts_with("rustls::client::")
                    || matches!(
                        event.target.as_str(),
                        "rustls::common_state"
                            | "rustls::conn"
                            | "shoes::tcp::tcp_client_handler_factory"
                    ),
                "unclassified fixture target: {event:?}"
            );
        } else {
            assert!(
                guard::server_record(event, &policy.protected).is_ok(),
                "{:?}: {event:?}",
                guard::server_record(event, &policy.protected)
            );
        }
    }
    let has = |target: &str, message: &str| {
        events
            .iter()
            .any(|e| !e.fixture_client && e.target == target && e.message == message)
    };
    assert!(has("tls_privacy_control", "debug collector active"));
    assert!(has("tls_privacy_control", "server rejection observed"));
    assert!(has(
        "shoes::shadow_tls::shadow_tls_server_handler",
        "SHADOWTLS FALLBACK: Connection completed"
    ));
    assert!(
        events.iter().any(|e| !e.fixture_client
            && e.level == "DEBUG"
            && e.target == "rustls::server::hs"
            && e.message.starts_with("decided upon suite ")),
        "real rustls server DEBUG diagnostics must arrive"
    );
    assert!(has(
        "shoes::tcp::tcp_server::startup",
        "TCP handler initialized"
    ));
    assert!(has(
        "shoes::tcp::tcp_server::listener",
        "TCP connection finished successfully"
    ));
    assert!(
        events
            .iter()
            .any(|e| !e.fixture_client && e.message.contains("finished with error (kind="))
    );
    assert!(
        events
            .iter()
            .any(|e| e.fixture_client && e.target.starts_with("rustls::client::")),
        "fixture attribution must be live too"
    );
    if trace {
        for (target, message) in [
            ("tls_privacy_control", "trace collector active"),
            ("rustls::server::hs", "received client hello"),
            (
                "rustls::server::server_conn",
                "Accepted::client_hello() available",
            ),
            ("rustls::server::tls13::client_hello", "sending finished"),
            (
                "rustls::server::tls13",
                "sending new ticket (stateless: false)",
            ),
            (
                "rustls::server::tls13",
                "sending new ticket (stateless: true)",
            ),
            (
                "rustls::server::tls12::client_hello",
                "sending server hello",
            ),
        ] {
            assert!(
                has(target, message),
                "missing positive control {target}: {message}"
            );
        }
    }
}

#[test]
fn server_diagnostics_are_private() {
    if let Ok(dir) = std::env::var(CHILD) {
        let dir = Path::new(&dir);
        let trace = std::env::var("SHOES_TLS_PRIVACY_LEVEL").unwrap() == "TRACE";
        init_multi_logger(
            vec![Box::new(Writer {
                file: FileLogWriter::new(dir.join("engine.log").to_str().unwrap()).unwrap(),
                serial: Mutex::new(()),
            })],
            vec![Directive {
                name: None,
                level: if trace {
                    LevelFilter::Trace
                } else {
                    LevelFilter::Debug
                },
            }],
        );
        let mut policy = Policy::default();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(LIMIT * 12, exercise(&mut policy))
                    .await
                    .expect("TLS privacy scenarios timed out")
            });
        log::logger().flush();
        std::fs::write(
            dir.join("policy.json"),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        return;
    }
    let root = std::env::var_os("SHOES_TLS_PRIVACY_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&root).unwrap();
    let root = tempfile::Builder::new()
        .prefix("tls-privacy-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    for level in ["DEBUG", "TRACE"] {
        let dir = root.join(level);
        std::fs::create_dir(&dir).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tls::server_diagnostics_are_private",
                "--nocapture",
                "--test-threads=1",
                "--quiet",
            ])
            .env(CHILD, &dir)
            .env("SHOES_TLS_PRIVACY_LEVEL", level)
            .output()
            .unwrap();
        std::fs::write(dir.join("stdout.capture"), &output.stdout).unwrap();
        std::fs::write(dir.join("stderr.capture"), &output.stderr).unwrap();
        std::fs::write(dir.join("exit.txt"), output.status.to_string()).unwrap();
        println!("Complete {level} TLS privacy captures: {}", dir.display());
        assert!(
            output.status.success(),
            "TLS child failed: {}; complete captures at {}",
            output.status,
            dir.display()
        );
        inspect(&dir, &output.stdout, &output.stderr, level == "TRACE");
    }
}
