//! Local, in-process listener regression with an unfiltered live log collector.
//! A separate test binary keeps the process-global logger isolated from other suites.
#[path = "listener_logging/tls.rs"]
mod tls;

use std::future::Future;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::{LevelFilter, Log, Metadata, Record};
use parking_lot::Mutex;
use shoes::NetLocation;
use shoes::async_stream::AsyncStream;
use shoes::config::{Config, create_server_configs};
use shoes::embedding::{
    OutboundDecision, ServerHooks, SessionAuth, SessionGrant, start_servers_with_hooks,
};
use shoes::resolver::{NativeResolver, Resolver};
use shoes::tcp::tcp_client_handler_factory::create_tcp_client_handler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

const LIMIT: Duration = Duration::from_secs(5);
const PASSWORD: &str = "listener-privacy-credential-canary";
const PAYLOAD: &[u8] = b"listener-privacy-payload-canary";
const DESTINATION: &str = "destination.listener-privacy.invalid";
const QUERY: &str = "query.listener-privacy.invalid";
const ERROR_IPV6: &str = "[2001:db8::cafe]:43197";
const CONTROL: &str = "listener privacy collector control";

#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl Log for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        // Do not filter by target, level or contents: capture dependencies too.
        self.0.lock().push(format!(
            "{} {} {}",
            record.level(),
            record.target(),
            record.args()
        ));
    }

    fn flush(&self) {}
}

impl Capture {
    fn output(&self) -> String {
        self.0.lock().join("\n")
    }

    async fn wait_for(&self, event: &str, count: usize) {
        timeout(LIMIT, async {
            while self.output().matches(event).count() < count {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing diagnostic {event:?}:\n{}", self.output()));
    }

    fn assert_private(&self, sensitive: &[String]) {
        let output = self.output();
        assert!(output.contains(CONTROL));
        for value in sensitive {
            assert!(
                !output.contains(value),
                "sensitive value {value:?} in logs:\n{output}"
            );
        }
        assert!(
            !output.contains("key_bytes"),
            "handler leaked key material:\n{output}"
        );
    }
}

#[derive(Debug)]
struct LocalResolver {
    echo: SocketAddr,
    refused: SocketAddr,
    // Deliberately hostile error text must never reach the listener's logs.
    error: Mutex<String>,
}

impl Resolver for LocalResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        let result = match location.address().hostname() {
            Some(DESTINATION) => Ok(vec![self.echo]),
            Some("refused.listener-privacy.invalid") => Ok(vec![self.refused]),
            Some(QUERY) => Err(Error::new(
                ErrorKind::PermissionDenied,
                self.error.lock().clone(),
            )),
            _ => panic!("unexpected local resolution request"),
        };
        Box::pin(async move { result })
    }
}

#[derive(Debug)]
struct Hooks {
    accept: AtomicBool,
    block: AtomicBool,
}

impl ServerHooks for Hooks {
    fn open_session(&self, _: SessionAuth<'_>) -> Option<SessionGrant> {
        self.accept
            .load(Ordering::SeqCst)
            .then(|| SessionGrant::new("private-session-identity", CancellationToken::new()))
    }

    fn check_outbound(&self, _: &NetLocation, _: SocketAddr) -> OutboundDecision {
        if self.block.load(Ordering::SeqCst) {
            OutboundDecision::Block
        } else {
            OutboundDecision::Allow
        }
    }
}

// Abort listeners even when an assertion fails. Connection tasks finish before
// their terminal diagnostics are observed; the runtime drops any remaining tasks.
struct Tasks(Vec<JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn connect(address: SocketAddr, sensitive: &mut Vec<String>) -> Box<dyn AsyncStream> {
    // Hooked TCP startup owns its listeners before returning. Do not retry a
    // refused connection here: that would mask a listener-readiness regression.
    let stream = timeout(LIMIT, TcpStream::connect(address))
        .await
        .expect("listener connect timed out")
        .expect("hooked listener must already be ready");
    let peer = stream.local_addr().unwrap();
    sensitive.extend([
        peer.to_string(),
        peer.ip().to_string(),
        peer.port().to_string(),
    ]);
    Box::new(stream)
}

async fn shadowsocks_connect(
    stream: Box<dyn AsyncStream>,
    hostname: &str,
    port: u16,
) -> Box<dyn AsyncStream> {
    let client = create_tcp_client_handler(
        serde_yaml::from_str(&format!(
            "type: shadowsocks\ncipher: aes-256-gcm\npassword: {PASSWORD}"
        ))
        .unwrap(),
        None,
        Arc::new(NativeResolver::new()),
    );
    timeout(
        LIMIT,
        client.setup_client_tcp_stream(
            stream,
            NetLocation::from_str(&format!("{hostname}:{port}"), None)
                .unwrap()
                .into(),
        ),
    )
    .await
    .expect("client handshake timed out")
    .unwrap()
    .client_stream
}

async fn assert_closed(mut stream: Box<dyn AsyncStream>, capture: &Capture) {
    let mut byte = [0];
    assert!(
        matches!(
            timeout(LIMIT, stream.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        ),
        "connection did not close:\n{}",
        capture.output()
    );
}

fn listener_config(binding: &str) -> Config {
    let configs: Vec<Config> = serde_yaml::from_str(&format!(
        r#"
- {binding}
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{PASSWORD}"
"#
    ))
    .unwrap();
    create_server_configs(configs).unwrap().configs.remove(0)
}

#[tokio::test]
async fn listener_logs_omit_sensitive_values() {
    let capture = Box::leak(Box::new(Capture::default()));
    log::set_logger(capture).expect("dedicated test binary must own its logger");
    log::set_max_level(LevelFilter::Trace);
    log::info!("{CONTROL}");
    assert!(
        capture.output().contains(CONTROL),
        "collector must be active"
    );

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    // Reserve an unused local port until just before the refusal check.
    let refused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused_address = refused.local_addr().unwrap();
    let resolver = Arc::new(LocalResolver {
        echo: echo_address,
        refused: refused_address,
        error: Mutex::new(String::new()),
    });
    let hooks = Arc::new(Hooks {
        accept: AtomicBool::new(true),
        block: AtomicBool::new(false),
    });
    let mut sensitive = vec![
        PASSWORD.to_string(),
        String::from_utf8(PAYLOAD.to_vec()).unwrap(),
        DESTINATION.to_string(),
        QUERY.to_string(),
        "refused.listener-privacy.invalid".to_string(),
        ERROR_IPV6.to_string(),
        "2001:db8::cafe".to_string(),
        "43197".to_string(),
        "private-session-identity".to_string(),
        echo_address.to_string(),
        echo_address.port().to_string(),
        refused_address.to_string(),
        refused_address.port().to_string(),
    ];

    // Reserve then release the port for synchronous hooked listener startup.
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let config = listener_config(&format!("address: '{address}'"));
    drop(reserved);
    let mut tasks = Tasks(
        start_servers_with_hooks(config, resolver.clone(), hooks.clone())
            .await
            .unwrap(),
    );
    tasks.0.push(tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut payload = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, PAYLOAD);
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
    }));

    // Successful forwarding of a hostname destination and application payload.
    let mut stream = shadowsocks_connect(
        connect(address, &mut sensitive).await,
        DESTINATION,
        echo_address.port(),
    )
    .await;
    stream.write_all(PAYLOAD).await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0; PAYLOAD.len()];
    timeout(LIMIT, stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, PAYLOAD);
    stream.shutdown().await.unwrap();
    drop(stream);
    capture.wait_for("finished successfully", 1).await;

    // Embedder authentication rejection, then outbound policy rejection.
    hooks.accept.store(false, Ordering::SeqCst);
    let stream =
        shadowsocks_connect(connect(address, &mut sensitive).await, DESTINATION, 443).await;
    assert_closed(stream, capture).await;
    capture
        .wait_for("session refused by embedder hooks", 1)
        .await;
    capture.wait_for("finished successfully", 2).await;
    hooks.accept.store(true, Ordering::SeqCst);
    hooks.block.store(true, Ordering::SeqCst);
    let stream =
        shadowsocks_connect(connect(address, &mut sensitive).await, DESTINATION, 443).await;
    assert_closed(stream, capture).await;
    capture.wait_for("finished successfully", 3).await;
    hooks.block.store(false, Ordering::SeqCst);

    // Invalid encrypted handshake, exercising the real protocol error path.
    let mut stream = connect(address, &mut sensitive).await;
    stream.write_all(&[0; 128]).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_closed(stream, capture).await;
    capture.wait_for("finished with error", 1).await;

    // DNS failure with sensitive values embedded inside an arbitrary io::Error.
    let stream = connect(address, &mut sensitive).await;
    *resolver.error.lock() = format!(
        "DNS query {QUERY} to {ERROR_IPV6}; peer {}; credential {PASSWORD}; payload {}",
        sensitive[sensitive.len() - 3],
        String::from_utf8_lossy(PAYLOAD)
    );
    let stream = shadowsocks_connect(stream, QUERY, 43197).await;
    assert_closed(stream, capture).await;
    capture.wait_for("finished with error", 2).await;

    // Actual outbound connect failure, including connector debug diagnostics.
    drop(refused);
    let stream = shadowsocks_connect(
        connect(address, &mut sensitive).await,
        "refused.listener-privacy.invalid",
        refused_address.port(),
    )
    .await;
    assert_closed(stream, capture).await;
    capture.wait_for("finished with error", 3).await;
    capture.assert_private(&sensitive);

    // The same listener completion boundary must be private for IPv6 peers.
    let reserved = std::net::TcpListener::bind("[::1]:0").unwrap();
    let ipv6_address = reserved.local_addr().unwrap();
    let config = listener_config(&format!("address: '{ipv6_address}'"));
    drop(reserved);
    tasks.0.extend(
        start_servers_with_hooks(config, resolver.clone(), hooks.clone())
            .await
            .unwrap(),
    );
    hooks.accept.store(false, Ordering::SeqCst);
    let stream = shadowsocks_connect(
        connect(ipv6_address, &mut sensitive).await,
        DESTINATION,
        443,
    )
    .await;
    assert_closed(stream, capture).await;
    capture
        .wait_for("session refused by embedder hooks", 2)
        .await;
    capture
        .wait_for("TCP connection finished successfully", 4)
        .await;
    hooks.accept.store(true, Ordering::SeqCst);
    let stream =
        shadowsocks_connect(connect(ipv6_address, &mut sensitive).await, QUERY, 43197).await;
    assert_closed(stream, capture).await;
    capture
        .wait_for("TCP connection finished with error", 4)
        .await;

    // Unix listeners share process_stream and can leak the same nested errors.
    #[cfg(unix)]
    {
        // Keep the owned socket path short regardless of worktree or TMPDIR length.
        let dir = tempfile::Builder::new()
            .prefix("shoes-listener-")
            .rand_bytes(8)
            .tempdir_in("/tmp")
            .unwrap();
        let path = dir.path().join("listener.sock");
        let config = listener_config(&format!("path: '{}'", path.display()));
        tasks.0.extend(
            start_servers_with_hooks(config, resolver.clone(), hooks.clone())
                .await
                .unwrap(),
        );
        let connect_unix = || async {
            timeout(LIMIT, async {
                loop {
                    match tokio::net::UnixStream::connect(&path).await {
                        Ok(stream) => break Box::new(stream) as Box<dyn AsyncStream>,
                        Err(e) if e.kind() == ErrorKind::NotFound => {
                            sleep(Duration::from_millis(10)).await;
                        }
                        Err(e) => panic!("Unix listener connect failed: {e}"),
                    }
                }
            })
            .await
            .expect("Unix listener did not start")
        };
        hooks.accept.store(false, Ordering::SeqCst);
        let stream = shadowsocks_connect(connect_unix().await, DESTINATION, 443).await;
        assert_closed(stream, capture).await;
        capture
            .wait_for("Unix connection finished successfully", 1)
            .await;
        hooks.accept.store(true, Ordering::SeqCst);
        let stream = shadowsocks_connect(connect_unix().await, QUERY, 43197).await;
        assert_closed(stream, capture).await;
        capture
            .wait_for("Unix connection finished with error", 1)
            .await;
        sensitive.push(path.to_string_lossy().into_owned());
    }

    capture.assert_private(&sensitive);
    let output = capture.output();
    assert!(output.contains("DEBUG shoes::tcp::tcp_server::listener "));
    assert!(output.contains("ERROR shoes::tcp::tcp_server::listener "));
    assert!(output.contains("DEBUG shoes::tcp::tcp_server::startup TCP handler initialized"));
    assert!(output.contains("Found matching routing rule"));
    assert!(output.contains("Chain TCP complete: 1 total hop(s)"));
    assert!(output.contains("TCP connect failed (kind=ConnectionRefused)"));
    // Operational error categories survive even when arbitrary error text does not.
    assert!(output.contains("InvalidData"), "{output}");
    assert!(output.contains("PermissionDenied"), "{output}");
    assert!(output.contains("ConnectionRefused"), "{output}");
}
