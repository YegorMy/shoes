//! Integration tests for server hooks installed by an embedding application.
//!
//! Servers are started in-process with `start_servers_with_hooks`; clients
//! connect through client proxy chains built from `ClientConfig`s.
use shoes_test_support as common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use common::certs::generate_test_cert_files;
use common::port_helper::PortHelper;
use parking_lot::Mutex;
use shoes::config::{
    ClientChainHop, ClientConfig, Config, ConfigSelection, convert_cert_paths,
    create_server_configs,
};
use shoes::embedding::{
    OutboundDecision, ServerHooks, SessionAuth, SessionGrant, start_servers_with_hooks,
};
use shoes::resolver::{NativeResolver, Resolver};
use shoes::tcp::chain_builder::build_client_proxy_chain;
use shoes::{NetLocation, OneOrSome, ResolvedLocation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const SNI: &str = "hooks.test.local";
const LISTENER_PASSWORD: &str = "test-hooks-listener-password";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Hooks that accept the AnyTLS passwords they were given, record every
/// outbound check, and apply per-port outbound decisions.
#[derive(Debug, Default)]
struct TestHooks {
    users: Mutex<HashMap<[u8; 32], (String, CancellationToken)>>,
    listener_session: Mutex<Option<CancellationToken>>,
    /// Listener sessions granted per server target (SNI).
    target_sessions: Mutex<HashMap<String, CancellationToken>>,
    outbound: Mutex<HashMap<u16, OutboundDecision>>,
    refused: AtomicUsize,
    checked: Mutex<Vec<SocketAddr>>,
    targets_seen: Mutex<Vec<Option<String>>>,
    /// One `done` token per granted session, in grant order.
    done: Mutex<Vec<CancellationToken>>,
}

impl TestHooks {
    fn add_user(&self, name: &str, password: &str) -> CancellationToken {
        let cancel = CancellationToken::new();
        self.users
            .lock()
            .insert(sha256(password), (name.to_string(), cancel.clone()));
        cancel
    }
}

impl TestHooks {
    fn grant(&self, identity: String, cancel: CancellationToken) -> SessionGrant {
        let done = CancellationToken::new();
        self.done.lock().push(done.clone());
        SessionGrant::with_done(identity, cancel, done)
    }

    fn done_token(&self, index: usize) -> CancellationToken {
        self.done.lock()[index].clone()
    }
}

impl ServerHooks for TestHooks {
    fn open_session(&self, auth: SessionAuth<'_>) -> Option<SessionGrant> {
        let grant = match auth {
            SessionAuth::AnyTls {
                password_sha256, ..
            } => self
                .users
                .lock()
                .get(password_sha256)
                .map(|(name, cancel)| self.grant(name.clone(), cancel.clone())),
            SessionAuth::Listener { target: None } => {
                self.targets_seen.lock().push(None);
                self.listener_session
                    .lock()
                    .clone()
                    .map(|cancel| self.grant("listener".to_string(), cancel))
            }
            SessionAuth::Listener {
                target: Some(target),
            } => {
                self.targets_seen.lock().push(Some(target.to_string()));
                self.target_sessions
                    .lock()
                    .get(target)
                    .cloned()
                    .map(|cancel| self.grant(target.to_string(), cancel))
            }
            _ => None,
        };
        if grant.is_none() {
            self.refused.fetch_add(1, Ordering::SeqCst);
        }
        grant
    }

    fn check_outbound(&self, destination: &NetLocation, resolved: SocketAddr) -> OutboundDecision {
        self.checked.lock().push(resolved);
        self.outbound
            .lock()
            .get(&destination.port())
            .cloned()
            .unwrap_or(OutboundDecision::Allow)
    }
}

fn sha256(password: &str) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest(&SHA256, password.as_bytes()).as_ref());
    hash
}

/// Echo server that counts accepted and still-open connections.
struct EchoServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    open: Arc<AtomicUsize>,
    handle: JoinHandle<()>,
}

impl EchoServer {
    async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let (accepted_count, open_count) = (accepted.clone(), open.clone());
        let handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                accepted_count.fetch_add(1, Ordering::SeqCst);
                open_count.fetch_add(1, Ordering::SeqCst);
                let open_count = open_count.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    open_count.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok(Self {
            addr,
            accepted,
            open,
            handle,
        })
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// True once every connection the server accepted has been closed by the peer.
    async fn wait_all_closed(&self) -> bool {
        for _ in 0..50 {
            if self.open.load(Ordering::SeqCst) == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start_hooked_servers(
    server_yaml: &str,
    resolver: &Arc<dyn Resolver>,
    hooks: Arc<TestHooks>,
) -> Result<Vec<JoinHandle<()>>, Box<dyn std::error::Error>> {
    let configs: Vec<Config> = serde_yaml::from_str(server_yaml)?;
    let (configs, _) = convert_cert_paths(configs).await?;
    let validated = create_server_configs(configs)?;
    let mut handles = Vec::new();
    for config in validated.configs {
        handles.extend(start_servers_with_hooks(config, resolver.clone(), hooks.clone()).await?);
    }
    Ok(handles)
}

fn anytls_server_yaml(ip: &str, port: u16, cert: &str, key: &str) -> String {
    // The configured user is never consulted once hooks are installed.
    format!(
        r#"
- address: "{ip}:{port}"
  protocol:
    type: tls
    tls_targets:
      "{SNI}":
        cert: "{cert}"
        key: "{key}"
        protocol:
          type: anytls
          users:
            - name: "configured"
              password: "configured-password"
"#
    )
}

fn anytls_client(ip: &str, port: u16, password: &str) -> Result<ClientConfig, serde_yaml::Error> {
    serde_yaml::from_str(&format!(
        r#"
address: "{ip}:{port}"
protocol:
  type: tls
  verify: false
  sni_hostname: "{SNI}"
  protocol:
    type: anytls
    password: "{password}"
"#
    ))
}

async fn connect(
    client: ClientConfig,
    target: SocketAddr,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<Box<dyn shoes::async_stream::AsyncStream>> {
    let chain = build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
        resolver.clone(),
    );
    let location = NetLocation::from_str(&target.to_string(), None)?;
    let setup = chain
        .connect_tcp(ResolvedLocation::from(location), resolver)
        .await?;
    Ok(setup.client_stream)
}

async fn assert_echo(stream: &mut Box<dyn shoes::async_stream::AsyncStream>, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(echoed, payload);
}

/// True if the stream delivers no data: it closes, errors, or stays silent.
async fn assert_no_echo(stream: &mut Box<dyn shoes::async_stream::AsyncStream>) {
    let _ = stream.write_all(b"probe").await;
    let _ = stream.flush().await;
    let mut buf = [0u8; 16];
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        assert_eq!(n, 0, "a refused connection must not relay data");
    }
}

/// True once the stream has ended (EOF or error).
async fn wait_closed(stream: &mut Box<dyn shoes::async_stream::AsyncStream>) -> bool {
    let mut buf = [0u8; 16];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

#[tokio::test]
async fn test_anytls_hooks_authenticate_and_cancel_sessions() -> TestResult {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();
    let echo = EchoServer::start().await?;
    let echo_addr = echo.addr;

    let (cert, key) = generate_test_cert_files()?;
    let (ip, port) = ports.get_localhost_listener_port();
    let hooks = Arc::new(TestHooks::default());
    let device_a = hooks.add_user("device-a", "device-a-password");
    let server_yaml = anytls_server_yaml(&ip, port, cert.to_str().unwrap(), key.to_str().unwrap());
    let handles = start_hooked_servers(&server_yaml, &resolver, hooks.clone()).await?;
    ports.wait_for_all_ports().await?;

    // A password the hooks accept relays, and its destination was checked.
    let mut stream = connect(
        anytls_client(&ip, port, "device-a-password")?,
        echo_addr,
        &resolver,
    )
    .await?;
    assert_echo(&mut stream, b"hello from device-a").await;
    assert_eq!(echo.accepted(), 1);
    assert!(hooks.checked.lock().contains(&echo_addr));

    // The configured user is not consulted: the hooks refuse it.
    if let Ok(mut refused) = connect(
        anytls_client(&ip, port, "configured-password")?,
        echo_addr,
        &resolver,
    )
    .await
    {
        assert_no_echo(&mut refused).await;
    }
    assert_eq!(echo.accepted(), 1);
    assert!(hooks.refused.load(Ordering::SeqCst) >= 1);

    // Cancelling the grant ends the session and the connections it opened.
    // (The AnyTLS client does not surface the server's close to an open
    // stream, so the check is on the server's outbound side.)
    device_a.cancel();
    assert!(
        echo.wait_all_closed().await,
        "cancelled session must close its outbound connections"
    );
    assert_no_echo(&mut stream).await;

    for handle in handles {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_hooks_block_and_redirect_outbound() -> TestResult {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();
    let blocked = EchoServer::start().await?;
    let redirect = EchoServer::start().await?;
    let (blocked_addr, redirect_addr) = (blocked.addr, redirect.addr);
    // Nothing listens on this port; the hooks redirect it to the second echo server.
    let unused_addr = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;

    let (cert, key) = generate_test_cert_files()?;
    let (ip, port) = ports.get_localhost_listener_port();
    let hooks = Arc::new(TestHooks::default());
    hooks.add_user("device-a", "device-a-password");
    hooks
        .outbound
        .lock()
        .insert(blocked_addr.port(), OutboundDecision::Block);
    hooks.outbound.lock().insert(
        unused_addr.port(),
        OutboundDecision::Redirect(NetLocation::from_str(&redirect_addr.to_string(), None)?),
    );
    let server_yaml = anytls_server_yaml(&ip, port, cert.to_str().unwrap(), key.to_str().unwrap());
    let handles = start_hooked_servers(&server_yaml, &resolver, hooks.clone()).await?;
    ports.wait_for_all_ports().await?;

    if let Ok(mut blocked_stream) = connect(
        anytls_client(&ip, port, "device-a-password")?,
        blocked_addr,
        &resolver,
    )
    .await
    {
        assert_no_echo(&mut blocked_stream).await;
    }
    assert_eq!(blocked.accepted(), 0);

    let mut redirected = connect(
        anytls_client(&ip, port, "device-a-password")?,
        unused_addr,
        &resolver,
    )
    .await?;
    assert_echo(&mut redirected, b"redirected").await;
    assert_eq!(redirect.accepted(), 1);

    for handle in handles {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_listener_sessions_are_granted_and_cancelled() -> TestResult {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();
    let echo = EchoServer::start().await?;
    let echo_addr = echo.addr;

    let (ip, port) = ports.get_localhost_listener_port();
    let hooks = Arc::new(TestHooks::default());
    let server_yaml = format!(
        r#"
- address: "{ip}:{port}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{LISTENER_PASSWORD}"
"#
    );
    let handles = start_hooked_servers(&server_yaml, &resolver, hooks.clone()).await?;
    ports.wait_for_all_ports().await?;
    let client: ClientConfig = serde_yaml::from_str(&format!(
        r#"
address: "{ip}:{port}"
protocol:
  type: shadowsocks
  cipher: aes-256-gcm
  password: "{LISTENER_PASSWORD}"
"#
    ))?;

    // Without a grant the session is refused before any outbound connection.
    if let Ok(mut refused) = connect(client.clone(), echo_addr, &resolver).await {
        assert_no_echo(&mut refused).await;
    }
    assert_eq!(echo.accepted(), 0);

    // With a grant it relays, and cancelling the grant ends it.
    let cancel = CancellationToken::new();
    *hooks.listener_session.lock() = Some(cancel.clone());
    let mut stream = connect(client, echo_addr, &resolver).await?;
    assert_echo(&mut stream, b"hello through a granted listener session").await;
    cancel.cancel();
    assert!(wait_closed(&mut stream).await, "cancelled session must end");
    assert!(echo.wait_all_closed().await);

    for handle in handles {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_listener_sessions_report_their_tls_target() -> TestResult {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();
    let echo = EchoServer::start().await?;
    let echo_addr = echo.addr;

    let (cert, key) = generate_test_cert_files()?;
    let (cert, key) = (cert.to_str().unwrap(), key.to_str().unwrap());
    let (ip, port) = ports.get_localhost_listener_port();
    let hooks = Arc::new(TestHooks::default());
    let device_a = CancellationToken::new();
    hooks
        .target_sessions
        .lock()
        .insert("a.hooks.test".to_string(), device_a.clone());
    // One listener, one TLS target per device, each with its own inner key.
    let server_yaml = format!(
        r#"
- address: "{ip}:{port}"
  protocol:
    type: tls
    tls_targets:
      "a.hooks.test":
        cert: "{cert}"
        key: "{key}"
        protocol:
          type: shadowsocks
          cipher: aes-256-gcm
          password: "device-a-key"
      "b.hooks.test":
        cert: "{cert}"
        key: "{key}"
        protocol:
          type: shadowsocks
          cipher: aes-256-gcm
          password: "device-b-key"
"#
    );
    let handles = start_hooked_servers(&server_yaml, &resolver, hooks.clone()).await?;
    ports.wait_for_all_ports().await?;
    let client = |sni: &str, key: &str| -> Result<ClientConfig, serde_yaml::Error> {
        serde_yaml::from_str(&format!(
            r#"
address: "{ip}:{port}"
protocol:
  type: tls
  verify: false
  sni_hostname: "{sni}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{key}"
"#
        ))
    };

    // Device B's target has no grant: refused before any outbound connection.
    if let Ok(mut refused) = connect(
        client("b.hooks.test", "device-b-key")?,
        echo_addr,
        &resolver,
    )
    .await
    {
        assert_no_echo(&mut refused).await;
    }
    assert_eq!(echo.accepted(), 0);

    // Device A's target is granted, and cancelling its grant ends the session.
    let mut stream = connect(
        client("a.hooks.test", "device-a-key")?,
        echo_addr,
        &resolver,
    )
    .await?;
    assert_echo(&mut stream, b"hello from the device a target").await;
    device_a.cancel();
    assert!(wait_closed(&mut stream).await, "cancelled session must end");
    assert!(echo.wait_all_closed().await);

    let seen = hooks.targets_seen.lock().clone();
    assert!(seen.contains(&Some("a.hooks.test".to_string())));
    assert!(seen.contains(&Some("b.hooks.test".to_string())));

    for handle in handles {
        handle.abort();
    }
    Ok(())
}

async fn wait_done(done: &CancellationToken) -> bool {
    tokio::time::timeout(Duration::from_secs(5), done.cancelled())
        .await
        .is_ok()
}

#[tokio::test]
async fn test_done_token_signals_anytls_session_end() -> TestResult {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();
    let echo = EchoServer::start().await?;
    let echo_addr = echo.addr;

    let (cert, key) = generate_test_cert_files()?;
    let (ip, port) = ports.get_localhost_listener_port();
    let hooks = Arc::new(TestHooks::default());
    let device_a = hooks.add_user("device-a", "device-a-password");
    let server_yaml = anytls_server_yaml(&ip, port, cert.to_str().unwrap(), key.to_str().unwrap());
    let handles = start_hooked_servers(&server_yaml, &resolver, hooks.clone()).await?;
    ports.wait_for_all_ports().await?;

    let mut stream = connect(
        anytls_client(&ip, port, "device-a-password")?,
        echo_addr,
        &resolver,
    )
    .await?;
    assert_echo(&mut stream, b"hello before the client leaves").await;
    let done = hooks.done_token(0);
    assert!(!done.is_cancelled(), "a live session is not done");

    // The client going away ends the session: `done` fires, while the user's
    // shared cancel token is left alone for its other sessions.
    drop(stream);
    assert!(
        wait_done(&done).await,
        "session end must cancel its done token"
    );
    assert!(!device_a.is_cancelled());

    for handle in handles {
        handle.abort();
    }
    Ok(())
}

#[tokio::test]
async fn test_done_token_signals_listener_session_end() -> TestResult {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let mut ports = PortHelper::new();
    let echo = EchoServer::start().await?;
    let echo_addr = echo.addr;

    let (ip, port) = ports.get_localhost_listener_port();
    let hooks = Arc::new(TestHooks::default());
    let server_yaml = format!(
        r#"
- address: "{ip}:{port}"
  protocol:
    type: shadowsocks
    cipher: aes-256-gcm
    password: "{LISTENER_PASSWORD}"
"#
    );
    let handles = start_hooked_servers(&server_yaml, &resolver, hooks.clone()).await?;
    ports.wait_for_all_ports().await?;
    let client: ClientConfig = serde_yaml::from_str(&format!(
        r#"
address: "{ip}:{port}"
protocol:
  type: shadowsocks
  cipher: aes-256-gcm
  password: "{LISTENER_PASSWORD}"
"#
    ))?;

    let cancel = CancellationToken::new();
    *hooks.listener_session.lock() = Some(cancel.clone());
    let mut stream = connect(client, echo_addr, &resolver).await?;
    assert_echo(&mut stream, b"hello before the listener client leaves").await;
    let done = hooks.done_token(0);
    assert!(!done.is_cancelled(), "a live session is not done");

    drop(stream);
    assert!(
        wait_done(&done).await,
        "session end must cancel its done token"
    );
    assert!(!cancel.is_cancelled());

    for handle in handles {
        handle.abort();
    }
    Ok(())
}
