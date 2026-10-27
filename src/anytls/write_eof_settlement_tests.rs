//! Transport-failure settlement of backpressured sessions over real TCP, real
//! TLS, the real AnyTLS handler and a real destination socket.
use super::anytls_server_session::AnyTlsSession;
use super::anytls_types::{Command, Frame};
use super::write_eof_offer_tests::{
    BOUND, Io, PASSWORD, Tls, client_tls, direct_group, direct_selector, location, tls, tls_from,
};
use super::*;
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::config::{Config, ConfigSelection, convert_cert_paths, create_server_configs};
use crate::embedding::{OutboundDecision, ServerHooks, SessionAuth, SessionGrant};
use crate::resolver::{NativeResolver, Resolver};
use crate::socks_handler::write_location_to_vec;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::tcp::tcp_server::process_stream;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
use bytes::{Bytes, BytesMut};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const UPLOAD: usize = 9 * 1024 * 1024;
// Legacy streams have deeper queues; the destination never reads this much.
const LEGACY_UPLOAD: usize = 64 * 1024 * 1024;
const RESPONSE: usize = 256 * 1024;
const CHUNK: usize = 64 * 1024;
// One PSH payload; frame lengths are u16.
const RAW_CHUNK: usize = 32 * 1024;
// Small socket buffers keep the backpressure point independent of OS autotuning.
const SMALL_BUFFER: u32 = 32 * 1024;

// The only helpers that name the transport-failure API.
type Watch = Option<crate::transport_watch::TransportWatch>;
fn watch(tcp: &TcpStream) -> Watch {
    crate::transport_watch::TransportWatch::tcp(tcp).ok()
}
fn attach(session: &AnyTlsSession, watch: Watch) {
    session.watch_transport(watch);
}

fn small_socket() -> TcpSocket {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(SMALL_BUFFER).unwrap();
    socket.set_send_buffer_size(SMALL_BUFFER).unwrap();
    socket
}

fn small_listener() -> TcpListener {
    let socket = small_socket();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    socket.listen(16).unwrap()
}

fn sha256(data: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Embedder hooks: `done` is the embedder's view of the session's lifetime.
#[derive(Debug, Default)]
struct Grants {
    done: CancellationToken,
}
impl ServerHooks for Grants {
    fn open_session(&self, _: SessionAuth<'_>) -> Option<SessionGrant> {
        Some(SessionGrant::with_done(
            "public-test",
            CancellationToken::new(),
            self.done.clone(),
        ))
    }
    fn check_outbound(&self, _: &NetLocation, _: SocketAddr) -> OutboundDecision {
        OutboundDecision::Allow
    }
}

/// TLS termination in front of a write-eof server, as an embedder runs it.
struct TlsThenAnyTls {
    acceptor: TlsAcceptor,
    inner: AnyTlsServerHandler,
}
impl std::fmt::Debug for TlsThenAnyTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsThenAnyTls")
    }
}
#[async_trait::async_trait]
impl TcpServerHandler for TlsThenAnyTls {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let tls = self.acceptor.accept(stream).await?;
        self.inner.setup_server_stream(Box::new(Io(tls))).await
    }
}

fn negotiated_handler(tls: &Tls, grants: &Arc<Grants>) -> Arc<dyn TcpServerHandler> {
    Arc::new(TlsThenAnyTls {
        acceptor: tls.acceptor.clone(),
        inner: crate::embedding::anytls_server_handler(
            vec![],
            PaddingFactory::default_factory(),
            Arc::new(NativeResolver),
            direct_group(),
            Some(grants.clone()),
            true,
        ),
    })
}

/// Shoes' own per-connection path for one accepted TCP connection.
fn serve(listener: TcpListener, handler: Arc<dyn TcpServerHandler>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        process_stream(tcp, handler, Arc::new(NativeResolver))
            .await
            .unwrap();
    })
}

struct ResetProxy {
    addr: SocketAddr,
    reset: CancellationToken,
    // True when the reset was injected while both directions were still open.
    task: JoinHandle<bool>,
}

fn reset_proxy(upstream: SocketAddr) -> ResetProxy {
    let listener = small_listener();
    let addr = listener.local_addr().unwrap();
    let reset = CancellationToken::new();
    let cancelled = reset.clone();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let socket = small_socket();
        socket.set_zero_linger().unwrap();
        let mut server = socket.connect(upstream).await.unwrap();
        // Dropping the zero-linger socket sends an actual TCP RST, not a TLS close.
        tokio::select! {
            () = cancelled.cancelled() => true,
            _ = tokio::io::copy_bidirectional(&mut client, &mut server) => false,
        }
    });
    ResetProxy { addr, reset, task }
}

/// A destination that accepts and then does not read.
fn sink() -> (SocketAddr, JoinHandle<TcpStream>) {
    let listener = small_listener();
    let addr = listener.local_addr().unwrap();
    (
        addr,
        tokio::spawn(async move { listener.accept().await.unwrap().0 }),
    )
}

/// TLS client over a small-buffer socket, so backpressure reaches it early.
async fn small_client_tls(tls: &Tls, addr: SocketAddr) -> Box<dyn AsyncStream> {
    client_tls(tls, small_socket().connect(addr).await.unwrap()).await
}

async fn strict_client(tls: &Tls, addr: SocketAddr) -> Arc<WriteEofClientSession> {
    WriteEofClientSession::connect(
        small_client_tls(tls, addr).await,
        PASSWORD,
        PaddingFactory::default_factory(),
        WriteEofOptions::default(),
    )
    .await
    .unwrap()
}

struct Upload<R> {
    progress: Arc<AtomicUsize>,
    // Upload, then the ordered local EOF. Ok only after the EOF is acknowledged.
    task: JoinHandle<io::Result<()>>,
    reader: R,
}

fn upload(stream: AnyTlsStream, size: usize) -> Upload<ReadHalf<AnyTlsStream>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let progress = Arc::new(AtomicUsize::new(0));
    let accepted = progress.clone();
    let task = tokio::spawn(async move {
        let chunk = vec![b'U'; CHUNK];
        while accepted.load(SeqCst) < size {
            writer.write_all(&chunk).await?;
            accepted.fetch_add(CHUNK, SeqCst);
        }
        writer.shutdown().await
    });
    Upload {
        progress,
        task,
        reader,
    }
}

/// Legacy wire client. Shoes' own legacy client queues writes without bound
/// (`AnyTlsClientSession` uses an unbounded channel), so it never stalls; this
/// writes ordinary v2 frames straight to TLS and stalls with the transport.
async fn raw_legacy_upload(
    mut transport: Box<dyn AsyncStream>,
    target: SocketAddr,
    size: usize,
) -> Upload<ReadHalf<Box<dyn AsyncStream>>> {
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
    let (reader, mut writer) = tokio::io::split(transport);
    let progress = Arc::new(AtomicUsize::new(0));
    let accepted = progress.clone();
    let task = tokio::spawn(async move {
        let mut head = BytesMut::new();
        Frame::with_data(Command::Settings, 0, Bytes::from_static(b"v=2")).encode_into(&mut head);
        Frame::control(Command::Syn, 1).encode_into(&mut head);
        Frame::with_data(
            Command::Psh,
            1,
            write_location_to_vec(&location(target)).into(),
        )
        .encode_into(&mut head);
        writer.write_all(&head).await?;
        let frame = Frame::data(1, Bytes::from(vec![b'U'; RAW_CHUNK])).encode();
        while accepted.load(SeqCst) < size {
            writer.write_all(&frame).await?;
            writer.flush().await?;
            accepted.fetch_add(RAW_CHUNK, SeqCst);
        }
        writer.shutdown().await
    });
    Upload {
        progress,
        task,
        reader,
    }
}

/// Wait until the upload stops making progress: the session is backpressured.
async fn backpressured<R>(upload: &Upload<R>, size: usize) -> usize {
    let accepted = timeout(Duration::from_secs(30), async {
        loop {
            let before = upload.progress.load(SeqCst);
            sleep(Duration::from_millis(500)).await;
            let after = upload.progress.load(SeqCst);
            if after == before && after > 0 {
                return after;
            }
        }
    })
    .await
    .expect("upload never became backpressured");
    assert!(
        accepted < size,
        "upload completed; nothing is backpressured"
    );
    assert!(!upload.task.is_finished());
    accepted
}

async fn inject_reset(proxy: ResetProxy) -> Instant {
    let started = Instant::now();
    proxy.reset.cancel();
    assert!(
        proxy.task.await.unwrap(),
        "proxy ended before the injected reset"
    );
    started
}

/// The destination saw closure and never a complete upload.
async fn assert_destination_closed(mut destination: TcpStream, limit: usize) {
    let mut drained = Vec::new();
    let result = timeout(BOUND, destination.read_to_end(&mut drained))
        .await
        .expect("destination connection was not closed");
    assert!(
        result.is_ok() || matches!(&result, Err(e) if e.kind() == io::ErrorKind::ConnectionReset),
        "{result:?}"
    );
    assert!(
        drained.len() < limit,
        "destination received the whole upload"
    );
}

struct Negotiated {
    grants: Arc<Grants>,
    server: JoinHandle<()>,
    proxy: ResetProxy,
    client: Arc<WriteEofClientSession>,
    destination: TcpStream,
    upload: Upload<ReadHalf<AnyTlsStream>>,
}

/// Negotiated session through Shoes' per-connection path and a reset proxy,
/// with an upload that the unread destination has backpressured.
async fn negotiated_backpressured(tls: &Tls) -> Negotiated {
    let grants = Arc::new(Grants::default());
    let listener = small_listener();
    let proxy = reset_proxy(listener.local_addr().unwrap());
    let server = serve(listener, negotiated_handler(tls, &grants));
    let (target, accepted) = sink();
    let client = strict_client(tls, proxy.addr).await;
    let stream = client.open_stream(location(target)).await.unwrap();
    let destination = accepted.await.unwrap();
    let upload = upload(stream, UPLOAD);
    backpressured(&upload, UPLOAD).await;
    Negotiated {
        grants,
        server,
        proxy,
        client,
        destination,
        upload,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressured_reset_settles_negotiated_session() {
    timeout(Duration::from_secs(60), async {
        let tls = tls();
        let case = negotiated_backpressured(&tls).await;
        assert!(!case.grants.done.is_cancelled());
        let started = inject_reset(case.proxy).await;
        timeout(BOUND, case.grants.done.cancelled())
            .await
            .expect("transport reset did not settle the backpressured session within 5 s");
        let elapsed = started.elapsed();
        // A lost or cancelled EOF is never success.
        let upload = timeout(BOUND, case.upload.task)
            .await
            .expect("client upload did not settle")
            .unwrap();
        assert!(
            upload.is_err(),
            "upload and EOF cannot succeed after a reset"
        );
        assert_destination_closed(case.destination, UPLOAD).await;
        assert!(elapsed < BOUND);
        eprintln!(
            "negotiated backpressured reset settled_ms={}",
            elapsed.as_millis()
        );
        drop(case.client);
        case.server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressured_reset_releases_session_resources() {
    timeout(Duration::from_secs(60), async {
        let tls = tls();
        let listener = small_listener();
        let proxy = reset_proxy(listener.local_addr().unwrap());
        let acceptor = tls.acceptor.clone();
        let (created, created_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let watch = watch(&tcp);
            let mut transport = acceptor.accept(tcp).await.unwrap();
            let mut hash = [0; 32];
            transport.read_exact(&mut hash).await.unwrap();
            assert_eq!(
                &hash[..],
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, PASSWORD.as_bytes()).as_ref()
            );
            let len = transport.read_u16().await.unwrap();
            transport
                .read_exact(&mut vec![0; len as usize])
                .await
                .unwrap();
            let session = AnyTlsSession::new_server_with_initial_data(
                Io(transport),
                PaddingFactory::default_factory(),
                Arc::new(NativeResolver),
                direct_selector(),
                false,
                "public-test".into(),
                None,
            );
            session.enable_write_eof(true);
            attach(&session, watch);
            created
                .send(session.clone())
                .unwrap_or_else(|_| panic!("test receiver closed"));
            session.run_until_cancelled(None).await
        });
        let (target, accepted) = sink();
        let client = strict_client(&tls, proxy.addr).await;
        let stream = client.open_stream(location(target)).await.unwrap();
        let destination = accepted.await.unwrap();
        let upload = upload(stream, UPLOAD);
        backpressured(&upload, UPLOAD).await;
        let session = created_rx.await.unwrap();
        assert_eq!(session.write_eof_resources_for_test(), (1, 7));
        let started = inject_reset(proxy).await;
        let result = timeout(BOUND, server)
            .await
            .expect("transport reset did not end the backpressured session within 5 s")
            .unwrap();
        assert!(
            result.is_err(),
            "a reset session cannot settle successfully"
        );
        // Aborted relay handlers drop asynchronously: poll, never assume.
        timeout(BOUND.saturating_sub(started.elapsed()), async {
            while session.write_eof_resources_for_test() != (0, 8) {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stream state and handler slots were not released");
        assert!(session.is_closed());
        assert!(timeout(BOUND, upload.task).await.unwrap().unwrap().is_err());
        assert_destination_closed(destination, UPLOAD).await;
        eprintln!(
            "negotiated reset resources (streams, free handler slots)={:?} settled_ms={}",
            session.write_eof_resources_for_test(),
            started.elapsed().as_millis()
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressured_healthy_session_is_not_settled() {
    timeout(Duration::from_secs(90), async {
        let tls = tls();
        let mut case = negotiated_backpressured(&tls).await;
        // Live traffic has no deadline: stay backpressured past the 5 s bound.
        sleep(BOUND + Duration::from_secs(1)).await;
        assert!(!case.upload.task.is_finished(), "live upload was terminated");
        assert!(
            !case.grants.done.is_cancelled(),
            "healthy session was settled"
        );
        let mut destination = case.destination;
        let reader = tokio::spawn(async move {
            let mut data = Vec::new();
            destination.read_to_end(&mut data).await.unwrap();
            (destination, data)
        });
        timeout(Duration::from_secs(30), case.upload.task)
            .await
            .expect("upload did not resume")
            .unwrap()
            .unwrap();
        let (mut destination, data) = timeout(Duration::from_secs(30), reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data.len(), UPLOAD);
        assert_eq!(sha256(&data), sha256(&vec![b'U'; UPLOAD]));
        destination.write_all(&vec![b'R'; RESPONSE]).await.unwrap();
        destination.shutdown().await.unwrap();
        let mut response = Vec::new();
        timeout(
            Duration::from_secs(30),
            case.upload.reader.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.len(), RESPONSE);
        assert_eq!(sha256(&response), sha256(&vec![b'R'; RESPONSE]));
        eprintln!(
            "healthy backpressured control destination_bytes={} destination_sha256={} response_bytes={}",
            data.len(),
            sha256(&data),
            response.len()
        );
        assert!(!case.grants.done.is_cancelled());
        case.client.close().await.unwrap();
        timeout(BOUND, case.grants.done.cancelled())
            .await
            .expect("completed session did not end");
        case.proxy.reset.cancel();
        case.server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_backpressured_reset_settles_through_shoes_config() {
    timeout(Duration::from_secs(60), async {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, identity.cert.pem()).unwrap();
        std::fs::write(&key, identity.signing_key.serialize_pem()).unwrap();
        let tls = tls_from(
            identity.cert.der().clone(),
            rustls::pki_types::PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()),
        );
        let yaml = format!(
            r#"
- address: "127.0.0.1:1"
  protocol:
    type: tls
    tls_targets:
      "localhost":
        cert: "{}"
        key: "{}"
        protocol:
          type: anytls
          users:
            - name: public-test
              password: "{PASSWORD}"
          udp_enabled: false
"#,
            cert.display(),
            key.display()
        );
        // Same loading steps as the binary: PEM paths first, then validation.
        let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
        let (configs, _) = convert_cert_paths(configs).await.unwrap();
        let Some(Config::Server(config)) = create_server_configs(configs)
            .unwrap()
            .configs
            .into_iter()
            .next()
        else {
            panic!("expected one server config");
        };
        // The same handler construction as the TCP listener startup.
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver);
        let grants = Arc::new(Grants::default());
        let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
        let selector = Arc::new(
            create_tcp_client_proxy_selector(rules, resolver.clone()).with_hooks(grants.clone()),
        );
        let handler: Arc<dyn TcpServerHandler> =
            create_tcp_server_handler(config.protocol, &selector, &resolver, None).into();
        let listener = small_listener();
        let proxy = reset_proxy(listener.local_addr().unwrap());
        let server = serve(listener, handler);
        let (target, accepted) = sink();
        let upload = raw_legacy_upload(
            small_client_tls(&tls, proxy.addr).await,
            target,
            LEGACY_UPLOAD,
        )
        .await;
        let destination = accepted.await.unwrap();
        backpressured(&upload, LEGACY_UPLOAD).await;
        assert!(!grants.done.is_cancelled());
        let started = inject_reset(proxy).await;
        timeout(BOUND, grants.done.cancelled())
            .await
            .expect("transport reset did not settle the backpressured legacy session within 5 s");
        eprintln!(
            "legacy backpressured reset settled_ms={}",
            started.elapsed().as_millis()
        );
        assert!(timeout(BOUND, upload.task).await.unwrap().unwrap().is_err());
        assert_destination_closed(destination, LEGACY_UPLOAD).await;
        server.await.unwrap();
    })
    .await
    .unwrap();
}
