//! Transport-failure settlement of backpressured sessions over real TCP, real
//! TLS, the real AnyTLS handler and a real destination socket.
use super::anytls_server_session::AnyTlsSession;
use super::anytls_stream::STREAM_CHANNEL_BUFFER;
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
    os::fd::{AsFd, AsRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
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

// The only helpers that name the transport-failure API. A session in these
// tests always has a watch: failing to create one fails the test.
type Watch = Option<crate::transport_watch::TransportWatch>;
fn watch(tcp: &TcpStream) -> Watch {
    Some(crate::transport_watch::TransportWatch::tcp(tcp).expect("transport watch"))
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

/// Upload bytes at offsets `start..start + len`: each 4-byte word is the
/// big-endian index of that word, so content, order and offset are checkable.
fn upload_bytes(start: usize, len: usize) -> Vec<u8> {
    (start..start + len)
        .map(|offset| (offset as u32 / 4).to_be_bytes()[offset % 4])
        .collect()
}

/// Raw v2 wire client: authenticates and opens stream 1 to `target`, offering
/// write-eof/1 when `negotiated`. Shoes' own legacy client queues writes
/// without bound (`AnyTlsClientSession` uses an unbounded channel), so it never
/// stalls; a raw client writes frames straight to TLS and stalls with the
/// transport.
async fn raw_open(
    mut transport: Box<dyn AsyncStream>,
    target: SocketAddr,
    negotiated: bool,
) -> (
    ReadHalf<Box<dyn AsyncStream>>,
    WriteHalf<Box<dyn AsyncStream>>,
) {
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
    let settings: &'static [u8] = if negotiated {
        b"v=2\nx-write-eof=1"
    } else {
        b"v=2"
    };
    let mut head = BytesMut::new();
    Frame::with_data(Command::Settings, 0, Bytes::from_static(settings)).encode_into(&mut head);
    Frame::control(Command::Syn, 1).encode_into(&mut head);
    Frame::with_data(
        Command::Psh,
        1,
        write_location_to_vec(&location(target)).into(),
    )
    .encode_into(&mut head);
    writer.write_all(&head).await.unwrap();
    (reader, writer)
}

/// Writes the frame of [`upload_bytes`] that starts at `offset`.
async fn write_upload_frame(
    writer: &mut WriteHalf<Box<dyn AsyncStream>>,
    offset: usize,
    chunk: usize,
) -> io::Result<()> {
    let frame = Frame::data(1, Bytes::from(upload_bytes(offset, chunk))).encode();
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Ends stream 1 (WRITE_EOF when negotiated), then TLS close_notify and TCP FIN.
async fn raw_end(writer: &mut WriteHalf<Box<dyn AsyncStream>>, negotiated: bool) -> io::Result<()> {
    if negotiated {
        writer
            .write_all(&Frame::control(Command::WriteEof, 1).encode())
            .await?;
    }
    writer.shutdown().await
}

/// Uploads `size` bytes in `chunk`-byte frames of [`upload_bytes`] over a raw
/// client, then ends the stream as [`raw_end`] does.
async fn raw_upload(
    transport: Box<dyn AsyncStream>,
    target: SocketAddr,
    size: usize,
    negotiated: bool,
    chunk: usize,
) -> Upload<ReadHalf<Box<dyn AsyncStream>>> {
    let (reader, mut writer) = raw_open(transport, target, negotiated).await;
    let progress = Arc::new(AtomicUsize::new(0));
    let accepted = progress.clone();
    let task = tokio::spawn(async move {
        while accepted.load(SeqCst) < size {
            write_upload_frame(&mut writer, accepted.load(SeqCst), chunk).await?;
            accepted.fetch_add(chunk, SeqCst);
        }
        raw_end(&mut writer, negotiated).await
    });
    Upload {
        progress,
        task,
        reader,
    }
}

async fn raw_legacy_upload(
    transport: Box<dyn AsyncStream>,
    target: SocketAddr,
    size: usize,
) -> Upload<ReadHalf<Box<dyn AsyncStream>>> {
    raw_upload(transport, target, size, false, RAW_CHUNK).await
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

/// Probes run only while the reader is parked: an idle session must not wake
/// its peer, and a session that moves again must stop probing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_is_probed_only_while_session_is_stuck() {
    timeout(Duration::from_secs(90), async {
        let tls = tls();
        let listener = small_listener();
        let server_addr = listener.local_addr().unwrap();
        let (observed, observed_rx) = tokio::sync::oneshot::channel::<OwnedFd>();
        let grants = Arc::new(Grants::default());
        let handler = negotiated_handler(&tls, &grants);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            observed
                .send(tcp.as_fd().try_clone_to_owned().unwrap())
                .unwrap();
            process_stream(tcp, handler, Arc::new(NativeResolver))
                .await
                .unwrap();
        });
        let (target, accepted) = sink();
        let client = strict_client(&tls, server_addr).await;
        let observer = observed_rx.await.unwrap();
        let probing = || socket2::SockRef::from(&observer).keepalive().unwrap();
        let idle_before = probing();

        // Idle past the stuck threshold: no probes, and none at all on open.
        let stream = client.open_stream(location(target)).await.unwrap();
        let mut destination = accepted.await.unwrap();
        sleep(Duration::from_millis(2500)).await;
        assert_eq!(probing(), idle_before, "an idle session was probed");
        assert!(
            !idle_before,
            "this listener path sets no keepalive of its own"
        );

        // Parked: probes start, and a live peer survives them.
        let upload = upload(stream, UPLOAD);
        backpressured(&upload, UPLOAD).await;
        timeout(BOUND, async {
            while !probing() {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("a stuck session was not probed");
        sleep(Duration::from_secs(3)).await;
        assert!(!upload.task.is_finished(), "probes ended a live upload");
        assert!(!grants.done.is_cancelled(), "probes settled a live session");

        // Moving again: probes stop and the previous setting returns.
        let drain = tokio::spawn(async move {
            let mut drained = vec![0; 1 << 20];
            loop {
                match destination.read(&mut drained).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        });
        timeout(Duration::from_secs(30), upload.task)
            .await
            .expect("upload did not finish after the destination drained")
            .unwrap()
            .unwrap();
        timeout(BOUND, async {
            while probing() {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("a session that moved again kept probing");
        drop(client);
        drain.abort();
        server.abort();
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

// A peer FIN is not a transport failure. These guards hold the session's
// reader parked on a full stream queue (the destination does not read) while
// the client's close_notify and FIN wait in the server's kernel receive queue
// behind the undelivered upload, for longer than the 5 s bound. A watch that
// fired on read-closed readiness would settle these sessions as failed and
// lose data. Once the destination reads again, the session reaches the FIN
// and ends cleanly.

/// Requested server receive buffer: the FIN must fit behind the queued upload.
/// The kernel may grant less (Linux caps it at `net.core.rmem_max`); the guard
/// never relies on this figure, only on what the kernel actually queues.
const FIN_RECEIVE_BUFFER: u32 = 1024 * 1024;
const FIN_RESPONSE: usize = 4 * 1024;
/// Frame payload for the guards: small, so a legacy close drops little.
const FIN_CHUNK: usize = 2 * 1024;
/// The most a legacy session drops when it reaches the FIN and aborts its
/// stream: a full stream queue, one partly read frame, and the relay's copy
/// buffer (16 KiB in `copy_bidirectional`).
const LEGACY_LOSS_BOUND: usize = (STREAM_CHANNEL_BUFFER + 1) * FIN_CHUNK + 16 * 1024;
/// Upload left in the server's kernel behind the parked reader when the client
/// sends its FIN: more than a legacy close may drop, so discarding that
/// remainder fails the legacy bound.
const PARKED_QUEUE: usize = 2 * LEGACY_LOSS_BOUND;

/// Bytes waiting in a socket's kernel receive queue.
fn receive_queued(socket: &OwnedFd) -> usize {
    let mut queued: libc::c_int = 0;
    // SAFETY: FIONREAD stores one int through the pointer.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::FIONREAD, &mut queued) };
    assert_eq!(result, 0, "FIONREAD: {}", io::Error::last_os_error());
    queued as usize
}

/// Bytes in a socket's kernel send queue that the peer has not acknowledged.
#[cfg(target_os = "linux")]
fn send_queued(socket: &OwnedFd) -> usize {
    let mut queued: libc::c_int = 0;
    // SAFETY: TIOCOUTQ (SIOCOUTQ) stores one int through the pointer.
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::TIOCOUTQ, &mut queued) };
    assert_eq!(result, 0, "TIOCOUTQ: {}", io::Error::last_os_error());
    queued as usize
}

/// Bytes in a socket's kernel send buffer (sent but unacknowledged included).
#[cfg(target_vendor = "apple")]
fn send_queued(socket: &OwnedFd) -> usize {
    let mut queued: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SO_NWRITE stores one int; `len` holds its size.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&mut queued as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    assert_eq!(result, 0, "SO_NWRITE: {}", io::Error::last_os_error());
    queued as usize
}

/// A destination that first sends a response and its write EOF (a negotiated
/// session settles gracefully only once both directions ended), then reads
/// nothing until `resume`, then reads to EOF.
fn held_destination(respond: bool) -> (SocketAddr, CancellationToken, JoinHandle<Vec<u8>>) {
    let listener = small_listener();
    let addr = listener.local_addr().unwrap();
    let resume = CancellationToken::new();
    let resumed = resume.clone();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        if respond {
            tcp.write_all(&vec![b'R'; FIN_RESPONSE]).await.unwrap();
            tcp.shutdown().await.unwrap();
        }
        resumed.cancelled().await;
        let mut data = Vec::new();
        tcp.read_to_end(&mut data).await.unwrap();
        data
    });
    (addr, resume, task)
}

/// Uploads until the session reader is parked: frames go out until more than
/// [`PARKED_QUEUE`] bytes wait in the server's kernel and that queue stops
/// draining. The queue is read in the same run from a duplicate of the server
/// socket, so neither reported buffer sizes nor autotuning between runs
/// matter. Then ends the stream and sends close_notify and FIN, which queue
/// behind that upload. Returns the number of upload bytes.
fn parking_upload(
    mut writer: WriteHalf<Box<dyn AsyncStream>>,
    negotiated: bool,
    server_socket: Arc<OwnedFd>,
) -> JoinHandle<io::Result<usize>> {
    tokio::spawn(async move {
        let mut written = 0;
        loop {
            while receive_queued(&server_socket) <= PARKED_QUEUE {
                write_upload_frame(&mut writer, written, FIN_CHUNK).await?;
                written += FIN_CHUNK;
            }
            // The reader is parked once it stops taking from the queue.
            let queued = receive_queued(&server_socket);
            sleep(Duration::from_millis(300)).await;
            if receive_queued(&server_socket) >= queued {
                break;
            }
        }
        raw_end(&mut writer, negotiated).await?;
        Ok(written)
    })
}

struct FinCase {
    session: Arc<AnyTlsSession>,
    server: JoinHandle<io::Result<()>>,
    // Kept open until the end: the client reads nothing, and dropping a
    // socket with unread data would reset the connection.
    _reader: ReadHalf<Box<dyn AsyncStream>>,
    upload: JoinHandle<io::Result<usize>>,
    resume: CancellationToken,
    destination: JoinHandle<Vec<u8>>,
    // Duplicates of the two TCP sockets, only for reading their kernel queues.
    server_socket: Arc<OwnedFd>,
    client_socket: OwnedFd,
}

/// A hand-built session behind Shoes' transport watch, with a parking upload
/// to a held destination over a small client socket and a large server one.
async fn fin_case(negotiated: bool) -> FinCase {
    let tls = tls();
    let socket = small_socket();
    socket.set_recv_buffer_size(FIN_RECEIVE_BUFFER).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(16).unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tls.acceptor.clone();
    let (created, created_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let server_socket = tcp.as_fd().try_clone_to_owned().unwrap();
        let watch = watch(&tcp);
        let mut transport = acceptor.accept(tcp).await.unwrap();
        let mut hash = [0; 32];
        transport.read_exact(&mut hash).await.unwrap();
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
        session.enable_write_eof(negotiated);
        attach(&session, watch);
        created
            .send((session.clone(), server_socket))
            .unwrap_or_else(|_| panic!("test receiver closed"));
        session.run_until_cancelled(None).await
    });
    let (target, resume, destination) = held_destination(negotiated);
    let client = small_socket().connect(addr).await.unwrap();
    let client_socket = client.as_fd().try_clone_to_owned().unwrap();
    let transport = client_tls(&tls, client).await;
    let (reader, writer) = raw_open(transport, target, negotiated).await;
    let (session, server_socket) = created_rx.await.unwrap();
    let server_socket = Arc::new(server_socket);
    let upload = parking_upload(writer, negotiated, server_socket.clone());
    FinCase {
        session,
        server,
        _reader: reader,
        upload,
        resume,
        destination,
        server_socket,
        client_socket,
    }
}

async fn fin_under_backpressure(negotiated: bool) {
    timeout(Duration::from_secs(90), async {
        let case = fin_case(negotiated).await;
        // The upload, WRITE_EOF (negotiated), close_notify and FIN were handed
        // to the kernel behind the parked reader; the destination reads nothing.
        let size = timeout(Duration::from_secs(30), case.upload)
            .await
            .expect("client could not park the reader and send its FIN")
            .unwrap()
            .expect("client upload and close");
        let closed = Instant::now();
        sleep(BOUND + Duration::from_secs(1)).await;
        assert!(
            !case.server.is_finished() && !case.session.is_closed(),
            "a FIN behind backpressured upload settled the session"
        );
        // Everything the client sent sits in the server's kernel: the FIN is
        // behind it, and more upload is queued there than a legacy close may
        // drop, so discarding that remainder fails the bound below.
        assert_eq!(
            send_queued(&case.client_socket),
            0,
            "upload left in the client"
        );
        let behind = receive_queued(&case.server_socket);
        assert!(
            behind > LEGACY_LOSS_BOUND,
            "only {behind} bytes queued behind the parked reader"
        );
        case.resume.cancel();
        let data = timeout(Duration::from_secs(30), case.destination)
            .await
            .expect("destination did not receive the upload and EOF")
            .unwrap();
        let expected = upload_bytes(0, size);
        if negotiated {
            assert_eq!(data.len(), size, "destination upload bytes");
            assert!(data == expected, "destination upload content or order");
        } else {
            // A legacy session ends at transport EOF and aborts its stream, so
            // upload still in the stream queue or relay when the reader reaches
            // the FIN is dropped (unchanged legacy close semantics). The rest
            // arrives in order, followed by EOF.
            assert!(
                data.len() + LEGACY_LOSS_BOUND >= size,
                "legacy close dropped {} of {size} bytes, more than {LEGACY_LOSS_BOUND}",
                size - data.len().min(size)
            );
            assert!(
                data[..] == expected[..data.len()],
                "destination upload is not an in-order prefix"
            );
        }
        let result = timeout(BOUND, case.server)
            .await
            .expect("session did not end after the FIN was reached")
            .unwrap();
        assert!(result.is_ok(), "session ended with {result:?}");
        if negotiated {
            timeout(BOUND, async {
                while case.session.write_eof_resources_for_test() != (0, 8) {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("stream state and handler slots were not released");
        } else {
            timeout(BOUND, async {
                while case.session.legacy_resources_for_test().await != (0, 0) {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("legacy streams and stream tasks were not released");
        }
        eprintln!(
            "FIN under backpressure negotiated={negotiated} upload_bytes={size} queued_behind_reader={behind} delivered_bytes={} delivered_sha256={} held_ms={} result=Ok",
            data.len(),
            sha256(&data),
            closed.elapsed().as_millis()
        );
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressured_negotiated_fin_is_not_a_transport_failure() {
    fin_under_backpressure(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressured_legacy_fin_is_not_a_transport_failure() {
    fin_under_backpressure(false).await;
}
