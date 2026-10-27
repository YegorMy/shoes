//! Bounded, loopback-only development fixture, not a proxy deployment CLI.
use aws_lc_rs::digest::{SHA256, digest};
use shoes::async_stream::{AsyncPing, AsyncStream};
use shoes::client_proxy_chain::ClientChainGroup;
use shoes::config::{ClientChainHop, ClientConfig, ConfigSelection};
use shoes::embedding::{
    self, AnyTlsClientSession, OutboundDecision, PaddingFactory, ServerHooks, SessionAuth,
    SessionGrant, TransportWatch, WriteEofClientSession, WriteEofOptions,
};
use shoes::resolver::{NativeResolver, Resolver};
use shoes::tcp::{chain_builder::build_client_proxy_chain, tcp_handler::TcpServerHandler};
use shoes::{NetLocation, OneOrSome};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "write-eof-public-test-only";
const MAX_FILE: usize = 16 * 1024 * 1024;

struct TlsIo<S>(S);
impl<S: AsyncRead + Unpin> AsyncRead for TlsIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, b)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for TlsIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl<S: Unpin> AsyncPing for TlsIo<S> {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream for TlsIo<S> {}

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn addr(text: &str) -> io::Result<SocketAddr> {
    let addr: SocketAddr = text
        .parse()
        .map_err(|_| failure("invalid fixture address"))?;
    if !addr.ip().is_loopback() {
        return Err(failure("fixtures require loopback addresses"));
    }
    Ok(addr)
}
fn file(path: &str) -> io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    if f.metadata()?.len() > MAX_FILE as u64 {
        return Err(failure("fixture file too large"));
    }
    let mut data = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(f, (MAX_FILE + 1) as u64),
        &mut data,
    )?;
    if data.len() > MAX_FILE {
        return Err(failure("fixture file too large"));
    }
    Ok(data)
}
fn hash(data: &[u8]) -> String {
    digest(&SHA256, data)
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}
fn mode(text: &str) -> io::Result<bool> {
    match text {
        "enabled" | "strict" => Ok(true),
        "legacy" => Ok(false),
        _ => Err(failure("invalid mode")),
    }
}

fn test_password(arg: Option<&String>) -> io::Result<&str> {
    let value = arg.map(String::as_str).unwrap_or(PASSWORD);
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(failure("invalid public test password"));
    }
    Ok(value)
}

#[derive(Debug)]
struct Hooks {
    password_hash: [u8; 32],
    target: SocketAddr,
    done: CancellationToken,
    cancel: CancellationToken,
}
impl ServerHooks for Hooks {
    fn open_session(&self, auth: SessionAuth<'_>) -> Option<SessionGrant> {
        match auth {
            SessionAuth::AnyTls {
                password_sha256, ..
            } if password_sha256 == &self.password_hash => Some(SessionGrant::with_done(
                "public-test",
                self.cancel.clone(),
                self.done.clone(),
            )),
            _ => None,
        }
    }
    fn check_outbound(&self, _: &NetLocation, resolved: SocketAddr) -> OutboundDecision {
        if resolved == self.target {
            OutboundDecision::Allow
        } else {
            OutboundDecision::Block
        }
    }
}

async fn server(a: &[String]) -> io::Result<()> {
    let listen = addr(&a[0])?;
    let certs =
        rustls_pemfile::certs(&mut file(&a[1])?.as_slice()).collect::<Result<Vec<_>, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut file(&a[2])?.as_slice())?.ok_or(failure("missing key"))?;
    let enabled = mode(&a[3])?;
    let target = addr(&a[4])?;
    let mut password_hash = [0; 32];
    password_hash.copy_from_slice(digest(&SHA256, test_password(a.get(5))?.as_bytes()).as_ref());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let config: ClientConfig =
        serde_yaml::from_str("protocol:\n  type: direct\n").map_err(io::Error::other)?;
    let chain = build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
        resolver.clone(),
    );
    let done = CancellationToken::new();
    let cancel = CancellationToken::new();
    let handler = embedding::anytls_server_handler(
        vec![],
        PaddingFactory::default_factory(),
        resolver,
        ClientChainGroup::new(vec![chain]),
        Some(Arc::new(Hooks {
            password_hash,
            target,
            done: done.clone(),
            cancel: cancel.clone(),
        })),
        enabled,
    );
    let listener = TcpListener::bind(listen).await?;
    println!(
        "READY server={} write_eof_enabled={enabled}",
        listener.local_addr()?
    );
    let (tcp, _) = listener.accept().await?;
    // This fixture terminates TCP and TLS itself, so it supplies the socket's
    // failure signal: a reset settles the session even while it is backpressured.
    let watch = TransportWatch::tcp(&tcp).ok();
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
        .accept(tcp)
        .await?;
    TransportWatch::scope(watch, handler.setup_server_stream(Box::new(TlsIo(tls)))).await?;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(50), done.cancelled()).await;
    cancel.cancel();
    result.map_err(|_| failure("fixture session did not settle"))?;
    println!(
        "session_settled=true session_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}

async fn client(a: &[String]) -> io::Result<()> {
    let server = addr(&a[0])?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut file(&a[1])?.as_slice()) {
        roots.add(cert?).map_err(io::Error::other)?;
    }
    let target = addr(&a[2])?;
    let legacy_bytes = a[3] == "legacy-bytes";
    let strict_bytes = a[3] == "strict-bytes";
    let strict_first = a[3] == "strict-first";
    let strict = if legacy_bytes {
        false
    } else if strict_bytes || strict_first {
        true
    } else {
        mode(&a[3])?
    };
    let upload = file(&a[4])?;
    let expected = file(&a[5])?;
    let password = test_password(a.get(6))?;
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(server).await?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect("localhost".try_into().unwrap(), tcp)
        .await?;
    let transport: Box<dyn AsyncStream> = Box::new(TlsIo(tls));
    let destination = NetLocation::from_str(&target.to_string(), None)?;
    let mut stream: Box<dyn AsyncStream> = if strict {
        let session = WriteEofClientSession::connect(
            transport,
            password,
            PaddingFactory::default_factory(),
            WriteEofOptions::default(),
        )
        .await?;
        println!("negotiated=write-eof/1");
        Box::new(session.open_stream(destination).await?)
    } else {
        let session =
            AnyTlsClientSession::new(transport, password, PaddingFactory::default_factory())
                .await?;
        println!("negotiated=legacy");
        Box::new(session.open_stream(destination).await?)
    };
    if strict_first {
        validate_response(&mut *stream, &expected).await?;
        println!("remote_eof_before_upload=true");
    }
    stream.write_all(&upload).await?;
    if strict_bytes {
        stream.flush().await?;
        println!(
            "strict_no_shutdown=true request_eof=false upload_bytes={} upload_sha256={}",
            upload.len(),
            hash(&upload)
        );
    } else if legacy_bytes {
        stream.flush().await?;
        println!(
            "legacy_no_shutdown=true upload_bytes={} upload_sha256={}",
            upload.len(),
            hash(&upload)
        );
    } else {
        stream.shutdown().await?;
        stream.shutdown().await?;
        println!(
            "upload_bytes={} upload_sha256={} shutdown_ack=true",
            upload.len(),
            hash(&upload)
        );
    }
    if !strict_first {
        validate_response(&mut *stream, &expected).await?;
    }
    Ok(())
}

async fn validate_response(stream: &mut dyn AsyncStream, expected: &[u8]) -> io::Result<()> {
    let mut response = Vec::new();
    stream
        .take((expected.len() + 1) as u64)
        .read_to_end(&mut response)
        .await?;
    if response != expected {
        return Err(failure("response count/hash mismatch"));
    }
    println!(
        "response_bytes={} response_sha256={} genuine_eof=true",
        response.len(),
        hash(&response)
    );
    Ok(())
}

async fn target(a: &[String], first: bool, length_delimited: bool) -> io::Result<()> {
    let listen = addr(&a[0])?;
    let expected = file(&a[1])?;
    let response = file(&a[2])?;
    let delay: u64 = a[3].parse().map_err(|_| failure("invalid delay"))?;
    if delay > 10_000 {
        return Err(failure("delay exceeds fixture bound"));
    }
    let listener = TcpListener::bind(listen).await?;
    println!("READY destination={}", listener.local_addr()?);
    let (mut tcp, _) = listener.accept().await?;
    if first {
        tcp.write_all(&response).await?;
        tcp.shutdown().await?;
        println!("remote_eof_first=true");
    }
    let mut upload = Vec::new();
    if length_delimited {
        upload.resize(expected.len(), 0);
        tcp.read_exact(&mut upload).await?;
    } else {
        (&mut tcp)
            .take((expected.len() + 1) as u64)
            .read_to_end(&mut upload)
            .await?;
    }
    if upload != expected {
        return Err(failure("destination upload count/hash mismatch"));
    }
    println!(
        "destination_bytes={} destination_sha256={} genuine_eof={}",
        upload.len(),
        hash(&upload),
        !length_delimited,
    );
    if !first {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        tcp.write_all(&response).await?;
        tcp.shutdown().await?;
    }
    println!(
        "delayed_response_bytes={} delayed_response_sha256={}",
        response.len(),
        hash(&response)
    );
    Ok(())
}

fn generate(dir: &str) -> io::Result<()> {
    let dir = std::path::Path::new(dir);
    std::fs::create_dir_all(dir)?;
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
    std::fs::write(dir.join("cert.pem"), cert.cert.pem())?;
    std::fs::write(dir.join("key.pem"), cert.signing_key.serialize_pem())?;
    std::fs::write(
        dir.join("upload.bin"),
        (0..8 * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>(),
    )?;
    std::fs::write(
        dir.join("response.bin"),
        (0..128 * 1024)
            .map(|i| 255 - (i % 251) as u8)
            .collect::<Vec<_>>(),
    )?;
    println!("generated public TLS identity and deterministic 8MiB/128KiB fixture files");
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> io::Result<()> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_secs(60), async {
        match a.first().map(String::as_str) {
            Some("generate") if a.len()==2 => generate(&a[1]),
            Some("server") if a.len()==6 || a.len()==7 => server(&a[1..]).await,
            Some("client") if a.len()==7 || a.len()==8 => client(&a[1..]).await,
            Some("target") if a.len()==5 => target(&a[1..],false,false).await,
            Some("target-first") if a.len()==5 => target(&a[1..],true,false).await,
            Some("target-length") if a.len()==5 => target(&a[1..],false,true).await,
            _ => Err(failure("usage: generate DIR | server LISTEN CERT KEY enabled|legacy TARGET [PUBLIC_TEST_PASSWORD] | client SERVER CA TARGET strict|strict-bytes|strict-first|legacy|legacy-bytes UPLOAD EXPECTED [PUBLIC_TEST_PASSWORD] | target[-first|-length] LISTEN UPLOAD RESPONSE DELAY_MS")),
        }
    }).await.map_err(|_| failure("fixture exceeded 60 second bound"))?
}
