//! Real TLS / real destination tests. The initial RED is retained in external evidence.
use super::*;
use crate::address::NetLocation;
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection};
use crate::option_util::OneOrSome;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::chain_builder::build_client_proxy_chain;
use crate::tcp::tcp_handler::TcpServerHandler;
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

struct TlsIo<S>(S);
impl<S: AsyncRead + Unpin> AsyncRead for TlsIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_read(cx,b) }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for TlsIo<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.0).poll_write(cx,b) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_shutdown(cx) }
}
impl<S: Unpin> AsyncPing for TlsIo<S> {
    fn supports_ping(&self) -> bool { false }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> { Poll::Ready(Ok(false)) }
}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream for TlsIo<S> {}

fn direct_selector() -> Arc<ClientProxySelector> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver);
    let config: ClientConfig = serde_yaml::from_str("protocol:\n  type: direct\n").unwrap();
    let chain = build_client_proxy_chain(OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))), resolver);
    Arc::new(ClientProxySelector::new(vec![ConnectRule::new(vec![crate::address::NetLocationMask::ANY], ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])))]))
}

async fn tls_pair() -> (Box<dyn AsyncStream>, Box<dyn AsyncStream>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let server = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
    let client = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let s = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(tcp).await.unwrap()
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let c = tokio_rustls::TlsConnector::from(Arc::new(client)).connect("localhost".try_into().unwrap(), tcp).await.unwrap();
    (Box::new(TlsIo(c)), Box::new(TlsIo(s.await.unwrap())))
}

async fn legacy_session() -> Arc<anytls_client_session::AnyTlsClientSession> {
    let (client, server) = tls_pair().await;
    let handler = AnyTlsServerHandler::new(vec![("public-test".into(), "write-eof-test".into())], PaddingFactory::default_factory(), Arc::new(NativeResolver), direct_selector(), false, None);
    handler.setup_server_stream(server).await.unwrap_or_else(|e| panic!("auth: {e}"));
    anytls_client_session::AnyTlsClientSession::new(client, "write-eof-test", PaddingFactory::default_factory()).await.unwrap()
}

// Start authentication concurrently: server waits for the client's real auth header.
async fn session_pair() -> Arc<anytls_client_session::AnyTlsClientSession> {
    let (client, server) = tls_pair().await;
    let handler = AnyTlsServerHandler::new(vec![("public-test".into(), "write-eof-test".into())], PaddingFactory::default_factory(), Arc::new(NativeResolver), direct_selector(), false, None);
    let server = tokio::spawn(async move { handler.setup_server_stream(server).await.unwrap(); });
    let client = anytls_client_session::AnyTlsClientSession::new(client, "write-eof-test", PaddingFactory::default_factory()).await.unwrap();
    server.await.unwrap();
    client
}

const UPLOAD: usize = 8 * 1024 * 1024;
const RESPONSE: usize = 128 * 1024;

#[tokio::test]
async fn baseline_full_close_cannot_return_delayed_response() {
    timeout(Duration::from_secs(20), async {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dest.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut data = Vec::new();
            tcp.read_to_end(&mut data).await.unwrap();
            assert_eq!(data.len(), UPLOAD);
            assert_eq!(blake3::hash(&data), blake3::hash(&vec![0x5a; UPLOAD]));
            eprintln!("destination bytes={} hash={} genuine_eof=true", data.len(), blake3::hash(&data));
            tokio::time::sleep(Duration::from_millis(150)).await;
            let result = tcp.write_all(&vec![0xa5; RESPONSE]).await;
            eprintln!("destination delayed response write={result:?}");
        });
        let session = session_pair().await;
        let mut stream = session.open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap()).await.unwrap();
        stream.write_all(&vec![0x5a; UPLOAD]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        let read = stream.read_to_end(&mut response).await;
        target.await.unwrap();
        eprintln!("client delayed response bytes={} read={read:?}", response.len());
        assert_eq!(response.len(), RESPONSE, "full FIN loses the delayed response");
    }).await.unwrap();
}

#[tokio::test]
async fn baseline_absent_shutdown_does_not_deliver_destination_eof() {
    timeout(Duration::from_secs(5), async {
    let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = dest.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (mut tcp, _) = dest.accept().await.unwrap();
        let mut data = [0; 3];
        tcp.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"abc");
        let mut byte = [0];
        let observed = timeout(Duration::from_millis(200), tcp.read(&mut byte)).await;
        eprintln!("absent shutdown destination EOF observation={observed:?}");
        assert!(matches!(observed, Ok(Ok(0))), "no shutdown is not genuine EOF");
    });
    let session = session_pair().await;
    let mut stream = session.open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap()).await.unwrap();
    stream.write_all(b"abc").await.unwrap();
    target.await.unwrap();
    }).await.unwrap();
}
