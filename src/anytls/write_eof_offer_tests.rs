//! Unsupported write-eof offers on an enabled server, over real TLS, the real
//! AnyTLS handler and a real destination listener.
use super::anytls_types::{Command, Frame};
use super::*;
use crate::address::{NetLocation, NetLocationMask};
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection};
use crate::option_util::OneOrSome;
use crate::resolver::{NativeResolver, Resolver};
use crate::socks_handler::write_location_to_vec;
use crate::tcp::chain_builder::build_client_proxy_chain;
use crate::tcp::tcp_handler::TcpServerHandler;
use bytes::{Bytes, BytesMut};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
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
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// The contract's settlement bound.
pub(super) const BOUND: Duration = Duration::from_secs(5);
pub(super) const PASSWORD: &str = "public-write-eof-test";

pub(super) struct Io<S>(pub(super) S);
impl<S: AsyncRead + Unpin> AsyncRead for Io<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, b)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Io<S> {
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
impl<S: Unpin> AsyncPing for Io<S> {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncStream for Io<S> {}

pub(super) struct Tls {
    pub(super) acceptor: TlsAcceptor,
    pub(super) connector: TlsConnector,
}

pub(super) fn tls_from(cert: CertificateDer<'static>, key: PrivatePkcs8KeyDer<'static>) -> Tls {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Tls {
        acceptor: TlsAcceptor::from(Arc::new(server)),
        connector: TlsConnector::from(Arc::new(client)),
    }
}

pub(super) fn tls() -> Tls {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    tls_from(
        cert.cert.der().clone(),
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    )
}

pub(super) async fn client_tls(tls: &Tls, tcp: TcpStream) -> Box<dyn AsyncStream> {
    let stream = tls
        .connector
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    Box::new(Io(stream))
}

pub(super) fn location(addr: SocketAddr) -> NetLocation {
    NetLocation::from_str(&addr.to_string(), None).unwrap()
}

pub(super) fn direct_group() -> ClientChainGroup {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver);
    let config: ClientConfig = serde_yaml::from_str("protocol:\n  type: direct\n").unwrap();
    ClientChainGroup::new(vec![build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
        resolver,
    )])
}

pub(super) fn direct_selector() -> Arc<ClientProxySelector> {
    Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![NetLocationMask::ANY],
        ConnectAction::new_allow(None, direct_group()),
    )]))
}

/// Writes one Settings offer with a SYN and destination PSH coalesced behind it.
async fn offer(enabled: bool, settings: &'static [u8]) -> (Box<dyn AsyncStream>, TcpListener) {
    let tls = tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tls.acceptor.clone();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let transport = acceptor.accept(tcp).await.unwrap();
        AnyTlsServerHandler::new(
            vec![("public-test".into(), PASSWORD.into())],
            PaddingFactory::default_factory(),
            Arc::new(NativeResolver),
            direct_selector(),
            false,
            None,
        )
        .with_write_eof(enabled)
        .setup_server_stream(Box::new(Io(transport)))
        .await
        .unwrap();
    });
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut transport = client_tls(&tls, TcpStream::connect(addr).await.unwrap()).await;
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
    let mut wire = BytesMut::new();
    Frame::with_data(Command::Settings, 0, Bytes::from_static(settings)).encode_into(&mut wire);
    Frame::control(Command::Syn, 1).encode_into(&mut wire);
    let mut request = write_location_to_vec(&location(destination.local_addr().unwrap()));
    request.extend_from_slice(b"legacy-payload");
    Frame::with_data(Command::Psh, 1, Bytes::from(request)).encode_into(&mut wire);
    transport.write_all(&wire).await.unwrap();
    transport.flush().await.unwrap();
    (transport, destination)
}

const UNSUPPORTED_OFFERS: [&[u8]; 8] = [
    b"v=2\nx-write-eof=2",
    b"v=2\nx-write-eof=0",
    b"v=2\nx-write-eof=",
    b"v=2\nx-write-eof=01",
    b"v=2\nx-write-eof=1 ",
    b"x-write-eof=1",
    b"v=1\nx-write-eof=1",
    b"v=3\nx-write-eof=1",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabled_server_closes_unsupported_offers() {
    let mut failures = Vec::new();
    for settings in UNSUPPORTED_OFFERS {
        let case = String::from_utf8_lossy(settings).replace('\n', "\\n");
        let (mut transport, destination) = offer(true, settings).await;
        let mut received = Vec::new();
        let closed = timeout(BOUND, async {
            let mut buf = [0; 4096];
            loop {
                match transport.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }
        })
        .await
        .is_ok();
        // Nothing precedes the failure: no settings reply, so no agreement.
        let replied = !received.is_empty();
        let connected = timeout(Duration::from_millis(200), destination.accept())
            .await
            .is_ok();
        eprintln!(
            "unsupported offer {case}: transport_closed={closed} replied={replied} destination={connected}"
        );
        if !closed || replied || connected {
            failures.push(case);
        }
    }
    assert!(
        failures.is_empty(),
        "enabled server did not fail closed for offers {failures:?}"
    );
}

/// Legacy behaviour: the stream reaches its destination and nothing agrees.
async fn assert_legacy(enabled: bool, settings: &'static [u8]) {
    let case = String::from_utf8_lossy(settings).replace('\n', "\\n");
    let (mut transport, destination) = offer(enabled, settings).await;
    let (mut tcp, _) = timeout(BOUND, destination.accept())
        .await
        .unwrap_or_else(|_| panic!("legacy offer {case} never reached its destination"))
        .unwrap();
    let mut payload = [0; 14];
    tcp.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"legacy-payload");
    let mut received = Vec::new();
    let mut buf = [0; 4096];
    while let Ok(Ok(n)) = timeout(Duration::from_millis(200), transport.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert!(
        !received.windows(11).any(|w| w == b"x-write-eof"),
        "offer {case} was agreed by a server with enabled={enabled}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_server_keeps_stock_behaviour_for_any_offer() {
    for settings in UNSUPPORTED_OFFERS
        .into_iter()
        .chain([b"v=2\nx-write-eof=1".as_slice()])
    {
        assert_legacy(false, settings).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabled_server_without_offer_stays_legacy() {
    for settings in [b"v=2".as_slice(), b"v=2\nX-Write-Eof=1"] {
        assert_legacy(true, settings).await;
    }
}
