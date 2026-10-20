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
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

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

fn direct_selector() -> Arc<ClientProxySelector> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver);
    let config: ClientConfig = serde_yaml::from_str("protocol:\n  type: direct\n").unwrap();
    let chain = build_client_proxy_chain(
        OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
        resolver,
    );
    Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![crate::address::NetLocationMask::ANY],
        ConnectAction::new_allow(None, ClientChainGroup::new(vec![chain])),
    )]))
}

async fn tls_pair() -> (Box<dyn AsyncStream>, Box<dyn AsyncStream>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let s = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(server))
            .accept(tcp)
            .await
            .unwrap()
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let c = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    (Box::new(TlsIo(c)), Box::new(TlsIo(s.await.unwrap())))
}

// Start authentication concurrently: server waits for the client's real auth header.
async fn session_pair() -> Arc<anytls_client_session::AnyTlsClientSession> {
    let (client, server) = tls_pair().await;
    let handler = AnyTlsServerHandler::new(
        vec![("public-test".into(), "write-eof-test".into())],
        PaddingFactory::default_factory(),
        Arc::new(NativeResolver),
        direct_selector(),
        false,
        None,
    );
    let server = tokio::spawn(async move {
        handler.setup_server_stream(server).await.unwrap();
    });
    let client = anytls_client_session::AnyTlsClientSession::new(
        client,
        "write-eof-test",
        PaddingFactory::default_factory(),
    )
    .await
    .unwrap();
    server.await.unwrap();
    client
}

const UPLOAD: usize = 8 * 1024 * 1024;
const RESPONSE: usize = 128 * 1024;

#[tokio::test]
async fn legacy_full_close_loses_delayed_response_control() {
    timeout(Duration::from_secs(20), async {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dest.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut data = Vec::new();
            tcp.read_to_end(&mut data).await.unwrap();
            assert_eq!(data.len(), UPLOAD);
            assert_eq!(blake3::hash(&data), blake3::hash(&vec![0x5a; UPLOAD]));
            eprintln!(
                "destination bytes={} hash={} genuine_eof=true",
                data.len(),
                blake3::hash(&data)
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
            let result = tcp.write_all(&vec![0xa5; RESPONSE]).await;
            eprintln!("destination delayed response write={result:?}");
        });
        let session = session_pair().await;
        let mut stream = session
            .open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap())
            .await
            .unwrap();
        stream.write_all(&vec![0x5a; UPLOAD]).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        let read = stream.read_to_end(&mut response).await;
        target.await.unwrap();
        eprintln!(
            "client delayed response bytes={} read={read:?}",
            response.len()
        );
        assert_eq!(response.len(), 0, "legacy is not directional-EOF capable");
        assert!(read.is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn absent_shutdown_does_not_deliver_destination_eof_control() {
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
            assert!(observed.is_err(), "no shutdown is not genuine EOF");
        });
        let session = session_pair().await;
        let mut stream = session
            .open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap())
            .await
            .unwrap();
        stream.write_all(b"abc").await.unwrap();
        target.await.unwrap();
    })
    .await
    .unwrap();
}

async fn enabled_transport(enabled: bool) -> Box<dyn AsyncStream> {
    let (client, server) = tls_pair().await;
    let handler = AnyTlsServerHandler::new(
        vec![("public-test".into(), "write-eof-test".into())],
        PaddingFactory::default_factory(),
        Arc::new(NativeResolver),
        direct_selector(),
        false,
        None,
    )
    .with_write_eof(enabled);
    tokio::spawn(async move {
        handler.setup_server_stream(server).await.unwrap();
    });
    client
}

async fn strict_session(options: WriteEofOptions) -> Arc<WriteEofClientSession> {
    WriteEofClientSession::connect(
        enabled_transport(true).await,
        "write-eof-test",
        PaddingFactory::default_factory(),
        options,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn negotiated_real_tls_8mib_eof_delayed_response() {
    timeout(Duration::from_secs(20), async {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dest.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut data = Vec::new();
            tcp.read_to_end(&mut data).await.unwrap();
            assert_eq!(data.len(), UPLOAD);
            assert_eq!(blake3::hash(&data), blake3::hash(&vec![0x5a; UPLOAD]));
            eprintln!(
                "negotiated destination bytes={} hash={} genuine_eof=true",
                data.len(),
                blake3::hash(&data)
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
            tcp.write_all(&vec![0xa5; RESPONSE]).await.unwrap();
            tcp.shutdown().await.unwrap();
        });
        // Exercise the real opt-in TcpClientHandler, not just a local reader wrapper.
        use crate::tcp::tcp_handler::TcpClientHandler;
        let client = AnyTlsClientHandler::new(
            "write-eof-test".into(),
            PaddingFactory::default_factory(),
            false,
        )
        .require_write_eof(WriteEofOptions::default());
        let mut stream = client
            .setup_client_tcp_stream(
                enabled_transport(true).await,
                NetLocation::from_str(&addr.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap()
            .client_stream;
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        stream.write_all(&vec![0x5a; UPLOAD]).await.unwrap();
        stream.shutdown().await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(
            stream.write(b"late").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, vec![0xa5; RESPONSE]);
        target.await.unwrap();
        eprintln!(
            "write-eof/1 upload={} delayed_response={} duplicate_shutdown=true",
            UPLOAD,
            response.len()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn negotiated_remote_eof_first_keeps_upload_live() {
    timeout(Duration::from_secs(20), async {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dest.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut upload = vec![0; 4096];
            tcp.read_exact(&mut upload).await.unwrap();
            tcp.write_all(&vec![0xa5; RESPONSE]).await.unwrap();
            tcp.shutdown().await.unwrap();
            tcp.read_to_end(&mut upload).await.unwrap();
            assert_eq!(upload, vec![0x5a; UPLOAD]);
            eprintln!(
                "remote EOF first: destination upload={} genuine_eof=true",
                upload.len()
            );
        });
        let session = strict_session(WriteEofOptions::default()).await;
        let mut stream = session
            .open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap())
            .await
            .unwrap();
        stream.write_all(&vec![0x5a; 4096]).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, vec![0xa5; RESPONSE]);
        // Remote read EOF has happened, and most of the upload has NOT been written.
        stream.write_all(&vec![0x5a; UPLOAD - 4096]).await.unwrap();
        stream.shutdown().await.unwrap();
        target.await.unwrap();
        assert_eq!(session.registered_streams(), 0);
        session.close().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn negotiated_multiplex_no_fin_request_reply_and_slow_live_io() {
    timeout(Duration::from_secs(10), async {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dest.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let mut jobs = Vec::new();
            for _ in 0..2 {
                let (mut tcp, _) = dest.accept().await.unwrap();
                jobs.push(tokio::spawn(async move {
                    for _ in 0..3 {
                        let mut b = [0; 3];
                        tcp.read_exact(&mut b).await.unwrap();
                        tcp.write_all(&b).await.unwrap();
                    }
                    let mut rest = Vec::new();
                    tcp.read_to_end(&mut rest).await.unwrap();
                    assert!(rest.is_empty());
                    tcp.shutdown().await.unwrap();
                }));
            }
            for job in jobs {
                job.await.unwrap();
            }
        });
        let session = strict_session(WriteEofOptions {
            eof_timeout: Duration::from_millis(60),
            ..Default::default()
        })
        .await;
        let location = NetLocation::from_str(&addr.to_string(), None).unwrap();
        let (a, b) = tokio::join!(
            session.open_stream(location.clone()),
            session.open_stream(location)
        );
        let run = |mut stream: AnyTlsStream, slow: bool| async move {
            for _ in 0..3 {
                stream.write_all(b"abc").await.unwrap();
                stream.flush().await.unwrap();
                let mut reply = [0; 3];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"abc");
                if slow {
                    tokio::time::sleep(Duration::from_millis(75)).await;
                }
            }
            stream.shutdown().await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        };
        // One stream retires while the other continues live IO past its EOF bound.
        tokio::join!(run(a.unwrap(), false), run(b.unwrap(), true));
        target.await.unwrap();
        assert_eq!(session.registered_streams(), 0);
        session.close().await.unwrap();
        eprintln!(
            "multiplex=2 no-FIN request/reply=true live_duration>EOF_control_bound=true retired=0"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn strict_to_disabled_server_is_typed_unsupported() {
    let result = WriteEofClientSession::connect(
        enabled_transport(false).await,
        "write-eof-test",
        PaddingFactory::default_factory(),
        WriteEofOptions::default(),
    )
    .await;
    let e = result.err().expect("strict must not downgrade");
    assert_eq!(
        e.get_ref().unwrap().downcast_ref::<WriteEofError>(),
        Some(&WriteEofError::Unsupported)
    );
}

async fn test_read_frame(io: &mut Box<dyn AsyncStream>) -> super::anytls_types::Frame {
    use super::anytls_types::*;
    let mut header = [0; 7];
    io.read_exact(&mut header).await.unwrap();
    let (cmd, id, len) = Frame::decode_header(&header).unwrap();
    let mut data = vec![0; len as usize];
    io.read_exact(&mut data).await.unwrap();
    Frame::with_data(cmd, id, bytes::Bytes::from(data))
}

async fn raw_negotiation_peer(mut io: Box<dyn AsyncStream>, response: Option<Vec<u8>>) {
    use super::anytls_types::*;
    let mut hash = [0; 32];
    io.read_exact(&mut hash).await.unwrap();
    assert_eq!(
        &hash[..],
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"write-eof-test").as_ref()
    );
    let len = io.read_u16().await.unwrap();
    let mut padding = vec![0; len as usize];
    io.read_exact(&mut padding).await.unwrap();
    let settings = test_read_frame(&mut io).await;
    assert_eq!(settings.cmd, Command::Settings);
    let offer = StringMap::negotiation(&settings.data).unwrap();
    assert_eq!(offer.get("v").unwrap(), "2");
    assert_eq!(offer.get("x-write-eof").unwrap(), "1");
    assert!(offer.get("client").is_some());
    assert!(offer.get("padding-md5").is_some());
    if let Some(response) = response {
        let frame = Frame::with_data(Command::ServerSettings, 0, bytes::Bytes::from(response));
        io.write_all(&frame.encode()).await.unwrap();
        io.flush().await.unwrap();
    }
    // Only padding is allowed before the failed negotiation closes the transport.
    loop {
        let mut header = [0; 7];
        match timeout(Duration::from_secs(1), io.read_exact(&mut header)).await {
            Ok(Ok(_)) => {
                let (cmd, _, len) = Frame::decode_header(&header).unwrap();
                assert_eq!(cmd, Command::Waste, "SYN/payload before agreement");
                let mut data = vec![0; len as usize];
                io.read_exact(&mut data).await.unwrap();
            }
            Ok(Err(_)) => break,
            Err(_) => panic!("failed negotiation did not settle transport"),
        }
    }
}

#[tokio::test]
async fn negotiation_negative_versions_duplicates_utf8_timeout_and_cancellation() {
    for (response, expected) in [
        (Some(b"v=2".to_vec()), WriteEofError::Unsupported),
        (
            Some(b"v=2\nx-write-eof=0".to_vec()),
            WriteEofError::Unsupported,
        ),
        (
            Some(b"v=2\nx-write-eof=2".to_vec()),
            WriteEofError::Unsupported,
        ),
        (
            Some(b"v=3\nx-write-eof=1".to_vec()),
            WriteEofError::Unsupported,
        ),
        (
            Some(b"v=2\nx-write-eof=1\nx-write-eof=1".to_vec()),
            WriteEofError::Negotiation,
        ),
        (
            Some(b"v=2\nx-write-eof=0\nx-write-eof=1".to_vec()),
            WriteEofError::Negotiation,
        ),
        (
            Some(b"v=2\nx-write-eof=1\ninvalid=\xff".to_vec()),
            WriteEofError::Negotiation,
        ),
        (None, WriteEofError::Timeout),
    ] {
        let (client, server) = tls_pair().await;
        let task = tokio::spawn(raw_negotiation_peer(server, response));
        let result = WriteEofClientSession::connect(
            client,
            "write-eof-test",
            PaddingFactory::default_factory(),
            WriteEofOptions {
                negotiation_timeout: Duration::from_millis(100),
                ..Default::default()
            },
        )
        .await;
        let e = result.err().expect("must reject negotiation");
        assert_eq!(
            e.get_ref().unwrap().downcast_ref::<WriteEofError>(),
            Some(&expected)
        );
        task.await.unwrap();
    }
    let (client, server) = tls_pair().await;
    let task = tokio::spawn(raw_negotiation_peer(server, None));
    assert!(
        timeout(
            Duration::from_millis(30),
            WriteEofClientSession::connect(
                client,
                "write-eof-test",
                PaddingFactory::default_factory(),
                WriteEofOptions::default()
            )
        )
        .await
        .is_err()
    );
    task.await.unwrap();
}

#[tokio::test]
async fn negotiated_session_close_settles_real_destination_and_pending_read() {
    timeout(Duration::from_secs(5), async {
        let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dest.local_addr().unwrap();
        let (ready, rx) = tokio::sync::oneshot::channel();
        let target = tokio::spawn(async move {
            let (mut tcp, _) = dest.accept().await.unwrap();
            let mut b = [0; 3];
            tcp.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"abc");
            ready.send(()).unwrap();
            assert_eq!(tcp.read(&mut [0; 1]).await.unwrap(), 0);
        });
        let session = strict_session(WriteEofOptions::default()).await;
        let mut stream = session
            .open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap())
            .await
            .unwrap();
        stream.write_all(b"abc").await.unwrap();
        stream.flush().await.unwrap();
        rx.await.unwrap();
        let read = tokio::spawn(async move { stream.read(&mut [0; 1]).await });
        session.close().await.unwrap();
        assert!(
            timeout(Duration::from_millis(500), read)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        timeout(Duration::from_secs(1), target)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.registered_streams(), 0);
        eprintln!("full session cancellation: pending read failed, destination socket settled");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn negotiated_padding_update_is_retained_for_subsequent_sessions() {
    // Real server emits its ordinary UpdatePaddingScheme before agreement.
    let (client, server) = tls_pair().await;
    let handler = AnyTlsServerHandler::new(
        vec![("public-test".into(), "write-eof-test".into())],
        Arc::new(PaddingFactory::new(b"stop=3\n0=30-30\n1=100-100\n2=100-100").unwrap()),
        Arc::new(NativeResolver),
        direct_selector(),
        false,
        None,
    )
    .with_write_eof(true);
    let task = tokio::spawn(async move {
        handler.setup_server_stream(server).await.unwrap();
    });
    let session = WriteEofClientSession::connect(
        client,
        "write-eof-test",
        PaddingFactory::default_factory(),
        WriteEofOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        session.padding_for_next_session().raw_scheme(),
        b"stop=3\n0=30-30\n1=100-100\n2=100-100"
    );
    session.close().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn client_conflicting_post_agreement_settings_closes_session() {
    use super::anytls_types::*;
    let (client, mut server) = tls_pair().await;
    let (send, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut auth = [0; 32];
        server.read_exact(&mut auth).await.unwrap();
        let len = server.read_u16().await.unwrap();
        server.read_exact(&mut vec![0; len as usize]).await.unwrap();
        assert_eq!(test_read_frame(&mut server).await.cmd, Command::Settings);
        server
            .write_all(
                &Frame::with_data(
                    Command::ServerSettings,
                    0,
                    bytes::Bytes::from_static(b"v=2\nx-write-eof=1"),
                )
                .encode(),
            )
            .await
            .unwrap();
        server.flush().await.unwrap();
        rx.await.unwrap();
        server
            .write_all(
                &Frame::with_data(
                    Command::ServerSettings,
                    0,
                    bytes::Bytes::from_static(b"v=2\nx-write-eof=0"),
                )
                .encode(),
            )
            .await
            .unwrap();
        server.flush().await.unwrap();
        // Reader drains harmless initial WASTE and then must see full transport closure.
        loop {
            let mut header = [0; 7];
            match timeout(Duration::from_secs(1), server.read_exact(&mut header)).await {
                Ok(Ok(_)) => {
                    let (cmd, _, len) = Frame::decode_header(&header).unwrap();
                    assert_eq!(cmd, Command::Waste);
                    server.read_exact(&mut vec![0; len as usize]).await.unwrap();
                }
                Ok(Err(_)) => break,
                Err(_) => panic!("conflicting settings failed to close session"),
            }
        }
    });
    let session = WriteEofClientSession::connect(
        client,
        "write-eof-test",
        PaddingFactory::default_factory(),
        WriteEofOptions::default(),
    )
    .await
    .unwrap();
    send.send(()).unwrap();
    task.await.unwrap();
    assert!(
        session
            .open_stream(NetLocation::from_str("127.0.0.1:1", None).unwrap())
            .await
            .is_err()
    );
    session.close().await.unwrap();
}

#[tokio::test]
async fn malformed_negotiated_eof_fails_real_tls_session_and_owned_read() {
    use super::anytls_types::*;
    for payload in [None, Some(bytes::Bytes::from_static(b"invalid"))] {
        timeout(Duration::from_secs(3), async {
            let dest = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = dest.local_addr().unwrap();
            let target = tokio::spawn(async move {
                let (mut tcp, _) = dest.accept().await.unwrap();
                let _ = tcp.read(&mut [0; 1]).await;
            });
            let session = strict_session(WriteEofOptions::default()).await;
            let mut stream = session
                .open_stream(NetLocation::from_str(&addr.to_string(), None).unwrap())
                .await
                .unwrap();
            let frame = if let Some(data) = payload {
                Frame::with_data(Command::WriteEof, stream.id(), data)
            } else {
                Frame::control(Command::WriteEof, 0)
            };
            session.inject_frame_for_test(frame).await.unwrap();
            assert!(
                stream.read(&mut [0; 1]).await.is_err(),
                "malformed EOF is not successful read EOF"
            );
            assert!(stream.shutdown().await.is_err());
            session.close().await.unwrap();
            target.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn unnegotiated_eof_fails_real_authenticated_tls_session() {
    use super::anytls_types::*;
    timeout(Duration::from_secs(3), async {
        let mut transport = enabled_transport(false).await;
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"write-eof-test");
        let mut password = [0; 32];
        password.copy_from_slice(hash.as_ref());
        AnyTlsClientSession::send_auth(
            &mut transport,
            &password,
            &PaddingFactory::default_factory(),
        )
        .await
        .unwrap();
        let settings = Frame::with_data(
            Command::Settings,
            0,
            bytes::Bytes::from_static(b"v=2\nclient=public-test\npadding-md5=not-current"),
        );
        transport.write_all(&settings.encode()).await.unwrap();
        transport
            .write_all(&Frame::control(Command::WriteEof, 1).encode())
            .await
            .unwrap();
        transport.flush().await.unwrap();
        let mut data = Vec::new();
        let _ = transport.read_to_end(&mut data).await;
        let mut data = bytes::BytesMut::from(data.as_slice());
        while let Some(frame) = FrameCodec::decode(&mut data).unwrap() {
            assert_ne!(frame.cmd, Command::WriteEof);
        }
    })
    .await
    .unwrap();
}
