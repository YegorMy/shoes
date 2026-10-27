//! Fixtures for the empty-datagram reply tests: real UDP destinations, Shoes
//! servers built from YAML config the way the TCP listener startup builds
//! them, and the UoT v2 record layouts.
use crate::config::{Config, ConfigSelection, create_server_configs};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server::process_stream;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// What a scripted destination sends back: a reply, an empty reply, a reply.
pub(crate) const SCRIPTED_REPLIES: [&[u8]; 3] = [b"before-empty", b"", b"after-empty"];

/// A real UDP destination that records the length of every datagram it gets.
pub(crate) struct Destination {
    pub(crate) target: SocketAddrV4,
    seen: Arc<Mutex<Vec<usize>>>,
    task: JoinHandle<()>,
}

impl Destination {
    /// Echoes every datagram to its sender.
    pub(crate) async fn echo() -> Self {
        Self::spawn(None).await
    }

    /// Answers nothing until `go` fires after the first datagram, then sends
    /// [`SCRIPTED_REPLIES`] to that datagram's sender.
    pub(crate) async fn scripted(go: oneshot::Receiver<()>) -> Self {
        Self::spawn(Some(go)).await
    }

    async fn spawn(script: Option<oneshot::Receiver<()>>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(target) = socket.local_addr().unwrap() else {
            unreachable!()
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let counted = seen.clone();
        let task = tokio::spawn(async move {
            let mut script = script;
            let echo = script.is_none();
            let mut buf = vec![0; 65535];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                counted.lock().unwrap().push(n);
                if echo {
                    socket.send_to(&buf[..n], peer).await.unwrap();
                } else if let Some(go) = script.take() {
                    go.await.unwrap();
                    for reply in SCRIPTED_REPLIES {
                        socket.send_to(reply, peer).await.unwrap();
                    }
                }
            }
        });
        Self { target, seen, task }
    }

    /// Lengths of the datagrams received so far, in order.
    pub(crate) fn seen(&self) -> Vec<usize> {
        self.seen.lock().unwrap().clone()
    }

    /// Waits up to 2 s until `count` datagrams have arrived.
    pub(crate) async fn wait_seen(&self, count: usize) {
        let _ = timeout(Duration::from_secs(2), async {
            while self.seen.lock().unwrap().len() < count {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serves one server config, given by its `protocol:` block (indented by four
/// spaces), with the handler construction of the TCP listener startup. The
/// listener is bound here and kept, so no port is released and rebound.
pub(crate) async fn serve_config(protocol: &str) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let yaml = format!("- address: '{addr}'\n  protocol:\n{protocol}");
    let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
    let Some(Config::Server(config)) = create_server_configs(configs)
        .unwrap()
        .configs
        .into_iter()
        .next()
    else {
        panic!("expected one server config");
    };
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let rules = config.rules.map(ConfigSelection::unwrap_config).into_vec();
    let selector = Arc::new(create_tcp_client_proxy_selector(rules, resolver.clone()));
    let handler: Arc<dyn TcpServerHandler> =
        create_tcp_server_handler(config.protocol, &selector, &resolver, Some(addr.ip())).into();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let handler = handler.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let _ = process_stream(tcp, handler, resolver).await;
            });
        }
    });
    (addr, task)
}

/// UoT v2 request: `isConnect`, then a SOCKS address (ATYP IPv4).
pub(crate) fn uot_request(connect: bool, target: SocketAddrV4) -> Vec<u8> {
    let mut bytes = vec![u8::from(connect), 0x01];
    bytes.extend(target.ip().octets());
    bytes.extend(target.port().to_be_bytes());
    bytes
}

/// One UoT v2 datagram. Connect mode: `[u16 length][payload]`. Non-connect
/// mode: `[family 0x00][IPv4][port][u16 length][payload]`.
pub(crate) fn uot_record(connect: bool, target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if !connect {
        bytes.push(0x00);
        bytes.extend(target.ip().octets());
        bytes.extend(target.port().to_be_bytes());
    }
    bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend(payload);
    bytes
}

/// Splits complete UoT v2 records off the received bytes.
pub(crate) fn take_uot_records(connect: bool, buffer: &mut Vec<u8>, replies: &mut Vec<Vec<u8>>) {
    // Non-connect records carry family + IPv4 + port before the length.
    let header = if connect { 2 } else { 9 };
    while buffer.len() >= header {
        if !connect {
            assert_eq!(buffer[0], 0x00, "reply record family");
        }
        let len = usize::from(u16::from_be_bytes([buffer[header - 2], buffer[header - 1]]));
        if buffer.len() < header + len {
            return;
        }
        replies.push(buffer[header..header + len].to_vec());
        buffer.drain(..header + len);
    }
}
