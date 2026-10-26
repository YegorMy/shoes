//! Real TLS client flights with a global, unfiltered Shoes logger. Fixture
//! servers run in a separate, logger-free process, so everything the client
//! process writes (stdout, stderr, the engine log and tracing) is client output
//! and must fit a closed, payload-free grammar. A canary run pushes known
//! disclosures through the same collector to prove the checks are not vacuous.
#[path = "tls_client_guard.rs"]
mod guard;

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{Error, ErrorKind, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use base64::Engine;
use log::LevelFilter;
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use serde::{Deserialize, Serialize};
use shoes::NetLocation;
use shoes::config::{Config, create_server_configs};
use shoes::embedding::start_servers_with_hooks;
use shoes::logging::{Directive, FileLogWriter, init_multi_logger};
use shoes::resolver::Resolver;
use shoes::tcp::tcp_client_handler_factory::create_tcp_client_handler;
use shoes::tcp::tcp_handler::TcpClientHandler;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::super::{Hooks, LIMIT, Tasks};
use super::guard::Event;
use super::{Policy, TERMINALS, Writer, trace};

// Every protected canary contains MARKER, so partial renderings are caught too.
const MARKER: &str = "client-privacy";
const TLS_SNI: &str = "tls-sni.client-privacy.invalid";
const SHADOWTLS_SNI: &str = "shadowtls-sni.client-privacy.invalid";
const REMOTE_SNI: &str = "shadowtls-remote-sni.client-privacy.invalid";
const ENDPOINT: &str = "shadowtls-endpoint.client-privacy.invalid";
const DESTINATION: &str = "destination.client-privacy.invalid";
const WRONG_NAME: &str = "wrong-name.client-privacy.invalid";
const ECH_PUBLIC_NAME: &str = "ech-public.client-privacy.invalid";
const CA_NAME: &str = "client-privacy-ca-canary";
const CLIENT_NAME: &str = "client-cert.client-privacy.invalid";
const ALPN: &str = "client-privacy-alpn-canary";
const OCSP: &[u8] = b"client-privacy-ocsp-canary";
const TICKET: &[u8] = b"client-privacy-ticket-canary:";
const PAYLOAD: &[u8] = b"client-privacy-payload-canary";
const PASSWORD: &str = "client-privacy-shadowtls-password";
const WRONG_PASSWORD: &str = "client-privacy-wrong-shadowtls-password";
const SS_KEY_BYTES: &[u8] = b"client-privacy-k";
const ECH_CONFIG_ID: u8 = 7;
const ROLE: &str = "SHOES_TLS_CLIENT_PRIVACY_ROLE";
const DIR: &str = "SHOES_TLS_CLIENT_PRIVACY_DIR";
const FIXTURE: &str = "SHOES_TLS_CLIENT_PRIVACY_FIXTURE";
const TEST: &str = "tls::client::client_diagnostics_are_private";

fn ss_key() -> String {
    base64::engine::general_purpose::STANDARD.encode(SS_KEY_BYTES)
}

fn pin(der: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn block(pem: &str, indent: usize) -> String {
    pem.lines()
        .map(|line| format!("{:indent$}{line}\n", ""))
        .collect()
}

/// Server-side material and addresses, published by the fixture process.
#[derive(Serialize, Deserialize)]
struct Fixture {
    ca: Vec<u8>,
    leaf: Vec<u8>,
    shadowtls_leaf: Vec<u8>,
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    client_cert_pem: String,
    client_key_pem: String,
    servers: BTreeMap<String, SocketAddr>,
}

impl Fixture {
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(self.ca.clone())).unwrap();
        roots
    }
}

#[derive(Debug)]
struct MapResolver(BTreeMap<String, SocketAddr>);

impl Resolver for MapResolver {
    fn resolve_location(
        &self,
        location: &NetLocation,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        let result = match location.to_socket_addr_nonblocking() {
            Some(address) => Ok(vec![address]),
            None => location
                .address()
                .hostname()
                .and_then(|name| self.0.get(name))
                .map(|address| vec![*address])
                .ok_or_else(|| Error::new(ErrorKind::NotFound, "unmapped fixture name")),
        };
        Box::pin(async move { result })
    }
}

// Tickets carry a known prefix so any ticket or PSK identity rendering is
// detectable. Fixture-only: the prefix is not encryption.
#[derive(Debug)]
struct CanaryTicketer;

impl rustls::server::ProducesTickets for CanaryTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        3600
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        Some([TICKET, plain].concat())
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        cipher.strip_prefix(TICKET).map(<[u8]>::to_vec)
    }
}

struct Material {
    ca: rcgen::Certificate,
    leaf: rcgen::Certificate,
    leaf_key: rcgen::KeyPair,
    shadowtls: rcgen::Certificate,
    shadowtls_key: rcgen::KeyPair,
    client: rcgen::Certificate,
    client_key: rcgen::KeyPair,
}

impl Material {
    fn new() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, CA_NAME);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let issue = |name: &str, usage| {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
            params.distinguished_name.push(DnType::CommonName, name);
            params.extended_key_usages = vec![usage];
            (params.signed_by(&key, &issuer).unwrap(), key)
        };
        let (leaf, leaf_key) = issue(TLS_SNI, ExtendedKeyUsagePurpose::ServerAuth);
        let (shadowtls, shadowtls_key) = issue(SHADOWTLS_SNI, ExtendedKeyUsagePurpose::ServerAuth);
        let (client, client_key) = issue(CLIENT_NAME, ExtendedKeyUsagePurpose::ClientAuth);
        Self {
            ca,
            leaf,
            leaf_key,
            shadowtls,
            shadowtls_key,
            client,
            client_key,
        }
    }

    fn server(
        &self,
        version: &'static SupportedProtocolVersion,
        stateless: bool,
        client_auth: bool,
        retry: bool,
    ) -> Arc<ServerConfig> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if retry {
            // Clients offer X25519-family shares first, so this forces a HelloRetryRequest.
            provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP384R1];
        }
        let provider = Arc::new(provider);
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap();
        let builder = if client_auth {
            let mut roots = RootCertStore::empty();
            roots.add(self.ca.der().clone()).unwrap();
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .build()
                .unwrap(),
            )
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder
            .with_single_cert_with_ocsp(
                vec![self.leaf.der().clone(), self.ca.der().clone()],
                PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()).into(),
                OCSP.to_vec(),
            )
            .unwrap();
        config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
        if stateless {
            config.ticketer = Arc::new(CanaryTicketer);
        }
        Arc::new(config)
    }
}

async fn serve_tls(listener: TcpListener, config: Arc<ServerConfig>) {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut tls) = acceptor.accept(socket).await {
                let mut payload = vec![0; PAYLOAD.len()];
                if tls.read_exact(&mut payload).await.is_ok() {
                    let _ = tls.write_all(&payload).await;
                    let _ = tls.shutdown().await;
                }
            }
        });
    }
}

async fn serve_echo(listener: TcpListener) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut payload = vec![0; PAYLOAD.len()];
            if socket.read_exact(&mut payload).await.is_ok() {
                let _ = socket.write_all(&payload).await;
                let _ = socket.shutdown().await;
            }
        });
    }
}

/// Fixture process: no logger is installed, so none of its output is captured.
fn fixture(dir: &Path) {
    let material = Material::new();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use rustls::version::{TLS12, TLS13};
            let mut tasks = Tasks(Vec::new());
            let mut servers = BTreeMap::new();
            for (name, config) in [
                ("tls13", material.server(&TLS13, false, false, false)),
                (
                    "tls13-stateless",
                    material.server(&TLS13, true, false, false),
                ),
                ("tls12", material.server(&TLS12, false, false, false)),
                (
                    "tls12-stateless",
                    material.server(&TLS12, true, false, false),
                ),
                ("retry", material.server(&TLS13, false, false, true)),
                ("auth13", material.server(&TLS13, false, true, false)),
                ("auth12", material.server(&TLS12, false, true, false)),
                ("handshake", material.server(&TLS13, false, false, false)),
            ] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                servers.insert(name.to_owned(), listener.local_addr().unwrap());
                tasks.0.push(tokio::spawn(serve_tls(listener, config)));
            }
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_address = echo.local_addr().unwrap();
            tasks.0.push(tokio::spawn(serve_echo(echo)));

            // The engine's own ShadowTLS v3 server: a local handshake identity
            // and a remote handshake relayed to a real TLS server.
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let bind = reserved.local_addr().unwrap();
            let yaml = format!(
                r#"
- address: '{bind}'
  protocol:
    type: tls
    shadowtls_targets:
      '{SHADOWTLS_SNI}':
        password: '{PASSWORD}'
        handshake:
          cert: |
{cert}          key: |
{key}        protocol: &inner
          type: shadowsocks
          cipher: '2022-blake3-aes-128-gcm'
          password: '{ss_key}'
      '{REMOTE_SNI}':
        password: '{PASSWORD}'
        handshake:
          address: '{handshake}'
        protocol: *inner
"#,
                cert = block(&material.shadowtls.pem(), 12),
                key = block(&material.shadowtls_key.serialize_pem(), 12),
                ss_key = ss_key(),
                handshake = servers["handshake"],
            );
            let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
            let config = create_server_configs(configs).unwrap().configs.remove(0);
            drop(reserved);
            let resolver = MapResolver([(DESTINATION.to_owned(), echo_address)].into());
            let hooks = Hooks {
                accept: true.into(),
                block: false.into(),
            };
            tasks.0.extend(
                start_servers_with_hooks(config, Arc::new(resolver), Arc::new(hooks))
                    .await
                    .unwrap(),
            );
            servers.insert("shadowtls".to_owned(), bind);

            let fixture = Fixture {
                ca: material.ca.der().to_vec(),
                leaf: material.leaf.der().to_vec(),
                shadowtls_leaf: material.shadowtls.der().to_vec(),
                client_cert: material.client.der().to_vec(),
                client_key: material.client_key.serialize_der(),
                client_cert_pem: material.client.pem(),
                client_key_pem: material.client_key.serialize_pem(),
                servers,
            };
            let staged = dir.join("fixture.json.tmp");
            std::fs::write(&staged, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
            std::fs::rename(staged, dir.join("fixture.json")).unwrap();
            // Serve until the parent closes stdin (or kills this process).
            tokio::task::spawn_blocking(|| std::io::stdin().read_to_end(&mut Vec::new()))
                .await
                .unwrap()
                .unwrap();
        });
}

/// Every rendering of protected bytes that a diagnostic could plausibly emit.
fn protect(policy: &mut Policy, bytes: &[u8]) {
    policy.protect(bytes);
    let debug = format!("{bytes:?}");
    policy
        .protected
        .push(debug.trim_matches(['[', ']']).to_owned());
    policy
        .protected
        .push(bytes.iter().map(|b| format!("{b:02X}")).collect());
    policy
        .protected
        .push(base64::engine::general_purpose::STANDARD.encode(bytes));
    if bytes.len() > 96 {
        // A middle window catches truncated or differently framed renderings.
        let window = &bytes[bytes.len() / 2..bytes.len() / 2 + 32];
        policy
            .protected
            .push(window.iter().map(|b| format!("{b:02x}")).collect());
        policy
            .protected
            .push(format!("{window:?}").trim_matches(['[', ']']).to_owned());
    }
}

fn protect_certificate(policy: &mut Policy, der: &[u8]) {
    protect(policy, der);
    let certificate = CertificateDer::from(der.to_vec());
    policy.protected.push(format!("{certificate:?}"));
    let pem = pem_certificate(der);
    policy.protected.extend(
        pem.lines()
            .filter(|line| !line.starts_with('-'))
            .map(str::to_owned),
    );
    let fingerprint = pin(der);
    policy.protected.push(fingerprint.clone());
    policy.protected.push(
        fingerprint
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":"),
    );
}

fn fixture_material(path: &Path) -> Fixture {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn pem_certificate(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<_> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

fn protected_policy(fixture: &Fixture) -> Policy {
    let mut policy = Policy::default();
    policy.protected.push(MARKER.to_owned());
    for value in [
        TLS_SNI,
        SHADOWTLS_SNI,
        REMOTE_SNI,
        ENDPOINT,
        DESTINATION,
        WRONG_NAME,
        ECH_PUBLIC_NAME,
        CA_NAME,
        CLIENT_NAME,
        ALPN,
        PASSWORD,
        WRONG_PASSWORD,
    ] {
        protect(&mut policy, value.as_bytes());
    }
    for bytes in [OCSP, TICKET, PAYLOAD, SS_KEY_BYTES, ss_key().as_bytes()] {
        protect(&mut policy, bytes);
    }
    for der in [
        &fixture.ca,
        &fixture.leaf,
        &fixture.shadowtls_leaf,
        &fixture.client_cert,
    ] {
        protect_certificate(&mut policy, der);
    }
    protect(&mut policy, &fixture.client_key);
    policy.protected.extend(
        [&fixture.client_key_pem, &fixture.client_cert_pem]
            .iter()
            .flat_map(|pem| pem.lines())
            .filter(|line| !line.starts_with('-'))
            .map(str::to_owned),
    );
    for address in fixture.servers.values() {
        policy.peer(*address);
    }
    policy
}

fn tls_handler(fixture: &Fixture, pin: &str, client_auth: bool) -> Box<dyn TcpClientHandler> {
    let auth = if client_auth {
        format!(
            "cert: |\n{}key: |\n{}",
            block(&fixture.client_cert_pem, 2),
            block(&fixture.client_key_pem, 2)
        )
    } else {
        String::new()
    };
    let yaml = format!(
        "type: tls\nverify: false\nserver_fingerprints: ['{pin}']\nalpn_protocols: ['{ALPN}']\n{auth}protocol:\n  type: portforward\n"
    );
    // No configured sni_hostname: the engine falls back to the chain's default.
    create_tcp_client_handler(
        serde_yaml::from_str(&yaml).unwrap(),
        Some(TLS_SNI.to_owned()),
        Arc::new(MapResolver(BTreeMap::new())),
    )
}

fn shadowtls_handler(password: &str, sni: &str, pin: &str) -> Box<dyn TcpClientHandler> {
    let yaml = format!(
        r#"
type: shadowtls
password: '{password}'
sni_hostname: '{sni}'
verify: false
server_fingerprints: ['{pin}']
protocol:
  type: shadowsocks
  cipher: '2022-blake3-aes-128-gcm'
  password: '{ss_key}'
  udp_enabled: false
"#,
        ss_key = ss_key()
    );
    create_tcp_client_handler(
        serde_yaml::from_str(&yaml).unwrap(),
        None,
        Arc::new(MapResolver(BTreeMap::new())),
    )
}

fn rejected() {
    log::debug!(target: "tls_privacy_control", "client rejection observed");
}

async fn relay(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> bool {
    let mut payload = vec![0; PAYLOAD.len()];
    let exchange = async {
        stream.write_all(PAYLOAD).await?;
        stream.flush().await?;
        stream.read_exact(&mut payload).await
    };
    let echoed = timeout(LIMIT, exchange)
        .await
        .expect("client relay timed out")
        .is_ok();
    let _ = timeout(LIMIT, stream.shutdown()).await;
    echoed && payload == PAYLOAD
}

// The engine's own client handler, exactly as a client chain drives it.
async fn handler_flight(
    handler: &dyn TcpClientHandler,
    address: SocketAddr,
    policy: &mut Policy,
    success: bool,
) {
    let socket = TcpStream::connect(address).await.unwrap();
    policy.peer(socket.local_addr().unwrap());
    let destination = NetLocation::from_str(&format!("{DESTINATION}:443"), None).unwrap();
    let setup = timeout(
        LIMIT,
        handler.setup_client_tcp_stream(Box::new(socket), destination.into()),
    )
    .await
    .expect("client handshake timed out");
    let echoed = match setup {
        Ok(mut setup) => relay(&mut setup.client_stream).await,
        Err(_) => false,
    };
    assert_eq!(echoed, success, "unexpected client flight outcome");
    if !success {
        rejected();
    }
}

// The vendored rustls client directly, with WebPKI verification against the
// fixture CA (the engine's `verify: true` verifier, with test roots).
async fn rustls_flight(
    config: Arc<ClientConfig>,
    address: SocketAddr,
    name: &'static str,
    policy: &mut Policy,
    success: bool,
) {
    let socket = TcpStream::connect(address).await.unwrap();
    policy.peer(socket.local_addr().unwrap());
    let connect = TlsConnector::from(config).connect(ServerName::try_from(name).unwrap(), socket);
    let echoed = match timeout(LIMIT, connect)
        .await
        .expect("client handshake timed out")
    {
        Ok(mut tls) => relay(&mut tls).await,
        Err(_) => false,
    };
    assert_eq!(echoed, success, "unexpected rustls client flight outcome");
    if !success {
        rejected();
    }
}

fn webpki_client(
    fixture: &Fixture,
    version: &'static SupportedProtocolVersion,
) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_root_certificates(fixture.roots())
    .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.as_bytes().to_vec()];
    Arc::new(config)
}

// An ECH offer to a server without ECH support: the client prepares an inner
// hello for TLS_SNI and an outer hello for ECH_PUBLIC_NAME, then rejects.
fn ech_client(fixture: &Fixture) -> Arc<ClientConfig> {
    use rustls::crypto::hpke::Hpke;
    let suite = rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public, _) = suite.generate_key_pair().unwrap();
    let mut contents = vec![ECH_CONFIG_ID];
    contents.extend(0x0020u16.to_be_bytes()); // DHKEM(X25519, HKDF-SHA256)
    contents.extend((public.0.len() as u16).to_be_bytes());
    contents.extend(&public.0);
    contents.extend(4u16.to_be_bytes());
    contents.extend(0x0001u16.to_be_bytes()); // HKDF-SHA256
    contents.extend(0x0001u16.to_be_bytes()); // AES-128-GCM
    contents.push(0); // maximum_name_length
    contents.push(ECH_PUBLIC_NAME.len() as u8);
    contents.extend(ECH_PUBLIC_NAME.as_bytes());
    contents.extend(0u16.to_be_bytes()); // no extensions
    let mut config = 0xfe0du16.to_be_bytes().to_vec();
    config.extend((contents.len() as u16).to_be_bytes());
    config.extend(contents);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend(config);
    let suites: [&'static dyn Hpke; 1] = [suite];
    let ech = rustls::client::EchConfig::new(list.into(), &suites).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_ech(rustls::client::EchMode::from(ech))
    .unwrap()
    .with_root_certificates(fixture.roots())
    .with_no_client_auth();
    Arc::new(config)
}

// The full client engine: a SOCKS listener whose client chain reaches the
// ShadowTLS server through a named endpoint, as an embedding drives it.
async fn engine_flight(fixture: &Fixture, pin: &str, policy: &mut Policy) {
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = reserved.local_addr().unwrap();
    policy.binds.push(bind.to_string());
    let endpoint = fixture.servers["shadowtls"];
    let yaml = format!(
        r#"
- address: '{bind}'
  protocol:
    type: socks
  rules:
    - masks: '0.0.0.0/0'
      action: allow
      client_chain:
        address: '{ENDPOINT}:{port}'
        protocol:
          type: shadowtls
          password: '{PASSWORD}'
          sni_hostname: '{SHADOWTLS_SNI}'
          verify: false
          server_fingerprints: ['{pin}']
          protocol:
            type: shadowsocks
            cipher: '2022-blake3-aes-128-gcm'
            password: '{ss_key}'
            udp_enabled: false
"#,
        port = endpoint.port(),
        ss_key = ss_key(),
    );
    let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
    let config = create_server_configs(configs).unwrap().configs.remove(0);
    drop(reserved);
    let resolver = MapResolver([(ENDPOINT.to_owned(), endpoint)].into());
    // Without hooks, as an embedding's client side starts it.
    let _tasks = Tasks(
        shoes::tcp::tcp_server::start_servers(config, Arc::new(resolver))
            .await
            .unwrap(),
    );
    let terminals = TERMINALS.load(Ordering::SeqCst);
    // Unhooked startup binds in its own task: retry only refusals, and use the
    // first accepted connection itself, so no probe adds a listener record.
    let mut stream = timeout(LIMIT, async {
        loop {
            match TcpStream::connect(bind).await {
                Ok(stream) => break stream,
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => panic!("engine listener connect failed: {e}"),
            }
        }
    })
    .await
    .expect("engine listener did not start");
    policy.peer(stream.local_addr().unwrap());
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, 1, 0, 3, DESTINATION.len() as u8];
    request.extend(DESTINATION.as_bytes());
    request.extend(443u16.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 4];
    timeout(LIMIT, stream.read_exact(&mut reply))
        .await
        .expect("SOCKS reply timed out")
        .unwrap();
    assert_eq!(reply[..2], [5, 0], "engine chain must connect");
    let mut bound = vec![0; if reply[3] == 4 { 18 } else { 6 }];
    stream.read_exact(&mut bound).await.unwrap();
    assert!(relay(&mut stream).await, "engine chain must relay");
    drop(stream);
    // Wait for the listener's terminal record, not a timing guess.
    timeout(LIMIT, async {
        while TERMINALS.load(Ordering::SeqCst) <= terminals {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("missing engine terminal diagnostic");
}

async fn exercise(fixture: &Fixture, policy: &mut Policy, canary: bool) {
    use rustls::version::{TLS12, TLS13};
    tokio::spawn(async {
        log::debug!(target: "tls_privacy_control", "debug collector active");
        log::trace!(target: "tls_privacy_control", "trace collector active");
        tracing::debug!(target: "tls_privacy_control", "debug collector active");
        tracing::trace!(target: "tls_privacy_control", "trace collector active");
    })
    .await
    .unwrap();
    let servers = &fixture.servers;
    let leaf_pin = pin(&fixture.leaf);
    if canary {
        // One live flight proves the collector before the injected disclosures.
        let handler = tls_handler(fixture, &leaf_pin, false);
        handler_flight(&*handler, servers["tls13"], policy, true).await;
        return;
    }
    // Plain TLS: full handshakes, then resumption (stateful and ticket-based).
    for name in ["tls13", "tls13-stateless", "tls12", "tls12-stateless"] {
        let handler = tls_handler(fixture, &leaf_pin, false);
        handler_flight(&*handler, servers[name], policy, true).await;
        handler_flight(&*handler, servers[name], policy, true).await;
    }
    let handler = tls_handler(fixture, &leaf_pin, false);
    handler_flight(&*handler, servers["retry"], policy, true).await;
    // CertificateRequest: answered with a client certificate, then rejected
    // by the server when the client has none.
    for name in ["auth13", "auth12"] {
        let handler = tls_handler(fixture, &leaf_pin, true);
        handler_flight(&*handler, servers[name], policy, true).await;
        let handler = tls_handler(fixture, &leaf_pin, false);
        handler_flight(&*handler, servers[name], policy, false).await;
    }
    // The client rejects a server certificate that does not match its pin.
    for name in ["tls13", "tls12"] {
        let handler = tls_handler(fixture, &pin(&fixture.ca), false);
        handler_flight(&*handler, servers[name], policy, false).await;
    }

    // ShadowTLS v3: local and relayed handshakes, then rejections.
    let shadowtls_pin = pin(&fixture.shadowtls_leaf);
    let shadowtls = servers["shadowtls"];
    for (password, sni, pinned, success) in [
        (PASSWORD, SHADOWTLS_SNI, &shadowtls_pin, true),
        (PASSWORD, REMOTE_SNI, &leaf_pin, true),
        (WRONG_PASSWORD, SHADOWTLS_SNI, &shadowtls_pin, false),
        (WRONG_PASSWORD, REMOTE_SNI, &leaf_pin, false),
        (PASSWORD, SHADOWTLS_SNI, &leaf_pin, false),
    ] {
        let handler = shadowtls_handler(password, sni, pinned);
        handler_flight(&*handler, shadowtls, policy, success).await;
    }
    engine_flight(fixture, &shadowtls_pin, policy).await;

    // Vendored rustls with WebPKI verification, stapled OCSP and name checks.
    for (name, version) in [("tls13", &TLS13), ("tls12", &TLS12)] {
        rustls_flight(
            webpki_client(fixture, version),
            servers[name],
            TLS_SNI,
            policy,
            true,
        )
        .await;
        rustls_flight(
            webpki_client(fixture, version),
            servers[name],
            WRONG_NAME,
            policy,
            false,
        )
        .await;
    }
    rustls_flight(
        ech_client(fixture),
        servers["tls13"],
        TLS_SNI,
        policy,
        false,
    )
    .await;
}

// Distinct values carried only by the injected canaries, so the parent can
// tell a detected canary from a disclosure by the live flight.
const CANARY_SNI: &str = "canary-sni.client-privacy.invalid";
const CANARY_HELLO: &str = "Sending ClientHello Hello {";

fn canary_signatures(fixture: &Fixture) -> Vec<String> {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    vec![
        CANARY_SNI.to_owned(),
        CANARY_HELLO.to_owned(),
        hex(&fixture.client_cert),
        hex(TICKET),
    ]
}

// Known disclosures, in their pre-fix message shapes, through the same
// collector and process channels. The parent must detect every one; otherwise
// the negative checks would be vacuous.
fn inject_canaries(fixture: &Fixture) {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Hello {
        random: [u8; 4],
        cipher_suites: Vec<&'static str>,
    }
    let name = ServerName::try_from(CANARY_SNI).unwrap();
    log::debug!(target: "rustls::client::hs", "No cached session for {name:?}");
    let hello = Hello {
        random: [1, 2, 3, 4],
        cipher_suites: vec!["TLS13_AES_128_GCM_SHA256"],
    };
    log::trace!(target: "rustls::client::hs", "Sending ClientHello {hello:#?}");
    let chain = [CertificateDer::from(fixture.client_cert.clone())];
    log::trace!(target: "rustls::client::tls13", "Server cert is {chain:?}");
    let ticket: String = TICKET.iter().map(|b| format!("{b:02x}")).collect();
    log::debug!(target: "rustls::client::tls13", "Resuming using PSK {ticket}");
    tracing::debug!(target: "rustls::client::hs", server_name = CANARY_SNI, "Resuming session");
    println!("{CANARY_SNI}");
    eprint!("{}", pem_certificate(&fixture.client_cert));
}

/// Client process: every byte it writes is under test.
fn client(dir: &Path, level: &str) {
    trace::install(dir);
    init_multi_logger(
        vec![Box::new(Writer {
            file: FileLogWriter::new(dir.join("engine.log").to_str().unwrap()).unwrap(),
            serial: Mutex::new(()),
        })],
        vec![Directive {
            name: None,
            level: if level == "DEBUG" {
                LevelFilter::Debug
            } else {
                LevelFilter::Trace
            },
        }],
    );
    let fixture = fixture_material(Path::new(&std::env::var(FIXTURE).unwrap()));
    let mut policy = protected_policy(&fixture);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(
                LIMIT * 12,
                exercise(&fixture, &mut policy, level == "CANARY"),
            )
            .await
            .expect("TLS client privacy scenarios timed out")
        });
    if level == "CANARY" {
        inject_canaries(&fixture);
    }
    log::logger().flush();
    std::fs::write(
        dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
}

#[derive(Debug)]
struct Violation {
    channel: &'static str,
    record: String,
    reason: String,
    detail: String,
}

impl Violation {
    fn new(channel: &'static str, record: &str, reason: &str, detail: &str) -> Self {
        Self {
            channel,
            record: record.to_owned(),
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        }
    }
}

// Bounded lifecycle records that must arrive at each level: the capture is
// live and the scenarios really reached these client paths.
fn controls(level: &str) -> Vec<(&'static str, &'static str)> {
    let mut controls = vec![
        ("tls_privacy_control", "debug collector active"),
        ("shoes::crypto::crypto_handshake", "TLS handshake starting"),
        (
            "shoes::tcp::tcp_client_handler_factory",
            "Using default sni hostname for TLS client connection",
        ),
        ("rustls::client::hs", "No cached session"),
        ("rustls::client::hs", "ALPN protocol selected"),
        (
            "rustls::client::tls13",
            "TLS1.3 encrypted extensions received",
        ),
    ];
    if level == "CANARY" {
        controls.extend([
            ("tls_privacy_control", "trace collector active"),
            ("rustls::client::hs", "Sending ClientHello"),
        ]);
        return controls;
    }
    controls.extend([
        ("tls_privacy_control", "client rejection observed"),
        ("rustls::client::hs", "Resuming session"),
        ("rustls::client::hs", "No ALPN protocol selected"),
        ("rustls::client::tls13", "Resuming using PSK"),
        ("rustls::client::tls13", "Got CertificateRequest"),
        (
            "rustls::client::tls12::server_hello",
            "Server agreed to resume",
        ),
        ("rustls::client::tls12", "Got CertificateRequest"),
        (
            "rustls::client::tls12",
            "Verifying server certificate for configured server name",
        ),
        ("rustls::client::common", "Attempting client auth"),
        (
            "rustls::client::common",
            "Client auth requested but no cert/sigscheme available",
        ),
        (
            "shoes::crypto::crypto_handshake",
            "TLS error processing packets (kind=InvalidData)",
        ),
        (
            "shoes::tcp::proxy_connector_impl",
            "[ProxyConnector] setup_tcp_stream",
        ),
        ("shoes::client_proxy_chain", "Initial hop: Proxy"),
        (
            "shoes::tcp::tcp_server::listener",
            "TCP connection finished successfully",
        ),
    ]);
    if level == "TRACE" {
        controls.extend([
            ("tls_privacy_control", "trace collector active"),
            ("rustls::client::hs", "Sending ClientHello"),
            ("rustls::client::hs", "We got ServerHello"),
            ("rustls::client::hs", "Got HRR"),
            (
                "rustls::client::tls13",
                "Server certificate chain received (count: 2)",
            ),
            (
                "rustls::client::tls12",
                "Server certificate chain received (count: 2)",
            ),
            (
                "rustls::client::tls12",
                "Server stapled OCSP response received",
            ),
            (
                "rustls::webpki::server_verifier",
                "Unvalidated OCSP response present",
            ),
            ("rustls::client::ech", "ECH Inner Hello prepared"),
            ("rustls::client::ech", "ECH rejected by server"),
        ]);
    }
    controls
}

fn inspect(dir: &Path, stdout: &[u8], stderr: &[u8], level: &str) -> Vec<Violation> {
    let policy: Policy =
        serde_json::from_slice(&std::fs::read(dir.join("policy.json")).unwrap()).unwrap();
    let protected = &policy.protected;
    let mut violations = Vec::new();
    let stdout = String::from_utf8_lossy(stdout);
    for bind in &policy.binds {
        let count = stdout
            .lines()
            .filter(|line| guard::startup(line, bind))
            .count();
        if count != 1 {
            violations.push(Violation::new(
                "stdout",
                "startup",
                "each configured bind is allowed only once, at startup",
                &count.to_string(),
            ));
        }
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
        if !harness && !policy.binds.iter().any(|bind| guard::startup(line, bind)) {
            violations.push(Violation::new(
                "stdout",
                "line",
                "unclassified stdout",
                line,
            ));
        }
        if protected.iter().any(|value| line.contains(value.as_str())) {
            violations.push(Violation::new(
                "stdout",
                "line",
                "protected disclosure",
                line,
            ));
        }
    }
    let mut events = Vec::new();
    for line in String::from_utf8_lossy(stderr).lines() {
        match serde_json::from_str::<Event>(line) {
            Ok(event) => events.push(event),
            Err(_) => violations.push(Violation::new(
                "stderr",
                "line",
                "stderr byte outside a complete diagnostic record",
                line,
            )),
        }
    }
    let original: String = events
        .iter()
        .map(|e| format!("{}\n", e.formatted))
        .collect();
    if std::fs::read(dir.join("engine.log")).unwrap() != original.as_bytes() {
        violations.push(Violation::new(
            "engine.log",
            "file",
            "complete engine channel must match the unfiltered records",
            "",
        ));
    }
    for event in &events {
        let record = format!("{} {}", event.level, event.target);
        let suffix = format!(" {} {}] {}", event.level, event.target, event.message);
        let shaped = event
            .formatted
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(&suffix))
            .is_some_and(|timestamp| {
                chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.3f").is_ok()
            });
        if !shaped {
            violations.push(Violation::new(
                "log",
                &record,
                "formatted record has fields beyond timestamp, level, target and message",
                &event.formatted,
            ));
        }
        let verdict = if event.fixture_client {
            Err("fixture attribution inside the client process")
        } else {
            guard::client_record(event, protected)
        };
        if let Err(reason) = verdict {
            violations.push(Violation::new("log", &record, reason, &event.message));
        }
    }
    for (target, message) in controls(level) {
        if !events
            .iter()
            .any(|e| e.target == target && e.message == message)
        {
            violations.push(Violation::new(
                "control",
                target,
                "missing positive control",
                message,
            ));
        }
    }
    if !events.iter().any(|e| {
        e.target == "rustls::client::hs" && e.message.starts_with("Using ciphersuite TLS13_")
    }) {
        violations.push(Violation::new(
            "control",
            "rustls::client::hs",
            "missing positive control",
            "Using ciphersuite",
        ));
    }
    for detail in trace::check(dir, protected, &events, guard::client_record) {
        violations.push(Violation::new(
            "tracing",
            "record",
            "tracing violation",
            &detail,
        ));
    }
    violations
}

fn summary(violations: &[Violation]) -> String {
    // Channel, record and reason only: details may hold protected values and
    // are kept in the capture directory instead.
    violations
        .iter()
        .map(|v| format!("{}: {}: {}\n", v.channel, v.record, v.reason))
        .collect()
}

struct FixtureProcess(Child);

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(role: &str, dir: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            TEST,
            "--nocapture",
            "--test-threads=1",
            "--quiet",
        ])
        .env(ROLE, role)
        .env(DIR, dir);
    command
}

#[test]
fn client_diagnostics_are_private() {
    if let Ok(role) = std::env::var(ROLE) {
        let dir = std::env::var(DIR).unwrap();
        if role == "fixture" {
            fixture(Path::new(&dir));
        } else {
            client(Path::new(&dir), &role);
        }
        return;
    }
    let _ports = super::super::PORTS.blocking_lock();
    let root = std::env::var_os("SHOES_TLS_PRIVACY_CAPTURE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"));
    std::fs::create_dir_all(&root).unwrap();
    let root = tempfile::Builder::new()
        .prefix("tls-client-privacy-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    let fixture_dir = root.join("fixture");
    std::fs::create_dir(&fixture_dir).unwrap();
    let mut fixture = FixtureProcess(
        child("fixture", &fixture_dir)
            .stdin(Stdio::piped())
            .stdout(std::fs::File::create(fixture_dir.join("stdout.capture")).unwrap())
            .stderr(std::fs::File::create(fixture_dir.join("stderr.capture")).unwrap())
            .spawn()
            .unwrap(),
    );
    let published = fixture_dir.join("fixture.json");
    let deadline = std::time::Instant::now() + LIMIT * 4;
    while !published.exists() {
        assert!(
            fixture.0.try_wait().unwrap().is_none(),
            "fixture process exited; captures at {}",
            fixture_dir.display()
        );
        assert!(
            std::time::Instant::now() < deadline,
            "fixture servers did not start"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut failures = Vec::new();
    for level in ["DEBUG", "TRACE", "CANARY"] {
        let dir = root.join(level);
        std::fs::create_dir(&dir).unwrap();
        let output = child(level, &dir)
            .env(FIXTURE, &published)
            .output()
            .unwrap();
        std::fs::write(dir.join("stdout.capture"), &output.stdout).unwrap();
        std::fs::write(dir.join("stderr.capture"), &output.stderr).unwrap();
        std::fs::write(dir.join("exit.txt"), output.status.to_string()).unwrap();
        println!(
            "Complete {level} TLS client privacy captures: {}",
            dir.display()
        );
        assert!(
            output.status.success(),
            "TLS client child failed: {}; complete captures at {}",
            output.status,
            dir.display()
        );
        let violations = inspect(&dir, &output.stdout, &output.stderr, level);
        std::fs::write(dir.join("violations.txt"), format!("{violations:#?}\n")).unwrap();
        if level != "CANARY" {
            if !violations.is_empty() {
                failures.push(format!(
                    "{level} client diagnostics rejected (details in {}):\n{}",
                    dir.display(),
                    summary(&violations)
                ));
            }
            continue;
        }
        let detected = |channel: &str, record: &str, reason: &str, detail: &str| {
            violations.iter().any(|v| {
                v.channel == channel
                    && v.record == record
                    && v.reason == reason
                    && v.detail.contains(detail)
            })
        };
        let fixture = fixture_material(&published);
        let signatures = canary_signatures(&fixture);
        for (channel, record, reason, detail) in [
            ("stdout", "line", "protected disclosure", CANARY_SNI),
            (
                "stderr",
                "line",
                "stderr byte outside a complete diagnostic record",
                "BEGIN CERTIFICATE",
            ),
            (
                "log",
                "DEBUG rustls::client::hs",
                "protected disclosure",
                CANARY_SNI,
            ),
            (
                "log",
                "TRACE rustls::client::hs",
                "multiline record",
                CANARY_HELLO,
            ),
            (
                "log",
                "TRACE rustls::client::tls13",
                "protected disclosure",
                &signatures[2],
            ),
            (
                "log",
                "DEBUG rustls::client::tls13",
                "protected disclosure",
                &signatures[3],
            ),
            ("tracing", "record", "tracing violation", "\"server_name\""),
        ] {
            if !detected(channel, record, reason, detail) {
                failures.push(format!(
                    "canary {channel}/{record}/{reason} was not detected (details in {})",
                    dir.display()
                ));
            }
        }
        // Everything else in the canary run, including its live flight, is clean.
        let pem = pem_certificate(&fixture.client_cert);
        let unexpected: Vec<_> = violations
            .into_iter()
            .filter(|v| {
                let injected = if v.channel == "stderr" {
                    pem.lines().any(|line| line == v.detail)
                } else {
                    signatures
                        .iter()
                        .any(|signature| v.detail.contains(signature.as_str()))
                };
                !injected
            })
            .collect();
        if !unexpected.is_empty() {
            failures.push(format!(
                "CANARY run has violations beyond the injected canaries (details in {}):\n{}",
                dir.display(),
                summary(&unexpected)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    drop(fixture.0.stdin.take());
}
