//! Local HTTP/HTTPS test servers
//!
//! This module provides simple HTTP and HTTPS servers with configurable TLS versions
//! for testing protocol behavior with different TLS scenarios.

use super::port_helper::OwnedEndpoint;
use aws_lc_rs::digest::{Context, SHA256};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::convert::Infallible;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

#[must_use = "the server stops when its guard is dropped"]
pub struct TestServer {
    task: JoinHandle<()>,
    address: SocketAddr,
}

impl TestServer {
    fn new(task: JoinHandle<()>, address: SocketAddr) -> Self {
        Self { task, address }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub async fn stop(mut self) -> Result<(), tokio::task::JoinError> {
        self.task.abort();
        match (&mut self.task).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn socket_addr(ip: &str, port: u16) -> std::io::Result<SocketAddr> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    Ok(SocketAddr::new(ip, port))
}

pub async fn start_udp_echo_server(ip: &str, port: u16) -> std::io::Result<TestServer> {
    start_udp_echo_server_with_suffix(ip, port, b" [ECHO]").await
}

pub async fn start_udp_echo_server_with_suffix(
    ip: &str,
    port: u16,
    suffix: &[u8],
) -> std::io::Result<TestServer> {
    let suffix = suffix.to_vec();
    start_udp_response_server(ip, port, move |payload, _| {
        let mut response = Vec::with_capacity(payload.len() + suffix.len());
        response.extend_from_slice(payload);
        response.extend_from_slice(&suffix);
        response
    })
    .await
}

pub async fn start_udp_response_server<F>(
    ip: &str,
    port: u16,
    response: F,
) -> std::io::Result<TestServer>
where
    F: Fn(&[u8], SocketAddr) -> Vec<u8> + Send + 'static,
{
    let socket = UdpSocket::bind(socket_addr(ip, port)?).await?;
    start_udp_response_server_with_socket(socket, response)
}

pub async fn start_udp_echo_server_owned(endpoint: OwnedEndpoint) -> std::io::Result<TestServer> {
    start_udp_response_server_owned(endpoint, |payload, _| [payload, b" [ECHO]"].concat()).await
}

pub async fn start_udp_response_server_owned<F>(
    endpoint: OwnedEndpoint,
    response: F,
) -> std::io::Result<TestServer>
where
    F: Fn(&[u8], SocketAddr) -> Vec<u8> + Send + 'static,
{
    start_udp_response_server_with_socket(endpoint.into_udp_socket()?, response)
}

fn start_udp_response_server_with_socket<F>(
    socket: UdpSocket,
    response: F,
) -> std::io::Result<TestServer>
where
    F: Fn(&[u8], SocketAddr) -> Vec<u8> + Send + 'static,
{
    let address = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let response = response(&buffer[..length], peer);
            if let Err(error) = socket.send_to(&response, peer).await {
                eprintln!("[TEST_SERVER] UDP response send failed: {error}");
                break;
            }
        }
    });
    Ok(TestServer::new(task, address))
}

pub async fn start_udp_asymmetric_echo_server(
    primary_ip: &str,
    primary_port: u16,
    response_ip: &str,
    response_port: u16,
    suffix: &[u8],
) -> std::io::Result<(TestServer, SocketAddr)> {
    let primary = UdpSocket::bind(socket_addr(primary_ip, primary_port)?).await?;
    let response = UdpSocket::bind(socket_addr(response_ip, response_port)?).await?;
    let primary_address = primary.local_addr()?;
    let response_address = response.local_addr()?;
    let suffix = suffix.to_vec();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        loop {
            let (length, client) = match primary.recv_from(&mut buffer).await {
                Ok(packet) => packet,
                Err(error) => {
                    eprintln!("[TEST_SERVER] primary UDP receive failed: {error}");
                    break;
                }
            };
            if let Err(error) = primary.send_to(&buffer[..length], response_address).await {
                eprintln!("[TEST_SERVER] UDP forwarding failed: {error}");
                break;
            }

            let (length, forwarder) = match response.recv_from(&mut buffer).await {
                Ok(packet) => packet,
                Err(error) => {
                    eprintln!("[TEST_SERVER] response UDP receive failed: {error}");
                    break;
                }
            };
            if forwarder != primary_address {
                eprintln!("[TEST_SERVER] unexpected UDP forwarder {forwarder}");
                break;
            }

            let mut reply = Vec::with_capacity(length + suffix.len());
            reply.extend_from_slice(&buffer[..length]);
            reply.extend_from_slice(&suffix);
            if let Err(error) = response.send_to(&reply, client).await {
                eprintln!("[TEST_SERVER] asymmetric UDP response failed: {error}");
                break;
            }
        }
    });
    Ok((TestServer::new(task, primary_address), response_address))
}

pub async fn start_tcp_eof_echo_server(ip: &str, port: u16) -> std::io::Result<TestServer> {
    let addr = socket_addr(ip, port)?;
    let listener = TcpListener::bind(addr).await?;
    start_tcp_eof_echo_server_with_listener(listener)
}

pub async fn start_tcp_eof_echo_server_owned(
    endpoint: OwnedEndpoint,
) -> std::io::Result<TestServer> {
    start_tcp_eof_echo_server_with_listener(endpoint.into_tcp_listener()?)
}

fn start_tcp_eof_echo_server_with_listener(listener: TcpListener) -> std::io::Result<TestServer> {
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => match result {
                    Ok((mut stream, _)) => {
                        connections.spawn(async move {
                            let mut payload = Vec::new();
                            stream.read_to_end(&mut payload).await?;
                            payload.extend_from_slice(b" [ECHO]");
                            stream.write_all(&payload).await
                        });
                    }
                    Err(error) => {
                        eprintln!("[TEST_SERVER] TCP echo accept failed: {error}");
                        break;
                    }
                },
                result = connections.join_next(), if !connections.is_empty() => {
                    match result {
                        Some(Ok(Err(error))) => {
                            eprintln!("[TEST_SERVER] TCP echo connection failed: {error}");
                        }
                        Some(Err(error)) => {
                            eprintln!("[TEST_SERVER] TCP echo task failed: {error}");
                        }
                        Some(Ok(Ok(()))) | None => {}
                    }
                }
            }
        }
    });
    Ok(TestServer::new(task, address))
}

async fn echo_stream(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
) -> std::io::Result<()> {
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let length = stream.read(&mut buffer).await?;
        if length == 0 {
            return Ok(());
        }
        stream.write_all(&buffer[..length]).await?;
        stream.flush().await?;
    }
}

pub async fn start_tcp_stream_echo_server(ip: &str, port: u16) -> std::io::Result<TestServer> {
    let listener = TcpListener::bind(socket_addr(ip, port)?).await?;
    start_tcp_stream_echo_server_with_listener(listener)
}

pub async fn start_tcp_stream_echo_server_owned(
    endpoint: OwnedEndpoint,
) -> std::io::Result<TestServer> {
    start_tcp_stream_echo_server_with_listener(endpoint.into_tcp_listener()?)
}

fn start_tcp_stream_echo_server_with_listener(
    listener: TcpListener,
) -> std::io::Result<TestServer> {
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        connections.spawn(echo_stream(stream));
                    }
                    Err(error) => {
                        eprintln!("[TEST_SERVER] TCP echo accept failed: {error}");
                        break;
                    }
                },
                result = connections.join_next(), if !connections.is_empty() => {
                    match result {
                        Some(Ok(Err(error))) => {
                            eprintln!("[TEST_SERVER] TCP echo connection failed: {error}");
                        }
                        Some(Err(error)) => {
                            eprintln!("[TEST_SERVER] TCP echo task failed: {error}");
                        }
                        Some(Ok(Ok(()))) | None => {}
                    }
                }
            }
        }
    });
    Ok(TestServer::new(task, address))
}

/// TLS version to use for HTTPS server
#[derive(Clone, Copy)]
pub enum TlsVersion {
    /// TLS 1.2 only
    Tls12Only,
    /// TLS 1.3 only
    Tls13Only,
}

/// Chunk size for streaming responses (64KB chunks)
const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Threshold above which responses are streamed instead of buffered (1MB)
const STREAM_THRESHOLD: usize = 1024 * 1024;

/// Enhanced HTTP request handler that supports GET and POST
///
/// GET endpoints:
/// - /bytes/N - Return N bytes of data (filled with 'X')
///   - For N > 1MB, response is streamed in chunks to avoid memory buffering
/// - /bytes_verified/N - Return N bytes of data + 32-byte SHA256 digest
///   - Used for integrity verification in streaming tests
///   - Total response size is N + 32 bytes
///
/// POST endpoints:
/// - /echo - Echo back the request body
/// - /sink - Accept data and return JSON with byte count
/// - /validate/N - Validate that all received bytes equal N
async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    use hyper::Method;

    let method = req.method();
    let path = req.uri().path();

    eprintln!(
        "[TEST_SERVER] Received {} request for path: {}",
        method, path
    );

    match *method {
        // GET /bytes_verified/N - Return N bytes of data + 32-byte SHA256 digest
        // Always streams (intended for large transfers with integrity check)
        Method::GET if path.starts_with("/bytes_verified/") => {
            let data_size = path
                .strip_prefix("/bytes_verified/")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1024);

            let total_size = data_size + 32; // data + SHA256 digest
            eprintln!(
                "[TEST_SERVER] Streaming {} bytes + 32-byte SHA256 digest (total {})",
                data_size, total_size
            );

            // Use Arc<Mutex> to share hasher state across async chunks
            use std::sync::Mutex;
            let hasher = Arc::new(Mutex::new(Context::new(&SHA256)));
            let hasher_clone = hasher.clone();

            // Stream: data chunks, then final digest
            let stream = futures::stream::unfold(
                (0usize, false), // (bytes_sent, digest_sent)
                move |(sent, digest_sent)| {
                    let hasher = hasher_clone.clone();
                    async move {
                        if digest_sent {
                            None
                        } else if sent >= data_size {
                            // Send the digest as final chunk
                            let digest = {
                                let ctx = hasher.lock().unwrap();
                                ctx.clone().finish()
                            };
                            let digest_bytes = digest.as_ref().to_vec();
                            let hex: String =
                                digest_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                            eprintln!("[TEST_SERVER] SHA256 digest: {}", hex);
                            Some((
                                Ok::<_, Infallible>(Frame::data(Bytes::from(digest_bytes))),
                                (sent, true),
                            ))
                        } else {
                            // Send data chunk
                            let chunk_size = std::cmp::min(STREAM_CHUNK_SIZE, data_size - sent);
                            let chunk = vec![b'X'; chunk_size];

                            // Update hasher
                            {
                                let mut ctx = hasher.lock().unwrap();
                                ctx.update(&chunk);
                            }

                            Some((
                                Ok::<_, Infallible>(Frame::data(Bytes::from(chunk))),
                                (sent + chunk_size, false),
                            ))
                        }
                    }
                },
            );

            let body = StreamBody::new(stream);
            Ok(Response::builder()
                .header("Content-Length", total_size.to_string())
                .body(BodyExt::boxed(body))
                .unwrap())
        }

        // GET /bytes/N - Return N bytes of data
        // For large sizes (>1MB), stream in chunks to avoid memory buffering
        Method::GET => {
            let data_size = if path.starts_with("/bytes/") {
                path.strip_prefix("/bytes/")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(1024)
            } else {
                1024
            };

            if data_size > STREAM_THRESHOLD {
                // Stream large responses in chunks
                eprintln!(
                    "[TEST_SERVER] Streaming {} bytes in {} chunks",
                    data_size,
                    data_size.div_ceil(STREAM_CHUNK_SIZE)
                );

                let stream = futures::stream::unfold(0usize, move |sent| async move {
                    if sent >= data_size {
                        None
                    } else {
                        let chunk_size = std::cmp::min(STREAM_CHUNK_SIZE, data_size - sent);
                        let chunk = vec![b'X'; chunk_size];
                        Some((
                            Ok::<_, Infallible>(Frame::data(Bytes::from(chunk))),
                            sent + chunk_size,
                        ))
                    }
                });

                let body = StreamBody::new(stream);
                Ok(Response::builder()
                    .header("Content-Length", data_size.to_string())
                    .body(BodyExt::boxed(body))
                    .unwrap())
            } else {
                // Small responses: buffer in memory (original behavior)
                let data = vec![b'X'; data_size];
                Ok(Response::new(Full::new(Bytes::from(data)).boxed()))
            }
        }

        // POST /echo - Echo back the request body
        Method::POST if path == "/echo" => {
            let whole_body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("[TEST_SERVER] Error reading body: {:?}", e);
                    return Ok(Response::builder()
                        .status(500)
                        .body(Full::new(Bytes::from("Error reading body")).boxed())
                        .unwrap());
                }
            };

            let received_len = whole_body.len();
            eprintln!("[TEST_SERVER] POST /echo received {} bytes", received_len);

            Ok(Response::new(Full::new(whole_body).boxed()))
        }

        // POST /sink - Accept data and return JSON with byte count
        Method::POST if path == "/sink" => {
            let whole_body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("[TEST_SERVER] Error reading body: {:?}", e);
                    return Ok(Response::builder()
                        .status(500)
                        .body(Full::new(Bytes::from("Error reading body")).boxed())
                        .unwrap());
                }
            };

            let received_len = whole_body.len();
            eprintln!("[TEST_SERVER] POST /sink received {} bytes", received_len);

            let response_json = format!(r#"{{"received": {}, "status": "ok"}}"#, received_len);

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response_json)).boxed())
                .unwrap())
        }

        // POST /validate/N - Validate that all received bytes equal N
        Method::POST if path.starts_with("/validate/") => {
            let expected_byte = path
                .strip_prefix("/validate/")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(b'Y');

            let whole_body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("[TEST_SERVER] Error reading body: {:?}", e);
                    return Ok(Response::builder()
                        .status(500)
                        .body(Full::new(Bytes::from("Error reading body")).boxed())
                        .unwrap());
                }
            };

            let received_len = whole_body.len();
            let all_match = whole_body.iter().all(|&b| b == expected_byte);

            eprintln!(
                "[TEST_SERVER] POST /validate/{} received {} bytes, valid={}",
                expected_byte, received_len, all_match
            );

            let response_json = format!(
                r#"{{"received": {}, "valid": {}, "expected_byte": {}}}"#,
                received_len, all_match, expected_byte
            );

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(response_json)).boxed())
                .unwrap())
        }

        // Unsupported method or path
        _ => {
            eprintln!("[TEST_SERVER] Unsupported {} request for {}", method, path);
            Ok(Response::builder()
                .status(405)
                .body(Full::new(Bytes::from("Method Not Allowed")).boxed())
                .unwrap())
        }
    }
}

/// Start a local HTTP server on the specified IP and port
///
/// Returns an owning guard that stops the server when dropped.
pub async fn start_local_http_server(ip: &str, port: u16) -> std::io::Result<TestServer> {
    let addr = socket_addr(ip, port)?;
    let listener = TcpListener::bind(addr).await?;
    start_local_http_server_with_listener(listener)
}

pub async fn start_local_http_server_owned(endpoint: OwnedEndpoint) -> std::io::Result<TestServer> {
    start_local_http_server_with_listener(endpoint.into_tcp_listener()?)
}

fn start_local_http_server_with_listener(listener: TcpListener) -> std::io::Result<TestServer> {
    let address = listener.local_addr()?;
    eprintln!("[TEST_SERVER] HTTP server listening on {}", address);

    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => {
                            eprintln!("[TEST_SERVER] Accept error: {}", error);
                            break;
                        }
                    };
                    let io = TokioIo::new(tcp);
                    connections.spawn(async move {
                        if let Err(error) = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .serve_connection(io, service_fn(handle_request))
                            .await
                        {
                            eprintln!("[TEST_SERVER] Error serving connection: {:?}", error);
                        }
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        eprintln!("[TEST_SERVER] Connection task failed: {}", error);
                    }
                }
            }
        }
    });

    Ok(TestServer::new(task, address))
}

/// Create TLS server config with specific version support
fn create_tls_config(
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<Arc<ServerConfig>> {
    // Load certificate
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let keys = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key"))?;

    // Create server config based on TLS version
    let config = match tls_version {
        TlsVersion::Tls12Only => {
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_single_cert(certs, key.into())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        }
        TlsVersion::Tls13Only => {
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key.into())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        }
    };

    Ok(Arc::new(config))
}

/// Start a local HTTPS server on the specified IP and port with specific TLS version
///
/// Returns an owning guard that stops the server when dropped.
///
/// # Arguments
/// * `ip` - IP address to bind to
/// * `port` - Port to bind to
/// * `cert_path` - Path to TLS certificate (can be self-signed)
/// * `key_path` - Path to TLS private key
/// * `tls_version` - TLS version to use (1.2 or 1.3)
///
pub async fn start_local_https_server(
    ip: &str,
    port: u16,
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<TestServer> {
    let addr = socket_addr(ip, port)?;
    let listener = TcpListener::bind(addr).await?;
    start_local_https_server_with_listener(listener, cert_path, key_path, tls_version)
}

pub async fn start_local_https_server_owned(
    endpoint: OwnedEndpoint,
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<TestServer> {
    start_local_https_server_with_listener(
        endpoint.into_tcp_listener()?,
        cert_path,
        key_path,
        tls_version,
    )
}

fn start_local_https_server_with_listener(
    listener: TcpListener,
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<TestServer> {
    let address = listener.local_addr()?;

    let tls_config = create_tls_config(cert_path, key_path, tls_version)?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    let version_str = match tls_version {
        TlsVersion::Tls12Only => "TLS 1.2",
        TlsVersion::Tls13Only => "TLS 1.3",
    };
    eprintln!(
        "[TEST_SERVER] HTTPS ({}) server listening on {}",
        version_str, address
    );

    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => {
                            eprintln!("[TEST_SERVER] Accept error: {}", error);
                            break;
                        }
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    connections.spawn(async move {
                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(stream) => stream,
                            Err(error) => {
                                eprintln!("[TEST_SERVER] TLS accept error: {}", error);
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        if let Err(error) = http1::Builder::new()
                            .timer(TokioTimer::new())
                            .serve_connection(io, service_fn(handle_request))
                            .await
                        {
                            eprintln!("[TEST_SERVER] Connection error: {}", error);
                        }
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = result {
                        eprintln!("[TEST_SERVER] Connection task failed: {}", error);
                    }
                }
            }
        }
    });

    Ok(TestServer::new(task, address))
}

pub async fn start_tls_stream_echo_server(
    ip: &str,
    port: u16,
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<TestServer> {
    let listener = TcpListener::bind(socket_addr(ip, port)?).await?;
    start_tls_stream_echo_server_with_listener(listener, cert_path, key_path, tls_version)
}

pub async fn start_tls_stream_echo_server_owned(
    endpoint: OwnedEndpoint,
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<TestServer> {
    start_tls_stream_echo_server_with_listener(
        endpoint.into_tcp_listener()?,
        cert_path,
        key_path,
        tls_version,
    )
}

fn start_tls_stream_echo_server_with_listener(
    listener: TcpListener,
    cert_path: &Path,
    key_path: &Path,
    tls_version: TlsVersion,
) -> std::io::Result<TestServer> {
    let address = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(create_tls_config(cert_path, key_path, tls_version)?);
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let acceptor = acceptor.clone();
                        connections.spawn(async move {
                            let stream = acceptor.accept(stream).await?;
                            echo_stream(stream).await
                        });
                    }
                    Err(error) => {
                        eprintln!("[TEST_SERVER] TLS echo accept failed: {error}");
                        break;
                    }
                },
                result = connections.join_next(), if !connections.is_empty() => {
                    match result {
                        Some(Ok(Err(error))) => {
                            eprintln!("[TEST_SERVER] TLS echo connection failed: {error}");
                        }
                        Some(Err(error)) => {
                            eprintln!("[TEST_SERVER] TLS echo task failed: {error}");
                        }
                        Some(Ok(Ok(()))) | None => {}
                    }
                }
            }
        }
    });
    Ok(TestServer::new(task, address))
}

// Re-export certificate generation from certs module
pub use super::certs::generate_test_cert_files as generate_test_cert;

// Test Functions for Local HTTP/HTTPS Servers

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn owned_udp_handoff_preserves_queued_packets_and_source() {
        let mut ports = super::super::port_helper::PortHelper::new();
        let endpoint = ports.get_listener_endpoint();
        let address = endpoint.local_addr();
        let client = UdpSocket::bind(SocketAddr::new(address.ip(), 0))
            .await
            .unwrap();
        client.send_to(b"queued", address).await.unwrap();
        let server = start_udp_echo_server_owned(endpoint).await.unwrap();
        assert_eq!(server.local_addr(), address);
        let mut response = [0; 32];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, address);
        assert_eq!(&response[..length], b"queued [ECHO]");
        // UDP conversion releases the unused TCP counterpart immediately.
        let counterpart = std::net::TcpListener::bind(address).unwrap();
        assert_eq!(
            UdpSocket::bind(address).await.unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
        server.stop().await.unwrap();
        let released = std::net::UdpSocket::bind(address).unwrap();
        assert_eq!(released.local_addr().unwrap(), address);
        drop(counterpart);
    }

    #[tokio::test]
    async fn owned_tcp_handoff_preserves_pending_stream_and_eof() {
        for eof in [false, true] {
            let mut ports = super::super::port_helper::PortHelper::new();
            let endpoint = ports.get_listener_endpoint();
            let address = endpoint.local_addr();
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client.write_all(b"queued tcp").await.unwrap();
            let server = if eof {
                client.shutdown().await.unwrap();
                start_tcp_eof_echo_server_owned(endpoint).await.unwrap()
            } else {
                start_tcp_stream_echo_server_owned(endpoint).await.unwrap()
            };
            assert_eq!(server.local_addr(), address);
            ports.wait_for_all_ports().await.unwrap();
            let expected: &[u8] = if eof {
                b"queued tcp [ECHO]"
            } else {
                b"queued tcp"
            };
            let mut response = vec![0; expected.len()];
            tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, expected);
            let counterpart = std::net::UdpSocket::bind(address).unwrap();
            assert_eq!(
                std::net::TcpListener::bind(address).unwrap_err().kind(),
                std::io::ErrorKind::AddrInUse
            );
            drop(client);
            server.stop().await.unwrap();
            drop(counterpart);
        }
    }

    #[tokio::test]
    async fn failed_tls_construction_releases_owned_pair() {
        let mut ports = super::super::port_helper::PortHelper::new();
        let endpoint = ports.get_listener_endpoint();
        let address = endpoint.local_addr();
        let missing = tempfile::tempdir().unwrap();
        let result = start_local_https_server_owned(
            endpoint,
            &missing.path().join("missing-cert"),
            &missing.path().join("missing-key"),
            TlsVersion::Tls13Only,
        )
        .await;
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        let listener = std::net::TcpListener::bind(address).unwrap();
        let socket = std::net::UdpSocket::bind(address).unwrap();
        assert_eq!(listener.local_addr().unwrap(), address);
        assert_eq!(socket.local_addr().unwrap(), address);
    }

    /// Test helper that verifies local HTTP server works and returns correct data size
    async fn test_local_http_with_size(data_size: usize) -> Result<(), Box<dyn std::error::Error>> {
        let mut port_helper = super::super::port_helper::PortHelper::new();
        let endpoint = port_helper.get_listener_endpoint();
        let address = endpoint.local_addr();
        let (ip, port) = (address.ip().to_string(), address.port());
        let _server = start_local_http_server_owned(endpoint).await?;
        port_helper.wait_for_all_ports().await?;

        let url = format!("http://{}:{}/bytes/{}", ip, port, data_size);
        let output = super::super::curl::curl_direct(&url).await?;

        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.len(), data_size);

        Ok(())
    }

    /// Test helper for HTTPS with TLS 1.3
    async fn test_local_https_tls13_with_size(
        data_size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut port_helper = super::super::port_helper::PortHelper::new();
        let endpoint = port_helper.get_listener_endpoint();
        let address = endpoint.local_addr();
        let (ip, port) = (address.ip().to_string(), address.port());
        let (cert_path, key_path) = generate_test_cert()?;

        let _server = start_local_https_server_owned(
            endpoint,
            AsRef::<Path>::as_ref(&cert_path),
            AsRef::<Path>::as_ref(&key_path),
            TlsVersion::Tls13Only,
        )
        .await?;
        port_helper.wait_for_all_ports().await?;

        let url = format!("https://{}:{}/bytes/{}", ip, port, data_size);
        let output = super::super::curl::curl_https_insecure_direct(&url).await?;

        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.len(), data_size);

        Ok(())
    }

    /// Test helper for HTTPS with TLS 1.2
    async fn test_local_https_tls12_with_size(
        data_size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut port_helper = super::super::port_helper::PortHelper::new();
        let endpoint = port_helper.get_listener_endpoint();
        let address = endpoint.local_addr();
        let (ip, port) = (address.ip().to_string(), address.port());
        let (cert_path, key_path) = generate_test_cert()?;

        let _server = start_local_https_server_owned(
            endpoint,
            AsRef::<Path>::as_ref(&cert_path),
            AsRef::<Path>::as_ref(&key_path),
            TlsVersion::Tls12Only,
        )
        .await?;
        port_helper.wait_for_all_ports().await?;

        let url = format!("https://{}:{}/bytes/{}", ip, port, data_size);
        let output = super::super::curl::curl_https_tls12_direct(&url).await?;

        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.len(), data_size);

        Ok(())
    }

    #[tokio::test]
    async fn test_local_http_server_works() -> Result<(), Box<dyn std::error::Error>> {
        test_local_http_with_size(1024).await
    }

    #[tokio::test]
    async fn dropping_server_guard_stops_listener() -> Result<(), Box<dyn std::error::Error>> {
        let mut port_helper = super::super::port_helper::PortHelper::new();
        let (ip, port) = port_helper.get_listener_port();
        let addr = format!("{ip}:{port}");
        let server = start_local_http_server(&ip, port).await?;
        port_helper.wait_for_all_ports().await?;

        drop(server);

        tokio::time::timeout(Duration::from_secs(1), async {
            while tokio::net::TcpStream::connect(&addr).await.is_ok() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn udp_echo_server_is_owned_by_guard() -> Result<(), Box<dyn std::error::Error>> {
        let server = start_udp_echo_server("127.0.0.1", 0).await?;
        let addr = server.local_addr();
        assert_ne!(addr.port(), 0);
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.send_to(b"hello", addr).await?;
        let mut response = [0; 32];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response)).await??;
        assert_eq!(&response[..length], b"hello [ECHO]");

        drop(server);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if UdpSocket::bind(addr).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn asymmetric_udp_echo_uses_the_response_socket() -> Result<(), Box<dyn std::error::Error>>
    {
        let response_ip = if cfg!(target_vendor = "apple") {
            "127.0.0.1"
        } else {
            "127.0.0.2"
        };
        let (server, response_address) =
            start_udp_asymmetric_echo_server("127.0.0.1", 0, response_ip, 0, b" response").await?;
        assert_ne!(server.local_addr(), response_address);
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        client.send_to(b"request", server.local_addr()).await?;

        let mut response = [0; 32];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response)).await??;
        assert_eq!(peer, response_address);
        assert_eq!(&response[..length], b"request response");
        Ok(())
    }

    #[tokio::test]
    async fn test_local_https_tls13_server_works() -> Result<(), Box<dyn std::error::Error>> {
        test_local_https_tls13_with_size(1024).await
    }

    #[tokio::test]
    async fn test_local_https_tls12_server_works() -> Result<(), Box<dyn std::error::Error>> {
        test_local_https_tls12_with_size(1024).await
    }
}
