use super::process_stream;
use crate::config::TcpConfig;
use crate::resolver::Resolver;
use crate::socket_util::{new_tcp_listener, set_tcp_keepalive};
use crate::tcp::tcp_handler::TcpServerHandler;
use log::{debug, error};
use std::net::SocketAddr;
#[cfg(target_family = "unix")]
use std::path::PathBuf;
use std::sync::Arc;

pub(super) async fn run_tcp_server(
    bind_address: SocketAddr,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let listener = new_tcp_listener(bind_address, 4096, None)?;
    run_tcp_listener(listener, tcp_config, resolver, server_handler).await
}

pub(super) async fn run_tcp_listener(
    listener: tokio::net::TcpListener,
    tcp_config: TcpConfig,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    let TcpConfig { no_delay } = tcp_config;

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TCP accept failed (kind={:?})", e.kind());
                continue;
            }
        };

        if let Err(e) = set_tcp_keepalive(
            &stream,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ) {
            error!("Failed to set TCP keepalive (kind={:?})", e.kind());
        }

        if no_delay && let Err(e) = stream.set_nodelay(true) {
            error!("Failed to set TCP nodelay (kind={:?})", e.kind());
        }

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(stream, cloned_handler, cloned_resolver).await {
                // Protocol and resolver errors can contain destinations, queried
                // names, credentials or payloads. Log only the bounded category,
                // never the peer or an arbitrary error's Display/Debug text.
                error!("TCP connection finished with error (kind={:?})", e.kind());
            } else {
                debug!("TCP connection finished successfully");
            }
        });
    }
}

#[cfg(target_family = "unix")]
pub(super) async fn run_unix_server(
    path_buf: PathBuf,
    resolver: Arc<dyn Resolver>,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<()> {
    if tokio::fs::symlink_metadata(&path_buf).await.is_ok() {
        println!(
            "WARNING: replacing file at socket path {}",
            path_buf.display()
        );
        let _ = tokio::fs::remove_file(&path_buf).await;
    }

    let listener = crate::socket_util::new_unix_listener(path_buf, 4096)?;

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Unix accept failed (kind={:?})", e.kind());
                continue;
            }
        };

        let cloned_resolver = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(stream, cloned_handler, cloned_resolver).await {
                error!("Unix connection finished with error (kind={:?})", e.kind());
            } else {
                debug!("Unix connection finished successfully");
            }
        });
    }
}
