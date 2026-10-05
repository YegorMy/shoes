#[cfg(target_family = "unix")]
use super::listener::run_unix_server;
use super::listener::{run_tcp_listener, run_tcp_server};
use crate::config::{BindLocation, Config, ConfigSelection, ServerConfig, TcpConfig, Transport};
use crate::embedding::ServerHooks;
use crate::quic_server::start_quic_servers;
use crate::resolver::Resolver;
use crate::socket_util::new_tcp_listener;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::tcp::tcp_handler::TcpServerHandler;
use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
#[cfg(unix)]
use crate::tun::start_tun_server;
use log::debug;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;

pub async fn start_servers(
    config: Config,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    start_servers_with(config, resolver, None).await
}

pub(crate) async fn start_servers_with(
    config: Config,
    resolver: Arc<dyn Resolver>,
    hooks: Option<Arc<dyn ServerHooks>>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    match config {
        Config::TunServer(_) if hooks.is_some() => Err(hooks_unsupported("TUN")),
        #[cfg(unix)]
        Config::TunServer(tun_config) => start_tun_server(tun_config, resolver)
            .await
            .map(|t| vec![t]),
        #[cfg(not(unix))]
        Config::TunServer(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN server is not supported on this platform",
        )),
        Config::Server(server_config) => {
            start_tcp_or_quic_servers(server_config, resolver, hooks).await
        }
        _ => unreachable!("create_server_configs only returns Server and TunServer"),
    }
}

fn hooks_unsupported(kind: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("server hooks are not supported for {kind} servers"),
    )
}

async fn start_tcp_or_quic_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    hooks: Option<Arc<dyn ServerHooks>>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut join_handles = Vec::with_capacity(3);

    if hooks.is_some() && !matches!(config.transport, Transport::Tcp) {
        return Err(hooks_unsupported("QUIC"));
    }

    match config.transport {
        Transport::Tcp => match start_tcp_servers(config.clone(), resolver, hooks).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Quic => match start_quic_servers(config.clone(), resolver).await {
            Ok(handles) => {
                join_handles.extend(handles);
            }
            Err(e) => {
                for join_handle in join_handles {
                    join_handle.abort();
                }
                return Err(e);
            }
        },
        Transport::Udp => todo!(),
    }

    if join_handles.is_empty() {
        return Err(std::io::Error::other(format!(
            "failed to start servers at {}",
            config.bind_location
        )));
    }

    Ok(join_handles)
}

async fn start_tcp_servers(
    config: ServerConfig,
    resolver: Arc<dyn Resolver>,
    hooks: Option<Arc<dyn ServerHooks>>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let ServerConfig {
        bind_location,
        tcp_settings,
        protocol,
        rules,
        ..
    } = config;

    println!("Starting {} TCP server at {}", protocol, bind_location);

    let rules = rules.map(ConfigSelection::unwrap_config).into_vec();
    // We should always have a direct entry.
    assert!(!rules.is_empty());

    let tcp_config = tcp_settings.unwrap_or_else(TcpConfig::default);

    let mut client_proxy_selector =
        create_tcp_client_proxy_selector(rules.clone(), resolver.clone());
    let hooked = hooks.is_some();
    if let Some(hooks) = hooks {
        client_proxy_selector = client_proxy_selector.with_hooks(hooks);
    }
    let client_proxy_selector = Arc::new(client_proxy_selector);

    let mut handles = vec![];

    match bind_location {
        BindLocation::Address(addresses) => {
            // Shares protocol state across ports without reusing an interface-specific UDP bind IP.
            let mut handlers: HashMap<IpAddr, Arc<dyn TcpServerHandler>> = HashMap::new();
            let mut spawn_listener =
                |socket_addr: SocketAddr, listener: Option<tokio::net::TcpListener>| {
                    let tcp_handler = handlers
                        .entry(socket_addr.ip())
                        .or_insert_with(|| {
                            create_tcp_server_handler(
                                protocol.clone(),
                                &client_proxy_selector,
                                &resolver,
                                Some(socket_addr.ip()),
                            )
                            .into()
                        })
                        .clone();
                    debug!("TCP handler for {}: {tcp_handler:?}", socket_addr.ip());

                    let tcp_config = tcp_config.clone();
                    let resolver = resolver.clone();
                    let handle = tokio::spawn(async move {
                        let result = match listener {
                            Some(listener) => {
                                run_tcp_listener(listener, tcp_config, resolver, tcp_handler).await
                            }
                            None => {
                                run_tcp_server(socket_addr, tcp_config, resolver, tcp_handler).await
                            }
                        };
                        result.unwrap();
                    });
                    handles.push(handle);
                };
            if hooked {
                // Own every address before any listener task starts. A later
                // bind error drops earlier sockets with the temporary vector.
                let mut listeners = Vec::new();
                for address in addresses.into_vec() {
                    for socket_addr in address.to_socket_addrs()? {
                        listeners.push((socket_addr, new_tcp_listener(socket_addr, 4096, None)?));
                    }
                }
                for (socket_addr, listener) in listeners {
                    spawn_listener(socket_addr, Some(listener));
                }
            } else {
                // Preserve ordinary startup's asynchronous bind and ordering.
                for address in addresses.into_vec() {
                    for socket_addr in address.to_socket_addrs()? {
                        spawn_listener(socket_addr, None);
                    }
                }
            }
        }
        BindLocation::Path(path_buf) => {
            #[cfg(target_family = "unix")]
            {
                let tcp_handler: Arc<dyn TcpServerHandler> =
                    create_tcp_server_handler(protocol, &client_proxy_selector, &resolver, None)
                        .into();
                debug!("TCP handler: {tcp_handler:?}");
                let handle = tokio::spawn(async move {
                    run_unix_server(path_buf, resolver, tcp_handler)
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }
            #[cfg(not(target_family = "unix"))]
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Unix sockets are not supported on this platform",
                ));
            }
        }
    }

    Ok(handles)
}
