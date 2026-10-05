use std::sync::Arc;
use std::time::Duration;

use log::debug;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::{AsyncShutdownMessageExt, AsyncStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::embedding::SessionAuth;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;

mod listener;
mod startup;

pub use startup::start_servers;
pub(crate) use startup::start_servers_with;

async fn setup_server_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
) -> std::io::Result<TcpServerSetupResult>
where
    AS: AsyncStream + 'static,
{
    let server_stream = Box::new(stream);
    server_handler.setup_server_stream(server_stream).await
}

pub async fn process_stream<AS>(
    stream: AS,
    server_handler: Arc<dyn TcpServerHandler>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()>
where
    AS: AsyncStream + 'static,
{
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, server_handler),
    );

    let setup_result = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {e}"),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {elapsed}"),
            ));
        }
    };

    // Protocols without a per-user identity report their sessions here;
    // handlers that authenticate users themselves return AlreadyHandled.
    let session = setup_result.proxy_selector().and_then(|selector| {
        selector.hooks().map(|hooks| {
            hooks.open_session(SessionAuth::Listener {
                target: selector.target(),
            })
        })
    });
    let grant = match session {
        Some(Some(grant)) => Some(grant),
        Some(None) => {
            debug!("session refused by embedder hooks");
            return Ok(());
        }
        None => None,
    };

    let forward = forward_setup_result(setup_result, resolver);
    match grant {
        Some(grant) => {
            let _done = grant.done_guard();
            // Cancellation is checked first, so a cancelled session never
            // starts or continues forwarding.
            tokio::select! {
                biased;
                () = grant.cancel_token().cancelled() => Ok(()),
                result = forward => result,
            }
        }
        None => forward.await,
    }
}

async fn forward_setup_result(
    setup_result: TcpServerSetupResult,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    match setup_result {
        TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
            connection_success_response,
            initial_remote_data,
        } => {
            let setup_client_stream_future = timeout(
                Duration::from_secs(60),
                setup_client_tcp_stream(
                    &mut server_stream,
                    proxy_selector,
                    resolver,
                    remote_location.clone(),
                ),
            );

            let mut client_stream = match setup_client_stream_future.await {
                Ok(Ok(Some(s))) => s,
                Ok(Ok(None)) => {
                    // Must have been blocked.
                    let _ = server_stream.shutdown().await;
                    return Ok(());
                }
                Ok(Err(e)) => {
                    let _ = server_stream.shutdown().await;
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to setup client stream to {remote_location}: {e}"),
                    ));
                }
                Err(elapsed) => {
                    let _ = server_stream.shutdown().await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("client setup to {remote_location} timed out: {elapsed}"),
                    ));
                }
            };

            if let Some(data) = connection_success_response {
                write_all(&mut server_stream, &data).await?;
                // server_need_initial_flush should be set to true by the handler if
                // it's needed.
            }

            let client_need_initial_flush = match initial_remote_data {
                Some(data) => {
                    write_all(&mut client_stream, &data).await?;
                    true
                }
                None => false,
            };

            let copy_result = copy_bidirectional(
                &mut server_stream,
                &mut client_stream,
                server_need_initial_flush,
                client_need_initial_flush,
            )
            .await;

            let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

            copy_result?;
            Ok(())
        }
        TcpServerSetupResult::BidirectionalUdp {
            remote_location,
            stream: server_stream,
            need_initial_flush: server_need_initial_flush,
            proxy_selector,
        } => {
            let action = proxy_selector
                .judge(remote_location.into(), &resolver)
                .await?;
            match action {
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                } => {
                    let client_stream = chain_group
                        .connect_udp_bidirectional(&resolver, remote_location)
                        .await?;

                    run_udp_copy(
                        server_stream,
                        client_stream,
                        server_need_initial_flush,
                        false,
                    )
                    .await
                }
                ConnectDecision::Block => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Blocked bidirectional udp forward",
                )),
            }
        }
        TcpServerSetupResult::MultiDirectionalUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each packet is routed based on its destination
            run_udp_routing(
                ServerStream::Targeted(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::SessionBasedUdp {
            stream: server_stream,
            need_initial_flush,
            proxy_selector,
        } => {
            // Per-destination routing: each session is routed based on its destination
            run_udp_routing(
                ServerStream::Session(server_stream),
                proxy_selector,
                resolver,
                need_initial_flush,
            )
            .await
        }
        TcpServerSetupResult::AlreadyHandled => {
            // Connection is being handled by a spawned task (e.g., Reality fallback).
            // Nothing more to do here.
            Ok(())
        }
    }
}

pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: NetLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_selector
        .judge(remote_location.into(), &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            if let Some(data) = early_data {
                server_stream.write_all(&data).await?;
                server_stream.flush().await?;
            }

            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}

/// Unified function to run the appropriate UDP copy based on the setup result.
/// Copy messages bidirectionally between server and client message streams.
///
/// After the copy completes (whether successfully or with an error), both streams
/// are shut down to ensure proper cleanup and FIN frames are sent.
#[inline]
pub async fn run_udp_copy(
    mut server_stream: Box<dyn AsyncMessageStream>,
    mut client_stream: Box<dyn AsyncMessageStream>,
    server_need_initial_flush: bool,
    client_need_initial_flush: bool,
) -> std::io::Result<()> {
    let copy_result = copy_bidirectional_message(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(
        server_stream.shutdown_message(),
        client_stream.shutdown_message()
    );

    copy_result
}
