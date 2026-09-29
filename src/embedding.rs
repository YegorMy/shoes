//! Hooks for applications that embed shoes servers.
//!
//! An embedding application that manages its own users (adding and revoking
//! them at runtime) and its own outbound policy installs a [`ServerHooks`]
//! implementation with [`start_servers_with_hooks`]. Servers started without
//! hooks behave exactly as before.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::address::NetLocation;
use crate::config::Config;
use crate::resolver::Resolver;

/// Like [`crate::tcp::tcp_server::start_servers`], with `hooks` installed on
/// every listener the config starts. Hooks are supported for TCP transport
/// servers; TUN and QUIC configs are refused with `ErrorKind::Unsupported`.
pub async fn start_servers_with_hooks(
    config: Config,
    resolver: Arc<dyn Resolver>,
    hooks: Arc<dyn ServerHooks>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    crate::tcp::tcp_server::start_servers_with(config, resolver, Some(hooks)).await
}

/// Callbacks a server makes into the embedding application.
///
/// Both methods run on the connection's task and must not block.
pub trait ServerHooks: Send + Sync + Debug {
    /// Called once per client session after the protocol has read the client's
    /// credentials, and before any outbound connection is made for it.
    ///
    /// AnyTLS sessions are reported with the client's identity. Connections
    /// the server forwards itself (for example Shadowsocks, including inside
    /// ShadowTLS) are reported as [`SessionAuth::Listener`]. Sessions a handler
    /// multiplexes on its own (for example Shadowsocks h2mux) are not reported;
    /// their outbound destinations still go through [`Self::check_outbound`].
    ///
    /// Return a [`SessionGrant`] to accept the session, or `None` to refuse it.
    /// A refused session is treated like one with an unknown password (for
    /// AnyTLS this includes the configured `fallback`, if any). When hooks are
    /// installed, this method decides: the users configured for the listener
    /// are not consulted.
    fn open_session(&self, auth: SessionAuth<'_>) -> Option<SessionGrant>;

    /// Called before every outbound TCP connection and every UDP destination
    /// the server would use, after the configured rules have allowed it.
    ///
    /// `resolved` is the address the server will connect to: hostnames are
    /// resolved before this call, and the connection uses that same address.
    fn check_outbound(&self, destination: &NetLocation, resolved: SocketAddr) -> OutboundDecision;
}

/// The credentials a client presented when opening a session.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionAuth<'a> {
    /// An AnyTLS client, identified by the SHA-256 hash of its password.
    AnyTls { password_sha256: &'a [u8; 32] },
    /// A client of a protocol that authenticates with the listener's own
    /// credential (for example a Shadowsocks key) and carries no per-user
    /// identity.
    Listener,
}

/// An accepted session.
#[derive(Debug, Clone)]
pub struct SessionGrant {
    identity: String,
    cancel: CancellationToken,
}

impl SessionGrant {
    /// `identity` names the session's user in logs. Cancelling `cancel` ends
    /// the session and every connection it opened.
    pub fn new(identity: impl Into<String>, cancel: CancellationToken) -> Self {
        Self {
            identity: identity.into(),
            cancel,
        }
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }
}

/// The embedding application's decision for one outbound destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundDecision {
    /// Connect to the destination.
    Allow,
    /// Refuse the destination, as a `block` rule would.
    Block,
    /// Connect to this location instead.
    Redirect(NetLocation),
}
