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
    /// ShadowTLS) are reported as [`SessionAuth::Listener`], and so are
    /// Shadowsocks h2mux sessions. Sessions other handlers multiplex on their
    /// own (VMess, VLESS, Trojan, Snell h2mux) are not reported; their outbound
    /// destinations still go through [`Self::check_outbound`].
    ///
    /// Return a [`SessionGrant`] to accept the session, or `None` to refuse it.
    /// A refused session is treated like one with an unknown password (for
    /// AnyTLS this includes the configured `fallback`, if any). When hooks are
    /// installed, this method decides: the users configured for the listener
    /// are not consulted. Grant with [`SessionGrant::with_done`] to learn when
    /// the session ends.
    fn open_session(&self, auth: SessionAuth<'_>) -> Option<SessionGrant>;

    /// Called before every outbound TCP connection and every UDP destination
    /// the server would use, after the configured rules have allowed it.
    ///
    /// `resolved` is the address the server will connect to: hostnames are
    /// resolved before this call, and the connection uses that same address.
    fn check_outbound(&self, destination: &NetLocation, resolved: SocketAddr) -> OutboundDecision;
}

/// The credentials a client presented when opening a session.
///
/// `target` names the server target the session arrived on when the listener
/// has several (the SNI of a TLS, ShadowTLS or REALITY target), so targets
/// configured per user can be told apart.
#[derive(Debug)]
#[non_exhaustive]
pub enum SessionAuth<'a> {
    /// An AnyTLS client, identified by the SHA-256 hash of its password.
    AnyTls {
        password_sha256: &'a [u8; 32],
        target: Option<&'a str>,
    },
    /// A client of a protocol that authenticates with the listener's or the
    /// target's own credential (for example a Shadowsocks key) and carries no
    /// per-user identity.
    Listener { target: Option<&'a str> },
}

/// An accepted session.
#[derive(Debug, Clone)]
pub struct SessionGrant {
    identity: String,
    cancel: CancellationToken,
    done: Option<Arc<DoneOnDrop>>,
}

/// Cancels the embedder's `done` token once the last clone of its grant is
/// dropped, so a grant the server drops without running a session still
/// signals `done`.
#[derive(Debug)]
struct DoneOnDrop(CancellationToken);

impl Drop for DoneOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl SessionGrant {
    /// `identity` names the session's user in logs. Cancelling `cancel` ends
    /// the session and every connection it opened.
    pub fn new(identity: impl Into<String>, cancel: CancellationToken) -> Self {
        Self {
            identity: identity.into(),
            cancel,
            done: None,
        }
    }

    /// Like [`Self::new`], and the server also cancels `done` once the session
    /// has ended for any reason, so the embedder can release per-session state.
    /// `done` is also cancelled when the server drops the grant without running
    /// a session (for example, the client closed before finishing its
    /// handshake). Pass a fresh `done` token for every session.
    pub fn with_done(
        identity: impl Into<String>,
        cancel: CancellationToken,
        done: CancellationToken,
    ) -> Self {
        Self {
            identity: identity.into(),
            cancel,
            done: Some(Arc::new(DoneOnDrop(done))),
        }
    }

    pub fn done_token(&self) -> Option<&CancellationToken> {
        self.done.as_deref().map(|done| &done.0)
    }

    /// Cancels `done` when dropped; the server holds it for the session's life.
    pub(crate) fn done_guard(&self) -> Option<tokio_util::sync::DropGuard> {
        self.done_token()
            .cloned()
            .map(CancellationToken::drop_guard)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dropping_an_unused_grant_cancels_done() {
        let done = CancellationToken::new();
        let grant = SessionGrant::with_done("user", CancellationToken::new(), done.clone());
        assert!(!done.is_cancelled());
        drop(grant);
        assert!(done.is_cancelled());
    }

    #[test]
    fn test_done_waits_for_the_last_clone() {
        let done = CancellationToken::new();
        let grant = SessionGrant::with_done("user", CancellationToken::new(), done.clone());
        let clone = grant.clone();
        drop(grant);
        assert!(!done.is_cancelled());
        drop(clone);
        assert!(done.is_cancelled());
    }

    #[test]
    fn test_dropping_a_grant_never_cancels_the_session() {
        let cancel = CancellationToken::new();
        drop(SessionGrant::with_done(
            "user",
            cancel.clone(),
            CancellationToken::new(),
        ));
        drop(SessionGrant::new("user", cancel.clone()));
        assert!(!cancel.is_cancelled());
    }
}
