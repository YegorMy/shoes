//! Out-of-band failure signal for an accepted transport socket.
//!
//! A session whose reader is parked on bounded per-stream delivery no longer
//! reads its transport, and the kernel returns already queued bytes before a
//! reset error. So a reset can stay unseen for as long as a destination stops
//! reading. The OS reports the failure at once as error readiness (kqueue
//! `EV_EOF` with an error, epoll `EPOLLERR`); a peer's FIN is not an error.
//!
//! [`TransportWatch`] holds a duplicate of the accepted socket that is never
//! read or written and is registered for error readiness only. Shoes' own
//! listeners attach one to every connection while its protocol is set up, and
//! a session that can be parked (AnyTLS) takes it for its lifetime.

use std::cell::RefCell;
use std::future::Future;
use std::io;

tokio::task_local! {
    static CURRENT: RefCell<Option<TransportWatch>>;
}

/// Error readiness of an accepted TCP (or Unix) socket.
///
/// An embedder that terminates TCP and TLS itself creates one from the
/// accepted socket before handing the stream on, and runs the server
/// handler's setup inside [`TransportWatch::scope`]:
///
/// ```ignore
/// let watch = TransportWatch::tcp(&tcp).ok();
/// let tls = acceptor.accept(tcp).await?;
/// TransportWatch::scope(watch, handler.setup_server_stream(Box::new(stream))).await
/// ```
///
/// Without a watch, a session keeps its previous behaviour.
#[derive(Debug)]
pub struct TransportWatch {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

impl TransportWatch {
    /// Duplicates the socket's descriptor (close-on-exec). The duplicate keeps
    /// the socket open while it lives, so it is dropped with the session.
    pub fn tcp(tcp: &tokio::net::TcpStream) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Self::duplicate(tcp)
        }
        #[cfg(not(unix))]
        {
            // No error-readiness registration here: the watch never fires.
            let _ = tcp;
            Ok(Self {})
        }
    }

    /// Like [`TransportWatch::tcp`], for a Unix socket listener.
    #[cfg(unix)]
    pub fn unix(stream: &tokio::net::UnixStream) -> io::Result<Self> {
        Self::duplicate(stream)
    }

    #[cfg(unix)]
    fn duplicate(socket: &impl std::os::fd::AsFd) -> io::Result<Self> {
        Ok(Self {
            fd: socket.as_fd().try_clone_to_owned()?,
        })
    }

    /// Runs a server handler's `setup` with `watch` available to the session
    /// it starts. Setup must run inline in this task, as server handlers do.
    pub async fn scope<F: Future>(watch: Option<Self>, setup: F) -> F::Output {
        CURRENT.scope(RefCell::new(watch), setup).await
    }

    /// Takes the watch of the connection being set up, if any.
    pub(crate) fn take_current() -> Option<Self> {
        CURRENT
            .try_with(|watch| watch.borrow_mut().take())
            .ok()
            .flatten()
    }

    /// Resolves once the OS reports an error on the socket (for example a
    /// reset), without reading it. Never resolves for a healthy socket, a
    /// peer's FIN, or when the error cannot be observed.
    pub(crate) async fn failed(self) {
        #[cfg(unix)]
        {
            use tokio::io::Interest;
            use tokio::io::unix::AsyncFd;
            // Never read SO_ERROR here: it belongs to the socket, and taking it
            // would turn the session reader's reset into a clean EOF.
            if let Ok(fd) = AsyncFd::with_interest(self.fd, Interest::ERROR)
                && fd.ready(Interest::ERROR).await.is_ok()
            {
                return;
            }
        }
        std::future::pending().await
    }
}
