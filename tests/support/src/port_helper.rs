//! Port allocation and readiness helper for tests
//!
//! Provides centralized port allocation with tracking and synchronization.
//! All tests should use PortHelper instead of directly allocating ports.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::{LazyLock, Mutex};
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, sleep, timeout};

/// Helper for allocating random ports and waiting for them to be ready.
/// Tracks all listener ports so we can wait for them to be ready before tests run.
#[derive(Default)]
pub struct PortHelper {
    listener_addrs: Vec<SocketAddr>,
}

impl PortHelper {
    /// Create a new PortHelper
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a random available address (IP, port) for a listening server.
    /// Uses kernel-selected localhost ports on Darwin and random 127/8 IPs elsewhere.
    /// This address will be tracked and waited for in wait_for_all_ports().
    pub fn get_listener_port(&mut self) -> (String, u16) {
        let (ip, port) = get_random_addr();
        self.listener_addrs
            .push(format!("{ip}:{port}").parse().unwrap());
        (ip, port)
    }

    /// Get a random available address for a client/connector.
    /// This address will NOT be tracked (clients don't listen).
    pub fn get_port(&mut self) -> (String, u16) {
        get_random_addr()
    }

    /// Require a distinct local source IP without unbounded allocation retries.
    pub fn get_port_on_different_ip(&mut self, primary_ip: &str) -> std::io::Result<(String, u16)> {
        select_distinct_source(primary_ip, || self.get_port())
    }

    /// Get a random available address for a QUIC/UDP listener.
    /// This address will NOT be tracked for TCP readiness checks since QUIC uses UDP.
    /// Use this for Hysteria2, TUIC, and other QUIC-based servers.
    pub fn get_quic_listener_port(&mut self) -> (String, u16) {
        get_random_udp_addr()
    }

    /// Get a random available port on 127.0.0.1 for a listening server.
    ///
    /// IMPORTANT: This is required for tests using libcronet (sing-box naive outbound).
    /// libcronet rejects connections to non-127.0.0.1 loopback addresses (e.g., 127.x.y.z)
    /// with "connection refused" or "invalid argument" errors. This appears to be a
    /// security restriction in Chromium's network stack.
    ///
    /// Returns ("127.0.0.1", port).
    pub fn get_localhost_listener_port(&mut self) -> (String, u16) {
        let address = allocate_addr(|| Ipv4Addr::LOCALHOST.into());
        self.listener_addrs.push(address);
        (address.ip().to_string(), address.port())
    }

    pub fn get_ipv6_listener_port(&mut self) -> (String, u16) {
        let address = allocate_addr(|| Ipv6Addr::LOCALHOST.into());
        self.listener_addrs.push(address);
        (address.ip().to_string(), address.port())
    }

    /// Wait for all tracked listener addresses to be ready for connections.
    /// Waits for all addresses in parallel with a 30 second timeout per address.
    /// If any address doesn't become ready, returns an error.
    pub async fn wait_for_all_ports(&mut self) -> std::io::Result<()> {
        use futures::future::join_all;

        let futures: Vec<_> = std::mem::take(&mut self.listener_addrs)
            .into_iter()
            .map(|addr| wait_for_addr(addr, Duration::from_secs(30)))
            .collect();

        let results = join_all(futures).await;

        // Check if any failed
        for result in results {
            result?;
        }

        Ok(())
    }
}

static ALLOCATED_ENDPOINTS: LazyLock<Mutex<HashSet<SocketAddr>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Probe TCP and UDP together and never reissue an endpoint within this process.
fn allocate_addr(mut choose_ip: impl FnMut() -> IpAddr) -> SocketAddr {
    let mut allocated = ALLOCATED_ENDPOINTS.lock().unwrap();
    for _ in 0..128 {
        let ip = choose_ip();
        if let Ok(listener) = TcpListener::bind((ip, 0)) {
            let address = listener.local_addr().unwrap();
            if !allocated.contains(&address) && UdpSocket::bind(address).is_ok() {
                allocated.insert(address);
                return address;
            }
        }
    }
    panic!("failed to allocate a fresh TCP/UDP loopback endpoint after 128 probes");
}

fn get_random_addr() -> (String, u16) {
    #[cfg(target_vendor = "apple")]
    let address = allocate_addr(|| Ipv4Addr::LOCALHOST.into());
    #[cfg(not(target_vendor = "apple"))]
    let address = {
        use rand::RngExt;
        let mut rng = rand::rng();
        allocate_addr(|| {
            loop {
                let ip = Ipv4Addr::new(
                    127,
                    rng.random_range(0..=255),
                    rng.random_range(0..=255),
                    rng.random_range(1..=255),
                );
                if ip != Ipv4Addr::LOCALHOST {
                    break ip.into();
                }
            }
        })
    };
    (address.ip().to_string(), address.port())
}

fn get_random_udp_addr() -> (String, u16) {
    get_random_addr()
}

fn select_distinct_source(
    primary_ip: &str,
    mut allocate: impl FnMut() -> (String, u16),
) -> std::io::Result<(String, u16)> {
    for _ in 0..32 {
        let candidate = allocate();
        if candidate.0 != primary_ip {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        format!(
            "Unavailable prerequisite: alternate-source XUDP coverage requires two distinct \
             bindable local IPv4 addresses; the loopback allocator returned only {primary_ip} \
             in 32 attempts. Run this coverage on a host with distinct local loopback addresses \
             and the checksum-pinned sing-box peer; a different port on the same IP is insufficient."
        ),
    ))
}

/// Wait for an address (IP, port) to be ready for connections by attempting TCP connections.
/// Retries every 100ms for up to the specified timeout duration.
/// Returns Ok(()) if address becomes available, Err if timeout is reached.
async fn wait_for_addr(addr: SocketAddr, wait_timeout: Duration) -> std::io::Result<()> {
    let deadline = Instant::now() + wait_timeout;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Address {addr} did not become ready within {wait_timeout:?}"),
            ));
        }

        let remaining = deadline - now;
        if timeout(remaining, TcpStream::connect(addr))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            return Ok(());
        }

        // Wait a bit before retrying
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_source_selection_fails_after_bounded_attempts() {
        let mut attempts = 0;
        let error = select_distinct_source("127.0.0.1", || {
            attempts += 1;
            ("127.0.0.1".to_string(), 12345)
        })
        .unwrap_err();
        assert_eq!(attempts, 32);
        assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable);
        assert!(error.to_string().contains("Unavailable prerequisite"));
    }

    #[test]
    fn distinct_source_selection_preserves_alternate_ip() {
        let mut attempts = 0;
        let selected = select_distinct_source("127.0.0.1", || {
            attempts += 1;
            let ip = if attempts == 1 {
                "127.0.0.1"
            } else {
                "127.0.0.2"
            };
            (ip.to_string(), 12345)
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(selected, ("127.0.0.2".to_string(), 12345));
    }

    #[test]
    fn allocated_endpoints_support_tcp_and_udp() {
        let mut listeners = Vec::new();
        let mut sockets = Vec::new();
        for _ in 0..32 {
            let (ip, port) = get_random_addr();
            let addr = SocketAddr::new(ip.parse().unwrap(), port);
            assert!(addr.ip().is_loopback());
            assert_ne!(port, 0);
            #[cfg(target_vendor = "apple")]
            assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
            listeners.push(TcpListener::bind(addr).unwrap());
            sockets.push(UdpSocket::bind(addr).unwrap());
        }
    }

    #[test]
    fn concurrent_allocations_are_distinct_before_callers_bind() {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    (0..32)
                        .map(|_| {
                            let (ip, port) = get_random_addr();
                            SocketAddr::new(ip.parse().unwrap(), port)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let addresses: Vec<_> = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(addresses.iter().copied().collect::<HashSet<_>>().len(), 256);
        let mut listeners = Vec::new();
        let mut sockets = Vec::new();
        for address in addresses {
            listeners.push(TcpListener::bind(address).unwrap());
            sockets.push(UdpSocket::bind(address).unwrap());
        }
    }

    #[tokio::test]
    async fn readiness_only_waits_for_pending_listeners() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut ports = PortHelper::new();
        ports.listener_addrs.push(addr);

        ports.wait_for_all_ports().await.unwrap();
        drop(listener);

        ports.wait_for_all_ports().await.unwrap();
    }

    #[tokio::test]
    async fn readiness_uses_the_shared_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let wait_timeout = Duration::from_millis(25);
        let started = Instant::now();
        let error = wait_for_addr(addr, wait_timeout).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
