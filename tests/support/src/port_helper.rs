//! Port allocation and readiness helper for tests
//!
//! Provides centralized port allocation with tracking and synchronization.
//! All tests should use PortHelper instead of directly allocating ports.

use rand::RngExt;
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
    /// Uses localhost on Darwin and random 127/8 IPs elsewhere.
    /// This address will be tracked and waited for in wait_for_all_ports().
    pub fn get_listener_port(&mut self) -> (String, u16) {
        let (ip, port) = get_random_addr();
        self.listener_addrs
            .push(format!("{ip}:{port}").parse().unwrap());
        (ip, port)
    }

    /// Keep both protocols bound until an in-process server takes ownership.
    pub fn get_listener_endpoint(&mut self) -> OwnedEndpoint {
        let endpoint = get_random_endpoint();
        self.listener_addrs.push(endpoint.local_addr());
        endpoint
    }

    pub fn get_localhost_listener_endpoint(&mut self) -> OwnedEndpoint {
        let endpoint = allocate_endpoint(|| Ipv4Addr::LOCALHOST.into());
        self.listener_addrs.push(endpoint.local_addr());
        endpoint
    }

    pub fn get_ipv6_listener_endpoint(&mut self) -> OwnedEndpoint {
        let endpoint = allocate_endpoint(|| Ipv6Addr::LOCALHOST.into());
        self.listener_addrs.push(endpoint.local_addr());
        endpoint
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

/// Exclusively owns TCP and UDP at one address; dropping it closes both sockets.
/// Conversion transfers the selected handle and drops the unused counterpart.
#[must_use = "the endpoint stays reserved only while its owner is retained"]
pub struct OwnedEndpoint {
    address: SocketAddr,
    listener: TcpListener,
    socket: UdpSocket,
}

impl OwnedEndpoint {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn into_sockets(self) -> (TcpListener, UdpSocket) {
        (self.listener, self.socket)
    }

    pub fn into_tcp_listener(self) -> std::io::Result<tokio::net::TcpListener> {
        self.listener.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(self.listener)
    }

    pub fn into_udp_socket(self) -> std::io::Result<tokio::net::UdpSocket> {
        self.socket.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(self.socket)
    }
}

/// Share bounded selection and permanent non-reissue with legacy raw candidates.
fn allocate_endpoint(mut choose_ip: impl FnMut() -> IpAddr) -> OwnedEndpoint {
    let mut allocated = ALLOCATED_ENDPOINTS.lock().unwrap();
    let mut rng = rand::rng();
    for _ in 0..128 {
        // Check before probing: bind(ip, 0) can temporarily own an issued endpoint
        // while its caller is about to bind. Avoid the usual ephemeral range too.
        let address = SocketAddr::new(choose_ip(), rng.random_range(1024..32768));
        if allocated.contains(&address) {
            continue;
        }
        if let Ok(listener) = TcpListener::bind(address)
            && let Ok(socket) = UdpSocket::bind(address)
        {
            allocated.insert(address);
            return OwnedEndpoint {
                address,
                listener,
                socket,
            };
        }
    }
    panic!("failed to allocate a fresh TCP/UDP loopback endpoint after 128 probes");
}

/// Legacy candidates are unreserved once returned; external children bind them.
fn allocate_addr(choose_ip: impl FnMut() -> IpAddr) -> SocketAddr {
    allocate_endpoint(choose_ip).local_addr()
}

fn get_random_endpoint() -> OwnedEndpoint {
    #[cfg(target_vendor = "apple")]
    let endpoint = allocate_endpoint(|| Ipv4Addr::LOCALHOST.into());
    #[cfg(not(target_vendor = "apple"))]
    let endpoint = {
        let mut rng = rand::rng();
        allocate_endpoint(|| {
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
    endpoint
}

fn get_random_addr() -> (String, u16) {
    let address = get_random_endpoint().local_addr();
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
    use std::io::{Read, Write};

    fn assert_pair_usable(listener: &TcpListener, socket: &UdpSocket, address: SocketAddr) {
        assert_eq!(listener.local_addr().unwrap(), address);
        assert_eq!(socket.local_addr().unwrap(), address);
        let limit = Duration::from_secs(2);
        let mut client = std::net::TcpStream::connect_timeout(&address, limit).unwrap();
        client.set_read_timeout(Some(limit)).unwrap();
        client.write_all(b"tcp owned request").unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        accepted.set_read_timeout(Some(limit)).unwrap();
        let mut request = [0; 17];
        accepted.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"tcp owned request");
        accepted.write_all(b"tcp response").unwrap();
        let mut response = [0; 12];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"tcp response");
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(accepted.read(&mut [0]).unwrap(), 0);
        drop(accepted);
        assert_eq!(client.read(&mut [0]).unwrap(), 0);

        let client = UdpSocket::bind(SocketAddr::new(address.ip(), 0)).unwrap();
        client.set_read_timeout(Some(limit)).unwrap();
        socket.set_read_timeout(Some(limit)).unwrap();
        client.send_to(b"udp request", address).unwrap();
        let mut buffer = [0; 32];
        let (length, peer) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
        assert_eq!(&buffer[..length], b"udp request");
        socket.send_to(b"udp response", peer).unwrap();
        let (length, source) = client.recv_from(&mut buffer).unwrap();
        assert_eq!(source, address);
        assert_eq!(&buffer[..length], b"udp response");
    }

    fn assert_unclaimed(address: SocketAddr) {
        let listener = TcpListener::bind(address).unwrap();
        let socket = UdpSocket::bind(address).unwrap();
        assert_eq!(listener.local_addr().unwrap(), address);
        assert_eq!(socket.local_addr().unwrap(), address);
    }

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
        let mut endpoints = Vec::new();
        for _ in 0..32 {
            let endpoint = get_random_endpoint();
            let addr = endpoint.local_addr();
            assert!(addr.ip().is_loopback());
            assert_ne!(addr.port(), 0);
            #[cfg(target_vendor = "apple")]
            assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
            assert_pair_usable(&endpoint.listener, &endpoint.socket, addr);
            endpoints.push(endpoint);
        }
    }

    #[test]
    fn probed_endpoint_can_be_claimed_before_delayed_caller_bind() {
        let (ip, port) = get_random_addr();
        let address = SocketAddr::new(ip.parse().unwrap(), port);
        let (tcp_owner, udp_owner) = std::thread::spawn(move || {
            (
                TcpListener::bind(address).unwrap(),
                UdpSocket::bind(address).unwrap(),
            )
        })
        .join()
        .unwrap();
        assert_eq!(tcp_owner.local_addr().unwrap(), address);
        assert_eq!(udp_owner.local_addr().unwrap(), address);
        let tcp_error = TcpListener::bind(address).unwrap_err();
        let udp_error = UdpSocket::bind(address).unwrap_err();
        assert_eq!(tcp_error.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(udp_error.kind(), std::io::ErrorKind::AddrInUse);
        println!("Controlled competing TCP/UDP owners claimed the returned unbound endpoint");
    }

    #[test]
    fn concurrent_owned_endpoints_survive_delayed_handoff() {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| (0..32).map(|_| get_random_endpoint()).collect::<Vec<_>>())
            })
            .collect();
        let endpoints: Vec<_> = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect();
        let addresses: Vec<_> = endpoints.iter().map(OwnedEndpoint::local_addr).collect();
        assert_eq!(addresses.iter().copied().collect::<HashSet<_>>().len(), 256);
        std::thread::sleep(Duration::from_millis(25));
        let competing_addresses = addresses.clone();
        std::thread::spawn(move || {
            for address in competing_addresses {
                assert!(address.ip().is_loopback());
                assert_ne!(address.port(), 0);
                assert_eq!(
                    TcpListener::bind(address).unwrap_err().kind(),
                    std::io::ErrorKind::AddrInUse
                );
                assert_eq!(
                    UdpSocket::bind(address).unwrap_err().kind(),
                    std::io::ErrorKind::AddrInUse
                );
            }
        })
        .join()
        .unwrap();
        let mut pairs = Vec::new();
        for endpoint in endpoints {
            let address = endpoint.local_addr();
            #[cfg(unix)]
            let original = {
                use std::os::fd::AsRawFd;
                (endpoint.listener.as_raw_fd(), endpoint.socket.as_raw_fd())
            };
            let (listener, socket) = endpoint.into_sockets();
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                assert_eq!((listener.as_raw_fd(), socket.as_raw_fd()), original);
            }
            assert_pair_usable(&listener, &socket, address);
            pairs.push((listener, socket));
        }
        drop(pairs);
        for address in addresses {
            assert_unclaimed(address);
            assert!(ALLOCATED_ENDPOINTS.lock().unwrap().contains(&address));
        }
    }

    #[test]
    fn dropped_owned_endpoints_release_both_protocols_without_reissue() {
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let endpoint = allocate_endpoint(|| ip);
            let address = endpoint.local_addr();
            assert_eq!(address.ip(), ip);
            drop(endpoint);
            assert_unclaimed(address);
            let next = allocate_endpoint(|| ip);
            assert_ne!(next.local_addr(), address);
            assert!(ALLOCATED_ENDPOINTS.lock().unwrap().contains(&address));
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
