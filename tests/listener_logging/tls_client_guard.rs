//! Fail closed on every client record: a closed grammar of bounded lifecycle,
//! status and error-kind messages. Anything else is a disclosure or unclassified.
use super::super::guard::Event;

// Debug renderings of handshake structures, certificates, tickets and keys.
// The closed grammar below rejects them too; this names the disclosure.
const STRUCTURES: &[&str] = &[
    "ClientHelloPayload",
    "ServerHelloPayload",
    "HelloRetryRequest {",
    "HelloRetryExtensions",
    "ServerExtensions",
    "CertificatePayload",
    "CertificateRequestPayload",
    "CertificateDer",
    "DistinguishedName",
    "PresharedKey",
    "Payload(",
    "PayloadU8",
    "PayloadU16",
    "DnsName(",
    "server_name:",
    "key_share",
    "session_id:",
    "identities:",
    "ticket:",
    "nonce:",
    "verify_data:",
    "public_name",
    "BEGIN CERTIFICATE",
    "PRIVATE KEY",
];

const SUITES: &[&str] = &[
    "TLS13_AES_128_GCM_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
];

const GROUPS: &[&str] = &["X25519", "secp256r1", "secp384r1", "X25519MLKEM768"];

const ECH_SUITE: &str = "HpkeSuite { kem: DHKEM_X25519_HKDF_SHA256, sym: HpkeSymmetricCipherSuite { kdf_id: HKDF_SHA256, aead_id: AES_128_GCM } }";

const KINDS: &[&str] = &[
    "InvalidData",
    "UnexpectedEof",
    "ConnectionReset",
    "ConnectionAborted",
    "BrokenPipe",
    "PermissionDenied",
    "Other",
];

/// Exact template match. `{n}` is a bounded count, `{b}` a boolean and `{k}`
/// an I/O error kind; every other byte must match literally.
fn fits(message: &str, template: &str) -> bool {
    let Some((literal, rest)) = template.split_once('{') else {
        return message == template;
    };
    let Some(message) = message.strip_prefix(literal) else {
        return false;
    };
    let (hole, rest) = rest.split_once('}').expect("closed template hole");
    let valid = |value: &str| match hole {
        "n" => value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit()),
        "b" => matches!(value, "true" | "false"),
        "k" => KINDS.contains(&value),
        _ => panic!("unknown template hole {hole}"),
    };
    (1..=message.len().min(32))
        .rev()
        .filter(|&end| message.is_char_boundary(end))
        .any(|end| valid(&message[..end]) && fits(&message[end..], rest))
}

pub(super) fn client_record(event: &Event, protected: &[String]) -> Result<(), &'static str> {
    let text = format!("{} {} {}", event.level, event.target, event.message);
    if protected.iter().any(|s| text.contains(s.as_str())) {
        return Err("protected disclosure");
    }
    if text.contains(['\n', '\r']) {
        return Err("multiline record");
    }
    if STRUCTURES.iter().any(|s| text.contains(s)) {
        return Err("handshake structure disclosure");
    }
    let m = event.message.as_str();
    let safe = match (event.level.as_str(), event.target.as_str()) {
        ("DEBUG", "rustls::client::hs") => {
            matches!(
                m,
                "Resuming session"
                    | "Not resuming any session"
                    | "No cached session"
                    | "ALPN protocol selected"
                    | "No ALPN protocol selected"
            ) || SUITES
                .iter()
                .any(|suite| m == format!("Using ciphersuite {suite}"))
        }
        ("TRACE", "rustls::client::hs") => {
            matches!(m, "Sending ClientHello" | "We got ServerHello" | "Got HRR")
        }
        ("DEBUG", "rustls::client::tls13") => matches!(
            m,
            "Resuming using PSK"
                | "Not resuming"
                | "TLS1.3 encrypted extensions received"
                | "Got CertificateRequest"
        ),
        ("TRACE", "rustls::client::tls13") => {
            fits(m, "Server certificate chain received (count: {n})")
        }
        ("DEBUG", "rustls::client::tls12::server_hello") => matches!(
            m,
            "Server supports tickets"
                | "Server may staple OCSP response"
                | "Server agreed to resume"
        ),
        ("DEBUG", "rustls::client::tls12") => {
            matches!(
                m,
                "Got CertificateRequest"
                    | "Verifying server certificate for configured server name"
                    | "Session not saved: server didn't allocate id or ticket"
            ) || GROUPS.iter().any(|group| {
                m == format!(
                    "ECDHE curve is EcParameters {{ curve_type: NamedCurve, named_group: {group} }}"
                )
            })
        }
        ("TRACE", "rustls::client::tls12") => {
            m == "Server stapled OCSP response received"
                || fits(m, "Server certificate chain received (count: {n})")
        }
        ("DEBUG", "rustls::client::common") => matches!(
            m,
            "Attempting client auth" | "Client auth requested but no cert/sigscheme available"
        ),
        ("DEBUG", "rustls::client::ech") => m
            .strip_prefix("selected ECH config ID ")
            .and_then(|rest| rest.split_once(" suite "))
            .is_some_and(|(id, suite)| fits(id, "{n}") && suite == ECH_SUITE),
        ("TRACE", "rustls::client::ech") => matches!(
            m,
            "Preparing ECH offer " | "ECH Inner Hello prepared" | "ECH rejected by server"
        ),
        ("TRACE", "rustls::webpki::server_verifier") => m == "Unvalidated OCSP response present",
        ("TRACE", "rustls::client::client_conn") => m == "EarlyData rejected",
        ("DEBUG", "rustls::common_state") => m == "Sending warning alert CloseNotify",
        ("TRACE", "rustls::conn") => m == "Dropping CCS",
        ("DEBUG", "shoes::crypto::crypto_handshake") => [
            "TLS handshake starting",
            "TLS handshake: EOF from peer",
            "TLS handshake: read and processed {n} bytes",
            "TLS handshake iteration {n} done: eof={b}, is_handshaking={b}, wants_write={b}",
            "TLS handshake: complete but has pending writes, continuing",
            "TLS handshake complete after {n} iterations",
            "TLS handshake complete (early exit) after {n} iterations",
            "TLS handshake continuing to iteration {n}",
            "TLS: read {n} bytes from peer",
            "TLS: processed packets successfully",
            "TLS: sending last-gasp alert ({n} bytes) before closing",
        ]
        .iter()
        .any(|template| fits(m, template)),
        ("TRACE", "shoes::crypto::crypto_handshake") => fits(
            m,
            "TLS handshake iteration {n}: is_handshaking={b}, wants_read={b}, wants_write={b}",
        ),
        ("ERROR", "shoes::crypto::crypto_handshake") => {
            fits(m, "TLS error processing packets (kind={k})")
        }
        ("DEBUG", "shoes::tcp::tcp_client_handler_factory") => {
            m == "Using default sni hostname for TLS client connection"
        }
        ("DEBUG", "shoes::tcp::proxy_connector_impl") => m == "[ProxyConnector] setup_tcp_stream",
        ("DEBUG", "shoes::client_proxy_chain") => matches!(
            m,
            "Chain TCP connect: 1 initial + 0 subsequent hop(s)"
                | "Initial hop: Proxy"
                | "Chain TCP complete: 1 total hop(s)"
        ),
        ("DEBUG", "shoes::client_proxy_selector") => m == "Found matching routing rule",
        ("DEBUG", "shoes::tcp::tcp_server::startup") => m == "TCP handler initialized",
        ("DEBUG", "shoes::tcp::tcp_server::listener") => {
            m == "TCP connection finished successfully"
        }
        ("DEBUG", "tls_privacy_control") => {
            matches!(m, "debug collector active" | "client rejection observed")
        }
        ("TRACE", "tls_privacy_control") => m == "trace collector active",
        _ => false,
    };
    safe.then_some(())
        .ok_or("unclassified diagnostic (not necessarily a disclosure)")
}

pub(super) fn startup(line: &str, configured_bind: &str) -> bool {
    // Exact stdout context only. No prefix/suffix/extra fields, no other binds.
    line == format!("Starting SOCKS TCP server at {configured_bind}")
}

#[test]
fn client_guard_admits_bounded_lifecycle_and_rejects_disclosures() {
    let protected = vec!["distinct-sni.client-guard.invalid".to_owned()];
    let mut event = Event {
        fixture_client: false,
        level: "TRACE".into(),
        target: "rustls::client::hs".into(),
        message: "Sending ClientHello".into(),
        formatted: String::new(),
    };
    assert!(client_record(&event, &protected).is_ok());
    for (level, target, message) in [
        (
            "DEBUG",
            "rustls::client::hs",
            "Using ciphersuite TLS13_AES_256_GCM_SHA384",
        ),
        (
            "TRACE",
            "rustls::client::tls13",
            "Server certificate chain received (count: 2)",
        ),
        (
            "DEBUG",
            "shoes::crypto::crypto_handshake",
            "TLS handshake complete after 3 iterations",
        ),
        (
            "ERROR",
            "shoes::crypto::crypto_handshake",
            "TLS error processing packets (kind=InvalidData)",
        ),
        (
            "TRACE",
            "shoes::crypto::crypto_handshake",
            "TLS handshake iteration 1: is_handshaking=true, wants_read=false, wants_write=true",
        ),
    ] {
        event.level = level.into();
        event.target = target.into();
        event.message = message.into();
        assert!(client_record(&event, &protected).is_ok(), "{message}");
    }
    for (level, target, message) in [
        (
            "DEBUG",
            "rustls::client::hs",
            "No cached session for DnsName(\"distinct-sni.client-guard.invalid\")",
        ),
        (
            "DEBUG",
            "rustls::client::hs",
            "distinct-sni.client-guard.invalid",
        ),
        (
            "TRACE",
            "rustls::client::hs",
            "Sending ClientHello ClientHelloPayload {\n    random: 17,\n}",
        ),
        (
            "TRACE",
            "rustls::client::hs",
            "We got ServerHello ServerHelloPayload { key_share: [1, 2] }",
        ),
        (
            "TRACE",
            "rustls::client::hs",
            "Got HRR HelloRetryRequest { session_id: aabb }",
        ),
        (
            "TRACE",
            "rustls::client::tls13",
            "Server cert is [CertificateDer(0x3082)]",
        ),
        (
            "TRACE",
            "rustls::client::tls13",
            "Server certificate chain received (count: 2a)",
        ),
        (
            "TRACE",
            "rustls::client::tls13",
            "Server certificate chain received (count: 12345678901)",
        ),
        (
            "DEBUG",
            "rustls::client::tls13",
            "TLS1.3 encrypted extensions: ServerExtensions { .. }",
        ),
        (
            "DEBUG",
            "rustls::client::tls13",
            "Got CertificateRequest CertificateRequestPayloadTls13 { .. }",
        ),
        (
            "DEBUG",
            "rustls::client::tls12",
            "Server DNS name is DnsName(\"x\")",
        ),
        (
            "TRACE",
            "rustls::client::tls12",
            "Server stapled OCSP response is [1, 2, 3]",
        ),
        (
            "DEBUG",
            "rustls::client::hs",
            "ALPN protocol is Some(private-alpn)",
        ),
        (
            "DEBUG",
            "rustls::client::ech",
            "selected ECH config ID 7 suite x public_name DnsName(\"p\")",
        ),
        (
            "TRACE",
            "rustls::client::ech",
            "ECH Inner Hello: ClientHelloPayload { .. }",
        ),
        (
            "TRACE",
            "rustls::webpki::server_verifier",
            "Unvalidated OCSP response: [1, 2]",
        ),
        (
            "ERROR",
            "shoes::crypto::crypto_handshake",
            "TLS error processing packets: invalid peer certificate",
        ),
        (
            "ERROR",
            "shoes::crypto::crypto_handshake",
            "TLS error processing packets (kind=NotValidForName)",
        ),
        (
            "DEBUG",
            "shoes::crypto::crypto_handshake",
            "TLS handshake complete after many iterations",
        ),
        (
            "DEBUG",
            "shoes::tcp::tcp_client_handler_factory",
            "Using default sni hostname for TLS client connection: x",
        ),
        (
            "DEBUG",
            "shoes::tcp::proxy_connector_impl",
            "[ProxyConnector] setup_tcp_stream: a -> b",
        ),
        ("DEBUG", "unrelated::dependency", "Sending ClientHello"),
        ("INFO", "rustls::client::hs", "Sending ClientHello"),
        (
            "TRACE",
            "rustls::client::hs",
            "Sending ClientHello\nserver_name: x",
        ),
        (
            "TRACE",
            "rustls::client::hs",
            "Sending ClientHello extra-secret",
        ),
    ] {
        event.level = level.into();
        event.target = target.into();
        event.message = message.into();
        assert!(
            client_record(&event, &protected).is_err(),
            "guard admitted {level} {target}: {message:?}"
        );
    }
    assert!(startup(
        "Starting SOCKS TCP server at 127.0.0.1:41973",
        "127.0.0.1:41973"
    ));
    for line in [
        "Starting SOCKS TCP server at 127.0.0.1:41974",
        "Starting SOCKS TCP server at 127.0.0.1:41973 peer=192.0.2.171:49171",
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41973",
    ] {
        assert!(!startup(line, "127.0.0.1:41973"), "{line}");
    }
}
