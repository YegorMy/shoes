//! Fail closed on every server record, not just known canaries or rustls targets.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub fixture_client: bool,
    pub level: String,
    pub target: String,
    pub message: String,
    pub formatted: String,
}

fn count(message: &str, prefix: &str, suffix: &str) -> bool {
    message
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
        .is_some_and(|s| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit()))
}

pub(super) fn fixture_record(event: &Event) -> Result<(), &'static str> {
    (event.target.starts_with("rustls::client::")
        || matches!(
            event.target.as_str(),
            "rustls::common_state" | "rustls::conn" | "shoes::tcp::tcp_client_handler_factory"
        ))
    .then_some(())
    .ok_or("unclassified fixture target")
}

pub(super) fn server_record(event: &Event, protected: &[String]) -> Result<(), &'static str> {
    let text = format!("{} {} {}", event.level, event.target, event.message);
    if protected.iter().any(|s| text.contains(s))
        || text.contains('\n')
        || text.contains('\r')
        || [
            "Payload",
            "DnsName(",
            "server_name:",
            "key_share:",
            "key_bytes",
            "ticket:",
            "nonce:",
            "session_id:",
            "verify_data:",
            "PRIVATE KEY",
        ]
        .iter()
        .any(|s| text.contains(s))
    {
        return Err("protected disclosure");
    }
    let m = event.message.as_str();
    let safe = match (event.level.as_str(), event.target.as_str()) {
        ("DEBUG", "rustls::server::hs") => {
            m == "ALPN protocol selected"
                || [
                    "TLS13_AES_256_GCM_SHA384",
                    "TLS13_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                ]
                .iter()
                .any(|suite| m == format!("decided upon suite {suite}"))
        }
        ("TRACE", "rustls::server::hs") => {
            matches!(m, "received client hello" | "Resolving server certificate")
        }
        ("TRACE", "rustls::server::server_conn") => m == "Accepted::client_hello() available",
        ("TRACE", "rustls::server::tls13::client_hello") => matches!(
            m,
            "sending server hello"
                | "requesting hello retry"
                | "sending encrypted extensions"
                | "sending certificate request"
                | "sending certificate"
                | "sending compressed certificate"
                | "sending certificate verify"
                | "sending finished"
        ),
        ("TRACE", "rustls::server::tls13") => matches!(
            m,
            "sending new ticket (stateless: false)"
                | "sending new ticket (stateless: true)"
                | "resumption not available; not issuing ticket"
                | "client CertificateVerify OK"
        ),
        ("TRACE", "rustls::server::tls12" | "rustls::server::tls12::client_hello") => {
            matches!(
                m,
                "supported EC point formats received"
                    | "sending server hello"
                    | "sending certificate request"
                    | "client CertificateVerify OK"
            ) || count(m, "received client certificate chain (count: ", ")")
        }
        ("DEBUG", "rustls::server::tls12" | "rustls::server::tls12::client_hello") => matches!(
            m,
            "Ticket received"
                | "Ticket didn't decrypt"
                | "Resuming connection"
                | "Session saved"
                | "Session not saved"
        ),
        ("TRACE", "rustls::conn") => m == "Dropping CCS",
        ("DEBUG", "rustls::common_state") => m == "Sending warning alert CloseNotify",
        ("WARN", "rustls::msgs::handshake") => matches!(
            m,
            "Illegal SNI hostname received"
                | "Illegal SNI extension: ignoring IP address presented as hostname"
        ),
        ("TRACE", "rustls::webpki::anchors") => m == "invalid trust anchor certificate",
        ("DEBUG", "rustls::webpki::anchors") => {
            m == "certificate parsing failed"
                || m.strip_prefix("add_parsable_certificates processed ")
                    .and_then(|s| s.split_once(" valid and "))
                    .is_some_and(|(valid, rest)| {
                        count(valid, "", "") && count(rest, "", " invalid certs")
                    })
        }
        ("DEBUG", "shoes::tcp::tcp_server::startup") => m == "TCP handler initialized",
        ("DEBUG", "shoes::rustls_config_util") => {
            count(m, "TLS server config: loaded ", " certificate(s) in chain")
        }
        ("WARN", "shoes::shadow_tls::shadow_tls_server_handler") => {
            m == "ShadowTLS authentication failed, falling back to handshake server (kind=PermissionDenied)"
        }
        ("DEBUG", "shoes::shadow_tls::shadow_tls_server_handler") => {
            matches!(
                m,
                "SHADOWTLS FALLBACK: Connecting to handshake server"
                    | "SHADOWTLS FALLBACK: ClientHello forwarded, spawning bidirectional copy"
                    | "SHADOWTLS FALLBACK: Connection completed"
            ) || count(
                m,
                "SHADOWTLS FALLBACK: Connected, forwarding ClientHello (",
                " bytes)",
            )
        }
        ("DEBUG", "shoes::tcp::tcp_server::listener") => {
            m == "TCP connection finished successfully"
        }
        ("ERROR", "shoes::tcp::tcp_server::listener") => [
            "InvalidData",
            "PermissionDenied",
            "Other",
            "UnexpectedEof",
            "ConnectionReset",
            "ConnectionRefused",
        ]
        .iter()
        .any(|kind| m == format!("TCP connection finished with error (kind={kind})")),
        ("DEBUG", "shoes::client_proxy_selector") => m == "Found matching routing rule",
        ("DEBUG", "shoes::tcp::tcp_server") => m == "session refused by embedder hooks",
        ("DEBUG", "shoes::client_proxy_chain") => matches!(
            m,
            "Chain TCP complete: 1 total hop(s)"
                | "Chain TCP connect: 1 initial + 0 subsequent hop(s)"
                | "Initial hop: Direct"
        ),
        ("DEBUG", "tls_privacy_control") => {
            m == "debug collector active" || m == "server rejection observed"
        }
        ("TRACE", "tls_privacy_control") => m == "trace collector active",
        _ => false,
    };
    safe.then_some(())
        .ok_or("unclassified diagnostic (not necessarily a disclosure)")
}

pub(super) fn startup(line: &str, configured_bind: &str) -> bool {
    // Exact stdout context only. No prefix/suffix/extra fields, no other binds.
    line == format!("Starting ShadowTLSv3 TCP server at {configured_bind}")
}

pub(super) fn cli_channels(
    stdout: &str,
    stderr: &str,
    file: &str,
    protected: &[String],
    expected_stdout: &str,
    expected_error: &str,
) -> Result<(), &'static str> {
    if stdout != expected_stdout || stderr != format!("{file}{expected_error}") {
        return Err("unclassified CLI process output or inconsistent log channels");
    }
    if [stdout, stderr, file]
        .iter()
        .any(|channel| protected.iter().any(|value| channel.contains(value)))
    {
        return Err("protected CLI disclosure");
    }
    if !file.is_empty() && !file.ends_with('\n') {
        return Err("incomplete CLI file capture");
    }
    for line in file.lines() {
        let (header, message) = line
            .strip_prefix('[')
            .and_then(|s| s.split_once("] "))
            .ok_or("malformed or multiline CLI record")?;
        let mut header = header.split(' ');
        let timestamp = header.next().ok_or("missing CLI timestamp")?;
        chrono::NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.3f")
            .map_err(|_| "invalid CLI timestamp")?;
        let level = header.next().ok_or("missing CLI level")?;
        let target = header.next().ok_or("missing CLI target")?;
        if header.next().is_some()
            || !matches!(
                (level, target, message),
                ("TRACE", "shoes", "Loading server configuration")
                    | ("DEBUG", "shoes", "Server configuration loaded")
                    | ("DEBUG", "shoes", "Server configuration validated")
                    | ("DEBUG", "shoes::config::pem", "Reading PEM file")
            )
        {
            return Err("unclassified CLI diagnostic");
        }
    }
    Ok(())
}

#[test]
fn cli_guard_rejects_complete_channel_injections() {
    let safe = "[2026-10-19T12:34:56.789 DEBUG shoes] Server configuration loaded\n";
    let protected = vec!["cli-protected-path-canary".to_owned()];
    assert!(cli_channels("", safe, safe, &protected, "", "").is_ok());
    for injection in [
        "cli-protected-path-canary",
        "[2026-10-19T12:34:56.789 DEBUG shoes] Server configuration loaded extra-secret\n",
        "[2026-10-19T12:34:56.789 DEBUG shoes peer=192.0.2.171] Server configuration loaded\n",
        "[2026-10-19T12:34:56.789 DEBUG shoes::config::pem] Reading PEM file: /unknown/credential.pem\n",
        "[2026-10-19T12:34:56.789 DEBUG unrelated] Server configuration loaded\n",
        "ClientHelloPayload {\n server_name: unknown.private.invalid\n}\n",
        "NewSessionTicketPayloadTls13 {\n ticket: aabb\n}\n",
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41973 peer=192.0.2.171\n",
    ] {
        assert!(cli_channels(injection, safe, safe, &protected, "", "").is_err());
        assert!(cli_channels("", &format!("{safe}{injection}"), safe, &protected, "", "").is_err());
        assert!(cli_channels("", injection, injection, &protected, "", "").is_err());
    }
}

#[test]
fn guard_rejects_protected_records_and_invalid_startup_contexts() {
    let protected = vec!["distinct-sni.private.invalid".to_owned()];
    let mut event = Event {
        fixture_client: false,
        level: "TRACE".into(),
        target: "rustls::server::hs".into(),
        message: "received client hello".into(),
        formatted: String::new(),
    };
    assert!(server_record(&event, &protected).is_ok());
    for message in [
        "distinct-sni.private.invalid",
        "peer=192.0.2.171:49171",
        "destination=198.51.100.172:49172",
        "dns=query-canary.private.invalid",
        "password=credential-canary",
        "key=key-canary",
        "application-payload-canary",
        "arbitrary error: private details",
        "ClientHelloPayload { random: 17 }",
        "ServerHello {\n key_share: [1, 2, 3]\n}",
        "Finished {\n verify_data: aabb\n}",
        "CertificateVerify {\n signature: aabb\n}",
        "NewSessionTicketPayloadTls13 {\n nonce: aabb,\n ticket: ccdd\n}",
        "received client hello extra-secret",
        "sending new ticket (stateless: false)\nticket bytes: aabb",
    ] {
        event.message = message.into();
        assert!(
            server_record(&event, &protected).is_err(),
            "guard admitted {message:?}"
        );
        event.target = "unrelated::dependency".into();
        assert!(server_record(&event, &protected).is_err());
        for target in [
            "rustls::server::tls13::client_hello",
            "rustls::server::tls13",
            "rustls::server::tls12::client_hello",
        ] {
            event.target = target.into();
            assert!(
                server_record(&event, &protected).is_err(),
                "guard admitted {target}: {message:?}"
            );
        }
        event.target = "rustls::server::hs".into();
    }
    let bind = "127.0.0.1:41973";
    assert!(startup(
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41973",
        bind
    ));
    for line in [
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41974",
        "Starting ShadowTLSv3 TCP server at 0.0.0.0:41973",
        "Starting ShadowTLSv3 TCP server at [::1]:41973",
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41973 peer=192.0.2.171:49171",
        "Starting ShadowTLSv3 TCP server at 127.0.0.1:41973\nsecret",
        "DEBUG Starting ShadowTLSv3 TCP server at 127.0.0.1:41973",
        "Connected ShadowTLSv3 TCP server at 127.0.0.1:41973",
        "Starting SOCKS TCP server at 127.0.0.1:41973",
    ] {
        assert!(!startup(line, bind), "invalid bind allowance: {line:?}");
    }
    event.message = format!("Starting ShadowTLSv3 TCP server at {bind}");
    event.target = "shoes::tcp::tcp_server::startup".into();
    event.level = "DEBUG".into();
    assert!(
        server_record(&event, &[]).is_err(),
        "startup is not a log/traffic allowance"
    );
}
