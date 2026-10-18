# Traffic-facing TLS and embedding security constraints

These rules preserve the supplied source/privacy task, rather than claim a whole
process security audit. They apply to the traffic-facing listener, embedding and
TLS diagnostics being validated. Known unexercised startup drift is recorded
below and in `arch-index.md`; it is not silently accepted or a new write grant.

### SEC-01: Keep useful live diagnostics without protected traffic content

Keep DEBUG/TRACE collectors and relevant targets active on the real listener/TLS
path while emitting bounded lifecycle, status and error-kind events. Never
serialize SNI/device identifiers, client/peer/forwarded/destination addresses,
DNS names, credentials, keys, application payloads or arbitrary secret-bearing
error text. Do not obtain privacy by lowering levels, disabling loggers/targets,
filtering/redacting observers or suppressing stdout/stderr. Sources:
`tests/listener_logging.rs`, `tests/listener_logging/tls.rs`,
`src/tcp/tcp_server/listener.rs`, source-task problem and acceptance scenarios.

### SEC-02: Limit startup-bind output to its exact configured context

Permit only the explicitly configured listener bind address/port in the exact
startup context under evaluation. The allowance does not extend to connection
records, another address, prefix/suffix/extra fields or arbitrary protocol/config
objects. Preserve stricter consumer observation/assertion behavior; a later
consumer grammar change needs separate authority. Sources:
`tests/listener_logging/tls_guard.rs::startup`, its invalid-context controls,
original source/infra privacy boundaries.

### SEC-03: Keep raw TLS handshake and ticket objects out of diagnostics

In maintained `vendor/rustls` server `hs`, `tls12`, `tls13` and `server_conn`
paths, retain bounded useful events rather than formatting ClientHello,
ServerHello, Finished, certificate-verify, ticket/session, key-share or other raw
handshake objects. Check raw and multiline representations across every complete
channel, not only familiar canary strings or a single target. Preserve licenses,
package/API identity and wire processing. Sources: maintained rustls server files,
`vendor/rustls/src/msgs/handshake.rs`, source task and TLS guard negative controls.

### SEC-04: Attribute fixture records without hiding their bytes

Preserve all raw collector/stdout/stderr bytes and distinguish demonstrably
fixture-only client events from actual server output. A benign bounded rustls
status is not automatically a disclosure, and an unclassified diagnostic is not
automatically safe. Keep positive live-event controls and injected protected,
multiline, extra-field and wrong-context negative controls. Sources:
`tests/listener_logging/tls.rs::Writer`, `tls_guard.rs::server_record` and
source-task guard/attribution requirements. This is observation attribution,
never permission for blanket target filtering.

### SEC-05: Preserve ShadowTLS certificate, name and fingerprint enforcement

Complete real TLS 1.3 certificate/signature/Finished verification before starting
the ShadowTLS inner protocol. With `verify: true`, retain platform trust/name
verification and any configured SHA-256 pins together. With `verify: false`,
require a nonempty pin list and authenticate the exact pinned certificate.
Reject missing/invalid required names and fail closed if platform verifier
initialization fails. Preserve the documented Apple Security.framework/SystemRoots
obligation; do not replace it with unchecked or bundled-root fallback. Sources:
`CONFIG.md`, `src/config/validate.rs`, `src/rustls_config_util/shadowtls.rs`,
`tests/cases/integration/shadowtls_cert_verification.rs` and source-task trust rules.
Local source inspection is not physical-iPhone trust proof.

### SEC-06: Keep authentication, revocation and outbound policy effective

Retain credential refusal, per-device/session independence and cancellation while
removing unsafe formatting. Preserve `open_session` decisions before connection,
configured routing rules and `check_outbound` for the actual resolved destination.
Do not turn a logging fix into an authentication bypass, policy change or consumer
callback/projection decision. Sources: `src/embedding.rs`, TLS/ShadowTLS handlers,
listener/hook regressions and source-task compatibility/anti-regression clauses.

### SEC-07: Retain ShadowTLS wire and inner-protocol behavior

Keep the maintained ClientHello session-ID signing hook before transcript hashing,
TLS 1.3 and current ShadowTLS v3/inner Shadowsocks semantics. Do not enable
resumption, early data, ECH, QUIC or HelloRetryRequest on this path to resolve
diagnostic failures. Preserve configured UDP support/refusal and separate EOF
semantics. Sources: `CONFIG.md`, `src/shadow_tls/shadow_tls_client_handler.rs`,
`src/rustls_config_util/shadowtls.rs`, source-task compatibility requirements.
Same-engine loopback cannot prove independent wire compatibility.

### SEC-08: Keep observed privacy drift visible and scope-bound

Report unsafe-looking source outside the exercised listener fixture with its
actual attribution and unanswered questions. In particular, `src/main.rs` currently
Debug-formats full loaded configuration objects before server startup. This
standalone binary path was not exercised by the embedded TLS fixture or remedied
by this task. Do not infer a blanket whole-process privacy guarantee, erase this
observation, or expand source writes without the actual prospective task grant.
Likewise, internal errors containing names are not proof of observed output
until their diagnostic path is established. Sources: direct `src/main.rs` read,
`src/tls_server_handler.rs`, source-task narrow remedy and scope rules.
