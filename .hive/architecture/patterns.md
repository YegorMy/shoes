# Runtime patterns to retain

### PAT-01: Distinguish a successful empty datagram from message EOF

After a successful empty `poll_read_message`, consult `is_message_eof()` before
ending a relay. Do not consult it after pending/error. Preserve native UDP's
non-EOF behavior, UoT V2/VLESS zero-length frame payloads, boxed/borrowed forwarding
and the default legacy behavior of other implementations. Keep partial-frame EOF
an I/O error and retain empty packets across pending writes and activity tracking.
Sources: `README.md` "Embedded message reads", `src/async_stream.rs`,
`src/copy_bidirectional_message.rs`, `src/async_stream/sockets.rs`,
`src/tcp/socket_connector_impl/unconnected_udp.rs` and relay tests.

### PAT-02: Keep session acceptance, revocation and completion independent

Honor `ServerHooks::open_session` before an outbound operation, including refusal
and the defined fallback behavior. Preserve `SessionGrant` cancellation ending
the session and its connections, and `with_done` signaling only after the last
grant/session owner is released. Do not log the credential, target or identity to
demonstrate these transitions. Hooks execute on connection tasks and must remain
nonblocking. Sources: `src/embedding.rs`, listener/hook integration tests and the
source task's per-device authentication/refusal/revocation requirement.

### PAT-03: Preserve actual listener ownership and readiness semantics

For hooked TCP address startup, acquire all requested sockets before reporting
success and release acquired sockets on a later bind failure before launching
tasks. Preserve stop/reload cleanup and owned listener lifetimes; do not treat a
port probe or safe startup message as proof that the requested owner holds the
bind. Keep unsupported hooked QUIC/TUN configurations explicit. Ordinary unhooked
startup retains its distinct behavior. Sources: `src/tcp/tcp_server/startup.rs`,
`src/embedding.rs`, `src/main.rs` and source-task readiness/cleanup constraints.

### PAT-04: Separate error propagation from diagnostic serialization

Propagate real I/O/TLS failure semantics to callers while emitting bounded
lifecycle/status/error-kind records on the traffic-facing listener/TLS path.
Do not format an arbitrary propagated error or complete protocol object into
diagnostics. `src/tcp/tcp_server/listener.rs` demonstrates category-only terminal
records; `src/crypto/crypto_tls_stream.rs` preserves stream state transitions.
Source-task privacy requirements govern output even when the internal error
contains names, credentials or payloads.

### PAT-05: Preserve bounded task ownership without inventing EOF guarantees

Retain the session-owned task maps, bounded channels, cancellation and existing
shutdown handling in `src/anytls/anytls_server_session.rs`. Diagnostic changes
must not reinterpret directional EOF, swallow delayed responses or claim that
the separate AnyTLS EOF issue is fixed. Neither `is_message_eof` nor the current
native certificate verifier promises a new timeout/cancellation guarantee.
Sources: exact local AnyTLS source, `README.md` and source-task anti-regressions.
