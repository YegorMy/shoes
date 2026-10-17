# Source ownership and placement

### STRUCT-01: Preserve the binary, Rust embedding and FFI boundaries

Place shared engine behavior in the existing modules exposed by `src/lib.rs` and
used by `src/main.rs`; preserve public exports and feature/platform gates in
`src/ffi/mod.rs`. These entry points share intermingled client/server modules;
this governance task does not prescribe or authorize a client/server split.
Retain the `rlib`/`cdylib`/`staticlib` package surfaces declared in `Cargo.toml`.

### STRUCT-02: Keep protocol corrections in their owning modules

Use the existing `src/tcp/` factories/listener processing, protocol directories
such as `src/shadow_tls/`, and shared `src/async_stream.rs` or socket/copy utilities
for their existing responsibilities. A diagnostic correction must stay limited
to the unsafe formatter and directly necessary regression coverage; do not
redesign routing, framing or protocol selection to resolve logging findings.
Sources: `src/tcp/tcp_server/startup.rs`, `src/tls_server_handler.rs`, source-task
"What Should Be Done" and "Anti-regressions".

### STRUCT-03: Preserve configuration and outbound-policy ordering

Keep validation in `src/config/validate.rs`, typed configuration in
`src/config/types/`, and DNS construction/resolution in `src/dns/` and
`src/resolver.rs`. Preserve the existing sequence of validation, configured rules,
resolution and embedder outbound decision; connect to the same resolved address
checked by the hook. Do not bypass these layers through an unguarded direct
connection. Sources: `src/main.rs`, `src/embedding.rs::ServerHooks`,
`src/tcp/tcp_server/startup.rs`.

### STRUCT-04: Treat vendor/rustls as maintained source with retained identity

Keep `vendor/rustls` changes in this repository with its licenses/provenance and
existing package/API/wire identity. `Cargo.toml` selects this tree through
`[patch.crates-io]`; `Cargo.lock` identifies local rustls 0.23.45. Never substitute
a dependency-cache patch or consumer-local vendor copy for an owning source fix.
Document any required root-workspace patch for consumers without editing or
claiming their adoption. Sources: root manifests, `CONFIG.md` ShadowTLS section,
source-task maintained-vendor and later-adoption boundaries.
