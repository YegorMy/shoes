# Shoes purpose and boundary

Shoes is a Rust multiprotocol proxy server and embeddable proxy engine. The binary
loads YAML configuration and starts protocol listeners; the Rust library exposes
client chains and server hooks, and platform-gated FFI supports Android/iOS
integration. This describes the code at `0cfbc98bc67312974a5be0376cccc395170a9feb`,
not independent certification of every advertised protocol/platform combination.
Sources: `README.md`, `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/ffi/mod.rs`.

The current takeover preserves the maintained fork while validating a candidate
remedy for server TLS diagnostic disclosures. The supplied requirements retain
traffic privacy with useful live diagnostics, TLS trust and authentication,
protocol/API/wire compatibility, listener ownership and UDP/EOF distinctions.
They require real checks, isolated reviews and separate approval before source
publication or consumer adoption. Architecture documents alone establish none of
those outcomes. See `arch-index.md` for reference mapping and known drift.

The package is `shoes` 0.2.8, Rust edition 2024. Its library builds `rlib`,
`cdylib` and `staticlib`; the binary is `src/main.rs`. The workspace includes
`tests/support`. Maintained `vendor/rustls` is excluded from workspace membership
but selected by the root Cargo patch. Consumers have separate dependency and
acceptance responsibilities; this project does not govern their pins or device
and deployment results.
