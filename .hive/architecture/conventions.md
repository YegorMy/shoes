# Project conventions

### CONV-01: Follow the existing Rust tool and module conventions

Keep Rust edition 2024 and the adjacent module, `use`, `cfg` and
`std::io::Result` patterns visible in `Cargo.toml`, `src/embedding.rs` and
`src/tcp/tcp_server/startup.rs`. Run the project's real formatting and strict
clippy commands; do not suppress diagnostics or add broad allow attributes to
obtain a passing receipt. No project rustfmt/clippy/editorconfig override was
found in the inspected owned source/config paths. A source portability correction
requires its own prospective authoring grant.

### CONV-02: Preserve locked dependencies and explicit feature/test targets

Use the committed `Cargo.lock` for owning checks and retain declared feature
boundaries and explicit `[[test]]` entries: `autotests = false` makes scheduling
intent material. Do not update package versions, dependency/reference pins or
enable a different protocol feature to cure a diagnostic problem. The observed
lockfile has Tokio 1.52.3, local rustls 0.23.45, rustls-platform-verifier 0.7.0,
aws-lc-rs 1.18.1 and log 0.4.33. These are observed versions, not authorization
to freeze or upgrade every dependency forever.

### CONV-03: Keep authored project documents separate from engine evidence

Author architecture in the fixed `.hive/architecture/` files with file-qualified
stable rule IDs and real source/requirement citations. Preserve the original
`.hive/architecture.md` stub and historical findings. Do not hand-edit managed
current records, receipts, review results or approval status. Native SELF captures,
fresh isolated all3 judgments and supported publication establish adoption;
this document's presence or a lint result cannot establish it. Sources:
`TICKET-c15e2cb7`, original task anti-regressions and `.hive/ONBOARDING.md`.

### CONV-04: Keep toolchain and environment observations explicit

Record the evaluated commit, effective commands, selected installed toolchain,
features, platform and actual overrides with each owning check. The unaccepted
`f19680` infrastructure candidate selects preinstalled Rust 1.94.1 and isolated
check captures; current CI separately provisions stable. Do not install tools,
change VPN/interfaces/services, edit engine policy or silently substitute another
toolchain to reclassify a failure. Missing prerequisites remain failures or
unavailable observations until a genuine supported recovery. Sources:
infrastructure task, candidate `scripts/verify-host.sh` and `.hive/ONBOARDING.md`.
