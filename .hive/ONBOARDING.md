# Shoes privacy-remedy workflow

The operator authorized a separate maintained-fork source remedy and necessary
verification infrastructure. The original bootstrap began at
`ade6949fc95ab2a3ce4bf1a36d0346e24954c8ae`. This isolated takeover starts from
`0cfbc98bc67312974a5be0376cccc395170a9feb`, which already contains candidate
source changes and the metadata bootstrap. Their presence is not acceptance.

The takeover workspace is `/private/tmp/shoes-privacy-takeover.QuHCmb`; its
canonical child project is `shoes`. Use the exact checkout issued by Hive.
The older root-equals-workspace description is historical. Use the installed
CLI/runtime path issued with the current action and its matching help/Atlas, clear
frozen `HIVE_CORE_ROOT` overrides, and do not modify Hive Core or captured policy.

## Bootstrap evidence and command accounting

The original generated manifest, generator preview (including policy warnings),
T1 validation, read and ticket resolver outputs are retained with complete streams,
commands and exits in the infrastructure task's attached evidence. The baseline
Git blob also preserves the original manifest. The exact historical captures are
`/private/tmp/shoes-infra-coder-evidence-7k0hhf_n/bootstrap-captures.json` and its
`bootstrap-{read,validate,resolve,preview}.{stdout,stderr}` files; the original
manifest is `bootstrap-verification.yaml` in that directory. The result-bound
report embeds the original report and complete streams with hashes and primary
exits, rather than treating this paragraph as evidence. T1 reported schema `valid` while
the independent generator preview reported missing `typecheck` and, in broader
policy cells, `integration`. Neither observation ran a build or test.

The generated commands were:

```sh
# unit
sh -c 'cargo test --workspace --locked --lib --bins --verbose' && sh -c 'cargo test --locked --test listener_logging --verbose'
# lint
sh -c 'cargo fmt --all -- --check' && sh -c 'cargo clippy --workspace --all-targets --all-features -- -D warnings'
# build
sh -c 'bash scripts/build-ios.sh' && sh -c 'cargo ndk -t arm64-v8a -t armeabi-v7a -P 21 -o android/src/main/jniLibs -- build --release --lib --locked' && sh -c 'cargo build --workspace --locked --verbose'
```

The host build moves to its own declared check. The exact iOS script and Android
NDK command remain in the unchanged `mobile.yml` jobs, followed by genuine
XCFramework/AAR packaging. Library/binary tests, listener tests, formatting and
clippy remain scheduled; listener execution adds `--nocapture` to expose capture
locations. No original CI job, target, assertion, peer checksum or mobile command
is removed. `build.yml` retains its native/cross release target matrix and artifact
checks. Its disabled Windows entries remain disabled and unsupported.

## Host checks and setup

`.hive/verification.yaml` is project-authored infrastructure, replacing an
unapproved conservative projection. Its five real commands apply to both ticket
and full-wave verification; no selection, focused-mode override, waiver, success
adapter or reuse policy is introduced. Every required host check is declared.
No live checkpoint is edited, and no missing source wave is invented.

Each command is prefixed with `bash scripts/verify-host.sh`; the runner executes
the selected installed Cargo directly and preserves its stdout, stderr and exit.
It performs no installation and neither filters logs nor suppresses warnings.

| Check | Cargo arguments after the runner | Purpose and timing |
| --- | --- | --- |
| `build` | `cargo build --workspace --locked --verbose` | Host library/binary compilation; ticket terminal and full wave. |
| `typecheck` | `cargo check --workspace --locked --all-targets --all-features --verbose` | Real compilation/type analysis of all feature-gated targets, derived from CI's all-target/all-feature clippy scope; ticket terminal and full wave. |
| `lint` | `cargo fmt --all -- --check` then `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Exact existing CI checks, fail-fast; ticket terminal and full wave. |
| `unit` | `cargo test --workspace --locked --lib --bins --verbose` then `cargo test --locked --test listener_logging --verbose -- --nocapture` | Existing library/binary and listener regressions; ticket terminal and full wave. |
| `integration` | `cargo test -p shoes --locked --features integration-tests --test integration --verbose shadowtls_cert_verification:: -- --nocapture --test-threads=1` | Existing real local ShadowTLS certificate flights, trust/pin rejection and relayed traffic; ticket terminal and full wave. |

Legacy smoke can select only compile checks. Terminal verification must retain
all five; declaration alone does not promise all five ran before an inner review.
The infrastructure ticket uses its existing captured full policy. The dependent
source ticket must start only after infrastructure approval and committed-source
resolver inspection, with its own exact candidate, regression evidence, fresh
inner/outer all3 and separate architect approval. Wave 1 owns infrastructure;
wave 2 is the declared later source stage, not evidence of a created or tested ref.

Setup runs `bash scripts/verify-host.sh prepare` once per pass. It checks the
already installed Rust 1.94.1 toolchain, rustfmt/clippy and native `cc`, CMake and Perl
requirements used by this repository's aws-lc/native dependencies. `python3` and
`rustup` must be on PATH. The host explicitly selects the available 1.94.1 release;
the host's stale stable alias is 1.88.0 and system Cargo is a separate installation.
CI retains its own stable provisioning using `dtolnay/rust-toolchain@stable`;
existing lint jobs provision rustfmt/clippy. The project runner selects Cargo,
rustc, rustdoc, rustfmt and clippy from that same toolchain, avoiding an unrelated
system Cargo. Missing toolchains/components fail; the runner never installs them.

The default read-only rustup root is the OS account's home plus `/.rustup`, found
with Python's `pwd` API. `SHOES_VERIFY_RUSTUP_HOME` may explicitly name another
preprovisioned root; `SHOES_VERIFY_TOOLCHAIN` may explicitly override the default `1.94.1` with
an installed toolchain; evidence must state any override. Setup
prints the actual tool versions and resolved locations. Hive retains its isolated
persistent HOME/XDG. Cargo uses `$HOME/.cargo`; build output uses `target` in the
evaluated checkout. Explicit cache/target overrides are `SHOES_VERIFY_CARGO_HOME`
and `SHOES_VERIFY_TARGET_DIR`; all hosts must record actual overrides in evidence.
Registry access or a fully provisioned Cargo cache and native SDK/compiler are
prerequisites. No package, lockfile or engine pin changes are part of this setup.

The runner exports `RUST_BACKTRACE=1`, `CARGO_TERM_COLOR=always`, the selected
`RUSTUP_HOME`/`RUSTUP_TOOLCHAIN`, `RUSTUP_NO_UPDATE_CHECK=1`, matching `RUSTC` and
`RUSTDOC`, and prepends that toolchain's bin directory to PATH. These settings are
identical across checks, so pass setup has no per-check reset or environment split.

The listener TLS test itself starts real DEBUG and TRACE child executions with
live unfiltered collectors, dependencies and positive controls. It does not rely
on `RUST_LOG` to raise levels. The runner defaults `SHOES_TLS_PRIVACY_CAPTURE_DIR`
to `$HOME/shoes-tls-privacy-captures`, outside disposable check scratch/worktrees;
each test creates a unique directory containing complete stdout/stderr captures,
engine logs, policy and child exit. Do not delete earlier failed captures.
`test.yml` also retains these files using an always-run artifact upload. An absent
artifact is a coverage gap, not proof of privacy. Engine-owned receipts/captures
remain the authority for each primary's actual outcome and evaluated commit.

## External CI and mobile acceptance stages

Host checks do not certify the following environments. These requirements remain
at the full compatibility/mobile CI stage for the exact source candidate, before
feature publication. They are additional to the five host checks and full-wave
verification; a host GREEN cannot waive them. They are not claimed to have run by
infrastructure setup. Existing CI triggers remain master pushes/pull requests;
mobile/build also retain tag/manual triggers. Obtain actual CI runs against the
candidate through those triggers and preserve their exact commit and job results.

`test.yml` keeps the full serial integration matrix and its checksum-verifying
setup, with `RUST_BACKTRACE=1` and `CARGO_TERM_COLOR=always`:

| Matrix cell | Feature / test target | Filter arguments | Required peer |
| --- | --- | --- | --- |
| Local protocols | `integration-tests` / `integration` | none: entire target | sing-box |
| Optional peer interoperability | `optional-peer-tests` / `optional_peer` | none: entire target | Mihomo |
| External DNS | `external-network-tests` / `external_network` | `dns::`, `resolver::`, `vless_doh::`, `vless_dot::` in separate executions | sing-box and reachable public DNS/HTTPS services |
| External proxies | `external-network-tests` / `external_network` | `portforward::`, `shadowtls::` in separate executions | sing-box and public proxy services |
| External REALITY | `external-network-tests` / `external_network` | `reality::` | sing-box and public REALITY service |

The unchanged matrix command is `cargo test -p shoes --locked --features "$FEATURE"`
`--test "$TARGET" --verbose -- --test-threads=1`, with each named `"$FILTER::"`
inserted before `--` for filtered cells. CI downloads Linux AMD64 sing-box 1.14.1
archive SHA-256 `12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f`
and sets `SHOES_TEST_SING_BOX_BIN`; it downloads Mihomo 1.19.31 compatible archive
SHA-256 `04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc` and sets
`SHOES_TEST_MIHOMO_BIN`. Both hashes are checked before executing peers.
Local host TLS tests need neither binary and do not substitute for this matrix.
Ignored privileged/libcronet tests retain their existing status and prerequisites;
the default CI matrix does not claim they executed.

The added `shadowtls-independent-peer` job schedules the previously unscheduled
Docker proof inside the `integration` target with `optional-peer-tests`:

```sh
cargo test -p shoes --locked --features optional-peer-tests --test integration --verbose shadowtls_cert_verification:: -- --nocapture --test-threads=1
```

Its existing transport test fixes the image to
`ghcr.io/sagernet/sing-box:v1.12.0@sha256:3c1ee82d450df9b336b6f63b1d272cf86e3835392d99596ef8c35f206a457999`.
The Ubuntu job first requires `docker info`; the test verifies version 1.12.0,
adds `host.docker.internal:host-gateway`, mounts only synthetic peer configuration,
and checks verified wire traffic and bad-pin rejection. This needs a working
Docker daemon, permission to start containers/bind loopback ports, host-gateway
routing and access to that exact registry image. Missing Docker is failure or an
unavailable prerequisite, never a skipped successful check. The Mihomo matrix's
`optional_peer` target alone does not execute this separate Docker test.

Mobile requirements remain in unchanged `mobile.yml`:

- iOS: `macos-latest`, Xcode/xcodebuild, cbindgen, Rust targets
  `aarch64-apple-ios` and `aarch64-apple-ios-sim`; run `bash scripts/build-ios.sh`.
  The script sets `IPHONEOS_DEPLOYMENT_TARGET=16.0`, builds both release static
  libraries and creates `output/ios/Shoes.xcframework`. Existing header generation
  and artifact checks remain. This is packaging, not physical-device execution.
- Android: `ubuntu-latest`, Android SDK/NDK with
  `ANDROID_NDK_HOME=$ANDROID_NDK_LATEST_HOME`, cargo-ndk, Rust targets
  `aarch64-linux-android` and `armv7-linux-androideabi`, Temurin Java 17 and Gradle
  9.5.0. Run `cargo ndk -t arm64-v8a -t armeabi-v7a -P 21 -o android/src/main/jniLibs
  -- build --release --lib --locked`, then `gradle assembleRelease --no-daemon`
  from `android/`, and retain the AAR. Comments mentioning four ABIs do not mean
  the existing CI builds four: its actual commands build only these two.

The current macOS host's installed iOS targets alone do not establish Xcode,
cbindgen, Android NDK/Java/Gradle or Docker readiness. An unavailable required
stage must be reported with its exact prerequisite before source dispatch;
provisioning is a separate action, with no local install/push/release here.
The takeover preflight observed Xcode 16.4, but no cbindgen, cargo-ndk, Gradle or
Android SDK/NDK environment. `docker info` returned exit 1 with permission denied
on the OrbStack Docker socket; this does not establish that the daemon is absent.
The exact pinned-peer CI environment above is therefore still required. Full
stdout/stderr and primary exits for these prerequisite observations are attached
to the infrastructure task, recovered from the original `candidate-captures.json`,
`host-prerequisites.json` and `{xcode,docker}-prerequisite.{stdout,stderr}` under
`/private/tmp/shoes-infra-coder-evidence-7k0hhf_n`. The Docker exit remains 1.
No mobile or container test was run.

## Narrow Darwin host-readiness recovery

The retained infrastructure subject `f19680c6662538ac86a12d090394f30789320877`
remains unapproved. Its actual full verification was RED: Darwin could not bind
random non-localhost 127/8 test endpoints, and Rust 1.94.1 clippy diagnosed two
unused interface bindings and three nonminimal Boolean assertions. Those earlier
results and complete captures remain historical evidence; these corrections do
not reclassify that subject or establish baseline attribution.

The first recovery ruling admitted four specific source/helper correction paths;
the current ruling additionally admits only the distinct-IP integration consumer.
`tests/support/src/port_helper.rs` uses the already configured `127.0.0.1` on
Darwin and asks the kernel for available ports. All allocator variants share a
process-wide set of issued endpoints, so a released probe is not reissued while
its caller is preparing a listener. Each allocation checks TCP and UDP together
and retries at most 128 times. Other hosts retain random non-localhost 127/8
addresses. The short allocation lock protects issuance; it does not serialize
test execution. Existing bind assertions remain, with an added parallel-allocation
regression that binds both protocols after allocation. As with the tuple-based
fixture API, a probe is released before the caller binds; an unrelated process
claiming it in that interval still causes a real bind failure.

The genuine alternate-IP XUDP integration test now requests a distinct source IP
with at most 32 allocations. If the allocator supplies only one local IPv4 address,
it returns an explicit `AddrNotAvailable` unavailable-prerequisite error before
peer setup. It does not skip, succeed, substitute a port, or change its alternate-IP
and payload assertions. Its full execution still belongs to the checksum-pinned
sing-box local-protocol CI cell on a host supporting distinct loopback addresses.
Positive/negative selection controls run in the existing workspace library tests.
No loopback alias, interface, VPN or service setup is performed.

`tests/support/src/test_servers.rs` retains independent primary and UDP response
sockets, its source-socket and payload assertions, and the earlier Darwin
localhost fixture correction. `src/socket_util.rs` retains cfg-local interface
bindings, and `src/config/types/dns.rs` retains the three equivalent `is_none()`
assertions. No warning allowance, test exclusion, privacy logging, trust,
authentication, wire or EOF change accompanies these corrections.

The governance prerequisite `TICKET-c15e2cb7` was separately accepted and
published at `b08814ce1f2f7788aa89b6d1fdcb84deb76808a8`. This retained worktree
starts this recovery at `e6c5a24d128fc7561ef1fee93d8491656759a99d`, preserving
`f19680c6662538ac86a12d090394f30789320877` in history; its wave target was
captured at `0cfbc98bc67312974a5be0376cccc395170a9feb`. The published governance
commit does not imply that either ref has been synchronized. The retained
architecture finding `critical-795701ed9e` still requires fresh review against
the actual canonical rules and delivered subject. The later review also retains
`critical-47a4650bdb` for this composition debt. The committed stub still has zero
parseable architecture rules. The required remedy remains: add at least one
prescriptive `### PREFIX-NN` rule in a rule-bearing canonical architecture file,
or populate the legacy architecture file, through its authorized governance
workflow. This code grant does not authorize that edit. Composition and any refusal
belong to the engine; do not manually rebase, reset or cherry-pick this work.
The complete captured check plan, fresh inner and outer all3, genuine integration
and separate architect approval remain required before source dispatch.

## Resolver and acceptance boundary

Use `verification read`, `verification validate`, and `verification resolve` with
explicit project paths. For the current infrastructure action, use its actual
`--ticket TICKET-3701ee88`. Bound resolution reports `source: current`; it is not
permission to rewrite captured policy. Also inspect `resolve --blast-radius
process-boundary` without a ticket for all five declarations and no missing policy
checks. This recovery captures read/validate/both resolutions against committed
infrastructure `e6c5a24d128fc7561ef1fee93d8491656759a99d` and its unchanged manifest
blob `abb1525f27395ea393f3becdaa6ac433cdb9d83a` in
`/private/tmp/shoes-infra-owned-endpoints-vlpdmf0n/current-observations.json` and
its complete streams. Bound resolution selects all five checks with `source:
current`, no deferred or missing focused checks; the broader process-boundary
resolution also declares all five. This observation does not replace the captured
wave baseline or the next engine-owned verification subject. After landing, the
parent must repeat resolution against the actual
committed project/integration source and record the commit and manifest blob.
Any new focused selection requires the installed new-run procedure and a real
opened wave; this infrastructure makes no such selection or policy change.

Validation and resolution are configuration observations. They are not compile,
test, packaging, independent-peer or approval results. The engine owns actual
committed-subject gates and complete primary streams/exits. Preserve all RED
history. The narrow recovery above is the only admitted exception to the original
source/test boundary; maintained rustls, dependency pins, privacy-source changes,
trust/authentication and wire behavior remain outside this infrastructure scope.

Only explicitly configured listener startup bind metadata may be logged. Traffic
addresses, SNI, credentials, keys, handshake/ticket/application payloads and arbitrary
error formatting remain prohibited. Keep useful bounded non-secret diagnostics
and transport behavior, with live DEBUG/TRACE collectors and raw captures.

The retained server-smoke RED, separate AnyTLS EOF issue, callback/projection gate,
consumer pin reconciliation and physical-device/deployment gates remain unchanged.
No consumer adoption, publication, release or source approval is supplied here.
This retained worktree's architecture file remains the bootstrap stub. Canonical
governance was separately published as recorded above; no synchronization, domain
analysis or contract analysis is implied by this infrastructure.

## Unix fixture location recovery

The next recovery starts from retained infrastructure
`cc982f885885a62d6a929d5dd466fd2bb0036e97`. Its actual owning terminal result
`deaf1d0b1bbf20d41dfc6a87654d7ed823446b6f844db7bed439eea1a2f5dfbc`
remains RED: library/binary/support tests passed, then the listener target had two
passes and one failure because its worktree-relative Unix socket path exceeded
Darwin `SUN_LEN`. The other four required checks returned zero. These are the
previous subject's results; the fixture correction does not rewrite them.

The newly admitted `tests/listener_logging.rs` correction creates an owned random
temporary directory directly under `/tmp`, with an eight-character random suffix
and the existing `listener.sock` filename. This short absolute socket location is
independent of both the issued worktree and `TMPDIR`. The same path configures
and connects the real Unix listener; the directory owner remains alive through
both Unix connection checks and removes the socket and directory on drop.
Existing assertions, canaries, accepted/refused/error paths, collectors, logging
levels, test commands and timeouts are unchanged. No process working directory,
interface or environment is relocated to make the test pass.

The full preceding task report, including the original 58004-byte setup evidence,
and complete capture references remain attached through the issued task-evidence
route. Fresh owning committed-subject checks and inner all3 remain required.
At the actual `inner_assessment_ready` boundary the parent must stop with child
and check roots settled for architect-coordinated governance publication and
native composition. SELF `TICKET-6298832d` has its own clean all3 and pending
wave-1 publication; it is not published or composed into this retained subject.
Original architecture findings and zero-rule observations remain true of their
reviewed subjects. No architecture files or refs are synchronized by this grant.
Both review stages, genuine integration and distinct architect approval remain
required before downstream source dispatch.


## Current governed infrastructure successor (2026-10-18)

The preceding recovery sections retain the original TICKET-3701ee88 history and
its subject-specific instructions and outcomes. That ticket was superseded after
the actual native composition preparation refused; it was never approved. This
ordinary replacement is TICKET-bc49c755, captured on the already-open wave 1 at
`8e276815885057296ddebe6c68ff44617b3edbb5`. SELF TICKET-6298832d genuinely
published the eight accepted canonical architecture documents to that wave and
closed. The base now contains 27 prescriptive rules; the old zero-rule findings
remain true of their original reviewed subjects. Fresh review must resolve this
successor's actual rules and source together.

This successor faithfully reapplies the ten authorized paths from retained
candidate `cb4a90e9598fc552a3d87251ec705dcdc7000fd8` relative to original
`0cfbc98bc67312974a5be0376cccc395170a9feb`, then appends this section. It
copies no governance and performs no source/ref synchronization. All declared
commands, host corrections, collision controls, independent UDP response
attribution, bounded distinct-IP failure, Unix fixture ownership, assertions,
collectors, canaries and external/mobile CI obligations above remain intact.

Use the actual successor checkout and `--ticket TICKET-bc49c755` for bound
configuration observations through the issued installed runtime. The parent
must obtain read/validate/resolve against the actual committed successor, owning
checks with complete primary streams/exits, fresh isolated inner and outer all3,
native integration/publication, full workspace verification and separate
architect approval. The historical cb4a terminal GREEN is evidence of cb4a only.
The old instruction to stop for pending SELF publication has been fulfilled;
this successor follows its ordinary issued workflow through genuine handoff.

The complete 118591-byte retained task report (SHA-256
`a28f6445471e4de123f9fd3da6865ae378b4be1e015ed3d1662f61a4d8668cb8`)
is the unchanged prefix of this successor's result-bound task evidence. All
historical RED, GREEN, refusals and original bootstrap/prerequisite captures
remain historical. Configuration validity and a command declaration certify no
execution. Source TICKET-8fe6bb32 remains unopened until this successor and the
governance prerequisites are independently accepted; it still owes its own exact
privacy candidate, production regression and approval. Fork publication follows
source approval through a separate architect action; server/iOS adoption remains
with the parent.
