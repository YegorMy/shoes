# Runtime and evidence overview

`src/main.rs` configures multi-output logging and a Tokio runtime, loads YAML,
converts certificate paths, validates server configurations, builds the DNS
registry, then starts each server. Its optional file watcher aborts listener
handles before restarting. The Rust embedding entry points in `src/lib.rs` and
`src/embedding.rs` let an application supply its resolver and runtime instead.
`src/ffi/mod.rs` gates mobile implementations and non-mobile stubs.

`src/tcp/tcp_server/startup.rs` dispatches supported server configurations to TCP,
QUIC or platform TUN handling. Hooked TCP address listeners acquire their sockets
before startup returns; unsupported QUIC/TUN hook configurations are refused.
Ordinary unhooked startup preserves its existing asynchronous bind behavior.
`src/tcp/tcp_server/listener.rs` accepts connections and runs protocol processing
on spawned tasks. Server/client factories and `src/tls_server_handler.rs` compose
protocol handlers and TLS/ShadowTLS/REALITY targets. Configuration, routing,
resolution and transport remain separate collaborating surfaces rather than a
database-backed application stack.

`src/embedding.rs` defines session grant/refusal, outbound allow/block/redirect,
cancellation and completion hooks. `src/async_stream.rs` defines byte and message
stream traits. The message relay and protocol wrappers preserve datagrams and
stream shutdown without treating every empty payload as EOF. AnyTLS session
ownership is implemented in `src/anytls/anytls_server_session.rs`; its separately
reported directional EOF issue remains unresolved by this governance work.

The six bounded research reports used the ready/fresh index and canonical graph
at `0cfbc98`; all reported partial output because graph evidence was truncated.
Direct source inspection establishes the relationships described here. Typed
graph `contains` edges confirm module/type containment; the returned `calls` edge
from `start_tcp_or_quic_servers` to `start_tcp_servers` agrees with the direct
startup source. Other repeated-name edges were ambiguous and were not treated as
validated runtime flow. Base-only semantic coverage and the AnyTLS file omission
are recorded in `arch-index.md`.

The project owns native host checks and declares external peer/mobile stages.
An executable declaration differs from a successful check. Infrastructure
candidate `f19680c6662538ac86a12d090394f30789320877` is still unaccepted with
real unit/lint RED; its proposed host manifest cannot be described as accepted
governance or passing production verification. Neither same-engine traffic nor
architecture review proves independent compatibility or physical-device behavior.
