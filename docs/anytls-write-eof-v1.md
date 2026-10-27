# AnyTLS write-eof/1 — coordinated implementation contract

Status: owner-authorized DEVELOPMENT contract for isolated engine/reference-peer
candidates. Not standard AnyTLS v1/v2, a published consumer pin, engine adoption,
independent-peer success, controller approval or physical-device evidence.

The owner explicitly approved a negotiated directional-EOF extension at both ends
with real-adapter and independent-peer tests. The original upload/genuine-EOF/
delayed-response requirement is retained. The owner also approved minimum new
separately scoped work. No installed runtime, consumer pin, shared service, remote
publication or existing source checkout is changed by this contract.

## Exact baseline and allocation evidence

- Rust engine base: YegorMy/shoes f595e589c4d0cdba75ed6b1c31d50f2edfb1b83e.
  The existing local Shoes checkout does not contain that object: use an owned
  fresh public clone/fetch, not the current owner's unrelated working branch.
- Independent Go base: anytls/sing-anytls130d2e61b8895727bfed4942c535e91b246a9603
  (v0.0.11 selected by the pinned sing-box reference). Keep the unmodified reference
  as a legacy control; the modified candidate is a separate extension implementation.
- Protocol authority audited at anytls/anytls-go
  fd6167acd6d73b9fa3e607659951847fbc9e6c50, docs/protocol.md: commands0..10,
  settings4/client and10/server, full-stream FIN3, 7-byte big-endian frame header.
- Exact approved Rust client/server source was inspected via commit-addressed raw
  URLs. Current client coalesces first Settings/SYN/destination; strict negotiation
  must explicitly avoid waiting for a response while Settings remains buffered.
  Existing server forwarding invokes the real bidirectional-copy seam. A local
  reader wrapper alone cannot implement the required destination half-close.

## Negotiation and unchanged legacy behavior

Extension identifier: write-eof/1. Capability setting: exact UTF-8 key/value
`x-write-eof=1`. This is a neutral private extension marker, NOT a standard v3 claim.
Existing AnyTLS TLS/password authentication, base v2 framing, padding, ordinary
settings, SYN/SYNACK, address encoding, UDP framing and full FIN remain unchanged.

Both endpoints opt in through explicit API/config policy; all existing constructors
and callers default to unchanged legacy behavior. The engine provides an explicit
require-negotiated-write-EOF client policy and an explicit enable-write-EOF server
policy. Exact API names belong to each implementation, not copied between them.

An enabled client sends ordinary valid cmdSettings with v=2 and the feature offer.
An enabled v2 server echoes x-write-eof=1 in cmdServerSettings ONLY if it received
that exact unambiguous offer. Only after that response may the strict client create
or expose an extension stream. Strict mode must transmit/flush the Settings offer
before waiting; no SYN, destination PSH or user payload is sent before agreement.
An extra negotiation round trip in strict mode is explicit; legacy initial record
coalescing remains unchanged when the feature is not requested.

Missing/zero/unknown-version feature response is unsupported, never an inference
from v>=2. A v1/no-response peer reaches a bounded negotiation timeout, not a false
unsupported-success result. Default negotiation bound5seconds, cancellable; tests
may use an explicitly smaller bound. It applies BEFORE live stream activation, not
as a healthy live-traffic/write/flush deadline. Reject duplicate feature keys,
invalid UTF-8 or conflicting negotiation; do not use last-value-wins to manufacture
agreement. An unknown extension version is not automatically compatible.

Shoes server rule: on an enabled server, a Settings offer that carries the
`x-write-eof` key with any value other than exactly `1` (for example `2`, `0`,
empty, `01`, `1 `), or carries it on a base version other than exactly `v=2`
(absent, `1`, `3`), is a negotiation failure. The server sends nothing in reply
(no ServerSettings, no padding update), handles no SYN or PSH queued behind the
offer, and closes the session with the sanitized negotiation error. An absent key
(keys are case-sensitive) keeps the legacy session. A server without the explicit
enable policy keeps stock behaviour and ignores the key.

Strict callers receive a typed/sanitized unsupported/negotiation/timeout error if
agreement is unavailable. Do not downgrade the requirement, send full FIN as a
substitute, omit EOF, inject an application terminator or fall back to direct IO.
An unchanged standard peer receives no extension command. Legacy byte forwarding
may still be tested, but is NOT certified as directional-EOF capable.

## Wire operation

Private command byte0xF0(240), named WRITE_EOF, is allocated by this development
contract after the audited0..10 table. There is no claim of upstream allocation.
It may be emitted/processed ONLY after write-eof/1 negotiation. Header format is
unchanged: command:u8, stream_id:u32be, payload_length:u16be. WRITE_EOF requires a
nonzero active stream_id and payload_length=0. Existing FIN(3) remains full close.

Post-authentication frame codec vectors (not a complete TLS/auth/padding transcript):

| Meaning | Hex bytes |
|---|---|
| Minimal isolated v2 extension Settings frame | 04 00 00 00 00 00 11 76 3d 32 0a 78 2d 77 72 69 74 65 2d 65 6f 66 3d 31 |
| ServerSettings agreement | 0a 00 00 00 00 00 11 76 3d 32 0a 78 2d 77 72 69 74 65 2d 65 6f 66 3d 31 |
| SYN stream1 | 01 00 00 00 01 00 00 |
| PSH stream1 abc | 02 00 00 00 01 00 03 61 62 63 |
| WRITE_EOF stream1 | f0 00 00 00 01 00 00 |
| Full FIN stream1, NOT directional EOF | 03 00 00 00 01 00 00 |
| Invalid WRITE_EOF reserved stream0 | f0 00 00 00 00 00 00 |
| Invalid WRITE_EOF payload | f0 00 00 00 01 00 01 01 |

The minimal Settings vector verifies frame/extension parsing only. Full-session
tests must use real valid client identity and padding digest/factory fields and
exercise existing padding/update handling; the abbreviated codec vector is not
claimed as full standard-client conformance. Preserve exact case and byte order.

Unnegotiated WRITE_EOF, stream0 or nonempty WRITE_EOF payload is a protocol error,
not data or legacy FIN; fail the affected session with a sanitized error and settle
its owned operations. A valid empty WRITE_EOF for an already unknown/retired id
is ignored without allocating any state, as unknown-stream control traffic; it is
not a successful open/EOF observation. Known duplicate remote EOF is idempotent.
PSH after that stream's remote WRITE_EOF is a stream protocol error/full close,
never bytes after EOF. Do not reset healthy unrelated streams on graceful EOF.

## Independent direction state and ordering

Track local write closure, remote write closure, pending accepted data and full
closure distinctly. Zero-length application writes are not an EOF signal.

- Local shutdown/CloseWrite stops future writes (typed closed-pipe failure), drains
  all accepted data in order, sends exactly one WRITE_EOF through the SAME ordered
  transport writer, and reports success only after that marker is actually written
  and flushed—not merely accepted by a forwarding queue. Repeated local shutdown
  is idempotent. Read remains usable until remote EOF/full failure.
- Remote WRITE_EOF is delivered after all earlier PSH data. Read returns0/io.EOF
  only after that buffered data drains. It does not close the writer, discard
  buffered responses or remove the stream registration prematurely.
- The actual server relay translates request EOF into destination TCP write-half
  shutdown while continuing to read and return the delayed destination response.
  Opposite close order must likewise preserve the still-active upload.
- Normal retirement requires both write halves complete, accepted outgoing work
  settled and incoming data drained. Do not automatically append a full FIN which
  could erase a peer's buffered data after graceful EOF. No unbounded tombstone map.
- Full FIN, transport error, reset, explicit full Close, cancellation and session
  shutdown remain full failures/closure and promptly unblock pending operations.
  A dropped/cancelled writer or lost IO acknowledgement is never success.

All new queues, acknowledgements, task maps and waiters require explicit finite
budgets. Preserve backpressure, do not move bounded per-stream data into an unbounded
forwarding queue. EOF/control settlement is bounded and cancellable; default bound
5seconds after shutdown is requested. Live traffic before EOF has no new arbitrary
idle/write deadline. The caller may apply its narrower existing close bound. Actual
timeout is a failure, not proof that all bytes/EOF reached the destination.

## Required source and independent interoperability proof

Each implementation uses its own existing source and state/IO abstractions. The
Go worker must NOT inspect or copy the Rust candidate, and vice versa. Shared input
is this wire contract, not shared implementation. Keep base/source and patch commits
separate from any published/pinned consumer reference. No source push is authorized.

1. Meaningful RED before runtime edits: old full-close behavior must fail the new
   EOF-delimited-upload/delayed-response expectation; an absent-shutdown control
   must fail the destination's real read-EOF expectation. Do not count a compile
   failure or expected BrokenPipe characterization as positive proof.
2. Real TLS + actual AnyTLS handlers/forwarding, not only a duplex wrapper. Upload
   at least8MiB (larger than relevant declared aggregate buffers), verify destination
   byte count/hash, observe genuine destination read EOF, then delay and send a
   complete >=128KiB response. Both directions must arrive intact.
3. Remote EOF first with a still-progressing upload, ordinary no-FIN request/reply,
   multiplexed independent streams, duplicate shutdown, invalid/unsupported/absent/
   conflicting negotiation, legacy mode and stalled/cancelled EOF/session close.
4. New resources/ports/tasks settle within declared bounds; slow LIVE traffic past
   the EOF-control bound is not terminated merely by that elapsed time.
5. Independent cross-matrix: Rust client -> patched Go peer server and Go client ->
   Rust server, plus unmodified standard-peer legacy/downgrade control. Local
   Rust-to-Rust or Go-to-Go is implementation evidence only, not this matrix.
6. Record exact source commits, commands, real primary exits/counts, complete logs,
   negotiated feature and observed byte/EOF/response stages. Docker image digest or
   executable hash must be ACTUAL, not a future placeholder. Missing capability is
   an explicit unavailable/failing result, never skipped success.

Workers provide test-only loopback fixture executables/examples using the actual
patched APIs so the lead can run the cross-matrix. Fixtures use public test
credentials and bounded local targets, never user credentials/public proxy exposure.
No new cryptography; reuse existing authenticated TLS and audited hash libraries.
Preserve the accepted base privacy behavior; no new raw credential/client/destination
logging. Prototype stdout reports may identify configured loopback test binds, not
captured application traffic. No deployment, existing consumer mutation or iPhone
claim follows. Canonical consumer pin/adoption, fresh all3 and explicit owner review
of the exact reference candidates remain required before clearing product gates.
