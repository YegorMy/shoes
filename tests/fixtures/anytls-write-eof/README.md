# Test-only write-eof/1 fixtures

This directory is reserved for public loopback test material. No deployment or
consumer adoption is implied. The source candidate's CLI is
`cargo run --locked --example write_eof_peer -- ...`; exact arguments and observed
results are recorded in the external `ENGINE-EOF-STATUS.md`.

The TLS, destination EOF, full-close and absent-shutdown controls live in
`src/anytls/write_eof_tests.rs`. Original pre-runtime-change failures are retained
outside the clone in `engine-evidence/red-01.log` (or the subsequent compile-fixed
RED invocation, if needed); they must not be relabelled as positive proof.

## CLI contract

Every network address must be a numeric loopback address. The process has a
60-second outer bound, the single server session a 50-second bound, input files a
16 MiB bound, and destination response delay a 10-second bound. These are fixture
bounds, not production live-traffic deadlines. TLS validates the generated
`localhost` certificate against the supplied CA file. Password is public fixture
data: `write-eof-public-test-only`.

```text
write_eof_peer generate DIR
write_eof_peer server LISTEN CERT KEY enabled|legacy TARGET [PUBLIC_TEST_PASSWORD]
write_eof_peer client SERVER CA TARGET strict|strict-bytes|strict-first|legacy|legacy-bytes UPLOAD EXPECTED_RESPONSE [PUBLIC_TEST_PASSWORD]
write_eof_peer target LISTEN EXPECTED_UPLOAD RESPONSE DELAY_MS
write_eof_peer target-first LISTEN EXPECTED_UPLOAD RESPONSE DELAY_MS
write_eof_peer target-length LISTEN EXPECTED_UPLOAD RESPONSE DELAY_MS
```

`generate` writes `cert.pem`, `key.pem`, `upload.bin` (8 MiB, byte `i % 251`),
and `response.bin` (128 KiB, byte `255 - (i % 251)`). These are public test data.
The target verifies the entire upload and observes actual TCP read EOF before
delaying and responding. `target-first` instead sends the response and shuts down
its TCP write half before reading the entire upload. The client verifies the exact
response, including remote stream EOF, after two idempotent local shutdown calls.

The server accepts one authenticated TLS session and permits only its configured
single destination through the existing routing/hooks seam. It does not expose a
general proxy. All counts/hashes use actual observed bytes and SHA-256; failure is
a nonzero process exit, never a skipped/passing interoperability result.
The optional trailing password (ASCII, 1..128 bytes) lets the lead match an
independent peer's public test credentials without source edits. Never use a real
user credential. Omitting it uses the public default above.

Do not run the old full-FIN/legacy client as a positive directional-EOF test.
Independent peer cross-matrix results are separately owed; Rust-to-Rust evidence
does not establish that matrix.

`legacy-bytes` plus `target-length` is an explicitly length-delimited ordinary
legacy forwarding control: no local shutdown is requested before receiving the
response, and the destination reports `genuine_eof=false`. It is never the
EOF-delimited-upload requirement or directional-EOF acceptance.

`strict-bytes` plus `target-length` is the negotiated ordinary no-FIN control:
it uses the production write-eof/1 API, writes and flushes the complete upload,
and validates the full response and real response EOF **without local shutdown**.
It reports `strict_no_shutdown=true request_eof=false`; full teardown is not proof
of request EOF or directional settlement. It never substitutes `legacy-bytes`.

`strict-first` plus `target-first` validates the complete response **and genuine
response EOF before writing any upload**, then reports
`remote_eof_before_upload=true`, uploads and awaits the actual ordered WRITE_EOF
write/flush acknowledgement. It does not wait for an application response after
that acknowledgement or retain the client to conceal server-side drain loss.
For cross tests supply the public password `public-write-eof-test` and files
containing `U` repeated 9,437,184 times / `R` repeated 262,144 times.

## Programmatic candidate APIs and budgets

Existing constructors remain legacy. Opt in with
`AnyTlsClientHandler::require_write_eof(WriteEofOptions::default())`, or use
`WriteEofClientSession::connect(..., WriteEofOptions::default())` and its
`open_stream` method. The server handler's `with_write_eof(true)` enables exact
offer/echo policy. These types and a factory accepting an explicit outbound chain
and optional existing embedder hooks are exposed under `shoes::embedding`.
An embedder that accepts TCP itself also passes the accepted socket's
`TransportWatch` (see the server fixture) so a reset settles a backpressured
session, and refuses the connection when the watch cannot be created: a
silent fallback to no watch brings back the hang. Unsupported offers (`x-write-eof` other than exactly `1`, or a base
version other than `v=2`) fail closed on an enabled server.

Strict sessions permit 8 registered streams, 4 incoming frames per stream and 16
shared outgoing operations, all with payload at most 65,535 bytes. The queue payload
budget is at most 3,145,680 bytes, plus fixed writer/codec/relay buffers and one
partial-read frame per stream. There is no forwarding queue/task, tombstone map,
or unbounded extension channel. Each stream has at most one flush and one EOF
acknowledgement; a client has exactly two session IO tasks and a server at most
8 stream handlers. Normal retirement requires both write halves, settled writes
and drained reads, and appends no full FIN.

On clean transport EOF, only already complete negotiated directional wire EOF
admits graceful relay settlement. A single EOF-only deadline (at most 5 seconds)
covers draining accepted receive data and joining the actual destination relays,
including TCP flush/shutdown after registry retirement. Retired wire ids do not
alias still-settling handler tasks; the same eight-handler semaphore covers both.
Incomplete EOF, reset, relay error, cancellation, truncated frames and drain
deadline expiry remain failures/full closure, not successful graceful cleanup.

Negotiation and EOF settlement default to 5 seconds; options may narrow, not widen,
these bounds. Live write/flush has no new idle deadline. Timeout, cancellation or
explicit full close is failure. Cancelling an in-progress transport frame closes
the session rather than continuing a partial frame or claiming EOF success.
