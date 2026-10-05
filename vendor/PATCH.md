# Rustls source provenance and ShadowTLS hook

Rustls 0.23.45 is copied from the published crate at source commit
2976d90fd1c2db6b518700dd101b714069cfcb17. All original licenses are retained.
RUSTLS-UPSTREAM-SHA256.json identifies the 119 original files;
RUSTLS-PATCH-IDENTITY.json identifies the four changed source files.

The optional client session-ID callback receives encoded ClientHello bytes
before transcript hashing. Only the session ID changes; the stored expected
echo also changes. Default configurations do not install this callback.
It disables resumption and early data, and refuses ECH, QUIC and retry
handshakes. Cipher suites, verification, signatures and key schedules are unchanged.

Shoes keeps ShadowTLS v3 session-ID HMAC and record framing. The client
authenticates/unwraps each server handshake record, gives its TLS ciphertext
to Rustls, and completes real certificate and Finished verification before
inner protocol setup. No separate preflight TLS connection or new ALPN mode is used.

Cargo ignores patches declared only by dependencies. An embedding workspace
must patch crates-io rustls to this exact maintained Git revision and
package subdirectory, alongside the same Shoes pin. Keep the selected Rustls
version and lockfile graph; do not adopt a mutable path in a shipped consumer.
