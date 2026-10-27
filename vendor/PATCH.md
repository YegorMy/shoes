# Rustls source provenance and ShadowTLS hook

Rustls 0.23.45 is copied from the published crate at source commit
2976d90fd1c2db6b518700dd101b714069cfcb17. All original licenses are retained.
RUSTLS-UPSTREAM-SHA256.json identifies the 119 original files;
RUSTLS-PATCH-IDENTITY.json identifies every changed source file.

The optional client session-ID callback receives encoded ClientHello bytes
before transcript hashing. Only the session ID changes; the stored expected
echo also changes. Default configurations do not install this callback.
It disables resumption and early data, and refuses ECH, QUIC and retry
handshakes. Cipher suites, verification, signatures and key schedules are unchanged.

Server and client diagnostics never format handshake messages, server
names, certificates, OCSP responses, tickets, ALPN names, CertificateRequest
contents or ECH public names and keys. They keep their levels and report
bounded progress, counts and outcomes. ECH diagnostics report only the
selected configuration ID and HPKE suite, or the position and version of an
unsupported configuration. The ALPN-only `bs_debug` helper is test-only.

Shoes keeps ShadowTLS v3 session-ID HMAC and record framing. The client
authenticates/unwraps each server handshake record, gives its TLS ciphertext
to Rustls, and completes real certificate and Finished verification before
inner protocol setup. No separate preflight TLS connection or new ALPN mode is used.

Cargo ignores patches declared only by dependencies. An embedding workspace
must patch crates-io rustls to this exact maintained Git revision and
package subdirectory, alongside the same Shoes pin. Keep the selected Rustls
version and lockfile graph; do not adopt a mutable path in a shipped consumer.

# rustls-platform-verifier source provenance

rustls-platform-verifier 0.7.0 is copied from the published crate (Cargo.lock
checksum 26d1e2536ce4f35f4846aa13bff16bd0ff40157cdb14cc056c7b14ba41233ba0) at
source commit 996b1c903491641b17b3c9afb65d1352f6fc6b76. All original licenses
are retained. RUSTLS-PLATFORM-VERIFIER-UPSTREAM-SHA256.json identifies the 48
original files; RUSTLS-PLATFORM-VERIFIER-PATCH-IDENTITY.json identifies every
changed source file.

Only diagnostics change. A failed verification logs a bounded category of
the error (for example `invalid certificate: unknown issuer`) instead of its
text, which can carry the server name, certificate names or platform messages
quoting them; Android trust and revocation warnings no longer include the
system message. Verification, trust stores, revocation checks, errors
returned to rustls and the dependency graph are unchanged. The optional
`cert-logging` feature, which logs the end-entity certificate, stays off in
Shoes; consumers must not enable it.

Cargo ignores patches declared only by dependencies. An embedding workspace
must patch crates-io rustls-platform-verifier to this exact Git revision and
package subdirectory, next to the rustls patch; without it the registry
verifier, with its unbounded error text, is silently used.
