# Shoes privacy-remedy workflow

The operator authorized a separate maintained-fork source-fix workflow and its
necessary Hive setup. Bootstrap began from clean commit
`ade6949fc95ab2a3ce4bf1a36d0346e24954c8ae`. No logging remedy or replacement
consumer pin is supplied by bootstrap.

The repository root is both the project root and this independent workspace
root. Use explicit absolute project paths for role assumption; do not assume
that the basename denotes a child directory. Use only the installed
`/Users/yegormy/.claude/hive/bin/hive-tools.cjs`, its matching skills/help/Atlas,
and clear any frozen-checkout `HIVE_CORE_ROOT` override. Do not modify Hive Core.

## Verification bootstrap limitations

`.hive/verification.yaml` is an exact deterministic distillation of existing
CI, not an accepted host-verification design or a test result. Its T1 schema
validation passes; the preview separately reports policy coverage warnings.

- `unit` includes the workspace library/binary tests and `listener_logging`.
- `lint` includes formatting and all-feature/all-target clippy.
- `build` combines the iOS script, Android NDK build and host workspace build.
  This composite is not certified runnable on the current host.
- The matrix/context-dependent integration block is excluded by the
  conservative distiller. No integration execution is claimed.
- No `typecheck` command is distilled. Do not invent one to satisfy a label.

Before dispatching the logging remedy, land separately reviewed project-owned
verification infrastructure that covers the required host and privacy
regressions, preserves the actual mobile/independent-peer obligations at their
appropriate stages, and exposes unsupported environments as gaps. Use real CI
and runner semantics; never hide an unsupported check behind success, delete
existing coverage, weaken policy, or modify an active captured policy.

## Acceptance boundary

Preserve complete failed and passing evidence and keep collectors live at
DEBUG/TRACE. Only explicitly configured listener startup binds are allowed;
traffic addresses, SNI, credentials, keys, handshake/ticket/application payloads
and arbitrary error formatting are not. A source fix must retain useful bounded
non-secret diagnostics and transport/authentication behavior, not lower log
levels or filter captures.

Produce an exact committed candidate, ancestry/diff provenance and fresh checks
and independent reviews before any consumer adoption. The retained server smoke
RED, separate AnyTLS EOF issue, callback/projection gate, final pin reconciliation
and physical-device/deployment gates remain unchanged. The architecture file is
still a stub; no domain/contract analysis or feature acceptance is implied.
