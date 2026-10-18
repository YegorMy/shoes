---
type: architecture-index
project: shoes
generated_by: hive-generate-architecture within TICKET-c15e2cb7 SELF
last_updated: 2026-10-18
rag_baseline_commit: 0cfbc98bc67312974a5be0376cccc395170a9feb
sweep_query_count: 6
reference_source: supplied canonical tasks and actual takeover request
---

# Shoes architecture provenance and coverage

| File | Kind | Rule IDs |
| --- | --- | --- |
| purpose.md | Narrative | None |
| overview.md | Narrative | None |
| structure.md | Source placement | STRUCT-01 through STRUCT-04 |
| patterns.md | Runtime constraints | PAT-01 through PAT-05 |
| conventions.md | Source/tool/evidence conventions | CONV-01 through CONV-04 |
| security.md | Listener/TLS privacy and retained trust | SEC-01 through SEC-08 |
| testing.md | Verification and acceptance | TEST-01 through TEST-06 |

These are proposed governance documents until genuine native SELF review and
publication complete. Preserve `.hive/architecture.md` as the original bootstrap
stub and architecture finding `critical-795701ed9e` as real historical evidence;
neither the stub nor these authored bytes retroactively resolve that finding.

The installed stack detector reported Rust/native/Tokio with `cli` tag, no ORM or
database tag. Direct root Cargo/source inspection found no database dependency,
migration or SQL persistence layer; `data-model.md` is deliberately omitted.
This says nothing about storage used by external embedding applications. No
domain files exist. Package and locked dependency observations are in purpose
and conventions; no dependency update is requested.

## One supplied reference layer

The reference is the complete canonical original infrastructure and source task
bodies plus the actual current human takeover request. It is not a web-best-
practices layer or a reconstructed earlier conversation. Ordinary preserved
copies are `/private/tmp/shoes-privacy-takeover.QuHCmb/infra-original-body.md`
(8796bytes; SHA256 b604277a9c0ce92363ed6d94b69dc1405dc3a4ed94817ad7cb7cc4d7f3acf6f1)
and `/private/tmp/shoes-privacy-takeover.QuHCmb/source-original-body.md`
(128166bytes including the full inert historical appendix; SHA256
998081edfa079d2d299744534f8e8a3173f7b13bb492f7d0e494c6f39cc791d4).
The feature's `TAKEOVER_REQUEST.md` preserves the actual current human quotes,
including that the earlier independent conversation is unavailable.

| Supplied requirement cluster | Preserved rules/context |
| --- | --- |
| Narrow maintained-source remedy, provenance/package/API/wire identity | STRUCT-01–04, CONV-02, SEC-03/07 |
| Live diagnostics, protected content, exact startup-bind context | SEC-01–04, PAT-04, TEST-02 |
| Full raw channels, positive/negative controls, fixture attribution | SEC-04, TEST-01/02/05 |
| Certificate/name/pin/Apple trust, fail-closed initialization | SEC-05, TEST-03/04 |
| Authentication/refusal/revocation/outbound independence | PAT-02, SEC-06 |
| Readiness/stop/reload and UDP/EOF compatibility | PAT-01/03/05, SEC-07 |
| Real infrastructure/host and explicit mobile/reference-peer stages | CONV-04, TEST-01/03/04 |
| Fresh all3/integration/approval, historical evidence preservation | CONV-03, TEST-05/06 |
| Separate consumers, smoke RED, AnyTLS EOF, device/deployment limits | purpose.md, PAT-05, TEST-04/06 |

Historical compressed reports/captures remain lossless inert provenance and
negative evidence. This mapping preserves their applicable task constraints;
it neither converts historical claims into new receipts nor republishes their
large encoded payload as architecture rules. Full reference files remain intact.

## Sweep and actual limits

Six complete purpose/overview/structure/patterns/security/testing questions ran
through installed bounded `research`; conventions were read directly. Full
ordinary responses and the source discovery scratchpad are in the outer takeover
directory as `architecture-research-*.json` and
`architecture-discovery-scratchpad.md`. All six report RAG/graph status `ok`
without provider/graph errors, but overall `partial` because graph output hit
the 20k/22k character budgets. This is not complete graph coverage. Direct known
source/config/test reads established cited semantics; ambiguous repeated-name
graph edges were not assumed correct.

RAG is populated3432chunks/412files, ready/fresh at `0cfbc98`, with base-only
coverage and no overlay. The settled producer recorded a fetch failure for
`src/anytls/anytls_server_session.rs`, leaving12estimated chunks absent. That
file was inspected locally where needed; no complete semantic corpus claim or
index/cache manipulation was made. Graph baseline is also `0cfbc98` and fresh.

Source `0cfbc98` contains the existing candidate remedy plus metadata bootstrap
on accepted `ade6949fc95ab2a3ce4bf1a36d0346e24954c8ae`; it is not newly accepted.
Separate infrastructure candidate `f19680` changes only verification/CI/docs/
runner and is unaccepted with real unit/lint RED. New canonical source
`TICKET-8fe6bb32` depends on infrastructure `TICKET-3701ee88` and governance
`TICKET-c15e2cb7`; those dependency declarations are not completion evidence.

Known drift: standalone `src/main.rs` Debug-formats full loaded configuration
before server startup. This path is outside the exercised embedded TLS fixture;
its actual output/privacy impact is unevaluated here, not silently accepted or
remedied. Other propagated error strings may contain names internally; an actual
output route must be established before calling them disclosures. These limits
preclude a blanket whole-process privacy/security claim and grant no new source
write scope. No independent peer, mobile/device, consumer or deployment acceptance
is claimed by this architecture draft.
