# V5 one-shot ceremony audit-fail remediation evidence

Date: 2026-08-02

Classification: `LOCAL SINGLE-HOST REMEDIATION EVIDENCE — NOT ACCEPTANCE`

Global verdict: `PRIVATE MATCHING AND GOVERNED RECOURSE: NOT PROVEN`

This record covers only the focused repair of F-01 through F-10. It does not claim three-host or
cross-platform acceptance, Byzantine-operator security, secure erasure, production readiness,
Private Matching readiness, or governed recourse proof.

## Git provenance

- Failed baseline: `8d8150209f067c9be78896653536c4b0e7ba108e`
- Failed baseline parent: `be6e6b240660213a6c9e6d02e443a0a068bceaab`
- Failed baseline tree: `5b4d67cfd6abcd7512a45f8611e478f2f61de355`
- Unchanged remote comparison branch: `origin/audit/private-matching-v5-oneshot-failed`
- Remediation branch: `remediation/private-matching-v5-oneshot-audit-fail`
- Test commit: `a419b2d9c6d3f53196cc1f3441eaa9a5cebb8486`, tree
  `178c0d7d8072218515e934be8f3df53bb1db48dd`
- Cryptographic/lifecycle commit: `eb66bbb416bdc86bc843c5e848489e0f047e6003`, tree
  `f649cdce328603cd013fdcf0bd0ac455ac2b28b3`
- Storage/witness/obsolete/provenance commit:
  `af20f7a62561af290cde0a7d3b839ae5d88b8342`, tree
  `b77ef7e0cd82e088ba156d48efca2a01ed411bc0`

The remediation was branched directly from the failed baseline. No failed commit was rewritten or
squashed.

## Finding-to-code and finding-to-test mapping

| Finding | Enforced property | Production mapping | Regression mapping |
| --- | --- | --- | --- |
| F-01 | Fixed roster coordinates `1,2,3`; unique/non-zero; denominators invertible for every Q/P modulus before secrets | `oneshotceremony/types.go`, `protocol.go` | `audit_remediation_test.go` F-01; real one- and two-share correspondence in `protocol_test.go` |
| F-02 | Canonical exact bundle bytes, create-only publication, fsync/readback receipt, `PUBLISHED` and `COMPLETED` receipt binding | `bundle.go`, `protocol.go` | F-02 missing/replacement/truncation/stale/digest/wrong-ceremony cases |
| F-03 | Deep-copied canonical context in participant and signed reservation; copy-returning accessors | `types.go`, `reservation.go`, `protocol.go`, `witness.go` | F-03 mutates roster fields, Galois slice, caller input, accessor and reservation snapshot |
| F-04 | Fixed MVP ordinal and create-only bilateral-session consumption independent of nonce/CeremonyID | `types.go`, `reservation.go`, `session_registry.go`, `storage.go` | F-04 sequential invalid ordinal, 12-way concurrency, restart and restored witness snapshot |
| F-05 | Statement-only event digest; separately hashed canonical signature artifact; durable per-sequence signing decision | `witness.go`, `storage.go`, `protocol.go` | F-05 all 2-of-3 subsets, reversed signature order, selective views and conflicting reason |
| F-06 | Stable create-only sequence slots, predecessor checks, three compatible replica histories before signing, terminal poison on ambiguity | `storage.go`, `witness.go`, `protocol.go`, `session_registry.go` | F-06 stale replica at every boundary, concurrent abort/progress append and ambiguous restart tombstone |
| F-07 | Private bundle consumer requires exact completed witnesses, KeyID, public bundle, publication receipt, private-ready digest and local completed tombstone | `bundle.go`, `protocol.go`, `session_registry.go` | F-07 stages real sealed bytes, aborts, verifies terminal tombstones and rejection by the supported consumer |
| F-08 | Recovery implementation and five historical commands require the explicit obsolete tag; historical output is non-acceptance | recovery build-tagged sources, `cmd/ceremony-*`, `README.md` | F-08 default package/dependency/build boundaries; `obsolete_boundary_test.go` parser and tag checks |
| F-09 | Concrete executable SHA-256, embedded VCS revision/dirty bit, Go/OS/arch/dependency state, context/bundle/receipt/witness bindings | `provenance.go`, `cmd/oneshot-provenance/main.go` | F-09 builds/runs/hashes a real binary, verifies live HEAD, rejects tampering and synthetic fixture provenance |
| F-10 | Durable create-only generation marker precedes secret/CRS-dependent randomness; replay or concurrent generation poisons | `storage.go`, `protocol.go`, `bundle.go` | F-10 eight concurrent generators, marker replay, restart and restored snapshot; repeated ten times |

All hostile tests call production parsers, verifiers, stores, participants, publication and bundle
consumers. The tests do not implement a second acceptance verifier.

## Resulting semantics

The construction remains one fresh key for one bilateral application session. It is not a reusable
key epoch and its public bundle is not intended to support multiple sessions. The durable session
binding includes key scope, service identity/version, privacy domain, bilateral session identity and
commitment, chain, policy identity/version, circuit identity/version, exact parameter fingerprint,
release layout and query budget. The ceremony nonce and CeremonyID cannot reopen that binding.

Activation requires exact bundle publication readback and three matching completed witness
histories. Expiry is immutable. No RC2 rotation or positive reusable epoch exists. Abort or poison
consumes the application session; retry requires a new bilateral session. Emergency revocation and
expiry remain separate terminal 2-of-3 status statements and cannot reactivate a key.

Each operator process alone reads its signing key, X25519 transport key, live RLWE/Shamir material
and its sealed threshold bundle. Coordinators, clients, evaluators and evidence processes do not read
those private artifacts. On completion or terminal failure, the implementation drops reachable live
secret references. A completed operator retains only its sealed bundle and sealing key for the
authorized release window. After terminal revocation/expiry and closure of that window, the owning
administrator must destroy the sealing key and delete the sealed bundle. Signed reservations,
decisions, witnesses, tombstones, canonical public artifacts and evidence are retained. Bytes can
remain in memory remnants, snapshots, backups or media; no physical or secure-erasure claim is made.

## Validation results

| Command | Result |
| --- | --- |
| `go test ./oneshotceremony -run '^TestAuditFailRemediations$' -count=1 -v` | PASS, F-01 through F-10 |
| `go test -timeout 30m ./oneshotceremony -count=1` | PASS, `113.634s` |
| `go test -race -timeout 30m ./oneshotceremony -count=1` | PASS, `262.238s` |
| `go test -timeout 30m ./oneshotceremony -run '^TestAuditFailRemediations/(F-04|F-06|F-10)' -count=10` | PASS, `156.944s` |
| `go vet ./oneshotceremony ./cmd/oneshot-provenance` | PASS |
| `go build ./...` | PASS; default list excludes all five historical ceremony commands |
| `go build -tags obsolete_recoverable_ceremony ./...` | PASS |
| `go test -timeout 30m -tags obsolete_recoverable_ceremony ./cmd/ceremony-client ./cmd/ceremony-coordinator ./cmd/ceremony-evaluator ./cmd/ceremony-lab ./cmd/ceremony-operator ./internal/thresholdnet` | PASS |
| `go test -timeout 30m ./...` | PASS; root `730.121s`, thresholdnet `18.590s`, one-shot `130.758s` |
| `pnpm fhe:test` | PASS, 206/206 |
| `pnpm validate` | PASS, including frozen-source, ABI, Solidity formatting, hygiene, secret scan, contracts, V5, and Next.js build |
| `pnpm test:e2e` | PASS, 13/13 |
| `git diff --check` | PASS |

The Go commands used isolated caches under `/tmp`. Network-listening Go and Node tests were executed
with loopback permission after their first sandbox-only attempts were refused with `EPERM`; the
successful reruns above are the validation results.

## Operational requirements still unproven

- execution on three separate hosts under three genuinely distinct administrators;
- independent writable storage, session registry, private keystore and backup domains per operator;
- real transport authentication, certificate issuance/revocation and network partition behavior;
- deployment monitoring and operator procedures at every crash/partial-replication boundary;
- actual runtime binaries matching each manifest operator identity on those hosts;
- cross-platform behavior and retained three-host evidence;
- active/Byzantine malicious-operator security beyond the stated passive/fewer-than-two-collusion model;
- physical deletion, secure erasure, swap/core-dump/media cleanup;
- client, enrollment, evaluator, release, Cleanverse, Monad, contract or frontend integration for this remediated ceremony.

No client, enrollment, evaluator, release, Cleanverse, Monad, contract, frontend, reusable-key-epoch,
multi-service or unrelated product implementation was performed in this remediation.
