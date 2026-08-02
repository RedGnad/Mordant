# Private Matching V5 one-shot ceremony implementation evidence

> **FAILED BASELINE — DO NOT USE AS ACCEPTANCE EVIDENCE.** Independent audit rejected the
> implementation at `8d8150209f067c9be78896653536c4b0e7ba108e` with findings F-01 through
> F-10. In particular, its retry and abort/private-bundle claims are invalid. This document is
> retained for provenance and is superseded on the remediation branch by
> `one-shot-ceremony-audit-fail-remediation-2026-08-02.md`.

Date: 2026-08-02

Evidence classification: **IMPLEMENTATION EVIDENCE — NOT AN ACCEPTANCE VERDICT**

Architecture checkpoint: `61aa52a62096953ca1bb8ed624957815f22bc48f`

Implementation commit: `be6e6b240660213a6c9e6d02e443a0a068bceaab`

Implementation tree: `17b1635d9989fe36cb9cae8e3c51f20f66620fc6`

Branch: `remediation/private-matching-v4-rc2`

The implemented construction is the authorized ephemeral one-shot Lattigo ceremony. It creates
one fresh 2-of-3 key for exactly one bilateral privacy session. `keyEpoch` is fixed to `0` and
`maximumSessions` to `1`; the bundle is not a reusable key epoch and is not intended to support
multiple sessions. A failed attempt is terminal, cannot be recovered or regenerated under the same
identity, and can be retried only with a new attempt ordinal, nonce, CeremonyID, and cryptographic
material.

This record does not establish three-host acceptance, distinct administrative custody, malicious-
operator security, release readiness, or overall Private Matching readiness. The required clean run
on three hosts under three genuinely distinct administrators remains a later acceptance condition.

## Changed-file inventory

The focused implementation commit contains 21 files and 5,386 insertions:

- `fhe-lab/lattigo/README.md`
- `fhe-lab/lattigo/cmd/ceremony-coordinator/main.go`
- `fhe-lab/lattigo/cmd/ceremony-lab/evidence.go`
- `fhe-lab/lattigo/cmd/ceremony-lab/main.go`
- `fhe-lab/lattigo/cmd/ceremony-operator/audit.go`
- `fhe-lab/lattigo/cmd/ceremony-operator/audit_test.go`
- `fhe-lab/lattigo/cmd/ceremony-operator/main.go`
- `fhe-lab/lattigo/oneshotceremony/README.md`
- `fhe-lab/lattigo/oneshotceremony/bundle.go`
- `fhe-lab/lattigo/oneshotceremony/canonical.go`
- `fhe-lab/lattigo/oneshotceremony/envelope.go`
- `fhe-lab/lattigo/oneshotceremony/evidence_test.go`
- `fhe-lab/lattigo/oneshotceremony/obsolete_boundary_test.go`
- `fhe-lab/lattigo/oneshotceremony/protocol.go`
- `fhe-lab/lattigo/oneshotceremony/protocol_test.go`
- `fhe-lab/lattigo/oneshotceremony/reservation.go`
- `fhe-lab/lattigo/oneshotceremony/status.go`
- `fhe-lab/lattigo/oneshotceremony/storage.go`
- `fhe-lab/lattigo/oneshotceremony/transcript.go`
- `fhe-lab/lattigo/oneshotceremony/types.go`
- `fhe-lab/lattigo/oneshotceremony/witness.go`

No shared primitive outside `fhe-lab/lattigo` changed. No client, enrollment, evaluator, release,
Monad, ABI, contract, frontend, or product source changed.

## Implementation structure

- `types.go` defines the fixed one-shot constants, complete context, ordered three-operator roster,
  CeremonyID, context/roster/scope digests, lifecycle, and distinct-administrator validation.
- `canonical.go` supplies strict deterministic length-delimited big-endian encoding and rejects
  trailing, truncated, mixed, or alternative encodings.
- `reservation.go` and `storage.go` create signed pre-secret process/boot reservations, immutable
  CeremonyID and scope/attempt-ordinal markers, no-replace signing decisions, restricted stores,
  file/directory `fsync`, and exact-byte readback.
- `envelope.go` signs the complete domain-separated envelope with Ed25519, derives the signer from
  verification, and protects pairwise Shamir wires for only their X25519 recipient with AES-GCM.
- `transcript.go` enforces exact stage count, operation, sender order, round, Galois ordering,
  predecessor root, and authenticated ciphertext/receipt inclusion.
- `protocol.go` executes real Lattigo v6.2.0 secret generation, threshold sharing, collective public
  key generation, two-round relinearization-key generation, Galois-key generation, and independent
  concrete-key reconstruction by every participant. Randomized actions are durably marked before
  execution and poison the identity on failure. There is no resume or recovery constructor.
- `witness.go` implements the replicated cryptographically chained state witness. Accepted normal
  transitions require all three signatures; terminal abort requires two.
- `bundle.go` constructs and strictly verifies the exact canonical public bundle, `KeyID`, all-three
  manifest attestations, all-three private-ready attestations, per-operator encrypted share bundle,
  no-replace publication, and final witness/bundle readback binding.
- `status.go` implements the initial `ACTIVE` status and terminal 2-of-3 `REVOKED` or `EXPIRED`
  statement. Status histories are replicated and cannot reactivate or equivocate.

## Canonical identity and public bundle binding

The canonical context binds:

- context, protocol, serialization, envelope, manifest, public-bundle, status, and CRS schemas;
- exact Lattigo module version `github.com/tuneinsight/lattigo/v6 v6.2.0` and checksum
  `h1:HZrksD5u87bOr/4hWHI1Jhps14Tafdvb84Fxmi3dou0=`;
- key scope `BILATERAL_SESSION`, key epoch `0`, maximum sessions `1`, threshold `2`, and party count
  `3`;
- privacy domain, session identity, exact session commitment, attempt nonce and attempt ordinal;
- chain ID, policy ID/version, circuit version/digest, release layout, and maximum release-query
  budget;
- the exact serialized Lattigo parameter fingerprint and ordered Galois elements;
- immutable activation and expiry times and exact source commit;
- the ordered three operator points and, for each operator, distinct administrator ID, Ed25519 public
  key, X25519 public key, transport certificate fingerprint, runtime binary digest, Go version,
  operating system, and architecture.

Every signed contribution additionally binds the CeremonyID, context digest, roster digest, scope
binding, epoch, sender, optional private recipient, operation, round, Galois element, predecessor
transcript digest, input digest, payload digest, signature domain, and algorithm. The signer is
derived by verification against the bound roster; it is not trusted from an unverified label.

The unsigned public bundle binds the exact context and parameters, complete authenticated
transcript, CRS commitment, concrete public key, concrete relinearization key, Galois keys in exact
element order, derived `KeyID`, pre-manifest witness head, and initial `ACTIVE` statement. Each of
the three manifest attestations signs its exact canonical digest. Each private-ready attestation
binds that digest and the owning operator's sealed-bundle digest. The published bundle adds the
ordered attestations and is bound into the `PUBLISHED` and `COMPLETED` witnesses.

## State machine and monotonicity

The successful state sequence for the sampled one-Galois-element test ceremony was:

```text
1  RESERVED
2  RUNNING
3  CRS_COMMITTED
4  CRS_REVEALED
5  PRIVATE_SHARES
6  PUBLIC_KEY
7  RELIN_ONE
8  RELIN_TWO
9  GALOIS[0]
10 MANIFEST
11 PUBLISHED
12 COMPLETED
```

Every statement commits to its sequence, predecessor digest, previous/to phase, transcript digest,
material digest, optional abort reason, and CeremonyID. Each operator retains the same complete
chain. Replica verification rejects missing entries, rollback, deletion, reordering, digest forks,
or divergent terminal heads. No transition is accepted from `COMPLETED` or `ABORTED`; an expired
context cannot be opened.

The sampled abandonment chain was `RESERVED -> RUNNING -> ABORTED`. Its abort record contained two
valid operator signatures, an explicit reason digest, no private bundle, and no path back to a live
phase.

## Test-only artifact hashes and witness samples

Command:

```text
cd fhe-lab/lattigo
go test ./oneshotceremony -run TestLocalNonAcceptanceEvidenceSample -count=1 -v
```

Result: exit `0`, pass. Classification emitted by the test:
`LOCAL_SINGLE_HOST_NON_ACCEPTANCE`.

Successful sample from that exact execution:

- CeremonyID: `73117227b0e6ea076cf7b5dd31cfa25387922c0bb33434b9f4abf39feb2d887d`
- KeyID: `679447fdd749014f37fbeda6d5a2066d2e3854d28a9c3cac051a9d69d6d9cfb7`
- canonical context SHA-256: `76e6180d6c441ed8ceb4f8ecd9aecd00826e678c89f7b509e18443d5c5fb6a60`
- unsigned public bundle SHA-256:
  `bccc6f28849b3af2cc194b2f334dff9da521df614d027944fe2fd4fc0538500f`
- published public bundle SHA-256:
  `09a41c83bca07a4370a0122deb6278dce2f6751bdd4f8500224dc2b0d0c4f5b6`
- transcript root: `daacd43f30f7ed72bf8d16c68757e490139378570da35db262c2e27ca8e5f1e6`
- completed witness head:
  `b65a72505d2acafc74262026c7a9e629c0f9f1bd6034aefa5e0c78ea174152f3`

The public/evaluation key bytes use fresh randomized test material, so a later execution is expected
to have different key and bundle hashes. These values identify only this captured local execution;
they are not a golden production key or a reusable fixture.

Terminal-abort sample:

- CeremonyID: `dc6fa12231eb9bb20fe6861c414c58fd7545afa02d71adf38b768e2eb4dacc74`
- terminal phase: `ABORTED` (`13`)
- abort witness SHA-256:
  `339cee2474179a5d34edf99c04c024ff2bef6e64c59214126efefd420815ba50`
- abort witness head: `8cf56ce7482416f8a7b0cbb5fc586c357dcdca350cd74bf363fef000c720fdee`
- signatures: `2`
- private bundle created: `false`

This sample used three local directories and three test participants on one host. It deliberately
contains no topology attestation and must not be represented as the required three-host proof.

## Secret readers, cleanup, and exact residual inventory

Only the owning operator process reads its signing-key and X25519-key handles. Only the exact
recipient operator can open a recipient-bound pairwise Shamir wire. Additive RLWE keys, Shamir
polynomials and plaintext evaluations, aggregate shares, CRS reveal/seed, relinearization
ephemerals, and generation state are read only by that operator's live ceremony process. The
coordinator and evaluator receive no private accessor and cannot open any sealed operator bundle.
The later status/release boundary may use the owning operator's keystore handle and sealed bundle;
no release implementation was added here.

Successful completion can leave:

- each operator's mode-`0700` witness root containing immutable `used-*` and `scope-*` markers, all
  three signed reservations, one no-replace signing decision and one signed witness record per
  sequence, and any later signed status decision/record;
- one mode-`0700` public publication directory containing mode-`0600` `public.bundle`; despite the
  restrictive local mode, its verified contents are public;
- each operator's separate mode-`0700` private root containing a mode-`0600` `operator.bundle` whose
  ciphertext contains exactly that operator's aggregate threshold share plus bound private
  metadata;
- the owning operator's bundle-sealing key in its external keystore or process boundary; this
  package neither persists nor exposes that key;
- the operator signing/X25519 private keys in their external owning keystores; this package does not
  copy them into public or coordinator-visible storage;
- retained public transcript ciphertexts and receipts, public keys, manifests, runtime/source
  digests, witness/status chains, and audit evidence.

On success, live references to the additive key, polynomial, aggregate in-memory share, CRS
reveal/seed, relinearization ephemeral, signing-key copy, and transport-key handle are dropped. The
aggregate share remains only inside the owning operator's encrypted bundle.

On abort, no private bundle is created. Live private state is dropped. Reservations, no-replace
decisions, the signed public witness chain, and—if the attempt reached those phases—signed public
envelopes, ciphertext private wires, and receipts remain as failure evidence. No plaintext private
wire is persisted by the package, and no bytes from a failed attempt may enter a retry.

After terminal revocation or expiry and closure of every authorized release window, the owning
administrator must destroy its bundle-sealing key and delete its private bundle. Public evidence is
retained. Go memory, swap, crash/core capture, VM snapshots, backups, media, or administrators may
retain remnants: this implementation makes no secure-erasure or physical-erasure claim.

## Required-test mapping

All numbered cases are subtests of `TestOneShotCeremonyRequirements` in `protocol_test.go`:

1. Fresh three-operator completion and exact public-bundle verification.
2. Distinct contexts produce distinct CeremonyIDs.
3. Completed CeremonyID and same scope/attempt ordinal reuse are rejected.
4. A signed contribution from another CeremonyID is rejected.
5. Privacy-domain substitution invalidates the signed envelope.
6. Session-commitment substitution invalidates the signed envelope.
7. Lattigo-version and serialized-parameter mixing are rejected.
8. Reordered operator identities are rejected.
9. Repeated phase execution and reopening after immutable expiry are rejected.
10. A second conflicting signing decision at one sequence is rejected.
11. Public-key substitution invalidates the public bundle.
12. Transcript truncation and stage reordering are rejected.
13. A shorter replica is detected as witness rollback.
14. A divergent terminal branch is detected as a fork.
15. One abandoned operator produces a two-signature terminal abort without private disclosure.
16. An aborted ceremony cannot regenerate secrets or extend its witness.
17. A completed ceremony cannot transition or expose the cleared in-memory aggregate share.
18. Retry succeeds only after a new nonce/ordinal and produces a new CeremonyID, KeyID, and key.
19. Aggregate-share bytes are absent from public bundles, witnesses, and diagnostic errors.
20. An unexpected partial persisted file makes the store fail closed.
21. Canonical bytes are deterministic across serialization, byte-identical after parse/reserialize,
   and reject trailing alternative encoding.
22. Concrete public artifacts parse and verify on the current local OS/architecture while emitting
   no three-host topology claim.

Additional subtests prove that randomized failure permanently prevents regeneration under the same
identity; terminal status requires two signatures, is replica-consistent, cannot reactivate, and
cannot be signed inconsistently. `obsolete_boundary_test.go` proves the recovery executables are
default-build constrained and that `MCR1`/`MCL1` inputs are unconditionally rejected. The successful
fixture also reconstructs from two aggregate shares, completes an encrypt/decrypt correspondence
check, and rejects a single-share reconstruction.

## C/H/M finding mapping

| Finding | Implementation | Tests/evidence |
| --- | --- | --- |
| C-01 | `protocol.go`, `transcript.go`, and `bundle.go`: every operator receives authenticated shares, independently reconstructs the concrete public/evaluation keys, derives `KeyID`, and signs exact bundle bytes. | Cases 1, 11, 12; two-share correspondence and one-share refusal in the success fixture. |
| C-02 | `types.go` requires three ordered operators with distinct administrator, signing, encryption, and transport identities; stores/private roots are per operator and the package is transport-agnostic. | Cases 8 and 22; README topology boundary. Three-host proof remains unresolved. |
| H-01 | Recipient-only encrypted Shamir wires, no recovery API/parser, and one aggregate share per sealed operator bundle. | Case 19; obsolete magic rejection. |
| H-02 | Pre-secret reservations and durable generation markers precede randomized work; any external/random failure poisons the identity. | Cases 9, 16, 18 and randomized-failure subtest. |
| H-03 | No-replace reservations/signing decisions and three independently supplied witness stores prevent accepted-state replacement. | Cases 3, 10, and 20. |
| H-04 | CeremonyID plus immutable scope/attempt-ordinal markers reject same-ID and same-scope attempt reuse. | Cases 2, 3, and 18. |
| H-05 | Replicated signed, sequenced, predecessor-chained witness with all-three normal acceptance and 2-of-3 abort. | Cases 13–17; witness samples above. |
| H-06 | Exact envelope binds context/roster/scope, derived signer/recipient, operation/round/Galois, predecessor, input, and payload. | Cases 4–8 and 12. |
| H-07 | Exact canonical bundle, concrete-key `KeyID`, pre-manifest head, all-three manifest signatures, and all-three private-ready digests. | Cases 1, 11, 21, and 22. |
| H-08 | Immutable activation/expiry in context and initial status; 2-of-3 terminal status chain; no reactivation or RC2 rotation. | Case 9 and terminal-status subtest. |
| H-09 | Coordinator has no raw-share accessor; private wires are recipient-only; each sealed bundle belongs to one operator. | Case 19 and explicit reader/residual inventory. Cross-host custody audit remains later work. |
| H-10 | Source commit, Lattigo checksum, runtime binary, Go/OS/architecture, context and artifact hashes are signed/bound. | Case 22; exact commit/tree, validations, and artifact hashes in this record. |
| M-01 | No production secret canary was created; tests use only test-owned material and label the run local non-acceptance. | Case 19 and local evidence sample. |
| M-02 | Restricted no-symlink roots, no-replace writes, file/directory `fsync`, parse and exact-byte readback for public/private/witness artifacts. | Cases 3, 11, and 20; successful publication fixture. |
| M-03 | Context and schemas are mandatory; old `MCR1`/`MCL1` and mixed versions/domains are unknown. | Cases 4–8 and obsolete-boundary tests. |
| M-04 | One strict verifier parses and independently reconstructs the concrete public/evaluation objects before accepting bundle signatures. | Cases 1, 11, 12, 21, and 22. |
| M-05 | Exact source/tree, changed files, commands, hashes, witness examples, and residual inventory are recorded here; no runner or acceptance claim was added. | This record and `evidence_test.go`; clean three-host signed report remains required. |

## Validation transcript

All passing commands below were run with the implementation commit as the checked-out `HEAD`.

| Command | Exit | Concise result |
| --- | ---: | --- |
| `node scripts/verify-frozen-sources.mjs` | 0 | RC1 frozen sources `16/16`, commit `af5baad`. |
| `node scripts/verify-frozen-v5-sources.mjs` | 0 | V5 frozen sources `12/12`. |
| `node scripts/verify-v5-typehashes.mjs` | 0 | Frozen V5 typehashes `4/4`. |
| `cd fhe-lab/lattigo && go test ./oneshotceremony -count=1` | 0 | One-shot package passed. |
| `cd fhe-lab/lattigo && go test ./oneshotceremony -run TestOneShotCeremonyRequirements -count=1 -v` | 0 | All 22 required cases plus randomized-failure and status cases passed. |
| `cd fhe-lab/lattigo && go vet ./oneshotceremony` | 0 | No finding. |
| `cd fhe-lab/lattigo && go build ./oneshotceremony` | 0 | Package builds. |
| `cd fhe-lab/lattigo && go test -timeout 30m ./...` | 0 | All Lattigo packages passed, including real one-shot cryptographic tests. |
| `cd fhe-lab/lattigo && go test -tags obsolete_recoverable_ceremony ./cmd/ceremony-client ./cmd/ceremony-coordinator ./cmd/ceremony-evaluator ./cmd/ceremony-lab ./cmd/ceremony-operator` | 0 | Historical evidence tools remain reproducible only with the explicit obsolete tag where applicable. |
| `cd fhe-lab/lattigo && go build ./cmd/ceremony-lab` | 1, expected | Default build reports that build constraints exclude the obsolete executable. |
| `pnpm validate` in restricted sandbox | 1, environmental | Runner tests could not connect to their own `127.0.0.1:8551` RPC because the sandbox returned `EPERM`; no implementation assertion failed before that boundary. |
| `pnpm validate` with local-test network permission | 0 | ESLint: 0 errors/35 pre-existing warnings; unit: 131 pass; runner passed; Forge: 273 pass; evidence/secret scans clean with 42 reviewed suppressions; frozen/integration/format/hygiene gates passed; FHE: 206 pass; Next production build passed with the pre-existing `ox` dynamic-dependency warning. |
| `pnpm test:e2e` | 0 | Playwright `13/13` passed. |
| `cd fhe-lab/lattigo && go test ./oneshotceremony -run TestLocalNonAcceptanceEvidenceSample -count=1 -v` | 0 | Test-only success and terminal-abort evidence emitted with explicit non-acceptance classification. |

## Obsolete recoverable-code boundary

Historical recoverable source and evidence were retained. The old setup/recovery executables
`ceremony-coordinator`, `ceremony-lab`, and `ceremony-operator` are hidden from default builds by the
explicit `obsolete_recoverable_ceremony` build tag. The tag exists only to reproduce rejected
historical evidence; it is not a fallback, compatibility, migration, or production mode. The
one-shot package does not import the old implementation and unconditionally rejects its `MCR1` and
`MCL1` formats. Client and evaluator source was not modified.

## Unresolved limitations and acceptance gates

- No clean deployment or run has occurred across three separate hosts under three genuinely
  distinct administrators. Local directories/processes do not substitute for it.
- Operator transport, deployment, timeout supervision, and independent binary installation are
  external operational responsibilities; this package defines the authenticated protocol and
  transport boundary but does not add an orchestrator.
- Operators are honest-but-curious. Lattigo v6.2.0 does not provide the missing active proofs for a
  malicious operator; malformed contributions may abort availability.
- Security fails at two colluding operators and does not cover two-domain compromise, host
  compromise, traffic analysis, or a lying administrator.
- Tests use small, insecure, test-only BGV parameters for tractable execution. A later accepted run
  must bind reviewed production parameters and measure time, memory, network, and disk on the exact
  three-host builds.
- Cross-OS/architecture byte equivalence is not proved by the single local environment. The context
  records platform/build fingerprints so a mismatch fails closed and is reviewable.
- No client, enrollment, evaluator, release, Monad, ABI, or contract integration was authorized or
  performed. Status/release consumers remain outside this implementation.
- Cleanup is logical and best effort. No secure or physical erasure, HSM custody, backup deletion,
  or separate-organization independence is established.
- The independent reviewer, not this record, must decide whether the implementation closes any
  finding or may proceed to the later three-host acceptance exercise.

Overall product verdict remains:

**PRIVATE MATCHING AND GOVERNED RECOURSE: NOT PROVEN**
