# RC2 / V5 remediation status

Branch: `remediation/private-matching-v4-rc2`, from `main` at `acd6789`.

RC1 is untouched. All sixteen frozen sources still match `af5baad`, verified by
`scripts/verify-frozen-sources.mjs` after every change. V5 is a parallel
generation, not an edit of the frozen files.

**No Monad run has been performed for V5**, per the standing instruction that no
Monad run precedes the freeze.

---

## Audit findings addressed

| Finding | Severity | Status | Where |
|---|---|---|---|
| C-01 pre-binding participant correlation | Critical | Corrected | `MordantSourceCommitmentRegistry.sol` |
| H-01 no binding between the two enrollments and one session | High | Corrected | `enrollment_v5.go`, `session_ledger.go` |
| H-02 circuit does not separately determine asset equality | High | Corrected | `MordantMatchResultV5.sol`, `circuit_v5.go` |
| H-03 operators release any evaluator-chosen ciphertext | High | Corrected | `operator_release_v5.go` |
| M-02 session not one-shot | Medium | Corrected | `MordantScopeGovernanceRegistryV5.sol` |
| M-03 same-block chronology ambiguity | Medium | Corrected | `MordantScopeGovernanceRegistryV5.sol` |
| M-04 retirement strands committed sessions | Medium | Corrected | `MordantScopeGovernanceRegistryV5.sol` |
| L-02 leak scanner never swept key material | Low | Corrected | `fhe-lab/privacy-v4/leak-scan.mjs` |
| L-03 terms scheme version signed but unchecked | Low | Corrected | `MordantSourceCommitmentRegistry.sol` |
| M-01 terms registry initialisation | Medium | Corrected | `MordantTermsRegistry.sol` |
| M-05 candidate reconciliation unauthenticated | Medium | Corrected | `MordantMatchResultV5.sol` |
| M-06 binder invariants / factory admission | Medium | **Open** | - |
| L-01 factory admission check | Low | **Open** | - |
| I-01 / I-02 / I-03 informational | Info | **Open** | - |

---

## The four gates

All four pass. Detail and measurements in `GATES.md`; raw Gate 1 data in
`gate1-determinism.json`.

Gate 1 is the load-bearing one, because the whole H-03 correction depends on
operators being able to compare recomputed ciphertexts as exact bytes. It was
measured, not assumed: 30 separate processes across two architectures, three key
loading orders and three thread counts produced **one** output digest.

Measured cost, which the owner pre-accepted: about **8.7 s of recomputation per
operator** on top of RC1's roughly 51 s ceremony, plus ~0.5 s key load and
~1.1 GB peak memory per operator. Recomputation was not weakened to recover RC1
latency.

---

## What changed, by layer

### Solidity (parallel V5 generation)

- `contracts/src/identity/MordantMatchResultV5.sol` - two released bits, a
  three-state outcome derived from them, (false, true) impossible, only
  `SameAssetPolicyConflict` bindable.
- `contracts/src/v5/MordantSourceCommitmentRegistry.sol` - opaque commit/reveal.
  Nothing correlatable is public before binding: no controller, no invoice root,
  no asset commitment. Reveal refuses a submitter that turns out to be the
  revealed controller, and validates both scheme versions.
- `contracts/src/v5/MordantScopeGovernanceRegistryV5.sol` - salt-independent
  session nullifier consumed at admission, and block numbers rather than
  timestamps so same-block ambiguity fails closed in both directions.
- `contracts/src/identity/MordantMatchResultV5.sol` also drops the tolerant
  "candidate alias" path entirely (M-05). The V5 circuit compares only the
  strict identifier, so there is no tolerant result for the schema to express;
  removing it is what makes the unauthenticated path unreachable rather than
  merely discouraged.
- `contracts/src/identity/MordantTermsRegistry.sol` (M-01) - `initialise` now
  takes only an anchor address, proves admission by reading the frozen factory,
  and reads every stored value from the anchor. The previous version accepted
  the asset commitment and the ISSUER as arguments and never read the anchor, so
  anyone could seed an unused id with a fabricated issuer. Amendments now
  require exactly one version step rather than merely increasing.
- `contracts/test/RC2Remediation.t.sol` - 27 tests. Full suite 244/244.

### Go (V5 protocol)

- `circuit_v5.go` - `RecomputeCircuitV5`, the deterministic circuit core both
  the evaluator and every operator run. Two outputs, no admission state.
- `enrollment_v5.go` - `SessionBindingV5` cross-certification. Each side names
  its own scope and the counterparty scope it expects, so two enrollments from
  different sessions cannot be paired by an evaluator.
- `session_ledger.go` - bbolt one-shot ledger. Session commitment, nullifier and
  both enrollment digests consumed in one fsynced transaction, surviving restart.
- `operator_release_v5.go` - the thirteen operator checks, release shares
  generated against the operator's **own** recomputation, `CombineReleaseBitV5`
  asserting the complete decrypted slot vector, and `ReleaseTranscriptV5`.
- Tests: `enrollment_v5_test.go`, `operator_release_v5_test.go`.
- `cmd/determinism-probe` + `scripts/gate1-determinism.mjs` - the Gate 1 harness.

### Product

- `src/lib/private-matching/config.ts` - the live path now fails closed below
  protocol V5. `canStartLiveSession` defaults its version parameter to the
  retired V4, so a caller that omits it gets a refusal rather than an
  unintended live V4 session.

### CI

- `fhe-go` job timeout raised to 45 minutes and `go test -timeout 40m`. The V5
  gate tests run real ceremonies and real threshold releases and exceed the
  default 10-minute per-package timeout by construction.

---

## Next, in order

1. **M-06 / L-01** binder invariants and the factory admission check.
2. **V5 verifier and binder.** Deliberately not written yet: their result core,
   typehashes, provider-proof binding and transcript fields stayed provisional
   until the gates passed. The gates have now passed, so the schemas listed
   below can be frozen against the shapes in `operator_release_v5.go` and
   `MordantMatchResultV5.sol`.
3. **Freeze**, once 1 lands: V5 result schema, provider-proof schema, V5
   verifier, V5 binder, validator digest, consent digest.
4. **Only then**, a fresh complete Monad run.

## Claims

Unchanged and still bounded. Nothing here establishes zero knowledge,
trustlessness, publicly proven FHE correctness, private settlement, hidden
transaction metadata, organizationally independent custody, fraud detection,
market completeness, absence of undisclosed pledges, or production readiness.
Gate 1's determinism result is scoped to one host, one OS and one Go toolchain.
