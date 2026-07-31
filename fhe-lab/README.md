# Mordant FHE decision gate

This directory is an isolated engineering spike for confidential receivables-policy evaluation. It
does not change Mordant's production contracts, M-15 runners, evidence artifacts, or UI.

The gate evaluates one policy only:

```text
same receivable
AND same currency
AND a.activeFrom < b.activeUntil
AND b.activeFrom < a.activeUntil
AND pledge A is exclusive
AND pledge B is exclusive
AND both submitters are authorized
```

## Boundaries

- Monad remains the canonical vault, recourse state machine, reserve, settlement, and receipt layer.
- FHE inputs and implementation types stop at the evaluator boundary.
- The onchain result contains commitments and the minimum actionable output, never pledge plaintext.
- A single-key run is a local circuit benchmark only. It is not an acceptable target architecture.
- The target prototype is a 2-of-3 threshold result plus an independently configurable validator
  quorum attestation bound to the chain, vault, policy, inputs, nonce, and expiry.

## Layout

- `openfhe/` records why the first candidate is currently blocked.
- `lattigo/` contains the exact-integer circuit and threshold benchmark.
- `shared/` contains provider-neutral schemas, field classification, vectors, and threat model.
- `monad-adapter/` contains a standalone verifier prototype and negative tests.
- `workflow/` connects a public provider result to a synthetic 2-of-3 quorum and the standalone
  verifier on an isolated Anvil chain.

Each child directory owns its own toolchain. Nothing in this lab is imported by the current Mordant
application or contracts.

The local workflow is an integration harness, not a distributed operator deployment. Its three FHE
parties and three attestation identities are synthetic and co-located on one machine. It proves wire
compatibility, threshold mathematics, digest binding, and adapter acceptance; it does not prove
independent custody, correct off-chain computation, or Monad testnet availability.

## Gate

**Result: `GO LATTIGO — controlled vertical-slice feasibility only`.** The exact policy, real local
2-of-3 cryptographic path, result authentication, replay protection, negative tests, serialization,
and measured latency passed. A cryptographically correct single-key demo would not have been enough.

This is simultaneously a **NO-GO for production or a separated external client**: authorization is
still a gateway hook, all shares are co-located, one-shot state is volatile, and the validator
attestation is not yet bound to the FHE result ciphertext or threshold transcript. The full evidence
and next boundary are in [`DECISION.md`](./DECISION.md).

## Reproduce the bounded workflow

```bash
node fhe-lab/shared/scripts/validate-spec.mjs
(cd fhe-lab/lattigo && go test ./... -count=1)
forge test --root fhe-lab/monad-adapter
node --test fhe-lab/workflow/workflow.test.mjs
(cd fhe-lab/lattigo && go run ./cmd/workflow | node ../workflow/run.mjs --stdin)
```

The workflow starts an isolated loopback Anvil instance; it is not a Monad transaction. Use a
native arm64 Go 1.24+ toolchain on Apple Silicon to reproduce the recorded benchmark.
