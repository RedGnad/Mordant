# V4 dealerless threshold custody gate

V4 removes the trusted dealer that the M-PRIV4 audit identified as the decisive defect. It does not
change the V3 result schema, the Monad verifier, the recourse consumer, the quorum or the policy
circuit, and it does not reinterpret any existing V2/V3 evidence.

## What the audit rejected

In V3 the evaluator process called `NewRuntime`, which generated all three RLWE secrets and all three
Shamir shares locally, and evaluated the circuit before it provisioned the operators and detached its
own parties. Input confidentiality against the evaluator was therefore an operational promise.

## What V4 does instead

```text
operator 1 process ─┐   each samples its own RLWE secret and its own Shamir polynomial
operator 2 process ─┼── pairwise private re-sharing over mutually authenticated mTLS
operator 3 process ─┘   with roster keys pinned on both ends; coordinator excluded

        │ public protocol shares only
        ▼
ceremony-coordinator ── aggregates public shares; holds no secret key, no share, no operator identity
        │
        ▼
collective public key · relinearization key · 9 Galois keys · operator-signed key manifest
        │
        ├─► ceremony-client A / B: verify the manifest, then encrypt
        └─► ceremony-evaluator: public material only, then a 2-of-3 network release
```

Setup runs in the N-out-of-N regime with all three operators contributing their raw local secrets;
release runs in the t-out-of-N regime through `Combiner.GenAdditiveShare`. Both address the same
ideal secret `S(0)`, which is why every operator can help generate the keys while any two can
release. The round-to-type mapping against Lattigo 6.2.0 is in `CEREMONY-DESIGN.md`.

## Commands

| Binary | Role |
|---|---|
| `cmd/ceremony-operator` | one operator; `-mode identity` generates its own key, `-mode serve` runs the ceremony then releases |
| `cmd/ceremony-coordinator` | drives public rounds, writes public artifacts |
| `cmd/ceremony-client` | verifies the key manifest, then encrypts one pledge |
| `cmd/ceremony-evaluator` | evaluates the policy and drives a 2-of-3 network release |
| `cmd/ceremony-lab` | parent orchestrator; builds, launches, verifies, writes commit-bound evidence |

```bash
go run ./cmd/ceremony-lab -out <evidence-dir> -repo . -root <work-dir>
```

## CRS

The fixed `mordant-lattigo-v6.2.0-kill-test-crs` seed is not used in V4. Every operator contributes
32 random bytes and the seed is
`sha256(domain, rosterDigest, parameterFingerprint, ceremonyId, keyEpoch, contributions in point
order)`. No single operator fixes it, and any verifier can recompute it from public data. The
contributions are revealed in one round without commit-then-reveal; under Lattigo's passive-adversary
model that is sound, and the limitation is recorded rather than papered over.

## What the gate establishes

- all three operators generate their secret material locally, in separate OS processes;
- no process, and no file on disk, holds more than one operator's Shamir share;
- the evaluator loads public material only, and cannot decrypt, provision operators or mint a
  release share;
- clients refuse an unknown operator set, wrong threshold, wrong key epoch, expired or revoked
  manifest, mismatched public key, mismatched evaluation keys and partial attestation;
- the exact unchanged policy evaluates under the collectively generated keys;
- every valid 2-of-3 coalition releases; one operator cannot;
- operator state is read from statements each operator signed with its own ceremony key.

## What it does not establish

- passive-adversary security only, per Lattigo; no operator proves its share was honestly computed;
- no proof of correct FHE execution; the release authenticates who endorsed a commitment;
- roster and PKI distribution remain a lab bootstrap assumption;
- three processes on one host under one administrator is process separation, not independent
  organizational custody;
- no production authorization, and no Monad transaction was performed for this gate.
