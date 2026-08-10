# Coalition release V5

Status: **on the canonical product path, fail-closed, co-located operators.**

A coalition case has no secret key. Its collective key comes out of a t-of-n ceremony, each operator
seals only its own Shamir share, and releasing the result needs a quorum of operators that each
verify the participants' enrollments and recompute the circuit for themselves.

The difference from the governed decryptor is not that the release is checked more carefully. It is
that **there is no object anywhere in the case that could decrypt on its own**, so there is nothing
to fall back to. A coalition case whose quorum cannot be assembled does not release, and cannot.

## Shape

| | Governed decryptor | Coalition |
|---|---|---|
| Release mode | `governed-decryptor-v1` | `coalition-v5` |
| Key origin | generated for the case | t-of-n ceremony |
| Secret key object | `secret-key.bin` | **none** |
| Release authority | one ed25519 key | the published threshold manifest, by digest |
| Released facts | one `conflict` boolean | `sameEconomicAsset` and `policyConflict`, separately |
| Quorum | 1 | 2 of 3 |

The case binding refuses an authority key in coalition mode rather than ignoring one. A key there
would recreate the single signer the coalition exists to remove.

## What each operator does for itself

- Loads its own sealed share; no share is ever exported or reassembled.
- Builds **its own evaluator** from the published public material, rather than sharing one object.
- **Derives its own enrollment trust store** from the signed case binding. An operator handed a list
  of issuers would be trusting whoever handed it over.
- Runs the fourteen named pre-release checks, then recomputes the circuit.
- Releases a key-switch share **against the ciphertext it computed itself**. The coordinator's
  proposal is compared, never decrypted.

Because the operators compare recomputations, the public circuit constants are fixed
(`NewCoalitionEvaluationRuntime`). With a freshly encrypted constant two honest operators would
produce different bytes and the comparison would mean nothing.

## The result is checkable by someone else

The released result carries no release-authority signature, because a coalition has no single key.
What it carries instead, per released bit per serving operator, is that operator's **signed**
statement: point, slot, statement digest and ed25519 signature. The signing keys are published in
the case's threshold manifest, whose digest is the case's release authority identity. A verifier
reads the manifest and checks the signatures directly rather than trusting that the coordinator
did.

## Failure is closed, everywhere

- Fewer reachable operators than the threshold: `ErrCoalitionQuorumUnavailable`, no release.
- An operator refuses a check: terminal for the session. The coalition is named **before** anyone
  verifies, because each operator checks its own membership, and an operator's ledger admits a
  session once, so a second coalition sharing a member cannot be tried afterwards.
- Two operators recompute different outputs: `ErrCoalitionOperatorDivergence`, terminal. Not
  resolved by majority: picking one would be picking which one to trust.
- The published evaluation disagrees with the recomputed circuit: `ErrEvaluatorMismatch`, terminal.
- A quorum failure names the failing check per operator, so a refusal can be read.

## H-02 and H-03

**H-02.** A single conjunction cannot distinguish "different receivable" from "same receivable, no
policy conflict". The coalition releases the two bits separately, each by its own quorum of shares
against its own threshold session. The test pledges the **same** receivable on both branches and
varies only the activity windows: the asset bit is true either way and only the policy bit moves.

The two are reported as released. What their combination means commercially is a policy question
answered elsewhere, and this layer does not answer it.

**H-03.** The evaluator's proposed output is never decrypted and is never the release target: the
descriptor carries what was recomputed locally. It is still compared, because a published result
that disagrees with the circuit means one of the two is wrong.

## What this does not establish

**Every operator runs in this process.** One address space holds all three shares at once. This is
recorded in the released result as `operatorTopology: colocated-single-process`, and it means:

- **not operational independence** — three processes on separate hosts is a later increment;
- **not institutional decentralization** — all three operators are under one administrator;
- the ceremony is dealerless as a protocol (no party ever holds the collective secret, each erases
  its transient RLWE secret before sealing), but a run of it in one process is not evidence of
  distributed custody.

Operator-versus-operator divergence is enforced in code and is **not yet induced by a test**: with
one public root every operator loads identical evaluation keys, so producing an honest divergence
needs the separate binaries of a later increment.

## Settlement is not connected

The deployed case adapter fixes `expectedGovernedReleaseAuthorityId` to a single immutable
authority ID. A coalition has no such identity, so **a coalition result cannot currently be settled
on chain**. This is a contract-level change and it is the blocker for the settlement increment. It
is deliberately not worked around by routing the coalition back through a single authority key.

## Settling a coalition release

A coalition result reaches an economic consequence through the same three legs as a governed one,
with one identity replaced.

**Settlement authority.** `verifyCoalitionEvidence` replaces the single Ed25519 check. It recomputes
the threshold manifest's digest and requires the result to name it, so the release identity is
*derived* rather than read; requires the serving coalition to be the manifest's own operators at or
above its quorum, with no repeated point; and verifies each operator statement's Ed25519 signature
against the key the manifest publishes for that point. Operator statements are plain signatures over
a 32-byte statement digest, so this needs no reimplementation of the threshold encoding.

It returns the same `GovernedResultFacts` the governed path produces, so **`deriveSettlementPlan` is
unchanged**. It still reads exactly one field from the result, `policyConflict`, and takes every
economic term from the pre-committed profile. `sameEconomicAsset` never becomes an economic input.

**Bridge.** Unchanged. The attestor is a secp256k1 signer of the EIP-712 payload, never the release
identity, and it signs only after the coalition evidence has been verified.

**Adapter.** `MordantCoalitionAdapter`, deployed per case as V2 already was. It pins the threshold
manifest digest and the required quorum, carries both released bits, and refuses the vector the
circuit cannot produce.

| | Governed | Coalition |
|---|---|---|
| Off-chain check | one Ed25519 signature | quorum of operator signatures against the manifest |
| Release identity | authority key identifier | threshold manifest digest |
| Plan input from the result | `conflict` | `policyConflict` |
| Economics | pre-committed profile | pre-committed profile, unchanged |

### What the off-chain verifier does not establish

The binding of each operator statement to *this* release is not re-derived in TypeScript. An
operator signs the digest of a statement built from the threshold descriptor it recomputed, and that
binding is checked by the combiner in the release path, before any result exists. Re-deriving it
here would mean reimplementing the threshold encoding in a second language, and a second
implementation that drifts is worse than one trusted for a stated reason.

So the verifier establishes that the identity is the manifest's and that the quorum is authentic. It
relies on the release path for the statements being about this release.

### Executed locally, not deployed

The contract is exercised against a real 2-of-3 spine release: the Foundry suite reads the digests a
coalition run actually produced. **It has not been deployed to testnet.** Deploying a case adapter
needs a funded deployer, and that decision is separate from this work.
