# V4 result and state model

Parallel to V3. Every V3 type, contract and artifact is unchanged.

## Does a public V4 result exist before binding?

**No.** This is the central design decision and it follows from the anti-probing analysis.

Before binding there is no on-chain object at all: no result, no commitment, no receipt, no event.
The evaluated result is a **private object** held by the two submitters and attested by the 2-of-3
quorum off-chain. A V4 result becomes public only as the payload of a binding transaction, and only
for a positive match that both parties chose to disclose.

If a result were published before binding, its mere existence would be a negative-match oracle for
anyone who knew a session had run.

## `ConfidentialPolicyResultV4`

```solidity
struct ConfidentialPolicyResultV4 {
    uint256 chainId;                  // replay scope
    address binder;                   // intended binder contract (V3's `consumer` role)
    bytes32 policyId;
    uint32  policyVersion;
    bytes32 scopeCommitmentA;         // which authorized portfolio submitted A
    bytes32 scopeCommitmentB;
    bytes32 inputCommitmentA;         // canonical input commitment, unchanged derivation
    bytes32 inputCommitmentB;
    bytes32 matchCommitment;          // H(domain ‖ assetId ‖ matchSalt) — binds the private identity
    bool    matchConfirmed;           // encrypted 256-bit economic-asset equality
    bool    conflictConfirmed;        // matchConfirmed AND currency AND overlap AND exclusivity
    uint8   anchorCount;              // 1 for the selected vertical; 2 reserved
    uint256 nonce;                    // one-shot replay identity
    uint64  validUntil;
    bytes32 providerProofCommitment;  // unchanged V3 semantics
    bytes32 resultCommitment;         // keccak over the core, recomputed on-chain
}
```

### Field justification

Every field is present because the threat model requires it; nothing is carried "for symmetry".

| Field | Why it must exist | Why it is safe to publish at binding |
|---|---|---|
| `chainId`, `nonce`, `validUntil` | replay scope and expiry | standard, already public in V3 |
| `binder` | intended-consumer binding, the V3 property that stops a result being redirected | the binder is public anyway |
| `policyId`, `policyVersion` | the quorum attests a specific frozen circuit | public policy scope |
| `scopeCommitmentA/B` | proves two distinct authorized portfolios submitted; the anti-probing accounting key | a commitment over `(issuer, portfolio, epoch, salt)`; names no receivable |
| `inputCommitmentA/B` | binds each ciphertext and its context; the decision identity | already public in V3 |
| `matchCommitment` | the only link between the private identity and a later anchor binding | hiding commitment; opened only to the binder, see below |
| `matchConfirmed` | the asset-identity equality | **only ever published for `true`** |
| `conflictConfirmed` | policy breach, distinct from identity match | as above |
| `anchorCount` | one-anchor and two-anchor bindings are different transitions | public |
| `providerProofCommitment` | binds result ciphertext, threshold transcript, session, key epoch, circuit | unchanged V3 semantics |
| `resultCommitment` | recomputed by the verifier; nothing may be asserted | unchanged V3 semantics |

### Fields deliberately absent

- **No `vault` address.** V3 carries one; that is what makes V3 unable to host this mode.
- **No canonical receivable identifier.** `assetId` never appears in the result.
- **No stable public receivable commitment.** `matchCommitment` is salted per session, so the same
  asset produces an unlinkable commitment in every session. A stable commitment would let an
  observer join two bindings and learn that two anchors are the same asset without any authorization.

`matchConfirmed` and `conflictConfirmed` remain distinct because they carry different meanings and
different consequences: same economic asset (a discovery) versus policy breach (a recourse trigger).
A match without a breach is a legitimate, non-actionable outcome.

## Verifier changes versus V3

The V3 verifier keys everything by vault. V4 cannot, so a parallel verifier is required:

```text
currentPolicyVersion[policyId]                      // no vault dimension
allowedScope[issuerKeyId][scopeCommitment][epoch]   // authorization allowlist
replayKey    = H(chainId, binder, policyId, nonce)
decisionKey  = H(chainId, binder, policyId, policyVersion, sorted(inputA, inputB))
matchKey     = matchCommitment                      // joins the one-time set
```

`matchCommitment` becoming a one-time identity is what stops a single positive match being bound
twice, to two different anchors.

## Lifecycle

```text
  PRIVATE EVALUATION
    two authorized scopes co-initiate one sessionId
    each submits a FullFHE256 enrollment; neither names an anchor
    evaluator computes matchConfirmed and conflictConfirmed under encryption
        │
        ▼
  PRIVATE MATCH RESULT                       ← no on-chain artifact exists
    2-of-3 threshold release of the bounded Boolean
    quorum signs the canonical V4 core off-chain
    delivered only to the two submitters
        │
        │  matchConfirmed = false → terminal, nothing is ever published
        │
        ▼
  AUTHORIZED DISCLOSURE DECISION
    both submitters must consent (see below)
        │
        ▼
  ANCHOR BINDING                             ← first and only public artifact
    binder verifies quorum, mapping attestation, anchor state
        │
        ▼
  BOUND RECOURSE
    non-economic recourse record; cure window; governed action
```

### Who receives what

- **The private Boolean**: the two submitters only. The evaluator aggregates the release but the
  descriptor binds the result to the submitters' session.
- **Who authorizes binding**: both submitters. The binding transaction requires a mapping attestation
  from the anchor-side issuer *and* a disclosure consent signature from the counterparty scope's
  issuer, over the same `matchCommitment` and `sessionId`. One party cannot unilaterally publish that
  the other's private book contains a given asset.
- **Only one platform has an anchor** (the selected vertical): `anchorCount = 1`. The anchor-side
  issuer supplies the mapping; the off-chain side supplies consent only. What becomes public is that
  *this anchor* is in conflict — not the counterparty's identity or book.
- **Both have anchors** (`anchorCount = 2`, reserved): both mappings and both consents are required,
  and the record names both anchors. Not implemented in the first vertical.

### What becomes public at binding

The anchor address (already public), the fact of a conflict against it, `matchConfirmed`,
`conflictConfirmed`, both scope commitments, both input commitments, the match commitment, the
policy scope, the responsible role, the cure deadline and the consequence id.

### What remains permanently private

`assetId` and its preimage facts; the counterparty's book and portfolio contents; every commercial
term of both pledges; which specific receivable inside a portfolio the scope commitment covers; and,
for the off-chain side, its very existence beyond "some authorized counterparty scope".

## Migration boundary

V3 and V4 are parallel and share nothing that must change:

| Component | V3 (Mode A) | V4 (Mode B) |
|---|---|---|
| Verifier | `ECDSAQuorumConfidentialPolicyVerifierV3` (deployed) | new `…VerifierV4` |
| Consumer | `ReceivableAnchoredRecourseConsumer` (deployed) | new `PrivateMatchBinder` |
| Result schema | `ConfidentialPolicyResultV3` | `ConfidentialPolicyResultV4` |
| Enrollment | vault-scoped | scope-commitment-scoped |
| Identity mode | `IdentityPublicCommitment` | `IdentityFullFHE256` |
| Ceremony | dealerless 2-of-3 | **same, unchanged and mode-agnostic** |
| `MordantInvoiceVault` | unchanged | **unchanged — read-only through `IReceivableAnchor`** |

No V3 artifact, evidence item or transaction is modified or reinterpreted. Clients select the mode
by which enrollment type they build.
