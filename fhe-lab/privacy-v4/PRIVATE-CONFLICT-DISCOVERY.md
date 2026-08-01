# Mode B architecture study: Private Conflict Discovery

Written after M-PRIV5C proved Mode A. This is a study and a schema proposal, **not an
implementation**. It ends at the owner-approval boundary because the answer to study question 6 is
that V3 cannot carry Mode B.

## 1. Does either enrollment currently reveal a common vault or stable identifier?

**Yes, mandatorily, and this is the finding that decides the whole study.**

`CiphertextEnrollment` (`enrollment.go:27`) carries `InputContext` and `AuthorizationClaim` to the
evaluator **in cleartext**. Validation at `enrollment.go:151-154` requires:

```go
if context.Vault == ([20]byte{}) { return ErrMalformedEnrollment }   // vault is mandatory
if claim.Vault != context.Vault  { return ErrUnauthorizedIngress }   // claim must match it
```

and `enrollmentSigningDigest` commits `addressWord(context.Vault)` and `addressWord(claim.Vault)`.
The evaluator recomputes each input commitment from that context, so it must read the vault.

Consequence: **both facilities present the same vault address, in cleartext, before any evaluation
happens.** Switching the identity mode to `IdentityFullFHE256` would encrypt
`ReceivableID` and add a homomorphic 256-bit equality, but the evaluator would already know both
inputs concern the same vault. That is precisely the

```text
public vault X + encrypted copy of invoice ID X
```

shape the brief identified as low value. The FHE equality would cost roughly +2.4 s and +12.5 MB per
pledge (measured in `DECISION.md`) to prove something the transport already stated.

**Mode B cannot be obtained by flipping the identity mode on V3.** The leakage is in the enrollment
envelope and the result core, not in the circuit.

Two further stable identifiers are shared today: `PolicyID` (acceptable, it is policy scope, not
asset identity) and the fact that `InputSlot ∈ {0,1}` pairs the two inputs into one session.

## 2. How can both sources be authorized without disclosing receivable identity?

Today authorization is `AuthorizationClaim{SubjectCommitment, Role, Vault, PolicyID, ...}` signed by
one issuer registered on the evaluator. It binds a submitter to a **named vault**.

Mode B needs authorization that binds a submitter to a **class of receivables it may claim against**,
without naming one. Proposal:

- Each platform runs its own issuer and is registered independently on the evaluator
  (`RegisterEnrollmentIssuer` already supports multiple issuers).
- The claim's `Vault` field is replaced by a **funding-scope commitment**
  `scopeCommitment = H(issuerKeyId ‖ portfolioId ‖ epochSalt)` naming a portfolio the platform is
  entitled to finance, never an individual receivable.
- Admission is per `(issuer, scopeCommitment, epoch)` with a per-epoch **submission budget**. This
  is the anti-probing control: an unlimited submitter could enumerate candidate identifiers and use
  the Boolean as an oracle.

The evaluator therefore learns *which two platforms are disputing within which portfolios*, which is
unavoidable if it is to authorize them at all, and does not learn which receivable.

## 3. Safe binding from a private match to an on-chain receivable

The danger is that the match result becomes a probing oracle or is redirected onto a different
receivable. Four attacks and their controls:

| Attack | Control |
|---|---|
| **Arbitrary identifier probing** — submit many guessed identifiers and read the Boolean | Per-epoch submission budget per `(issuer, scopeCommitment)`; one-shot enrollment nonces (already enforced); the Boolean is released only to the two submitters, never to a public channel |
| **Result substitution** — attach a different evaluation to this binding | Unchanged V3 machinery: `providerProofCommitment` binds the result ciphertext, threshold transcript, session, key epoch and policy circuit; the quorum signs the exact canonical core |
| **Anchor substitution** — bind a genuine match to an unrelated vault | The anchor must **prove it is the matched asset**, not be asserted. The consumer requires an opening of the matched identifier against the anchor's own `invoiceRoot` |
| **Replay across receivables** | Replay, decision and provider-proof keys become anchor-scoped once the anchor is revealed; the decision key is derived from the two input commitments, which are per-session |

The binding step is the novel part. After the threshold release, exactly one of the two submitters
(or both) reveals the matched identifier's opening to the consumer:

```text
matchCommitment = H(domain ‖ receivableId ‖ matchSalt)     // computed inside the client
anchor.invoiceRoot() == receivableId                        // checked on-chain at binding time
```

The result carries `matchCommitment`; the binding transaction carries `(receivableId, matchSalt)`
and the anchor address. The consumer recomputes the commitment and requires it to equal the one the
quorum signed, and requires `anchor.invoiceRoot() == receivableId`. An attacker who has not seen the
opening cannot bind, and an opening for receivable X cannot bind to an anchor for Y.

**The identifier becomes public at binding time.** That is deliberate: recourse against a public
receivable is a public act. Mode B's claim is that identity stays private *through discovery and
evaluation*, not forever.

## 4. Who may learn that a private match occurred?

- **The two submitters**: yes, that is the product.
- **The threshold operators**: they learn a session released a Boolean; a 2-of-3 coalition learns
  the Boolean's value. They do not learn the identifiers.
- **The evaluator**: learns that two authorized scopes produced a session and, after release, the
  Boolean. Not the identifiers, amounts, currency or periods.
- **The public**: nothing until binding. After binding, the receivable, the fact of a conflict and
  the recourse record are public.
- **Non-match sessions must stay unbound.** A `false` result must never produce an on-chain artifact,
  otherwise the absence of a record leaks information about probed identifiers.

## 5. One or two public anchors?

Both cases are real and they differ materially.

- **One anchor** — the same receivable was financed twice on two platforms, but only one vault was
  ever tokenized. Binding names that vault. This is the common case and the one to implement first.
- **Two anchors** — each platform tokenized its own vault over the same underlying invoice. The
  match means *these two distinct vaults are the same economic asset*. Binding must then name **both**
  and record a cross-anchor conflict, and both openings must be produced. This is the genuinely
  differentiated case and it is the one no access-control design can reach, because neither platform
  can be asked to hand its receivable list to the other or to a shared intermediary.

The schema below carries `anchorCount ∈ {1,2}` so the two-anchor case is not retrofitted later.

## 6. Can V3 support this? — No.

V3 blocks Mode B in three independent places:

1. `CiphertextEnrollment` **requires** a non-zero cleartext `InputContext.Vault` and a matching
   `AuthorizationClaim.Vault`.
2. `PublicPolicyResultV3Core` **contains** `Vault [20]byte`, so the signed result names the asset.
3. The verifier keys policy configuration by vault: `currentPolicyVersion[vault][policyId]`, and
   `replayKey`/`decisionKey` are vault-scoped.

Distorting V3 to carry a placeholder vault would be exactly the "do not distort V3" failure: it would
weaken Mode A's anchor binding, which M-PRIV5C just proved, to accommodate a mode with different
requirements.

---

## Proposed V4 schema (for owner approval)

### Enrollment: `CiphertextEnrollmentV4`

Replaces the vault-bearing context. Changed fields only:

| Field | Type | Change | Reason |
|---|---|---|---|
| `InputContext.Vault` | removed | — | the asset must not be named before evaluation |
| `InputContext.ScopeCommitment` | `[32]byte` | new | `H(issuerKeyId ‖ portfolioId ‖ epochSalt)` |
| `InputContext.Epoch` | `uint64` | new | budget and salt rotation window |
| `AuthorizationClaim.Vault` | removed | — | as above |
| `AuthorizationClaim.ScopeCommitment` | `[32]byte` | new | must equal the context's |
| `AuthorizationClaim.SubmissionBudget` | `uint32` | new | anti-probing ceiling the issuer signs |
| `IdentityMode` | fixed | `IdentityFullFHE256` only | `ReceivableIDBits` mandatory, `ReceivableCommitment` must be zero |

Everything else (ciphertext digest, key id, parameter fingerprint, policy version, issuer id, issued
at, valid until, one-shot nonce) is unchanged.

### Result: `ConfidentialPolicyResultV4`

```solidity
struct ConfidentialPolicyResultV4 {
    uint256 chainId;
    address consumer;          // intended consumer, unchanged semantics
    bytes32 policyId;
    uint32  policyVersion;
    bytes32 scopeCommitmentA;  // replaces vault: which portfolio submitted A
    bytes32 scopeCommitmentB;
    bytes32 inputCommitmentA;
    bytes32 inputCommitmentB;
    bool    matchConfirmed;    // receivable identity equality, under encryption
    bool    conflictConfirmed; // match AND currency AND overlap AND exclusivity
    bytes32 matchCommitment;   // H(domain ‖ receivableId ‖ matchSalt)
    uint8   anchorCount;       // 1 or 2
    uint256 nonce;
    uint64  validUntil;
    bytes32 providerProofCommitment;
    bytes32 resultCommitment;
}
```

`vault` is gone; `matchCommitment` and `anchorCount` are new; `matchConfirmed` is separated from
`conflictConfirmed` so a same-asset finding is distinguishable from a policy breach.

### Verifier changes

- Policy configuration keys on `(policyId)` plus an allowlist of scope commitments, not on a vault.
- `replayKey = H(chainId, consumer, policyId, nonce)`.
- `decisionKey = H(chainId, consumer, policyId, policyVersion, sorted(inputCommitmentA, inputCommitmentB))`.
- `matchCommitment` joins the one-time set: a match may be bound once.

### State transitions

```text
UNBOUND        result accepted by the verifier, matchConfirmed = true, no anchor named
   │  bindAnchor(receivableId, matchSalt, anchor[, anchor2])
   │  requires H(domain ‖ receivableId ‖ matchSalt) == matchCommitment
   │  requires anchor.invoiceRoot() == receivableId  (and anchor2 likewise)
   │  requires anchor Outstanding and protection Active
   ▼
BOUND          receivable(s) now public; recourse record opened, non-economic
   │  cure window elapses without cure
   ▼
ESCALATED      governed action, out of scope for this study
```

`UNBOUND` results expire at `validUntil` and can never be bound afterwards. A `matchConfirmed = false`
result is never submitted on-chain at all.

### Trust model delta versus Mode A

| Property | Mode A (proven) | Mode B (proposed) |
|---|---|---|
| Evaluator learns the receivable | **yes**, vault in cleartext | no, until binding |
| Evaluator learns commercial terms | no (5 encrypted, 4 committed) | no |
| Same-asset linkage visible pre-evaluation | **yes**, shared vault | no |
| Anti-probing control | not needed | **required**: per-epoch budget |
| Identifier public after recourse | yes | yes |
| Cross-platform, no shared anchor | no | yes |

### Migration boundary

V3 and V4 are parallel, not sequential. Mode A keeps the deployed
`ECDSAQuorumConfidentialPolicyVerifierV3` and `ReceivableAnchoredRecourseConsumer` unchanged; Mode B
gets its own verifier and consumer. No V3 artifact, evidence item or transaction is reinterpreted.
Clients select the mode by which enrollment type they build. Nothing shared is modified except the
`multiparty` ceremony, which is mode-agnostic and already dealerless.

## Why this cannot be done with ordinary encryption or access control

- **Ordinary encryption** requires a party who can decrypt. Whoever that is learns both portfolios'
  receivable identifiers, which is precisely the disclosure both platforms refuse.
- **Access control** on a shared registry has the same problem one level up: the registry operator
  learns every identifier, and each platform must upload its book to a competitor's dependency.
- **Hashed identifier exchange** fails because receivable identifiers are low-entropy and structured
  (invoice numbers, debtor names, dates). A shared salt is exactly what the parties will not agree,
  and an unsalted hash is trivially enumerable.
- **FHE is required because the evaluator must compute on data it may never see**, and the operators
  who hold the key shares are not the parties and never see plaintext either. The equality is
  evaluated homomorphically and only a bounded Boolean is released through a 2-of-3 threshold.

## Escalation

Mode B requires a V4 result schema and a new on-chain binding model. Per the delivery order, this
study stops here and requests owner approval before any implementation.

**OWNER APPROVAL REQUESTED — V4 SCHEMA AND ANCHOR-BINDING MODEL**
