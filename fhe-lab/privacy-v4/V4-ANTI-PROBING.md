# V4 anti-probing

`assetId` is derived from structured invoice facts and is **not high-entropy**. FHE hides it from the
evaluator and the operators; it does not make it unguessable. Anti-probing is therefore a first-class
security boundary, not a hardening detail. This document states exactly what stops an authorized
participant from testing a dictionary of receivable identifiers.

## The structural control: mutual session initiation

**A match is only ever evaluated when two independently authorized scopes both submit against the
same session identifier, and neither can create that session alone.**

```text
sessionId = H(domain ‖ scopeCommitmentA ‖ scopeCommitmentB ‖ epoch ‖ sessionNonce)
```

Both submitters must present an enrollment naming the same `sessionId`, and the evaluator refuses a
session that does not receive exactly two enrollments from the two distinct scopes named in it.

This is the control that makes probing credible to defend against, and it is structural rather than
promissory: **a prober cannot test its dictionary without the victim co-submitting for every single
guess.** The party whose book is being probed is the party who must agree to each query.

It also explains the scope limit recorded in the threat model. A standing encrypted corpus that
anyone may query is an oracle by construction; this design deliberately does not offer one.

## Budgets

Enforceable by the evaluator without seeing any identity, because they count submissions rather than
inspect content.

| Control | Binding | Enforced by |
|---|---|---|
| Per-scope epoch budget | `AuthorizationClaim.SubmissionBudget`, signed by the issuer | evaluator counts accepted enrollments per `(issuerKeyId, scopeCommitment, epoch)` |
| Per-issuer epoch ceiling | issuer registration | evaluator, across all that issuer's scopes |
| Per-session uniqueness | `sessionId` one-shot | evaluator; a second use of a `sessionId` is refused |
| One-shot enrollment nonce | existing V3 mechanism, unchanged | evaluator's `usedEnrollments` registry |
| One-shot result nonce | existing V3 mechanism | verifier `consumedReplayKeys` |
| Cooldown | minimum interval per `(scopeCommitment, counterparty scope)` | evaluator |
| Counterparty allowlist | issuer names which counterparty scopes it will match against | evaluator, at session admission |

The budget is signed **by the issuer into the claim**, so a client cannot inflate its own allowance,
and the evaluator's count is the enforcement point because the evaluator is the only party that sees
every submission.

## What duplicate-query detection can and cannot do

An honest limit, stated because the obvious design does not work.

Detecting "this scope already asked about this identity" would require a deterministic tag over the
identity. Any such tag is computed client-side, so **a malicious client simply randomises it**, and
re-encrypting the same `assetId` yields a different ciphertext and therefore a different
`inputCommitment`. Duplicate detection over identities is **not enforceable against a malicious
submitter** and is not claimed.

What is enforceable and is claimed:

- duplicate *session* detection (`sessionId` one-shot);
- duplicate *enrollment* detection (existing one-shot nonce);
- total query volume per scope and per issuer per epoch.

So the defence against dictionary probing is **volume plus counterparty consent**, not content
deduplication. A prober with a budget of `n` per epoch and a cooperating counterparty can test `n`
identifiers per epoch and no more, and every one of those tests is attributable to its scope and
retained as audit evidence.

## No negative-result oracle

A `matchConfirmed = false` result produces **no public artifact of any kind**. This matters more than
it first appears: if a positive match produced an on-chain record and a negative produced silence,
then the *absence* of a record would itself answer the question for any observer who knew a session
had run. Two rules close that:

1. **No pre-binding public artifact exists at all.** A V4 result is a private object held by the two
   submitters until an authorized binding. Nothing is written on-chain for either outcome.
2. **Binding is an authorized disclosure decision, not an automatic consequence.** Even a positive
   match produces an on-chain record only when the disclosure step runs, so the on-chain record's
   existence reflects a decision to disclose rather than the Boolean's value.

Consequently an observer who somehow learned that a session occurred still cannot infer the Boolean
from chain state.

## Audit evidence for rejected excess queries

Every refusal is recorded by the evaluator with its reason and the scope that hit it, and the counts
are retained as public evidence carrying no identity material:

```json
{
  "epoch": 7,
  "scopeCommitment": "0x…",
  "issuerKeyId": "0x…",
  "budget": 32,
  "accepted": 32,
  "rejected": [
    { "reason": "SCOPE_BUDGET_EXHAUSTED", "at": "…", "count": 5 },
    { "reason": "COOLDOWN_ACTIVE", "at": "…", "count": 2 },
    { "reason": "COUNTERPARTY_NOT_ALLOWED", "at": "…", "count": 1 },
    { "reason": "SESSION_ALREADY_USED", "at": "…", "count": 1 }
  ]
}
```

This makes over-querying visible and attributable after the fact, which is what turns a budget into
an accountable control rather than a silent cap.

## Residual risk, stated plainly

- A prober with a **cooperating counterparty** and a large budget can still test that many
  identifiers. The design bounds and attributes probing; it does not make it impossible.
- Budget enforcement lives in the **evaluator**, which is the party the mode otherwise does not trust
  with identities. It is trusted for availability and accounting, not for confidentiality. A
  dishonest evaluator can refuse service or mis-count; it still cannot decrypt.
- The **issuer** sets the budget. A dishonest issuer can grant its own platform a large one. This is
  the same trust already required to authorize submissions at all, and it is bounded by the
  per-issuer ceiling and by revocation.

## Verdict on the stop condition

The mission requires NO-GO if the only defence is a promise. It is not: mutual session initiation is
structural, budgets are issuer-signed and evaluator-enforced, session and enrollment nonces are
one-shot, and refusals are retained as attributable evidence. **Anti-probing is credible for the
bilateral vertical**, and explicitly not claimed for open-book screening, which is out of scope.
