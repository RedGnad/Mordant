# Conflicting Pledge Protection — first implemented workflow

Conflicting Pledge Protection is Mordant's first implemented workflow. Mordant is the recourse layer
for tokenized private credit; the two-claim conflict mechanism below is the current concrete entry
point, not the definition of the whole category.

The workflow uses synthetic financing-claim windows and a verified Cleanverse/Monad testnet asset
identity. It does not establish legal priority, legal responsibility, ownership, fraud, default,
invoice authenticity, legal enforceability, payout recipient or payout amount. It is not production
authorized.

## Exact workflow

```text
MINV01 provenance and A-Pass eligibility
  → two submitted financing-claim windows
  → fixed BGV encrypted evaluation
  → governed conflict/no-conflict result
  → precommitted Governed Recourse Policy
  → verified governed action plan
  → durable bounded-operation authorization
  → operation-bound evidence
```

The governed Boolean establishes conflict status. It is an authenticated input to the precommitted
policy, not an authorization for recourse or settlement by itself.

## Root asset

The product root is the retained Cleanverse M-11 issuance/readback for MINV01 on Monad testnet:

- Cleanverse A-Token `0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b`;
- request `IA20260729032221850604`;
- issuance transaction `0xd26ba9b1624a6e10127a48e2acabdbbf94cae97e0be071e243c7ee5b08211b8c`;
- token deployment block `48901234`;
- canonical classified asset digest
  `sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c`.

This establishes the Cleanverse provenance and identity used by the demo. The record does not
invent a legal issuer, and it does not prove invoice authenticity, legal validity or enforceability.

Retained sources:

- `docs/evidence/monad-invoice-atoken-launch-2026-07-28.json`;
- `docs/evidence/cleanverse-monad-2026-07-28.json`;
- `docs/evidence/monad-m13a-ceremony-2026-07-28.json`.

## Intake and privacy boundaries

### Managed combined intake

This is the active public profile. One eligible test context submits both synthetic windows.
Managed Mordant infrastructure receives their plaintext values during intake/preparation and then
produces real encrypted artifacts for the fixed BGV execution. The evaluator receives ciphertexts
only and has no decryption key.

### Direct participant admission

Two distinct wallets each accept A-Pass observation and sign an exact role-bound
`ParticipantAdmissionV1` payload. The same wallet cannot fill both roles. Expired nonces and changed
payloads fail closed; exact retry reuses the retained signature. This proves separate authorization,
not participant-local encryption.

### Participant-originated native CLI

This profile is not integrated in the current `origin/main`. It remains the intended
institutional-privacy path and must be merged and requalified before any current-product claim says
that Mordant coordination receives ciphertext rather than a raw claim window.

The workflow does not require either counterparty to disclose its claim window to the other. It does
not claim browser/device BGV, participant-controlled decryption, threshold release or that no Mordant
infrastructure sees plaintext.

## Runtime split

- The accepted N15 BGV path runs key generation, participant preparation, evaluator and governed
  decryptor as separate processes.
- The evaluator receives the public case root and ciphertext artifacts. It receives no secret-key
  path.
- The designated governed decryptor independently recomputes the circuit, decrypts the final result
  and signs the conflict status. It is trusted and Mordant-controlled.
- Product APIs accept only fixed operations; callers cannot choose a ciphertext path, key, circuit,
  output slot, asset identity or result.
- Durable state and public-safe projections fail closed on schema, digest or cross-reference mismatch.

## Current managed Governed Recourse Policy

Policy `mordant.managed-demo.facility-protection@1`, hash
`sha256:a79e86e58de597a81d646c72434882ad60592d79fda0d6337dac4426932a225e`,
is selected before result exposure.

| Result | Closed branch | Bounded effect | Settlement |
| --- | --- | --- | --- |
| Conflict | `OPEN_LOCAL_CURE_PATH` | Open a 24-hour local protocol-double cure path; manual review stays outside the managed run | `NOT_AUTHORIZED` |
| No conflict | `RECORD_AND_CLOSE` | Retain evidence and close the managed case | `NOT_AUTHORIZED` |

The conflict operation is valid only when
`cureDeadlineUnix - cureStartedAtUnix === 86,400`. The selected plan binds the result digest and
policy selection. The durable operation authorization rebinds the plan, exact parameters and
operation identity. Terminal evidence must match the selected action and operation outcome.

The policy is code/deployment committed. No institution-facing policy editor or cryptographic
institution-approval attestation exists in the current implementation. See
[Governed Recourse Policy](governed-recourse-policy.md).

## Evidence and recovery

Each product mutation is journaled before a subprocess or irreversible filesystem action. The
journal binds run, sequence, phase, immutable parameters, expected state transition and terminal
reconciliation. Reconciliation advances from cryptographically verified public artifacts and does
not repeat a one-shot operation.

Before dispatch, the browser retains a no-secret recovery record for creation, fixed mutation or
evidence retention. Refresh and navigation restore the same run through lookup and GET-only
readback. Recovery never asks the browser to invent a second create request or terminal outcome.

Current managed receipts can bind:

- eligibility observation and case authorization;
- participant and evaluated artifact digests;
- governed result and result ciphertext digests;
- policy selection, action plan and operation authorization;
- action-compatible operation outcome;
- terminal evidence digest.

Hashes are technical verification handles. A user normally follows the layered receipt rather than
submitting a digest to a separate service.

## Separate historical hardened execution

The verified run at `/protection/verified-run` is a distinct historical proof surface. It used two
canonical wallets and the historical Adapter V2 architecture:

```text
governed conflict result
  → preconfigured historical demo policy
  → Adapter V2 opened the case
  → 600-second cure window
  → permissionless finalization
  → configured aUSDC claims
  → reconciliation
```

The 600-second historical cure is not the current managed 24-hour local cure. The historical run
did not use the new managed V2 policy-selection/action-authorization chain, and the current managed
proof does not execute or authorize that settlement. Its retained receipts and digested evidence
remain unchanged.

## Exact supported product claim

“Mordant is the recourse layer for tokenized private credit. Its first implemented workflow,
Conflicting Pledge Protection, evaluates two financing-claim windows under BGV encryption, releases
only governed conflict status, applies a policy committed before result exposure, authorizes one
bounded managed operation from the selected plan, and binds the outcome to evidence.”

Qualification: the managed demo uses synthetic inputs, managed plaintext preparation, a trusted
designated decryptor, a 24-hour local protocol-double cure branch and no settlement authorization.
A separate retained hardened run proves historical Adapter V2/aUSDC execution with a 600-second
cure window.
