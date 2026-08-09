# Governed recourse policy experiment

## Status and boundary

This is an isolated, off-chain, evidence-only design-lab experiment. It tests whether one already
verified governed conflict/no-conflict result can be combined with a policy selected before that
result is exposed for an experimental run, an exact human approval when required, and a signed
action receipt.

The governed cryptographic result establishes **only `CONFLICT` or `NO_CONFLICT`**. It does not
establish legal responsibility, legal priority, ownership, default, fraud, an action owner, a
deadline, or a payout. The policy-selected actions are prototype operational instructions. They are
not claims of legal correctness or production institutional authorization.

The route and engine expose no RPC writer, wallet client, transaction broadcaster, settlement
adapter, bridge executor, controlled settlement module, or token movement capability. Every action
has `executionMode: EVIDENCE_ONLY`. Both retained policies set settlement to `PROHIBITED`.

## Architecture

The experiment is deliberately narrower than a policy engine:

1. `policy.ts` defines the closed schemas, canonical JSON encoding, SHA-256 digests, deterministic
   prototype Ed25519 authorities, and independent verifiers.
2. `fixtures.ts` defines exactly two immutable signed policies and consumes the existing retained
   governed results without modifying them. It reuses `verifyGovernedResultSignature` and
   `governedResultDigest` from the hardened evidence implementation.
3. `engine.ts` keeps the immutable governed result reference separate from the policy/action state.
   Each transition is hash-linked. A policy can be bound only from `CASE_AUTHORIZED`.
4. `experiment-store.ts` supplies a single in-memory design-lab case. Its closed command set cannot
   accept scripts, conditions, calldata, settlement instructions, or arbitrary actions.
5. `/design-lab/governed-recourse-policy` is a local-development-only interactive case surface. The
   page and API return not-found in production mode.
6. `retained-evidence-cli.ts` deterministically regenerates the separated evidence fixtures under
   `docs/evidence/governed-recourse-policy-experiment/`.

## Exact policy schema

Schema: `mordant.governed-recourse-policy/1`

Closed top-level fields:

- `schemaVersion`
- `policyId`
- `policyVersion`
- `scope`
- `acceptedGovernedResult`
- `effectiveFromUnix`
- `effectiveUntilUnix`
- `conflictBranch`
- `noConflictBranch`
- `settlement`
- `policyAuthority`
- `digest`
- `signature`

`scope` is closed to `programId`, `assetClass`, and `assetIdentity`. The only accepted program is
`mordant.governed-recourse-policy-experiment-v1`; the only asset class is
`TOKENIZED_PRIVATE_CREDIT`; the retained fixtures bind the exact governed-result asset identity.

`acceptedGovernedResult` is closed to:

- `semantic: CONFLICT_OR_NO_CONFLICT_ONLY`
- `schemaVersion: mordant.governed-conflict-result/1`
- `serviceId: mordant.private-pledge-matching`
- `serviceVersion: 1`
- `releaseMode: governed-decryptor-v1`

Each branch is closed to:

- `governedOutcome`
- `evaluationActionType`
- `authorizedActionType`
- `accountableInstitutionalRole`
- `authorizationMode`
- `allowedApproverRoles`
- `approvalWindowSeconds`
- `deadlineRule`
- `escalationRule`
- `actionConfigurationDigest`

The only action types are `REVIEW_REQUIRED`, `RECORD_AND_CLOSE`, `OPEN_CURE_PATH`, and
`MANUAL_ESCALATION`. Human-required branches must use `REVIEW_REQUIRED`, have a non-empty allowed
role list, and have a bounded approval window. Automatic branches must not carry approver roles or a
fake approval window. A deadline can only be a positive integer relative to experimental result
exposure and can only pair with an unresolved-deadline `MANUAL_ESCALATION` rule.

`settlement` is closed to `permission` and `configurationDigest`. `PROHIBITED` requires a null
configuration. `PERMITTED` would require an exact SHA-256 configuration digest, although neither
fixture permits settlement and no settlement action or executor exists in this experiment.

`policyAuthority` is closed to `authorityId`, `purpose`, `label`, `prototypeAuthority`, `algorithm`,
and `publicKey`. `prototypeAuthority` must be true. The policy digest covers the entire closed body,
including the authority envelope, and the prototype authority signs that body with Ed25519.

The new `policyId` values are named experimental identities. They do not reuse the existing
governed-result protection `policyId` digest.

## The two immutable fixtures

### Policy A — Facility protection

- ID: `mordant.experimental.facility-protection`
- Conflict evaluation: `REVIEW_REQUIRED`
- Allowed approval: `CREDIT_OPS_APPROVER`
- Approved action: `OPEN_CURE_PATH`
- Accountable role: `CREDIT_OPERATIONS`
- Operational deadline: 604,800 seconds after experimental result exposure
- Unresolved deadline: `MANUAL_ESCALATION`
- No conflict: automatic `RECORD_AND_CLOSE`
- Settlement: `PROHIBITED`

### Policy B — Manual escalation

- ID: `mordant.experimental.manual-escalation`
- Conflict evaluation: `REVIEW_REQUIRED`
- Allowed approval: `INSTITUTIONAL_REVIEWER`
- Approved action: `MANUAL_ESCALATION`
- Accountable role: `RISK_OPERATIONS`
- No conflict: automatic `RECORD_AND_CLOSE`
- Settlement: `PROHIBITED`

## Exact evidence chain

### 1. Policy selection event

Schema: `mordant.policy-selection-event/1`

Closed fields: `schemaVersion`, `caseId`, `runId`, `programId`, `policyDigest`, `selectedAtUnix`,
`applicabilityAtUnix`, `nonce`, `previousEventDigest`, `selectorAuthority`, `digest`, `signature`.

The event is signed by a labeled prototype policy-selector authority. The verifier checks policy
signature and digest, policy effectiveness at applicability time, exact policy linkage, event digest,
and event signature. When a result exposure time is supplied it requires
`applicabilityAtUnix == selectedAtUnix < exposedAtUnix` and requires the policy to remain effective
at exposure. The state machine accepts policy binding only from
`CASE_AUTHORIZED`, so a run cannot replace its policy after selection or result exposure.

### 2. Governance approval event

Schema: `mordant.governance-approval-event/1`

Closed fields: `schemaVersion`, `caseId`, `runId`, `governedResultDigest`, `policyDigest`,
`proposedActionDigest`, `decision`, `approverRole`, `approverAuthority`, `nonce`, `issuedAtUnix`,
`expiresAtUnix`, `previousEventDigest`, `digest`, `signature`.

An approval binds the exact governed result, policy, proposed action, approver role/key, nonce,
issue/expiry interval, and preceding `REVIEW_REQUIRED` history event. The verifier rejects a role not
listed by the selected branch, a key-purpose mismatch, another proposed action digest, an expired
approval, or a consumed nonce.

### 3. Governed action receipt

Schema: `mordant.governed-action-receipt/1`

Closed fields: `schemaVersion`, `caseId`, `runId`, `governedResult`, `policy`,
`selectionEventDigest`, `approvalEventDigest`, `proposedActionDigest`, `resultingAction`,
`stateTransition`, `recorderAuthority`, `recordedAtUnix`, `digest`, `signature`.

The receipt binds the exact result digest/schema/semantic/outcome/exposure time, policy
ID/version/digest, selection event, optional exact approval, proposed action, resulting action,
deadline, escalation, action configuration reference, settlement rule, evidence-only execution mode,
and the `ACTION_AUTHORIZED → ACTION_RECORDED` hash-linked transition. Verification independently
revalidates all supplied objects before checking the receipt digest and prototype recorder signature.

## State model

The supported happy paths are:

```text
CASE_AUTHORIZED → POLICY_BOUND → RESULT_AVAILABLE → POLICY_EVALUATED
POLICY_EVALUATED → ACTION_AUTHORIZED → ACTION_RECORDED
POLICY_EVALUATED → REVIEW_REQUIRED → REVIEW_APPROVED → ACTION_AUTHORIZED → ACTION_RECORDED
REVIEW_REQUIRED → REVIEW_EXPIRED → ESCALATION_REQUIRED
```

The automatic path is available only for `NO_CONFLICT → RECORD_AND_CLOSE`. Conflict branches in both
fixtures require explicit human approval. Rejection recording is intentionally outside this V1 proof;
the state enum reserves `REVIEW_REJECTED` and `ACTION_NOT_AUTHORIZED` for a later signed-decision
object rather than inventing an unsigned rejection path.

## Supported and forbidden claims

This experiment supports the claim that, in an isolated off-chain prototype, the same exact signed
conflict fact can produce different pre-selected, signed-policy action paths and independently
verifiable evidence. It supports tamper detection across the policy, selection, approval, action,
deadline, configuration reference, and state transition.

It does not support claims of production authorization, legal correctness, legal priority, ownership,
default, fraud, complete operational governance, persistent/concurrent workflow durability, signer
security, production isolation, settlement correctness, payout correctness, RPC execution, or token
movement. Prototype private signing material is reproducible by design and therefore must never be
treated as a production trust anchor.

The retained governed result was already public before this experiment. The signed selection and
state machine prove ordering inside the experimental run; they do not prove that a human selector
had never learned the historical fixture outcome. A future live pilot would need a fresh result held
behind an access-controlled release boundary to test selector ignorance as well as event ordering.
