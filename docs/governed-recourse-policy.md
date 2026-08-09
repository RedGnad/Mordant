# Governed Recourse Policy

Status: current managed V2 product authority, introduced on `origin/main` by PR #45.

Mordant is the recourse layer for tokenized private credit. Conflicting Pledge Protection is its
first implemented workflow. In the current managed V2 path, a governed conflict/no-conflict result
does not directly become recourse. It enters a policy selected before result exposure, and the
selected policy branch becomes the authority for one bounded operation.

## Authority chain

```text
private claims
  → governed cryptographic result
  → precommitted Governed Recourse Policy selection
  → verified governed action plan
  → durable plan-derived operation authorization
  → existing bounded managed operation
  → verified action-compatible outcome
  → operation-bound evidence reference
```

Every link is fail-closed. The selection binds the case, workflow, result contract, policy body and
policy hash. The plan must match the released result and one closed branch. The operation
authorization rebinds the selection, plan, result and exact operation parameters. The terminal
evidence reference must bind the recorded operation outcome back to all of those values.

## Result boundary

The governed result establishes exactly one of:

- `CONFLICT`;
- `NO_CONFLICT`.

The governed Boolean establishes conflict status. It is an authenticated input to the precommitted
policy, not an authorization for recourse or settlement by itself.

Neither the result nor the current managed policy establishes legal priority, legal responsibility,
ownership, fraud, default, payout recipient, payout amount or the legally correct action. Human and
institutional processes remain responsible for legal and operational judgment.

## Current managed policy

| Field | Value |
| --- | --- |
| Schema | `mordant.governed-recourse-policy/1` |
| Policy | `mordant.managed-demo.facility-protection@1` |
| Hash | `sha256:a79e86e58de597a81d646c72434882ad60592d79fda0d6337dac4426932a225e` |
| Workflow | `Conflicting Pledge Protection` · first implemented workflow |
| Result contract | Conflict/no-conflict only |
| Commitment point | Selected before result exposure |

The policy is code/deployment committed. There is no institution-facing policy editor and no
cryptographic institution-approval attestation in the current implementation.

### Conflict branch

| Field | Value |
| --- | --- |
| Selected action | `OPEN_LOCAL_CURE_PATH` |
| Managed executor (not legal action owner) | `MORDANT_MANAGED_EXECUTION` |
| Action class | `LOCAL_PROTOCOL_DOUBLE` |
| Cure duration | `86,400` seconds — 24 hours |
| Deadline rule | Starts when the local cure path opens |
| Escalation | Manual review outside the managed run |
| Settlement authorization | `NOT_AUTHORIZED` |

The operation is compatible only if the recorded local cure path is open and:

```text
cureDeadlineUnix - cureStartedAtUnix = 86,400
```

The 24-hour duration is not a UI estimate. It is a policy rule validated against the operation
record.

### No-conflict branch

| Field | Value |
| --- | --- |
| Selected action | `RECORD_AND_CLOSE` |
| Managed executor (not legal action owner) | `MORDANT_MANAGED_EXECUTION` |
| Action class | `EVIDENCE_ONLY` |
| Cure duration | Not applicable |
| Escalation | None |
| Settlement authorization | `NOT_AUTHORIZED` |

No-conflict authorizes a durable record-and-close operation. It is not a credit approval and it does
not make any legal or underwriting determination.

## What the evidence proves

For a terminal managed V2 run, the public-safe projection may include:

- policy identifier, version, hash and selection hash;
- result digest and closed result semantic;
- selected action, plan hash and action class;
- exact operation authorization hash and parameters digest;
- operation outcome digest and durable operation record hash;
- receipt/evidence digest and the reference binding those fields.

The product UI leads with human-readable branch and operation language. Hashes and exact enum values
remain in progressive proof layers.

## Separate historical Adapter V2 execution

The retained hardened run at `/protection/verified-run` used a different historical architecture
and configuration:

```text
historical governed result
  → preconfigured historical demo recourse policy
  → Adapter V2 case opened
  → 600-second cure window
  → permissionless finalization
  → configured aUSDC claims
  → reconciliation
```

That 600-second window is exact historical evidence and must remain 600 seconds. It is not the
current managed policy's 24-hour local cure. The historical run did not use the new managed V2
policy-selection/action-authorization chain, and a fresh managed run does not execute or authorize
that historical settlement.

## Implementation map

- Policy body and exact validators: `src/lib/protection/governed-recourse-policy.ts`
- Policy and durable operation binding: `src/lib/protection/governed-recourse-policy.ts`
- Server application and public projection: `src/lib/protection/governed-fhe-product-server.ts`
- Browser parser: `src/components/live-product/managed-intake-adapter.ts`
- Product presentation: `src/components/live-product/live-product.tsx`
- Focused qualification: `pnpm recourse-policy:test`
