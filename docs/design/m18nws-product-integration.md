# M-18NWS — product integration candidate

Status: **product integration selected for `main`**. This migration applies the selected benchmark
logic to the three existing product surfaces without changing their synthetic data, state machines,
transactions or contract boundaries. The benchmark and intermediate candidate commits remain in the
history, but the product no longer depends on a protected branch preview for review.

## Product promise

Mordant should answer three questions before it explains the protocol:

1. What is true for me now?
2. Who must act, and by when?
3. What happens to the receivable and the protection separately?

The shared interface therefore uses three information levels:

- **Decision:** verdict, owner, deadline, consequence and next action.
- **Reason:** the minimum role and state explanation required to act safely.
- **Evidence:** transitions, identifiers, source classification and prototype boundaries.

Evidence remains available and exact; it does not compete with the decision in the first viewport.

## Shared visual contract

| Concern | Product rule |
| --- | --- |
| Grid | 12 columns on desktop, 8 on tablet, 4 on mobile; regions are implied by alignment and `1px` rules |
| Type | Archivo Variable for product hierarchy; IBM Plex Mono only for identifiers and evidence |
| Receivable | `#006c9c`; open, stable and visually dominant |
| Protection | `#d62e68`; separate, conditional and contained |
| Action | `#6750d8`; reserved for controls and the one current deadline gesture |
| Ground / proof | `#f3f4ef` for product work; `#161c28` only where deep proof needs contrast |
| Displacement | One functional macro displacement per surface, tied to responsibility under time |
| Controls | Flat, `8px` radius, at least `44px`; no split icon cell or hard shadow |
| Identity | No root-derived stripe or pictogram family in the integrated product |
| Motion | Short functional transitions only; reduced-motion produces the final state immediately |

The colour system is deliberately local to Mordant and does not reuse the Lock-in palette. Meaning
is also carried by labels, position and edge treatment so colour is never the only signal.

## Surface extension

### Participant Deal Room

The first view now starts with the direct outcome `Nothing you need to do.` and reassures the holder
that the invoice payment remains theirs. Facility B and the deadline form one human sentence. The
two accounting domains are a flat two-line money summary rather than competing cards. `Why am I
waiting?` stays entirely human; `How do we know?` starts with a trust summary, while readiness,
gates, transitions and identifiers require a second `Technical details` disclosure.

### Deal Workspace

The queue remains a real triage control with all fourteen modeled deals, three filters, search,
saved selection and the existing transaction-review rehearsal. The selected record prioritizes one
verdict, one owner, one deadline and one action. Machine rails and proof follow rather than compete.

### Protocol Operations

The event rail remains dense, but the selected incident, impact and recovery route lead. Exact
before/action/after evidence, diagnostics, artifact manifest context and recovery instructions are
preserved as the expert layer. The dark proof field is allowed here without becoming the atmosphere
of participant-facing pages.

## UX density calibration

The three audiences intentionally keep different densities: Participant is low-to-medium,
Workspace remains operationally dense, and Protocol remains expert-dense.

- Participant exposes four perceptual blocks: outcome, one owner/deadline sentence, a flat two-line
  money summary and one conditional consequence. One exit and the closed `Why am I waiting?` /
  `How do we know?` links follow. The complete first view is capped at 80 visible words and contains
  no technical identifier.
- Participant chrome exposes the brand, portfolio return, role and synthetic boundary. Wallet,
  network and freshness are grouped under the closed `Context` control.
- Workspace navigation now changes product mode rather than pretending a visible panel is a
  destination. `Portfolio` becomes a full-width monitored-deals view; choosing a deal returns to the
  three-column Workspace. `Evidence` becomes a dedicated proof view with the queue and decision rail
  removed. Each state is deep-linkable, focused and visibly current.
- Protocol preserves the perceptual sequence `incident → impact → runbook → proof`, including at
  `390px`, without duplicating content for mobile.

## Preserved safety and accounting boundaries

- One vault still represents one immutable buyer-accepted invoice root and one immutable CVA.
- Receivable redemption and funded protection remain separate accounting domains.
- A protection claim never burns or transfers invoice units.
- The fixture does not establish external financing, fraud, legal priority, insurance or production
  safety.
- No Cleanverse credential, ABI, contract call, write path or money path is changed by this branch.
- The `10%` reserve remains a synthetic demo parameter and is not presented as production pricing.

## Integration gate

The integration can reach `main` only when all existing product behavior tests, responsive checks,
type/lint/build validation and a live visual review pass. Non-technical comprehension still needs the
M-31 user-test protocol; screenshots and automated checks cannot approve comprehension on their own.

## Validation record

- `pnpm validate`: passed (118 unit tests, runner checks, 89 Forge tests, evidence and secret scans,
  lint, typecheck and production build). The existing unused-variable warning in
  `scripts/m05-runner-lib.mjs` is unchanged.
- `pnpm test:e2e`: 58/58 scenarios passed across desktop, tablet, mobile and the transaction journey.
- Independent visual review: the participant hierarchy and the three Workspace navigation states
  are materially distinct at desktop and mobile widths; Protocol keeps incident and impact ahead of
  the runbook and proof on mobile.
- Deployment target: `main`, with the public alias verified only after the resulting production
  deployment reports the integrated commit SHA.
