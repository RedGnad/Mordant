# M-18NWS — product integration candidate

Status: **candidate branch for live review**. This migration applies the selected benchmark logic to
the three existing product surfaces without changing their synthetic data, state machines,
transactions, contract boundaries or public deployment alias. It is intentionally stacked on the
M-18NWS benchmark so it can be reviewed and discarded independently.

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

The first view is a human conclusion: the receivable has not moved, the holder has no cure action,
Facility B owns the cure, and the UTC deadline appears once. The two balances stay unequal and
separate. Explanation, readiness and evidence remain secondary and inspectable.

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

- Participant exposes only the conclusion, absence of action, one owner/deadline, two two-line
  amounts, one consequence, one exit and the closed `Why?` / `Evidence` disclosures. The complete
  first view is capped at 80 visible words and contains no technical identifier.
- Participant chrome exposes the brand, portfolio return, role and synthetic boundary. Wallet,
  network and freshness are grouped under the closed `Context` control.
- Workspace `Portfolio` now scrolls and focuses the queue. `Evidence` opens, scrolls to and focuses
  its disclosure. The current `Workspace` location is static rather than a false link.
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

This branch is technically integrable only when all existing product behavior tests, responsive
checks, type/lint/build validation and a live visual review pass. Merge and movement of the public
Vercel alias remain separate decisions. Non-technical comprehension still needs the M-31 user-test
protocol; screenshots and automated checks cannot approve comprehension on their own.

## Validation record

- `pnpm validate`: passed (118 unit tests, runner checks, 89 Forge tests, evidence and secret scans,
  lint, typecheck and production build). The existing unused-variable warning in
  `scripts/m05-runner-lib.mjs` is unchanged.
- `pnpm test:e2e`: 58/58 scenarios passed across desktop, tablet, mobile and the transaction journey.
- Independent visual review: `READY` on Workspace, Participant and Protocol at `1440 × 960` and
  `390 × 844`. Participant measures about 57 visible words on desktop and 48 on mobile, including
  chrome; Protocol keeps incident and impact ahead of the runbook and proof on mobile.
- Public alias: unchanged. Integration remains isolated on its candidate branch until review.
