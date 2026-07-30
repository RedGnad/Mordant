# M-32 — Release-readiness checklist

Status: **NO-GO until the release evidence below is attached**. Scope is the public synthetic
hackathon demo only. Real funds and production claims remain NO-GO under
[`docs/production-gates.md`](../production-gates.md), regardless of this checklist.

## Release record

Fill this block once for one immutable candidate. A result from another commit is not evidence.

| Field | Required value |
| --- | --- |
| Commit | Full Git SHA |
| Branch | `main` |
| Deployment | Immutable Vercel deployment URL and deployment ID |
| Public alias | `https://mordant-two.vercel.app/` |
| Validation time | UTC timestamp |
| Validator | Person or CI identity |
| M-31 result | Link to signed-off result for this commit, or a documented newer UI-equivalent commit |

## Automatically verifiable release gates

Mark a gate only from a clean checkout of the recorded commit. Save command, exit code, timestamp and
artifact/log link; a local recollection is not evidence.

| Gate | Command or check | Pass condition | Status |
| --- | --- | --- | --- |
| Repository validation | `pnpm validate` | Exit `0`; lint, typecheck, unit/model tests, runner controls, contract tests/format, evidence checks, secret scan and production build all complete | `[ ]` |
| Browser journeys | `pnpm test:e2e` | Exit `0` for every configured project, including local protocol-double journeys | `[ ]` |
| Product semantics | Unit and browser assertions inside the two commands above | Exact integer/pro-rata amounts, immutable identity, all readiness verdicts, role-specific navigation and evidence classes pass | `[ ]` |
| Transaction review | Browser assertions inside `pnpm test:e2e` | Review stages, persistent failure states, keyboard escape/focus return and non-executing fixture boundary pass | `[ ]` |
| Responsive and accessible baseline | Browser assertions inside `pnpm test:e2e` | `1280x800` and `390 px` layouts, no horizontal overflow, 44 px targets, focus visibility, contrast guard and reduced motion pass | `[ ]` |
| Deployment identity | Vercel inspection plus Git metadata | Production deployment resolves to the recorded commit on `main`, is `READY`, and is newer than the previous placeholder deployment | `[ ]` |
| Public smoke | HTTP/browser check on the immutable URL and alias | `/`, `/participant`, `/protocol`, `/protocol/local-journey` and `/design-system` return the expected release with fixture/prototype boundaries visible | `[ ]` |
| Client-secret boundary | `pnpm validate` plus deployed bundle/log review | No Cleanverse credential, private key or server-only secret is present in client output or public fixtures | `[ ]` |

Any failed, skipped, flaky or stale automated gate is a release **NO-GO**. Record warnings separately;
do not convert an unexecuted check into `N/A` without an owner and rationale.

## Human and external decisions

These cannot be cleared by a green build or an attractive screenshot.

### Required for the synthetic public demo

- `[ ]` M-31 meets every predeclared cohort threshold in
  [`m31-user-test-protocol.md`](./m31-user-test-protocol.md); unresolved critical or repeated
  high-severity findings are NO-GO.
- `[ ]` A product owner confirms that every public route and action is fixture-only or safely
  access-controlled, and that role-aware presentation is not being mistaken for authorization.
- `[ ]` A privacy owner approves analytics, recording, consent, retention and any public read-route
  exposure. No real invoice, participant or wallet data is used.
- `[ ]` A release owner reviews all visible claims and confirms the product says synthetic/test
  asset, does not imply live settlement, and does not claim invoice truth, legal priority,
  insurance, universal duplicate-financing detection or production safety.
- `[ ]` Named monitoring and rollback owners verify the public alias, error visibility and recovery
  contact for the demo window.

### Still required before any real-funds or production release

- independent legal opinion, named jurisdiction, authoritative invoice-root/amendment process and
  validated product terminology;
- written Cleanverse confirmation of the deployed A-Token ABI, contract eligibility, A-Pass roles,
  custody, burn/release and recovery boundaries; `ICvaAdapter` remains the custody boundary until
  then;
- enforced authentication/authorization and signed-wallet/rate-limit controls, not merely separate
  UI surfaces;
- external contract/security audits, invariant fuzzing, privacy review and bug bounty;
- KYB/AML/sanctions/UBO/related-party controls, confidential matching and incident response;
- multisig/timelock, monitoring, reconciliation, fail-closed renewal and stranded-credit recovery;
- two independent facilities, a shadow pilot, a paid design partner and measured coverage, error and
  ROI thresholds.

The complete authoritative list remains [`docs/production-gates.md`](../production-gates.md). If a
line here conflicts with it, the stricter production gate wins.

## Decision rule

The synthetic demo is **GO** only when every automatic gate and every synthetic-demo human decision
is checked against the recorded candidate. Otherwise it is **NO-GO**. A synthetic-demo GO must be
written as exactly that; it cannot be reused as evidence for production or real funds.
