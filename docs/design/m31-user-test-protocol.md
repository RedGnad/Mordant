# M-31 — Real-user test protocol

Status: **required before declaring the redesigned synthetic demo ready**. This is a formative
usability study, not a production, legal, security or economic validation.

## Decision this study supports

Can an intended user, without product coaching, correctly identify the current situation, economic
domain, responsible party, consequence, evidence boundary and safe next action in Mordant's
synthetic prototype?

All sessions use synthetic invoices, fixture identities, test assets and non-executing review flows.
No participant connects a wallet, signs a message, sends funds or supplies client data. Passing M-31
does not clear any gate in [`docs/production-gates.md`](../production-gates.md).

## Sample and setup

- Recruit at least **five valid sessions per cohort**; target six to eight to reduce the effect of one
  outlier. Do not combine cohorts to hide a cohort-specific failure.
- Cohorts: deal operations, occasional participant/holder, and protocol operations. A valid
  participant must have performed the comparable role before; record experience band, not employer.
- Use the same release commit and fixture state for every scored session. Record commit, deployment,
  browser, viewport, input method and session ID (`OPS-01`, `PART-01`, `PROTO-01`).
- Test desktop for all cohorts and include at least two `390 px` mobile sessions in the participant
  cohort. Counterbalance first task when task order is not state-dependent.
- Moderator reads the scenario, then remains silent. A clarification that reveals the interface or
  answer marks that task **assisted**.

## Scored tasks

### Deal operations

1. From the intervention queue, select the case that should be handled first. State its verdict,
   cause, responsible party, deadline and next safe action.
2. Explain the difference between the receivable and protection amounts, then identify the exact
   economic effect of the selected action without opening raw proof.
3. Open the transaction review and decide whether to continue. Explain the expected before/after
   state, allowance/signature boundary and where confirmation evidence would appear. Do not execute
   or simulate a real transaction.

### Participant / holder

1. In the Deal Room, state which role and position the fixture assigns to you, your exact personal
   exposure in each economic domain, and whether those amounts represent the whole deal.
2. Decide whether you can act now. Name the blocking gate, the party responsible for curing it and
   what you should do next; do not infer a capability from a manual role switch.
3. Classify one fact from each visible evidence layer as observed, attested, derived or external/not
   established, and state whether the screen proves a live invoice or settlement.

### Protocol operations

1. Select the `after_state_unavailable` record and correlate the diagnostic, readiness verdict and
   proof record without changing records accidentally.
2. Identify where the ceremony stopped, what information is unavailable and the safe runbook step.
   State the condition that must clear before any resume.
3. Inspect the pinned M-14 artifact boundary and state only what it establishes, including the
   `public writes NOT AUTHORIZED` and `settlement NOT PROVEN LIVE` limitations.

## Measurement sheet

Capture one row per task. Store no names, wallet addresses, invoice data or employer identifiers.

| Field | Definition |
| --- | --- |
| Outcome | `unassisted`, `assisted`, `failed` or `abandoned` |
| Time | Seconds from scenario end to final answer/action |
| First action | First control or region used |
| Wrong turns | Distinct actions that do not advance the task |
| Critical error | One of the predefined errors below; include observable evidence |
| Comprehension | Correct/incorrect for verdict, domain, responsibility, next action and evidence boundary |
| SEQ | Participant's 1–7 Single Ease Question score after the task |
| Observation | Short behavioural note; interpretation is written separately |

An unassisted success completes the task and gives every required answer without moderator help.
Report medians and raw counts; do not report percentages alone with this sample size. Confidence or
preference never overrides an incorrect decision.

### Critical errors

Any of the following is critical: confusing receivable money with protection money; believing a
protection claim burns or transfers invoice units; proceeding despite a blocked/wrong-role verdict;
assigning cure responsibility to the wrong party; treating derived/attested/fixture data as observed
live evidence; claiming the fixture proves invoice truth, legal priority, insurance, universal
duplicate-financing detection or production safety; or attempting to use real credentials, funds or
identifiers.

## Predeclared go / no-go thresholds

M-31 is **GO for the next synthetic-demo release only if every condition passes**:

- at least five valid sessions in each cohort;
- zero critical errors across all valid sessions;
- every task reaches at least four unassisted successes in each five-session cohort (or **80%** when
  the cohort is larger), and overall unassisted success is at least **85%**;
- each comprehension item is correct for at least **80% per cohort** and **90% overall**;
- median completion time is at most **120 s** for the operations scenario, **90 s** for the
  participant scenario and **180 s** for the protocol scenario;
- median SEQ is at least **5/7** for every task;
- no severity-high usability problem recurs in two or more sessions. High means it can cause a wrong
  economic action, conceal a blocked state, misstate evidence or prevent task completion.

Anything else is **NO-GO until the implicated surface is fixed and the failed task is rerun with at
least five new valid participants from that cohort**. Do not average a failed cohort into a pass.

## Consent, confidentiality and moderation safety

Before starting, obtain explicit informed consent for participation and separate optional consent
for screen/audio recording. Explain purpose, duration, incentive, voluntary withdrawal and who can
access raw notes. Use only the supplied fixture account and stop immediately if real financial,
identity, credential or client information appears.

Pseudonymise records at capture. Limit raw notes and recordings to the named research team, encrypt
them at rest and delete them after 30 days unless a shorter approved policy applies. Retain only
de-identified task metrics and redacted observations. A privacy owner must approve the notice,
retention and recruitment method for the applicable jurisdiction; this protocol is not legal advice.

## Decision record

Publish a one-page result with the tested commit/deployment, cohort counts, raw task counts, medians,
critical errors, repeated high-severity findings and the resulting GO/NO-GO. Link fixes to a new
commit and preserve failed results; never rewrite the baseline after remediation.
