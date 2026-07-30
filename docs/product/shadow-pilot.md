# Mordant shadow pilot

Status: product definition for a permissioned B2B pilot. This is not production deployment approval.

## Purpose

Run Mordant beside a receivables platform, factor, or multi-funder credit operator. The client keeps its current process and decision authority. Mordant evaluates the same agreed exceptions without moving funds or automatically executing production actions.

The primary user is the credit or operations team. Every recommendation requires human validation.

## Inputs

- A real anonymized portfolio or representative test data.
- Receivable identities agreed with the client.
- Participants and their operational roles.
- Events supplied by an authorized source.
- A protection policy configured and approved with the client.

No borrower names, wallet keys, credentials, or unnecessary personal data enter the pilot dataset.

## Processing

1. Detect or receive an exception from the authorized source.
2. Calculate the responsible party.
3. Establish the applicable deadline.
4. Derive the configured economic consequence.
5. Recommend the safe next action.
6. Present the conclusion and basis for mandatory human validation.

Mordant does not claim legal priority, universal duplicate-financing detection, insurance, custody, or autonomous production enforcement.

## Outputs

- Incident case with the relevant facts and status.
- Decision, justification, responsible party, deadline, and consequence.
- Before/action/after history.
- Exportable evidence package.
- Pilot measurement record.

## Measurements

For every agreed exception, record both the Mordant path and the current-process baseline:

- Time until the conflict is identified.
- Time until a responsible party is assigned.
- Number of manual exchanges required.
- Ambiguities left unresolved.
- Total resolution time.
- Evidence completeness against the client-approved checklist.
- Differences between Mordant and the current process, including the final human decision.

No target improvement is assumed. Baselines, thresholds, sample size, and an acceptable difference policy are agreed before the first run.

## Operating boundary

- Permissioned participants and an agreed dataset only.
- Read-only or shadow recommendations only.
- No production funds, custody, or automatic onchain action.
- Human owner for every decision and escalation.
- Client-approved retention and deletion period.
- A named stop condition for unsafe, incomplete, or contradictory data.

The pilot ends with a joint review of evidence, operational fit, unresolved risks, and whether any next phase is justified.

## Application intake

The public form delivers a validated `mordant.pilot-application.v1` JSON envelope only to the server-side `PILOT_APPLICATION_WEBHOOK_URL`. An optional `PILOT_APPLICATION_WEBHOOK_TOKEN` is sent as a bearer credential. If no private destination is configured, the form is visibly unavailable and no success receipt is shown.
