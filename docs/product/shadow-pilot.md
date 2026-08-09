# Mordant shadow pilot

Status: product definition for a permissioned B2B pilot. This is not production deployment approval.

Mordant is the recourse layer for tokenized private credit. Conflicting Pledge Protection is the
first implemented workflow; this shadow-pilot design evaluates broader institutional fit without
claiming that additional workflows are current. Participant-originated encryption is a separately
qualified, opt-in native-CLI profile; this shadow-pilot definition does not silently enable or
globalize that privacy claim.

## Purpose

Run Mordant beside a receivables platform, factor, or multi-funder credit operator. The client keeps its current process and decision authority. Mordant evaluates the same agreed exceptions without moving funds or automatically executing production actions.

The primary user is the credit or operations team. Every recommendation requires human validation.

## Inputs

- A real anonymized portfolio or representative test data.
- Receivable identities agreed with the client.
- Participants and their operational roles.
- Events supplied by an authorized source.
- A shadow policy mapping agreed for evaluation with the client. This does not represent a
  cryptographic institution-approval attestation in the current product.

No borrower names, wallet keys, credentials, or unnecessary personal data enter the pilot dataset.

## Processing

1. Detect or receive an exception from the authorized source.
2. Establish the bounded case state supported by that evidence.
3. Apply the pre-agreed shadow policy to select a recommendation branch.
4. Present the result, policy basis and evidence for mandatory human validation.
5. Let the client's authorized human process assign any action owner, deadline, escalation and
   operational or legal responsibility.

Mordant does not claim legal priority, universal duplicate-financing detection, insurance, custody, or autonomous production enforcement.

## Outputs

- Incident case with the relevant facts and status.
- Case state, policy branch, evidence and human-recorded disposition.
- Human-assigned action owner, deadline and escalation where the client records them.
- Before/action/after history.
- Exportable evidence package.
- Pilot measurement record.

## Measurements

For every agreed exception, record both the Mordant path and the current-process baseline:

- Time until the conflict is identified.
- Time until the client's human process assigns an action owner, where required.
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
