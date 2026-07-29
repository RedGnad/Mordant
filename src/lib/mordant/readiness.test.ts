import assert from "node:assert/strict";
import { test } from "node:test";

import {
  getSyntheticDeal,
  makeGateVector,
  type DealAction,
  type DealScenarioId,
  type GateOverrides,
  type SyntheticDeal,
} from "./product-model";
import { READINESS_VERDICT_CODES, deriveReadinessVerdict, type ReadinessVerdictCode } from "./readiness";

function firstAction(scenario: DealScenarioId): DealAction {
  const action = getSyntheticDeal(scenario).actions[0];
  assert.ok(action, `${scenario} must expose a primary action`);
  return action;
}

function verdict(scenario: DealScenarioId): ReturnType<typeof deriveReadinessVerdict> {
  const deal = getSyntheticDeal(scenario);
  return deriveReadinessVerdict(deal, firstAction(scenario));
}

test("derives all eight canonical M-21 verdicts from existing fixtures", () => {
  const expected: Readonly<Record<DealScenarioId, ReadinessVerdictCode>> = {
    healthy: "AVAILABLE_AT",
    "cure-expiring": "AVAILABLE_NOW",
    "pending-finality": "AVAILABLE_AT",
    "funds-missing": "FUNDS_REQUIRED",
    "allowance-missing": "FUNDS_REQUIRED",
    "wrong-role": "WRONG_ROLE",
    "credential-required": "CREDENTIAL_REQUIRED",
    "prerequisite-missing": "PREVIOUS_ACTION_REQUIRED",
    completed: "ALREADY_COMPLETED",
    "recovery-required": "RECOVERY_REQUIRED",
    "stale-observation": "PREVIOUS_ACTION_REQUIRED",
    "unknown-observation": "PREVIOUS_ACTION_REQUIRED",
    "partial-redemption": "AVAILABLE_NOW",
    "protection-settled": "ALREADY_COMPLETED",
  };

  const observedCodes = new Set<ReadinessVerdictCode>();
  for (const [scenario, code] of Object.entries(expected) as [DealScenarioId, ReadinessVerdictCode][]) {
    const observed = verdict(scenario);
    assert.equal(observed.code, code, scenario);
    assert.ok(observed.conclusion.length > 0, `${scenario} conclusion`);
    assert.ok(observed.cause.length > 0, `${scenario} cause`);
    assert.ok(observed.responsible.length > 0, `${scenario} responsible`);
    assert.ok(observed.unlock.length > 0, `${scenario} unlock`);
    assert.ok(observed.economicConsequence.length > 0, `${scenario} economic consequence`);
    assert.ok(observed.nextAction.length > 0, `${scenario} next action`);
    assert.ok("blockingGate" in observed, `${scenario} blockingGate`);
    assert.ok("recheckAt" in observed, `${scenario} recheckAt`);
    observedCodes.add(observed.code);
  }

  assert.deepEqual([...observedCodes].sort(), [...READINESS_VERDICT_CODES].sort());
});

test("returns the blocking gate and its data-driven resolution", () => {
  const credential = verdict("credential-required");
  assert.equal(credential.blockingGate?.kind, "identity");
  assert.equal(credential.blockingGate?.code, "viewer_synthetic_credential_missing");
  assert.equal(credential.responsible, "You");
  assert.equal(credential.unlock, "Complete the synthetic demo eligibility step for your participant.");

  const role = verdict("wrong-role");
  assert.equal(role.blockingGate?.kind, "role");
  assert.equal(role.responsible, "Facility B (synthetic)");

  const funds = verdict("funds-missing");
  assert.equal(funds.blockingGate?.kind, "economic");
  assert.match(funds.unlock, /synthetic test assets/);

  const prerequisite = verdict("prerequisite-missing");
  assert.equal(prerequisite.blockingGate?.kind, "protocol");
  assert.match(prerequisite.unlock, /commitment first/);
});

test("keeps timed readiness distinct from pending network finality", () => {
  const timed = verdict("healthy");
  assert.equal(timed.code, "AVAILABLE_AT");
  assert.equal(timed.blockingGate?.kind, "time");
  assert.equal(timed.recheckAt, "2026-07-31T14:00:00.000Z");

  const finality = verdict("pending-finality");
  assert.equal(finality.code, "AVAILABLE_AT");
  assert.equal(finality.blockingGate, null);
  assert.equal(finality.recheckAt, null);
  assert.match(finality.cause, /requires finalized finality/);
});

test("recovery overrides completed, which overrides an untrustworthy observation", () => {
  const recoveryDeal = getSyntheticDeal("recovery-required");
  const recoveryAction = firstAction("recovery-required");
  const completedRecoveryAction: DealAction = { ...recoveryAction, lifecycle: "completed" };

  assert.equal(deriveReadinessVerdict(recoveryDeal, completedRecoveryAction).code, "RECOVERY_REQUIRED");

  const completedDeal = getSyntheticDeal("completed");
  const staleDeal = getSyntheticDeal("stale-observation");
  const completedWithStaleObservation: SyntheticDeal = {
    ...completedDeal,
    observation: staleDeal.observation,
    diagnostics: staleDeal.diagnostics,
  };

  assert.equal(
    deriveReadinessVerdict(completedWithStaleObservation, firstAction("completed")).code,
    "ALREADY_COMPLETED",
  );
});

test("an untrustworthy observation overrides every unresolved gate", () => {
  const identityDeal = getSyntheticDeal("credential-required");
  const staleDeal = getSyntheticDeal("stale-observation");
  const identityWithStaleObservation: SyntheticDeal = {
    ...identityDeal,
    observation: staleDeal.observation,
    diagnostics: staleDeal.diagnostics,
    nextResponsibility: staleDeal.nextResponsibility,
  };

  const observed = deriveReadinessVerdict(identityWithStaleObservation, firstAction("credential-required"));
  assert.equal(observed.code, "PREVIOUS_ACTION_REQUIRED");
  assert.equal(observed.blockingGate, null);
  assert.equal(observed.responsible, "Observation service");
});

test("uses identity, role, time, economic, then protocol gate priority", () => {
  const deal = getSyntheticDeal("cure-expiring");
  const baseAction = firstAction("cure-expiring");
  const blocked = {
    status: "blocked",
    detail: "Synthetic priority test blocker.",
  } as const;
  const cases: readonly [GateOverrides, ReadinessVerdictCode, string][] = [
    [
      { identity: blocked, role: blocked, time: blocked, economic: blocked, protocol: blocked },
      "CREDENTIAL_REQUIRED",
      "identity",
    ],
    [{ role: blocked, time: blocked, economic: blocked, protocol: blocked }, "WRONG_ROLE", "role"],
    [{ time: blocked, economic: blocked, protocol: blocked }, "AVAILABLE_AT", "time"],
    [{ economic: blocked, protocol: blocked }, "FUNDS_REQUIRED", "economic"],
    [{ protocol: blocked }, "PREVIOUS_ACTION_REQUIRED", "protocol"],
  ];

  for (const [overrides, code, kind] of cases) {
    const action: DealAction = { ...baseAction, gates: makeGateVector(overrides) };
    const observed = deriveReadinessVerdict(deal, action);
    assert.equal(observed.code, code);
    assert.equal(observed.blockingGate?.kind, kind);
  }
});

test("a protocol prerequisite overrides otherwise pending finality", () => {
  const deal = getSyntheticDeal("pending-finality");
  const action: DealAction = {
    ...firstAction("pending-finality"),
    gates: makeGateVector({
      protocol: {
        status: "blocked",
        code: "synthetic_priority_prerequisite",
        detail: "A synthetic prerequisite is still missing.",
      },
    }),
  };

  const observed = deriveReadinessVerdict(deal, action);
  assert.equal(observed.code, "PREVIOUS_ACTION_REQUIRED");
  assert.equal(observed.blockingGate?.kind, "protocol");
});

test("pending gates remain pending instead of becoming definitive failures", () => {
  const deal = getSyntheticDeal("cure-expiring");
  const baseAction = firstAction("cure-expiring");

  for (const kind of ["identity", "role", "time", "economic", "protocol"] as const) {
    const action: DealAction = {
      ...baseAction,
      gates: makeGateVector({
        [kind]: {
          status: "pending",
          detail: `The synthetic ${kind} check is still in progress.`,
        },
      }),
    };
    const observed = deriveReadinessVerdict(deal, action);

    assert.equal(observed.code, "AVAILABLE_AT", kind);
    assert.equal(observed.blockingGate, null, kind);
    assert.match(observed.cause, /is pending/, kind);
    assert.doesNotMatch(observed.conclusion, /required|wrong|insufficient/i, kind);
  }
});

test("unknown gates request evidence without claiming that the gate failed", () => {
  const deal = getSyntheticDeal("cure-expiring");
  const baseAction = firstAction("cure-expiring");

  for (const kind of ["identity", "role", "time", "economic", "protocol"] as const) {
    const action: DealAction = {
      ...baseAction,
      gates: makeGateVector({
        [kind]: {
          status: "unknown",
          detail: `The synthetic ${kind} result is unavailable.`,
          remediation: `Refresh the synthetic ${kind} source.`,
        },
      }),
    };
    const observed = deriveReadinessVerdict(deal, action);

    assert.equal(observed.code, "PREVIOUS_ACTION_REQUIRED", kind);
    assert.equal(observed.conclusion, "Readiness cannot be established yet", kind);
    assert.equal(observed.blockingGate, null, kind);
    assert.match(observed.cause, /is unknown/, kind);
    assert.match(observed.nextAction, /do not infer that the gate failed/, kind);
  }
});
