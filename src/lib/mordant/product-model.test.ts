import assert from "node:assert/strict";
import { test } from "node:test";

import {
  FIXTURE_NOW,
  GATE_KINDS,
  PRODUCT_MODEL_SCHEMA_VERSION,
  SYNTHETIC_DEALS,
  SYNTHETIC_DEALS_BY_ID,
  SYNTHETIC_MODEL_NOTICE,
  amount,
  assessAction,
  deriveDealSummary,
  getSyntheticDeal,
  makeGateVector,
  proRateAmount,
  type DealAction,
  type DealScenarioId,
  type MonetaryEffect,
} from "./product-model";

function firstAction(scenario: DealScenarioId): DealAction {
  const action = getSyntheticDeal(scenario).actions[0];
  assert.ok(action, `${scenario} must expose a primary action`);
  return action;
}

test("publishes fourteen uniquely indexed synthetic scenarios", () => {
  assert.equal(SYNTHETIC_DEALS.length, 14);
  assert.equal(Object.keys(SYNTHETIC_DEALS_BY_ID).length, 14);
  assert.equal(new Set(SYNTHETIC_DEALS.map((deal) => deal.scenario)).size, 14);

  const requiredScenarios: readonly DealScenarioId[] = [
    "healthy",
    "cure-expiring",
    "pending-finality",
    "funds-missing",
    "allowance-missing",
    "wrong-role",
    "credential-required",
    "prerequisite-missing",
    "completed",
    "recovery-required",
    "stale-observation",
    "unknown-observation",
    "partial-redemption",
    "protection-settled",
  ];

  assert.deepEqual(
    SYNTHETIC_DEALS.map((deal) => deal.scenario),
    requiredScenarios,
  );
  for (const scenario of requiredScenarios) {
    assert.equal(getSyntheticDeal(scenario), SYNTHETIC_DEALS_BY_ID[scenario]);
  }
});

test("marks every fixture as synthetic and uses only synthetic references", () => {
  for (const deal of SYNTHETIC_DEALS) {
    assert.equal(deal.schemaVersion, PRODUCT_MODEL_SCHEMA_VERSION);
    assert.equal(deal.environment, "synthetic-demo");
    assert.equal(deal.notice, SYNTHETIC_MODEL_NOTICE);
    assert.match(deal.id, /^synthetic:/);
    assert.match(deal.viewer.participantId, /^synthetic:/);
    assert.match(deal.machines.receivable.immutableInvoiceRoot, /^synroot:/);
    assert.match(deal.machines.protection.immutablePolicyId, /^synthetic:/);

    for (const proof of deal.proofs) {
      assert.match(proof.action.reference, /^synthetic:/);
    }
  }
});

test("always exposes the complete ordered five-gate vector", () => {
  for (const deal of SYNTHETIC_DEALS) {
    for (const action of deal.actions) {
      assert.equal(action.gates.length, 5);
      assert.deepEqual(
        action.gates.map((gate) => gate.kind),
        GATE_KINDS,
      );
    }
  }

  assert.deepEqual(
    makeGateVector().map((gate) => gate.kind),
    ["identity", "role", "time", "economic", "protocol"],
  );
});

test("assesses gate failures without collapsing or replacing the gate vector", () => {
  const deal = getSyntheticDeal("wrong-role");
  const action = firstAction("wrong-role");
  const assessment = assessAction(action, deal.observation);

  assert.equal(assessment.availability, "blocked");
  assert.equal(assessment.gates, action.gates);
  assert.equal(assessment.gates.length, 5);
  assert.deepEqual(assessment.blockingGates.map((gate) => gate.kind), ["role"]);
  assert.equal(assessment.blockingGates[0]?.code, "role_reserved_for_facility_b");
  assert.equal(assessment.pendingGates.length, 0);
  assert.equal(assessment.unknownGates.length, 0);
});

test("keeps pending finality separate from otherwise satisfied gates", () => {
  const deal = getSyntheticDeal("pending-finality");
  const action = firstAction("pending-finality");
  const assessment = assessAction(action, deal.observation);

  assert.ok(action.gates.every((gate) => gate.status === "satisfied"));
  assert.equal(assessment.blockingGates.length, 0);
  assert.equal(assessment.pendingGates.length, 0);
  assert.equal(assessment.availability, "pending");
  assert.equal(assessment.observationReason, "finality_required");
  assert.equal(assessment.observation.finality.status, "pending");
  assert.equal(assessment.observation.freshness.status, "fresh");
});

test("stale and unknown observations never masquerade as executable gates", () => {
  const staleDeal = getSyntheticDeal("stale-observation");
  const staleAction = firstAction("stale-observation");
  const stale = assessAction(staleAction, staleDeal.observation);
  assert.ok(staleAction.gates.every((gate) => gate.status === "satisfied"));
  assert.equal(stale.availability, "unknown");
  assert.equal(stale.observationReason, "refresh_required");

  const unknownDeal = getSyntheticDeal("unknown-observation");
  const unknownAction = firstAction("unknown-observation");
  const unknown = assessAction(unknownAction, unknownDeal.observation);
  assert.ok(unknownAction.gates.every((gate) => gate.status === "satisfied"));
  assert.equal(unknown.availability, "unknown");
  assert.equal(unknown.observationReason, "observation_unknown");
});

test("distinguishes balance, allowance, credential, and protocol blockers", () => {
  const expected = [
    ["funds-missing", "economic", "synthetic_balance_insufficient", "viewer_only"],
    ["allowance-missing", "economic", "synthetic_allowance_insufficient", "viewer_only"],
    ["credential-required", "identity", "viewer_synthetic_credential_missing", "viewer_only"],
    ["prerequisite-missing", "protocol", "commitment_not_observed", "shared"],
  ] as const;

  for (const [scenario, kind, code, visibility] of expected) {
    const deal = getSyntheticDeal(scenario);
    const assessment = assessAction(firstAction(scenario), deal.observation);
    assert.equal(assessment.availability, "blocked");
    assert.equal(assessment.blockingGates.length, 1);
    assert.equal(assessment.blockingGates[0]?.kind, kind);
    assert.equal(assessment.blockingGates[0]?.code, code);
    assert.equal(assessment.blockingGates[0]?.visibility, visibility);
  }
});

test("keeps receivable and protection state machines independent after protection settlement", () => {
  const deal = getSyntheticDeal("protection-settled");
  const settlement = firstAction("protection-settled");

  assert.equal(deal.machines.protection.state, "settled");
  assert.equal(deal.machines.receivable.state, "outstanding");
  assert.equal(deal.economics.receivable.outstanding.minorUnits, "2480000000000");
  assert.equal(deal.economics.receivable.outstandingUnits, "100");
  assert.equal(settlement.machine, "protection");
  assert.equal(settlement.consequence.receivableTransition, undefined);
  assert.equal(settlement.consequence.receivableUnitsEffect, "none");
});

test("never lets a protection action burn or transfer receivable units", () => {
  const protectionActions = SYNTHETIC_DEALS.flatMap((deal) =>
    deal.actions.filter((action) => action.machine === "protection"),
  );
  assert.ok(protectionActions.length > 0);

  for (const action of protectionActions) {
    assert.equal(action.consequence.receivableUnitsEffect, "none", action.id);
    assert.equal(action.consequence.receivableTransition, undefined, action.id);
  }
});

test("keeps every money effect in its declared accounting domain", () => {
  function assertEffectDomain(effect: MonetaryEffect): void {
    assert.equal(effect.amount.domain, effect.domain);
  }

  for (const deal of SYNTHETIC_DEALS) {
    assert.equal(deal.economics.receivable.domain, "receivable");
    assert.equal(deal.economics.receivable.faceValue.domain, "receivable");
    assert.equal(deal.economics.receivable.outstanding.domain, "receivable");
    assert.equal(deal.economics.receivable.redeemed.domain, "receivable");
    assert.equal(deal.economics.protection.domain, "protection");
    assert.equal(deal.economics.protection.initialReserve.domain, "protection");
    assert.equal(deal.economics.protection.requiredReserve.domain, "protection");
    assert.equal(deal.economics.protection.lockedReserve.domain, "protection");
    assert.equal(deal.economics.protection.protectionPaid.domain, "protection");

    for (const action of deal.actions) {
      action.consequence.monetaryEffects.forEach(assertEffectDomain);
    }
  }
});

test("models the ten-percent demo reserve as amortizing with outstanding protected principal", () => {
  const deal = getSyntheticDeal("partial-redemption");

  assert.equal(deal.economics.receivable.issuedUnits, "100");
  assert.equal(deal.economics.receivable.outstandingUnits, "50");
  assert.equal(deal.economics.protection.demoReserveParameterBps, 1000);
  assert.equal(deal.economics.protection.initialReserve.minorUnits, "248000000000");
  assert.equal(deal.economics.protection.requiredReserve.minorUnits, "124000000000");
  assert.equal(deal.economics.protection.lockedReserve.minorUnits, "124000000000");
});

test("derives the connected holder's 60/100 personal exposures with exact bigint arithmetic", () => {
  const deal = getSyntheticDeal("wrong-role");
  const position = deal.viewer.position;
  assert.deepEqual(position, { invoiceUnits: "60", totalUnits: "100" });
  assert.equal(deal.viewer.role, "holder");

  assert.deepEqual(proRateAmount(deal.economics.receivable.outstanding, position), {
    domain: "receivable",
    asset: deal.economics.receivable.outstanding.asset,
    minorUnits: "1488000000000",
  });
  assert.deepEqual(proRateAmount(deal.economics.protection.lockedReserve, position), {
    domain: "protection",
    asset: deal.economics.protection.lockedReserve.asset,
    minorUnits: "148800000000",
  });
});

test("rejects invalid or non-integral participant exposure ratios instead of rounding", () => {
  const source = amount("receivable", "1");

  assert.throws(
    () => proRateAmount(source, { invoiceUnits: "1", totalUnits: "0" }),
    /totalUnits > 0/,
  );
  assert.throws(
    () => proRateAmount(source, { invoiceUnits: "101", totalUnits: "100" }),
    /invoiceUnits <= totalUnits/,
  );
  assert.throws(
    () => proRateAmount(source, { invoiceUnits: "1", totalUnits: "3" }),
    /not exactly representable/,
  );
});

test("represents evidence as before, action, after with provenance and diagnostics", () => {
  const pendingProof = getSyntheticDeal("pending-finality").proofs[0];
  assert.ok(pendingProof);
  assert.equal(pendingProof.before.state, "active");
  assert.equal(pendingProof.action.name, "revealSyntheticConflict()");
  assert.equal(pendingProof.after.state, "conflict_registered");
  assert.equal(pendingProof.finality.status, "pending");
  assert.equal(pendingProof.evidence[0]?.classification, "observed_onchain");
  assert.equal(pendingProof.evidence[0]?.source, "Synthetic fixture event stream");
  assert.equal(pendingProof.diagnostics[0]?.code, "finality_pending");

  const settlementProof = getSyntheticDeal("protection-settled").proofs[0];
  assert.ok(settlementProof);
  assert.deepEqual(
    settlementProof.evidence.map((item) => item.classification),
    ["observed_onchain", "derived_by_mordant"],
  );
  assert.equal(settlementProof.evidence[1]?.value, "None");
});

test("exposes explicit next responsibility, consequence, and deadline where applicable", () => {
  const deal = getSyntheticDeal("cure-expiring");
  const responsibility = deal.nextResponsibility;

  assert.equal(responsibility.status, "due_now");
  assert.equal(responsibility.actorLabel, "Originator or Facility B");
  assert.equal(responsibility.dueAt, "2026-07-29T10:00:00.000Z");
  assert.match(responsibility.consequenceIfMissed ?? "", /receivable units remain untouched/i);
  assert.match(firstAction("cure-expiring").consequence.summary, /without burning or transferring receivable units/i);
});

test("derives deterministic summaries without discarding action diagnostics", () => {
  const scenarios = [
    ["healthy", "stable"],
    ["cure-expiring", "attention"],
    ["completed", "complete"],
    ["recovery-required", "recovery"],
    ["stale-observation", "unknown"],
  ] as const;

  for (const [scenario, posture] of scenarios) {
    const deal = getSyntheticDeal(scenario);
    const first = deriveDealSummary(deal);
    const second = deriveDealSummary(deal);
    assert.deepEqual(first, second);
    assert.equal(first.posture, posture);
    if (deal.actions[0] !== undefined) {
      assert.equal(first.primaryAction?.gates, deal.actions[0].gates);
    }
  }

  assert.equal(FIXTURE_NOW, "2026-07-29T08:00:00.000Z");
});

test("validates exact non-negative minor-unit amounts", () => {
  assert.deepEqual(amount("receivable", "2480000000000"), {
    domain: "receivable",
    asset: {
      id: "synthetic-ausdc",
      symbol: "aUSDC",
      label: "Synthetic aUSDC",
      decimals: 6,
      kind: "synthetic-test-asset",
    },
    minorUnits: "2480000000000",
  });
  assert.throws(() => amount("protection", "-1"), RangeError);
  assert.throws(() => amount("protection", "01" as `${bigint}`), RangeError);
  assert.throws(() => amount("protection", "1.5" as `${bigint}`), RangeError);
});
