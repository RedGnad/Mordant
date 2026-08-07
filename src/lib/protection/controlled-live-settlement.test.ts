import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  LIVE_SETTLEMENT_ACK_VALUE,
  LIVE_SETTLEMENT_CONDITIONS,
  LIVE_SETTLEMENT_ENABLED_VALUE,
  LIVE_SETTLEMENT_ENVIRONMENT,
  LIVE_SETTLEMENT_ONCHAIN_CONDITIONS,
  liveSettlementArmed,
  qualifyLiveSettlement,
} from "./controlled-live-settlement";

const RUN_ID = "76005a0c-2787-4c50-b196-636e45b71781";

function evidence(): Record<string, unknown> {
  return JSON.parse(readFileSync(
    join(process.cwd(), "docs", "evidence", "activation-direct-participant-bridge-evidence-2026-08-07.json"),
    "utf8",
  )) as Record<string, unknown>;
}

const ARMED = Object.freeze({
  [LIVE_SETTLEMENT_ENVIRONMENT.enable]: LIVE_SETTLEMENT_ENABLED_VALUE,
  [LIVE_SETTLEMENT_ENVIRONMENT.acknowledgement]: LIVE_SETTLEMENT_ACK_VALUE,
});

function qualify(environment: Record<string, string | undefined>, overrides: Record<string, unknown> = {}) {
  const artifact = { ...evidence(), ...overrides };
  return qualifyLiveSettlement(
    { evidence: artifact, sourceCommit: String(artifact.sourceCommit), runId: RUN_ID },
    environment,
  );
}

test("live settlement is disarmed unless both exact names carry their exact values", () => {
  assert.equal(liveSettlementArmed({}), false);
  assert.equal(liveSettlementArmed({ [LIVE_SETTLEMENT_ENVIRONMENT.enable]: LIVE_SETTLEMENT_ENABLED_VALUE }), false);
  assert.equal(liveSettlementArmed({ [LIVE_SETTLEMENT_ENVIRONMENT.acknowledgement]: LIVE_SETTLEMENT_ACK_VALUE }), false);
  assert.equal(liveSettlementArmed({ ...ARMED, [LIVE_SETTLEMENT_ENVIRONMENT.enable]: "true" }), false);
  assert.equal(liveSettlementArmed({ ...ARMED, [LIVE_SETTLEMENT_ENVIRONMENT.enable]: "1" }), false);
  assert.equal(liveSettlementArmed({ ...ARMED, [LIVE_SETTLEMENT_ENVIRONMENT.acknowledgement]: "yes" }), false);
  assert.equal(liveSettlementArmed(ARMED), true);
});

test("an unarmed deployment refuses even when the run itself is perfect", () => {
  const qualification = qualify({});
  assert.equal(qualification.permitted, false);
  assert.ok(qualification.refused.includes("SERVER_CAPABILITY_ENABLED"));
  assert.match(qualification.reason, /not armed/iu);
});

test("an armed deployment permits the qualified run", () => {
  const qualification = qualify({ ...ARMED });
  assert.equal(qualification.permitted, true, `refused: ${qualification.refused.join(", ")}`);
  assert.deepEqual([...qualification.refused], []);
  assert.deepEqual([...qualification.satisfied], [...LIVE_SETTLEMENT_CONDITIONS]);
});

test("the gate is fail-closed: unreadable evidence refuses every evidence-dependent condition", () => {
  for (const broken of [null, {}, [], "evidence", 7]) {
    const qualification = qualifyLiveSettlement(
      { evidence: broken, sourceCommit: "0".repeat(40), runId: RUN_ID },
      { ...ARMED },
    );
    assert.equal(qualification.permitted, false);
    assert.ok(qualification.refused.includes("BRIDGE_EVIDENCE_VERIFIED"));
    assert.ok(qualification.refused.includes("GOVERNED_SIGNATURE_VERIFIED"));
    assert.ok(qualification.refused.includes("CANONICAL_PARTICIPANT_A"));
    assert.ok(qualification.refused.includes("SIGNED_CONFLICT_PRESENT"));
  }
});

test("a run from a different checkout or a different case is refused", () => {
  assert.equal(qualifyLiveSettlement(
    { evidence: evidence(), sourceCommit: "a".repeat(40), runId: RUN_ID },
    { ...ARMED },
  ).permitted, false);
  assert.equal(qualifyLiveSettlement(
    { evidence: evidence(), sourceCommit: String(evidence().sourceCommit), runId: "11111111-1111-4111-8111-111111111111" },
    { ...ARMED },
  ).permitted, false);
});

test("a tampered participant, Boolean or signature cannot be settled", () => {
  const tampered = evidence();
  const participants = tampered.participants as Record<string, unknown>[];
  participants[0] = { ...participants[0], participantWallet: "0x1111111111111111111111111111111111111111" };
  assert.equal(qualify({ ...ARMED }, { participants }).permitted, false);

  const flipped = evidence();
  const result = { ...(flipped.governedResult as Record<string, unknown>) };
  result.conflict = !(result.conflict as boolean);
  assert.equal(qualify({ ...ARMED }, { governedResult: result }).permitted, false);
});

test("the qualification report carries no secret and no environment value", () => {
  const encoded = JSON.stringify(qualify({ ...ARMED }));
  for (const forbidden of [
    LIVE_SETTLEMENT_ACK_VALUE, "privateKey", "PRIVATE_KEY", "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY",
    "CLEANVERSE_API_KEY", "activeFrom", "activeUntil",
  ]) {
    assert.equal(encoded.includes(forbidden), false, `qualification leaked ${forbidden}`);
  }
});

test("the gate accepts no economic value from its caller", () => {
  // The input type has exactly three members, none of them economic. This is the
  // structural reason a browser cannot choose holders, payouts or the Boolean.
  const qualification = qualifyLiveSettlement(
    {
      evidence: evidence(),
      sourceCommit: String(evidence().sourceCommit),
      runId: RUN_ID,
      // Extra members are simply not read; nothing here can reach a payload.
      ...({ holderA: "0x0", payoutA: "999999", conflict: true } as unknown as Record<string, never>),
    },
    { ...ARMED },
  );
  assert.equal(qualification.permitted, true);
  const encoded = JSON.stringify(qualification);
  assert.equal(encoded.includes("999999"), false);
  assert.equal(encoded.includes("0x0"), false);
});

test("the on-chain conditions remain enforced at signing time, not cached here", () => {
  assert.ok(LIVE_SETTLEMENT_ONCHAIN_CONDITIONS.includes("RESULT_NOT_ALREADY_CONSUMED"));
  assert.ok(LIVE_SETTLEMENT_ONCHAIN_CONDITIONS.includes("SIMULATION_SUCCEEDS_IMMEDIATELY_BEFORE_BROADCAST"));
  assert.ok(LIVE_SETTLEMENT_ONCHAIN_CONDITIONS.includes("BRIDGE_ATTESTOR_EQUALS_ADAPTER_IMMUTABLE"));
  // None of them is claimed as satisfied by the offline gate.
  const satisfied = qualify({ ...ARMED }).satisfied as readonly string[];
  for (const condition of LIVE_SETTLEMENT_ONCHAIN_CONDITIONS) {
    assert.equal(satisfied.includes(condition), false, `${condition} must not be answered offline`);
  }
});
