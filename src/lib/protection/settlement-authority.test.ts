import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MANAGED_DEMO_SETTLEMENT_AUTHORIZATION,
  SETTLEMENT_AUTHORIZED,
  SETTLEMENT_NOT_AUTHORIZED,
  SETTLEMENT_PROFILE_SCHEMA,
  SettlementAuthorityError,
  assertSettlementAuthorization,
  assertWellFormedSettlementProfile,
  deriveSettlementAuthorization,
  deriveSettlementPlan,
  settlementProfileDigest,
  type AuthorizedReleaseFacts,
  type GovernedResultFacts,
  type SettlementProfile,
} from "./settlement-authority";

const ADAPTER = "0x1111111111111111111111111111111111111111" as const;
const TOKEN = "0xaC0893567D43C3E7e6e35a72803df05416C1f20D" as const;
const VERIFIER = "0xCFFA4cbF5117718EB7fC0dE2E13E07ce75B840aB" as const;
const FACILITY = "0x2222222222222222222222222222222222222222" as const;
const ATTESTOR = "0x3333333333333333333333333333333333333333" as const;
const HOLDER_A = "0x4444444444444444444444444444444444444444" as const;
const HOLDER_B = "0x5555555555555555555555555555555555555555" as const;
const AUTHORITY = `0x${"ab".repeat(32)}` as const;
const RESULT_DIGEST = `0x${"cd".repeat(32)}` as const;
const RUN_ID = `0x${"ef".repeat(32)}` as const;

function profile(overrides: Partial<SettlementProfile> = {}): SettlementProfile {
  return Object.freeze({
    schemaVersion: SETTLEMENT_PROFILE_SCHEMA,
    profileId: "mordant.fresh-settlement.minimal",
    profileVersion: 1,
    caseBinding: {
      runId: "10f6b34f-2189-4efb-91c2-1b7f4f372a4d",
      caseId: `sha256:${"12".repeat(32)}`,
      caseBindingDigest: `sha256:${"34".repeat(32)}`,
      protectionBindingDigest: `sha256:${"56".repeat(32)}`,
      releaseMode: "governed-decryptor-v1",
    },
    participantConfig: { path: "docs/evidence/fresh-case-participant-config.json", sha256: "78".repeat(32) },
    committedAtUnix: 1_786_000_000,
    chainId: 10_143,
    adapter: ADAPTER,
    settlementToken: TOKEN,
    cviVerifier: VERIFIER,
    facility: FACILITY,
    attestor: ATTESTOR,
    holderA: HOLDER_A,
    holderB: HOLDER_B,
    payoutA: "1",
    payoutB: "1",
    cureWindowSeconds: 600,
    releaseAuthorityId: AUTHORITY,
    settlementAuthorization: SETTLEMENT_AUTHORIZED,
    ...overrides,
  });
}

const conflictResult: GovernedResultFacts = Object.freeze({
  governedResultDigest: RESULT_DIGEST,
  runId: RUN_ID,
  releaseAuthorityId: AUTHORITY,
  conflict: true,
  caseId: `sha256:${"12".repeat(32)}`,
  caseBindingDigest: `sha256:${"34".repeat(32)}`,
});

function release(overrides: Partial<AuthorizedReleaseFacts> = {}): AuthorizedReleaseFacts {
  return Object.freeze({
    adapter: ADAPTER,
    chainId: 10_143,
    governedResultDigest: RESULT_DIGEST,
    runId: RUN_ID,
    holderA: HOLDER_A,
    holderB: HOLDER_B,
    payoutA: 1n,
    payoutB: 1n,
    conflict: true,
    ...overrides,
  });
}

function code(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    assert.ok(error instanceof SettlementAuthorityError, `expected a SettlementAuthorityError, got ${String(error)}`);
    return error.code;
  }
  return assert.fail("expected a refusal, the call succeeded");
}

/** The whole point: committed economics plus a governed conflict, and nothing else. */
test("an authorized profile settles exactly what it committed", () => {
  const committed = profile();
  const digest = settlementProfileDigest(committed);
  const plan = deriveSettlementPlan(committed, digest, conflictResult);
  const authorization = deriveSettlementAuthorization(plan);

  assert.equal(plan.payoutA, "1");
  assert.equal(plan.payoutB, "1");
  assert.equal(plan.cureWindowSeconds, 600);
  assert.equal(authorization.settlementProfileDigest, digest);
  assert.doesNotThrow(() => assertSettlementAuthorization(authorization, plan, release()));
});

test("the digest binds every committed term", () => {
  const base = settlementProfileDigest(profile());
  for (const overrides of [
    { holderA: HOLDER_B, holderB: HOLDER_A },
    { payoutA: "2" },
    { adapter: FACILITY },
    { settlementToken: VERIFIER },
    { cviVerifier: TOKEN },
    { facility: ATTESTOR },
    { attestor: FACILITY },
    { cureWindowSeconds: 60 },
    { releaseAuthorityId: `0x${"11".repeat(32)}` as const },
    { settlementAuthorization: SETTLEMENT_NOT_AUTHORIZED },
  ] satisfies Partial<SettlementProfile>[]) {
    assert.notEqual(settlementProfileDigest(profile(overrides)), base, `${JSON.stringify(overrides)} did not move the digest`);
  }
});

// ------------------------------------------------------------ negative controls

test("a governed Boolean without settlement authority is refused", () => {
  const unauthorized = profile({ settlementAuthorization: SETTLEMENT_NOT_AUTHORIZED });
  assert.equal(
    code(() => deriveSettlementPlan(unauthorized, settlementProfileDigest(unauthorized), conflictResult)),
    "SETTLEMENT_NOT_AUTHORIZED",
  );
});

test("a no-conflict result cannot settle", () => {
  const committed = profile();
  assert.equal(
    code(() => deriveSettlementPlan(committed, settlementProfileDigest(committed), { ...conflictResult, conflict: false })),
    "NO_CONFLICT",
  );
});

test("a profile tampered with after commitment is refused", () => {
  const committed = profile();
  const digest = settlementProfileDigest(committed);
  const tampered = profile({ payoutA: "4000" });
  assert.equal(code(() => deriveSettlementPlan(tampered, digest, conflictResult)), "PROFILE_TAMPERED");
});

test("a result from an uncommitted authority is refused", () => {
  const committed = profile();
  const digest = settlementProfileDigest(committed);
  const foreign = { ...conflictResult, releaseAuthorityId: `0x${"99".repeat(32)}` as const };
  assert.equal(code(() => deriveSettlementPlan(committed, digest, foreign)), "AUTHORITY_MISMATCH");
});

test("a changed holder is refused at the gate", () => {
  const committed = profile();
  const plan = deriveSettlementPlan(committed, settlementProfileDigest(committed), conflictResult);
  const authorization = deriveSettlementAuthorization(plan);
  const attacker = "0x9999999999999999999999999999999999999999" as const;
  assert.equal(
    code(() => assertSettlementAuthorization(authorization, plan, release({ holderB: attacker }))),
    "HOLDER_MISMATCH",
  );
});

test("a changed payout is refused at the gate", () => {
  const committed = profile();
  const plan = deriveSettlementPlan(committed, settlementProfileDigest(committed), conflictResult);
  const authorization = deriveSettlementAuthorization(plan);
  assert.equal(
    code(() => assertSettlementAuthorization(authorization, plan, release({ payoutB: 4_000n }))),
    "PAYOUT_MISMATCH",
  );
});

test("a wrong adapter is refused at the gate", () => {
  const committed = profile();
  const plan = deriveSettlementPlan(committed, settlementProfileDigest(committed), conflictResult);
  const authorization = deriveSettlementAuthorization(plan);
  const other = "0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1" as const;
  assert.equal(
    code(() => assertSettlementAuthorization(authorization, plan, release({ adapter: other }))),
    "ADAPTER_MISMATCH",
  );
});

test("an authorization from another plan is refused", () => {
  const committed = profile();
  const plan = deriveSettlementPlan(committed, settlementProfileDigest(committed), conflictResult);

  const otherCommitted = profile({ profileId: "mordant.fresh-settlement.other" });
  const otherPlan = deriveSettlementPlan(otherCommitted, settlementProfileDigest(otherCommitted), conflictResult);
  const foreignAuthorization = deriveSettlementAuthorization(otherPlan);

  assert.equal(code(() => assertSettlementAuthorization(foreignAuthorization, plan, release())), "PLAN_MISMATCH");
});

test("an authorization never rides along with a no-conflict release", () => {
  const committed = profile();
  const plan = deriveSettlementPlan(committed, settlementProfileDigest(committed), conflictResult);
  const authorization = deriveSettlementAuthorization(plan);
  assert.equal(
    code(() => assertSettlementAuthorization(authorization, plan, release({ conflict: false }))),
    "NO_CONFLICT_RELEASE",
  );
});

test("a release for a different governed result is refused", () => {
  const committed = profile();
  const plan = deriveSettlementPlan(committed, settlementProfileDigest(committed), conflictResult);
  const authorization = deriveSettlementAuthorization(plan);
  assert.equal(
    code(() => assertSettlementAuthorization(authorization, plan, release({ governedResultDigest: `0x${"01".repeat(32)}` }))),
    "RESULT_MISMATCH",
  );
});

test("the published managed policy stays settlement NOT_AUTHORIZED", () => {
  assert.equal(MANAGED_DEMO_SETTLEMENT_AUTHORIZATION.settlementAuthorization, SETTLEMENT_NOT_AUTHORIZED);
  assert.equal(MANAGED_DEMO_SETTLEMENT_AUTHORIZATION.policyId, "mordant.managed-demo.facility-protection");
  assert.equal(MANAGED_DEMO_SETTLEMENT_AUTHORIZATION.policyVersion, 1);

  // And it cannot be smuggled into a settling profile by reusing its identity.
  const wearingManagedIdentity = profile({
    profileId: MANAGED_DEMO_SETTLEMENT_AUTHORIZATION.policyId,
    settlementAuthorization: MANAGED_DEMO_SETTLEMENT_AUTHORIZATION.settlementAuthorization,
  });
  assert.equal(
    code(() => deriveSettlementPlan(
      wearingManagedIdentity,
      settlementProfileDigest(wearingManagedIdentity),
      conflictResult,
    )),
    "SETTLEMENT_NOT_AUTHORIZED",
  );
});

// ------------------------------------------------------------ profile hygiene

test("a profile that could never settle is refused at commitment", () => {
  assert.equal(code(() => assertWellFormedSettlementProfile(profile({ payoutA: "0", payoutB: "0" }))), "PROFILE_ZERO_TOTAL");
  assert.equal(code(() => assertWellFormedSettlementProfile(profile({ payoutB: "0" }))), "PROFILE_ZERO_HOLDER");
  assert.equal(code(() => assertWellFormedSettlementProfile(profile({ holderB: HOLDER_A }))), "PROFILE_HOLDER_COLLISION");
  assert.equal(code(() => assertWellFormedSettlementProfile(profile({ cureWindowSeconds: 0 }))), "PROFILE_CURE_WINDOW");
  assert.equal(code(() => assertWellFormedSettlementProfile(profile({ payoutA: "1.5" }))), "PROFILE_PAYOUT_FORMAT");
});

test("a well-formed NOT_AUTHORIZED profile is still committable", () => {
  // Publishing a governed product must not require granting it settlement power.
  assert.doesNotThrow(() => assertWellFormedSettlementProfile(profile({ settlementAuthorization: SETTLEMENT_NOT_AUTHORIZED })));
});
