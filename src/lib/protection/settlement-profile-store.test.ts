import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE } from "./bridge-executor";
import { bridgeRunId } from "./governed-recourse-bridge";
import { digestToBytes32 } from "./participant-authorization";
import {
  SETTLEMENT_AUTHORIZED,
  SETTLEMENT_NOT_AUTHORIZED,
  SETTLEMENT_PROFILE_SCHEMA,
  SettlementAuthorityError,
  settlementPlanHash,
  type GovernedResultFacts,
  type SettlementProfile,
} from "./settlement-authority";
import {
  SettlementProfileStoreError,
  commitSettlementProfile,
  readCommittedSettlementProfile,
  settlementAuthorityForRun,
  settlementProfilePath,
} from "./settlement-profile-store";

const RUN = "30ef645f-8047-45ee-8b7c-19952a54555f";
const AUTHORITY = `0x${"ab".repeat(32)}` as const;

function profile(overrides: Partial<SettlementProfile> = {}): SettlementProfile {
  return Object.freeze({
    schemaVersion: SETTLEMENT_PROFILE_SCHEMA,
    profileId: "mordant.fresh-settlement.minimal",
    profileVersion: 1,
    committedAtUnix: 1_786_000_000,
    chainId: 10_143,
    adapter: "0x1111111111111111111111111111111111111111",
    settlementToken: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
    cviVerifier: "0xCFFA4cbF5117718EB7fC0dE2E13E07ce75B840aB",
    facility: "0x2222222222222222222222222222222222222222",
    attestor: "0x3333333333333333333333333333333333333333",
    holderA: "0x4444444444444444444444444444444444444444",
    holderB: "0x5555555555555555555555555555555555555555",
    payoutA: "1",
    payoutB: "1",
    cureWindowSeconds: 600,
    releaseAuthorityId: AUTHORITY,
    settlementAuthorization: SETTLEMENT_AUTHORIZED,
    ...overrides,
  });
}

const result: GovernedResultFacts = Object.freeze({
  governedResultDigest: `0x${"cd".repeat(32)}`,
  runId: `0x${"ef".repeat(32)}`,
  releaseAuthorityId: AUTHORITY,
  conflict: true,
});

function root(): string {
  return mkdtempSync(join(tmpdir(), "mordant-settlement-store-"));
}

function storeCode(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    assert.ok(error instanceof SettlementProfileStoreError, `expected a store error, got ${String(error)}`);
    return error.code;
  }
  return assert.fail("expected a refusal, the call succeeded");
}

test("a committed profile round-trips and yields a plan-bound authorization", () => {
  const runRoot = root();
  try {
    const committed = commitSettlementProfile(runRoot, RUN, profile());
    const read = readCommittedSettlementProfile(runRoot, RUN);
    assert.equal(read.committedDigest, committed.committedDigest);

    const authority = settlementAuthorityForRun(runRoot, RUN, result);
    assert.equal(authority.plan.payoutA, "1");
    assert.equal(authority.plan.payoutB, "1");
    assert.equal(authority.plan.settlementProfileDigest, committed.committedDigest);
    assert.equal(authority.authorization.planHash, settlementPlanHash(authority.plan));
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("a profile cannot be committed once the governed result exists", () => {
  const runRoot = root();
  try {
    mkdirSync(join(runRoot, RUN), { recursive: true });
    writeFileSync(join(runRoot, RUN, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE), "{}");
    assert.equal(storeCode(() => commitSettlementProfile(runRoot, RUN, profile())), "RESULT_ALREADY_EXPOSED");
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("committing twice is refused rather than silently replacing the commitment", () => {
  const runRoot = root();
  try {
    commitSettlementProfile(runRoot, RUN, profile());
    assert.equal(
      storeCode(() => commitSettlementProfile(runRoot, RUN, profile({ payoutA: "4000" }))),
      "ALREADY_COMMITTED",
    );
    // The original terms survive the attempt.
    assert.equal(readCommittedSettlementProfile(runRoot, RUN).profile.payoutA, "1");
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("editing the retained profile after commitment is detected on read", () => {
  const runRoot = root();
  try {
    commitSettlementProfile(runRoot, RUN, profile());
    const path = settlementProfilePath(runRoot, RUN);
    const record = JSON.parse(readFileSync(path, "utf8")) as { profile: { payoutA: string } };
    record.profile.payoutA = "4000";
    writeFileSync(path, JSON.stringify(record, null, 2));

    assert.equal(storeCode(() => readCommittedSettlementProfile(runRoot, RUN)), "TAMPERED");
    assert.equal(storeCode(() => settlementAuthorityForRun(runRoot, RUN, result)), "TAMPERED");
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("a run with no commitment has no settlement authority to offer", () => {
  const runRoot = root();
  try {
    assert.equal(storeCode(() => readCommittedSettlementProfile(runRoot, RUN)), "NOT_COMMITTED");
    assert.equal(storeCode(() => settlementAuthorityForRun(runRoot, RUN, result)), "NOT_COMMITTED");
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("an unauthorized commitment can be stored but can never produce authority", () => {
  const runRoot = root();
  try {
    commitSettlementProfile(runRoot, RUN, profile({ settlementAuthorization: SETTLEMENT_NOT_AUTHORIZED }));
    try {
      settlementAuthorityForRun(runRoot, RUN, result);
      assert.fail("an unauthorized profile must not produce settlement authority");
    } catch (error) {
      assert.ok(error instanceof SettlementAuthorityError);
      assert.equal(error.code, "SETTLEMENT_NOT_AUTHORIZED");
    }
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

/**
 * The runtime handoff the consume script performs.
 *
 * The script converts the durable evidence's own fields into the bytes32 forms
 * the release message carries. If those conversions ever diverge, the gate
 * would refuse a legitimate settlement at broadcast time with RESULT_MISMATCH
 * or RUN_MISMATCH, which is exactly the failure no other test would catch.
 */
test("evidence-derived identity reproduces the values a real settlement recorded on chain", () => {
  // Ground truth from the retained hardened run: the durable evidence holds the
  // source uuid and sha256 digest, the consumed record holds what the adapter
  // actually saw. scripts/activation-bridge-consume.mjs bridges the two with
  // exactly these conversions, and a divergence would refuse a legitimate
  // settlement at broadcast with RUN_MISMATCH or RESULT_MISMATCH.
  const evidence = JSON.parse(readFileSync(
    "docs/evidence/hardened-direct-participant-bridge-evidence-2026-08-07.json", "utf8",
  )) as { runId: string; governedResultDigest: `sha256:${string}` };
  const consumed = JSON.parse(readFileSync(
    "docs/evidence/hardened-release-consumed-2026-08-07.json", "utf8",
  )) as { bridgeRunId: string; governedResultDigest: string };

  assert.equal(bridgeRunId(evidence.runId), consumed.bridgeRunId);
  assert.equal(digestToBytes32(evidence.governedResultDigest), consumed.governedResultDigest);
});

test("a no-conflict governed result produces no authority from a valid commitment", () => {
  const runRoot = root();
  try {
    commitSettlementProfile(runRoot, RUN, profile());
    try {
      settlementAuthorityForRun(runRoot, RUN, { ...result, conflict: false });
      assert.fail("a refusing result must not produce settlement authority");
    } catch (error) {
      assert.ok(error instanceof SettlementAuthorityError);
      assert.equal(error.code, "NO_CONFLICT");
    }
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});
