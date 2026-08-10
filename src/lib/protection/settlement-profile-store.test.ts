import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE } from "./bridge-executor";
import {
  PINNED_PARTICIPANT_CONFIGS,
  loadCanonicalRecourseConfiguration,
  readParticipantConfigSelection,
} from "./adapter-compatibility";
import { bridgeRunId } from "./governed-recourse-bridge";
import { digestToBytes32 } from "./participant-authorization";
import {
  SETTLEMENT_AUTHORIZED,
  SETTLEMENT_NOT_AUTHORIZED,
  SETTLEMENT_PROFILE_SCHEMA,
  SettlementAuthorityError,
  settlementPlanHash,
  settlementProfileDigest,
  type GovernedResultFacts,
  type SettlementProfile,
} from "./settlement-authority";
import {
  SettlementProfileStoreError,
  commitSettlementProfile,
  readCommittedSettlementProfile,
  existingResultArtifact,
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
  caseId: `sha256:${"12".repeat(32)}`,
  caseBindingDigest: `sha256:${"34".repeat(32)}`,
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

/**
 * The temporal boundary, checked against every artifact that reveals an outcome.
 *
 * The first version of this guard only knew the bridge evidence, which is
 * written last. In an observed run the outcome landed at 00:50:18 and the bridge
 * evidence at 00:50:26, so a commitment in that gap passed a guard it should
 * have failed. Each artifact below must independently close the window.
 */
test("a profile cannot be committed once any result-bearing artifact exists", () => {
  for (const relative of [
    join("public", "evaluated-conflict.json"),
    join("public", "governed-conflict-result.json"),
    join("public", "result-conflict.bin"),
    join("public", "recourse-record.json"),
    join("public", "product-recourse-attestation.json"),
    "recourse-outcome.json",
    DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE,
  ]) {
    const runRoot = root();
    try {
      mkdirSync(dirname(join(runRoot, RUN, relative)), { recursive: true });
      writeFileSync(join(runRoot, RUN, relative), "{}");
      assert.equal(
        storeCode(() => commitSettlementProfile(runRoot, RUN, profile())),
        "RESULT_ALREADY_EXPOSED",
        `${relative} must close the commitment window`,
      );
      assert.equal(existingResultArtifact(runRoot, RUN), relative);
    } finally {
      rmSync(runRoot, { recursive: true, force: true });
    }
  }
});

test("a result from another case cannot borrow this profile's economics", () => {
  const runRoot = root();
  try {
    commitSettlementProfile(runRoot, RUN, profile());
    for (const [overrides, code] of [
      [{ caseId: `sha256:${"99".repeat(32)}` }, "CASE_MISMATCH"],
      [{ caseBindingDigest: `sha256:${"99".repeat(32)}` }, "CASE_BINDING_MISMATCH"],
      [{ releaseAuthorityId: `0x${"99".repeat(32)}` }, "AUTHORITY_MISMATCH"],
    ] as const) {
      try {
        settlementAuthorityForRun(runRoot, RUN, { ...result, ...overrides });
        assert.fail(`expected ${code}`);
      } catch (error) {
        assert.ok(error instanceof SettlementAuthorityError);
        assert.equal(error.code, code);
      }
    }
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("the two pinned participant configurations are never interchangeable", () => {
  // Each is accepted only against its own reviewed bytes, so naming one and
  // serving the other is a refusal rather than a silent substitution.
  const retained = loadCanonicalRecourseConfiguration(process.cwd(), "retained");
  const fresh = loadCanonicalRecourseConfiguration(process.cwd(), "case");
  assert.notEqual(retained.participants.holderA.toLowerCase(), fresh.participants.holderA.toLowerCase());
  assert.notEqual(retained.participants.holderB.toLowerCase(), fresh.participants.holderB.toLowerCase());
  assert.notEqual(PINNED_PARTICIPANT_CONFIGS.retained.sha256, PINNED_PARTICIPANT_CONFIGS["case"].sha256);
  assert.notEqual(PINNED_PARTICIPANT_CONFIGS.retained.path, PINNED_PARTICIPANT_CONFIGS["case"].path);

  // A selection that names no pinned artifact is refused, never defaulted.
  assert.throws(() => readParticipantConfigSelection({ MORDANT_PARTICIPANT_CONFIG: "not-a-config" }));
  assert.equal(readParticipantConfigSelection({}), "retained");
});

test("a committed profile records which pinned participant configuration the case ran under", () => {
  const runRoot = root();
  try {
    const committed = commitSettlementProfile(runRoot, RUN, profile());
    assert.equal(committed.profile.participantConfig.path, "docs/evidence/fresh-case-participant-config.json");
    // Changing the recorded configuration digest changes the commitment digest,
    // so a profile cannot be reused across participant configurations.
    const other = profile({ participantConfig: { path: "docs/evidence/fresh-case-participant-config.json", sha256: "99".repeat(32) } });
    assert.notEqual(settlementProfileDigest(other), committed.committedDigest);
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
