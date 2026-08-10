import { deepStrictEqual, ok, strictEqual, throws } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  CoalitionEvidenceError,
  verifyCoalitionEvidence,
  type CoalitionConflictResult,
  type CoalitionThresholdManifest,
} from "./coalition-evidence";
import {
  deriveSettlementPlan,
  settlementProfileDigest,
  SettlementAuthorityError,
  type SettlementProfile,
} from "./settlement-authority";

// The evidence a real 2-of-3 spine release produced, verbatim. Regenerate with
// the Go emitter named in contracts/test/MordantCoalitionAdapter.t.sol.
const evidence = JSON.parse(
  readFileSync(join(process.cwd(), "contracts/test/fixtures/coalition-evidence.json"), "utf8"),
) as { thresholdManifest: CoalitionThresholdManifest; coalitionResult: CoalitionConflictResult };

const RESULT_DIGEST = `0x${"11".repeat(32)}`;
const RUN_ID = `0x${"22".repeat(32)}`;

/** The fixture is deep-frozen in shape only; the clones below are editable. */
type Mutable<T> = { -readonly [K in keyof T]: Mutable<T[K]> };
type MutableManifest = Mutable<CoalitionThresholdManifest>;
type MutableResult = Mutable<CoalitionConflictResult>;

function verify(
  mutate: (input: { manifest: MutableManifest; result: MutableResult }) => void = () => {},
) {
  const manifest = JSON.parse(JSON.stringify(evidence.thresholdManifest)) as MutableManifest;
  const result = JSON.parse(JSON.stringify(evidence.coalitionResult)) as MutableResult;
  mutate({ manifest, result });
  return verifyCoalitionEvidence(result as CoalitionConflictResult, manifest as CoalitionThresholdManifest, RESULT_DIGEST, RUN_ID);
}

function refuses(code: string, mutate: Parameters<typeof verify>[0]): void {
  throws(
    () => verify(mutate),
    (error: unknown) => error instanceof CoalitionEvidenceError && error.code === code,
    `expected ${code}`,
  );
}

test("a real coalition release yields the facts the settlement plan reads", () => {
  const verified = verify();
  strictEqual(verified.coalitionAuthorityId, evidence.coalitionResult.releaseAuthorityId);
  strictEqual(verified.servingQuorum, 2);
  strictEqual(verified.operatorTopology, "colocated-single-process");
  // Only the policy decision reaches the plan.
  strictEqual(verified.facts.conflict, evidence.coalitionResult.policyConflict);
  strictEqual(verified.facts.caseId, evidence.coalitionResult.caseId);
  strictEqual(verified.facts.caseBindingDigest, evidence.coalitionResult.caseBindingDigest);
  // Both bits survive as separate facts.
  strictEqual(verified.sameEconomicAsset, true);
  strictEqual(verified.policyConflict, true);
});

test("the release identity is recomputed from the manifest, never read from the result", () => {
  refuses("AUTHORITY_NOT_DERIVED", ({ result }) => {
    result.releaseAuthorityId = `sha256:${"ab".repeat(32)}`;
  });
  // Editing the manifest moves its digest, so it stops being the identity too.
  refuses("AUTHORITY_NOT_DERIVED", ({ manifest }) => {
    manifest.operators[0].point = 99;
  });
});

test("a quorum of one is refused wherever it is claimed", () => {
  refuses("MANIFEST_THRESHOLD", ({ manifest }) => {
    manifest.threshold = 1;
  });
  refuses("QUORUM_MISMATCH", ({ result }) => {
    result.threshold = 1;
  });
  refuses("QUORUM_SIZE", ({ result }) => {
    result.coalition = [result.coalition[0]];
  });
});

test("an operator outside the manifest cannot serve, and none can be counted twice", () => {
  refuses("QUORUM_MEMBERSHIP", ({ result }) => {
    result.coalition = [result.coalition[0], 77];
  });
  refuses("QUORUM_MEMBERSHIP", ({ result }) => {
    result.coalition = [result.coalition[0], result.coalition[0]];
  });
});

test("a statement that its named operator did not sign is refused", () => {
  refuses("STATEMENT_SIGNATURE", ({ result }) => {
    const statements = [...result.operatorStatements];
    statements[0] = { ...statements[0], statementDigest: `0x${"cd".repeat(32)}` };
    result.operatorStatements = statements;
  });
  // Swapping two operators' signatures breaks attribution in both directions.
  refuses("STATEMENT_SIGNATURE", ({ result }) => {
    const statements = [...result.operatorStatements];
    const first = statements[0];
    const other = statements.find((statement) => statement.point !== first.point);
    ok(other, "the fixture must carry statements from two operators");
    statements[0] = { ...first, signature: other.signature };
    result.operatorStatements = statements;
  });
});

test("every serving operator must attest both released bits", () => {
  refuses("STATEMENT_COVERAGE", ({ result }) => {
    result.operatorStatements = result.operatorStatements.filter((statement) => statement.slot !== 1);
  });
});

test("a policy conflict without an asset match cannot have come from the circuit", () => {
  refuses("NON_CANONICAL_DECISION", ({ result }) => {
    result.sameEconomicAsset = false;
    result.policyConflict = true;
  });
});

test("an asset match without a policy conflict verifies and settles nothing", () => {
  const verified = verify(({ result }) => {
    result.sameEconomicAsset = true;
    result.policyConflict = false;
  });
  strictEqual(verified.facts.conflict, false, "the plan must see no conflict");
  strictEqual(verified.sameEconomicAsset, true, "the asset fact survives as evidence");
});

test("the verified facts carry exactly the fields the settlement plan consumes", () => {
  deepStrictEqual(Object.keys(verify().facts).sort(), [
    "caseBindingDigest",
    "caseId",
    "conflict",
    "governedResultDigest",
    "releaseAuthorityId",
    "runId",
  ]);
});

// -------------------------------------------------------------- the settlement seam

/**
 * The settlement authority leg of the coalition path.
 *
 * `deriveSettlementPlan` is unchanged: it still reads exactly one field from the
 * result and takes every economic term from the pre-committed profile. What the
 * coalition changes is only which identity the profile commits to.
 */
function coalitionProfile(releaseAuthorityId: string): SettlementProfile {
  return Object.freeze({
    schemaVersion: "mordant.settlement-profile/2",
    profileId: "mordant.coalition.test-profile",
    profileVersion: 1,
    caseBinding: Object.freeze({
      runId: RUN_ID,
      caseId: evidence.coalitionResult.caseId,
      caseBindingDigest: evidence.coalitionResult.caseBindingDigest,
      protectionBindingDigest: `sha256:${"ee".repeat(32)}`,
      releaseMode: evidence.coalitionResult.releaseMode,
    }),
    participantConfig: Object.freeze({ path: "docs/evidence/coalition.json", sha256: `sha256:${"dd".repeat(32)}` }),
    committedAtUnix: 1_786_000_000,
    chainId: 10143,
    adapter: "0x9cd93089e02d301bddfc86eaabb39242272cafa1",
    settlementToken: "0xac0893567d43c3e7e6e35a72803df05416c1f20d",
    cviVerifier: "0xcffa4cbf5117718eb7fc0de2e13e07ce75b840ab",
    facility: "0x344412229b3b581c19572f9bf1f5d08d4ae897e6",
    attestor: "0xee3260ba47d097de5a8601107e1b83454593617c",
    holderA: "0x3883cbe36be79bd8d1b73ff160b8e7c3cb983685",
    holderB: "0x0f8b9a0c064306f938912658c96c681d8655140b",
    payoutA: "2400",
    payoutB: "1600",
    cureWindowSeconds: 600,
    releaseAuthorityId,
    settlementAuthorization: "AUTHORIZED",
  }) as SettlementProfile;
}

test("a verified coalition release drives the unchanged settlement plan", () => {
  const verified = verify();
  const profile = coalitionProfile(verified.coalitionAuthorityId);
  const committed = settlementProfileDigest(profile);

  const plan = deriveSettlementPlan(profile, committed, verified.facts);

  // The identity the plan carries is the coalition's, and it came from the manifest.
  strictEqual(plan.releaseAuthorityId, verified.coalitionAuthorityId);
  strictEqual(plan.conflict, true);
  // Every economic term is the profile's, none is the result's.
  strictEqual(plan.payoutA, "2400");
  strictEqual(plan.payoutB, "1600");
  strictEqual(plan.cureWindowSeconds, 600);
  strictEqual(plan.adapter, profile.adapter);
});

test("a profile committed to another coalition refuses this release", () => {
  const verified = verify();
  const profile = coalitionProfile(`sha256:${"11".repeat(32)}`);
  const committed = settlementProfileDigest(profile);
  throws(
    () => deriveSettlementPlan(profile, committed, verified.facts),
    (error: unknown) => error instanceof SettlementAuthorityError && error.code === "AUTHORITY_MISMATCH",
  );
});

test("a coalition release with no policy conflict authorizes no settlement", () => {
  const verified = verify(({ result }) => {
    result.policyConflict = false;
  });
  const profile = coalitionProfile(verified.coalitionAuthorityId);
  const committed = settlementProfileDigest(profile);
  throws(
    () => deriveSettlementPlan(profile, committed, verified.facts),
    (error: unknown) => error instanceof SettlementAuthorityError && error.code === "NO_CONFLICT",
  );
});
