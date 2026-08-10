import { deepStrictEqual, ok, strictEqual, throws } from "node:assert/strict";
import { createHash } from "node:crypto";
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

/** Mirrors the verifier's own derivation so a test can keep it intact on purpose. */
function thresholdManifestDigestForTest(manifest: MutableManifest): string {
  return `sha256:${createHash("sha256")
    .update(
      JSON.stringify({
        schemaVersion: manifest.schemaVersion,
        caseId: manifest.caseId,
        keyId: manifest.keyId,
        parameterFingerprint: manifest.parameterFingerprint,
        threshold: manifest.threshold,
        operators: manifest.operators.map((operator) => ({
          operatorId: operator.operatorId,
          point: operator.point,
          signingPublicKey: operator.signingPublicKey,
        })),
        operatorTopology: manifest.operatorTopology,
      }),
    )
    .digest("hex")}`;
}

const noConflictEvidence = JSON.parse(
  readFileSync(join(process.cwd(), "contracts/test/fixtures/coalition-evidence-no-conflict.json"), "utf8"),
) as { thresholdManifest: CoalitionThresholdManifest; coalitionResult: CoalitionConflictResult };

/** The genuinely released non-conflicting branch, verified as produced. */
function verifyNoConflict() {
  return verifyCoalitionEvidence(
    noConflictEvidence.coalitionResult,
    noConflictEvidence.thresholdManifest,
    RESULT_DIGEST,
    RUN_ID,
  );
}

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

test("a policy conflict without an asset match is refused", () => {
  // The canonical-vector check remains as defence in depth, but a result edited
  // into that shape now fails at the settlement binding first: the operators
  // confirmed the bits they recombined, and these are not those bits.
  throws(
    () =>
      verify(({ result }) => {
        result.sameEconomicAsset = false;
        result.policyConflict = true;
      }),
    (error: unknown) =>
      error instanceof CoalitionEvidenceError &&
      (error.code === "SETTLEMENT_SIGNATURE" || error.code === "NON_CANONICAL_DECISION"),
  );
});

test("a real asset match without a policy conflict verifies and settles nothing", () => {
  // A genuinely released non-conflicting branch, not an edited one: the same
  // receivable on both sides with windows that do not meet.
  const verified = verifyNoConflict();
  strictEqual(verified.sameEconomicAsset, true, "the asset fact survives as evidence");
  strictEqual(verified.policyConflict, false);
  strictEqual(verified.facts.conflict, false, "the plan must see no conflict");
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
function coalitionProfile(
  releaseAuthorityId: string,
  source: CoalitionConflictResult = evidence.coalitionResult,
): SettlementProfile {
  return Object.freeze({
    schemaVersion: "mordant.settlement-profile/2",
    profileId: "mordant.coalition.test-profile",
    profileVersion: 1,
    caseBinding: Object.freeze({
      runId: RUN_ID,
      caseId: source.caseId,
      caseBindingDigest: source.caseBindingDigest,
      protectionBindingDigest: `sha256:${"ee".repeat(32)}`,
      releaseMode: source.releaseMode,
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
  const verified = verifyNoConflict();
  const profile = coalitionProfile(verified.coalitionAuthorityId, noConflictEvidence.coalitionResult);
  const committed = settlementProfileDigest(profile);
  throws(
    () => deriveSettlementPlan(profile, committed, verified.facts),
    (error: unknown) => error instanceof SettlementAuthorityError && error.code === "NO_CONFLICT",
  );
});

// -------------------------------------------------------------- the binding

/**
 * The property the settlement authority must have: a coalition result edited
 * after production is detectable, without trusting whoever wrote the file.
 *
 * Every case below leaves all supplied Ed25519 signatures authentic. What breaks
 * is the message they were made over.
 */
test("flipping a released bit is refused although every signature is authentic", () => {
  refuses("SETTLEMENT_SIGNATURE", ({ result }) => {
    result.policyConflict = !result.policyConflict;
    result.sameEconomicAsset = true;
  });
  refuses("SETTLEMENT_SIGNATURE", ({ result }) => {
    result.sameEconomicAsset = false;
    result.policyConflict = false;
  });
});

test("moving the release to another case or binding is refused", () => {
  refuses("SETTLEMENT_SIGNATURE", ({ manifest, result }) => {
    const moved = `sha256:${"41".repeat(32)}`;
    result.caseId = moved;
    manifest.caseId = moved;
    // Keep the identity derivation intact so the failure is the binding, not it.
    result.releaseAuthorityId = thresholdManifestDigestForTest(manifest);
  });
  refuses("SETTLEMENT_SIGNATURE", ({ result }) => {
    result.caseBindingDigest = `sha256:${"42".repeat(32)}`;
  });
  refuses("SETTLEMENT_SIGNATURE", ({ result }) => {
    result.assetIdentity = `sha256:${"43".repeat(32)}`;
  });
});

test("substituting another release's transcript is refused", () => {
  refuses("SETTLEMENT_SIGNATURE", ({ result }) => {
    result.releaseTranscript = `0x${"44".repeat(32)}`;
  });
});

test("a confirmation cannot be moved between operators", () => {
  refuses("SETTLEMENT_SIGNATURE", ({ result }) => {
    const [first, second] = result.settlementAttestations;
    result.settlementAttestations = [
      { point: first.point, signature: second.signature },
      { point: second.point, signature: first.signature },
    ];
  });
});

test("a quorum of confirmations is required, not one", () => {
  refuses("SETTLEMENT_QUORUM", ({ result }) => {
    result.settlementAttestations = [result.settlementAttestations[0]];
  });
  refuses("SETTLEMENT_QUORUM", ({ result }) => {
    result.settlementAttestations = [];
  });
  refuses("SETTLEMENT_REPLAY", ({ result }) => {
    result.settlementAttestations = [result.settlementAttestations[0], result.settlementAttestations[0]];
  });
});

test("a confirmation from outside the serving coalition does not count", () => {
  refuses("SETTLEMENT_ATTRIBUTION", ({ result }) => {
    result.settlementAttestations = [
      result.settlementAttestations[0],
      { point: 99, signature: result.settlementAttestations[1].signature },
    ];
  });
});
