import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";

import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  CANONICAL_CLEANVERSE_ASSET_RECORD,
  CleanverseAssetBindingError,
  allAssetFieldClassifications,
  assertCanonicalCleanverseAssetRecord,
  cleanverseAssetRecordDigest,
  type CleanverseAssetRecord,
  type Sha256Digest,
} from "./cleanverse-asset";
import {
  assertGovernedResultAsset,
  assertParticipantSubmissionAsset,
  assertRecourseAsset,
  createProtectionCase,
  ProtectionBindingError,
} from "./protection-case";
import { assertPublicProtectionEvidence, type MordantProtectionEvidence } from "./protection-evidence";
import { evaluateDiskSpace, PRODUCT_STORAGE } from "./governed-fhe-product-server";
import { PRODUCT_EXECUTION_LABELS, recoursePresentation } from "./protection-presentation";

const BAD_DIGEST = `sha256:${"ff".repeat(32)}` as Sha256Digest;

function mutateRecord(
  mutate: (record: Record<string, unknown>) => void,
): CleanverseAssetRecord {
  const clone = structuredClone(CANONICAL_CLEANVERSE_ASSET_RECORD) as unknown as Record<string, unknown>;
  mutate(clone);
  return clone as unknown as CleanverseAssetRecord;
}

test("canonical Cleanverse record has a stable authoritative digest", () => {
  assert.equal(cleanverseAssetRecordDigest(CANONICAL_CLEANVERSE_ASSET_RECORD), CANONICAL_CLEANVERSE_ASSET_DIGEST);
  assert.match(CANONICAL_CLEANVERSE_ASSET_DIGEST, /^sha256:[0-9a-f]{64}$/);
  assert.equal(assertCanonicalCleanverseAssetRecord(CANONICAL_CLEANVERSE_ASSET_RECORD), CANONICAL_CLEANVERSE_ASSET_DIGEST);
});

test("every asset mutation changes the digest and the canonical gate rejects it", () => {
  const changed = mutateRecord((record) => {
    const reference = record.receivableReference as { value: { reference: string } };
    reference.value.reference = "SUBSTITUTED";
  });
  assert.notEqual(cleanverseAssetRecordDigest(changed), CANONICAL_CLEANVERSE_ASSET_DIGEST);
  assert.throws(() => assertCanonicalCleanverseAssetRecord(changed), CleanverseAssetBindingError);
});

test("wrong chain, contract or token identity is rejected", () => {
  const mutations: CleanverseAssetRecord[] = [
    mutateRecord((record) => { ((record.network as { value: { chainId: number } }).value.chainId) = 1; }),
    mutateRecord((record) => { ((record.token as { value: { address: string } }).value.address) = "0x0000000000000000000000000000000000000001"; }),
    mutateRecord((record) => { ((record.token as { value: { symbol: string } }).value.symbol) = "OTHER"; }),
  ];
  for (const mutation of mutations) {
    assert.throws(() => assertCanonicalCleanverseAssetRecord(mutation), CleanverseAssetBindingError);
  }
});

test("wrong source, issuer, policy or terms version is rejected", () => {
  const mutations: CleanverseAssetRecord[] = [
    mutateRecord((record) => { ((record.sourceIdentity as { value: { cleanverseRequestId: string } }).value.cleanverseRequestId) = "OTHER"; }),
    mutateRecord((record) => { ((record.sourceIdentity as { value: { adminAddress: string } }).value.adminAddress) = "0x0000000000000000000000000000000000000001"; }),
    mutateRecord((record) => { ((record.policy as { value: { address: string } }).value.address) = "0x0000000000000000000000000000000000000001"; }),
    mutateRecord((record) => { ((record.policy as { value: { documentedTermsVersion: string } }).value.documentedTermsVersion) = "v9"; }),
  ];
  for (const mutation of mutations) {
    assert.throws(() => assertCanonicalCleanverseAssetRecord(mutation), CleanverseAssetBindingError);
  }
});

test("the FHE case is derived only from the protection-case asset and policy", () => {
  const protection = createProtectionCase({
    scenario: "conflict",
    createdAt: "2026-08-03T12:00:00.000Z",
    caseNonce: "01".repeat(32),
  });
  const replay = createProtectionCase({
    scenario: "conflict",
    createdAt: "2026-08-03T12:00:00.000Z",
    caseNonce: "01".repeat(32),
  });
  assert.equal(protection.cleanverseAssetDigest, CANONICAL_CLEANVERSE_ASSET_DIGEST);
  assert.equal(protection.fheCaseId, replay.fheCaseId);
  assert.equal(protection.policyId, replay.policyId);
});

test("participant, governed result and recourse reject another asset", () => {
  const protection = createProtectionCase({
    scenario: "conflict",
    createdAt: "2026-08-03T12:00:00.000Z",
    caseNonce: "02".repeat(32),
  });
  assert.throws(() => assertParticipantSubmissionAsset(protection, BAD_DIGEST), ProtectionBindingError);
  assert.throws(() => assertGovernedResultAsset(protection, BAD_DIGEST), ProtectionBindingError);
  assert.throws(() => assertRecourseAsset(protection, BAD_DIGEST), ProtectionBindingError);
});

test("reserve and receivable claim remain separate in the protection model", () => {
  const protection = createProtectionCase({
    scenario: "conflict",
    createdAt: "2026-08-03T12:00:00.000Z",
    caseNonce: "03".repeat(32),
  });
  assert.equal(protection.reserve.accountingDomain, "PROTECTION");
  assert.equal(protection.reserve.basisPoints, 1000);
  assert.equal(protection.originalReceivable.accountingDomain, "RECEIVABLE");
  assert.equal(protection.originalReceivable.state, "OUTSTANDING_INTACT");
  assert.equal(protection.originalReceivable.units, "100000000");
});

test("asset classifications explicitly include live, fixture and unproven facts", () => {
  const classifications = new Set(allAssetFieldClassifications(CANONICAL_CLEANVERSE_ASSET_RECORD));
  assert.ok(classifications.has("LIVE_OBSERVED"));
  assert.ok(classifications.has("FIXTURE"));
  assert.ok(classifications.has("UNPROVEN"));
});

test("disk preflight refuses before key generation when the safety margin is unavailable", () => {
  const insufficient = evaluateDiskSpace(PRODUCT_STORAGE.estimatedCaseBytes);
  const sufficient = evaluateDiskSpace(PRODUCT_STORAGE.estimatedCaseBytes + PRODUCT_STORAGE.safetyMarginBytes);
  assert.equal(insufficient.sufficient, false);
  assert.equal(sufficient.sufficient, true);
  assert.equal(insufficient.requiredBytes, PRODUCT_STORAGE.estimatedCaseBytes + PRODUCT_STORAGE.safetyMarginBytes);
});

test("frontend copy never presents protocol-double recourse as live settlement", () => {
  assert.match(PRODUCT_EXECUTION_LABELS.recourse, /^Local protocol double/);
  assert.match(PRODUCT_EXECUTION_LABELS.recourse, /no Cleanverse settlement transaction/);
  assert.doesNotMatch(PRODUCT_EXECUTION_LABELS.recourse, /^Live /i);
});

for (const scenario of ["conflict", "no-conflict"] as const) {
  test(`retained real governed-FHE ${scenario} evidence is structurally safe when present`, (context) => {
    const path = join(process.cwd(), "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`);
    try {
      const evidence = JSON.parse(readFileSync(path, "utf8")) as MordantProtectionEvidence;
      assertPublicProtectionEvidence(evidence);
      assert.equal(evidence.scenario, scenario);
      assert.equal(evidence.cleanverseAssetDigest, CANONICAL_CLEANVERSE_ASSET_DIGEST);
      assert.equal(evidence.fhe.assetIdentity, CANONICAL_CLEANVERSE_ASSET_DIGEST);
      assert.equal(evidence.governedResult.assetIdentity, CANONICAL_CLEANVERSE_ASSET_DIGEST);
      assert.equal(evidence.governedResult.conflict, scenario === "conflict");
      assert.equal(evidence.recourse.opened, scenario === "conflict");
      assert.equal(recoursePresentation(evidence).status, scenario === "conflict" ? "AVAILABLE" : "REFUSED");
      assert.equal(evidence.originalReceivablePreservation.state, "OUTSTANDING_INTACT");
      assert.equal(evidence.originalReceivablePreservation.claimBurnedOrTransferredByProtection, false);
      assert.doesNotMatch(JSON.stringify(evidence), /secret-key|private-root|receivableId|privateMetadataCommitment/i);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        context.skip("real smoke evidence has not been generated yet");
        return;
      }
      throw error;
    }
  });
}
