import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";

import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  CANONICAL_CLEANVERSE_ASSET_RECORD,
  CleanverseAssetBindingError,
  StrictJsonError,
  allAssetFieldClassifications,
  assertCanonicalCleanverseAssetRecord,
  cleanverseAssetRecordDigest,
  canonicalJson,
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
import {
  ProtectionEvidenceError,
  assertPublicProtectionEvidence,
  governedResultDigest,
  protectionEvidenceDigest,
  verifyGovernedResultSignature,
  type MordantProtectionEvidence,
} from "./protection-evidence";
import { evaluateDiskSpace, PRODUCT_STORAGE } from "./governed-fhe-product-server";
import type { ProtectionCaseView } from "./governed-fhe-product-server";
import { protectionMutationGate } from "./protection-api-gate";
import {
  PRODUCT_EXECUTION_LABELS,
  evidenceForDisplayedCase,
  recoursePresentation,
  recourseStatePresentation,
} from "./protection-presentation";
import { POST } from "../../app/api/protection/conflicting-pledge/route";

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

test("strict JSON canonicalization rejects every non-JSON or ambiguous value", () => {
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  const sparse = new Array(2);
  sparse[1] = "present";
  class Instance { value = 1; }
  for (const value of [
    { value: Number.NaN }, { value: Number.POSITIVE_INFINITY }, { value: undefined },
    sparse, new Date("2026-08-03T00:00:00Z"), new Instance(), cyclic,
  ]) assert.throws(() => canonicalJson(value), StrictJsonError);
  assert.equal(canonicalJson({ z: [true, null, 3], a: "ok" }), '{"a":"ok","z":[true,null,3]}');
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
    mutateRecord((record) => { ((record.documentationTerms as { value: { version: string } }).value.version) = "v9"; }),
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

test("recourse labels derive only from the four explicit product states", () => {
  assert.match(recourseStatePresentation("NOT_OPEN").label, /not opened/i);
  assert.match(recourseStatePresentation("CURE_WINDOW").label, /window open/i);
  assert.match(recourseStatePresentation("AVAILABLE").label, /available/i);
  assert.match(recourseStatePresentation("REFUSED").label, /refused/i);
});

test("production POST gate returns before parsing any request body", async () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = "production";
  let parsed = false;
  try {
    const request = {
      url: "https://mordant.example/api/protection/conflicting-pledge",
      headers: new Headers(),
      json: async () => { parsed = true; throw new Error("body must not be parsed"); },
    } as unknown as Request;
    const response = await POST(request);
    assert.equal(response.status, 405);
    assert.equal(parsed, false);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test("local mutation requires opt-in plus loopback or an external capability", () => {
  const loopback = new Request("http://127.0.0.1:3000/api/protection/conflicting-pledge", { method: "POST" });
  assert.equal(protectionMutationGate(loopback, { NODE_ENV: "development" }).allowed, false);
  assert.equal(protectionMutationGate(loopback, { NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1" }).allowed, true);
  const remote = new Request("https://mordant.example/api/protection/conflicting-pledge", {
    method: "POST", headers: { "x-mordant-admin-capability": "a".repeat(32) },
  });
  assert.equal(protectionMutationGate(remote, {
    NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "b".repeat(32),
  }).allowed, false);
  assert.equal(protectionMutationGate(remote, {
    NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "a".repeat(32),
  }).allowed, true);
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

function retainedEvidence(scenario: "conflict" | "no-conflict"): MordantProtectionEvidence {
  return JSON.parse(readFileSync(join(
    process.cwd(), "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`,
  ), "utf8")) as MordantProtectionEvidence;
}

type Mutable<T> = { -readonly [Key in keyof T]: T[Key] extends object ? Mutable<T[Key]> : T[Key] };

function mutableEvidence(scenario: "conflict" | "no-conflict"): Mutable<MordantProtectionEvidence> {
  return structuredClone(retainedEvidence(scenario)) as Mutable<MordantProtectionEvidence>;
}

function rehash(evidence: MordantProtectionEvidence): MordantProtectionEvidence {
  const clone = structuredClone(evidence);
  const { manifestDigest: _discarded, ...value } = clone;
  return { ...value, manifestDigest: protectionEvidenceDigest(value) };
}

function rejectsEvidence(evidence: MordantProtectionEvidence, expectedCode: string): void {
  assert.throws(() => assertPublicProtectionEvidence(evidence), (error: unknown) => (
    error instanceof ProtectionEvidenceError && error.code === expectedCode
  ));
}

test("TypeScript verifies the exact retained Go-generated Ed25519 result", () => {
  const conflict = retainedEvidence("conflict");
  verifyGovernedResultSignature(conflict.governedResult);
  assert.equal(governedResultDigest(conflict.governedResult), conflict.governedResult.digest);
});

test("hybrid conflict case plus no-conflict governed result is rejected", () => {
  const conflict = mutableEvidence("conflict");
  conflict.governedResult = mutableEvidence("no-conflict").governedResult;
  rejectsEvidence(rehash(conflict), "SCENARIO_BINDING");
});

test("hybrid no-conflict case plus conflict recourse record is rejected", () => {
  const noConflict = mutableEvidence("no-conflict");
  noConflict.recourse = structuredClone(retainedEvidence("conflict").recourse);
  rejectsEvidence(rehash(noConflict), "RECOURSE_CASE_ID");
});

test("hybrid conflict product evidence plus no-conflict governed-FHE evidence is rejected", () => {
  const conflict = mutableEvidence("conflict");
  conflict.governedFheEvidence = mutableEvidence("no-conflict").governedFheEvidence;
  rejectsEvidence(rehash(conflict), "SCENARIO_BINDING");
});

test("another release-authority projection is rejected", () => {
  const conflict = mutableEvidence("conflict");
  const another = retainedEvidence("no-conflict").governedResult;
  conflict.governedResult.releaseAuthorityId = another.releaseAuthorityId;
  conflict.governedResult.releaseAuthorityPublicKey = another.releaseAuthorityPublicKey;
  rejectsEvidence(rehash(conflict), "RELEASE_AUTHORITY_BINDING");
});

test("mutated Cleanverse record with retained old digest is rejected", () => {
  const conflict = mutableEvidence("conflict");
  (conflict.cleanverseAsset as unknown as { token: { value: { name: string } } }).token.value.name = "Substituted token";
  rejectsEvidence(rehash(conflict), "ASSET_RECORD_DIGEST");
});

test("mutated governed-result signature is rejected after exact rehashing", () => {
  const noConflict = mutableEvidence("no-conflict");
  const signature = Buffer.from(noConflict.governedResult.signature, "base64");
  signature[0] ^= 1;
  noConflict.governedResult.signature = signature.toString("base64");
  noConflict.governedResult.digest = governedResultDigest(noConflict.governedResult);
  noConflict.governedFheEvidence.governedResultDigest = noConflict.governedResult.digest;
  rejectsEvidence(rehash(noConflict), "GOVERNED_RESULT_SIGNATURE");
});

test("mutated signed Boolean is rejected", () => {
  const noConflict = mutableEvidence("no-conflict");
  noConflict.governedResult.conflict = true;
  rejectsEvidence(rehash(noConflict), "SCENARIO_BINDING");
});

test("mutated CaseID is rejected", () => {
  const conflict = mutableEvidence("conflict");
  conflict.fhe.caseId = BAD_DIGEST;
  rejectsEvidence(rehash(conflict), "CASE_ID_BINDING");
});

test("component evidence state never falls back across imported and local transitions", () => {
  const imported = retainedEvidence("conflict");
  const incomplete = {
    runId: "11111111-1111-4111-8111-111111111111",
    protectionCase: { ...imported.protectionCase, recourseState: "NOT_OPEN" },
    evidence: null,
  } as unknown as ProtectionCaseView;
  const cureWindow = {
    ...incomplete,
    protectionCase: { ...incomplete.protectionCase, recourseState: "CURE_WINDOW" },
  } as ProtectionCaseView;
  const complete = {
    ...incomplete,
    runId: imported.runId,
    protectionCase: imported.protectionCase,
    evidence: imported,
  } as ProtectionCaseView;
  assert.equal(evidenceForDisplayedCase("imported", imported, null), imported);
  assert.equal(evidenceForDisplayedCase("local", imported, incomplete), null);
  assert.equal(evidenceForDisplayedCase("local", imported, cureWindow), null);
  assert.equal(recourseStatePresentation(cureWindow.protectionCase.recourseState).status, "CURE_WINDOW");
  assert.equal(evidenceForDisplayedCase("local", imported, complete), imported);
});
