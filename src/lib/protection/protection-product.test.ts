import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
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
  assertProtectionBindingDerivations,
  createProtectionCase,
  protectionBindingFromCase,
  ProtectionBindingError,
} from "./protection-case";
import {
  ProtectionEvidenceError,
  assertPublicProtectionEvidence,
  governedResultDigest,
  protectionBindingDigest,
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
  const binding = protectionBindingFromCase(protection);
  assertProtectionBindingDerivations(binding);
  assert.equal(protectionBindingDigest(binding), protectionBindingDigest(protectionBindingFromCase(replay)));
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

test("recourse labels derive only from the five explicit product states", () => {
  assert.match(recourseStatePresentation("NOT_OPEN").label, /not opened/i);
  assert.match(recourseStatePresentation("CURE_WINDOW").label, /window open/i);
  assert.match(recourseStatePresentation("AVAILABLE").label, /available/i);
  assert.match(recourseStatePresentation("SIMULATED_AVAILABLE").label, /simulated/i);
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

test("every network mutation requires opt-in and the external administrator capability", () => {
  const loopback = new Request("http://127.0.0.1:3000/api/protection/conflicting-pledge", { method: "POST" });
  assert.equal(protectionMutationGate(loopback, { NODE_ENV: "development" }).allowed, false);
  assert.equal(protectionMutationGate(loopback, { NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1" }).allowed, false);
  const remote = new Request("https://mordant.example/api/protection/conflicting-pledge", {
    method: "POST", headers: { "x-mordant-admin-capability": "a".repeat(32) },
  });
  assert.equal(protectionMutationGate(remote, {
    NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "b".repeat(32),
  }).allowed, false);
  assert.equal(protectionMutationGate(remote, {
    NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "a".repeat(32),
  }).allowed, true);
  const forgedLoopbackHost = new Request("https://remote.example/api/protection/conflicting-pledge", {
    method: "POST", headers: { host: "localhost" },
  });
  assert.equal(protectionMutationGate(forgedLoopbackHost, {
    NODE_ENV: "development", MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "a".repeat(32),
  }).allowed, false);
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
      assert.equal(recoursePresentation(evidence).status, scenario === "conflict" ? "SIMULATED_AVAILABLE" : "REFUSED");
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

const retainedArtifactsAvailable = ["conflict", "no-conflict"].every((scenario) => existsSync(join(
  process.cwd(), "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`,
)));
const artifactTest = retainedArtifactsAvailable ? test : test.skip;

type Mutable<T> = { -readonly [Key in keyof T]: T[Key] extends object ? Mutable<T[Key]> : T[Key] };

function mutableEvidence(scenario: "conflict" | "no-conflict"): Mutable<MordantProtectionEvidence> {
  return structuredClone(retainedEvidence(scenario)) as Mutable<MordantProtectionEvidence>;
}

function rehash(evidence: MordantProtectionEvidence): MordantProtectionEvidence {
  const clone = structuredClone(evidence);
  const value = Object.fromEntries(
    Object.entries(clone).filter(([key]) => key !== "manifestDigest"),
  ) as Omit<MordantProtectionEvidence, "manifestDigest">;
  return { ...value, manifestDigest: protectionEvidenceDigest(value) };
}

function rejectsEvidence(evidence: MordantProtectionEvidence, expectedCode: string): void {
  assert.throws(() => assertPublicProtectionEvidence(evidence), (error: unknown) => (
    error instanceof ProtectionEvidenceError && error.code === expectedCode
  ));
}

artifactTest("TypeScript verifies the exact retained Go-generated Ed25519 result", () => {
  const conflict = retainedEvidence("conflict");
  verifyGovernedResultSignature(conflict.governedResult);
  assert.equal(governedResultDigest(conflict.governedResult), conflict.governedResult.digest);
});

artifactTest("hybrid conflict case plus no-conflict governed result is rejected", () => {
  const conflict = mutableEvidence("conflict");
  conflict.governedResult = mutableEvidence("no-conflict").governedResult;
  rejectsEvidence(rehash(conflict), "SCENARIO_BINDING");
});

artifactTest("hybrid no-conflict case plus conflict recourse record is rejected", () => {
  const noConflict = mutableEvidence("no-conflict");
  noConflict.recourse = structuredClone(retainedEvidence("conflict").recourse);
  rejectsEvidence(rehash(noConflict), "RECOURSE_CASE_ID");
});

artifactTest("hybrid conflict product evidence plus no-conflict governed-FHE evidence is rejected", () => {
  const conflict = mutableEvidence("conflict");
  conflict.governedFheEvidence = mutableEvidence("no-conflict").governedFheEvidence;
  rejectsEvidence(rehash(conflict), "PROTECTION_BINDING_CROSS_REFERENCE");
});

artifactTest("another release-authority projection is rejected", () => {
  const conflict = mutableEvidence("conflict");
  const another = retainedEvidence("no-conflict").governedResult;
  conflict.governedResult.releaseAuthorityId = another.releaseAuthorityId;
  conflict.governedResult.releaseAuthorityPublicKey = another.releaseAuthorityPublicKey;
  rejectsEvidence(rehash(conflict), "RELEASE_AUTHORITY_BINDING");
});

artifactTest("mutated Cleanverse record with retained old digest is rejected", () => {
  const conflict = mutableEvidence("conflict");
  (conflict.cleanverseAsset as unknown as { token: { value: { name: string } } }).token.value.name = "Substituted token";
  rejectsEvidence(rehash(conflict), "ASSET_RECORD_DIGEST");
});

artifactTest("mutated governed-result signature is rejected after exact rehashing", () => {
  const noConflict = mutableEvidence("no-conflict");
  const signature = Buffer.from(noConflict.governedResult.signature, "base64");
  signature[0] ^= 1;
  noConflict.governedResult.signature = signature.toString("base64");
  noConflict.governedResult.digest = governedResultDigest(noConflict.governedResult);
  noConflict.governedFheEvidence.governedResultDigest = noConflict.governedResult.digest;
  rejectsEvidence(rehash(noConflict), "GOVERNED_RESULT_SIGNATURE");
});

artifactTest("mutated signed Boolean is rejected", () => {
  const noConflict = mutableEvidence("no-conflict");
  noConflict.governedResult.conflict = true;
  rejectsEvidence(rehash(noConflict), "SCENARIO_BINDING");
});

artifactTest("mutated CaseID is rejected", () => {
  const conflict = mutableEvidence("conflict");
  conflict.fhe.caseId = BAD_DIGEST;
  rejectsEvidence(rehash(conflict), "CASE_ID_BINDING");
});

artifactTest("every canonical signed product field rejects an adversarial mutation", () => {
  const mutations: ReadonlyArray<readonly [string, (evidence: Mutable<MordantProtectionEvidence>) => void]> = [
    ["holder snapshot", (value) => { value.protectionCase.holderSnapshot[0].protectedUnits = "1"; }],
    ["holder allocation", (value) => { value.protectionCase.holderAllocationDigest = BAD_DIGEST; }],
    ["record date", (value) => { value.protectionCase.holderRecordDate = "2026-08-03T00:00:00.000Z"; }],
    ["reserve", (value) => { value.protectionCase.reserve.minorUnits = "1" as "10000000"; }],
    ["scenario", (value) => { value.scenario = "no-conflict"; }],
    ["chronology", (value) => { value.chronology.events[0].kind = "SUBSTITUTED_CHRONOLOGY"; }],
    ["cure deadline", (value) => { value.chronology.cureDeadlineUnix = 1; }],
    ["recourse state", (value) => { value.chronology.finalRecourseState = "REFUSED"; }],
    ["original receivable state", (value) => { value.protectionCase.originalReceivable.state = "OTHER" as "OUTSTANDING_INTACT"; }],
    ["product claim", (value) => { value.recourseAttestation.attestation.productClaim = "other" as typeof value.recourseAttestation.attestation.productClaim; }],
    ["execution class", (value) => { value.recourseAttestation.attestation.executionClass = "OTHER" as "REAL_BGV_FHE"; }],
    ["deployment class", (value) => { value.recourseAttestation.attestation.deploymentClass = "OTHER" as "LOCAL_SINGLE_HOST"; }],
    ["release class", (value) => { value.recourseAttestation.attestation.releaseClass = "OTHER" as "GOVERNED_DECRYPTOR"; }],
    ["recourse class", (value) => { value.recourseAttestation.attestation.recourseClass = "OTHER" as "LOCAL_PROTOCOL_DOUBLE"; }],
    ["production isolation", (value) => { value.recourseAttestation.attestation.productionIsolationProven = true as false; }],
  ];
  for (const [name, mutate] of mutations) {
    const evidence = mutableEvidence("conflict");
    mutate(evidence);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence)),
      (error: unknown) => error instanceof ProtectionEvidenceError,
      `${name} mutation was accepted`,
    );
  }
});

artifactTest("canonical chronology rejects every caller-controlled mutation after outer rehash", () => {
  const mutations: ReadonlyArray<readonly [string, (value: Mutable<MordantProtectionEvidence>) => void]> = [
    ["timestamp", (value) => { value.chronology.events[0].atUnix! += 1; }],
    ["order", (value) => { [value.chronology.events[0], value.chronology.events[1]] = [value.chronology.events[1], value.chronology.events[0]]; }],
    ["kind", (value) => { value.chronology.events[0].kind = "CALLER_EVENT"; }],
    ["ordinal", (value) => { value.chronology.events[0].ordinal = 99; }],
    ["clock source", (value) => { value.chronology.events[0].clockSource = "CALLER_CLOCK"; }],
    ["reference", (value) => { value.chronology.events[0].evidenceRef = BAD_DIGEST; }],
    ["duplicate", (value) => { value.chronology.events.push(structuredClone(value.chronology.events[0])); }],
    ["clock class", (value) => { value.chronology.clockClass = "REAL_OBSERVED_CLOCK"; }],
    ["simulation as-of", (value) => { value.chronology.simulationAsOfUnix! += 1; }],
    ["signed at", (value) => { value.chronology.signedAtUnix += 1; }],
    ["cure deadline", (value) => { value.chronology.cureDeadlineUnix! += 1; }],
    ["incident", (value) => { value.chronology.finalIncidentState = "CLEARED"; }],
    ["recourse", (value) => { value.chronology.finalRecourseState = "AVAILABLE"; }],
    ["caller simulation timestamp", (value) => { value.chronology.events.at(-1)!.atUnix! += 30; }],
    ["arbitrary future real", (value) => {
      value.chronology.clockClass = "REAL_OBSERVED_CLOCK";
      value.chronology.signedAtUnix = value.caseAuthorization.binding.expiresAtUnix + 1;
      value.chronology.simulationAsOfUnix = null;
    }],
    ["real before deadline", (value) => {
      value.chronology.clockClass = "REAL_OBSERVED_CLOCK";
      value.chronology.signedAtUnix = value.recourse.record!.cureDeadlineUnix - 1;
      value.chronology.simulationAsOfUnix = null;
    }],
    ["source classification", (value) => { value.sourceClassifications[0] = "CLEANVERSE_CONFIRMED_CONFLICT_ON_CHAIN" as typeof value.sourceClassifications[0]; }],
    ["forged presentation text", (value) => { (value.chronology.events[0] as unknown as Record<string, unknown>).label = "Cleanverse confirmed the conflict on-chain"; }],
    ["second public chronology", (value) => { (value.protectionCase as unknown as Record<string, unknown>).timeline = []; }],
  ];
  for (const [name, mutate] of mutations) {
    const evidence = mutableEvidence("conflict");
    mutate(evidence);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence)),
      (error: unknown) => error instanceof ProtectionEvidenceError,
      `${name} mutation was accepted`,
    );
  }
});

artifactTest("TypeScript verifies both participant product signatures and the release-authority attestation", () => {
  for (const scenario of ["conflict", "no-conflict"] as const) {
    const evidence = retainedEvidence(scenario);
    assertPublicProtectionEvidence(evidence);
    assert.equal(protectionBindingDigest(evidence.protectionAuthorization.binding), evidence.protectionAuthorization.bindingDigest);
    assert.equal(evidence.recourseAttestation.attestation.protectionBindingDigest, evidence.protectionAuthorization.bindingDigest);
    assert.equal(evidence.recourseAttestation.attestation.governedResultDigest, evidence.governedResult.digest);
  }
});

function replaceJsonPath(root: unknown, path: readonly (string | number)[], value: unknown): void {
  let cursor = root as Record<string | number, unknown>;
  for (const part of path.slice(0, -1)) cursor = cursor[part] as Record<string | number, unknown>;
  cursor[path.at(-1)!] = value;
}

artifactTest("every MordantProtectionBinding field is authenticated", () => {
  const mutations: ReadonlyArray<readonly [string, readonly (string | number)[], unknown]> = [
    ["schemaVersion", ["schemaVersion"], "other/1"],
    ["cleanverseAssetRecordDigest", ["cleanverseAssetRecordDigest"], BAD_DIGEST],
    ["protectionService", ["protectionService"], "Other service"],
    ["protectionServiceVersion", ["protectionServiceVersion"], 2],
    ["policyId", ["policyId"], BAD_DIGEST],
    ["policyVersion", ["policyVersion"], 2],
    ["productScenario", ["productScenario"], "no-conflict"],
    ["fixtureClassification", ["fixtureClassification"], "LIVE"],
    ["protectedAmount.asset", ["protectedAmount", "asset"], "OTHER"],
    ["protectedAmount.minorUnits", ["protectedAmount", "minorUnits"], "1"],
    ["reserveBasisPoints", ["reserveBasisPoints"], 999],
    ["reserveAmount.asset", ["reserveAmount", "asset"], "OTHER"],
    ["reserveAmount.minorUnits", ["reserveAmount", "minorUnits"], "1"],
    ["holderRecordDate", ["holderRecordDate"], "2026-08-03T00:00:00.000Z"],
    ["holderSnapshot.holderId", ["holderSnapshot", 0, "holderId"], "OTHER"],
    ["holderSnapshot.protectedUnits", ["holderSnapshot", 0, "protectedUnits"], "1"],
    ["holderSnapshot.allocationBps", ["holderSnapshot", 0, "allocationBps"], 5999],
    ["holderAllocationDigest", ["holderAllocationDigest"], BAD_DIGEST],
    ["caseNonce", ["caseNonce"], BAD_DIGEST],
    ["fheCaseId", ["fheCaseId"], BAD_DIGEST],
    ["governedReleaseMode", ["governedReleaseMode"], "threshold-2of3-v1"],
  ];
  for (const [field, path, replacement] of mutations) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence.protectionAuthorization.binding, path, replacement);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence)),
      (error: unknown) => error instanceof ProtectionEvidenceError,
      `${field} was not authenticated`,
    );
  }
});

artifactTest("every MordantRecourseAttestation field is authenticated", () => {
  const mutations: ReadonlyArray<readonly [string, readonly (string | number)[], unknown]> = [
    ["schemaVersion", ["schemaVersion"], "other/1"],
    ["protectionBindingDigest", ["protectionBindingDigest"], BAD_DIGEST],
    ["governedResultDigest", ["governedResultDigest"], BAD_DIGEST],
    ["caseId", ["caseId"], BAD_DIGEST],
    ["cleanverseAssetRecordDigest", ["cleanverseAssetRecordDigest"], BAD_DIGEST],
    ["signedBoolean", ["signedBoolean"], false],
    ["recourseRecordDigest", ["recourseRecordDigest"], BAD_DIGEST],
    ["recourseRefusal", ["recourseRefusal"], "SIGNED_RESULT_FALSE"],
    ["holderAllocationDigest", ["holderAllocationDigest"], BAD_DIGEST],
    ["recordDate", ["recordDate"], "2026-08-03T00:00:00.000Z"],
    ["cureDeadline", ["cureDeadline"], null],
    ["finalRecourseState", ["finalRecourseState"], "REFUSED"],
    ["finalIncidentState", ["finalIncidentState"], "CLEARED"],
    ["clockClass", ["clockClass"], "REAL_OBSERVED_CLOCK"],
    ["signedAtUnix", ["signedAtUnix"], 1],
    ["simulationAsOfUnix", ["simulationAsOfUnix"], 1],
    ["chronologyDigest", ["chronologyDigest"], BAD_DIGEST],
    ["originalReceivableState", ["originalReceivableState"], "BURNED"],
    ["reserveAccountingSeparation.reserveDomain", ["reserveAccountingSeparation", "reserveDomain"], "OTHER"],
    ["reserveAccountingSeparation.receivableDomain", ["reserveAccountingSeparation", "receivableDomain"], "OTHER"],
    ["reserveAccountingSeparation.separate", ["reserveAccountingSeparation", "separate"], false],
    ["reserveAccountingSeparation.claimBurnedOrTransferred", ["reserveAccountingSeparation", "claimBurnedOrTransferred"], true],
    ["executionClass", ["executionClass"], "OTHER"],
    ["deploymentClass", ["deploymentClass"], "OTHER"],
    ["releaseClass", ["releaseClass"], "OTHER"],
    ["recourseClass", ["recourseClass"], "OTHER"],
    ["productionIsolationProven", ["productionIsolationProven"], true],
    ["productClaim", ["productClaim"], "other"],
    ["releaseAuthorityId", ["releaseAuthorityId"], BAD_DIGEST],
    ["signature", ["signature"], Buffer.alloc(64, 1).toString("base64")],
  ];
  for (const [field, path, replacement] of mutations) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence.recourseAttestation.attestation, path, replacement);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence)),
      (error: unknown) => error instanceof ProtectionEvidenceError,
      `${field} was not authenticated`,
    );
  }
});

artifactTest("component evidence state never falls back across imported and local transitions", () => {
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
