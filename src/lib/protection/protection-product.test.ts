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
  resolveProtectionExportSourceCommit,
  verifyGovernedResultSignature,
  type MordantProtectionEvidence,
} from "./protection-evidence";
import { assertRawProtectionEvidenceMetadata } from "./protection-evidence-metadata";
import {
  projectPublicProtectionCase,
  verifyAndProjectPublicProtectionEvidence,
} from "./protection-public-view";
import { evaluateDiskSpace, PRODUCT_STORAGE } from "./governed-fhe-product-server";
import type { ProtectionCaseView } from "./governed-fhe-product-server";
import { protectionMutationGate } from "./protection-api-gate";
import {
  PROTECTION_RECOVERY_TTL_MS,
  parseProtectionBrowserRecovery,
  pendingCreationRecovery,
  pendingMutationRecovery,
  retentionRequiredRecovery,
} from "./protection-browser-recovery";
import {
  PRODUCT_EXECUTION_LABELS,
  evidenceForDisplayedCase,
  parseProtectionEvidencePresentation,
  recoursePresentation,
  recourseStatePresentation,
} from "./protection-presentation";
import { GET } from "../../app/api/protection/conflicting-pledge/route";
import { createProtectionPostHandler } from "./protection-api-route";

const BAD_DIGEST = `sha256:${"ff".repeat(32)}` as Sha256Digest;
const RETAINED_SOURCE_COMMIT = process.env.MORDANT_PROTECTION_SOURCE_COMMIT
  ?? "cf4d9543c18cc5ba9776572a66d0a9cc677d403a";
if (!/^[0-9a-f]{40}$/.test(RETAINED_SOURCE_COMMIT) || /^0{40}$/.test(RETAINED_SOURCE_COMMIT)) {
  throw new Error("Tests require an exact non-zero lowercase product source commit pin");
}

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
  let parsed = false;
  const request = {
    url: "https://mordant.example/api/protection/conflicting-pledge",
    headers: new Headers(),
    json: async () => { parsed = true; throw new Error("body must not be parsed"); },
  } as unknown as Request;
  const post = createProtectionPostHandler({ NODE_ENV: "production" });
  const response = await post(request);
  assert.equal(response.status, 405);
  assert.equal(parsed, false);
});

test("imported evidence API rejects malformed, duplicate and unknown URL authority", async () => {
  for (const query of [
    "scenario=other",
    "scenario=conflict&scenario=no-conflict",
    "scenario=conflict&privateRoot=%2Ftmp%2Fsecret",
    "runId=11111111-1111-4111-8111-111111111111&scenario=conflict",
    "runId=11111111-1111-4111-8111-111111111111&runId=22222222-2222-4222-8222-222222222222",
  ]) {
    const response = await GET(new Request(`http://127.0.0.1/api/protection/conflicting-pledge?${query}`));
    assert.equal(response.status, 400, query);
  }
});

test("every network mutation requires opt-in and the external administrator capability", () => {
  const loopback = new Request("http://127.0.0.1:3000/api/protection/conflicting-pledge", { method: "POST" });
  const missingModeEnvironment = {
    MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "a".repeat(32),
  } as unknown as NodeJS.ProcessEnv;
  assert.equal(protectionMutationGate(loopback, missingModeEnvironment).allowed, false);
  assert.equal(protectionMutationGate(new Request(loopback, {
    headers: { "x-mordant-admin-capability": "a".repeat(32) },
  }), {
    NODE_ENV: "test", MORDANT_LOCAL_EXECUTION_ENABLED: "1", MORDANT_LOCAL_ADMIN_CAPABILITY: "a".repeat(32),
  }).allowed, false);
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

test("A6-F02/F03 browser recovery authority is exact, no-secret and expires within its fixed bound", () => {
  const now = Date.UTC(2026, 7, 3);
  const runId = "11111111-1111-4111-8111-111111111111";
  const values = [
    pendingCreationRecovery("conflict", runId, now),
    pendingMutationRecovery("no-conflict", runId, "evaluatePrivateConflict", now),
    retentionRequiredRecovery("conflict", runId, now),
  ];
  for (const value of values) {
    const serialized = JSON.stringify(value);
    assert.deepEqual(parseProtectionBrowserRecovery(serialized, now), value);
    assert.equal(value.expiresAtUnix - value.createdAtUnix, PROTECTION_RECOVERY_TTL_MS);
    assert.doesNotMatch(serialized, /"(?:capability|credential|secret|privateRoot|path)"\s*:/i);
    assert.equal(parseProtectionBrowserRecovery(serialized, value.expiresAtUnix), null);
    assert.equal(parseProtectionBrowserRecovery(JSON.stringify({ ...value, extra: true }), now), null);
    assert.equal(parseProtectionBrowserRecovery(JSON.stringify({ ...value, scenario: "other" }), now), null);
    assert.equal(parseProtectionBrowserRecovery(JSON.stringify({ ...value, expiresAtUnix: now + 1 }), now), null);
  }
  assert.equal(parseProtectionBrowserRecovery("not-json", now), null);
  assert.equal(parseProtectionBrowserRecovery(JSON.stringify({
    ...pendingMutationRecovery("conflict", runId, "releaseGovernedResult", now),
    operation: "exportPrivateKeys",
  }), now), null);
});

for (const scenario of ["conflict", "no-conflict"] as const) {
  test(`retained real governed-FHE ${scenario} evidence is structurally safe when present`, (context) => {
    const path = join(process.cwd(), "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`);
    try {
      const evidence = JSON.parse(readFileSync(path, "utf8")) as MordantProtectionEvidence;
      assertPublicProtectionEvidence(evidence, RETAINED_SOURCE_COMMIT);
      const presentation = verifyAndProjectPublicProtectionEvidence(evidence, RETAINED_SOURCE_COMMIT);
      assert.equal(evidence.scenario, scenario);
      assert.equal(evidence.cleanverseAssetDigest, CANONICAL_CLEANVERSE_ASSET_DIGEST);
      assert.equal(evidence.fhe.assetIdentity, CANONICAL_CLEANVERSE_ASSET_DIGEST);
      assert.equal(evidence.governedResult.assetIdentity, CANONICAL_CLEANVERSE_ASSET_DIGEST);
      assert.equal(evidence.governedResult.conflict, scenario === "conflict");
      assert.equal(evidence.recourse.opened, scenario === "conflict");
      assert.equal(recoursePresentation(presentation).status, scenario === "conflict" ? "SIMULATED_AVAILABLE" : "REFUSED");
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
  assert.throws(() => assertPublicProtectionEvidence(evidence, RETAINED_SOURCE_COMMIT), (error: unknown) => (
    error instanceof ProtectionEvidenceError && error.code === expectedCode
  ));
}

function addOwnKey(value: object, key: string, entry: unknown): void {
  Object.defineProperty(value, key, { value: entry, enumerable: true, configurable: true, writable: true });
}

function sha256ValuePaths(
  value: unknown,
  path: readonly (string | number)[] = [],
  output: Array<readonly (string | number)[]> = [],
): Array<readonly (string | number)[]> {
  if (typeof value === "string" && value.startsWith("sha256:")) {
    output.push(path);
  } else if (Array.isArray(value)) {
    value.forEach((entry, index) => sha256ValuePaths(entry, [...path, index], output));
  } else if (value !== null && typeof value === "object") {
    Object.entries(value).forEach(([key, entry]) => sha256ValuePaths(entry, [...path, key], output));
  }
  return output;
}

const R1_RECEIVABLE_LITERAL_CASES = [
  ["case principal", ["protectionCase", "originalReceivable", "principalMinorUnits"], "910000001", "110000000"],
  ["case units", ["protectionCase", "originalReceivable", "units"], "910000002", "100000000"],
  ["preservation principal", ["originalReceivablePreservation", "principalMinorUnits"], "910000003", "110000000"],
  ["preservation units", ["originalReceivablePreservation", "units"], "910000004", "100000000"],
] as const;

for (const [field, path, marker] of R1_RECEIVABLE_LITERAL_CASES) {
  artifactTest(`A4-01-R1 ${field} exact literal rejects its unique rehashed marker`, () => {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence, path, marker);
    const rehashed = rehash(evidence);
    let rejected: unknown;
    try {
      verifyAndProjectPublicProtectionEvidence(rehashed, RETAINED_SOURCE_COMMIT);
    } catch (error) {
      rejected = error;
    }
    assert.ok(rejected instanceof ProtectionEvidenceError, `${field} marker reached public projection`);
    assert.equal(JSON.stringify(rejected).includes(marker), false, `${field} marker leaked through the validator error`);
  });
}

artifactTest("A4-01-R1 all four receivable literals reject wrong type and non-canonical variants", () => {
  for (const [field, path, , expected] of R1_RECEIVABLE_LITERAL_CASES) {
    const variants: ReadonlyArray<readonly [string, unknown]> = [
      ["another numeric string", `${Number(expected) + 1}`],
      ["number", Number(expected)],
      ["empty", ""],
      ["leading whitespace", ` ${expected}`],
      ["trailing whitespace", `${expected} `],
      ["leading zero", `0${expected}`],
      ["null", null],
    ];
    for (const [variant, replacement] of variants) {
      const evidence = mutableEvidence("conflict");
      replaceJsonPath(evidence, path, replacement);
      assert.throws(
        () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
        ProtectionEvidenceError,
        `${field} accepted ${variant}`,
      );
    }
    const evidence = mutableEvidence("conflict") as unknown as Record<string, unknown>;
    let parent = evidence;
    for (const part of path.slice(0, -1)) parent = parent[part] as Record<string, unknown>;
    delete parent[path.at(-1)!];
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(
        rehash(evidence as unknown as MordantProtectionEvidence),
        RETAINED_SOURCE_COMMIT,
      ),
      ProtectionEvidenceError,
      `${field} accepted a missing literal`,
    );
  }
});

const A6_BOOLEAN_FIELDS = [
  ["recourse.opened", ["recourse", "opened"], (scenario: "conflict" | "no-conflict") => scenario === "conflict"],
  [
    "originalReceivablePreservation.reserveAccountingSeparate",
    ["originalReceivablePreservation", "reserveAccountingSeparate"],
    () => true,
  ],
  [
    "originalReceivablePreservation.claimBurnedOrTransferredByProtection",
    ["originalReceivablePreservation", "claimBurnedOrTransferredByProtection"],
    () => false,
  ],
  ["governedFheEvidence.publicStructureValidated", ["governedFheEvidence", "publicStructureValidated"], () => true],
  [
    "recourseAttestation.attestation.productionIsolationProven",
    ["recourseAttestation", "attestation", "productionIsolationProven"],
    () => false,
  ],
] as const;

artifactTest("A6-F01 exact scenario-bound Booleans reject every non-Boolean, missing and opposite value", () => {
  for (const scenario of ["conflict", "no-conflict"] as const) {
    for (const [field, path, expectedForScenario] of A6_BOOLEAN_FIELDS) {
      const expected = expectedForScenario(scenario);
      const variants: ReadonlyArray<readonly [string, unknown]> = [
        ["opposite Boolean", !expected],
        ["expected string", String(expected)],
        ["opposite string", String(!expected)],
        ["expected number", Number(expected)],
        ["opposite number", Number(!expected)],
        ["null", null],
      ];
      for (const [variant, replacement] of variants) {
        const evidence = mutableEvidence(scenario);
        replaceJsonPath(evidence, path, replacement);
        assert.throws(
          () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
          ProtectionEvidenceError,
          `${field} accepted ${variant} for ${scenario}`,
        );
      }
      const missing = mutableEvidence(scenario) as unknown as Record<string, unknown>;
      let parent = missing;
      for (const part of path.slice(0, -1)) parent = parent[part] as Record<string, unknown>;
      delete parent[path.at(-1)!];
      assert.throws(
        () => verifyAndProjectPublicProtectionEvidence(
          rehash(missing as unknown as MordantProtectionEvidence),
          RETAINED_SOURCE_COMMIT,
        ),
        ProtectionEvidenceError,
        `${field} accepted a missing value for ${scenario}`,
      );
    }
  }
});

artifactTest("A4-01-R2 every accepted raw schema literal is required at runtime", () => {
  const schemaPaths: ReadonlyArray<readonly [string, readonly (string | number)[]]> = [
    ["protection evidence", ["schemaVersion"]],
    ["protection case", ["protectionCase", "schemaVersion"]],
    ["Cleanverse asset", ["cleanverseAsset", "schemaVersion"]],
    ["case Cleanverse asset", ["protectionCase", "cleanverseAsset", "schemaVersion"]],
    ["protection binding", ["protectionAuthorization", "binding", "schemaVersion"]],
    ["FHE case binding", ["caseAuthorization", "binding", "schemaVersion"]],
    ["governed result", ["governedResult", "schemaVersion"]],
    ["chronology", ["chronology", "schemaVersion"]],
    ["recourse record", ["recourse", "record", "schemaVersion"]],
    ["recourse attestation", ["recourseAttestation", "attestation", "schemaVersion"]],
    ["governed-FHE manifest", ["governedFheEvidence", "schemaVersion"]],
  ];
  for (const [field, path] of schemaPaths) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence, path, `mordant.invalid-${field.replaceAll(" ", "-")}/99`);
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `${field} schema mutation was accepted`,
    );
  }
});

artifactTest("A4-01-R2 evidence references require the exact canonical relative set and order", () => {
  const replacements: ReadonlyArray<readonly [string, unknown]> = [
    ["non-string", 7],
    ["absolute Unix", "/tmp/evidence.json"],
    ["absolute Windows", "C:\\evidence.json"],
    ["parent traversal", "docs/evidence/../secret.json"],
    ["empty segment", "docs//evidence.json"],
    ["backslash", "docs\\evidence\\item.json"],
    ["NUL", "docs/evidence/item.json\0private"],
    ["URL", "https://example.test/evidence.json"],
    ["query", "docs/evidence/item.json?raw=1"],
    ["fragment", "docs/evidence/item.json#private"],
  ];
  for (const [name, replacement] of replacements) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence, ["protectionCase", "evidenceReferences", 0], replacement);
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `${name} evidence reference was accepted`,
    );
  }
  for (const mutation of ["missing", "extra", "reordered"] as const) {
    const evidence = mutableEvidence("conflict");
    if (mutation === "missing") evidence.protectionCase.evidenceReferences.pop();
    else if (mutation === "extra") evidence.protectionCase.evidenceReferences.push("docs/evidence/extra.json");
    else [evidence.protectionCase.evidenceReferences[0], evidence.protectionCase.evidenceReferences[1]] = [
      evidence.protectionCase.evidenceReferences[1], evidence.protectionCase.evidenceReferences[0],
    ];
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `${mutation} evidence-reference set was accepted`,
    );
  }
});

artifactTest("A4-01-R2 digest metadata rejects malformed syntax field by field", () => {
  for (const scenario of ["conflict", "no-conflict"] as const) {
    const pristine = mutableEvidence(scenario);
    const paths = sha256ValuePaths(pristine);
    assert.ok(paths.length > 80, `${scenario} fixture unexpectedly exposes only ${paths.length} digest fields`);
    for (const path of paths) {
      const evidence = mutableEvidence(scenario);
      replaceJsonPath(evidence, path, `sha256:${"A".repeat(64)}`);
      const candidate = path.length === 1 && path[0] === "manifestDigest" ? evidence : rehash(evidence);
      assert.throws(
        () => verifyAndProjectPublicProtectionEvidence(candidate, RETAINED_SOURCE_COMMIT),
        ProtectionEvidenceError,
        `${scenario}:${path.join(".")} accepted a non-canonical digest`,
      );
    }
  }
  for (const replacement of [
    `sha256:${"0".repeat(64)}`,
    `sha256:${"a".repeat(63)}`,
    `sha256:${"a".repeat(65)}`,
    "sha256:not-hex",
    7,
  ]) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence, ["fhe", "circuitDigest"], replacement);
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
    );
  }
});

artifactTest("A4-01-R2 caseManifestDigest is pinned by CaseID or a derived local expectation", () => {
  const evidence = mutableEvidence("conflict");
  evidence.governedFheEvidence.caseManifestDigest = BAD_DIGEST;
  rejectsEvidence(rehash(evidence), "CASE_MANIFEST_DIGEST_CROSS_REFERENCE");

  const unknown = mutableEvidence("conflict");
  unknown.fhe.caseId = BAD_DIGEST;
  assert.throws(
    () => assertRawProtectionEvidenceMetadata(rehash(unknown)),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "CASE_MANIFEST_DIGEST_PIN",
  );

  const dynamicExpected = `sha256:${"1".repeat(64)}` as Sha256Digest;
  const dynamic = mutableEvidence("conflict");
  dynamic.governedFheEvidence.caseManifestDigest = dynamicExpected;
  assert.doesNotThrow(() => assertRawProtectionEvidenceMetadata(rehash(dynamic), dynamicExpected));

  const mismatchedExpected = `sha256:${"2".repeat(64)}` as Sha256Digest;
  assert.throws(
    () => assertRawProtectionEvidenceMetadata(rehash(dynamic), mismatchedExpected),
    (error: unknown) => (
      error instanceof Error && "code" in error && error.code === "CASE_MANIFEST_DIGEST_CROSS_REFERENCE"
    ),
  );
});

artifactTest("A4-01-R2 canonical dates, timestamp semantics and exactRetry types are enforced", () => {
  const conflict = mutableEvidence("conflict");
  const dateMutations: ReadonlyArray<readonly [string, readonly (string | number)[], unknown]> = [
    ["normalized impossible generatedAt", ["generatedAt"], "2026-02-30T14:50:45.846Z"],
    ["generatedAt without milliseconds", ["generatedAt"], "2026-08-03T14:50:45Z"],
    ["holder date offset", ["protectionCase", "holderRecordDate"], "2026-08-03T16:48:49.163+02:00"],
    ["documentation impossible date", ["cleanverseAsset", "documentationTerms", "value", "consultedAtRaw"], "2026-02-30"],
    ["observation offset", ["cleanverseAsset", "aPass", "observedAt"], "2026-07-28T01:23:14.605+02:00"],
    ["issuedAt normalized overflow", ["cleanverseAsset", "issuance", "value", "issuedAtRaw"], "2026-07-32 03:22:22"],
    ["negative Unix", ["governedFheEvidence", "generatedAtUnix"], -1],
    ["fractional Unix", ["chronology", "signedAtUnix"], 1.5],
    [
      "envelope generatedAt before governed generation",
      ["generatedAt"],
      new Date((conflict.governedFheEvidence.generatedAtUnix - 2) * 1_000).toISOString(),
    ],
    [
      "envelope generatedAt after case expiry",
      ["generatedAt"],
      new Date((conflict.caseAuthorization.binding.expiresAtUnix + 1) * 1_000).toISOString(),
    ],
  ];
  for (const [name, path, replacement] of dateMutations) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence, path, replacement);
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `${name} was accepted`,
    );
  }
  for (const replacement of ["false", 0, 1, null, {}, []]) {
    const evidence = mutableEvidence("conflict");
    replaceJsonPath(evidence, ["governedFheEvidence", "measurements", "release", "exactRetry"], replacement);
    assert.throws(
      () => verifyAndProjectPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `exactRetry accepted ${JSON.stringify(replacement)}`,
    );
  }
  const exactRetry = mutableEvidence("conflict");
  exactRetry.governedFheEvidence.measurements.release.exactRetry = true;
  assertPublicProtectionEvidence(rehash(exactRetry), RETAINED_SOURCE_COMMIT);

  const forbiddenTrueRelations: ReadonlyArray<readonly [string, readonly (string | number)[], unknown]> = [
    ["non-terminal release ordinal", ["governedResult", "releaseOrdinal"], 2],
    ["different governed result", ["governedFheEvidence", "governedResultDigest"], BAD_DIGEST],
    ["different result ciphertext", ["governedFheEvidence", "resultCiphertextDigest"], BAD_DIGEST],
    ["unvalidated public structure", ["governedFheEvidence", "publicStructureValidated"], false],
  ];
  for (const [name, path, replacement] of forbiddenTrueRelations) {
    const evidence = mutableEvidence("conflict");
    evidence.governedFheEvidence.measurements.release.exactRetry = true;
    replaceJsonPath(evidence, path, replacement);
    assert.throws(
      () => assertRawProtectionEvidenceMetadata(rehash(evidence)),
      (error: unknown) => (
        error instanceof Error && "code" in error && error.code === "EXACT_RETRY_TERMINAL_RELATION"
      ),
      `exactRetry=true accepted ${name}`,
    );
  }
});

artifactTest("A4 source provenance requires the exact non-zero server/build pin", () => {
  const rejected: ReadonlyArray<readonly [string, string | undefined]> = [
    ["zero", "0".repeat(40)],
    ["other valid SHA", "1".repeat(40)],
    ["missing", undefined],
    ["malformed", "not-a-commit"],
    ["uppercase", RETAINED_SOURCE_COMMIT.toUpperCase()],
  ];
  for (const [name, sourceCommit] of rejected) {
    const evidence = mutableEvidence("conflict") as unknown as Record<string, unknown>;
    if (sourceCommit === undefined) delete evidence.sourceCommit;
    else evidence.sourceCommit = sourceCommit;
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence as unknown as MordantProtectionEvidence), RETAINED_SOURCE_COMMIT),
      (error: unknown) => error instanceof ProtectionEvidenceError && error.code === "SOURCE_COMMIT",
      `${name} source commit was accepted`,
    );
  }
  assert.throws(
    () => assertPublicProtectionEvidence(retainedEvidence("conflict"), "1".repeat(40)),
    (error: unknown) => error instanceof ProtectionEvidenceError && error.code === "SOURCE_COMMIT",
  );
  assert.throws(
    () => assertPublicProtectionEvidence(retainedEvidence("conflict"), undefined),
    (error: unknown) => error instanceof ProtectionEvidenceError && error.code === "SOURCE_COMMIT_PIN",
  );
});

test("A4 export provenance refuses every environment disagreement", () => {
  assert.equal(
    resolveProtectionExportSourceCommit(RETAINED_SOURCE_COMMIT, RETAINED_SOURCE_COMMIT),
    RETAINED_SOURCE_COMMIT,
  );
  for (const environmentValue of [undefined, "", "0".repeat(40), "1".repeat(40), RETAINED_SOURCE_COMMIT.toUpperCase()]) {
    assert.throws(
      () => resolveProtectionExportSourceCommit(RETAINED_SOURCE_COMMIT, environmentValue),
      (error: unknown) => error instanceof ProtectionEvidenceError && error.code === "SOURCE_COMMIT_ENV",
    );
  }
  assert.throws(
    () => resolveProtectionExportSourceCommit(undefined, RETAINED_SOURCE_COMMIT),
    (error: unknown) => error instanceof ProtectionEvidenceError && error.code === "SOURCE_COMMIT_PIN",
  );
});

artifactTest("A4 exact nested schema rejects rehashed private, path, prototype-like and unknown fields", () => {
  const mutations: ReadonlyArray<readonly [string, (value: Mutable<MordantProtectionEvidence>) => void]> = [
    ["plaintext pledge", (value) => { addOwnKey(value.fhe, "plaintextPledge", { receivableId: "PRIVATE" }); }],
    ["underscore plaintext", (value) => { addOwnKey(value.fhe, "plaintext_pledge", "PRIVATE"); }],
    ["case variant", (value) => { addOwnKey(value.fhe, "PlaintextPledge", "PRIVATE"); }],
    ["private root", (value) => { addOwnKey(value.fhe, "private_root", "/tmp/private"); }],
    ["nested FHE key", (value) => { addOwnKey(value.fhe.publicKey, "extra", { secret: true }); }],
    ["measurement root", (value) => { addOwnKey(value.governedFheEvidence.measurements, "extra", {}); }],
    ["measurement release", (value) => { addOwnKey(value.governedFheEvidence.measurements.release, "extra", {}); }],
    ["trusted pin", (value) => { addOwnKey(value.governedFheEvidence.measurements.release.trustedRecoursePins, "extra", BAD_DIGEST); }],
    ["reserve", (value) => { addOwnKey(value.protectionCase.reserve, "localPath", "/tmp/reserve"); }],
    ["holder", (value) => { addOwnKey(value.protectionCase.holderSnapshot[0], "secret", "PRIVATE"); }],
    ["receivable", (value) => { addOwnKey(value.protectionCase.originalReceivable, "privateMetadata", {}); }],
    ["protection envelope", (value) => { addOwnKey(value.protectionAuthorization, "extra", {}); }],
    ["case envelope", (value) => { addOwnKey(value.caseAuthorization, "extra", {}); }],
    ["recourse envelope", (value) => { addOwnKey(value.recourse, "extra", {}); }],
    ["preservation envelope", (value) => { addOwnKey(value.originalReceivablePreservation, "extra", {}); }],
    ["attestation envelope", (value) => { addOwnKey(value.recourseAttestation, "extra", {}); }],
    ["participant identity", (value) => { addOwnKey(value.participantPublicIdentities[0], "extra", {}); }],
    ["prototype-like", (value) => { addOwnKey(value.fhe.publicKey, "__proto__", { polluted: true }); }],
    ["malformed run ID", (value) => { value.runId = "-".repeat(36); }],
  ];
  for (const [name, mutate] of mutations) {
    const evidence = mutableEvidence("conflict");
    mutate(evidence);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `${name} field was accepted after transport rehash`,
    );
  }
});

artifactTest("A4 canonical FHE paths and sizes reject absolute, private, variant and unexpected values", () => {
  const mutations: ReadonlyArray<readonly [string, (value: Mutable<MordantProtectionEvidence>) => void]> = [
    ["absolute public key", (value) => { value.fhe.publicKey.path = "/tmp/public-key.bin"; }],
    ["private key path", (value) => { value.fhe.publicKey.path = "decryptor-private/secret-key.bin"; }],
    ["case variant", (value) => { value.fhe.publicKey.path = "Public-Key.bin"; }],
    ["underscore variant", (value) => { value.fhe.publicKey.path = "public_key.bin"; }],
    ["public key size", (value) => { value.fhe.publicKey.length += 1; }],
    ["result path", (value) => { value.fhe.resultCiphertext.path = "/tmp/result-conflict.bin"; }],
    ["result size", (value) => { value.fhe.resultCiphertext.length -= 1; }],
    ["measurement size", (value) => {
      const keyGeneration = value.governedFheEvidence.measurements.keyGeneration as Record<string, unknown>;
      keyGeneration.publicKeyBytes = Number(keyGeneration.publicKeyBytes) + 1;
    }],
    ["release result size", (value) => {
      const release = value.governedFheEvidence.measurements.release as Record<string, unknown>;
      release.resultBytes = Number(release.resultBytes) + 1;
    }],
    ["public artifact total", (value) => { value.governedFheEvidence.publicArtifactBytes += 1; }],
  ];
  for (const [name, mutate] of mutations) {
    const evidence = mutableEvidence("conflict");
    mutate(evidence);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
      `${name} was accepted`,
    );
  }
});

artifactTest("A4 contradictory public execution classifications are rejected", () => {
  const mutations: ReadonlyArray<(value: Mutable<MordantProtectionEvidence>) => void> = [
    (value) => { value.governedFheEvidence.executionClass = "PLAINTEXT" as "REAL_BGV_FHE"; },
    (value) => { value.governedFheEvidence.deploymentClass = "REMOTE" as "LOCAL_SINGLE_HOST"; },
    (value) => { value.governedFheEvidence.releaseClass = "GENERIC" as "GOVERNED_DECRYPTOR"; },
    (value) => { value.governedFheEvidence.recourseClass = "LIVE" as "LOCAL_PROTOCOL_DOUBLE"; },
    (value) => { value.governedFheEvidence.productionIsolationProven = true as false; },
    (value) => { value.protectionCase.reserve.executionClassification = "LIVE" as "PROTOCOL_DOUBLE"; },
    (value) => { value.recourse.classification = "LIVE" as "PROTOCOL_DOUBLE"; },
  ];
  for (const mutate of mutations) {
    const evidence = mutableEvidence("conflict");
    mutate(evidence);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      ProtectionEvidenceError,
    );
  }
});

artifactTest("A4 malformed nested values fail as ProtectionEvidenceError rather than TypeError", () => {
  const mutations: ReadonlyArray<(value: Mutable<MordantProtectionEvidence>) => void> = [
    (value) => { value.fhe.publicKey = null as unknown as typeof value.fhe.publicKey; },
    (value) => { value.governedFheEvidence.measurements = [] as unknown as typeof value.governedFheEvidence.measurements; },
    (value) => { value.recourseAttestation.attestation = null as unknown as typeof value.recourseAttestation.attestation; },
    (value) => { value.protectionCase.holderSnapshot = {} as unknown as typeof value.protectionCase.holderSnapshot; },
  ];
  for (const mutate of mutations) {
    const evidence = mutableEvidence("conflict");
    mutate(evidence);
    assert.throws(
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      (error: unknown) => error instanceof ProtectionEvidenceError && !(error instanceof TypeError),
    );
  }
  for (const malformed of [null, [], "evidence", 1]) {
    assert.throws(
      () => assertPublicProtectionEvidence(malformed, RETAINED_SOURCE_COMMIT),
      (error: unknown) => error instanceof ProtectionEvidenceError && !(error instanceof TypeError),
    );
  }
});

artifactTest("A4 verified projection is allowlisted, detached and strips raw FHE metadata", () => {
  const evidence = mutableEvidence("conflict");
  const originalManifest = evidence.manifestDigest;
  const projected = verifyAndProjectPublicProtectionEvidence(evidence, RETAINED_SOURCE_COMMIT);
  assert.notEqual(projected, evidence);
  assert.notEqual(projected.protectionCase, evidence.protectionCase);
  assert.notEqual(projected.chronology.events, evidence.chronology.events);
  assert.equal(projected.recourseAttestation.attestation.chronologyDigest, evidence.recourseAttestation.attestation.chronologyDigest);
  const serialized = JSON.stringify(projected);
  for (const forbidden of [
    "public-key.bin", "result-conflict.bin", "measurements", "governedFheEvidence", "evidenceReferences",
    "privateArtifactBytes", "publicKeyBytes", "resultCiphertextBytes", "\"length\"", "\"path\"",
  ]) assert.equal(serialized.includes(forbidden), false, `${forbidden} survived projection`);

  evidence.manifestDigest = BAD_DIGEST;
  evidence.chronology.events[0].kind = "SENTINEL_MUTATION";
  addOwnKey(evidence.fhe, "sentinelPrivateRoot", "/tmp/sentinel");
  assert.equal(projected.manifestDigest, originalManifest);
  assert.equal(JSON.stringify(projected).includes("SENTINEL"), false);
  assert.equal(Object.isFrozen(projected), true);
  assert.equal(Object.isFrozen(projected.chronology.events), true);
});

artifactTest("A4 case projection strips sentinel fields and shares no caller references", () => {
  const source = structuredClone(retainedEvidence("conflict").protectionCase) as unknown as Record<string, unknown>;
  addOwnKey(source, "privateRoot", "/tmp/SENTINEL_PRIVATE_ROOT");
  addOwnKey(source.reserve as object, "secretPath", "/tmp/SENTINEL_SECRET_PATH");
  const projected = projectPublicProtectionCase(source as unknown as MordantProtectionEvidence["protectionCase"]);
  (source.reserve as Record<string, unknown>).minorUnits = "SENTINEL_MUTATION";
  const serialized = JSON.stringify(projected);
  assert.equal(serialized.includes("SENTINEL"), false);
  assert.equal(projected.reserve.minorUnits, "10000000");
  assert.notEqual(projected.reserve, source.reserve);
});

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
  conflict.governedFheEvidence.publicArtifactBytes = 391_684_354;
  (conflict.governedFheEvidence.measurements.release as Record<string, unknown>).resultBytes = 1_750;
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
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
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
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      (error: unknown) => error instanceof ProtectionEvidenceError,
      `${name} mutation was accepted`,
    );
  }
});

artifactTest("TypeScript verifies both participant product signatures and the release-authority attestation", () => {
  for (const scenario of ["conflict", "no-conflict"] as const) {
    const evidence = retainedEvidence(scenario);
    assertPublicProtectionEvidence(evidence, RETAINED_SOURCE_COMMIT);
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
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
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
      () => assertPublicProtectionEvidence(rehash(evidence), RETAINED_SOURCE_COMMIT),
      (error: unknown) => error instanceof ProtectionEvidenceError,
      `${field} was not authenticated`,
    );
  }
});

artifactTest("component evidence state never falls back across imported and local transitions", () => {
  const imported = verifyAndProjectPublicProtectionEvidence(retainedEvidence("conflict"), RETAINED_SOURCE_COMMIT);
  const incomplete = {
    runId: "11111111-1111-4111-8111-111111111111",
    protectionCase: { ...imported.protectionCase, recourseState: "NOT_OPEN" },
    evidence: null,
  } as unknown as ProtectionCaseView;
  const cureWindow = {
    ...incomplete,
    protectionCase: { ...incomplete.protectionCase, recourseState: "CURE_WINDOW" },
  } as unknown as ProtectionCaseView;
  const complete = {
    ...incomplete,
    runId: imported.runId,
    protectionCase: { ...imported.protectionCase, recourseState: "SIMULATED_AVAILABLE" },
    evidence: imported,
  } as unknown as ProtectionCaseView;
  assert.equal(evidenceForDisplayedCase("imported", imported, null), imported);
  assert.equal(evidenceForDisplayedCase("local", imported, incomplete), null);
  assert.equal(evidenceForDisplayedCase("local", imported, cureWindow), null);
  assert.equal(recourseStatePresentation(cureWindow.protectionCase.recourseState).status, "CURE_WINDOW");
  assert.equal(evidenceForDisplayedCase("local", imported, complete), imported);
});

artifactTest("client presentation parser detaches the exact verified allowlist and rejects extra fields", () => {
  const projected = verifyAndProjectPublicProtectionEvidence(retainedEvidence("conflict"), RETAINED_SOURCE_COMMIT);
  const parsed = parseProtectionEvidencePresentation(projected);
  assert.deepEqual(parsed, projected);
  assert.notEqual(parsed, projected);

  const topLevel = structuredClone(projected) as unknown as Record<string, unknown>;
  topLevel.privatePlaintext = "must-not-enter-react-state";
  assert.equal(parseProtectionEvidencePresentation(topLevel), null);

  const nested = structuredClone(projected) as unknown as { fhe: Record<string, unknown> };
  nested.fhe.privateArtifactPath = "/private/plaintext";
  assert.equal(parseProtectionEvidencePresentation(nested), null);
});
