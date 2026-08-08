import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { test } from "node:test";

import { CANONICAL_CLEANVERSE_ASSET_DIGEST, type Sha256Digest } from "./cleanverse-asset";
import {
  EXPECTED_GOVERNED_FHE_COMMIT,
  releaseAuthorityIdentity,
  type FheCaseBinding,
} from "./protection-evidence";
import { FHE_CIRCUIT, FHE_PARAMETER_PROFILE, GOVERNED_RELEASE_MODE, protectionPolicyId } from "./protection-case";
import {
  EXPECTED_CIRCUIT_DIGEST,
  EXPECTED_PARAMETER_FINGERPRINT,
  N3_STARTING_COMMIT,
  ConflictGraphError,
  ReceivableConflictSession,
  canonicalClaimPair,
  canonicalGraphJson,
  claimGlobalAllClear,
  createGraphClaimAuthorization,
  createGraphPairBinding,
  createGraphPairIntent,
  enumerateCanonicalPairs,
  graphClaimNodeDigest,
  graphDigest,
  participantReference,
  projectConflictGraph,
  verifyGraphClaimAuthorization,
  verifyGraphPrivateClaimRecord,
  verifyGraphPairBinding,
  verifyGraphPairIntent,
  type GraphPins,
  type GraphPrivateClaimRecord,
  type PairRelationRecord,
} from "./receivable-conflict-session";

const ISSUED_AT = 1_800_000_000;
const EXPIRES_AT = ISSUED_AT + 7_200;
const SOURCE_COMMIT = "a".repeat(40);
const SOURCE_TREE = "b".repeat(40);

function digest(label: string): Sha256Digest {
  return graphDigest("MordantN3GraphTest/v1", { label });
}

function pins(): GraphPins {
  return {
    startingCommit: N3_STARTING_COMMIT,
    executionSourceCommit: SOURCE_COMMIT,
    executionSourceTree: SOURCE_TREE,
    governedFheSourceCommit: EXPECTED_GOVERNED_FHE_COMMIT,
    assetIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    policyId: protectionPolicyId(),
    policyVersion: 1,
    serviceId: "mordant.private-pledge-matching",
    serviceVersion: 1,
    circuitId: FHE_CIRCUIT,
    circuitVersion: 5,
    circuitDigest: EXPECTED_CIRCUIT_DIGEST,
    parameterProfile: FHE_PARAMETER_PROFILE,
    parameterFingerprint: EXPECTED_PARAMETER_FINGERPRINT,
    releaseMode: GOVERNED_RELEASE_MODE,
    nativeBinaries: {
      keygen: digest("keygen"),
      client: digest("client"),
      evaluator: digest("evaluator"),
      decryptor: digest("decryptor"),
      inspect: digest("inspect"),
    },
  };
}

function claim(label: string, activeFrom: number, activeUntil: number): GraphPrivateClaimRecord {
  return createGraphClaimAuthorization({
    graphSessionId: digest("session"),
    receivableIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    participantRef: participantReference(),
    activeFrom,
    activeUntil,
    issuedAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
  });
}

function session(): ReceivableConflictSession {
  return new ReceivableConflictSession({
    graphSessionId: digest("session"),
    receivableIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    issuedAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
    pins: pins(),
  });
}

function expectCode(operation: () => unknown, code: string): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof ConflictGraphError);
    assert.equal(error.code, code);
    return true;
  });
}

function syntheticCaseBinding(runLabel: string): FheCaseBinding {
  const authority = generateKeyPairSync("ed25519");
  const authorityPublic = authority.publicKey.export({ format: "der", type: "spki" });
  // Go stores the raw 32-byte Ed25519 public key. SPKI is 12 bytes of prefix
  // followed by that raw key; this synthetic binding is only for graph-binding
  // unit tests, never a claimed governed execution.
  const rawAuthority = Buffer.from(authorityPublic).subarray(-32).toString("base64");
  const participantA = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" });
  const participantB = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" });
  const idA = digest(`${runLabel}/participant-a`);
  const idB = digest(`${runLabel}/participant-b`);
  return {
    schemaVersion: "mordant.fhe-case-binding/1",
    caseId: digest(`${runLabel}/case`),
    assetIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    serviceId: "mordant.private-pledge-matching",
    serviceVersion: 1,
    policyId: protectionPolicyId(),
    policyVersion: 1,
    circuitId: FHE_CIRCUIT,
    circuitVersion: 5,
    circuitDigest: EXPECTED_CIRCUIT_DIGEST,
    parameterProfile: FHE_PARAMETER_PROFILE,
    parameterFingerprint: EXPECTED_PARAMETER_FINGERPRINT,
    publicKeyDigest: digest(`${runLabel}/public-key`),
    evaluationKeyManifestDigest: digest(`${runLabel}/evaluation-keys`),
    participantA: { id: idA, role: "PARTICIPANT_A", signingPublicKey: Buffer.from(participantA).subarray(-32).toString("base64") },
    participantB: { id: idB, role: "PARTICIPANT_B", signingPublicKey: Buffer.from(participantB).subarray(-32).toString("base64") },
    participantOrder: [idA, idB],
    inputSchema: "mordant.encrypted-pledge/governed-fhe-v1",
    resultSchema: "mordant.fixed-conflict-boolean/v1",
    releaseMode: GOVERNED_RELEASE_MODE,
    releaseAuthorityId: releaseAuthorityIdentity(rawAuthority, GOVERNED_RELEASE_MODE),
    releaseAuthorityPublicKey: rawAuthority,
    caseNonce: digest(`${runLabel}/nonce`),
    createdAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
  };
}

test("three incremental claim admissions enumerate exactly three canonical pairs", () => {
  const graph = session();
  const a = claim("a", 100, 400);
  const b = claim("b", 200, 600);
  const c = claim("c", 500, 800);

  assert.deepEqual(graph.admitClaim(a.authorization, new Date(ISSUED_AT * 1_000).toISOString()), []);
  assert.equal(graph.admitClaim(b.authorization, new Date((ISSUED_AT + 1) * 1_000).toISOString()).length, 1);
  expectCode(
    () => graph.admitClaim(c.authorization, new Date((ISSUED_AT + 2) * 1_000).toISOString()),
    "GRAPH_ADMISSION_ORDER",
  );

  const pairs = enumerateCanonicalPairs([a.authorization, b.authorization, c.authorization]);
  assert.equal(pairs.length, 3);
  assert.equal(new Set(pairs.map((pair) => pair.pairId)).size, 3);
  assert.equal(graph.relations().length, 1);
  assert.equal(graph.relations().every((relation) => relation.state === "PENDING"), true);
  assert.equal(graph.aggregate().completeness, "PARTIAL");
});

test("pair canonicalization and graph-node to local-role mapping are deterministic", () => {
  const a = claim("a", 100, 400);
  const b = claim("b", 200, 600);
  const forward = canonicalClaimPair(a.authorization.claimId, b.authorization.claimId);
  const reverse = canonicalClaimPair(b.authorization.claimId, a.authorization.claimId);
  assert.deepEqual(reverse, forward);

  const first = createGraphPairIntent({ first: a, second: b, pairRunId: randomUUID(), createdAtUnix: ISSUED_AT + 10 });
  const second = createGraphPairIntent({ first: b, second: a, pairRunId: randomUUID(), createdAtUnix: ISSUED_AT + 11 });
  assert.deepEqual(first.roleMapping, second.roleMapping);
  assert.equal(first.roleMapping.participantAClaimId, forward.leftClaimId);
  assert.equal(first.roleMapping.participantBClaimId, forward.rightClaimId);
  verifyGraphPairIntent(first, [a.authorization, b.authorization]);
});

test("a stable graph claim is reused across independently frozen pair bindings", () => {
  const a = claim("a", 100, 400);
  const b = claim("b", 200, 600);
  const c = claim("c", 500, 800);
  const abIntent = createGraphPairIntent({ first: a, second: b, pairRunId: randomUUID(), createdAtUnix: ISSUED_AT + 10 });
  const acIntent = createGraphPairIntent({ first: a, second: c, pairRunId: randomUUID(), createdAtUnix: ISSUED_AT + 20 });
  const ab = createGraphPairBinding({
    intent: abIntent,
    claims: [a, b],
    caseBinding: syntheticCaseBinding("ab"),
    boundAtUnix: ISSUED_AT + 11,
    pins: pins(),
  });
  const ac = createGraphPairBinding({
    intent: acIntent,
    claims: [a, c],
    caseBinding: syntheticCaseBinding("ac"),
    boundAtUnix: ISSUED_AT + 21,
    pins: pins(),
  });
  verifyGraphPairBinding(ab, abIntent, [a.authorization, b.authorization], pins());
  verifyGraphPairBinding(ac, acIntent, [a.authorization, c.authorization], pins());

  const abA = ab.roleBindings.find((entry) => entry.claimId === a.authorization.claimId);
  const acA = ac.roleBindings.find((entry) => entry.claimId === a.authorization.claimId);
  assert.equal(abA?.claimNodeDigest, graphClaimNodeDigest(a.authorization));
  assert.equal(acA?.claimNodeDigest, graphClaimNodeDigest(a.authorization));
  const abClaimA = abIntent.claimBindings.find((entry) => entry.claimId === a.authorization.claimId);
  const acClaimA = acIntent.claimBindings.find((entry) => entry.claimId === a.authorization.claimId);
  assert.equal(abClaimA?.claimCommitment, a.authorization.claimCommitment);
  assert.equal(acClaimA?.claimCommitment, a.authorization.claimCommitment);
  assert.notEqual(ab.caseBinding.publicKeyDigest, ac.caseBinding.publicKeyDigest);
  assert.notEqual(ab.caseBinding.releaseAuthorityId, ac.caseBinding.releaseAuthorityId);
});

test("claim commitments are signed, salted, private-opening bound, and tamper evident", () => {
  const a = claim("a", 100, 400);
  verifyGraphPrivateClaimRecord(a);
  verifyGraphClaimAuthorization(a.authorization);
  assert.equal(Buffer.from(a.opening.salt, "base64").length, 32);
  const tampered = structuredClone(a) as unknown as {
    opening: { activeFrom: number };
  };
  tampered.opening.activeFrom = 101;
  expectCode(() => verifyGraphPrivateClaimRecord(tampered as unknown as GraphPrivateClaimRecord), "CLAIM_OPENING");

  const injected = { ...a.authorization, activeFrom: 100 };
  expectCode(() => verifyGraphClaimAuthorization(injected as typeof a.authorization), "CLAIM_FIELDS");
  assert.notEqual(participantReference(), participantReference());
  const cyclic: { self?: unknown } = {};
  cyclic.self = cyclic;
  expectCode(() => canonicalGraphJson(cyclic), "CANONICAL_CYCLE");
});

test("pair binding rejects wrong asset, policy, circuit, and parameter profile pins", () => {
  const a = claim("a", 100, 400);
  const b = claim("b", 200, 600);
  const intent = createGraphPairIntent({ first: a, second: b, pairRunId: randomUUID(), createdAtUnix: ISSUED_AT + 10 });
  const original = syntheticCaseBinding("wrong-pins");
  const wrongBindings = [
    { ...original, assetIdentity: digest("wrong-asset") },
    { ...original, policyId: digest("wrong-policy") },
    { ...original, circuitId: "mordant.wrong-circuit" },
    { ...original, circuitDigest: digest("wrong-circuit-digest") },
    { ...original, parameterProfile: "mordant.wrong-profile/v1" },
    { ...original, parameterFingerprint: digest("wrong-parameter-fingerprint") },
  ] as unknown as readonly FheCaseBinding[];
  for (const caseBinding of wrongBindings) {
    expectCode(() => createGraphPairBinding({
      intent,
      claims: [a, b],
      caseBinding,
      boundAtUnix: ISSUED_AT + 11,
      pins: pins(),
    }), "PAIR_BINDING_PINS");
  }
});

test("public and claimant projections leak no raw interval or unrelated pair", () => {
  const graph = session();
  const a = claim("a", 100, 400);
  const b = claim("b", 200, 600);
  const c = claim("c", 500, 800);
  for (const [index, item] of [a, b].entries()) {
    graph.admitClaim(item.authorization, new Date((ISSUED_AT + index) * 1_000).toISOString());
  }
  const aggregate = graph.aggregate();
  const projections = projectConflictGraph(aggregate);
  const publicText = JSON.stringify(projections.public);
  assert.equal(/activeFrom|activeUntil|salt|claimCommitment|leftClaimId|rightClaimId/u.test(publicText), false);
  assert.equal(Object.values(projections.public).some((value) => value === 100 || value === 400), false);

  const claimantA = projections.claimants.find((projection) => projection.claimId === a.authorization.claimId);
  assert.equal(claimantA?.relations.length, 1);
  const unrelated = canonicalClaimPair(b.authorization.claimId, c.authorization.claimId);
  assert.equal(claimantA?.relations.some((relation) => relation.claimPair.pairId === unrelated.pairId), false);
});

test("a global all-clear is impossible while any expected pair is unresolved", () => {
  const [a, b, c] = [claim("a", 100, 400), claim("b", 200, 600), claim("c", 500, 800)];
  const pairs = enumerateCanonicalPairs([a.authorization, b.authorization, c.authorization]);
  const unresolved = [
    { claimPair: pairs[0], state: "NO_CONFLICT_UNDER_POLICY" as const },
    { claimPair: pairs[1], state: "PENDING" as const },
    { claimPair: pairs[2], state: "NO_CONFLICT_UNDER_POLICY" as const },
  ] satisfies readonly Pick<PairRelationRecord, "claimPair" | "state">[];
  expectCode(() => claimGlobalAllClear("PARTIAL", unresolved), "ALL_CLEAR_INCOMPLETE");
  assert.equal(claimGlobalAllClear("COMPLETE", [
    { claimPair: pairs[0], state: "NO_CONFLICT_UNDER_POLICY" },
    { claimPair: pairs[1], state: "NO_CONFLICT_UNDER_POLICY" },
    { claimPair: pairs[2], state: "NO_CONFLICT_UNDER_POLICY" },
  ]), true);
  assert.equal(claimGlobalAllClear("COMPLETE", [
    { claimPair: pairs[0], state: "NO_CONFLICT_UNDER_POLICY" },
    { claimPair: pairs[1], state: "CONFLICT" },
    { claimPair: pairs[2], state: "NO_CONFLICT_UNDER_POLICY" },
  ]), false);
  expectCode(() => claimGlobalAllClear("COMPLETE", [
    { claimPair: pairs[0], state: "NO_CONFLICT_UNDER_POLICY" },
  ]), "ALL_CLEAR_INCOMPLETE");
});
