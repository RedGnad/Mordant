import assert from "node:assert/strict";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
  type KeyObject,
} from "node:crypto";
import { test } from "node:test";

import { CANONICAL_CLEANVERSE_ASSET_DIGEST, type Sha256Digest } from "./cleanverse-asset";
import {
  EXPECTED_GOVERNED_FHE_COMMIT,
  governedResultDigest,
  releaseAuthorityIdentity,
  type FheCaseBinding,
  type GovernedSignedResult,
} from "./protection-evidence";
import {
  FHE_CIRCUIT,
  FHE_PARAMETER_PROFILE,
  GOVERNED_RELEASE_MODE,
  protectionPolicyId,
} from "./protection-case";
import {
  EXPECTED_CIRCUIT_DIGEST,
  EXPECTED_PARAMETER_FINGERPRINT,
  N3_STARTING_COMMIT,
  REQUIRED_PAIR_OPERATIONS,
  ConflictGraphError,
  ReceivableConflictSession,
  claimGlobalAllClear,
  createGraphClaimAuthorization,
  createPairPublicInspection,
  fheCaseBindingDigest,
  graphDigest,
  publicInspectionReportDigest,
  projectClaimantGraph,
  verifyAggregateManifest,
  verifyConflictGraphProjections,
  verifyGraphPairEvidenceLeaf,
  type CanonicalClaimPair,
  type GraphPairBindingRecord,
  type GraphPairEvidenceLeaf,
  type GraphPairIntent,
  type GraphPins,
  type GraphPrivateClaimRecord,
  type PairPublicInspection,
} from "./receivable-conflict-session";
import {
  RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES,
  runReceivableConflictSession,
  type ReceivableConflictPairInspector,
  type ReceivableConflictPairJsonReader,
  type ReceivableConflictPairOrchestrator,
  type ReceivableConflictSessionPersistence,
} from "./receivable-conflict-session-runner";

const ISSUED_AT = 1_900_000_000;
const EXPIRES_AT = ISSUED_AT + 7_200;
const RUN_IDS = Object.freeze([
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003",
] as const);

type ClaimLabel = "A" | "B" | "C";
type PairLabel = "AB" | "AC" | "BC";
type FakeStage =
  | "ALLOCATED"
  | "CASE_CREATED"
  | "MATCH_PREPARED"
  | "PARTICIPANT_A_SUBMITTED"
  | "PARTICIPANT_B_SUBMITTED"
  | "EVALUATED"
  | "RELEASED";

type FakeRun = {
  pair: CanonicalClaimPair;
  label: PairLabel;
  ordinal: number;
  stage: FakeStage;
  binding?: FheCaseBinding;
  governedResult?: GovernedSignedResult;
};

function digest(label: string): Sha256Digest {
  return graphDigest("MordantN3RunnerTest/v1", { label });
}

function graphPins(): GraphPins {
  return {
    startingCommit: N3_STARTING_COMMIT,
    executionSourceCommit: "a".repeat(40),
    executionSourceTree: "b".repeat(40),
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
      keygen: digest("binary/keygen"),
      client: digest("binary/client"),
      evaluator: digest("binary/evaluator"),
      decryptor: digest("binary/decryptor"),
      inspect: digest("binary/inspect"),
    },
  };
}

function claim(
  graphSessionId: Sha256Digest,
  label: ClaimLabel,
  activeFrom: number,
  activeUntil: number,
): GraphPrivateClaimRecord {
  return createGraphClaimAuthorization({
    graphSessionId,
    receivableIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    participantRef: digest(`claimant/${label}`),
    activeFrom,
    activeUntil,
    issuedAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
  });
}

function deterministicPrivateKey(label: string): KeyObject {
  const seed = createHash("sha256").update(`MordantN3RunnerEd25519/v1\0${label}`).digest();
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function rawPublicKey(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return Buffer.from(required(jwk.x, "Ed25519 JWK x coordinate"), "base64url").toString("base64");
}

function caseBinding(runId: string, ordinal: number, pins: GraphPins): FheCaseBinding {
  const authorityPublicKey = rawPublicKey(deterministicPrivateKey(`${runId}/release-authority`));
  const participantAPublicKey = rawPublicKey(deterministicPrivateKey(`${runId}/participant-a`));
  const participantBPublicKey = rawPublicKey(deterministicPrivateKey(`${runId}/participant-b`));
  const participantAId = digest(`${runId}/participant-a-id`);
  const participantBId = digest(`${runId}/participant-b-id`);
  return {
    schemaVersion: "mordant.fhe-case-binding/1",
    caseId: digest(`${runId}/case`),
    assetIdentity: pins.assetIdentity,
    serviceId: pins.serviceId,
    serviceVersion: pins.serviceVersion,
    policyId: pins.policyId,
    policyVersion: pins.policyVersion,
    circuitId: pins.circuitId,
    circuitVersion: pins.circuitVersion,
    circuitDigest: pins.circuitDigest,
    parameterProfile: pins.parameterProfile,
    parameterFingerprint: pins.parameterFingerprint,
    publicKeyDigest: digest(`${runId}/public-key`),
    evaluationKeyManifestDigest: digest(`${runId}/evaluation-key-manifest`),
    participantA: {
      id: participantAId,
      role: "PARTICIPANT_A",
      signingPublicKey: participantAPublicKey,
    },
    participantB: {
      id: participantBId,
      role: "PARTICIPANT_B",
      signingPublicKey: participantBPublicKey,
    },
    participantOrder: [participantAId, participantBId],
    inputSchema: "mordant.encrypted-pledge/governed-fhe-v1",
    resultSchema: "mordant.fixed-conflict-boolean/v1",
    releaseMode: pins.releaseMode,
    releaseAuthorityId: releaseAuthorityIdentity(authorityPublicKey, pins.releaseMode),
    releaseAuthorityPublicKey: authorityPublicKey,
    caseNonce: digest(`${runId}/case-nonce`),
    createdAtUnix: ISSUED_AT + ordinal,
    expiresAtUnix: EXPIRES_AT,
  };
}

function governedSigningValue(result: Omit<GovernedSignedResult, "signature">): object {
  return {
    schemaVersion: result.schemaVersion,
    caseId: result.caseId,
    caseBindingDigest: result.caseBindingDigest,
    assetIdentity: result.assetIdentity,
    serviceId: result.serviceId,
    serviceVersion: result.serviceVersion,
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    circuitId: result.circuitId,
    circuitVersion: result.circuitVersion,
    circuitDigest: result.circuitDigest,
    parameterProfile: result.parameterProfile,
    parameterFingerprint: result.parameterFingerprint,
    participantArtifactDigests: [...result.participantArtifactDigests],
    evaluatedArtifactDigest: result.evaluatedArtifactDigest,
    resultCiphertextDigest: result.resultCiphertextDigest,
    resultCiphertextCommitment: result.resultCiphertextCommitment,
    conflict: result.conflict,
    releaseOrdinal: result.releaseOrdinal,
    releaseMode: result.releaseMode,
    releaseAuthorityId: result.releaseAuthorityId,
    releaseAuthorityPublicKey: result.releaseAuthorityPublicKey,
    releasedAtUnix: result.releasedAtUnix,
    sourceProvenance: result.sourceProvenance,
    signature: null,
  };
}

function signedGovernedResult(
  runId: string,
  ordinal: number,
  binding: FheCaseBinding,
  pins: GraphPins,
  conflict: boolean,
): GovernedSignedResult {
  const unsigned: Omit<GovernedSignedResult, "signature"> = {
    schemaVersion: "mordant.governed-conflict-result/1",
    caseId: binding.caseId,
    caseBindingDigest: fheCaseBindingDigest(binding),
    assetIdentity: pins.assetIdentity,
    serviceId: pins.serviceId,
    serviceVersion: pins.serviceVersion,
    policyId: pins.policyId,
    policyVersion: pins.policyVersion,
    circuitId: pins.circuitId,
    circuitVersion: pins.circuitVersion,
    circuitDigest: pins.circuitDigest,
    parameterProfile: pins.parameterProfile,
    parameterFingerprint: pins.parameterFingerprint,
    participantArtifactDigests: [
      digest(`${runId}/participant-a-artifact`),
      digest(`${runId}/participant-b-artifact`),
    ],
    evaluatedArtifactDigest: digest(`${runId}/evaluated-artifact`),
    resultCiphertextDigest: digest(`${runId}/result-ciphertext`),
    resultCiphertextCommitment: digest(`${runId}/result-ciphertext-commitment`),
    conflict,
    releaseOrdinal: 1,
    releaseMode: pins.releaseMode,
    releaseAuthorityId: binding.releaseAuthorityId,
    releaseAuthorityPublicKey: binding.releaseAuthorityPublicKey,
    releasedAtUnix: ISSUED_AT + 100 + ordinal,
    sourceProvenance: pins.nativeBinaries.decryptor,
  };
  const message = Buffer.concat([
    Buffer.from("MordantGovernedConflictResult/v1"),
    Buffer.of(0),
    Buffer.from(JSON.stringify(governedSigningValue(unsigned))),
  ]);
  const signature = signEd25519(
    null,
    message,
    deterministicPrivateKey(`${runId}/release-authority`),
  ).toString("base64");
  return { ...unsigned, signature };
}

function pairLabel(
  pair: CanonicalClaimPair,
  labelsByClaimId: ReadonlyMap<Sha256Digest, ClaimLabel>,
): PairLabel {
  const left = required(labelsByClaimId.get(pair.leftClaimId), "left claim label");
  const right = required(labelsByClaimId.get(pair.rightClaimId), "right claim label");
  const label = [left, right].sort().join("");
  assert.ok(label === "AB" || label === "AC" || label === "BC");
  return label;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function required<T>(value: T | undefined, label: string): T {
  if (value === undefined) throw new Error(`Missing ${label}`);
  return value;
}

test("the N=3 runner freezes and executes AB, then AC, then BC through RELEASED", async () => {
  const graphSessionId = digest("graph-session");
  const pins = graphPins();
  const claims = [
    claim(graphSessionId, "A", 100, 400),
    claim(graphSessionId, "B", 200, 600),
    claim(graphSessionId, "C", 500, 800),
  ] as const;
  const labelsByClaimId = new Map<Sha256Digest, ClaimLabel>(claims.map((record, index) => [
    record.authorization.claimId,
    (["A", "B", "C"] as const)[index],
  ]));
  const claimsById = new Map(claims.map((record) => [record.authorization.claimId, record]));
  const runs = new Map<string, FakeRun>();
  const persistedIntents = new Set<string>();
  const persistedBindings = new Set<string>();
  const retainedPrivateRecords: unknown[] = [];
  const persistedBytes = new Map<string, string>();
  const log: string[] = [];
  let activePairs = 0;
  let fakeMaxConcurrentPairs = 0;

  const createOnly = (key: string, value: unknown): void => {
    const encoded = JSON.stringify(value);
    const existing = persistedBytes.get(key);
    if (existing === undefined) persistedBytes.set(key, encoded);
    else assert.equal(existing, encoded, `create-only retry changed ${key}`);
  };
  const labelForClaimId = (claimId: string): ClaimLabel => {
    return required(labelsByClaimId.get(claimId as Sha256Digest), "claim label");
  };
  const requireRun = (runId: string): FakeRun => {
    return required(runs.get(runId), "fake pair run");
  };
  const view = (runId: string, stage: FakeStage) => Object.freeze({ runId, stage });

  const persist: ReceivableConflictSessionPersistence = Object.freeze({
    writePublicClaimAuthorization: (sessionId, claimId, value) => {
      const label = labelForClaimId(claimId);
      createOnly(`${sessionId}/public-claim/${claimId}`, value);
      log.push(`public:${label}`);
    },
    writePrivateClaimRecord: (sessionId, claimId, value) => {
      const label = labelForClaimId(claimId);
      assert.ok(isRecord(value));
      assert.equal(Object.hasOwn(value, "authorizationPrivateKey"), false);
      assert.deepEqual(Object.keys(value).sort(), ["authorization", "opening", "retention", "schemaVersion"].sort());
      createOnly(`${sessionId}/private-claim/${claimId}`, value);
      retainedPrivateRecords.push(value);
      log.push(`private:${label}`);
    },
    writePairIntent: (sessionId, pairId, value) => {
      const intent = value as GraphPairIntent;
      const label = pairLabel(intent.claimPair, labelsByClaimId);
      assert.equal(intent.claimPair.pairId, pairId);
      createOnly(`${sessionId}/intent/${pairId}`, value);
      persistedIntents.add(pairId);
      log.push(`intent:${label}`);
    },
    writePairBinding: (sessionId, pairId, value) => {
      const binding = value as GraphPairBindingRecord;
      const label = pairLabel(binding.claimPair, labelsByClaimId);
      assert.equal(binding.claimPair.pairId, pairId);
      createOnly(`${sessionId}/binding/${pairId}`, value);
      persistedBindings.add(pairId);
      log.push(`binding:${label}`);
    },
    writeEvidenceLeaf: (sessionId, pairId, value) => {
      const leaf = value as GraphPairEvidenceLeaf;
      const label = pairLabel(leaf.claimPair, labelsByClaimId);
      assert.equal(leaf.claimPair.pairId, pairId);
      createOnly(`${sessionId}/leaf/${pairId}`, value);
      log.push(`leaf:${label}`);
    },
    writeAggregate: (sessionId, value) => createOnly(`${sessionId}/aggregate`, value),
    writeProjection: (sessionId, projectionId, value) => createOnly(
      `${sessionId}/projection/${projectionId}`,
      value,
    ),
    writeChronology: (sessionId, value) => createOnly(`${sessionId}/chronology`, value),
    writeRetentionDeclaration: (sessionId) => createOnly(`${sessionId}/retention`, { sessionId }),
  });

  const orchestrator: ReceivableConflictPairOrchestrator = Object.freeze({
    createProtectionCase: (scenario, runId, windows) => {
      const run = requireRun(runId);
      assert.equal(scenario, "conflict");
      assert.equal(run.stage, "ALLOCATED");
      assert.ok(persistedIntents.has(run.pair.pairId), "pair intent must be persisted before engine create");
      const participantA = required(claimsById.get(run.pair.leftClaimId), "participant A claim");
      const participantB = required(claimsById.get(run.pair.rightClaimId), "participant B claim");
      assert.deepEqual(windows, {
        participantA: {
          activeFrom: participantA.opening.activeFrom,
          activeUntil: participantA.opening.activeUntil,
        },
        participantB: {
          activeFrom: participantB.opening.activeFrom,
          activeUntil: participantB.opening.activeUntil,
        },
      });
      activePairs += 1;
      fakeMaxConcurrentPairs = Math.max(fakeMaxConcurrentPairs, activePairs);
      run.stage = "CASE_CREATED";
      log.push(`create:${run.label}`);
      return view(runId, run.stage);
    },
    preparePrivateMatch: (runId) => {
      const run = requireRun(runId);
      assert.equal(run.stage, "CASE_CREATED");
      run.binding = caseBinding(runId, run.ordinal, pins);
      run.stage = "MATCH_PREPARED";
      log.push(`prepare:${run.label}`);
      return view(runId, run.stage);
    },
    submitParticipantPledge: (runId, role, expectedAssetDigest) => {
      const run = requireRun(runId);
      assert.equal(expectedAssetDigest, pins.assetIdentity);
      if (role === "PARTICIPANT_A") {
        assert.equal(run.stage, "MATCH_PREPARED");
        assert.ok(persistedBindings.has(run.pair.pairId), "pair binding must be persisted before submit A");
        run.stage = "PARTICIPANT_A_SUBMITTED";
        log.push(`submit-a:${run.label}`);
      } else {
        assert.equal(run.stage, "PARTICIPANT_A_SUBMITTED");
        run.stage = "PARTICIPANT_B_SUBMITTED";
        log.push(`submit-b:${run.label}`);
      }
      return view(runId, run.stage);
    },
    evaluatePrivateConflict: (runId) => {
      const run = requireRun(runId);
      assert.equal(run.stage, "PARTICIPANT_B_SUBMITTED");
      run.stage = "EVALUATED";
      log.push(`evaluate:${run.label}`);
      return view(runId, run.stage);
    },
    releaseGovernedResult: (runId) => {
      const run = requireRun(runId);
      assert.equal(run.stage, "EVALUATED");
      const binding = required(run.binding, "case binding");
      const left = required(claimsById.get(run.pair.leftClaimId), "left private claim");
      const right = required(claimsById.get(run.pair.rightClaimId), "right private claim");
      const conflict = left.opening.activeFrom < right.opening.activeUntil
        && right.opening.activeFrom < left.opening.activeUntil;
      run.governedResult = signedGovernedResult(runId, run.ordinal, binding, pins, conflict);
      run.stage = "RELEASED";
      activePairs -= 1;
      log.push(`release:${run.label}`);
      return view(runId, run.stage);
    },
  });

  const readJson: ReceivableConflictPairJsonReader = <T>(runId: string, fileName: string): T => {
    const run = requireRun(runId);
    if (fileName === RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES.caseBinding) {
      assert.notEqual(run.binding, undefined);
      log.push(`read-binding:${run.label}`);
      return structuredClone(run.binding) as unknown as T;
    }
    if (fileName === RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES.evaluatedConflict) {
      assert.equal(run.stage, "RELEASED");
      log.push(`read-evaluated:${run.label}`);
      return { evaluatorProvenance: pins.nativeBinaries.evaluator } as T;
    }
    assert.equal(fileName, RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES.governedResult);
    assert.notEqual(run.governedResult, undefined);
    log.push(`read-result:${run.label}`);
    return structuredClone(run.governedResult) as unknown as T;
  };

  const inspect: ReceivableConflictPairInspector = (runId: string): PairPublicInspection => {
    const run = requireRun(runId);
    assert.equal(run.stage, "RELEASED");
    const result = required(run.governedResult, "governed result");
    log.push(`inspect:${run.label}`);
    return createPairPublicInspection({
      finalized: true,
      evaluationAdmission: true,
      releaseVerified: true,
      ambiguous: false,
      recoursePresent: false,
      publicEvidencePresent: false,
      resultDigest: governedResultDigest(result),
      conflict: result.conflict,
      releaseMode: result.releaseMode,
      participantArtifactDigests: result.participantArtifactDigests,
      evaluatedArtifactDigest: result.evaluatedArtifactDigest,
      inspectBinaryDigest: pins.nativeBinaries.inspect,
      inspectionReportDigest: publicInspectionReportDigest({ runId, stage: run.stage }),
    });
  };

  let clockTick = 0;
  const result = await runReceivableConflictSession({
    graphSessionId,
    receivableIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    issuedAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
    pins,
    claims,
    orchestrator,
    readJson,
    inspect,
    persist,
    now: () => new Date((ISSUED_AT + clockTick++) * 1_000),
    newPairRunId: (pair, executionOrdinal) => {
      const label = pairLabel(pair, labelsByClaimId);
      const runId = RUN_IDS[executionOrdinal - 1];
      assert.notEqual(runId, undefined);
      runs.set(runId, { pair, label, ordinal: executionOrdinal, stage: "ALLOCATED" });
      log.push(`pair-run:${label}`);
      return runId;
    },
  });

  const pairLifecycle = log.filter((entry) => /^(?:pair-run|intent|create|prepare|read-binding|binding|submit-a|submit-b|evaluate|release|inspect|read-evaluated|read-result|leaf):/u.test(entry));
  const expectedPairLifecycle = (["AB", "AC", "BC"] as const).flatMap((label) => [
    `pair-run:${label}`,
    `intent:${label}`,
    `create:${label}`,
    `prepare:${label}`,
    `read-binding:${label}`,
    `binding:${label}`,
    `submit-a:${label}`,
    `submit-b:${label}`,
    `evaluate:${label}`,
    `release:${label}`,
    `inspect:${label}`,
    `read-evaluated:${label}`,
    `read-result:${label}`,
    `leaf:${label}`,
  ]);
  assert.deepEqual(pairLifecycle, expectedPairLifecycle);
  assert.deepEqual(
    log.filter((entry) => /^(?:private|leaf):/u.test(entry)),
    ["private:A", "private:B", "leaf:AB", "private:C", "leaf:AC", "leaf:BC"],
  );

  assert.equal(result.intents.length, 3);
  assert.equal(result.bindings.length, 3);
  assert.equal(result.leaves.length, 3);
  assert.deepEqual(result.leaves.map((leaf) => pairLabel(leaf.claimPair, labelsByClaimId)), ["AB", "AC", "BC"]);
  assert.deepEqual(result.leaves.map((leaf) => leaf.state), [
    "CONFLICT",
    "NO_CONFLICT_UNDER_POLICY",
    "CONFLICT",
  ]);
  for (const leaf of result.leaves) {
    assert.equal(leaf.execution.terminalStage, "RELEASED");
    assert.deepEqual(leaf.execution.operations, REQUIRED_PAIR_OPERATIONS);
  }
  assert.deepEqual(
    result.chronology.events.filter((event) => event.kind === "PAIR_COMPLETED")
      .map((event) => pairLabel(
        result.leaves.find((leaf) => leaf.claimPair.pairId === event.pairId)?.claimPair
          ?? assert.fail("completed pair leaf missing"),
        labelsByClaimId,
      )),
    ["AB", "AC", "BC"],
  );
  assert.equal(result.aggregate.completeness, "COMPLETE");
  assert.equal(result.aggregate.reviewState, "REVIEW_READY");
  assert.equal(result.aggregate.globalAllClear, false);
  assert.equal(result.maxConcurrentPairsObserved, 1);
  assert.equal(result.aggregate.execution.maxConcurrentPairsObserved, 1);
  assert.equal(fakeMaxConcurrentPairs, 1);
  assert.equal(activePairs, 0);
  assert.equal(retainedPrivateRecords.length, 3);
  assert.equal(retainedPrivateRecords.every((record) => isRecord(record)
    && !Object.hasOwn(record, "authorizationPrivateKey")), true);
  verifyAggregateManifest(result.aggregate, result.chronology, result.leaves);
  verifyConflictGraphProjections(result.aggregate, result.projections);

  const replay = new ReceivableConflictSession({
    graphSessionId,
    receivableIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    issuedAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
    pins,
  });
  replay.admitClaim(claims[0].authorization, new Date(ISSUED_AT * 1_000).toISOString());
  replay.admitClaim(claims[1].authorization, new Date((ISSUED_AT + 1) * 1_000).toISOString());
  replay.ingestPairEvidence(result.leaves[0], result.bindings[0], result.intents[0], result.leaves[0].execution.completedAt);
  replay.admitClaim(claims[2].authorization, new Date((ISSUED_AT + 5) * 1_000).toISOString());
  replay.sealAdmissions(new Date((ISSUED_AT + 5) * 1_000).toISOString());

  const missingAc = replay.aggregate();
  assert.equal(missingAc.completeness, "PARTIAL");
  assert.equal(missingAc.reviewState, "AWAITING_EVIDENCE");
  assert.equal(missingAc.pairRelations.find((relation) => (
    pairLabel(relation.claimPair, labelsByClaimId) === "AC"
  ))?.state, "PENDING");
  assert.throws(() => claimGlobalAllClear(missingAc.completeness, missingAc.pairRelations), ConflictGraphError);

  const corruptAc = structuredClone(result.leaves[1]) as unknown as {
    governedResult: { signature: string };
  };
  corruptAc.governedResult.signature = `${corruptAc.governedResult.signature.slice(0, -2)}AA`;
  assert.throws(
    () => replay.ingestPairEvidence(
      corruptAc as unknown as GraphPairEvidenceLeaf,
      result.bindings[1],
      result.intents[1],
      result.leaves[1].execution.completedAt,
    ),
    ConflictGraphError,
  );
  replay.ingestPairEvidence(result.leaves[2], result.bindings[2], result.intents[2], result.leaves[2].execution.completedAt);
  const isolated = replay.aggregate();
  assert.equal(isolated.completeness, "PARTIAL");
  assert.deepEqual(isolated.pairRelations.map((relation) => relation.state).sort(), ["CONFLICT", "CONFLICT", "FAILED"].sort());
  assert.throws(() => claimGlobalAllClear(isolated.completeness, isolated.pairRelations), ConflictGraphError);
  verifyGraphPairEvidenceLeaf(result.leaves[0], result.bindings[0], result.intents[0], result.aggregate.nodes, pins);
  verifyGraphPairEvidenceLeaf(result.leaves[2], result.bindings[2], result.intents[2], result.aggregate.nodes, pins);

  const foreignLeaf = { ...result.leaves[0], graphSessionId: digest("foreign-session") };
  assert.throws(
    () => replay.ingestPairEvidence(foreignLeaf, result.bindings[0], result.intents[0], foreignLeaf.execution.completedAt),
    (error: unknown) => error instanceof ConflictGraphError && error.code === "CROSS_SESSION_LEAF",
  );
  assert.throws(
    () => verifyGraphPairEvidenceLeaf(
      result.leaves[0],
      result.bindings[0],
      result.intents[0],
      result.aggregate.nodes,
      { ...pins, parameterFingerprint: digest("wrong-profile") },
    ),
    ConflictGraphError,
  );

  const trustedLocatorReplay = new ReceivableConflictSession({
    graphSessionId,
    receivableIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    issuedAtUnix: ISSUED_AT,
    expiresAtUnix: EXPIRES_AT,
    pins,
  });
  const firstAdmission = result.chronology.events.find((event) => (
    event.kind === "CLAIM_ADMITTED" && event.claimId === claims[0].authorization.claimId
  )) ?? assert.fail("A admission event missing");
  const secondAdmission = result.chronology.events.find((event) => (
    event.kind === "CLAIM_ADMITTED" && event.claimId === claims[1].authorization.claimId
  )) ?? assert.fail("B admission event missing");
  const intentEvent = result.chronology.events.find((event) => (
    event.kind === "PAIR_INTENT_FROZEN" && event.pairId === result.intents[0].claimPair.pairId
  )) ?? assert.fail("A/B intent event missing");
  const bindingEvent = result.chronology.events.find((event) => (
    event.kind === "PAIR_BOUND" && event.pairId === result.bindings[0].claimPair.pairId
  )) ?? assert.fail("A/B binding event missing");
  trustedLocatorReplay.admitClaim(claims[0].authorization, firstAdmission.occurredAt);
  trustedLocatorReplay.admitClaim(claims[1].authorization, secondAdmission.occurredAt);
  trustedLocatorReplay.beginPair(result.intents[0], intentEvent.occurredAt);
  trustedLocatorReplay.bindPair(result.bindings[0], bindingEvent.occurredAt);
  const forgedLocator = {
    ...result.leaves[0],
    claimPair: result.leaves[2].claimPair,
    pairRunId: result.leaves[2].pairRunId,
  };
  assert.throws(
    () => trustedLocatorReplay.completePair(forgedLocator, result.leaves[0].execution.completedAt),
    ConflictGraphError,
  );
  const trustedFailure = trustedLocatorReplay.chronology().events.at(-1);
  assert.equal(trustedFailure?.kind, "PAIR_FAILED");
  assert.equal(trustedFailure?.pairId, result.intents[0].claimPair.pairId);
  assert.equal(trustedFailure?.pairRunId, result.intents[0].pairRunId);

  const claimantA = projectClaimantGraph(result.aggregate, claims[0].authorization.claimId);
  assert.equal(claimantA.relations.length, 2);
  assert.equal(claimantA.relations.some((relation) => pairLabel(relation.claimPair, labelsByClaimId) === "BC"), false);

  assert.deepEqual(Object.keys(orchestrator).sort(), [
    "createProtectionCase",
    "evaluatePrivateConflict",
    "preparePrivateMatch",
    "releaseGovernedResult",
    "submitParticipantPledge",
  ]);
  assert.equal("openRecourseCase" in orchestrator, false);
});
