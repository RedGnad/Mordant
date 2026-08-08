/**
 * Sequential execution adapter for the bounded N=3 receivable-conflict graph.
 *
 * This module intentionally owns no paths and no engine construction. The proof
 * harness supplies a narrowly projected protection orchestrator, public JSON
 * readback, independent inspection and create-only persistence callbacks. That
 * keeps this adapter limited to the six governed-FHE operations needed to stop
 * each pair at RELEASED.
 */

import type { Sha256Digest } from "./cleanverse-asset";
import {
  governedResultDigest,
  type FheCaseBinding,
  type GovernedSignedResult,
} from "./protection-evidence";
import type { SupervisedPledgeWindows } from "./supervised-pledge-windows";
import {
  ConflictGraphError,
  REQUIRED_PAIR_OPERATIONS,
  ReceivableConflictSession,
  createGraphPairBinding,
  createGraphPairEvidenceLeaf,
  createGraphPairIntent,
  projectConflictGraph,
  retainedGraphPrivateClaimRecord,
  verifyGraphPrivateClaimRecord,
  verifyFheCaseBindingShape,
  type AggregateManifest,
  type CanonicalClaimPair,
  type ConflictGraphProjections,
  type GraphPairBindingRecord,
  type GraphPairEvidenceLeaf,
  type GraphPairIntent,
  type GraphPins,
  type GraphPrivateClaimRecord,
  type PairPublicInspection,
} from "./receivable-conflict-session";

export const RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES = Object.freeze({
  caseBinding: "case-binding.json",
  evaluatedConflict: "evaluated-conflict.json",
  governedResult: "governed-conflict-result.json",
} as const);

export type ReceivableConflictPairPublicFile =
  typeof RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES[keyof typeof RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES];

type Awaitable<T> = T | Promise<T>;

export type ReceivableConflictPairEngineView = Readonly<{
  runId: string;
  stage: string;
}>;

/** Only the engine calls permitted for this experiment. */
export type ReceivableConflictPairOrchestrator = Readonly<{
  createProtectionCase: (
    scenario: "conflict",
    pairRunId: string,
    supervisedPledgeWindows: SupervisedPledgeWindows,
  ) => Awaitable<ReceivableConflictPairEngineView>;
  preparePrivateMatch: (pairRunId: string) => Awaitable<ReceivableConflictPairEngineView>;
  submitParticipantPledge: (
    pairRunId: string,
    role: "PARTICIPANT_A" | "PARTICIPANT_B",
    expectedAssetDigest: Sha256Digest,
  ) => Awaitable<ReceivableConflictPairEngineView>;
  evaluatePrivateConflict: (pairRunId: string) => Awaitable<ReceivableConflictPairEngineView>;
  releaseGovernedResult: (pairRunId: string) => Awaitable<ReceivableConflictPairEngineView>;
}>;

export type ReceivableConflictPairJsonReader = <T>(
  pairRunId: string,
  fileName: ReceivableConflictPairPublicFile,
) => Awaitable<T>;

export type ReceivableConflictPairInspector = (
  pairRunId: string,
) => Awaitable<PairPublicInspection>;

/**
 * Structural subset of the create-only session store. Returning a path/result
 * is allowed, but this adapter never interprets it or obtains a path from it.
 */
export type ReceivableConflictSessionPersistence = Readonly<{
  writePublicClaimAuthorization: (
    sessionId: string,
    claimId: string,
    value: unknown,
  ) => Awaitable<unknown>;
  writePrivateClaimRecord: (
    sessionId: string,
    claimId: string,
    value: unknown,
  ) => Awaitable<unknown>;
  writePairIntent: (
    sessionId: string,
    pairId: string,
    value: unknown,
  ) => Awaitable<unknown>;
  writePairBinding: (
    sessionId: string,
    pairId: string,
    value: unknown,
  ) => Awaitable<unknown>;
  writeEvidenceLeaf: (
    sessionId: string,
    pairId: string,
    value: unknown,
  ) => Awaitable<unknown>;
  writeAggregate: (sessionId: string, value: unknown) => Awaitable<unknown>;
  writeProjection: (
    sessionId: string,
    projectionId: string,
    value: unknown,
  ) => Awaitable<unknown>;
  writeChronology: (sessionId: string, value: unknown) => Awaitable<unknown>;
  writeRetentionDeclaration: (sessionId: string) => Awaitable<unknown>;
}>;

export type ReceivableConflictSessionRunnerOptions = Readonly<{
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  issuedAtUnix: number;
  expiresAtUnix: number;
  pins: GraphPins;
  /** Admission order is the only A/B/C association retained by the caller. */
  claims: readonly [GraphPrivateClaimRecord, GraphPrivateClaimRecord, GraphPrivateClaimRecord];
  orchestrator: ReceivableConflictPairOrchestrator;
  readJson: ReceivableConflictPairJsonReader;
  inspect: ReceivableConflictPairInspector;
  persist: ReceivableConflictSessionPersistence;
  now: () => Date;
  newPairRunId: (pair: CanonicalClaimPair, executionOrdinal: number) => string;
}>;

export type ReceivableConflictSessionRunnerResult = Readonly<{
  session: ReceivableConflictSession;
  intents: readonly GraphPairIntent[];
  bindings: readonly GraphPairBindingRecord[];
  leaves: readonly GraphPairEvidenceLeaf[];
  aggregate: AggregateManifest;
  chronology: ReturnType<ReceivableConflictSession["chronology"]>;
  projections: ConflictGraphProjections;
  maxConcurrentPairsObserved: 0 | 1;
}>;

type EvaluatedConflictReadback = Readonly<{
  evaluatorProvenance: Sha256Digest;
}>;

function observedTime(now: () => Date): Readonly<{ iso: string; unix: number }> {
  const value = now();
  if (!(value instanceof Date)) {
    throw new ConflictGraphError("RUNNER_CLOCK", "Runner clock returned an invalid Date");
  }
  const milliseconds = value.getTime();
  if (!Number.isFinite(milliseconds)) {
    throw new ConflictGraphError("RUNNER_CLOCK", "Runner clock returned an invalid Date");
  }
  return Object.freeze({
    iso: value.toISOString(),
    unix: Math.floor(milliseconds / 1_000),
  });
}

/** Strip any fields outside the governed public case-binding schema. */
function publicCaseBinding(value: FheCaseBinding): FheCaseBinding {
  verifyFheCaseBindingShape(value);
  return Object.freeze({
    schemaVersion: value.schemaVersion,
    caseId: value.caseId,
    assetIdentity: value.assetIdentity,
    serviceId: value.serviceId,
    serviceVersion: value.serviceVersion,
    policyId: value.policyId,
    policyVersion: value.policyVersion,
    circuitId: value.circuitId,
    circuitVersion: value.circuitVersion,
    circuitDigest: value.circuitDigest,
    parameterProfile: value.parameterProfile,
    parameterFingerprint: value.parameterFingerprint,
    publicKeyDigest: value.publicKeyDigest,
    evaluationKeyManifestDigest: value.evaluationKeyManifestDigest,
    participantA: Object.freeze({
      id: value.participantA.id,
      role: value.participantA.role,
      signingPublicKey: value.participantA.signingPublicKey,
    }),
    participantB: Object.freeze({
      id: value.participantB.id,
      role: value.participantB.role,
      signingPublicKey: value.participantB.signingPublicKey,
    }),
    participantOrder: Object.freeze([value.participantOrder[0], value.participantOrder[1]] as const),
    inputSchema: value.inputSchema,
    resultSchema: value.resultSchema,
    releaseMode: value.releaseMode,
    releaseAuthorityId: value.releaseAuthorityId,
    releaseAuthorityPublicKey: value.releaseAuthorityPublicKey,
    caseNonce: value.caseNonce,
    createdAtUnix: value.createdAtUnix,
    expiresAtUnix: value.expiresAtUnix,
  });
}

/** Persist only the fixed public inspection projection, never callback extras. */
function publicInspection(value: PairPublicInspection): PairPublicInspection {
  return Object.freeze({
    finalized: value.finalized,
    evaluationAdmission: value.evaluationAdmission,
    releaseVerified: value.releaseVerified,
    ambiguous: value.ambiguous,
    recoursePresent: value.recoursePresent,
    publicEvidencePresent: value.publicEvidencePresent,
    resultDigest: value.resultDigest,
    conflict: value.conflict,
    releaseMode: value.releaseMode,
    participantArtifactDigests: Object.freeze([
      value.participantArtifactDigests[0],
      value.participantArtifactDigests[1],
    ] as const),
    evaluatedArtifactDigest: value.evaluatedArtifactDigest,
    inspectBinaryDigest: value.inspectBinaryDigest,
    inspectionReportDigest: value.inspectionReportDigest,
    inspectionDigest: value.inspectionDigest,
  });
}

function requireEngineStage(
  view: ReceivableConflictPairEngineView,
  pairRunId: string,
  expectedStage: string,
): void {
  if (view.runId !== pairRunId || view.stage !== expectedStage) {
    throw new ConflictGraphError("PAIR_ENGINE_STAGE", `Pair engine did not reach ${expectedStage}`);
  }
}

function failureCode(error: unknown): string {
  if (error instanceof ConflictGraphError) return error.code;
  if (error !== null && typeof error === "object" && "code" in error) {
    const code = (error as Readonly<{ code?: unknown }>).code;
    if (typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/u.test(code)) return code;
  }
  return "PAIR_EXECUTION_FAILED";
}

function canonicalPrivatePair(
  pair: CanonicalClaimPair,
  claims: ReadonlyMap<Sha256Digest, GraphPrivateClaimRecord>,
): readonly [GraphPrivateClaimRecord, GraphPrivateClaimRecord] {
  const participantA = claims.get(pair.leftClaimId);
  const participantB = claims.get(pair.rightClaimId);
  if (participantA === undefined || participantB === undefined) {
    throw new ConflictGraphError("PAIR_PRIVATE_CLAIM", "Canonical pair private claim is unavailable");
  }
  return [participantA, participantB];
}

function supervisedWindowsFromClaims(
  claims: readonly [GraphPrivateClaimRecord, GraphPrivateClaimRecord],
): SupervisedPledgeWindows {
  return Object.freeze({
    participantA: Object.freeze({
      activeFrom: claims[0].opening.activeFrom,
      activeUntil: claims[0].opening.activeUntil,
    }),
    participantB: Object.freeze({
      activeFrom: claims[1].opening.activeFrom,
      activeUntil: claims[1].opening.activeUntil,
    }),
  });
}

function assertRunnerClaims(options: ReceivableConflictSessionRunnerOptions): void {
  if (options.claims.length !== 3) {
    throw new ConflictGraphError("RUNNER_CLAIMS", "The N=3 runner requires exactly three private claims");
  }
  const claimIds = new Set<string>();
  const participantRefs = new Set<string>();
  for (const record of options.claims) {
    verifyGraphPrivateClaimRecord(record);
    const authorization = record.authorization;
    if (
      authorization.graphSessionId !== options.graphSessionId
      || authorization.receivableIdentity !== options.receivableIdentity
      || claimIds.has(authorization.claimId)
      || participantRefs.has(authorization.participantRef)
    ) {
      throw new ConflictGraphError("RUNNER_CLAIMS", "Private claims do not form one unique graph session");
    }
    claimIds.add(authorization.claimId);
    participantRefs.add(authorization.participantRef);
  }
}

/**
 * Admit A, B and C incrementally and run only the newly formed pairs. Pair work
 * is deliberately an awaited nested loop: AB completes before C is admitted,
 * then AC completes before BC starts.
 */
export async function runReceivableConflictSession(
  options: ReceivableConflictSessionRunnerOptions,
): Promise<ReceivableConflictSessionRunnerResult> {
  assertRunnerClaims(options);
  const session = new ReceivableConflictSession({
    graphSessionId: options.graphSessionId,
    receivableIdentity: options.receivableIdentity,
    issuedAtUnix: options.issuedAtUnix,
    expiresAtUnix: options.expiresAtUnix,
    pins: options.pins,
  });
  const claimsById = new Map<Sha256Digest, GraphPrivateClaimRecord>(
    options.claims.map((record) => [record.authorization.claimId, record]),
  );
  const intents: GraphPairIntent[] = [];
  const bindings: GraphPairBindingRecord[] = [];
  const leaves: GraphPairEvidenceLeaf[] = [];
  let activePairCount = 0;
  let maxConcurrentPairsObserved: 0 | 1 = 0;
  let nextExecutionOrdinal = 0;

  await options.persist.writeRetentionDeclaration(session.graphSessionId);

  for (let claimIndex = 0; claimIndex < options.claims.length; claimIndex += 1) {
    const privateClaim = options.claims[claimIndex];
    const authorization = privateClaim.authorization;
    await options.persist.writePrivateClaimRecord(
      session.graphSessionId,
      authorization.claimId,
      retainedGraphPrivateClaimRecord(privateClaim),
    );
    await options.persist.writePublicClaimAuthorization(session.graphSessionId, authorization.claimId, authorization);

    const admissionTime = observedTime(options.now);
    const newPairs = session.admitClaim(authorization, admissionTime.iso);
    if (claimIndex === options.claims.length - 1) session.sealAdmissions(admissionTime.iso);

    for (const pair of newPairs) {
      const pairClaims = canonicalPrivatePair(pair, claimsById);
      const started = observedTime(options.now);
      nextExecutionOrdinal += 1;
      const pairRunId = options.newPairRunId(pair, nextExecutionOrdinal);
      const intent = createGraphPairIntent({
        first: pairClaims[0],
        second: pairClaims[1],
        pairRunId,
        createdAtUnix: started.unix,
      });

      // This is the durable pre-result freeze. No engine case exists before it.
      await options.persist.writePairIntent(session.graphSessionId, pair.pairId, intent);
      session.beginPair(intent, started.iso);
      intents.push(intent);
      activePairCount += 1;
      if (activePairCount > 1) {
        throw new ConflictGraphError("PAIR_CONCURRENCY", "More than one pair execution became active");
      }
      maxConcurrentPairsObserved = 1;

      try {
        const windows = supervisedWindowsFromClaims(pairClaims);
        requireEngineStage(
          await options.orchestrator.createProtectionCase("conflict", pairRunId, windows),
          pairRunId,
          "CASE_CREATED",
        );
        requireEngineStage(
          await options.orchestrator.preparePrivateMatch(pairRunId),
          pairRunId,
          "MATCH_PREPARED",
        );

        const caseBinding = publicCaseBinding(
          await options.readJson<FheCaseBinding>(
            pairRunId,
            RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES.caseBinding,
          ),
        );
        const bound = observedTime(options.now);
        const binding = createGraphPairBinding({
          intent,
          claims: pairClaims,
          caseBinding,
          boundAtUnix: bound.unix,
          pins: options.pins,
        });
        // The stable graph-claim to pair-local identity binding is frozen before
        // either participant submission can reveal an eventual relation.
        await options.persist.writePairBinding(session.graphSessionId, pair.pairId, binding);
        session.bindPair(binding, bound.iso);
        bindings.push(binding);

        requireEngineStage(
          await options.orchestrator.submitParticipantPledge(
            pairRunId,
            "PARTICIPANT_A",
            options.pins.assetIdentity,
          ),
          pairRunId,
          "PARTICIPANT_A_SUBMITTED",
        );
        requireEngineStage(
          await options.orchestrator.submitParticipantPledge(
            pairRunId,
            "PARTICIPANT_B",
            options.pins.assetIdentity,
          ),
          pairRunId,
          "PARTICIPANT_B_SUBMITTED",
        );
        requireEngineStage(
          await options.orchestrator.evaluatePrivateConflict(pairRunId),
          pairRunId,
          "EVALUATED",
        );
        requireEngineStage(
          await options.orchestrator.releaseGovernedResult(pairRunId),
          pairRunId,
          "RELEASED",
        );

        const inspection = publicInspection(await options.inspect(pairRunId));
        const evaluated = await options.readJson<EvaluatedConflictReadback>(
          pairRunId,
          RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES.evaluatedConflict,
        );
        const governedResult = await options.readJson<GovernedSignedResult>(
          pairRunId,
          RECEIVABLE_CONFLICT_PAIR_PUBLIC_FILES.governedResult,
        );
        const completed = observedTime(options.now);
        const leaf = createGraphPairEvidenceLeaf({
          graphSessionId: session.graphSessionId,
          receivableIdentity: session.receivableIdentity,
          claimPair: pair,
          pairRunId,
          pairBindingDigest: binding.bindingDigest,
          caseId: binding.caseId,
          caseBindingDigest: binding.caseBindingDigest,
          participantArtifactDigests: governedResult.participantArtifactDigests,
          evaluatedArtifactDigest: governedResult.evaluatedArtifactDigest,
          evaluatorProvenance: evaluated.evaluatorProvenance,
          governedResult,
          governedResultDigest: governedResultDigest(governedResult),
          inspection,
          execution: {
            executionOrdinal: nextExecutionOrdinal,
            startedAt: started.iso,
            completedAt: completed.iso,
            terminalStage: "RELEASED",
            operations: REQUIRED_PAIR_OPERATIONS,
          },
          binding,
          intent,
          nodes: session.publicNodes(),
          pins: options.pins,
        });
        session.validateActivePairEvidence(leaf, completed.iso);
        await options.persist.writeEvidenceLeaf(session.graphSessionId, pair.pairId, leaf);
        session.completePair(leaf, completed.iso);
        leaves.push(leaf);
      } catch (error) {
        const failed = observedTime(options.now);
        try {
          session.failActivePair(failureCode(error), failed.iso);
        } catch (failureError) {
          // completePair marks and closes its active pair when validation fails.
          if (!(failureError instanceof ConflictGraphError && failureError.code === "PAIR_ACTIVE")) {
            throw failureError;
          }
        }
      } finally {
        activePairCount -= 1;
      }
    }
  }

  const chronology = session.chronology();
  const aggregate = session.aggregate();
  const projections = projectConflictGraph(aggregate);
  if (aggregate.execution.maxConcurrentPairsObserved !== maxConcurrentPairsObserved) {
    throw new ConflictGraphError("PAIR_CONCURRENCY", "Runner and session concurrency records diverged");
  }

  await options.persist.writeChronology(session.graphSessionId, chronology);
  await options.persist.writeAggregate(session.graphSessionId, aggregate);
  await options.persist.writeProjection(session.graphSessionId, "operator", projections.operator);
  for (const claimant of projections.claimants) {
    await options.persist.writeProjection(
      session.graphSessionId,
      `claimant:${claimant.claimId}`,
      claimant,
    );
  }
  await options.persist.writeProjection(session.graphSessionId, "public", projections.public);

  return Object.freeze({
    session,
    intents: Object.freeze([...intents]),
    bindings: Object.freeze([...bindings]),
    leaves: Object.freeze([...leaves]),
    aggregate,
    chronology,
    projections,
    maxConcurrentPairsObserved,
  });
}
