import "server-only";

import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statfsSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  type Sha256Digest,
} from "./cleanverse-asset";
import {
  appendProtectionEvent,
  assertProtectionAssetBinding,
  createProtectionCase as createProtectionCaseModel,
  FHE_CIRCUIT,
  FHE_PARAMETER_PROFILE,
  type MordantProtectionCase,
  type ProductScenario,
} from "./protection-case";
import {
  EXPECTED_GOVERNED_FHE_COMMIT,
  EXPECTED_PROTECTION_SOURCE_COMMIT,
  assertPublicProtectionEvidence,
  governedResultDigest,
  protectionEvidenceDigest,
  verifyGovernedResultSignature,
  type FheCaseBinding,
  type GovernedFhePublicEvidence,
  type GovernedSignedResult,
  type MordantProtectionEvidence,
  type ParticipantBindingSignature,
  type PublicRecourseRecord,
} from "./protection-evidence";
import {
  beginOperation,
  finishOperation,
  pendingOperation,
  readOperationJournal,
  writeDurableJsonAtomic,
  type ProductOperationRecord,
} from "./protection-operation-journal";

const execFileAsync = promisify(execFile);

export const PRODUCT_STORAGE = Object.freeze({
  estimatedCaseBytes: 576_716_800,
  twoCaseRetainedBytes: 1_153_433_600,
  retainedEvidenceBytes: 131_072,
  safetyMarginBytes: 1_610_612_736,
  binaryAndCacheBytes: 805_306_368,
});

const SOURCE_COMMIT = process.env.MORDANT_PROTECTION_SOURCE_COMMIT ?? EXPECTED_PROTECTION_SOURCE_COMMIT;
const GOVERNED_FHE_COMMIT = EXPECTED_GOVERNED_FHE_COMMIT;
const MAX_PROCESS_BUFFER = 8 << 20;

const BINARIES = Object.freeze({
  keygen: "mordant-fhe-keygen",
  client: "mordant-fhe-client",
  evaluator: "mordant-fhe-evaluator",
  decryptor: "mordant-fhe-decryptor",
  recourse: "mordant-fhe-recourse",
  inspect: "mordant-fhe-inspect",
});

type ExecutionStage =
  | "CASE_CREATED"
  | "MATCH_PREPARED"
  | "PARTICIPANT_A_SUBMITTED"
  | "PARTICIPANT_B_PUBLISHED"
  | "PARTICIPANT_B_SUBMITTED"
  | "EVALUATED"
  | "RELEASED"
  | "RECOURSE_OPENED"
  | "CHRONOLOGY_COMPLETE"
  | "COMPLETE"
  | "ABORTED";

type KeygenOutput = Readonly<{
  bindingDigest: Sha256Digest;
  durationNanos: number;
  report: Readonly<Record<string, unknown>>;
}>;
type SubmissionOutput = Readonly<{
  artifactDigest: Sha256Digest;
  durationNanos: number;
  ciphertextBytes: number;
  artifactBytes: number;
}>;
type EvaluationOutput = Readonly<{
  artifactDigest: Sha256Digest;
  durationNanos: number;
  resultBytes: number;
  artifactBytes: number;
}>;
type ReleaseOutput = Readonly<{
  resultDigest: Sha256Digest;
  conflict: boolean;
  releaseMode: "governed-decryptor-v1";
  durationNanos: number;
  resultBytes: number;
  exactRetry: boolean;
  trustedRecoursePins: Readonly<{
    participantArtifactDigestA: Sha256Digest;
    participantArtifactDigestB: Sha256Digest;
    evaluatedArtifactDigest: Sha256Digest;
    recomputedResultCiphertextDigest: Sha256Digest;
    resultCiphertextCommitment: Sha256Digest;
    decryptorProvenance: Sha256Digest;
    releaseMode: "governed-decryptor-v1";
    releaseAuthorityId: Sha256Digest;
  }>;
}>;

type ProductInspection = Readonly<{
  foundation?: Readonly<{ bindingDigest: Sha256Digest; report: Readonly<Record<string, unknown>> }>;
  submissionA?: Omit<SubmissionOutput, "durationNanos">;
  submissionB?: Omit<SubmissionOutput, "durationNanos">;
  finalized: boolean;
  evaluationAdmission: boolean;
  evaluation?: Omit<EvaluationOutput, "durationNanos">;
  releaseAdmission: boolean;
  release?: Omit<ReleaseOutput, "durationNanos">;
  recourse?: PublicRecourseRecord;
  evidence?: GovernedFhePublicEvidence;
  ambiguous: boolean;
  ambiguousReason?: string;
}>;

export type ProtectionRuntimeOptions = Readonly<{
  runRoot?: string;
  binRoot?: string;
  goRoot?: string;
  importedEvidenceRoot?: string;
  now?: () => Date;
  failpoint?: (name: string) => void;
  binaryRunner?: <T>(binary: keyof typeof BINARIES, args: readonly string[]) => Promise<T>;
  statfsAvailableBytes?: (root: string) => number;
  skipBinaryBuild?: boolean;
}>;

type ProtectionRuntime = Readonly<{
  runRoot: string;
  binRoot: string;
  goRoot: string;
  importedEvidenceRoot: string;
  now: () => Date;
  failpoint: (name: string) => void;
  binaryRunner?: ProtectionRuntimeOptions["binaryRunner"];
  statfsAvailableBytes?: ProtectionRuntimeOptions["statfsAvailableBytes"];
  skipBinaryBuild: boolean;
}>;

function runtimeFrom(options: ProtectionRuntimeOptions = {}): ProtectionRuntime {
  return {
    runRoot: resolve(options.runRoot ?? process.env.MORDANT_PROTECTION_RUN_ROOT ?? join(process.cwd(), ".mordant", "protection")),
    binRoot: resolve(options.binRoot ?? process.env.MORDANT_GOVERNED_FHE_BIN_DIR ?? join(process.cwd(), ".mordant", "governed-fhe-bin")),
    goRoot: resolve(options.goRoot ?? join(process.cwd(), "fhe-lab", "lattigo")),
    importedEvidenceRoot: resolve(options.importedEvidenceRoot ?? join(process.cwd(), "docs", "evidence", "conflicting-pledge-protection")),
    now: options.now ?? (() => new Date()),
    failpoint: options.failpoint ?? (() => undefined),
    binaryRunner: options.binaryRunner,
    statfsAvailableBytes: options.statfsAvailableBytes,
    skipBinaryBuild: options.skipBinaryBuild ?? false,
  };
}

const DEFAULT_RUNTIME = runtimeFrom();

type InternalState = Readonly<{
  schemaVersion: "mordant.protection-execution/2";
  runId: string;
  stage: ExecutionStage;
  protectionCase: MordantProtectionCase;
  paths: Readonly<{
    root: string;
    publicRoot: string;
    decryptorPrivateRoot: string;
    participantPrivateRoot: string;
  }>;
  participantKeys?: Readonly<Record<"PARTICIPANT_A" | "PARTICIPANT_B", string>>;
  keygen?: KeygenOutput;
  submissions?: Readonly<Partial<Record<"PARTICIPANT_A" | "PARTICIPANT_B", SubmissionOutput>>>;
  evaluation?: EvaluationOutput;
  release?: ReleaseOutput;
  recourse?: Readonly<{ opened: boolean; reason?: "SIGNED_RESULT_FALSE"; record?: Readonly<Record<string, unknown>> }>;
  evidence?: MordantProtectionEvidence;
  abortedReason?: string;
  startedAtUnix: number;
}>;

export type ProtectionCaseView = Readonly<{
  schemaVersion: "mordant.protection-product-view/1";
  runId: string;
  stage: ExecutionStage;
  nextOperation: string | null;
  protectionCase: MordantProtectionCase;
  participantArtifactDigests: Readonly<{
    participantA: Sha256Digest | null;
    participantB: Sha256Digest | null;
  }>;
  evaluatedArtifactDigest: Sha256Digest | null;
  governedResult: Readonly<{
    conflict: boolean;
    digest: Sha256Digest;
    releaseMode: "governed-decryptor-v1";
  }> | null;
  recourse: InternalState["recourse"] | null;
  evidence: MordantProtectionEvidence | null;
  execution: Readonly<{
    fhe: "REAL_BGV_FHE";
    deployment: "LOCAL_SINGLE_HOST";
    webPresentation: "PUBLIC_EVIDENCE_READBACK";
    recourse: "LOCAL_PROTOCOL_DOUBLE";
  }>;
}>;

export class ProtectionProductError extends Error {
  constructor(message: string, readonly status = 409) {
    super(message);
    this.name = "ProtectionProductError";
  }
}

export type DiskPreflight = Readonly<{
  availableBytes: number;
  estimatedCaseBytes: number;
  safetyMarginBytes: number;
  requiredBytes: number;
  sufficient: boolean;
}>;

export function evaluateDiskSpace(
  availableBytes: number,
  estimatedCaseBytes: number = PRODUCT_STORAGE.estimatedCaseBytes,
  safetyMarginBytes: number = PRODUCT_STORAGE.safetyMarginBytes,
): DiskPreflight {
  const requiredBytes = estimatedCaseBytes + safetyMarginBytes;
  return Object.freeze({
    availableBytes,
    estimatedCaseBytes,
    safetyMarginBytes,
    requiredBytes,
    sufficient: Number.isSafeInteger(availableBytes) && availableBytes >= requiredBytes,
  });
}

export function diskSpacePreflight(
  root: string,
  availableOverride?: (root: string) => number,
  estimatedBytes: number = PRODUCT_STORAGE.estimatedCaseBytes,
  safetyBytes: number = PRODUCT_STORAGE.safetyMarginBytes,
): DiskPreflight {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const availableBytes = availableOverride === undefined ? (() => {
    const stat = statfsSync(root, { bigint: true });
    const available = stat.bavail * stat.bsize;
    return available > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(available);
  })() : availableOverride(root);
  return evaluateDiskSpace(availableBytes, estimatedBytes, safetyBytes);
}

function assertDiskSpace(runtime: ProtectionRuntime): DiskPreflight {
  const result = diskSpacePreflight(runtime.runRoot, runtime.statfsAvailableBytes);
  if (!result.sufficient) {
    throw new ProtectionProductError(
      `Insufficient disk for one N15 case: ${result.availableBytes} bytes available; `
      + `${result.requiredBytes} bytes required including safety margin. No key material was generated.`,
      507,
    );
  }
  return result;
}

function assertBinaryBuildSpace(runtime: ProtectionRuntime): DiskPreflight {
  const result = diskSpacePreflight(runtime.binRoot, runtime.statfsAvailableBytes, PRODUCT_STORAGE.binaryAndCacheBytes, 0);
  if (!result.sufficient) {
    throw new ProtectionProductError("Insufficient disk for governed-FHE command binaries and bounded Go cache.", 507);
  }
  return result;
}

function pathForBinary(runtime: ProtectionRuntime, name: keyof typeof BINARIES): string {
  return join(runtime.binRoot, BINARIES[name]);
}

async function ensureBinaries(runtime: ProtectionRuntime): Promise<void> {
  if (runtime.skipBinaryBuild || runtime.binaryRunner !== undefined) return;
  if (process.env.NODE_ENV === "production") {
    throw new ProtectionProductError("Local BGV execution is unavailable in the deployed web runtime.", 404);
  }
  mkdirSync(runtime.binRoot, { recursive: true, mode: 0o700 });
  const goCache = join(runtime.runRoot, "go-build-cache");
  mkdirSync(goCache, { recursive: true, mode: 0o700 });
  for (const [name, binary] of Object.entries(BINARIES) as Array<[keyof typeof BINARIES, string]>) {
    const target = pathForBinary(runtime, name);
    if (existsSync(target)) continue;
    await execFileAsync("go", ["build", "-o", target, `./cmd/${binary}`], {
      cwd: runtime.goRoot,
      maxBuffer: MAX_PROCESS_BUFFER,
      env: { ...process.env, CGO_ENABLED: "0", GOCACHE: goCache },
    });
    chmodSync(target, 0o700);
  }
}

function writeJsonAtomic(path: string, value: unknown, mode = 0o600): void {
  writeDurableJsonAtomic(path, value, mode);
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function assertRunId(runId: string): void {
  if (!/^[0-9a-f-]{36}$/.test(runId)) throw new ProtectionProductError("Invalid protection run id", 400);
}

function statePath(runtime: ProtectionRuntime, runId: string): string {
  assertRunId(runId);
  return join(runtime.runRoot, runId, "execution.json");
}

function loadStateRaw(runtime: ProtectionRuntime, runId: string): InternalState {
  const path = statePath(runtime, runId);
  if (!existsSync(path)) throw new ProtectionProductError("Protection case not found", 404);
  const state = readJson<InternalState>(path);
  if (state.runId !== runId || state.paths.root !== dirname(path)) {
    throw new ProtectionProductError("Protection execution record rejected", 500);
  }
  assertProtectionAssetBinding(state.protectionCase, CANONICAL_CLEANVERSE_ASSET_DIGEST);
  return state;
}

function saveState(runtime: ProtectionRuntime, state: InternalState): InternalState {
  writeJsonAtomic(statePath(runtime, state.runId), state);
  return state;
}

function nextOperation(stage: ExecutionStage, scenario: ProductScenario): string | null {
  switch (stage) {
    case "CASE_CREATED": return "preparePrivateMatch";
    case "MATCH_PREPARED": return "submitParticipantPledge:PARTICIPANT_A";
    case "PARTICIPANT_A_SUBMITTED": return "submitParticipantPledge:PARTICIPANT_B";
    case "PARTICIPANT_B_PUBLISHED": return "submitParticipantPledge:PARTICIPANT_B";
    case "PARTICIPANT_B_SUBMITTED": return "evaluatePrivateConflict";
    case "EVALUATED": return "releaseGovernedResult";
    case "RELEASED": return "openRecourseCase";
    case "RECOURSE_OPENED": return scenario === "conflict" ? "completeCureChronology" : "exportProtectionEvidence";
    case "CHRONOLOGY_COMPLETE": return "exportProtectionEvidence";
    case "COMPLETE": return null;
    case "ABORTED": return null;
  }
}

function publicView(state: InternalState): ProtectionCaseView {
  const view: ProtectionCaseView = {
    schemaVersion: "mordant.protection-product-view/1",
    runId: state.runId,
    stage: state.stage,
    nextOperation: nextOperation(state.stage, state.protectionCase.productScenario),
    protectionCase: state.protectionCase,
    participantArtifactDigests: {
      participantA: state.submissions?.PARTICIPANT_A?.artifactDigest ?? null,
      participantB: state.submissions?.PARTICIPANT_B?.artifactDigest ?? null,
    },
    evaluatedArtifactDigest: state.evaluation?.artifactDigest ?? null,
    governedResult: state.release === undefined ? null : {
      conflict: state.release.conflict,
      digest: state.release.resultDigest,
      releaseMode: state.release.releaseMode,
    },
    recourse: state.recourse ?? null,
    evidence: state.evidence ?? null,
    execution: {
      fhe: "REAL_BGV_FHE",
      deployment: "LOCAL_SINGLE_HOST",
      webPresentation: "PUBLIC_EVIDENCE_READBACK",
      recourse: "LOCAL_PROTOCOL_DOUBLE",
    },
  };
  return Object.freeze(view);
}

function appendEventOnce(
  protectionCase: MordantProtectionCase,
  event: Parameters<typeof appendProtectionEvent>[1],
  patch: Parameters<typeof appendProtectionEvent>[2] = {},
): MordantProtectionCase {
  return protectionCase.timeline.some((existing) => existing.kind === event.kind)
    ? protectionCase
    : appendProtectionEvent(protectionCase, event, patch);
}

function participantKeyPaths(state: InternalState): Readonly<Record<"PARTICIPANT_A" | "PARTICIPANT_B", string>> {
  return {
    PARTICIPANT_A: join(state.paths.participantPrivateRoot, "participant_a.ed25519"),
    PARTICIPANT_B: join(state.paths.participantPrivateRoot, "participant_b.ed25519"),
  };
}

async function inspectCase(runtime: ProtectionRuntime, state: InternalState): Promise<ProductInspection> {
  await ensureBinaries(runtime);
  return runJSON<ProductInspection>(runtime, "inspect", [
    "-public-root", state.paths.publicRoot,
    "-private-root", state.paths.decryptorPrivateRoot,
  ]);
}

function abortState(runtime: ProtectionRuntime, state: InternalState, pending: ProductOperationRecord, reason: string): InternalState {
  finishOperation(runtime.runRoot, state.runId, pending.operationId, "ABORTED", runtime.now().toISOString(), reason);
  return saveState(runtime, { ...state, stage: "ABORTED", abortedReason: reason });
}

function reconstructedSubmission(value: Omit<SubmissionOutput, "durationNanos">): SubmissionOutput {
  return { ...value, durationNanos: 0 };
}

function recourseFromRecord(record: PublicRecourseRecord): NonNullable<InternalState["recourse"]> {
  return { opened: true, record };
}

function reconcileProtectionProjection(
  state: InternalState,
  pending: ProductOperationRecord,
  inspection: ProductInspection,
): InternalState | null {
  const at = pending.createdAt;
  switch (pending.phase) {
    case "PREPARING": {
      if (inspection.foundation === undefined) return null;
      const protectionCase = appendEventOnce(state.protectionCase, {
        kind: "HOLDER_SNAPSHOT_RECORDED",
        at,
        label: "Record-date holder allocation fixed at 60 / 40 and reserve held separately",
        classification: "PROTOCOL_DOUBLE",
        evidenceRef: state.protectionCase.holderAllocationDigest,
      }, { incidentState: "PRIVATE_MATCH_OPEN" });
      return {
        ...state,
        stage: "MATCH_PREPARED",
        protectionCase,
        keygen: { bindingDigest: inspection.foundation.bindingDigest, durationNanos: 0, report: inspection.foundation.report },
        participantKeys: participantKeyPaths(state),
      };
    }
    case "SUBMITTING_A":
    case "SUBMITTING_B": {
      const role = pending.phase === "SUBMITTING_A" ? "PARTICIPANT_A" : "PARTICIPANT_B";
      const output = role === "PARTICIPANT_A" ? inspection.submissionA : inspection.submissionB;
      if (output === undefined) return null;
      const protectionCase = appendEventOnce(state.protectionCase, {
        kind: `${role}_ENCRYPTED_PLEDGE_RECEIVED`,
        at,
        label: `${role === "PARTICIPANT_A" ? "Participant A" : "Participant B"} encrypted pledge received`,
        classification: "LOCAL_EXECUTION",
        evidenceRef: output.artifactDigest,
      });
      return {
        ...state,
        stage: role === "PARTICIPANT_A" ? "PARTICIPANT_A_SUBMITTED" : "PARTICIPANT_B_PUBLISHED",
        protectionCase,
        submissions: { ...state.submissions, [role]: reconstructedSubmission(output) },
      };
    }
    case "FINALIZING":
      return inspection.finalized ? { ...state, stage: "PARTICIPANT_B_SUBMITTED" } : null;
    case "EVALUATING": {
      if (inspection.evaluation === undefined) return null;
      const protectionCase = appendEventOnce(state.protectionCase, {
        kind: "FHE_EVALUATION_COMPLETE",
        at,
        label: "Fixed N15 BGV conflict circuit evaluated without an evaluator decryption key",
        classification: "LOCAL_EXECUTION",
        evidenceRef: inspection.evaluation.artifactDigest,
      }, { incidentState: "EVALUATED" });
      return { ...state, stage: "EVALUATED", protectionCase, evaluation: { ...inspection.evaluation, durationNanos: 0 } };
    }
    case "RELEASING": {
      if (inspection.release === undefined) return null;
      const release: ReleaseOutput = { ...inspection.release, durationNanos: 0 };
      let protectionCase = appendEventOnce(state.protectionCase, {
        kind: "GOVERNED_RECOMPUTATION_VERIFIED",
        at,
        label: "Governed decryptor independently recomputed the fixed circuit",
        classification: "LOCAL_EXECUTION",
        evidenceRef: release.trustedRecoursePins.recomputedResultCiphertextDigest,
      });
      protectionCase = appendEventOnce(protectionCase, {
        kind: release.conflict ? "SIGNED_CONFLICT_CONFIRMED" : "SIGNED_CONFLICT_CLEARED",
        at,
        label: release.conflict ? "Signed Boolean confirmed a conflicting pledge" : "Signed Boolean cleared the conflicting-pledge check",
        classification: "LOCAL_EXECUTION",
        evidenceRef: release.resultDigest,
      }, { incidentState: release.conflict ? "CONFLICT_CONFIRMED" : "CLEARED" });
      return { ...state, stage: "RELEASED", protectionCase, release };
    }
    case "OPENING_RECOURSE": {
      const outcomePath = join(state.paths.root, "recourse-outcome.json");
      if (inspection.recourse === undefined && !existsSync(outcomePath)) return null;
      const recourse = inspection.recourse === undefined
        ? readJson<NonNullable<InternalState["recourse"]>>(outcomePath)
        : recourseFromRecord(inspection.recourse);
      if (state.release === undefined || recourse.opened !== state.release.conflict) return null;
      let protectionCase = state.protectionCase;
      if (recourse.opened && recourse.record !== undefined) {
        protectionCase = appendEventOnce(protectionCase, {
          kind: "CURE_WINDOW_OPENED",
          at,
          label: "Record-date holders remain fixed while the cure / dispute window runs",
          classification: "PROTOCOL_DOUBLE",
          evidenceRef: state.protectionCase.holderAllocationDigest,
        }, {
          cureDeadline: new Date(Number(recourse.record.cureDeadlineUnix) * 1000).toISOString(),
          recourseState: "CURE_WINDOW",
        });
      } else {
        protectionCase = appendEventOnce(protectionCase, {
          kind: "RECOURSE_REFUSED", at, label: "A signed false result cannot open conflicting-pledge recourse",
          classification: "PROTOCOL_DOUBLE", evidenceRef: state.release.resultDigest,
        }, { recourseState: "REFUSED" });
      }
      return { ...state, stage: "RECOURSE_OPENED", protectionCase, recourse };
    }
    case "ADVANCING_CURE":
      return state.stage === "CHRONOLOGY_COMPLETE" ? state : null;
    case "EXPORTING": {
      const productEvidencePath = join(state.paths.root, "protection-evidence.json");
      if (!existsSync(productEvidencePath) && inspection.evidence !== undefined) {
        const recovered = buildProtectionEvidence(state, inspection.evidence, pending.createdAt);
        writeJsonAtomic(productEvidencePath, recovered, 0o644);
      }
      if (!existsSync(productEvidencePath)) return null;
      const evidence = readJson<MordantProtectionEvidence>(productEvidencePath);
      assertPublicProtectionEvidence(evidence);
      return { ...state, stage: "COMPLETE", evidence };
    }
    case "RETAINING":
      if (typeof pending.immutableParameters.destination !== "string" || !existsSync(pending.immutableParameters.destination)) return null;
      try {
        const retained = readJson<MordantProtectionEvidence>(pending.immutableParameters.destination);
        assertPublicProtectionEvidence(retained);
        return retained.scenario === state.protectionCase.productScenario
          && retained.protectionCase.fheCaseId === state.protectionCase.fheCaseId
          && retained.manifestDigest === state.evidence?.manifestDigest ? state : null;
      } catch {
        return null;
      }
    case "ABORTED":
      return state;
  }
}

async function reconcileState(runtime: ProtectionRuntime, state: InternalState): Promise<InternalState> {
  const journal = readOperationJournal(runtime.runRoot, state.runId);
  const last = journal.records.at(-1);
  if (last?.outcome === "ABORTED" && state.stage !== "ABORTED") {
    return saveState(runtime, { ...state, stage: "ABORTED", abortedReason: last.outcomeReason ?? "OPERATION_ABORTED" });
  }
  const pending = pendingOperation(runtime.runRoot, state.runId);
  const inspection = await inspectCase(runtime, state);
  if (inspection.ambiguous) {
    if (pending === null) throw new ProtectionProductError("Ambiguous cryptographic terminal state", 500);
    return abortState(runtime, state, pending, inspection.ambiguousReason ?? "AMBIGUOUS_CRYPTOGRAPHIC_ACTION");
  }
  if (pending === null) return state;
  const reconstructed = reconcileProtectionProjection(state, pending, inspection);
  if (reconstructed !== null) {
    const saved = saveState(runtime, reconstructed);
    finishOperation(runtime.runRoot, state.runId, pending.operationId, "RECONCILED", runtime.now().toISOString());
    for (const path of [
      join(state.paths.participantPrivateRoot, "participant_a-pledge.json"),
      join(state.paths.participantPrivateRoot, "participant_b-pledge.json"),
    ]) if (existsSync(path)) rmSync(path);
    if (pending.phase === "SUBMITTING_A" || pending.phase === "SUBMITTING_B") {
      const role = pending.phase === "SUBMITTING_A" ? "PARTICIPANT_A" : "PARTICIPANT_B";
      const key = participantKeyPaths(state)[role];
      if (existsSync(key)) rmSync(key);
    }
    return saved;
  }
  if (pending.phase === "EVALUATING" && inspection.evaluationAdmission) {
    return abortState(runtime, state, pending, "IRREVERSIBLE_EVALUATION_WITHOUT_TERMINAL_ARTIFACT");
  }
  if (pending.phase === "RELEASING" && inspection.releaseAdmission) {
    return abortState(runtime, state, pending, "IRREVERSIBLE_RELEASE_WITHOUT_TERMINAL_RESULT");
  }
  return state;
}

async function loadState(runtime: ProtectionRuntime, runId: string): Promise<InternalState> {
  return reconcileState(runtime, loadStateRaw(runtime, runId));
}

async function runJSON<T>(runtime: ProtectionRuntime, binary: keyof typeof BINARIES, args: readonly string[]): Promise<T> {
  try {
    if (runtime.binaryRunner !== undefined) return await runtime.binaryRunner<T>(binary, args);
    const { stdout } = await execFileAsync(pathForBinary(runtime, binary), [...args], {
      cwd: process.cwd(),
      maxBuffer: MAX_PROCESS_BUFFER,
      env: { ...process.env },
    });
    return JSON.parse(stdout) as T;
  } catch (error) {
    throw new ProtectionProductError(`Governed FHE ${binary} operation failed`, 500);
  }
}

function rawParticipantKey(role: "PARTICIPANT_A" | "PARTICIPANT_B", root: string) {
  const path = join(root, `${role.toLowerCase()}.ed25519`);
  if (existsSync(path)) {
    const retained = readFileSync(path);
    if (retained.length !== 64) throw new ProtectionProductError("Retained participant key rejected", 500);
    return { path, publicBase64: retained.subarray(32).toString("base64") };
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  if (publicJwk.x === undefined || privateJwk.d === undefined) {
    throw new ProtectionProductError("Participant key generation failed", 500);
  }
  const decode = (value: string) => Buffer.from(value, "base64url");
  const rawPublic = decode(publicJwk.x);
  const rawPrivate = Buffer.concat([decode(privateJwk.d), rawPublic]);
  writeFileSync(path, rawPrivate, { mode: 0o600, flag: "wx" });
  return { path, publicBase64: rawPublic.toString("base64") };
}

function digestText(domain: string, value: string): Sha256Digest {
  return `sha256:${createHash("sha256").update(`${domain}\0${value}`).digest("hex")}`;
}

function unix(iso: string): number {
  return Math.floor(new Date(iso).valueOf() / 1000);
}

const locks = new Set<string>();
async function exclusive<T>(runId: string, operation: () => Promise<T>): Promise<T> {
  if (locks.has(runId)) throw new ProtectionProductError("A protection operation is already running", 423);
  locks.add(runId);
  try {
    return await operation();
  } finally {
    locks.delete(runId);
  }
}

async function createProtectionCaseRuntime(runtime: ProtectionRuntime, scenario: ProductScenario): Promise<ProtectionCaseView> {
  if (scenario !== "conflict" && scenario !== "no-conflict") {
    throw new ProtectionProductError("Unsupported product scenario", 400);
  }
  const runId = randomUUID();
  const root = join(runtime.runRoot, runId);
  const createdAt = runtime.now().toISOString();
  const protectionCase = createProtectionCaseModel({
    scenario,
    createdAt,
    caseNonce: randomBytes(32).toString("hex"),
  });
  const state: InternalState = {
    schemaVersion: "mordant.protection-execution/2",
    runId,
    stage: "CASE_CREATED",
    protectionCase,
    paths: {
      root,
      publicRoot: join(root, "public"),
      decryptorPrivateRoot: join(root, "decryptor-private"),
      participantPrivateRoot: join(root, "participant-private"),
    },
    startedAtUnix: unix(createdAt),
  };
  mkdirSync(runtime.runRoot, { recursive: true, mode: 0o700 });
  mkdirSync(root, { recursive: false, mode: 0o700 });
  return publicView(saveState(runtime, state));
}

async function preparePrivateMatchRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "MATCH_PREPARED") return publicView(state);
    if (state.stage !== "CASE_CREATED") throw new ProtectionProductError("Private match is already prepared");
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "preparePrivateMatch",
      phase: "PREPARING",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        assetIdentity: state.protectionCase.cleanverseAssetDigest,
        policyId: state.protectionCase.policyId,
      },
      expectedCurrentStage: "CASE_CREATED",
      expectedTargetStage: "MATCH_PREPARED",
      expectedArtifacts: ["case-binding.json", "case-crypto.json", "release-authority.json", "private-case.json"],
      createdAt: runtime.now().toISOString(),
    });
    assertDiskSpace(runtime);
    assertBinaryBuildSpace(runtime);
    await ensureBinaries(runtime);
    assertDiskSpace(runtime);

    mkdirSync(state.paths.publicRoot, { recursive: true, mode: 0o755 });
    mkdirSync(state.paths.decryptorPrivateRoot, { recursive: true, mode: 0o700 });
    mkdirSync(state.paths.participantPrivateRoot, { recursive: true, mode: 0o700 });
    const participantA = rawParticipantKey("PARTICIPANT_A", state.paths.participantPrivateRoot);
    runtime.failpoint("after-participant-key-a");
    const participantB = rawParticipantKey("PARTICIPANT_B", state.paths.participantPrivateRoot);
    runtime.failpoint("after-both-participant-keys");
    const specPath = join(state.paths.participantPrivateRoot, "case-spec.json");
    const createdAtUnix = unix(state.protectionCase.createdAt);
    const spec = {
      caseId: state.protectionCase.fheCaseId,
      assetIdentity: state.protectionCase.cleanverseAssetDigest,
      policyId: state.protectionCase.policyId,
      participantA: {
        id: digestText("MordantProtectionParticipant/v1", `${state.runId}/PARTICIPANT_A`),
        role: "PARTICIPANT_A",
        signingPublicKey: participantA.publicBase64,
      },
      participantB: {
        id: digestText("MordantProtectionParticipant/v1", `${state.runId}/PARTICIPANT_B`),
        role: "PARTICIPANT_B",
        signingPublicKey: participantB.publicBase64,
      },
      caseNonce: digestText("MordantProtectionCaseNonce/v1", state.runId),
      createdAtUnix,
      expiresAtUnix: createdAtUnix + 4 * 60 * 60,
    };
    writeJsonAtomic(specPath, spec);
    runtime.failpoint("after-case-spec");

    const preparedCase = appendEventOnce(state.protectionCase, {
      kind: "HOLDER_SNAPSHOT_RECORDED",
      at: operation.createdAt,
      label: "Record-date holder allocation fixed at 60 / 40 and reserve held separately",
      classification: "PROTOCOL_DOUBLE",
      evidenceRef: state.protectionCase.holderAllocationDigest,
    }, { incidentState: "PRIVATE_MATCH_OPEN" });
    const output = await runJSON<KeygenOutput>(runtime, "keygen", [
      "-mode", "create",
      "-public-root", state.paths.publicRoot,
      "-private-root", state.paths.decryptorPrivateRoot,
      "-spec", specPath,
    ]);
    runtime.failpoint("after-keygen-before-state-save");
    const binding = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "case-binding.json"));
    if (
      binding.caseId !== state.protectionCase.fheCaseId
      || binding.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || binding.policyId !== state.protectionCase.policyId
      || binding.releaseMode !== state.protectionCase.releaseMode
      || binding.parameterProfile !== FHE_PARAMETER_PROFILE
      || binding.circuitId !== FHE_CIRCUIT
    ) {
      throw new ProtectionProductError("Generated FHE case does not match the protection case", 500);
    }
    state = saveState(runtime, {
      ...state,
      stage: "MATCH_PREPARED",
      keygen: output,
      participantKeys: { PARTICIPANT_A: participantA.path, PARTICIPANT_B: participantB.path },
    });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state);
  });
}

function pledgeFor(state: InternalState, role: "PARTICIPANT_A" | "PARTICIPANT_B") {
  const base = state.protectionCase.cleanverseAssetDigest;
  const activeFrom = role === "PARTICIPANT_A" ? 100 : state.protectionCase.productScenario === "conflict" ? 200 : 500;
  const activeUntil = role === "PARTICIPANT_A" ? 400 : state.protectionCase.productScenario === "conflict" ? 500 : 700;
  return {
    activeFrom,
    activeUntil,
    amount: [0, 0, 0, 100_000_000],
    currency: digestText("MordantProtectionCurrency/v1", "aUSDC").slice(7),
    obligationId: digestText("MordantProtectionObligation/v1", `${state.runId}/${role}`).slice(7),
    receivableId: digestText("MordantProtectionReceivable/v1", base).slice(7),
    exclusive: true,
    authorizationCommitment: digestText("MordantProtectionAuthorization/v1", `${state.runId}/${role}`).slice(7),
    privateMetadataCommitment: digestText("MordantProtectionPrivateMetadata/v1", `${state.runId}/${role}`).slice(7),
  };
}

async function finalizeParticipantSubmissions(runtime: ProtectionRuntime, state: InternalState): Promise<InternalState> {
  if (state.stage === "PARTICIPANT_B_SUBMITTED") return state;
  if (state.stage !== "PARTICIPANT_B_PUBLISHED") throw new ProtectionProductError("Participant B publication is required before finalization");
  const operation = beginOperation(runtime.runRoot, state.runId, {
    operation: "finalizeParticipantSubmissions",
    phase: "FINALIZING",
    immutableParameters: {
      caseId: state.protectionCase.fheCaseId,
      participantA: state.submissions?.PARTICIPANT_A?.artifactDigest,
      participantB: state.submissions?.PARTICIPANT_B?.artifactDigest,
    },
    expectedCurrentStage: "PARTICIPANT_B_PUBLISHED",
    expectedTargetStage: "PARTICIPANT_B_SUBMITTED",
    expectedArtifacts: ["case-manifest.json"],
    createdAt: runtime.now().toISOString(),
  });
  await runJSON<Record<string, unknown>>(runtime, "keygen", [
    "-mode", "finalize",
    "-public-root", state.paths.publicRoot,
  ]);
  runtime.failpoint("after-participant-b-finalize-before-state-save");
  const saved = saveState(runtime, { ...state, stage: "PARTICIPANT_B_SUBMITTED" });
  finishOperation(runtime.runRoot, state.runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
  return saved;
}

async function submitParticipantPledgeRuntime(
  runtime: ProtectionRuntime,
  runId: string,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  expectedAssetDigest = CANONICAL_CLEANVERSE_ASSET_DIGEST,
): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    assertProtectionAssetBinding(state.protectionCase, expectedAssetDigest);
    if (role === "PARTICIPANT_B" && state.stage === "PARTICIPANT_B_PUBLISHED") {
      return publicView(await finalizeParticipantSubmissions(runtime, state));
    }
    if (state.submissions?.[role] !== undefined) return publicView(state);
    const expectedStage = role === "PARTICIPANT_A" ? "MATCH_PREPARED" : "PARTICIPANT_A_SUBMITTED";
    if (state.stage !== expectedStage || state.participantKeys === undefined) {
      throw new ProtectionProductError(`Participant ${role} submission is out of order`);
    }
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: role === "PARTICIPANT_A" ? "submitParticipantA" : "submitParticipantB",
      phase: role === "PARTICIPANT_A" ? "SUBMITTING_A" : "SUBMITTING_B",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        assetIdentity: expectedAssetDigest,
        role,
        submissionNonce: digestText("MordantProtectionSubmission/v1", `${state.runId}/${role}`),
      },
      expectedCurrentStage: expectedStage,
      expectedTargetStage: role === "PARTICIPANT_A" ? "PARTICIPANT_A_SUBMITTED" : "PARTICIPANT_B_PUBLISHED",
      expectedArtifacts: [role === "PARTICIPANT_A" ? "submission-a.json" : "submission-b.json"],
      createdAt: runtime.now().toISOString(),
    });
    const pledgePath = join(state.paths.participantPrivateRoot, `${role.toLowerCase()}-pledge.json`);
    writeJsonAtomic(pledgePath, pledgeFor(state, role));
    const createdAtUnix = unix(state.protectionCase.createdAt);
    const output = await runJSON<SubmissionOutput>(runtime, "client", [
      "-public-root", state.paths.publicRoot,
      "-role", role,
      "-signing-key", state.participantKeys[role],
      "-pledge", pledgePath,
      "-submission-nonce", digestText("MordantProtectionSubmission/v1", `${state.runId}/${role}`),
      "-expires-at", String(createdAtUnix + 3 * 60 * 60),
    ]);
    runtime.failpoint("after-submission-publication-before-unlink");
    // Ordinary unlink of Mordant-generated transient plaintext/key files. This
    // is operational cleanup, not a secure-erasure claim.
    rmSync(pledgePath);
    rmSync(state.participantKeys[role]);
    runtime.failpoint("after-submission-unlink-before-state-save");

    const manifestName = role === "PARTICIPANT_A" ? "submission-a.json" : "submission-b.json";
    const artifact = readJson<Record<string, unknown>>(join(state.paths.publicRoot, manifestName));
    if (
      artifact.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || artifact.caseId !== state.protectionCase.fheCaseId
    ) {
      throw new ProtectionProductError("Participant artifact asset binding mismatch", 500);
    }
    const stage: ExecutionStage = role === "PARTICIPANT_A" ? "PARTICIPANT_A_SUBMITTED" : "PARTICIPANT_B_PUBLISHED";
    const event = appendEventOnce(state.protectionCase, {
      kind: `${role}_ENCRYPTED_PLEDGE_RECEIVED`,
      at: operation.createdAt,
      label: `${role === "PARTICIPANT_A" ? "Participant A" : "Participant B"} encrypted pledge received`,
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.artifactDigest,
    });
    state = { ...state, stage, protectionCase: event, submissions: { ...state.submissions, [role]: output } };
    state = saveState(runtime, state);
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    if (role === "PARTICIPANT_B") state = await finalizeParticipantSubmissions(runtime, state);
    return publicView(state);
  });
}

async function evaluatePrivateConflictRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "EVALUATED") return publicView(state);
    if (state.stage !== "PARTICIPANT_B_SUBMITTED") throw new ProtectionProductError("Both encrypted submissions are required");
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "evaluatePrivateConflict",
      phase: "EVALUATING",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        participantA: state.submissions?.PARTICIPANT_A?.artifactDigest,
        participantB: state.submissions?.PARTICIPANT_B?.artifactDigest,
      },
      expectedCurrentStage: "PARTICIPANT_B_SUBMITTED",
      expectedTargetStage: "EVALUATED",
      expectedArtifacts: ["evaluation-admitted.json", "evaluated-conflict.json", "evaluation-completed.json"],
      createdAt: runtime.now().toISOString(),
    });
    const output = await runJSON<EvaluationOutput>(runtime, "evaluator", ["-public-root", state.paths.publicRoot]);
    runtime.failpoint("after-evaluation-completion-before-state-save");
    const artifact = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "evaluated-conflict.json"));
    if (
      artifact.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || artifact.caseId !== state.protectionCase.fheCaseId
    ) {
      throw new ProtectionProductError("Evaluated artifact asset binding mismatch", 500);
    }
    const protectionCase = appendEventOnce(state.protectionCase, {
      kind: "FHE_EVALUATION_COMPLETE",
      at: operation.createdAt,
      label: "Fixed N15 BGV conflict circuit evaluated without an evaluator decryption key",
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.artifactDigest,
    }, { incidentState: "EVALUATED" });
    state = saveState(runtime, { ...state, stage: "EVALUATED", protectionCase, evaluation: output });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state);
  });
}

async function releaseGovernedResultRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "RELEASED" && state.release !== undefined) return publicView(state);
    if (state.stage !== "EVALUATED") throw new ProtectionProductError("FHE evaluation is not complete");
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "releaseGovernedResult",
      phase: "RELEASING",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        evaluatedArtifactDigest: state.evaluation?.artifactDigest,
        releaseMode: state.protectionCase.releaseMode,
        releaseOrdinal: 1,
      },
      expectedCurrentStage: "EVALUATED",
      expectedTargetStage: "RELEASED",
      expectedArtifacts: ["release-admitted.json", "retained-governed-result.json", "governed-conflict-result.json"],
      createdAt: runtime.now().toISOString(),
    });
    const output = await runJSON<ReleaseOutput>(runtime, "decryptor", [
      "-public-root", state.paths.publicRoot,
      "-private-root", state.paths.decryptorPrivateRoot,
    ]);
    runtime.failpoint("after-release-publication-before-state-save");
    if (
      output.releaseMode !== state.protectionCase.releaseMode
      || output.conflict !== (state.protectionCase.productScenario === "conflict")
    ) {
      throw new ProtectionProductError("Governed release does not match the protection scenario", 500);
    }
    const result = readJson<GovernedSignedResult>(join(state.paths.publicRoot, "governed-conflict-result.json"));
    verifyGovernedResultSignature(result);
    const pins = output.trustedRecoursePins;
    if (
      result.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || result.caseId !== state.protectionCase.fheCaseId
      || result.releaseMode !== state.protectionCase.releaseMode
      || governedResultDigest(result) !== output.resultDigest
      || result.conflict !== output.conflict
      || result.participantArtifactDigests[0] !== pins.participantArtifactDigestA
      || result.participantArtifactDigests[1] !== pins.participantArtifactDigestB
      || result.evaluatedArtifactDigest !== pins.evaluatedArtifactDigest
      || result.resultCiphertextDigest !== pins.recomputedResultCiphertextDigest
      || result.resultCiphertextCommitment !== pins.resultCiphertextCommitment
      || result.sourceProvenance !== pins.decryptorProvenance
      || result.releaseAuthorityId !== pins.releaseAuthorityId
    ) {
      throw new ProtectionProductError("Governed result asset binding mismatch", 500);
    }
    let protectionCase = appendEventOnce(state.protectionCase, {
      kind: "GOVERNED_RECOMPUTATION_VERIFIED",
      at: operation.createdAt,
      label: "Governed decryptor independently recomputed the fixed circuit",
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.trustedRecoursePins.recomputedResultCiphertextDigest,
    });
    protectionCase = appendEventOnce(protectionCase, {
      kind: output.conflict ? "SIGNED_CONFLICT_CONFIRMED" : "SIGNED_CONFLICT_CLEARED",
      at: operation.createdAt,
      label: output.conflict ? "Signed Boolean confirmed a conflicting pledge" : "Signed Boolean cleared the conflicting-pledge check",
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.resultDigest,
    }, { incidentState: output.conflict ? "CONFLICT_CONFIRMED" : "CLEARED" });
    state = saveState(runtime, { ...state, stage: "RELEASED", protectionCase, release: output });
    finishOperation(runtime.runRoot, runId, operation.operationId, output.exactRetry ? "RECONCILED" : "COMPLETED", runtime.now().toISOString());
    return publicView(state);
  });
}

async function openRecourseCaseRuntime(
  runtime: ProtectionRuntime,
  runId: string,
  expectedAssetDigest = CANONICAL_CLEANVERSE_ASSET_DIGEST,
): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    assertProtectionAssetBinding(state.protectionCase, expectedAssetDigest);
    if (
      state.recourse !== undefined
      && ["RECOURSE_OPENED", "CHRONOLOGY_COMPLETE", "COMPLETE"].includes(state.stage)
    ) {
      return publicView(state);
    }
    if (state.stage !== "RELEASED" || state.release === undefined) {
      throw new ProtectionProductError("A signed governed result is required");
    }
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "openRecourseCase",
      phase: "OPENING_RECOURSE",
      immutableParameters: {
        assetIdentity: state.protectionCase.cleanverseAssetDigest,
        caseId: state.protectionCase.fheCaseId,
        expectedPins: state.release.trustedRecoursePins,
        recordDateUnix: unix(state.protectionCase.holderRecordDate),
        holderAllocationDigest: state.protectionCase.holderAllocationDigest,
      },
      expectedCurrentStage: "RELEASED",
      expectedTargetStage: "RECOURSE_OPENED",
      fixedNowUnix: Math.floor(runtime.now().valueOf() / 1000),
      expectedArtifacts: state.release.conflict ? ["recourse-record.json", "recourse-outcome.json"] : ["recourse-outcome.json"],
      createdAt: runtime.now().toISOString(),
    });
    const requestPath = join(state.paths.root, "recourse-request.json");
    const nowUnix = operation.fixed.nowUnix;
    if (nowUnix === null) throw new ProtectionProductError("Fixed recourse timestamp is unavailable", 500);
    writeJsonAtomic(requestPath, {
      assetIdentity: state.protectionCase.cleanverseAssetDigest,
      caseId: state.protectionCase.fheCaseId,
      expectedPins: state.release.trustedRecoursePins,
      recordDateUnix: unix(state.protectionCase.holderRecordDate),
      holderAllocationDigest: state.protectionCase.holderAllocationDigest,
      nowUnix,
    });
    const recourse = await runJSON<NonNullable<InternalState["recourse"]>>(runtime, "recourse", [
      "-mode", "recourse",
      "-public-root", state.paths.publicRoot,
      "-request", requestPath,
    ]);
    writeJsonAtomic(join(state.paths.root, "recourse-outcome.json"), recourse);
    runtime.failpoint("after-recourse-publication-before-state-save");
    if (existsSync(requestPath)) rmSync(requestPath);
    if (state.release.conflict !== recourse.opened) {
      throw new ProtectionProductError("Recourse admission does not match the signed Boolean", 500);
    }
    let protectionCase = state.protectionCase;
    if (recourse.opened) {
      const deadlineUnix = Number(recourse.record?.cureDeadlineUnix);
      const cureDeadline = new Date(deadlineUnix * 1000).toISOString();
      protectionCase = appendEventOnce(protectionCase, {
        kind: "CURE_WINDOW_OPENED",
        at: operation.createdAt,
        label: "Record-date holders remain fixed while the cure / dispute window runs",
        classification: "PROTOCOL_DOUBLE",
        evidenceRef: state.protectionCase.holderAllocationDigest,
      }, { cureDeadline, recourseState: "CURE_WINDOW" });
    } else {
      protectionCase = appendEventOnce(protectionCase, {
        kind: "RECOURSE_REFUSED",
        at: operation.createdAt,
        label: "A signed false result cannot open conflicting-pledge recourse",
        classification: "PROTOCOL_DOUBLE",
        evidenceRef: state.release.resultDigest,
      }, { recourseState: "REFUSED" });
    }
    state = saveState(runtime, { ...state, stage: "RECOURSE_OPENED", protectionCase, recourse });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state);
  });
}

async function completeCureChronologyRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (
      state.stage !== "RECOURSE_OPENED"
      || !state.recourse?.opened
      || state.protectionCase.cureDeadline === null
    ) {
      throw new ProtectionProductError("No conflict cure window is open");
    }
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "completeCureChronology",
      phase: "ADVANCING_CURE",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        cureDeadline: state.protectionCase.cureDeadline,
        resultDigest: state.release?.resultDigest,
      },
      expectedCurrentStage: "RECOURSE_OPENED",
      expectedTargetStage: "CHRONOLOGY_COMPLETE",
      expectedArtifacts: ["execution.json"],
      createdAt: runtime.now().toISOString(),
    });
    const protectionCase = appendEventOnce(state.protectionCase, {
      kind: "RECOURSE_AVAILABLE_AFTER_CURE",
      at: new Date(new Date(state.protectionCase.cureDeadline).valueOf() + 1_000).toISOString(),
      label: "Local chronology reached the cure deadline; governed recourse is available",
      classification: "PROTOCOL_DOUBLE",
      evidenceRef: state.release?.resultDigest,
    }, { recourseState: "AVAILABLE" });
    state = saveState(runtime, { ...state, stage: "CHRONOLOGY_COMPLETE", protectionCase });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state);
  });
}

function digestPublicFile(path: string): Sha256Digest {
  const data = readFileSync(path);
  const canonical = data.at(-1) === 0x0a ? data.subarray(0, data.length - 1) : data;
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function buildProtectionEvidence(
  state: InternalState,
  governedFheEvidence: GovernedFhePublicEvidence,
  generatedAt: string,
): MordantProtectionEvidence {
  if (
    state.keygen === undefined || state.submissions?.PARTICIPANT_A === undefined
    || state.submissions.PARTICIPANT_B === undefined || state.evaluation === undefined
    || state.release === undefined || state.recourse === undefined
  ) {
    throw new ProtectionProductError("The complete governed FHE run is required", 500);
  }
  if (!/^[0-9a-f]{40}$/.test(SOURCE_COMMIT)) {
    throw new ProtectionProductError("Exact product source commit is required for evidence export", 500);
  }
  const binding = readJson<FheCaseBinding>(join(state.paths.publicRoot, "case-binding.json"));
  const signatureA = readJson<ParticipantBindingSignature>(join(state.paths.publicRoot, "binding-signature-a.json"));
  const signatureB = readJson<ParticipantBindingSignature>(join(state.paths.publicRoot, "binding-signature-b.json"));
  const evaluated = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "evaluated-conflict.json"));
  const result = readJson<GovernedSignedResult>(join(state.paths.publicRoot, "governed-conflict-result.json"));
  const publicKey = (readJson<Record<string, unknown>>(join(state.paths.publicRoot, "case-crypto.json")).publicKey ?? {}) as Record<string, unknown>;
  const participants = [binding.participantA, binding.participantB] as const;
  const resultCiphertext = (evaluated.resultCiphertext ?? {}) as Record<string, unknown>;
  const recourseRecord = (state.recourse.record ?? null) as PublicRecourseRecord | null;
  const base: Omit<MordantProtectionEvidence, "manifestDigest"> = {
    schemaVersion: "mordant.protection-evidence/2",
    runId: state.runId,
    sourceCommit: SOURCE_COMMIT,
    governedFheCommit: GOVERNED_FHE_COMMIT,
    scenario: state.protectionCase.productScenario,
    cleanverseAsset: state.protectionCase.cleanverseAsset,
    cleanverseAssetDigest: state.protectionCase.cleanverseAssetDigest,
    sourceClassifications: [
      { subject: "Cleanverse MINV01 asset record", classification: "LIVE_OBSERVED", detail: "Retained M-11 issuance and readback evidence" },
      { subject: "Cleanverse documentation version", classification: "DOCUMENTED", detail: "Retained manual versioned transcription; not classified as on-chain" },
      { subject: "N15 BGV evaluation and governed release", classification: "LOCAL_EXECUTION", detail: "Real single-host subprocess execution" },
      { subject: "Recourse admission and chronology", classification: "PROTOCOL_DOUBLE", detail: "Accepted local governed-FHE recourse adapter; no live settlement" },
      { subject: "Protected amount and private pledge contents", classification: "FIXTURE", detail: "Synthetic hackathon scenario" },
      { subject: "Legal issuer identity and production custody", classification: "UNPROVEN", detail: "Not established by the retained evidence" },
    ],
    protectionCase: state.protectionCase,
    participantPublicIdentities: [
      { role: "PARTICIPANT_A", id: participants[0].id, signingPublicKey: participants[0].signingPublicKey },
      { role: "PARTICIPANT_B", id: participants[1].id, signingPublicKey: participants[1].signingPublicKey },
    ],
    caseAuthorization: {
      binding,
      bindingDigest: state.keygen.bindingDigest,
      participantSignatures: [signatureA, signatureB],
    },
    fhe: {
      caseId: state.protectionCase.fheCaseId,
      assetIdentity: state.protectionCase.cleanverseAssetDigest,
      caseBindingDigest: state.keygen.bindingDigest,
      profile: FHE_PARAMETER_PROFILE,
      circuitId: FHE_CIRCUIT,
      circuitVersion: binding.circuitVersion,
      circuitDigest: binding.circuitDigest,
      publicKey: {
        path: String(publicKey.path),
        sha256: publicKey.sha256 as Sha256Digest,
        length: Number(publicKey.length),
      },
      evaluationKeyManifestDigest: binding.evaluationKeyManifestDigest,
      participantArtifactDigests: [
        state.submissions.PARTICIPANT_A.artifactDigest,
        state.submissions.PARTICIPANT_B.artifactDigest,
      ],
      evaluatedArtifactDigest: state.evaluation.artifactDigest,
      resultCiphertext: {
        path: String(resultCiphertext.path),
        sha256: resultCiphertext.sha256 as Sha256Digest,
        length: Number(resultCiphertext.length),
      },
      resultCiphertextCommitment: evaluated.resultCiphertextCommitment as Sha256Digest,
      evaluatorProvenance: evaluated.evaluatorProvenance as Sha256Digest,
      independentlyRecomputedResultDigest: state.release.trustedRecoursePins.recomputedResultCiphertextDigest,
    },
    governedResult: { digest: state.release.resultDigest, ...result },
    chronology: {
      recordDate: state.protectionCase.holderRecordDate,
      holderAllocationDigest: state.protectionCase.holderAllocationDigest,
      cureDeadline: state.protectionCase.cureDeadline,
      events: state.protectionCase.timeline,
    },
    recourse: {
      classification: "PROTOCOL_DOUBLE",
      opened: state.recourse.opened,
      refusedReason: state.recourse.reason ?? null,
      recordDigest: recourseRecord === null
        ? null
        : digestPublicFile(join(state.paths.publicRoot, "recourse-record.json")),
      record: recourseRecord,
    },
    originalReceivablePreservation: {
      state: "OUTSTANDING_INTACT",
      principalMinorUnits: "110000000",
      units: "100000000",
      reserveAccountingSeparate: true,
      claimBurnedOrTransferredByProtection: false,
    },
    governedFheEvidence,
    generatedAt,
  };
  const evidence: MordantProtectionEvidence = { ...base, manifestDigest: protectionEvidenceDigest(base) };
  assertPublicProtectionEvidence(evidence);
  return evidence;
}

async function exportProtectionEvidenceRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "COMPLETE" && state.evidence !== undefined) return publicView(state);
    const expectedStage = state.protectionCase.productScenario === "conflict" ? "CHRONOLOGY_COMPLETE" : "RECOURSE_OPENED";
    if (state.stage !== expectedStage || state.release === undefined || state.keygen === undefined) {
      throw new ProtectionProductError("The product journey is not complete");
    }
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "exportProtectionEvidence",
      phase: "EXPORTING",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        resultDigest: state.release.resultDigest,
        scenario: state.protectionCase.productScenario,
      },
      expectedCurrentStage: expectedStage,
      expectedTargetStage: "COMPLETE",
      fixedNowUnix: Math.floor(runtime.now().valueOf() / 1000),
      expectedArtifacts: ["evidence.json", "protection-evidence.json"],
      createdAt: runtime.now().toISOString(),
    });
    const measurementsPath = join(state.paths.root, "measurements.json");
    const report = state.keygen.report;
    writeJsonAtomic(measurementsPath, {
      keyGeneration: report,
      submissions: [
        {
          duration: state.submissions?.PARTICIPANT_A?.durationNanos ?? 0,
          ciphertextBytes: state.submissions?.PARTICIPANT_A?.ciphertextBytes ?? 0,
          artifactBytes: state.submissions?.PARTICIPANT_A?.artifactBytes ?? 0,
        },
        {
          duration: state.submissions?.PARTICIPANT_B?.durationNanos ?? 0,
          ciphertextBytes: state.submissions?.PARTICIPANT_B?.ciphertextBytes ?? 0,
          artifactBytes: state.submissions?.PARTICIPANT_B?.artifactBytes ?? 0,
        },
      ],
      evaluation: {
        duration: state.evaluation?.durationNanos ?? 0,
        resultCiphertextBytes: state.evaluation?.resultBytes ?? 0,
        artifactBytes: state.evaluation?.artifactBytes ?? 0,
      },
      release: {
        duration: state.release.durationNanos,
        resultBytes: state.release.resultBytes,
        exactRetry: state.release.exactRetry,
        trustedRecoursePins: state.release.trustedRecoursePins,
      },
      completeDuration: ((operation.fixed.nowUnix ?? state.startedAtUnix) - state.startedAtUnix) * 1_000_000_000,
      peakRssBytes: 0,
    });
    const governedFheEvidence = await runJSON<GovernedFhePublicEvidence>(runtime, "recourse", [
      "-mode", "evidence",
      "-public-root", state.paths.publicRoot,
      "-request", measurementsPath,
    ]);
    if (existsSync(measurementsPath)) rmSync(measurementsPath);
    const evidence = buildProtectionEvidence(state, governedFheEvidence, operation.createdAt);
    writeJsonAtomic(join(state.paths.root, "protection-evidence.json"), evidence, 0o644);
    runtime.failpoint("after-evidence-publication-before-state-save");
    state = saveState(runtime, { ...state, stage: "COMPLETE", evidence });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state);
  });
}

async function readProtectionCaseRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return publicView(await loadState(runtime, runId));
}

function loadImportedProtectionEvidenceRuntime(runtime: ProtectionRuntime, scenario: ProductScenario = "conflict"): MordantProtectionEvidence {
  const path = join(runtime.importedEvidenceRoot, `${scenario}.json`);
  if (!existsSync(path)) throw new ProtectionProductError("Imported protection evidence is unavailable", 503);
  const evidence = readJson<MordantProtectionEvidence>(path);
  assertPublicProtectionEvidence(evidence);
  return evidence;
}

async function retainProtectionEvidenceRuntime(runtime: ProtectionRuntime, runId: string, destination: string): Promise<string> {
  const state = await loadState(runtime, runId);
  if (state.stage !== "COMPLETE" || state.evidence === undefined) {
    throw new ProtectionProductError("Only complete public evidence may be retained");
  }
  const allowed = resolve(runtime.importedEvidenceRoot, `${state.protectionCase.productScenario}.json`);
  if (resolve(destination) !== allowed) throw new ProtectionProductError("Evidence destination rejected", 400);
  const operation = beginOperation(runtime.runRoot, runId, {
    operation: "retainProtectionEvidence",
    phase: "RETAINING",
    immutableParameters: {
      destination: allowed,
      scenario: state.protectionCase.productScenario,
      caseId: state.protectionCase.fheCaseId,
      manifestDigest: state.evidence.manifestDigest,
    },
    expectedCurrentStage: "COMPLETE",
    expectedTargetStage: "COMPLETE",
    expectedArtifacts: [allowed],
    createdAt: runtime.now().toISOString(),
  });
  mkdirSync(runtime.importedEvidenceRoot, { recursive: true });
  if (existsSync(allowed)) {
    const prior = readJson<MordantProtectionEvidence>(allowed);
    try {
      assertPublicProtectionEvidence(prior);
    } catch {
      finishOperation(runtime.runRoot, runId, operation.operationId, "ABORTED", runtime.now().toISOString(), "RETAINED_EVIDENCE_INVALID");
      throw new ProtectionProductError("Existing retained evidence is invalid and was not overwritten", 409);
    }
    if (
      prior.scenario !== state.protectionCase.productScenario
      || prior.protectionCase.fheCaseId !== state.protectionCase.fheCaseId
      || prior.manifestDigest !== state.evidence.manifestDigest
    ) {
      finishOperation(runtime.runRoot, runId, operation.operationId, "ABORTED", runtime.now().toISOString(), "RETAINED_EVIDENCE_CASE_MISMATCH");
      throw new ProtectionProductError("A different retained case was not overwritten", 409);
    }
    finishOperation(runtime.runRoot, runId, operation.operationId, "RECONCILED", runtime.now().toISOString());
    return allowed;
  }
  writeDurableJsonAtomic(allowed, state.evidence, 0o644, () => runtime.failpoint("during-retention-before-atomic-rename"));
  const retained = readJson<MordantProtectionEvidence>(allowed);
  assertPublicProtectionEvidence(retained);
  if (
    retained.scenario !== state.protectionCase.productScenario
    || retained.protectionCase.fheCaseId !== state.protectionCase.fheCaseId
    || retained.manifestDigest !== state.evidence.manifestDigest
  ) throw new ProtectionProductError("Retained evidence readback mismatch", 500);
  finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
  return allowed;
}

async function validateRetainedPublicArtifactsRuntime(runtime: ProtectionRuntime, runId: string): Promise<Readonly<{
  evidenceDigest: Sha256Digest;
  governedResultDigest: Sha256Digest;
  privateMarkersAbsent: true;
}>> {
  const state = await loadState(runtime, runId);
  if (state.evidence === undefined) throw new ProtectionProductError("Evidence not exported");
  const publicFiles = [
    join(state.paths.root, "protection-evidence.json"),
    join(state.paths.publicRoot, "evidence.json"),
    join(state.paths.publicRoot, "governed-conflict-result.json"),
  ];
  const publicText = publicFiles.map((path) => readFileSync(path, "utf8")).join("\n").toLowerCase();
  for (const marker of ["secret-key.bin", "decryptor-signing-key.bin", "private-root", "receivableid"]) {
    if (publicText.includes(marker)) throw new ProtectionProductError(`Public evidence contains ${marker}`, 500);
  }
  return {
    evidenceDigest: state.evidence.manifestDigest,
    governedResultDigest: digestPublicFile(join(state.paths.publicRoot, "governed-conflict-result.json")),
    privateMarkersAbsent: true,
  };
}

export function createProtectionOrchestrator(options: ProtectionRuntimeOptions = {}) {
  const runtime = runtimeFrom(options);
  return Object.freeze({
    createProtectionCase: (scenario: ProductScenario) => createProtectionCaseRuntime(runtime, scenario),
    preparePrivateMatch: (runId: string) => preparePrivateMatchRuntime(runtime, runId),
    submitParticipantPledge: (
      runId: string,
      role: "PARTICIPANT_A" | "PARTICIPANT_B",
      expectedAssetDigest = CANONICAL_CLEANVERSE_ASSET_DIGEST,
    ) => submitParticipantPledgeRuntime(runtime, runId, role, expectedAssetDigest),
    evaluatePrivateConflict: (runId: string) => evaluatePrivateConflictRuntime(runtime, runId),
    releaseGovernedResult: (runId: string) => releaseGovernedResultRuntime(runtime, runId),
    openRecourseCase: (runId: string, expectedAssetDigest = CANONICAL_CLEANVERSE_ASSET_DIGEST) => (
      openRecourseCaseRuntime(runtime, runId, expectedAssetDigest)
    ),
    completeCureChronology: (runId: string) => completeCureChronologyRuntime(runtime, runId),
    exportProtectionEvidence: (runId: string) => exportProtectionEvidenceRuntime(runtime, runId),
    readProtectionCase: (runId: string) => readProtectionCaseRuntime(runtime, runId),
    loadImportedProtectionEvidence: (scenario: ProductScenario = "conflict") => loadImportedProtectionEvidenceRuntime(runtime, scenario),
    retainProtectionEvidence: (runId: string, destination: string) => retainProtectionEvidenceRuntime(runtime, runId, destination),
    validateRetainedPublicArtifacts: (runId: string) => validateRetainedPublicArtifactsRuntime(runtime, runId),
  });
}

const DEFAULT_ORCHESTRATOR = createProtectionOrchestrator();

export const createProtectionCase = DEFAULT_ORCHESTRATOR.createProtectionCase;
export const preparePrivateMatch = DEFAULT_ORCHESTRATOR.preparePrivateMatch;
export const submitParticipantPledge = DEFAULT_ORCHESTRATOR.submitParticipantPledge;
export const evaluatePrivateConflict = DEFAULT_ORCHESTRATOR.evaluatePrivateConflict;
export const releaseGovernedResult = DEFAULT_ORCHESTRATOR.releaseGovernedResult;
export const openRecourseCase = DEFAULT_ORCHESTRATOR.openRecourseCase;
export const completeCureChronology = DEFAULT_ORCHESTRATOR.completeCureChronology;
export const exportProtectionEvidence = DEFAULT_ORCHESTRATOR.exportProtectionEvidence;
export const readProtectionCase = DEFAULT_ORCHESTRATOR.readProtectionCase;
export const loadImportedProtectionEvidence = DEFAULT_ORCHESTRATOR.loadImportedProtectionEvidence;
export const retainProtectionEvidence = DEFAULT_ORCHESTRATOR.retainProtectionEvidence;
export const validateRetainedPublicArtifacts = DEFAULT_ORCHESTRATOR.validateRetainedPublicArtifacts;
