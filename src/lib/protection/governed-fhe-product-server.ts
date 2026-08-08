import "server-only";

import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import {
  constants as fsConstants,
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  statfsSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  type Sha256Digest,
} from "./cleanverse-asset";
import { currentCustomReceiptDisclosures } from "../custom-supervised-receipt-disclosures";
import {
  appendProtectionEvent,
  assertProtectionAssetBinding,
  createProtectionCase as createProtectionCaseModel,
  FHE_CIRCUIT,
  FHE_PARAMETER_PROFILE,
  PROTECTION_FIXTURE_CLASSIFICATION,
  protectionBindingFromCase,
  type MordantProtectionCase,
  type ProductScenario,
} from "./protection-case";
import {
  EXPECTED_GOVERNED_FHE_COMMIT,
  assertPublicProtectionEvidence,
  governedResultDigest,
  protectionBindingDigest,
  protectionEvidenceDigest,
  resolveProtectionExportSourceCommit,
  verifyGovernedResultSignature,
  type FheCaseBinding,
  type CanonicalChronologyEvent,
  type GovernedFhePublicEvidence,
  type GovernedSignedResult,
  type MordantProtectionEvidence,
  type MordantRecourseAttestation,
  type ParticipantBindingSignature,
  type ProtectionBindingSignature,
  type PublicRecourseRecord,
} from "./protection-evidence";
import {
  projectPublicProtectionCase,
  verifyAndProjectPublicProtectionEvidence,
  type PublicProtectionCaseProjection,
  type VerifiedPublicProtectionEvidence,
} from "./protection-public-view";
import {
  beginOperation,
  finishOperation,
  pendingOperation,
  readOperationJournal,
  writeDurableJsonAtomic,
  type ProductOperationRecord,
} from "./protection-operation-journal";
import {
  assertSupervisedPledgeWindow,
  assertSupervisedPledgeWindows,
  type SupervisedPledgeWindow,
  type SupervisedPledgeWindows,
} from "./supervised-pledge-windows";
import { participantClaimCommitment } from "./participant-authorization";
import { readAdmission } from "./participant-admission-store";
import {
  MONAD_TESTNET_CHAIN_ID,
  loadCanonicalRecourseConfiguration,
} from "./adapter-compatibility";
import {
  CUSTOM_SUPERVISED_VIEW_SCHEMA,
  type CustomSupervisedProtectionView,
} from "./custom-supervised-view";
import {
  CUSTOM_SUPERVISED_RECEIPT_SCHEMA,
  assertCustomSupervisedReceipt,
  customSupervisedReceiptDigest,
  type CustomSupervisedProtectionReceipt,
} from "./custom-supervised-receipt";
import {
  CUSTOM_SUPERVISED_BINDING_SCHEMA,
  CUSTOM_SUPERVISED_EXECUTION_VARIANT,
  assertNeutralCustomBinding,
  customSupervisedBindingDigestV2,
  type MordantCustomSupervisedBindingV2,
} from "./custom-supervised-v2";
import {
  assertDirectParticipantBridgeEvidence,
  buildDirectParticipantBridgeEvidence,
  type DirectParticipantAdmissionFact,
} from "./direct-participant-bridge-evidence";

const execFileAsync = promisify(execFile);

export const PRODUCT_STORAGE = Object.freeze({
  estimatedCaseBytes: 576_716_800,
  twoCaseRetainedBytes: 1_153_433_600,
  retainedEvidenceBytes: 131_072,
  safetyMarginBytes: 1_610_612_736,
  binaryAndCacheBytes: 805_306_368,
});

const GOVERNED_FHE_COMMIT = EXPECTED_GOVERNED_FHE_COMMIT;
const MAX_PROCESS_BUFFER = 8 << 20;

const BINARIES = Object.freeze({
  keygen: "mordant-fhe-keygen",
  client: "mordant-fhe-client",
  evaluator: "mordant-fhe-evaluator",
  decryptor: "mordant-fhe-decryptor",
  recourse: "mordant-fhe-recourse",
  inspect: "mordant-fhe-inspect",
  retain: "mordant-fhe-retain",
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
  protectionBindingDigest: Sha256Digest;
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
  foundationPrivateComplete: boolean;
  releasePrivateComplete: boolean;
  release?: Omit<ReleaseOutput, "durationNanos">;
  recourse?: PublicRecourseRecord;
  protectionBindingDigest?: Sha256Digest;
  recourseAttestationDigest?: Sha256Digest;
  evidence?: GovernedFhePublicEvidence;
  ambiguous: boolean;
  ambiguousReason?: string;
}>;

export type ProtectionRuntimeOptions = Readonly<{
  runRoot?: string;
  binRoot?: string;
  goRoot?: string;
  importedEvidenceRoot?: string;
  retentionRoot?: string;
  now?: () => Date;
  failpoint?: (name: string) => void;
  binaryRunner?: <T>(binary: keyof typeof BINARIES, args: readonly string[]) => Promise<T>;
  statfsAvailableBytes?: (root: string) => number;
  skipBinaryBuild?: boolean;
  expectedSourceCommit?: string;
  /**
   * Direct wallet admission is an opt-in server capability. It is deliberately
   * off for a normal custom/FHE orchestrator, including the module default.
   */
  directParticipantAdmissionEnabled?: boolean;
}>;

type ProtectionRuntime = Readonly<{
  runRoot: string;
  binRoot: string;
  goRoot: string;
  importedEvidenceRoot: string;
  retentionRoot: string;
  now: () => Date;
  failpoint: (name: string) => void;
  binaryRunner?: ProtectionRuntimeOptions["binaryRunner"];
  statfsAvailableBytes?: ProtectionRuntimeOptions["statfsAvailableBytes"];
  skipBinaryBuild: boolean;
  expectedSourceCommit: unknown;
  directParticipantAdmissionEnabled: boolean;
}>;

function runtimeFrom(options: ProtectionRuntimeOptions = {}): ProtectionRuntime {
  const importedEvidenceRoot = resolve(
    options.importedEvidenceRoot
    ?? process.env.MORDANT_PROTECTION_EVIDENCE_ROOT
    ?? join(process.cwd(), "docs", "evidence", "conflicting-pledge-protection"),
  );
  return {
    runRoot: resolve(options.runRoot ?? process.env.MORDANT_PROTECTION_RUN_ROOT ?? join(process.cwd(), ".mordant", "protection")),
    binRoot: resolve(options.binRoot ?? process.env.MORDANT_GOVERNED_FHE_BIN_DIR ?? join(process.cwd(), ".mordant", "governed-fhe-bin")),
    goRoot: resolve(options.goRoot ?? join(process.cwd(), "fhe-lab", "lattigo")),
    importedEvidenceRoot,
    // Imported, reviewable fixtures and locally retained evidence are separate
    // capabilities. Configuring a read root can never make it writable.
    retentionRoot: resolve(
      options.retentionRoot
      ?? process.env.MORDANT_PROTECTION_RETENTION_ROOT
      ?? join(process.cwd(), ".mordant", "protection-retained-evidence"),
    ),
    now: options.now ?? (() => new Date()),
    failpoint: options.failpoint ?? (() => undefined),
    binaryRunner: options.binaryRunner,
    statfsAvailableBytes: options.statfsAvailableBytes,
    skipBinaryBuild: options.skipBinaryBuild ?? false,
    // Capture the independent build/server pin once. Export separately checks
    // the live environment so a changed or missing value cannot rewrite it.
    expectedSourceCommit: options.expectedSourceCommit ?? process.env.MORDANT_PROTECTION_SOURCE_COMMIT,
    directParticipantAdmissionEnabled: options.directParticipantAdmissionEnabled
      ?? process.env.MORDANT_PROTECTION_DIRECT_PARTICIPANT_ADMISSION === "enabled",
  };
}

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
  /**
   * Operator-entered private pledge windows for a supervised local run. Present
   * only for a custom run. This is private execution input: `publicView` never
   * reads it, `beginOperation` never records it, and no error message quotes
   * it. Its only use is writing the transient participant pledge files.
   */
  supervisedPledgeWindows?: SupervisedPledgeWindows;
  /**
   * Role-specific admitted claims, written by the participant admission path.
   *
   * This is the two-wallet replacement for `supervisedPledgeWindows`: instead of
   * one operator entering both windows before anything exists, each participant
   * writes only their own. `claim` is private execution input under exactly the
   * same discipline as the operator windows above: `publicView` never reads it,
   * `customSupervisedView` never reads it, `beginOperation` never records it and
   * no error message quotes it. The durable admission ledger holds only its
   * commitment, so the claim can be pruned while the admission stays provable.
   */
  admittedClaims?: Readonly<Partial<Record<"PARTICIPANT_A" | "PARTICIPANT_B", Readonly<{
    participantWallet: string;
    authorizationDigest: string;
    claimCommitment: string;
    authorizationNonce: string;
    chainId: number;
    issuedAt: number;
    expiresAt: number;
    claim: SupervisedPledgeWindow;
  }>>>>;
  /**
   * Neutral marker for a supervised custom run. Its presence, and nothing about
   * the entered windows, selects the V2 authorization path.
   */
  executionVariant?: typeof CUSTOM_SUPERVISED_EXECUTION_VARIANT;
  /** Terminal artifact of a custom V2 run, in place of V4 evidence. */
  customReceipt?: CustomSupervisedProtectionReceipt;
}>;

export type ProtectionCaseView = Readonly<{
  schemaVersion: "mordant.protection-product-view/1";
  runId: string;
  stage: ExecutionStage;
  nextOperation: string | null;
  protectionCase: PublicProtectionCaseProjection & Readonly<{
    incidentState: MordantProtectionCase["incidentState"];
    cureDeadline: string | null;
    recourseState: MordantProtectionCase["recourseState"];
  }>;
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
  recourse: Readonly<{
    opened: boolean;
    reason: "SIGNED_RESULT_FALSE" | null;
  }> | null;
  evidence: VerifiedPublicProtectionEvidence | null;
  execution: Readonly<{
    fhe: "REAL_BGV_FHE";
    deployment: "LOCAL_SINGLE_HOST";
    webPresentation: "PUBLIC_EVIDENCE_READBACK";
    recourse: "LOCAL_PROTOCOL_DOUBLE";
  }>;
}>;

export type RetainedProtectionEvidenceView = Readonly<{
  schemaVersion: "mordant.retained-protection-view/1";
  runId: string;
  scenario: ProductScenario;
  caseId: Sha256Digest;
  manifestDigest: Sha256Digest;
  evidence: VerifiedPublicProtectionEvidence;
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
  mkdirSync(runtime.binRoot, { recursive: true, mode: 0o700 });
  const names = Object.keys(BINARIES) as Array<keyof typeof BINARIES>;
  // Compiling the FHE binaries on demand is a development affordance. What must
  // never happen in a deployed runtime is shelling out to the Go toolchain, so
  // the refusal belongs to the build itself: a purpose-built worker image ships
  // every binary prebuilt and therefore never reaches it, while the deployed web
  // runtime has none and is refused exactly as before.
  if (names.every((name) => existsSync(pathForBinary(runtime, name)))) return;
  if (process.env.NODE_ENV === "production") {
    throw new ProtectionProductError("Local BGV execution is unavailable in the deployed web runtime.", 404);
  }
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

function readJsonNoFollow<T>(path: string): T {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) throw new ProtectionProductError("Retained evidence path rejected", 400);
    return JSON.parse(readFileSync(descriptor, "utf8")) as T;
  } finally {
    closeSync(descriptor);
  }
}

function assertRunId(runId: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(runId)) {
    throw new ProtectionProductError("Invalid protection run id", 400);
  }
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
  // A retained terminal receipt is restored as immutable evidence. Validate
  // its original digest and exact disclosure contract; the narrow legacy
  // disclosure layout remains accepted without rewriting its covered bytes.
  if (state.customReceipt !== undefined) assertCustomSupervisedReceipt(state.customReceipt);
  return state;
}

function saveState(runtime: ProtectionRuntime, state: InternalState): InternalState {
  writeJsonAtomic(statePath(runtime, state.runId), state);
  return state;
}

/**
 * Stages before a governed release never depend on a scenario, so this branch
 * never has to name one. Reaching RECOURSE_OPENED here would be a defect.
 */
function nextOperationBeforeRelease(stage: ExecutionStage): string | null {
  switch (stage) {
    case "CASE_CREATED": return "preparePrivateMatch";
    case "MATCH_PREPARED": return "submitParticipantPledge:PARTICIPANT_A";
    case "PARTICIPANT_A_SUBMITTED": return "submitParticipantPledge:PARTICIPANT_B";
    case "PARTICIPANT_B_PUBLISHED": return "submitParticipantPledge:PARTICIPANT_B";
    case "PARTICIPANT_B_SUBMITTED": return "evaluatePrivateConflict";
    case "EVALUATED": return "releaseGovernedResult";
    default: return null;
  }
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

/**
 * A custom run is projected into its own schema rather than being forced into
 * the V1 view. Before a verified governed release it carries no scenario at
 * all, which is the honest state: there is nothing to report yet.
 */
function customSupervisedView(state: InternalState): CustomSupervisedProtectionView {
  const governedResult = state.release === undefined ? null : {
    conflict: state.release.conflict,
    digest: state.release.resultDigest,
    releaseMode: "governed-decryptor-v1" as const,
  };
  return {
    schemaVersion: CUSTOM_SUPERVISED_VIEW_SCHEMA,
    runId: state.runId,
    executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT,
    stage: state.stage,
    // The scenario argument is consulted only at RECOURSE_OPENED, which implies
    // a release exists, so the guard is never asked to invent one.
    nextOperation: state.release === undefined
      ? nextOperationBeforeRelease(state.stage)
      : nextOperation(state.stage, terminalScenarioAfterRelease(state)),
    terminalScenario: governedResult === null ? null : (governedResult.conflict ? "conflict" : "no-conflict"),
    protectionCase: {
      cleanverseAssetDigest: state.protectionCase.cleanverseAssetDigest,
      fheCaseId: state.protectionCase.fheCaseId,
      incidentState: state.protectionCase.incidentState,
      recourseState: state.protectionCase.recourseState,
      cureDeadline: state.protectionCase.cureDeadline,
    },
    participantArtifactDigests: {
      participantA: state.submissions?.PARTICIPANT_A?.artifactDigest ?? null,
      participantB: state.submissions?.PARTICIPANT_B?.artifactDigest ?? null,
    },
    evaluatedArtifactDigest: state.evaluation?.artifactDigest ?? null,
    governedResult,
    recourse: state.recourse === undefined ? null : {
      opened: state.recourse.opened,
      reason: state.recourse.reason ?? null,
    },
    receipt: state.customReceipt ?? null,
  };
}

function publicView(state: InternalState, runtime: ProtectionRuntime): ProtectionCaseView {
  const protectionCase = projectPublicProtectionCase(state.protectionCase);
  const view: ProtectionCaseView = {
    schemaVersion: "mordant.protection-product-view/1",
    runId: state.runId,
    stage: state.stage,
    nextOperation: nextOperation(state.stage, state.release === undefined
      ? state.protectionCase.productScenario
      : terminalScenarioAfterRelease(state)),
    protectionCase: {
      ...protectionCase,
      incidentState: state.protectionCase.incidentState,
      cureDeadline: state.protectionCase.cureDeadline,
      recourseState: state.protectionCase.recourseState,
    },
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
    recourse: state.recourse === undefined ? null : {
      opened: state.recourse.opened,
      reason: state.recourse.reason ?? null,
    },
    evidence: state.evidence === undefined
      ? null
      : verifyAndProjectPublicProtectionEvidence(
        state.evidence,
        runtime.expectedSourceCommit,
        localCaseManifestDigest(state),
      ),
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

async function inspectCase(
  runtime: ProtectionRuntime,
  state: InternalState,
  pending: ProductOperationRecord | null,
  allowPrivateInspection: boolean,
): Promise<ProductInspection> {
  await ensureBinaries(runtime);
  const publicInspection = await runJSON<ProductInspection>(runtime, "inspect", [
    "-mode", "public",
    "-public-root", state.paths.publicRoot,
  ]);
  if (
    !allowPrivateInspection || pending === null || publicInspection.ambiguous
    || (pending.phase === "PREPARING" && publicInspection.foundation === undefined)
    || (pending.phase !== "PREPARING" && pending.phase !== "RELEASING")
  ) return publicInspection;
  const privateInspection = await runJSON<ProductInspection>(runtime, "inspect", [
    "-mode", "pending-private",
    "-public-root", state.paths.publicRoot,
    "-private-root", state.paths.decryptorPrivateRoot,
    "-pending-phase", pending.phase,
  ]);
  return {
    ...publicInspection,
    foundationPrivateComplete: privateInspection.foundationPrivateComplete,
    releaseAdmission: privateInspection.releaseAdmission,
    releasePrivateComplete: privateInspection.releasePrivateComplete,
    ambiguous: privateInspection.ambiguous,
    ...(privateInspection.ambiguousReason === undefined ? {} : { ambiguousReason: privateInspection.ambiguousReason }),
  };
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
  runtime: ProtectionRuntime,
  state: InternalState,
  pending: ProductOperationRecord,
  inspection: ProductInspection,
): InternalState | null {
  const at = pending.createdAt;
  switch (pending.phase) {
    case "PREPARING": {
      if (
        inspection.foundation === undefined || !inspection.foundationPrivateComplete
        || inspection.protectionBindingDigest === undefined
      ) return null;
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
        keygen: {
          bindingDigest: inspection.foundation.bindingDigest,
          protectionBindingDigest: inspection.protectionBindingDigest,
          durationNanos: 0,
          report: inspection.foundation.report,
        },
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
      if (inspection.release === undefined || !inspection.releasePrivateComplete) return null;
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
        const recovered = buildProtectionEvidence(
          runtime,
          state,
          inspection.evidence,
          runtime.now().toISOString(),
        );
        writeJsonAtomic(productEvidencePath, recovered, 0o644);
      }
      if (!existsSync(productEvidencePath)) return null;
      const evidence = readJson<MordantProtectionEvidence>(productEvidencePath);
      assertPublicProtectionEvidence(evidence, runtime.expectedSourceCommit, localCaseManifestDigest(state));
      return { ...state, stage: "COMPLETE", evidence };
    }
    case "RETAINING":
      if (typeof pending.immutableParameters.destination !== "string" || !existsSync(pending.immutableParameters.destination)) return null;
      try {
        const retained = readJsonNoFollow<MordantProtectionEvidence>(pending.immutableParameters.destination);
        assertPublicProtectionEvidence(retained, runtime.expectedSourceCommit, localCaseManifestDigest(state));
        return retained.scenario === terminalScenarioAfterRelease(state)
          && retained.protectionCase.fheCaseId === state.protectionCase.fheCaseId
          && retained.manifestDigest === state.evidence?.manifestDigest ? state : null;
      } catch {
        return null;
      }
    case "ABORTED":
      return state;
  }
}

async function reconcileState(runtime: ProtectionRuntime, state: InternalState, allowPrivateInspection = true): Promise<InternalState> {
  const journal = readOperationJournal(runtime.runRoot, state.runId);
  const last = journal.records.at(-1);
  if (last?.outcome === "ABORTED" && state.stage !== "ABORTED") {
    return saveState(runtime, { ...state, stage: "ABORTED", abortedReason: last.outcomeReason ?? "OPERATION_ABORTED" });
  }
  const pending = pendingOperation(runtime.runRoot, state.runId);
  const inspection = await inspectCase(runtime, state, pending, allowPrivateInspection);
  if (inspection.ambiguous) {
    if (pending === null) throw new ProtectionProductError("Ambiguous cryptographic terminal state", 500);
    return abortState(runtime, state, pending, inspection.ambiguousReason ?? "AMBIGUOUS_CRYPTOGRAPHIC_ACTION");
  }
  if (pending === null) return state;
  const reconstructed = reconcileProtectionProjection(runtime, state, pending, inspection);
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
  if (allowPrivateInspection && pending.phase === "RELEASING" && inspection.releaseAdmission) {
    return abortState(runtime, state, pending, "IRREVERSIBLE_RELEASE_WITHOUT_TERMINAL_RESULT");
  }
  return state;
}

async function loadState(runtime: ProtectionRuntime, runId: string, allowPrivateInspection = true): Promise<InternalState> {
  return reconcileState(runtime, loadStateRaw(runtime, runId), allowPrivateInspection);
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
  } catch {
    throw new ProtectionProductError(`Governed FHE ${binary} operation failed`, 500);
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function readRegularNoFollow(path: string): Buffer {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1) throw new ProtectionProductError("Private key path rejected", 500);
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function rawParticipantKey(
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  root: string,
  recoverTruncated: boolean,
) {
  const path = join(root, `${role.toLowerCase()}.ed25519`);
  if (existsSync(path)) {
    const retained = readRegularNoFollow(path);
    if (retained.length === 64) return { path, publicBase64: retained.subarray(32).toString("base64") };
    if (!recoverTruncated) throw new ProtectionProductError("Truncated participant key after foundation admission", 500);
    unlinkSync(path);
    fsyncDirectory(root);
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
  const temporary = join(root, `.mordant-participant-key-${process.pid}-${randomUUID()}.tmp`);
  let descriptor = -1;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, rawPrivate);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    linkSync(temporary, path);
    unlinkSync(temporary);
    fsyncDirectory(root);
  } finally {
    rawPrivate.fill(0);
    if (descriptor >= 0) closeSync(descriptor);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
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

/**
 * The terminal scenario of a supervised custom run exists only once the
 * governed decryptor has released its signed Boolean. Nothing derives it from
 * the entered windows, and asking for it earlier is a programming error rather
 * than a value this function is willing to invent.
 */
/**
 * The pre-execution authorization both participants sign. A V1 run keeps the
 * existing binding untouched. A custom run is authorized under the neutral V2
 * shape, which structurally omits `productScenario`, so nothing about the
 * expected Boolean is signed before the governed decryptor speaks.
 */
function protectionAuthorizationBinding(
  state: InternalState,
): ReturnType<typeof protectionBindingFromCase> | MordantCustomSupervisedBindingV2 {
  if (state.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
    return protectionBindingFromCase(state.protectionCase);
  }
  const protectionCase = state.protectionCase;
  const binding: MordantCustomSupervisedBindingV2 = {
    schemaVersion: CUSTOM_SUPERVISED_BINDING_SCHEMA,
    cleanverseAssetRecordDigest: protectionCase.cleanverseAssetDigest,
    protectionService: protectionCase.service,
    protectionServiceVersion: protectionCase.serviceVersion,
    policyId: protectionCase.policyId,
    policyVersion: protectionCase.policyVersion,
    fixtureClassification: PROTECTION_FIXTURE_CLASSIFICATION,
    protectedAmount: protectionCase.protectedAmount,
    reserveBasisPoints: protectionCase.reserve.basisPoints,
    reserveAmount: { asset: "aUSDC", minorUnits: protectionCase.reserve.minorUnits },
    holderRecordDate: protectionCase.holderRecordDate,
    holderSnapshot: protectionCase.holderSnapshot,
    holderAllocationDigest: protectionCase.holderAllocationDigest,
    caseNonce: protectionCase.caseNonce,
    fheCaseId: protectionCase.fheCaseId,
    governedReleaseMode: protectionCase.releaseMode,
    executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT,
  };
  assertNeutralCustomBinding(binding);
  return binding;
}

function protectionAuthorizationBindingDigest(state: InternalState): Sha256Digest {
  return state.executionVariant === CUSTOM_SUPERVISED_EXECUTION_VARIANT
    ? customSupervisedBindingDigestV2(protectionAuthorizationBinding(state) as MordantCustomSupervisedBindingV2)
    : protectionBindingDigest(protectionBindingFromCase(state.protectionCase));
}

/** Where a direct-participant run's bridge authorization is retained. */
export const DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE = "direct-participant-bridge-evidence.json";

export function directParticipantBridgeEvidencePath(runRoot: string, runId: string): string {
  assertRunId(runId);
  return join(runRoot, runId, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE);
}

function admissionFact(
  runtime: ProtectionRuntime,
  runId: string,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
): DirectParticipantAdmissionFact | null {
  const record = readAdmission(runtime.runRoot, runId, role);
  if (record === null) return null;
  // Only commitments and observations cross over. The admitted claim window is
  // private execution input and is deliberately not carried.
  return Object.freeze({
    role,
    participantWallet: record.participantWallet,
    authorizationDigest: record.authorizationDigest,
    claimCommitment: record.claimCommitment,
    authorizationNonce: record.authorizationNonce,
    chainId: record.chainId,
    eligibilityBlock: record.eligibilityBlock,
  });
}

/**
 * Writes the direct-participant bridge authorization for a completed run.
 *
 * Only a run with two durable wallet admissions produces one: an operator-driven
 * custom run has no admitted wallets and is silently skipped. The governed
 * result is copied from the decryptor's published object as-is and the artifact
 * is verified before it is written, so an unverifiable authorization can never
 * reach the disk.
 */
function persistDirectParticipantBridgeEvidence(
  runtime: ProtectionRuntime,
  state: InternalState,
  receipt: CustomSupervisedProtectionReceipt,
): void {
  const admissionA = admissionFact(runtime, state.runId, "PARTICIPANT_A");
  const admissionB = admissionFact(runtime, state.runId, "PARTICIPANT_B");
  if (admissionA === null || admissionB === null) return;
  if (state.release === undefined || state.keygen === undefined) {
    throw new ProtectionProductError("A complete direct-participant run is required", 500);
  }
  const binding = readJson<FheCaseBinding>(join(state.paths.publicRoot, "case-binding.json"));
  const result = readJson<GovernedSignedResult>(join(state.paths.publicRoot, "governed-conflict-result.json"));
  const pins = state.release.trustedRecoursePins;
  const evidence = buildDirectParticipantBridgeEvidence({
    sourceCommit: receipt.sourceCommit,
    runId: state.runId,
    fheCaseId: state.protectionCase.fheCaseId,
    protectionBindingDigest: protectionAuthorizationBindingDigest(state),
    caseBindingDigest: state.keygen.bindingDigest,
    caseBinding: {
      caseId: binding.caseId,
      assetIdentity: binding.assetIdentity,
      policyId: binding.policyId,
      circuitDigest: binding.circuitDigest,
      parameterFingerprint: binding.parameterFingerprint,
      releaseMode: binding.releaseMode,
      releaseAuthorityId: binding.releaseAuthorityId,
      releaseAuthorityPublicKey: binding.releaseAuthorityPublicKey,
    },
    participants: [admissionA, admissionB],
    participantArtifactDigestA: pins.participantArtifactDigestA,
    participantArtifactDigestB: pins.participantArtifactDigestB,
    evaluatedArtifactDigest: pins.evaluatedArtifactDigest,
    governedResult: result,
    customReceiptDigest: receipt.receiptDigest,
  });
  const canonical = loadCanonicalRecourseConfiguration();
  assertDirectParticipantBridgeEvidence(evidence, {
    sourceCommit: receipt.sourceCommit,
    assetIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    holderA: canonical.participants.holderA,
    holderB: canonical.participants.holderB,
    excludedWallets: [
      canonical.participants.excluded.negativeControl,
      canonical.participants.excluded.uncontrolledApassWallet,
    ],
    runId: state.runId,
  });
  writeJsonAtomic(directParticipantBridgeEvidencePath(runtime.runRoot, state.runId), evidence, 0o600);
}

function buildCustomSupervisedReceipt(
  runtime: ProtectionRuntime,
  state: InternalState,
  governedFheEvidence: GovernedFhePublicEvidence,
  chronology: MordantProtectionEvidence["chronology"],
): CustomSupervisedProtectionReceipt {
  if (state.release === undefined || state.keygen === undefined || state.evaluation === undefined) {
    throw new ProtectionProductError("A complete custom run is required", 500);
  }
  const sourceCommit = resolveProtectionExportSourceCommit(
    runtime.expectedSourceCommit,
    process.env.MORDANT_PROTECTION_SOURCE_COMMIT,
  );
  const pins = state.release.trustedRecoursePins;
  const body: Omit<CustomSupervisedProtectionReceipt, "receiptDigest"> = {
    schemaVersion: CUSTOM_SUPERVISED_RECEIPT_SCHEMA,
    runId: state.runId,
    sourceCommit,
    // A custom run rebuilds the governed-FHE binaries from this checkout, so it
    // pins its own commit rather than the accepted V1 constant.
    governedFheCommit: sourceCommit,
    executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT,
    authorization: {
      protectionBindingSchema: CUSTOM_SUPERVISED_BINDING_SCHEMA,
      protectionBindingDigest: protectionAuthorizationBindingDigest(state),
      fheCaseId: state.protectionCase.fheCaseId,
      caseBindingDigest: state.keygen.protectionBindingDigest,
    },
    execution: {
      participantArtifactDigests: [pins.participantArtifactDigestA, pins.participantArtifactDigestB],
      evaluatedArtifactDigest: pins.evaluatedArtifactDigest,
      evaluatorProvenance: governedFheEvidence.evaluatorProvenance,
      decryptorProvenance: pins.decryptorProvenance,
      circuitId: FHE_CIRCUIT,
      parameterProfile: FHE_PARAMETER_PROFILE,
    },
    governedResult: {
      conflict: state.release.conflict,
      digest: state.release.resultDigest,
      releaseMode: state.release.releaseMode,
      releaseOrdinal: 1,
      resultCiphertextDigest: pins.recomputedResultCiphertextDigest,
      independentlyRecomputedResultDigest: pins.recomputedResultCiphertextDigest,
    },
    terminal: {
      incidentState: state.release.conflict ? "CONFLICT_CONFIRMED" : "CLEARED",
      recourseState: state.protectionCase.recourseState,
      recourseOpened: state.recourse?.opened === true,
      recourseRefusal: state.recourse?.reason ?? null,
      // Same derivation the V1 evidence uses: the digest of the published
      // recourse record file, not a field of the record itself.
      recourseRecordDigest: state.recourse?.record === undefined || state.recourse.record === null
        ? null
        : digestPublicFile(join(state.paths.publicRoot, "recourse-record.json")),
      originalReceivableState: state.protectionCase.originalReceivable.state,
    },
    chronology: {
      clockClass: chronology.clockClass,
      signedAtUnix: chronology.signedAtUnix,
      events: chronology.events.map((event) => ({ ordinal: event.ordinal, kind: event.kind, atUnix: event.atUnix })),
    },
    disclosures: currentCustomReceiptDisclosures(
      state.supervisedPledgeWindows === undefined ? "PARTICIPANT" : "OPERATOR",
    ),
  };
  return { ...body, receiptDigest: customSupervisedReceiptDigest(body) };
}

function terminalScenarioAfterRelease(state: InternalState): ProductScenario {
  if (state.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) return state.protectionCase.productScenario;
  if (state.release === undefined) {
    throw new ProtectionProductError("A custom supervised run has no scenario before governed release", 500);
  }
  return state.release.conflict ? "conflict" : "no-conflict";
}

async function createProtectionCaseRuntime(
  runtime: ProtectionRuntime,
  scenario: ProductScenario,
  creationRequestId: string,
  supervisedPledgeWindows?: SupervisedPledgeWindows,
  // A participant-admitted case is neutral and carries no private input at all
  // at creation: each window arrives later, with its own wallet authorization.
  participantAdmission = false,
): Promise<ProtectionCaseView> {
  const windows = supervisedPledgeWindows === undefined
    ? undefined
    : assertSupervisedPledgeWindows(supervisedPledgeWindows);
  if (windows !== undefined && participantAdmission) {
    throw new ProtectionProductError("A participant-admitted case cannot carry operator windows", 400);
  }
  const custom = windows !== undefined || participantAdmission;
  if (!custom && scenario !== "conflict" && scenario !== "no-conflict") {
    throw new ProtectionProductError("Unsupported product scenario", 400);
  }
  // The browser-generated creation request ID is the durable one-to-one map to
  // the run. Identity mapping makes a lost create response recoverable without
  // admitting another create or maintaining a second fallible registry.
  assertRunId(creationRequestId);
  const runId = creationRequestId;
  return exclusive(`creation:${creationRequestId}`, async () => {
    const existingPath = statePath(runtime, runId);
    if (existsSync(existingPath)) {
      const existing = await loadState(runtime, runId, false);
      // A custom run is identified by its neutral execution variant, never by a
      // scenario, so replaying a lost create compares the variant instead.
      const sameShape = custom
        ? existing.executionVariant === CUSTOM_SUPERVISED_EXECUTION_VARIANT
        : existing.executionVariant === undefined && existing.protectionCase.productScenario === scenario;
      if (!sameShape) throw new ProtectionProductError("Creation request scenario mismatch", 409);
      return publicView(existing, runtime);
    }
    const root = join(runtime.runRoot, runId);
    const createdAt = runtime.now().toISOString();
    const protectionCase = createProtectionCaseModel({
      // For a custom run this placeholder is never bound, never derived from and
      // never displayed: the V2 binding omits it, the V2 case identity ignores
      // it, and `terminalScenarioAfterRelease` refuses to read it before the
      // governed Boolean exists.
      scenario: custom ? "conflict" : scenario,
      createdAt,
      caseNonce: randomBytes(32).toString("hex"),
      ...(custom ? { executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT } : {}),
    });
    const state: InternalState = {
      schemaVersion: "mordant.protection-execution/2",
      runId,
      stage: "CASE_CREATED",
      protectionCase,
      ...(custom ? { executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT } : {}),
      ...(windows === undefined ? {} : { supervisedPledgeWindows: windows }),
      paths: {
        root,
        publicRoot: join(root, "public"),
        decryptorPrivateRoot: join(root, "decryptor-private"),
        participantPrivateRoot: join(root, "participant-private"),
      },
      startedAtUnix: unix(createdAt),
    };
    mkdirSync(runtime.runRoot, { recursive: true, mode: 0o700 });
    // A process loss after directory creation but before execution.json is
    // safely recoverable by the same creationRequestId.
    mkdirSync(root, { recursive: true, mode: 0o700 });
    return publicView(saveState(runtime, state), runtime);
  });
}

async function preparePrivateMatchRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "MATCH_PREPARED") return publicView(state, runtime);
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
      expectedArtifacts: [
        "case-binding.json", "case-crypto.json", "release-authority.json", "private-case.json",
        "protection-binding.json", "protection-binding-signature-a.json", "protection-binding-signature-b.json",
      ],
      createdAt: runtime.now().toISOString(),
    });
    assertDiskSpace(runtime);
    assertBinaryBuildSpace(runtime);
    await ensureBinaries(runtime);
    assertDiskSpace(runtime);

    mkdirSync(state.paths.publicRoot, { recursive: true, mode: 0o755 });
    mkdirSync(state.paths.decryptorPrivateRoot, { recursive: true, mode: 0o700 });
    mkdirSync(state.paths.participantPrivateRoot, { recursive: true, mode: 0o700 });
    const preFoundation = !existsSync(join(state.paths.publicRoot, "case-binding.json"));
    const participantA = rawParticipantKey("PARTICIPANT_A", state.paths.participantPrivateRoot, preFoundation);
    runtime.failpoint("after-participant-key-a");
    const participantB = rawParticipantKey("PARTICIPANT_B", state.paths.participantPrivateRoot, preFoundation);
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
      caseNonce: state.protectionCase.caseNonce,
      createdAtUnix,
      expiresAtUnix: createdAtUnix + 4 * 60 * 60,
      protectionBinding: protectionAuthorizationBinding(state),
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
      "-participant-a-key", participantA.path,
      "-participant-b-key", participantB.path,
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
      || output.protectionBindingDigest !== protectionAuthorizationBindingDigest(state)
    ) {
      throw new ProtectionProductError("Generated FHE case does not match the protection case", 500);
    }
    state = saveState(runtime, {
      ...state,
      stage: "MATCH_PREPARED",
      protectionCase: preparedCase,
      keygen: output,
      participantKeys: { PARTICIPANT_A: participantA.path, PARTICIPANT_B: participantB.path },
    });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state, runtime);
  });
}

/**
 * Exactly what a participant wallet must bind, and nothing else.
 *
 * `protectionBindingDigest` is the V2 authorization digest the case already
 * derives and that keygen already verifies. Exposing it here lets a wallet sign
 * against the same binding the engine enforces, without widening the audited
 * custom view or introducing a second derivation of it.
 */
export type ParticipantAdmissionContext = Readonly<{
  runId: string;
  stage: ExecutionStage;
  fheCaseId: Sha256Digest;
  assetIdentityDigest: Sha256Digest;
  protectionBindingDigest: Sha256Digest;
}>;

function assertDirectParticipantAdmissionEnabled(runtime: ProtectionRuntime): void {
  if (!runtime.directParticipantAdmissionEnabled) {
    throw new ProtectionProductError("Direct participant admission is disabled", 403);
  }
  try {
    const canonical = loadCanonicalRecourseConfiguration();
    if (canonical.adapter.chainId !== MONAD_TESTNET_CHAIN_ID) {
      throw new ProtectionProductError("The canonical direct-admission chain is unavailable", 503);
    }
  } catch (error) {
    if (error instanceof ProtectionProductError) throw error;
    throw new ProtectionProductError("The canonical direct-admission configuration is unavailable", 503);
  }
}

async function readParticipantAdmissionContextRuntime(
  runtime: ProtectionRuntime,
  runId: string,
): Promise<ParticipantAdmissionContext> {
  assertDirectParticipantAdmissionEnabled(runtime);
  const state = await loadState(runtime, runId, false);
  if (state.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
    throw new ProtectionProductError("This case does not admit participants", 409);
  }
  return Object.freeze({
    runId: state.runId,
    stage: state.stage,
    fheCaseId: state.protectionCase.fheCaseId,
    assetIdentityDigest: state.protectionCase.cleanverseAssetDigest,
    protectionBindingDigest: protectionAuthorizationBindingDigest(state),
  });
}

export type AdmittedParticipantClaim = Readonly<{
  participantWallet: string;
  authorizationDigest: string;
  claimCommitment: string;
  authorizationNonce: string;
  chainId: number;
  issuedAt: number;
  expiresAt: number;
  claim: SupervisedPledgeWindow;
}>;

/**
 * The engine trusts only the create-only admission ledger, never the object an
 * in-process caller supplied. The service writes that ledger only after typed
 * signature, policy and canonical-role checks. Recomputing the claim commitment
 * closes the remaining gap between a durable commitment and plaintext used to
 * build the Go pledge.
 */
function assertVerifiedDurableAdmission(
  runtime: ProtectionRuntime,
  state: InternalState,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  admission: AdmittedParticipantClaim,
): void {
  const durable = readAdmission(runtime.runRoot, state.runId, role);
  if (durable === null) {
    throw new ProtectionProductError(`Participant ${role} has no verified durable admission`, 409);
  }
  const claim = assertSupervisedPledgeWindow(
    admission.claim,
    role === "PARTICIPANT_A" ? "participantA" : "participantB",
  );
  const recomputedClaimCommitment = participantClaimCommitment({ runId: state.runId, role, claim });
  let canonicalWallet: string;
  try {
    const canonical = loadCanonicalRecourseConfiguration();
    canonicalWallet = role === "PARTICIPANT_A"
      ? canonical.participants.holderA
      : canonical.participants.holderB;
  } catch {
    throw new ProtectionProductError("The canonical direct-admission configuration is unavailable", 503);
  }
  if (
    durable.chainId !== MONAD_TESTNET_CHAIN_ID
    || admission.chainId !== MONAD_TESTNET_CHAIN_ID
    || durable.participantWallet.toLowerCase() !== canonicalWallet.toLowerCase()
    || durable.participantWallet.toLowerCase() !== admission.participantWallet.toLowerCase()
    || durable.authorizationDigest !== admission.authorizationDigest
    || durable.claimCommitment !== admission.claimCommitment
    || durable.authorizationNonce !== admission.authorizationNonce
    || durable.chainId !== admission.chainId
    || durable.issuedAt !== admission.issuedAt
    || durable.expiresAt !== admission.expiresAt
    || durable.claimCommitment !== recomputedClaimCommitment
  ) {
    throw new ProtectionProductError(`Participant ${role} durable admission does not match this pledge`, 409);
  }
}

/**
 * Records one participant's admitted claim against a prepared case.
 *
 * This is the durable admission point and it deliberately does no FHE work: the
 * ledger write commits first, the expensive submission runs afterwards under its
 * own lock. A crash between the two leaves an admitted role with no submission,
 * which the existing submission path completes idempotently on retry.
 *
 * The role's turn is enforced against the engine's own stage, so B cannot be
 * admitted before A and neither can be admitted before the case is prepared.
 */
async function admitParticipantClaimRuntime(
  runtime: ProtectionRuntime,
  runId: string,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  admission: AdmittedParticipantClaim,
): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    assertDirectParticipantAdmissionEnabled(runtime);
    let state = await loadState(runtime, runId);
    if (state.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
      throw new ProtectionProductError("This case does not admit participants", 409);
    }
    if (state.supervisedPledgeWindows !== undefined) {
      throw new ProtectionProductError("This case was created with operator windows", 409);
    }
    const existing = state.admittedClaims?.[role];
    if (existing !== undefined) {
      // An exact retry is idempotent. A different authorization or a different
      // claim for an occupied role is refused without touching durable state.
      if (
        existing.authorizationDigest !== admission.authorizationDigest
        || existing.claimCommitment !== admission.claimCommitment
        || existing.participantWallet !== admission.participantWallet
        || existing.authorizationNonce !== admission.authorizationNonce
      ) {
        throw new ProtectionProductError(`${role} has already been admitted for this case`, 409);
      }
      assertVerifiedDurableAdmission(runtime, state, role, admission);
      return publicView(state, runtime);
    }
    const expectedStage: ExecutionStage = role === "PARTICIPANT_A" ? "MATCH_PREPARED" : "PARTICIPANT_A_SUBMITTED";
    if (state.stage !== expectedStage) {
      throw new ProtectionProductError(`Participant ${role} admission is out of order`, 409);
    }
    assertVerifiedDurableAdmission(runtime, state, role, admission);
    state = saveState(runtime, {
      ...state,
      admittedClaims: { ...state.admittedClaims, [role]: admission },
    });
    return publicView(state, runtime);
  });
}

function pledgeFor(state: InternalState, role: "PARTICIPANT_A" | "PARTICIPANT_B") {
  const base = state.protectionCase.cleanverseAssetDigest;
  // A supervised custom run substitutes only the two window bounds. Every other
  // field, and every derivation below, is identical to the fixed fixture, so
  // the Go pledge schema, the circuit and all signing semantics are unchanged.
  //
  // Two sources can supply that window and they never mix. A participant-admitted
  // run reads only this role's own claim, written by this role's own wallet; the
  // operator-entered path is unchanged and still reads the pair. Admission wins
  // when present, so a case that admitted participants can never silently fall
  // back to operator input for a role.
  const admitted = state.admittedClaims?.[role];
  const custom = state.supervisedPledgeWindows;
  const window = admitted !== undefined
    ? admitted.claim
    : custom === undefined
      ? undefined
      : role === "PARTICIPANT_A" ? custom.participantA : custom.participantB;
  if (
    state.executionVariant === CUSTOM_SUPERVISED_EXECUTION_VARIANT
    && custom === undefined
    && admitted === undefined
  ) {
    throw new ProtectionProductError(`Participant ${role} has no verified durable admission`, 409);
  }
  const activeFrom = window !== undefined
    ? window.activeFrom
    : role === "PARTICIPANT_A" ? 100 : state.protectionCase.productScenario === "conflict" ? 200 : 500;
  const activeUntil = window !== undefined
    ? window.activeUntil
    : role === "PARTICIPANT_A" ? 400 : state.protectionCase.productScenario === "conflict" ? 500 : 700;
  return {
    activeFrom,
    activeUntil,
    amount: [0, 0, 0, 100_000_000],
    currency: digestText("MordantProtectionCurrency/v1", "aUSDC").slice(7),
    obligationId: digestText("MordantProtectionObligation/v1", `${state.runId}/${role}`).slice(7),
    receivableId: digestText("MordantProtectionReceivable/v1", base).slice(7),
    exclusive: true,
    // The Go pledge schema remains the same 64-hex-character fields. For the
    // direct-admission variant, they now carry the exact EIP-712 authorization
    // digest and the independently recomputable claim commitment. Both values
    // already bind run, role, wallet and interval, so the FHE input can be
    // checked against the verified durable admission without changing the BGV
    // circuit or governed-result schema.
    authorizationCommitment: admitted === undefined
      ? digestText("MordantProtectionAuthorization/v1", `${state.runId}/${role}`).slice(7)
      : admitted.authorizationDigest.slice(2),
    privateMetadataCommitment: admitted === undefined
      ? digestText("MordantProtectionPrivateMetadata/v1", `${state.runId}/${role}`).slice(7)
      : admitted.claimCommitment.slice(2),
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
    if (state.executionVariant === CUSTOM_SUPERVISED_EXECUTION_VARIANT && state.supervisedPledgeWindows === undefined) {
      assertDirectParticipantAdmissionEnabled(runtime);
      const admitted = state.admittedClaims?.[role];
      if (admitted === undefined) {
        throw new ProtectionProductError(`Participant ${role} has no verified durable admission`, 409);
      }
      assertVerifiedDurableAdmission(runtime, state, role, admitted);
    }
    if (role === "PARTICIPANT_B" && state.stage === "PARTICIPANT_B_PUBLISHED") {
      return publicView(await finalizeParticipantSubmissions(runtime, state), runtime);
    }
    if (state.submissions?.[role] !== undefined) return publicView(state, runtime);
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
    return publicView(state, runtime);
  });
}

async function evaluatePrivateConflictRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "EVALUATED") return publicView(state, runtime);
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
    return publicView(state, runtime);
  });
}

async function releaseGovernedResultRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "RELEASED" && state.release !== undefined) return publicView(state, runtime);
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
    // A fixed-fixture run still asserts the pre-declared scenario, because its
    // inputs are known and any divergence is a real defect. A supervised custom
    // run has operator-authored windows, so the governed Boolean is the
    // authority: the terminal scenario is derived from it below, never asserted
    // against the caller's routing value.
    const customRun = state.supervisedPledgeWindows !== undefined;
    if (
      output.releaseMode !== state.protectionCase.releaseMode
      || (!customRun && output.conflict !== (state.protectionCase.productScenario === "conflict"))
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
    return publicView(state, runtime);
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
      return publicView(state, runtime);
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
      },
      expectedCurrentStage: "RELEASED",
      expectedTargetStage: "RECOURSE_OPENED",
      expectedArtifacts: state.release.conflict
        ? ["recourse-clock-binding.json", "recourse-record.json", "recourse-outcome.json"]
        : ["recourse-outcome.json"],
      createdAt: runtime.now().toISOString(),
    });
    const requestPath = join(state.paths.root, "recourse-request.json");
    writeJsonAtomic(requestPath, {
      assetIdentity: state.protectionCase.cleanverseAssetDigest,
      caseId: state.protectionCase.fheCaseId,
      expectedPins: state.release.trustedRecoursePins,
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
    return publicView(state, runtime);
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
    // This selects the fixed MVP simulation branch only. The release authority
    // derives and signs its timestamp, event and final state internally.
    state = saveState(runtime, { ...state, stage: "CHRONOLOGY_COMPLETE" });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state, runtime);
  });
}

function digestPublicFile(path: string): Sha256Digest {
  const data = readFileSync(path);
  const canonical = data.at(-1) === 0x0a ? data.subarray(0, data.length - 1) : data;
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function localCaseManifestDigest(state: Pick<InternalState, "paths">): Sha256Digest {
  return digestPublicFile(join(state.paths.publicRoot, "case-manifest.json"));
}

function buildProtectionEvidence(
  runtime: ProtectionRuntime,
  state: InternalState,
  governedFheEvidence: GovernedFhePublicEvidence,
  generatedAt: string,
  signerChronology?: MordantProtectionEvidence["chronology"],
): MordantProtectionEvidence {
  if (
    state.keygen === undefined || state.submissions?.PARTICIPANT_A === undefined
    || state.submissions.PARTICIPANT_B === undefined || state.evaluation === undefined
    || state.release === undefined || state.recourse === undefined
  ) {
    throw new ProtectionProductError("The complete governed FHE run is required", 500);
  }
  const expectedCaseManifestDigest = localCaseManifestDigest(state);
  if (governedFheEvidence.caseManifestDigest !== expectedCaseManifestDigest) {
    throw new ProtectionProductError("Governed-FHE case manifest digest readback mismatch", 500);
  }
  let sourceCommit: string;
  try {
    sourceCommit = resolveProtectionExportSourceCommit(
      runtime.expectedSourceCommit,
      process.env.MORDANT_PROTECTION_SOURCE_COMMIT,
    );
  } catch {
    throw new ProtectionProductError("Exact product source commit disagrees with the server/build pin", 500);
  }
  const binding = readJson<FheCaseBinding>(join(state.paths.publicRoot, "case-binding.json"));
  const signatureA = readJson<ParticipantBindingSignature>(join(state.paths.publicRoot, "binding-signature-a.json"));
  const signatureB = readJson<ParticipantBindingSignature>(join(state.paths.publicRoot, "binding-signature-b.json"));
  const protectionBinding = readJson<ReturnType<typeof protectionBindingFromCase>>(join(state.paths.publicRoot, "protection-binding.json"));
  const protectionSignatureA = readJson<ProtectionBindingSignature>(join(state.paths.publicRoot, "protection-binding-signature-a.json"));
  const protectionSignatureB = readJson<ProtectionBindingSignature>(join(state.paths.publicRoot, "protection-binding-signature-b.json"));
  const recourseAttestation = readJson<MordantRecourseAttestation>(join(state.paths.publicRoot, "product-recourse-attestation.json"));
  const evaluated = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "evaluated-conflict.json"));
  const result = readJson<GovernedSignedResult>(join(state.paths.publicRoot, "governed-conflict-result.json"));
  const publicKey = (readJson<Record<string, unknown>>(join(state.paths.publicRoot, "case-crypto.json")).publicKey ?? {}) as Record<string, unknown>;
  const participants = [binding.participantA, binding.participantB] as const;
  const resultCiphertext = (evaluated.resultCiphertext ?? {}) as Record<string, unknown>;
  const recourseRecord = (state.recourse.record ?? null) as PublicRecourseRecord | null;
  const recourseRecordDigest = recourseRecord === null
    ? null
    : digestPublicFile(join(state.paths.publicRoot, "recourse-record.json"));
  const chronologyEvents: CanonicalChronologyEvent[] = [
    { ordinal: 1, kind: "PROTECTED_HOLDER_SNAPSHOT_FIXED", atUnix: unix(protectionBinding.holderRecordDate), clockSource: "PROTECTION_BINDING_RECORD_DATE", evidenceRef: protectionBindingDigest(protectionBinding) },
    { ordinal: 2, kind: "FHE_CASE_CREATED", atUnix: binding.createdAtUnix, clockSource: "SIGNED_FHE_CASE_CLOCK", evidenceRef: state.keygen.bindingDigest },
    { ordinal: 3, kind: "PARTICIPANT_A_ARTIFACT_BOUND", atUnix: null, clockSource: "CRYPTOGRAPHIC_ORDER_ONLY", evidenceRef: result.participantArtifactDigests[0] },
    { ordinal: 4, kind: "PARTICIPANT_B_ARTIFACT_BOUND", atUnix: null, clockSource: "CRYPTOGRAPHIC_ORDER_ONLY", evidenceRef: result.participantArtifactDigests[1] },
    { ordinal: 5, kind: "FHE_EVALUATION_BOUND", atUnix: null, clockSource: "CRYPTOGRAPHIC_ORDER_ONLY", evidenceRef: result.evaluatedArtifactDigest },
    { ordinal: 6, kind: "GOVERNED_RESULT_RELEASED", atUnix: result.releasedAtUnix, clockSource: "SIGNED_GOVERNED_RELEASE_CLOCK", evidenceRef: state.release.resultDigest },
  ];
  if (result.conflict && recourseRecord !== null && recourseRecordDigest !== null) {
    chronologyEvents.push(
      { ordinal: 7, kind: "RECOURSE_BOUND", atUnix: recourseRecord.boundAtUnix, clockSource: "DURABLE_RECOURSE_CLOCK", evidenceRef: recourseRecordDigest },
      recourseAttestation.clockClass === "SIMULATED_PROTOCOL_CLOCK"
        ? { ordinal: 8, kind: "SIMULATED_CURE_WINDOW_COMPLETED", atUnix: recourseAttestation.simulationAsOfUnix, clockSource: "SIMULATED_PROTOCOL_CLOCK", evidenceRef: recourseRecordDigest }
        : { ordinal: 8, kind: "CURE_WINDOW_COMPLETED", atUnix: recourseAttestation.signedAtUnix, clockSource: "REAL_OBSERVED_CLOCK", evidenceRef: recourseRecordDigest },
    );
  } else {
    chronologyEvents.push({ ordinal: 7, kind: "RECOURSE_REFUSED_BY_SIGNED_FALSE", atUnix: result.releasedAtUnix, clockSource: "SIGNED_GOVERNED_RELEASE_CLOCK", evidenceRef: state.release.resultDigest });
  }
  const chronology: MordantProtectionEvidence["chronology"] = {
    schemaVersion: "mordant.product-chronology/1",
    clockClass: recourseAttestation.clockClass,
    signedAtUnix: recourseAttestation.signedAtUnix,
    simulationAsOfUnix: recourseAttestation.simulationAsOfUnix,
    recordDate: protectionBinding.holderRecordDate,
    holderAllocationDigest: protectionBinding.holderAllocationDigest,
    cureDeadlineUnix: recourseRecord?.cureDeadlineUnix ?? null,
    finalIncidentState: recourseAttestation.finalIncidentState,
    finalRecourseState: recourseAttestation.finalRecourseState,
    events: chronologyEvents,
  };
  if (signerChronology !== undefined && JSON.stringify(signerChronology) !== JSON.stringify(chronology)) {
    throw new ProtectionProductError("Signer chronology reconstruction mismatch", 500);
  }
  const {
    timeline: _timeline,
    incidentState: _incidentState,
    cureDeadline: _cureDeadline,
    recourseState: _recourseState,
    createdAt: _createdAt,
    ...publicProtectionCase
  } = state.protectionCase;
  const base: Omit<MordantProtectionEvidence, "manifestDigest"> = {
    schemaVersion: "mordant.protection-evidence/4",
    runId: state.runId,
    sourceCommit,
    governedFheCommit: GOVERNED_FHE_COMMIT,
    scenario: terminalScenarioAfterRelease(state),
    cleanverseAsset: state.protectionCase.cleanverseAsset,
    cleanverseAssetDigest: state.protectionCase.cleanverseAssetDigest,
    sourceClassifications: [
      "CLEANVERSE_M11_LIVE_OBSERVED",
      "CLEANVERSE_TERMS_DOCUMENTED",
      "N15_GOVERNED_FHE_LOCAL_EXECUTION",
      "RECOURSE_LOCAL_PROTOCOL_DOUBLE",
      "SYNTHETIC_PROTECTED_PLEDGE_FIXTURE",
      "PRODUCTION_CUSTODY_UNPROVEN",
    ],
    protectionCase: publicProtectionCase,
    participantPublicIdentities: [
      { role: "PARTICIPANT_A", id: participants[0].id, signingPublicKey: participants[0].signingPublicKey },
      { role: "PARTICIPANT_B", id: participants[1].id, signingPublicKey: participants[1].signingPublicKey },
    ],
    protectionAuthorization: {
      binding: protectionBinding,
      bindingDigest: protectionBindingDigest(protectionBinding),
      participantSignatures: [protectionSignatureA, protectionSignatureB],
    },
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
    chronology,
    recourse: {
      classification: "PROTOCOL_DOUBLE",
      opened: state.recourse.opened,
      refusedReason: state.recourse.reason ?? null,
      recordDigest: recourseRecordDigest,
      record: recourseRecord,
    },
    originalReceivablePreservation: {
      state: "OUTSTANDING_INTACT",
      principalMinorUnits: "110000000",
      units: "100000000",
      reserveAccountingSeparate: true,
      claimBurnedOrTransferredByProtection: false,
    },
    recourseAttestation: {
      digest: digestPublicFile(join(state.paths.publicRoot, "product-recourse-attestation.json")),
      attestation: recourseAttestation,
    },
    governedFheEvidence,
    generatedAt,
  };
  const evidence: MordantProtectionEvidence = { ...base, manifestDigest: protectionEvidenceDigest(base) };
  assertPublicProtectionEvidence(evidence, runtime.expectedSourceCommit, expectedCaseManifestDigest);
  return evidence;
}

async function exportProtectionEvidenceRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = await loadState(runtime, runId);
    if (state.stage === "COMPLETE" && state.evidence !== undefined) return publicView(state, runtime);
    const expectedStage = terminalScenarioAfterRelease(state) === "conflict" ? "CHRONOLOGY_COMPLETE" : "RECOURSE_OPENED";
    if (state.stage !== expectedStage || state.release === undefined || state.keygen === undefined) {
      throw new ProtectionProductError("The product journey is not complete");
    }
    const operation = beginOperation(runtime.runRoot, runId, {
      operation: "exportProtectionEvidence",
      phase: "EXPORTING",
      immutableParameters: {
        caseId: state.protectionCase.fheCaseId,
        resultDigest: state.release.resultDigest,
        scenario: terminalScenarioAfterRelease(state),
      },
      expectedCurrentStage: expectedStage,
      expectedTargetStage: "COMPLETE",
      fixedNowUnix: Math.floor(runtime.now().valueOf() / 1000),
      expectedArtifacts: ["product-recourse-attestation.json", "evidence.json", "protection-evidence.json"],
      createdAt: runtime.now().toISOString(),
    });
    const attestation = await runJSON<Readonly<{
      digest: Sha256Digest;
      attestation: MordantRecourseAttestation;
      chronology: MordantProtectionEvidence["chronology"];
    }>>(
      runtime,
      "recourse",
      [
        "-mode", "attest",
        "-public-root", state.paths.publicRoot,
        "-private-root", state.paths.decryptorPrivateRoot,
      ],
    );
    if (
      attestation.digest !== digestPublicFile(join(state.paths.publicRoot, "product-recourse-attestation.json"))
      || attestation.attestation.protectionBindingDigest !== state.keygen.protectionBindingDigest
      || attestation.attestation.governedResultDigest !== state.release.resultDigest
    ) throw new ProtectionProductError("Signed product attestation readback mismatch", 500);
    runtime.failpoint("after-attestation-publication-before-evidence");
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
    // A custom V2 run produces its own local receipt. It cannot produce V4
    // evidence, because that schema cross-checks its scenario against a
    // `binding.productScenario` that a neutral V2 authorization does not have,
    // and widening or weakening the published V1 contract is not acceptable.
    if (state.executionVariant === CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
      const receipt = buildCustomSupervisedReceipt(runtime, state, governedFheEvidence, attestation.chronology);
      assertCustomSupervisedReceipt(receipt);
      writeJsonAtomic(join(state.paths.root, "custom-supervised-receipt.json"), receipt, 0o644);
      // A direct-participant run additionally emits its own bridge authorization
      // artifact. It is written under the durable run root, never under
      // `public/`, so it survives the worker's post-terminal pruning while the
      // reproducible and private artifacts it was derived from do not.
      persistDirectParticipantBridgeEvidence(runtime, state, receipt);
      runtime.failpoint("after-evidence-publication-before-state-save");
      state = saveState(runtime, { ...state, stage: "COMPLETE", customReceipt: receipt });
      finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
      return publicView(state, runtime);
    }
    const evidence = buildProtectionEvidence(
      runtime,
      state,
      governedFheEvidence,
      runtime.now().toISOString(),
      attestation.chronology,
    );
    writeJsonAtomic(join(state.paths.root, "protection-evidence.json"), evidence, 0o644);
    runtime.failpoint("after-evidence-publication-before-state-save");
    state = saveState(runtime, { ...state, stage: "COMPLETE", evidence });
    finishOperation(runtime.runRoot, runId, operation.operationId, "COMPLETED", runtime.now().toISOString());
    return publicView(state, runtime);
  });
}

async function readProtectionCaseRuntime(runtime: ProtectionRuntime, runId: string): Promise<ProtectionCaseView> {
  // A GET must never reconcile an admitted operation while this process is
  // still executing it. Ordinary restart clears this in-memory lock and then
  // the durable journal is the authority for reconciliation.
  if (locks.has(runId)) {
    throw new ProtectionProductError("A protection operation is still running; resume durable readback after it completes", 423);
  }
  return publicView(await loadState(runtime, runId, false), runtime);
}

async function readProtectionCreationRuntime(
  runtime: ProtectionRuntime,
  creationRequestId: string,
): Promise<ProtectionCaseView> {
  // Lookup is strictly passive and resolves the durable identity map only.
  return readProtectionCaseRuntime(runtime, creationRequestId);
}

function loadImportedProtectionEvidenceRuntime(
  runtime: ProtectionRuntime,
  scenario: ProductScenario = "conflict",
): VerifiedPublicProtectionEvidence {
  const path = join(runtime.importedEvidenceRoot, `${scenario}.json`);
  if (!existsSync(path)) throw new ProtectionProductError("Imported protection evidence is unavailable", 503);
  const evidence = readJson<MordantProtectionEvidence>(path);
  return verifyAndProjectPublicProtectionEvidence(evidence, runtime.expectedSourceCommit);
}

/**
 * A supervised custom run retains under its own run directory, never into the
 * shared retention root whose two scenario files back the published evidence.
 * A custom run can therefore fail, repeat or produce either outcome without
 * touching the validated public fallback.
 */
function retentionTargetFor(state: InternalState, runtime: ProtectionRuntime): Readonly<{ root: string; path: string }> {
  const root = state.supervisedPledgeWindows === undefined
    ? runtime.retentionRoot
    : join(state.paths.root, "custom-retained-evidence");
  return Object.freeze({ root, path: resolve(root, `${terminalScenarioAfterRelease(state)}.json`) });
}

async function retainProtectionEvidenceRuntime(runtime: ProtectionRuntime, runId: string, destination: string): Promise<string> {
  const state = await loadState(runtime, runId);
  if (state.stage !== "COMPLETE" || state.evidence === undefined) {
    throw new ProtectionProductError("Only complete public evidence may be retained");
  }
  assertPublicProtectionEvidence(state.evidence, runtime.expectedSourceCommit, localCaseManifestDigest(state));
  const target = retentionTargetFor(state, runtime);
  const allowed = target.path;
  if (resolve(destination) !== allowed) throw new ProtectionProductError("Evidence destination rejected", 400);
  // A custom run owns its retention directory, so it is created on demand. The
  // shared public retention root stays an externally configured capability that
  // is never created implicitly.
  if (state.supervisedPledgeWindows !== undefined) mkdirSync(target.root, { recursive: true, mode: 0o700 });
  if (!existsSync(target.root)) {
    throw new ProtectionProductError("Configured evidence retention capability is unavailable", 503);
  }
  const operation = beginOperation(runtime.runRoot, runId, {
    operation: "retainProtectionEvidence",
    phase: "RETAINING",
    immutableParameters: {
      destination: allowed,
      scenario: terminalScenarioAfterRelease(state),
      caseId: state.protectionCase.fheCaseId,
      manifestDigest: state.evidence.manifestDigest,
    },
    expectedCurrentStage: "COMPLETE",
    expectedTargetStage: "COMPLETE",
    expectedArtifacts: [allowed],
    createdAt: runtime.now().toISOString(),
  });
  const retention = await runJSON<Readonly<{ reconciled: boolean }>>(runtime, "retain", [
    "-retention-root", target.root,
    "-scenario", terminalScenarioAfterRelease(state),
    "-source", join(state.paths.root, "protection-evidence.json"),
    "-manifest-digest", state.evidence.manifestDigest,
    "-case-id", state.protectionCase.fheCaseId,
  ]);
  runtime.failpoint("after-capability-retention-before-readback");
  const retained = readJsonNoFollow<MordantProtectionEvidence>(allowed);
  assertPublicProtectionEvidence(retained, runtime.expectedSourceCommit, localCaseManifestDigest(state));
  if (
    retained.runId !== state.runId
    || retained.scenario !== terminalScenarioAfterRelease(state)
    || retained.protectionCase.fheCaseId !== state.protectionCase.fheCaseId
    || retained.manifestDigest !== state.evidence.manifestDigest
  ) throw new ProtectionProductError("Retained evidence readback mismatch", 500);
  finishOperation(runtime.runRoot, runId, operation.operationId, retention.reconciled ? "RECONCILED" : "COMPLETED", runtime.now().toISOString());
  return allowed;
}

function readRetainedProtectionEvidenceInConfiguredRootRuntime(
  runtime: ProtectionRuntime,
  runId: string,
): RetainedProtectionEvidenceView {
  // This boundary is deliberately read-only. In particular it must not call
  // loadState/reconciliation, beginOperation, or the retention command: a
  // browser GET may verify an operation already admitted, but may not admit
  // retention on its own authority.
  const state = loadStateRaw(runtime, runId);
  if (state.stage !== "COMPLETE" || state.evidence === undefined) {
    throw new ProtectionProductError("Complete retained evidence is not yet available", 423);
  }
  const scenario = terminalScenarioAfterRelease(state);
  if (scenario !== "conflict" && scenario !== "no-conflict") {
    throw new ProtectionProductError("Retained evidence readback mismatch", 500);
  }
  const retainedPath = retentionTargetFor(state, runtime).path;
  if (!existsSync(retainedPath)) {
    throw new ProtectionProductError("Complete retained evidence is not yet available", 423);
  }
  const retained = readJsonNoFollow<MordantProtectionEvidence>(retainedPath);
  const evidence = verifyAndProjectPublicProtectionEvidence(
    retained,
    runtime.expectedSourceCommit,
    localCaseManifestDigest(state),
  );
  if (
    evidence.runId !== state.runId
    || evidence.scenario !== terminalScenarioAfterRelease(state)
    || evidence.fhe.caseId !== state.protectionCase.fheCaseId
    || evidence.manifestDigest !== state.evidence.manifestDigest
  ) throw new ProtectionProductError("Retained evidence readback mismatch", 500);
  return Object.freeze({
    schemaVersion: "mordant.retained-protection-view/1",
    runId: state.runId,
    scenario: evidence.scenario,
    caseId: evidence.fhe.caseId,
    manifestDigest: evidence.manifestDigest,
    evidence,
  });
}

async function retainProtectionEvidenceInConfiguredRootRuntime(
  runtime: ProtectionRuntime,
  runId: string,
): Promise<RetainedProtectionEvidenceView> {
  return exclusive(runId, async () => {
    const pending = pendingOperation(runtime.runRoot, runId);
    if (pending?.operation === "retainProtectionEvidence") {
      await loadState(runtime, runId);
      if (pendingOperation(runtime.runRoot, runId) === null) {
        return readRetainedProtectionEvidenceInConfiguredRootRuntime(runtime, runId);
      }
    } else {
      try {
        // A confirmed retry after a lost retention response must not create a
        // second operation-journal result or rerun the retain command.
        return readRetainedProtectionEvidenceInConfiguredRootRuntime(runtime, runId);
      } catch (error) {
        if (!(error instanceof ProtectionProductError) || error.status !== 423) throw error;
      }
    }
    const state = await loadState(runtime, runId);
    const retainedPath = await retainProtectionEvidenceRuntime(
      runtime,
      runId,
      retentionTargetFor(state, runtime).path,
    );
    // This is a second independent no-follow read, after the retention command
    // and its own readback, so the adapter only receives the exact durable bytes.
    const retained = readJsonNoFollow<MordantProtectionEvidence>(retainedPath);
    const evidence = verifyAndProjectPublicProtectionEvidence(
      retained,
      runtime.expectedSourceCommit,
      localCaseManifestDigest(state),
    );
    if (
      evidence.runId !== state.runId
      || evidence.scenario !== terminalScenarioAfterRelease(state)
      || evidence.fhe.caseId !== state.protectionCase.fheCaseId
      || evidence.manifestDigest !== state.evidence?.manifestDigest
    ) throw new ProtectionProductError("Retained evidence readback mismatch", 500);
    return Object.freeze({
      schemaVersion: "mordant.retained-protection-view/1",
      runId: state.runId,
      scenario: evidence.scenario,
      caseId: evidence.fhe.caseId,
      manifestDigest: evidence.manifestDigest,
      evidence,
    });
  });
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
    createProtectionCase: (
      scenario: ProductScenario,
      creationRequestId: string = randomUUID(),
      supervisedPledgeWindows?: SupervisedPledgeWindows,
    ) => (
      createProtectionCaseRuntime(runtime, scenario, creationRequestId, supervisedPledgeWindows)
    ),
    /**
     * A neutral case that admits two participants. It carries no scenario and no
     * private input: the placeholder first argument is never bound, never derived
     * from and never displayed, exactly as on the operator-entered custom path.
     */
    createNeutralParticipantCase: async (creationRequestId: string = randomUUID()) => {
      assertDirectParticipantAdmissionEnabled(runtime);
      return createProtectionCaseRuntime(runtime, "conflict", creationRequestId, undefined, true);
    },
    readParticipantAdmissionContext: (runId: string) => readParticipantAdmissionContextRuntime(runtime, runId),
    admitParticipantClaim: (
      runId: string,
      role: "PARTICIPANT_A" | "PARTICIPANT_B",
      admission: AdmittedParticipantClaim,
    ) => admitParticipantClaimRuntime(runtime, runId, role, admission),
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
    /**
     * Custom V2 readback. A custom run is never projected into the V1 view, so
     * the browser must ask for it under its own schema.
     */
    readCustomSupervisedCase: async (runId: string): Promise<CustomSupervisedProtectionView> => {
      if (locks.has(runId)) {
        throw new ProtectionProductError("A protection operation is still running; resume durable readback after it completes", 423);
      }
      const state = await loadState(runtime, runId, false);
      if (state.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
        throw new ProtectionProductError("This run is not a supervised custom case", 400);
      }
      return customSupervisedView(state);
    },
    readProtectionCreation: (creationRequestId: string) => readProtectionCreationRuntime(runtime, creationRequestId),
    loadImportedProtectionEvidence: (scenario: ProductScenario = "conflict") => loadImportedProtectionEvidenceRuntime(runtime, scenario),
    retainProtectionEvidence: (runId: string, destination: string) => retainProtectionEvidenceRuntime(runtime, runId, destination),
    readRetainedProtectionEvidenceInConfiguredRoot: (runId: string) => (
      readRetainedProtectionEvidenceInConfiguredRootRuntime(runtime, runId)
    ),
    retainProtectionEvidenceInConfiguredRoot: (runId: string) => (
      retainProtectionEvidenceInConfiguredRootRuntime(runtime, runId)
    ),
    validateRetainedPublicArtifacts: (runId: string) => validateRetainedPublicArtifactsRuntime(runtime, runId),
  });
}

const DEFAULT_ORCHESTRATOR = createProtectionOrchestrator();

export const createProtectionCase = DEFAULT_ORCHESTRATOR.createProtectionCase;
export const createNeutralParticipantCase = DEFAULT_ORCHESTRATOR.createNeutralParticipantCase;
export const readParticipantAdmissionContext = DEFAULT_ORCHESTRATOR.readParticipantAdmissionContext;
export const admitParticipantClaim = DEFAULT_ORCHESTRATOR.admitParticipantClaim;
export const preparePrivateMatch = DEFAULT_ORCHESTRATOR.preparePrivateMatch;
export const submitParticipantPledge = DEFAULT_ORCHESTRATOR.submitParticipantPledge;
export const evaluatePrivateConflict = DEFAULT_ORCHESTRATOR.evaluatePrivateConflict;
export const releaseGovernedResult = DEFAULT_ORCHESTRATOR.releaseGovernedResult;
export const openRecourseCase = DEFAULT_ORCHESTRATOR.openRecourseCase;
export const completeCureChronology = DEFAULT_ORCHESTRATOR.completeCureChronology;
export const exportProtectionEvidence = DEFAULT_ORCHESTRATOR.exportProtectionEvidence;
export const readProtectionCase = DEFAULT_ORCHESTRATOR.readProtectionCase;
export const readProtectionCreation = DEFAULT_ORCHESTRATOR.readProtectionCreation;
export const loadImportedProtectionEvidence = DEFAULT_ORCHESTRATOR.loadImportedProtectionEvidence;
export const retainProtectionEvidence = DEFAULT_ORCHESTRATOR.retainProtectionEvidence;
export const readRetainedProtectionEvidenceInConfiguredRoot = (
  DEFAULT_ORCHESTRATOR.readRetainedProtectionEvidenceInConfiguredRoot
);
export const retainProtectionEvidenceInConfiguredRoot = DEFAULT_ORCHESTRATOR.retainProtectionEvidenceInConfiguredRoot;
export const validateRetainedPublicArtifacts = DEFAULT_ORCHESTRATOR.validateRetainedPublicArtifacts;
