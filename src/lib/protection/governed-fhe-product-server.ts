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
  copyFileSync,
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
  assertPublicProtectionEvidence,
  protectionEvidenceDigest,
  type MordantProtectionEvidence,
} from "./protection-evidence";

const execFileAsync = promisify(execFile);

export const PRODUCT_STORAGE = Object.freeze({
  estimatedCaseBytes: 576_716_800,
  twoCaseRetainedBytes: 1_153_433_600,
  retainedEvidenceBytes: 131_072,
  safetyMarginBytes: 1_610_612_736,
});

const SOURCE_COMMIT = "e5a5d15145e3b1ef2c573374a08439acb46b4e95";
const GOVERNED_FHE_COMMIT = "3b0247593d022fb18aadd2b554329f85c5a19898";
const RUN_ROOT = resolve(process.env.MORDANT_PROTECTION_RUN_ROOT ?? join(process.cwd(), ".mordant", "protection"));
const BIN_ROOT = resolve(process.env.MORDANT_GOVERNED_FHE_BIN_DIR ?? join(process.cwd(), ".mordant", "governed-fhe-bin"));
const GO_ROOT = resolve(process.cwd(), "fhe-lab", "lattigo");
const IMPORTED_EVIDENCE_ROOT = resolve(process.cwd(), "docs", "evidence", "conflicting-pledge-protection");
const MAX_PROCESS_BUFFER = 8 << 20;

const BINARIES = Object.freeze({
  keygen: "mordant-fhe-keygen",
  client: "mordant-fhe-client",
  evaluator: "mordant-fhe-evaluator",
  decryptor: "mordant-fhe-decryptor",
  recourse: "mordant-fhe-recourse",
});

type ExecutionStage =
  | "CASE_CREATED"
  | "MATCH_PREPARED"
  | "PARTICIPANT_A_SUBMITTED"
  | "PARTICIPANT_B_SUBMITTED"
  | "EVALUATED"
  | "RELEASED"
  | "RECOURSE_OPENED"
  | "CHRONOLOGY_COMPLETE"
  | "COMPLETE";

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

type InternalState = Readonly<{
  schemaVersion: "mordant.protection-execution/1";
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

export function evaluateDiskSpace(availableBytes: number): DiskPreflight {
  const requiredBytes = PRODUCT_STORAGE.estimatedCaseBytes + PRODUCT_STORAGE.safetyMarginBytes;
  return Object.freeze({
    availableBytes,
    estimatedCaseBytes: PRODUCT_STORAGE.estimatedCaseBytes,
    safetyMarginBytes: PRODUCT_STORAGE.safetyMarginBytes,
    requiredBytes,
    sufficient: Number.isSafeInteger(availableBytes) && availableBytes >= requiredBytes,
  });
}

export function diskSpacePreflight(root = process.cwd()): DiskPreflight {
  const stat = statfsSync(root, { bigint: true });
  const available = stat.bavail * stat.bsize;
  const availableBytes = available > BigInt(Number.MAX_SAFE_INTEGER)
    ? Number.MAX_SAFE_INTEGER
    : Number(available);
  return evaluateDiskSpace(availableBytes);
}

function assertDiskSpace(): DiskPreflight {
  const result = diskSpacePreflight();
  if (!result.sufficient) {
    throw new ProtectionProductError(
      `Insufficient disk for one N15 case: ${result.availableBytes} bytes available; `
      + `${result.requiredBytes} bytes required including safety margin. No key material was generated.`,
      507,
    );
  }
  return result;
}

function pathForBinary(name: keyof typeof BINARIES): string {
  return join(BIN_ROOT, BINARIES[name]);
}

async function ensureBinaries(): Promise<void> {
  if (process.env.NODE_ENV === "production") {
    throw new ProtectionProductError("Local BGV execution is unavailable in the deployed web runtime.", 404);
  }
  mkdirSync(BIN_ROOT, { recursive: true, mode: 0o700 });
  const goCache = join(RUN_ROOT, "go-build-cache");
  mkdirSync(goCache, { recursive: true, mode: 0o700 });
  for (const [name, binary] of Object.entries(BINARIES) as Array<[keyof typeof BINARIES, string]>) {
    const target = pathForBinary(name);
    if (existsSync(target)) continue;
    await execFileAsync("go", ["build", "-o", target, `./cmd/${binary}`], {
      cwd: GO_ROOT,
      maxBuffer: MAX_PROCESS_BUFFER,
      env: { ...process.env, CGO_ENABLED: "0", GOCACHE: goCache },
    });
    chmodSync(target, 0o700);
  }
}

function writeJsonAtomic(path: string, value: unknown, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode });
  renameSync(temporary, path);
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function assertRunId(runId: string): void {
  if (!/^[0-9a-f-]{36}$/.test(runId)) throw new ProtectionProductError("Invalid protection run id", 400);
}

function statePath(runId: string): string {
  assertRunId(runId);
  return join(RUN_ROOT, runId, "execution.json");
}

function loadState(runId: string): InternalState {
  const path = statePath(runId);
  if (!existsSync(path)) throw new ProtectionProductError("Protection case not found", 404);
  const state = readJson<InternalState>(path);
  if (state.runId !== runId || state.paths.root !== dirname(path)) {
    throw new ProtectionProductError("Protection execution record rejected", 500);
  }
  assertProtectionAssetBinding(state.protectionCase, CANONICAL_CLEANVERSE_ASSET_DIGEST);
  return state;
}

function saveState(state: InternalState): InternalState {
  writeJsonAtomic(statePath(state.runId), state);
  return state;
}

function nextOperation(stage: ExecutionStage, scenario: ProductScenario): string | null {
  switch (stage) {
    case "CASE_CREATED": return "preparePrivateMatch";
    case "MATCH_PREPARED": return "submitParticipantPledge:PARTICIPANT_A";
    case "PARTICIPANT_A_SUBMITTED": return "submitParticipantPledge:PARTICIPANT_B";
    case "PARTICIPANT_B_SUBMITTED": return "evaluatePrivateConflict";
    case "EVALUATED": return "releaseGovernedResult";
    case "RELEASED": return "openRecourseCase";
    case "RECOURSE_OPENED": return scenario === "conflict" ? "completeCureChronology" : "exportProtectionEvidence";
    case "CHRONOLOGY_COMPLETE": return "exportProtectionEvidence";
    case "COMPLETE": return null;
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

async function runJSON<T>(binary: keyof typeof BINARIES, args: readonly string[]): Promise<T> {
  try {
    const { stdout } = await execFileAsync(pathForBinary(binary), [...args], {
      cwd: process.cwd(),
      maxBuffer: MAX_PROCESS_BUFFER,
      env: { ...process.env },
    });
    return JSON.parse(stdout) as T;
  } catch (error) {
    const stderr = typeof error === "object" && error !== null && "stderr" in error
      ? String((error as { stderr: unknown }).stderr).trim()
      : "";
    throw new ProtectionProductError(stderr || `Governed FHE ${binary} operation failed`, 500);
  }
}

function rawParticipantKey(role: "PARTICIPANT_A" | "PARTICIPANT_B", root: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  if (publicJwk.x === undefined || privateJwk.d === undefined) {
    throw new ProtectionProductError("Participant key generation failed", 500);
  }
  const decode = (value: string) => Buffer.from(value, "base64url");
  const rawPublic = decode(publicJwk.x);
  const rawPrivate = Buffer.concat([decode(privateJwk.d), rawPublic]);
  const path = join(root, `${role.toLowerCase()}.ed25519`);
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

export async function createProtectionCase(scenario: ProductScenario): Promise<ProtectionCaseView> {
  if (scenario !== "conflict" && scenario !== "no-conflict") {
    throw new ProtectionProductError("Unsupported product scenario", 400);
  }
  const runId = randomUUID();
  const root = join(RUN_ROOT, runId);
  const createdAt = new Date().toISOString();
  const protectionCase = createProtectionCaseModel({
    scenario,
    createdAt,
    caseNonce: randomBytes(32).toString("hex"),
  });
  const state: InternalState = {
    schemaVersion: "mordant.protection-execution/1",
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
  mkdirSync(RUN_ROOT, { recursive: true, mode: 0o700 });
  mkdirSync(root, { recursive: false, mode: 0o700 });
  return publicView(saveState(state));
}

export async function preparePrivateMatch(runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
    if (state.stage !== "CASE_CREATED") throw new ProtectionProductError("Private match is already prepared");
    assertDiskSpace();
    await ensureBinaries();
    assertDiskSpace();

    mkdirSync(state.paths.publicRoot, { recursive: true, mode: 0o755 });
    mkdirSync(state.paths.decryptorPrivateRoot, { recursive: true, mode: 0o700 });
    mkdirSync(state.paths.participantPrivateRoot, { recursive: true, mode: 0o700 });
    const participantA = rawParticipantKey("PARTICIPANT_A", state.paths.participantPrivateRoot);
    const participantB = rawParticipantKey("PARTICIPANT_B", state.paths.participantPrivateRoot);
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

    const preparedCase = appendProtectionEvent(state.protectionCase, {
      kind: "HOLDER_SNAPSHOT_RECORDED",
      at: new Date().toISOString(),
      label: "Record-date holder allocation fixed at 60 / 40 and reserve held separately",
      classification: "PROTOCOL_DOUBLE",
      evidenceRef: state.protectionCase.holderAllocationDigest,
    }, { incidentState: "PRIVATE_MATCH_OPEN" });
    state = saveState({ ...state, protectionCase: preparedCase });

    const output = await runJSON<KeygenOutput>("keygen", [
      "-mode", "create",
      "-public-root", state.paths.publicRoot,
      "-private-root", state.paths.decryptorPrivateRoot,
      "-spec", specPath,
    ]);
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
    state = saveState({
      ...state,
      stage: "MATCH_PREPARED",
      keygen: output,
      participantKeys: { PARTICIPANT_A: participantA.path, PARTICIPANT_B: participantB.path },
    });
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

export async function submitParticipantPledge(
  runId: string,
  role: "PARTICIPANT_A" | "PARTICIPANT_B",
  expectedAssetDigest = CANONICAL_CLEANVERSE_ASSET_DIGEST,
): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
    assertProtectionAssetBinding(state.protectionCase, expectedAssetDigest);
    const expectedStage = role === "PARTICIPANT_A" ? "MATCH_PREPARED" : "PARTICIPANT_A_SUBMITTED";
    if (state.stage !== expectedStage || state.participantKeys === undefined) {
      throw new ProtectionProductError(`Participant ${role} submission is out of order`);
    }
    const pledgePath = join(state.paths.participantPrivateRoot, `${role.toLowerCase()}-pledge.json`);
    writeJsonAtomic(pledgePath, pledgeFor(state, role));
    const createdAtUnix = unix(state.protectionCase.createdAt);
    const output = await runJSON<SubmissionOutput>("client", [
      "-public-root", state.paths.publicRoot,
      "-role", role,
      "-signing-key", state.participantKeys[role],
      "-pledge", pledgePath,
      "-submission-nonce", digestText("MordantProtectionSubmission/v1", `${state.runId}/${role}`),
      "-expires-at", String(createdAtUnix + 3 * 60 * 60),
    ]);
    // Ordinary unlink of Mordant-generated transient plaintext/key files. This
    // is operational cleanup, not a secure-erasure claim.
    rmSync(pledgePath);
    rmSync(state.participantKeys[role]);

    const manifestName = role === "PARTICIPANT_A" ? "submission-a.json" : "submission-b.json";
    const artifact = readJson<Record<string, unknown>>(join(state.paths.publicRoot, manifestName));
    if (
      artifact.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || artifact.caseId !== state.protectionCase.fheCaseId
    ) {
      throw new ProtectionProductError("Participant artifact asset binding mismatch", 500);
    }
    const stage: ExecutionStage = role === "PARTICIPANT_A" ? "PARTICIPANT_A_SUBMITTED" : "PARTICIPANT_B_SUBMITTED";
    const event = appendProtectionEvent(state.protectionCase, {
      kind: `${role}_ENCRYPTED_PLEDGE_RECEIVED`,
      at: new Date().toISOString(),
      label: `${role === "PARTICIPANT_A" ? "Participant A" : "Participant B"} encrypted pledge received`,
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.artifactDigest,
    });
    state = { ...state, stage, protectionCase: event, submissions: { ...state.submissions, [role]: output } };
    if (role === "PARTICIPANT_B") {
      await runJSON<Record<string, unknown>>("keygen", [
        "-mode", "finalize",
        "-public-root", state.paths.publicRoot,
      ]);
    }
    state = saveState(state);
    return publicView(state);
  });
}

export async function evaluatePrivateConflict(runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
    if (state.stage !== "PARTICIPANT_B_SUBMITTED") throw new ProtectionProductError("Both encrypted submissions are required");
    const output = await runJSON<EvaluationOutput>("evaluator", ["-public-root", state.paths.publicRoot]);
    const artifact = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "evaluated-conflict.json"));
    if (
      artifact.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || artifact.caseId !== state.protectionCase.fheCaseId
    ) {
      throw new ProtectionProductError("Evaluated artifact asset binding mismatch", 500);
    }
    const protectionCase = appendProtectionEvent(state.protectionCase, {
      kind: "FHE_EVALUATION_COMPLETE",
      at: new Date().toISOString(),
      label: "Fixed N15 BGV conflict circuit evaluated without an evaluator decryption key",
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.artifactDigest,
    }, { incidentState: "EVALUATED" });
    state = saveState({ ...state, stage: "EVALUATED", protectionCase, evaluation: output });
    return publicView(state);
  });
}

export async function releaseGovernedResult(runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
    if (state.stage !== "EVALUATED") throw new ProtectionProductError("FHE evaluation is not complete");
    const output = await runJSON<ReleaseOutput>("decryptor", [
      "-public-root", state.paths.publicRoot,
      "-private-root", state.paths.decryptorPrivateRoot,
    ]);
    if (
      output.releaseMode !== state.protectionCase.releaseMode
      || output.conflict !== (state.protectionCase.productScenario === "conflict")
      || output.exactRetry
    ) {
      throw new ProtectionProductError("Governed release does not match the protection scenario", 500);
    }
    const result = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "governed-conflict-result.json"));
    if (
      result.assetIdentity !== state.protectionCase.cleanverseAssetDigest
      || result.caseId !== state.protectionCase.fheCaseId
      || result.releaseMode !== state.protectionCase.releaseMode
    ) {
      throw new ProtectionProductError("Governed result asset binding mismatch", 500);
    }
    let protectionCase = appendProtectionEvent(state.protectionCase, {
      kind: "GOVERNED_RECOMPUTATION_VERIFIED",
      at: new Date().toISOString(),
      label: "Governed decryptor independently recomputed the fixed circuit",
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.trustedRecoursePins.recomputedResultCiphertextDigest,
    });
    protectionCase = appendProtectionEvent(protectionCase, {
      kind: output.conflict ? "SIGNED_CONFLICT_CONFIRMED" : "SIGNED_CONFLICT_CLEARED",
      at: new Date().toISOString(),
      label: output.conflict ? "Signed Boolean confirmed a conflicting pledge" : "Signed Boolean cleared the conflicting-pledge check",
      classification: "LOCAL_EXECUTION",
      evidenceRef: output.resultDigest,
    }, { incidentState: output.conflict ? "CONFLICT_CONFIRMED" : "CLEARED" });
    state = saveState({ ...state, stage: "RELEASED", protectionCase, release: output });
    return publicView(state);
  });
}

export async function openRecourseCase(
  runId: string,
  expectedAssetDigest = CANONICAL_CLEANVERSE_ASSET_DIGEST,
): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
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
    const requestPath = join(state.paths.root, "recourse-request.json");
    const nowUnix = Math.floor(Date.now() / 1000);
    writeJsonAtomic(requestPath, {
      assetIdentity: state.protectionCase.cleanverseAssetDigest,
      caseId: state.protectionCase.fheCaseId,
      expectedPins: state.release.trustedRecoursePins,
      recordDateUnix: unix(state.protectionCase.holderRecordDate),
      holderAllocationDigest: state.protectionCase.holderAllocationDigest,
      nowUnix,
    });
    const recourse = await runJSON<NonNullable<InternalState["recourse"]>>("recourse", [
      "-mode", "recourse",
      "-public-root", state.paths.publicRoot,
      "-request", requestPath,
    ]);
    rmSync(requestPath);
    if (state.release.conflict !== recourse.opened) {
      throw new ProtectionProductError("Recourse admission does not match the signed Boolean", 500);
    }
    let protectionCase = state.protectionCase;
    if (recourse.opened) {
      const deadlineUnix = Number(recourse.record?.cureDeadlineUnix);
      const cureDeadline = new Date(deadlineUnix * 1000).toISOString();
      protectionCase = appendProtectionEvent(protectionCase, {
        kind: "CURE_WINDOW_OPENED",
        at: new Date().toISOString(),
        label: "Record-date holders remain fixed while the cure / dispute window runs",
        classification: "PROTOCOL_DOUBLE",
        evidenceRef: state.protectionCase.holderAllocationDigest,
      }, { cureDeadline, recourseState: "CURE_WINDOW" });
    } else {
      protectionCase = appendProtectionEvent(protectionCase, {
        kind: "RECOURSE_REFUSED",
        at: new Date().toISOString(),
        label: "A signed false result cannot open conflicting-pledge recourse",
        classification: "PROTOCOL_DOUBLE",
        evidenceRef: state.release.resultDigest,
      }, { recourseState: "REFUSED" });
    }
    state = saveState({ ...state, stage: "RECOURSE_OPENED", protectionCase, recourse });
    return publicView(state);
  });
}

export async function completeCureChronology(runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
    if (
      state.stage !== "RECOURSE_OPENED"
      || !state.recourse?.opened
      || state.protectionCase.cureDeadline === null
    ) {
      throw new ProtectionProductError("No conflict cure window is open");
    }
    const protectionCase = appendProtectionEvent(state.protectionCase, {
      kind: "RECOURSE_AVAILABLE_AFTER_CURE",
      at: new Date(new Date(state.protectionCase.cureDeadline).valueOf() + 1_000).toISOString(),
      label: "Local chronology reached the cure deadline; governed recourse is available",
      classification: "PROTOCOL_DOUBLE",
      evidenceRef: state.release?.resultDigest,
    }, { recourseState: "AVAILABLE" });
    state = saveState({ ...state, stage: "CHRONOLOGY_COMPLETE", protectionCase });
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
  governedFheEvidence: Readonly<Record<string, unknown>>,
): MordantProtectionEvidence {
  if (
    state.keygen === undefined || state.submissions?.PARTICIPANT_A === undefined
    || state.submissions.PARTICIPANT_B === undefined || state.evaluation === undefined
    || state.release === undefined || state.recourse === undefined
  ) {
    throw new ProtectionProductError("The complete governed FHE run is required", 500);
  }
  const binding = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "case-binding.json"));
  const evaluated = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "evaluated-conflict.json"));
  const result = readJson<Record<string, unknown>>(join(state.paths.publicRoot, "governed-conflict-result.json"));
  const publicKey = (readJson<Record<string, unknown>>(join(state.paths.publicRoot, "case-crypto.json")).publicKey ?? {}) as Record<string, unknown>;
  const participants = [binding.participantA, binding.participantB] as Array<Record<string, unknown>>;
  const resultCiphertext = (evaluated.resultCiphertext ?? {}) as Record<string, unknown>;
  const recourseRecord = state.recourse.record ?? null;
  const base: Omit<MordantProtectionEvidence, "manifestDigest"> = {
    schemaVersion: "mordant.protection-evidence/1",
    sourceCommit: SOURCE_COMMIT,
    governedFheCommit: GOVERNED_FHE_COMMIT,
    scenario: state.protectionCase.productScenario,
    cleanverseAsset: state.protectionCase.cleanverseAsset,
    cleanverseAssetDigest: state.protectionCase.cleanverseAssetDigest,
    sourceClassifications: [
      { subject: "Cleanverse MINV01 asset record", classification: "LIVE_OBSERVED", detail: "Retained M-11 issuance and readback evidence" },
      { subject: "N15 BGV evaluation and governed release", classification: "LOCAL_EXECUTION", detail: "Real single-host subprocess execution" },
      { subject: "Recourse admission and chronology", classification: "PROTOCOL_DOUBLE", detail: "Accepted local governed-FHE recourse adapter; no live settlement" },
      { subject: "Protected amount and private pledge contents", classification: "FIXTURE", detail: "Synthetic hackathon scenario" },
      { subject: "Legal issuer identity and production custody", classification: "UNPROVEN", detail: "Not established by the retained evidence" },
    ],
    protectionCase: state.protectionCase,
    participantPublicIdentities: [
      { role: "PARTICIPANT_A", id: participants[0]?.id as Sha256Digest, signingPublicKey: String(participants[0]?.signingPublicKey) },
      { role: "PARTICIPANT_B", id: participants[1]?.id as Sha256Digest, signingPublicKey: String(participants[1]?.signingPublicKey) },
    ],
    fhe: {
      caseId: state.protectionCase.fheCaseId,
      assetIdentity: state.protectionCase.cleanverseAssetDigest,
      caseBindingDigest: state.keygen.bindingDigest,
      profile: FHE_PARAMETER_PROFILE,
      circuitId: FHE_CIRCUIT,
      circuitVersion: Number(binding.circuitVersion),
      circuitDigest: binding.circuitDigest as Sha256Digest,
      publicKey: {
        path: String(publicKey.path),
        sha256: publicKey.sha256 as Sha256Digest,
        length: Number(publicKey.length),
      },
      evaluationKeyManifestDigest: binding.evaluationKeyManifestDigest as Sha256Digest,
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
    governedResult: {
      digest: state.release.resultDigest,
      assetIdentity: result.assetIdentity as Sha256Digest,
      conflict: state.release.conflict,
      signature: String(result.signature),
      releaseMode: state.release.releaseMode,
      releaseAuthorityId: result.releaseAuthorityId as Sha256Digest,
      releaseAuthorityPublicKey: String(result.releaseAuthorityPublicKey),
      releaseOrdinal: 1,
      releasedAtUnix: Number(result.releasedAtUnix),
    },
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
    generatedAt: new Date().toISOString(),
  };
  const evidence: MordantProtectionEvidence = { ...base, manifestDigest: protectionEvidenceDigest(base) };
  assertPublicProtectionEvidence(evidence);
  return evidence;
}

export async function exportProtectionEvidence(runId: string): Promise<ProtectionCaseView> {
  return exclusive(runId, async () => {
    let state = loadState(runId);
    const expectedStage = state.protectionCase.productScenario === "conflict" ? "CHRONOLOGY_COMPLETE" : "RECOURSE_OPENED";
    if (state.stage !== expectedStage || state.release === undefined || state.keygen === undefined) {
      throw new ProtectionProductError("The product journey is not complete");
    }
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
      completeDuration: (Math.floor(Date.now() / 1000) - state.startedAtUnix) * 1_000_000_000,
      peakRssBytes: 0,
    });
    const governedFheEvidence = await runJSON<Readonly<Record<string, unknown>>>("recourse", [
      "-mode", "evidence",
      "-public-root", state.paths.publicRoot,
      "-request", measurementsPath,
    ]);
    rmSync(measurementsPath);
    const evidence = buildProtectionEvidence(state, governedFheEvidence);
    writeJsonAtomic(join(state.paths.root, "protection-evidence.json"), evidence, 0o644);
    state = saveState({ ...state, stage: "COMPLETE", evidence });
    return publicView(state);
  });
}

export function readProtectionCase(runId: string): ProtectionCaseView {
  return publicView(loadState(runId));
}

export function loadImportedProtectionEvidence(scenario: ProductScenario = "conflict"): MordantProtectionEvidence {
  const path = join(IMPORTED_EVIDENCE_ROOT, `${scenario}.json`);
  if (!existsSync(path)) throw new ProtectionProductError("Imported protection evidence is unavailable", 503);
  const evidence = readJson<MordantProtectionEvidence>(path);
  assertPublicProtectionEvidence(evidence);
  return evidence;
}

export function retainProtectionEvidence(runId: string, destination: string): string {
  const state = loadState(runId);
  if (state.stage !== "COMPLETE" || state.evidence === undefined) {
    throw new ProtectionProductError("Only complete public evidence may be retained");
  }
  const allowed = resolve(IMPORTED_EVIDENCE_ROOT, `${state.protectionCase.productScenario}.json`);
  if (resolve(destination) !== allowed) throw new ProtectionProductError("Evidence destination rejected", 400);
  mkdirSync(IMPORTED_EVIDENCE_ROOT, { recursive: true });
  copyFileSync(join(state.paths.root, "protection-evidence.json"), allowed);
  return allowed;
}

export function validateRetainedPublicArtifacts(runId: string): Readonly<{
  evidenceDigest: Sha256Digest;
  governedResultDigest: Sha256Digest;
  privateMarkersAbsent: true;
}> {
  const state = loadState(runId);
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
