/**
 * Two-wallet participant admission.
 *
 * One neutral case, two independent wallets, two independent claims. Each wallet
 * proves control of its own address, passes the active Cleanverse policy, accepts
 * exactly one role, and writes exactly one claim. No caller ever supplies both
 * sides, and no role is ever inferred from the other.
 *
 * The order of operations is the safety property. Signature and policy are
 * checked before anything durable happens; the create-only ledger write admits
 * the role and consumes its nonce in one object; the engine's own state and then
 * the FHE submission follow. A loss at any boundary leaves a state the next
 * attempt can complete without inventing anything, and never one where a role has
 * been reassigned.
 *
 * What this does NOT do: it does not give either wallet custody of the FHE
 * participant Ed25519 key, and it does not encrypt anything in the browser. Those
 * keys are Mordant-generated and the private interval reaches Mordant
 * infrastructure in plaintext. See `docs/participant-admission.md`.
 */

import { randomBytes, randomUUID } from "node:crypto";

import type { CustomSupervisedProtectionView } from "./custom-supervised-view";
import type { AdmittedParticipantClaim, ParticipantAdmissionContext } from "./governed-fhe-product-server";
import {
  MONAD_TESTNET_CHAIN_ID,
  loadCanonicalRecourseConfiguration,
  type CanonicalRecourseConfiguration,
} from "./adapter-compatibility";
import {
  ParticipantAuthorizationError,
  digestToBytes32,
  isParticipantRole,
  participantClaimCommitment,
  type ParticipantRole,
  type TypedDataVerifier,
} from "./participant-authorization";
import { hashTypedData } from "viem";

import {
  ParticipantAdmissionV2Error,
  assertParticipantAdmissionV2Message,
  participantAdmissionV2TypedData,
  participantSigningKeyDigest,
  verifyParticipantAdmissionV2,
} from "./participant-admission-v2";
import {
  ParticipantAdmissionStoreError,
  admissionAbandoned,
  admissionProgress,
  admitParticipantRole,
  bindCaseCode,
  generateCaseCode,
  readAdmission,
  readAdmissions,
  resolveCaseCode,
  type AdmissionProgress,
} from "./participant-admission-store";
import { assertSupervisedPledgeWindow, SupervisedPledgeWindowsError } from "./supervised-pledge-windows";

export const PARTICIPANT_CASE_SCHEMA = "mordant.participant-case/1" as const;
export const PARTICIPANT_CHALLENGE_SCHEMA = "mordant.participant-admission-challenge/1" as const;

/** How long a case waits for its second participant before it is abandoned. */
export const PARTICIPANT_CASE_LIFETIME_SECONDS = 30 * 60;
/** How long a server-issued challenge stays signable. */
export const PARTICIPANT_CHALLENGE_LIFETIME_SECONDS = 10 * 60;

export class ParticipantAdmissionError extends Error {
  constructor(readonly code: string, readonly status: number, message: string) {
    super(message);
    this.name = "ParticipantAdmissionError";
  }
}

function fail(code: string, status: number, message: string): never {
  throw new ParticipantAdmissionError(code, status, message);
}

/** The engine surface this module drives. Narrow on purpose, so a test can supply it. */
export type AdmissionOrchestrator = Readonly<{
  createNeutralParticipantCase: (creationRequestId?: string) => Promise<{ runId: string }>;
  readCustomSupervisedCase: (runId: string) => Promise<CustomSupervisedProtectionView>;
  readParticipantAdmissionContext: (
    runId: string,
    role: "PARTICIPANT_A" | "PARTICIPANT_B",
  ) => Promise<ParticipantAdmissionContext>;
  preparePrivateMatch: (runId: string) => Promise<unknown>;
  admitParticipantClaim: (
    runId: string,
    role: ParticipantRole,
    admission: AdmittedParticipantClaim,
  ) => Promise<unknown>;
  submitParticipantPledge: (runId: string, role: ParticipantRole) => Promise<unknown>;
}>;

export type ApassVerdict = Readonly<{ eligible: boolean; holderAddress: string; observedBlock: number }>;

export type AdmissionDependencies = Readonly<{
  orchestrator: AdmissionOrchestrator;
  runRoot: string;
  /** Disabled by default; the worker enables it only after all runtime gates pass. */
  directParticipantAdmissionEnabled?: boolean;
  /** The exact service the wallet signed for. */
  verifyingService: string;
  chainId?: number;
  verifyApass: (wallet: string) => Promise<ApassVerdict>;
  verifyTypedData: TypedDataVerifier;
  /** Unix seconds. */
  now: () => number;
  caseLifetimeSeconds?: number;
  /** Records the durable case clock before private preparation begins. */
  onParticipantCaseCreated?: (input: Readonly<{ runId: string; caseCode: string }>) => void | Promise<void>;
}>;

function canonicalDirectAdmissionConfiguration(dependencies: AdmissionDependencies): CanonicalRecourseConfiguration {
  if (dependencies.directParticipantAdmissionEnabled !== true) {
    fail("DIRECT_ADMISSION_DISABLED", 403, "Direct participant admission is disabled");
  }
  if (dependencies.chainId !== MONAD_TESTNET_CHAIN_ID) {
    fail("DIRECT_ADMISSION_CHAIN", 403, `Direct participant admission requires chain ${MONAD_TESTNET_CHAIN_ID}`);
  }
  try {
    const canonical = loadCanonicalRecourseConfiguration();
    if (canonical.adapter.chainId !== MONAD_TESTNET_CHAIN_ID) {
      fail("DIRECT_ADMISSION_CHAIN", 503, "The canonical direct-admission chain is unavailable");
    }
    return canonical;
  } catch (error) {
    if (error instanceof ParticipantAdmissionError) throw error;
    fail("CANONICAL_CONFIGURATION", 503, "The canonical direct-admission configuration is unavailable");
  }
}

function assertCanonicalParticipantWallet(
  configuration: CanonicalRecourseConfiguration,
  role: ParticipantRole,
  wallet: string,
): `0x${string}` {
  const expected = role === "PARTICIPANT_A"
    ? configuration.participants.holderA
    : configuration.participants.holderB;
  if (typeof wallet !== "string" || wallet.toLowerCase() !== expected.toLowerCase()) {
    fail("CANONICAL_PARTICIPANT", 403, `That wallet is not the canonical ${role} participant`);
  }
  return expected;
}

/**
 * Public-safe admission projection.
 *
 * Wallet addresses are public facts a participant needs in order to see that the
 * other side is a different wallet. No claim, no interval and nothing about an
 * outcome appears here.
 */
export type ParticipantAdmissionProjection = Readonly<{
  schemaVersion: typeof PARTICIPANT_CASE_SCHEMA;
  caseCode: string;
  runId: string;
  lifecycle: ParticipantLifecycle;
  participantA: Readonly<{ admitted: boolean; wallet: string | null }>;
  participantB: Readonly<{ admitted: boolean; wallet: string | null }>;
  bothAdmitted: boolean;
  abandoned: boolean;
}>;

export const PARTICIPANT_LIFECYCLE = [
  "CASE_CREATED_NEUTRAL",
  "MATCH_PREPARED",
  "PARTICIPANT_A_ADMITTED",
  "PARTICIPANT_B_ADMITTED",
  "SUBMISSIONS_FINALIZED",
  "EVALUATED",
  "RELEASED",
  "EXECUTION_ABORTED",
  "ABANDONED",
] as const;
export type ParticipantLifecycle = (typeof PARTICIPANT_LIFECYCLE)[number];

/**
 * Maps the engine's audited execution stage plus the admission ledger onto the
 * participant lifecycle. The engine's own stage names are not renamed: the
 * journal, reconciliation and retained evidence all depend on them.
 */
export function participantLifecycle(
  stage: string,
  progress: AdmissionProgress,
  abandoned: boolean,
): ParticipantLifecycle {
  const knownStage = [
    "CASE_CREATED",
    "MATCH_PREPARED",
    "PARTICIPANT_A_SUBMITTED",
    "PARTICIPANT_B_PUBLISHED",
    "PARTICIPANT_B_SUBMITTED",
    "EVALUATED",
    "RELEASED",
    "RECOURSE_OPENED",
    "CHRONOLOGY_COMPLETE",
    "COMPLETE",
    "ABORTED",
  ].includes(stage);
  if (!knownStage) fail("ADMISSION_STAGE", 500, "The participant execution stage is not recognized");
  if (stage === "ABORTED") return "EXECUTION_ABORTED";
  if (abandoned) return "ABANDONED";
  switch (stage) {
    case "CASE_CREATED": return "CASE_CREATED_NEUTRAL";
    case "MATCH_PREPARED": return progress.participantA ? "PARTICIPANT_A_ADMITTED" : "MATCH_PREPARED";
    case "PARTICIPANT_A_SUBMITTED": return progress.participantB ? "PARTICIPANT_B_ADMITTED" : "PARTICIPANT_A_ADMITTED";
    case "PARTICIPANT_B_PUBLISHED": return "PARTICIPANT_B_ADMITTED";
    case "PARTICIPANT_B_SUBMITTED": return "SUBMISSIONS_FINALIZED";
    case "EVALUATED": return "EVALUATED";
    case "RELEASED":
    case "RECOURSE_OPENED":
    case "CHRONOLOGY_COMPLETE":
    case "COMPLETE": return "RELEASED";
    default: fail("ADMISSION_STAGE", 500, "The participant execution stage is not recognized");
  }
}

function projectAdmission(
  dependencies: AdmissionDependencies,
  caseCode: string,
  runId: string,
  stage: string,
  createdAtUnix: number,
): ParticipantAdmissionProjection {
  const progress = admissionProgress(dependencies.runRoot, runId);
  if (progress.participantB && !progress.participantA) {
    fail("ADMISSION_INTEGRITY", 500, "Participant B cannot be admitted before Participant A");
  }
  const abandoned = admissionAbandoned(
    dependencies.runRoot,
    runId,
    createdAtUnix,
    dependencies.now(),
    dependencies.caseLifetimeSeconds ?? PARTICIPANT_CASE_LIFETIME_SECONDS,
  );
  return Object.freeze({
    schemaVersion: PARTICIPANT_CASE_SCHEMA,
    caseCode,
    runId,
    lifecycle: participantLifecycle(stage, progress, abandoned),
    participantA: Object.freeze({ admitted: progress.participantA, wallet: progress.wallets.participantA }),
    participantB: Object.freeze({ admitted: progress.participantB, wallet: progress.wallets.participantB }),
    bothAdmitted: progress.bothAdmitted,
    abandoned,
  });
}

export type CreatedParticipantCase = Readonly<{
  runId: string;
  caseCode: string;
  view: CustomSupervisedProtectionView;
  admission: ParticipantAdmissionProjection;
}>;

/**
 * Creates a neutral case and prepares its private match.
 *
 * Preparation runs here rather than on first admission because the FHE case
 * binding must exist before any wallet can sign an authorization that references
 * it. No private input exists at this point, from anyone.
 */
export async function createParticipantCase(
  dependencies: AdmissionDependencies,
  creationRequestId: string = randomUUID(),
): Promise<CreatedParticipantCase> {
  canonicalDirectAdmissionConfiguration(dependencies);
  const created = await dependencies.orchestrator.createNeutralParticipantCase(creationRequestId);
  const runId = created.runId;
  const caseCode = generateCaseCode();
  bindCaseCode(dependencies.runRoot, caseCode, runId);
  // The worker records its durable case clock here, before BGV preparation can
  // consume significant resources or fail. A restart can therefore never reset
  // the participant lifetime merely because preparation had not completed.
  await dependencies.onParticipantCaseCreated?.(Object.freeze({ runId, caseCode }));
  await dependencies.orchestrator.preparePrivateMatch(runId);
  const view = await dependencies.orchestrator.readCustomSupervisedCase(runId);
  return Object.freeze({
    runId,
    caseCode,
    view,
    admission: projectAdmission(dependencies, caseCode, runId, view.stage, dependencies.now()),
  });
}

export type ParticipantCaseReadback = Readonly<{
  runId: string;
  caseCode: string;
  view: CustomSupervisedProtectionView;
  admission: ParticipantAdmissionProjection;
}>;

export async function readParticipantCase(
  dependencies: AdmissionDependencies,
  caseCode: string,
  createdAtUnix: number = dependencies.now(),
): Promise<ParticipantCaseReadback> {
  const runId = resolveCaseCode(dependencies.runRoot, caseCode);
  if (runId === null) fail("UNKNOWN_CASE", 404, "Unknown case code");
  const view = await dependencies.orchestrator.readCustomSupervisedCase(runId);
  return Object.freeze({
    runId,
    caseCode,
    view,
    admission: projectAdmission(dependencies, caseCode, runId, view.stage, createdAtUnix),
  });
}

// ------------------------------------------------------------------ challenge

export type ParticipantChallenge = Readonly<{
  schemaVersion: typeof PARTICIPANT_CHALLENGE_SCHEMA;
  domain: Readonly<{ name: string; version: string; chainId: number; salt: string }>;
  primaryType: string;
  types: unknown;
  message: Readonly<Record<string, unknown>>;
}>;

/**
 * The exact struct a wallet must sign, produced by the server.
 *
 * The nonce and both timestamps are server-generated, so a browser cannot choose
 * its own replay window. The interval is echoed back rather than invented here:
 * the participant already entered it, and it must appear in the wallet for them
 * to read before they approve.
 */
export async function participantAdmissionChallenge(
  dependencies: AdmissionDependencies,
  caseCode: string,
  role: ParticipantRole,
  participantWallet: string,
  claim: unknown,
  createdAtUnix?: number,
): Promise<ParticipantChallenge> {
  const canonical = canonicalDirectAdmissionConfiguration(dependencies);
  if (!isParticipantRole(role)) fail("ROLE", 400, "The role must be PARTICIPANT_A or PARTICIPANT_B");
  const canonicalWallet = assertCanonicalParticipantWallet(canonical, role, participantWallet);
  const runId = resolveCaseCode(dependencies.runRoot, caseCode);
  if (runId === null) fail("UNKNOWN_CASE", 404, "Unknown case code");
  const caseCreatedAt = createdAtUnix ?? dependencies.now();
  if (admissionAbandoned(
    dependencies.runRoot,
    runId,
    caseCreatedAt,
    dependencies.now(),
    dependencies.caseLifetimeSeconds ?? PARTICIPANT_CASE_LIFETIME_SECONDS,
  )) {
    fail("CASE_ABANDONED", 410, "This case is no longer accepting participants");
  }
  if (readAdmission(dependencies.runRoot, runId, role) !== null) {
    fail("ROLE_OCCUPIED", 409, `${role} has already been admitted for this case`);
  }
  const window = assertSupervisedPledgeWindow(
    claim,
    role === "PARTICIPANT_A" ? "participantA" : "participantB",
  );
  const context = await dependencies.orchestrator.readParticipantAdmissionContext(runId, role);
  const expectedStage = role === "PARTICIPANT_A" ? "MATCH_PREPARED" : "PARTICIPANT_A_SUBMITTED";
  if (context.stage !== expectedStage) {
    fail("ADMISSION_OUT_OF_ORDER", 409, `Participant ${role} admission is out of order`);
  }
  // The key this wallet is about to authorize. It already exists: the context
  // materialises this role's key before its wallet is asked to sign, so a wallet
  // never names a key the case has yet to choose.
  const signingKeyDigest = participantSigningKeyDigest(context.participantSigningKey);
  const issuedAt = dependencies.now();
  const typed = participantAdmissionV2TypedData({
    verifyingService: dependencies.verifyingService,
    runId,
    fheCaseId: digestToBytes32(context.fheCaseId),
    protectionBindingDigest: digestToBytes32(context.protectionBindingDigest),
    assetIdentityDigest: digestToBytes32(context.assetIdentityDigest),
    role,
    activeFrom: window.activeFrom,
    activeUntil: window.activeUntil,
    participantWallet: canonicalWallet as `0x${string}`,
    authorizationNonce: `0x${randomBytes(32).toString("hex")}`,
    issuedAt,
    expiresAt: issuedAt + PARTICIPANT_CHALLENGE_LIFETIME_SECONDS,
    participantSigningKeyDigest: signingKeyDigest,
  }, dependencies.chainId);
  return Object.freeze({
    schemaVersion: PARTICIPANT_CHALLENGE_SCHEMA,
    domain: typed.domain,
    primaryType: typed.primaryType,
    types: typed.types,
    message: Object.freeze(typed.message as Readonly<Record<string, unknown>>),
  });
}

// ------------------------------------------------------------------ admission

export type AdmissionRequest = Readonly<{
  caseCode: string;
  role: ParticipantRole;
  authorization: unknown;
  signature: unknown;
  claim: unknown;
}>;

/** Exact parse of an untrusted admission body. */
export function assertAdmissionRequest(value: unknown): AdmissionRequest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("BODY_SHAPE", 400, "An exact admission body is required");
  }
  const body = value as Record<string, unknown>;
  const keys = Object.keys(body).sort();
  const expected = ["authorization", "caseCode", "claim", "role", "signature"];
  if (keys.length !== expected.length || !keys.every((key, index) => key === expected[index])) {
    fail("BODY_MEMBERS", 400, "The admission members are not exact");
  }
  if (typeof body.caseCode !== "string") fail("CASE_CODE", 400, "A case code is required");
  if (!isParticipantRole(body.role)) fail("ROLE", 400, "The role must be PARTICIPANT_A or PARTICIPANT_B");
  return Object.freeze({
    caseCode: body.caseCode,
    role: body.role,
    authorization: body.authorization,
    signature: body.signature,
    claim: body.claim,
  });
}

export type AdmissionResult = Readonly<{
  runId: string;
  caseCode: string;
  role: ParticipantRole;
  participantWallet: string;
  eligibilityBlock: number;
  /** False when this exact authorization had already been admitted. */
  newlyAdmitted: boolean;
  admission: ParticipantAdmissionProjection;
  view: CustomSupervisedProtectionView;
}>;

/**
 * Admits one participant and submits only that participant's claim.
 *
 * Evaluation is never started here. It becomes reachable only once the engine
 * itself reports both submissions finalized, which cannot happen with one
 * participant because the engine refuses B's submission before A's exists.
 */
export async function admitParticipant(
  dependencies: AdmissionDependencies,
  request: AdmissionRequest,
  createdAtUnix?: number,
): Promise<AdmissionResult> {
  const canonical = canonicalDirectAdmissionConfiguration(dependencies);
  const runId = resolveCaseCode(dependencies.runRoot, request.caseCode);
  if (runId === null) fail("UNKNOWN_CASE", 404, "Unknown case code");

  const caseCreatedAt = createdAtUnix ?? dependencies.now();
  if (admissionAbandoned(
    dependencies.runRoot,
    runId,
    caseCreatedAt,
    dependencies.now(),
    dependencies.caseLifetimeSeconds ?? PARTICIPANT_CASE_LIFETIME_SECONDS,
  )) {
    fail("CASE_ABANDONED", 410, "This case is no longer accepting participants");
  }

  // The claim is validated before the signature, so a malformed interval is
  // rejected without spending a signature verification on it.
  const claim = assertSupervisedPledgeWindow(
    request.claim,
    request.role === "PARTICIPANT_A" ? "participantA" : "participantB",
  );

  const context = await dependencies.orchestrator.readParticipantAdmissionContext(runId, request.role);
  const expectedStage = request.role === "PARTICIPANT_A" ? "MATCH_PREPARED" : "PARTICIPANT_A_SUBMITTED";
  // Do not reserve a durable role before the engine can accept it. Exact
  // retries are allowed to repair a crash after the ledger write.
  if (readAdmission(dependencies.runRoot, runId, request.role) === null && context.stage !== expectedStage) {
    fail("ADMISSION_OUT_OF_ORDER", 409, `Participant ${request.role} admission is out of order`);
  }
  // V2 is verified here, and the signing-key digest is compared against the key
  // this server already holds for the role. The challenge emits that digest; a
  // wallet that signed a different one is refused rather than admitted.
  const message = assertParticipantAdmissionV2Message(request.authorization);
  const admitted = await verifyParticipantAdmissionV2(
    message,
    request.signature,
    {
      verifyingService: dependencies.verifyingService,
      runId,
      fheCaseId: digestToBytes32(context.fheCaseId),
      protectionBindingDigest: digestToBytes32(context.protectionBindingDigest),
      assetIdentityDigest: digestToBytes32(context.assetIdentityDigest),
      role: request.role,
      participantSigningKeyBase64: context.participantSigningKey,
      activeFrom: claim.activeFrom,
      activeUntil: claim.activeUntil,
      chainId: dependencies.chainId,
      now: dependencies.now(),
    },
    async (input) => dependencies.verifyTypedData({
      address: input.address,
      typedData: input.typedData as never,
      digest: hashTypedData(input.typedData as never),
      signature: input.signature,
    }),
  );
  const verified = Object.freeze({
    message: admitted.message,
    role: admitted.message.role,
    authorizationDigest: hashTypedData(
      participantAdmissionV2TypedData(admitted.message, dependencies.chainId) as never,
    ) as `0x${string}`,
    signature: request.signature as `0x${string}`,
    participantWallet: admitted.message.participantWallet,
    claimCommitment: participantClaimCommitment({ runId, role: admitted.message.role, claim }),
  });
  assertCanonicalParticipantWallet(canonical, request.role, verified.participantWallet);

  // The active Cleanverse policy decides on the verified signing address, never
  // on an address the body merely asserted.
  const verdict = await dependencies.verifyApass(verified.participantWallet);
  if (!verdict.eligible) {
    fail("APASS_DENIED", 403, "That wallet does not pass the active compliance policy");
  }
  if (typeof verdict.holderAddress !== "string" || verdict.holderAddress.toLowerCase() !== verified.participantWallet.toLowerCase()) {
    fail("APASS_IDENTITY", 403, "The compliance verdict did not bind the verified wallet");
  }

  const outcome = admitParticipantRole(dependencies.runRoot, {
    runId,
    role: request.role,
    participantWallet: verified.participantWallet,
    authorizationDigest: verified.authorizationDigest,
    participantSigningKeyDigest: admitted.signingKeyDigest,
    claimCommitment: verified.claimCommitment,
    authorizationNonce: message.authorizationNonce,
    chainId: canonical.adapter.chainId,
    issuedAt: message.issuedAt,
    expiresAt: message.expiresAt,
    eligibilityBlock: verdict.observedBlock,
    admittedAtUnix: dependencies.now(),
    // The signed struct and its signature, retained verbatim. Nothing here is
    // secret: it is the participant's own public authorization, and keeping it
    // is what lets the bridge re-verify the wallet after the run is pruned.
    authorization: { ...verified.message },
    signature: verified.signature,
  });

  await dependencies.orchestrator.admitParticipantClaim(runId, request.role, {
    participantWallet: verified.participantWallet,
    authorizationDigest: verified.authorizationDigest,
    claimCommitment: verified.claimCommitment,
    authorizationNonce: message.authorizationNonce,
    chainId: canonical.adapter.chainId,
    issuedAt: message.issuedAt,
    expiresAt: message.expiresAt,
    claim,
  });

  // Only this role's own artifact is produced.
  await dependencies.orchestrator.submitParticipantPledge(runId, request.role);

  const view = await dependencies.orchestrator.readCustomSupervisedCase(runId);
  return Object.freeze({
    runId,
    caseCode: request.caseCode,
    role: request.role,
    participantWallet: verified.participantWallet,
    eligibilityBlock: verdict.observedBlock,
    newlyAdmitted: outcome.admitted,
    admission: projectAdmission(dependencies, request.caseCode, runId, view.stage, caseCreatedAt),
    view,
  });
}

export function admittedWallets(runRoot: string, runId: string): Readonly<Record<string, string>> {
  const admitted = readAdmissions(runRoot, runId);
  const wallets: Record<string, string> = {};
  for (const [role, record] of Object.entries(admitted)) {
    if (record !== undefined) wallets[role] = record.participantWallet;
  }
  return Object.freeze(wallets);
}

/** Normalizes every failure this module can raise into one HTTP-shaped answer. */
export function admissionFailure(error: unknown): Readonly<{ status: number; code: string; message: string }> {
  if (error instanceof ParticipantAdmissionError
    || error instanceof ParticipantAuthorizationError
    || error instanceof ParticipantAdmissionStoreError
    // A V2 refusal is as diagnosable as the others and says nothing private: it
    // names a schema, a role, a window or a key binding. Leaving it out made
    // every V2 refusal reach the browser as an opaque 500, so a participant
    // whose admission named the wrong key was told only that the service
    // refused the request.
    || error instanceof ParticipantAdmissionV2Error) {
    return { status: error.status, code: error.code, message: error.message };
  }
  if (error instanceof SupervisedPledgeWindowsError) {
    return { status: 400, code: error.code, message: error.message };
  }
  return { status: 500, code: "ADMISSION", message: "Participant admission failed" };
}
