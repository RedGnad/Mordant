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
  PARTICIPANT_ADMISSION_PRIMARY_TYPE,
  PARTICIPANT_ADMISSION_TYPES,
  ParticipantAuthorizationError,
  assertParticipantAdmissionMessage,
  digestToBytes32,
  isParticipantRole,
  participantAdmissionDomain,
  verifyParticipantAuthorization,
  type ParticipantRole,
  type TypedDataVerifier,
} from "./participant-authorization";
import {
  ParticipantAdmissionStoreError,
  admissionAbandoned,
  admissionProgress,
  admitParticipantRole,
  bindCaseCode,
  generateCaseCode,
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
  readParticipantAdmissionContext: (runId: string) => Promise<ParticipantAdmissionContext>;
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
  /** The exact service the wallet signed for. */
  verifyingService: string;
  chainId?: number;
  verifyApass: (wallet: string) => Promise<ApassVerdict>;
  verifyTypedData: TypedDataVerifier;
  /** Unix seconds. */
  now: () => number;
  caseLifetimeSeconds?: number;
}>;

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
  if (abandoned) return "ABANDONED";
  switch (stage) {
    case "CASE_CREATED": return "CASE_CREATED_NEUTRAL";
    case "MATCH_PREPARED": return progress.participantA ? "PARTICIPANT_A_ADMITTED" : "MATCH_PREPARED";
    case "PARTICIPANT_A_SUBMITTED": return progress.participantB ? "PARTICIPANT_B_ADMITTED" : "PARTICIPANT_A_ADMITTED";
    case "PARTICIPANT_B_PUBLISHED": return "PARTICIPANT_B_ADMITTED";
    case "PARTICIPANT_B_SUBMITTED": return "SUBMISSIONS_FINALIZED";
    case "EVALUATED": return "EVALUATED";
    default: return "RELEASED";
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
  const created = await dependencies.orchestrator.createNeutralParticipantCase(creationRequestId);
  const runId = created.runId;
  const caseCode = generateCaseCode();
  bindCaseCode(dependencies.runRoot, caseCode, runId);
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
): Promise<ParticipantChallenge> {
  const runId = resolveCaseCode(dependencies.runRoot, caseCode);
  if (runId === null) fail("UNKNOWN_CASE", 404, "Unknown case code");
  const window = assertSupervisedPledgeWindow(
    claim,
    role === "PARTICIPANT_A" ? "participantA" : "participantB",
  );
  const context = await dependencies.orchestrator.readParticipantAdmissionContext(runId);
  const issuedAt = dependencies.now();
  return Object.freeze({
    schemaVersion: PARTICIPANT_CHALLENGE_SCHEMA,
    domain: participantAdmissionDomain(dependencies.chainId),
    primaryType: PARTICIPANT_ADMISSION_PRIMARY_TYPE,
    types: PARTICIPANT_ADMISSION_TYPES,
    message: Object.freeze({
      verifyingService: dependencies.verifyingService,
      runId,
      fheCaseId: digestToBytes32(context.fheCaseId),
      protectionBindingDigest: digestToBytes32(context.protectionBindingDigest),
      assetIdentityDigest: digestToBytes32(context.assetIdentityDigest),
      role,
      activeFrom: window.activeFrom,
      activeUntil: window.activeUntil,
      participantWallet,
      authorizationNonce: `0x${randomBytes(32).toString("hex")}`,
      issuedAt,
      expiresAt: issuedAt + PARTICIPANT_CHALLENGE_LIFETIME_SECONDS,
    }),
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

  const context = await dependencies.orchestrator.readParticipantAdmissionContext(runId);
  const message = assertParticipantAdmissionMessage(request.authorization);
  const verified = await verifyParticipantAuthorization(
    message,
    request.signature,
    {
      verifyingService: dependencies.verifyingService,
      runId,
      fheCaseId: context.fheCaseId,
      protectionBindingDigest: context.protectionBindingDigest,
      assetIdentityDigest: context.assetIdentityDigest,
      role: request.role,
      claim,
      chainId: dependencies.chainId,
      now: dependencies.now(),
    },
    dependencies.verifyTypedData,
  );

  // The active Cleanverse policy decides on the verified signing address, never
  // on an address the body merely asserted.
  const verdict = await dependencies.verifyApass(verified.participantWallet);
  if (!verdict.eligible) {
    fail("APASS_DENIED", 403, "That wallet does not pass the active compliance policy");
  }

  const outcome = admitParticipantRole(dependencies.runRoot, {
    runId,
    role: request.role,
    participantWallet: verified.participantWallet,
    authorizationDigest: verified.authorizationDigest,
    claimCommitment: verified.claimCommitment,
    authorizationNonce: message.authorizationNonce,
    issuedAt: message.issuedAt,
    expiresAt: message.expiresAt,
    eligibilityBlock: verdict.observedBlock,
    admittedAtUnix: dependencies.now(),
  });

  await dependencies.orchestrator.admitParticipantClaim(runId, request.role, {
    participantWallet: verified.participantWallet,
    authorizationDigest: verified.authorizationDigest,
    claimCommitment: verified.claimCommitment,
    authorizationNonce: message.authorizationNonce,
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
    || error instanceof ParticipantAdmissionStoreError) {
    return { status: error.status, code: error.code, message: error.message };
  }
  if (error instanceof SupervisedPledgeWindowsError) {
    return { status: 400, code: error.code, message: error.message };
  }
  return { status: 500, code: "ADMISSION", message: "Participant admission failed" };
}
