/**
 * Exact browser-side contracts for the dormant participant-admission worker
 * routes. These are intentionally UI-owned: a typed TypeScript assertion is not
 * a network parser, and the browser must refuse a response that is broader than
 * the public projection it is allowed to render.
 */

import { parseManagedWorkerView, type ManagedWorkerView } from "./managed-intake-adapter";

export const PARTICIPANT_CASE_SCHEMA = "mordant.participant-case/1" as const;
export const PARTICIPANT_CHALLENGE_SCHEMA = "mordant.participant-admission-challenge/1" as const;
export const LIVE_WORKER_SCHEMA = "mordant.live-worker/1" as const;
export const PARTICIPANT_ADMISSION_PRIMARY_TYPE = "ParticipantAdmissionV1" as const;
/** `keccak256(toHex("mordant.participant-admission/1"))`, pinned by the worker contract. */
export const PARTICIPANT_ADMISSION_DOMAIN_SALT =
  "0x140e0c549c6e2bee1578dce11133296086e105ae9861f1935a89a6df0710cf15" as const;

export type DirectParticipantRole = "A" | "B";
export type WorkerParticipantRole = "PARTICIPANT_A" | "PARTICIPANT_B";

export function workerRoleFor(role: DirectParticipantRole): WorkerParticipantRole {
  return role === "A" ? "PARTICIPANT_A" : "PARTICIPANT_B";
}

export function directRoleFor(role: WorkerParticipantRole): DirectParticipantRole {
  return role === "PARTICIPANT_A" ? "A" : "B";
}

export type AdmissionClaim = Readonly<{ activeFrom: number; activeUntil: number }>;

export type ParticipantProjection = Readonly<{
  admitted: boolean;
  wallet: string | null;
}>;

export type ParticipantAdmissionProjection = Readonly<{
  schemaVersion: typeof PARTICIPANT_CASE_SCHEMA;
  caseCode: string;
  runId: string;
  lifecycle:
    | "CASE_CREATED_NEUTRAL"
    | "MATCH_PREPARED"
    | "PARTICIPANT_A_ADMITTED"
    | "PARTICIPANT_B_ADMITTED"
    | "SUBMISSIONS_FINALIZED"
    | "EVALUATED"
    | "RELEASED"
    | "ABANDONED"
    | "EXECUTION_ABORTED";
  participantA: ParticipantProjection;
  participantB: ParticipantProjection;
  bothAdmitted: boolean;
  abandoned: boolean;
}>;

export type ParticipantCaseResponse = Readonly<{
  view: ManagedWorkerView;
  admission: ParticipantAdmissionProjection;
  progress: string;
}>;

export const PARTICIPANT_ADMISSION_TYPES = Object.freeze({
  ParticipantAdmissionV1: Object.freeze([
    Object.freeze({ name: "verifyingService", type: "string" }),
    Object.freeze({ name: "runId", type: "string" }),
    Object.freeze({ name: "fheCaseId", type: "bytes32" }),
    Object.freeze({ name: "protectionBindingDigest", type: "bytes32" }),
    Object.freeze({ name: "assetIdentityDigest", type: "bytes32" }),
    Object.freeze({ name: "role", type: "string" }),
    Object.freeze({ name: "activeFrom", type: "uint64" }),
    Object.freeze({ name: "activeUntil", type: "uint64" }),
    Object.freeze({ name: "participantWallet", type: "address" }),
    Object.freeze({ name: "authorizationNonce", type: "bytes32" }),
    Object.freeze({ name: "issuedAt", type: "uint64" }),
    Object.freeze({ name: "expiresAt", type: "uint64" }),
  ]),
});

export type ParticipantAuthorization = Readonly<{
  verifyingService: string;
  runId: string;
  fheCaseId: `0x${string}`;
  protectionBindingDigest: `0x${string}`;
  assetIdentityDigest: `0x${string}`;
  role: WorkerParticipantRole;
  activeFrom: number;
  activeUntil: number;
  participantWallet: `0x${string}`;
  authorizationNonce: `0x${string}`;
  issuedAt: number;
  expiresAt: number;
}>;

export type ParticipantChallenge = Readonly<{
  schemaVersion: typeof PARTICIPANT_CHALLENGE_SCHEMA;
  domain: Readonly<{
    name: "Mordant Participant Admission";
    version: "1";
    chainId: number;
    salt: `0x${string}`;
  }>;
  primaryType: typeof PARTICIPANT_ADMISSION_PRIMARY_TYPE;
  types: typeof PARTICIPANT_ADMISSION_TYPES;
  message: ParticipantAuthorization;
}>;

export type AdmissionPost = Readonly<{
  role: WorkerParticipantRole;
  authorization: ParticipantAuthorization;
  signature: `0x${string}`;
  claim: AdmissionClaim;
}>;

export type ParticipantAdmissionResponse = Readonly<ParticipantCaseResponse & {
  role: WorkerParticipantRole;
  participantWallet: string;
  eligibilityBlock: number;
  newlyAdmitted: boolean;
}>;

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const CASE_CODE = /^[0-9A-HJKMNP-TV-Z]{16}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const FORBIDDEN_PUBLIC_KEYS = Object.freeze([
  "activeFrom", "activeUntil", "supervisedPledgeWindows", "pledges", "admittedClaims", "claim", "productScenario",
]);
const LIFECYCLES = Object.freeze([
  "CASE_CREATED_NEUTRAL", "MATCH_PREPARED", "PARTICIPANT_A_ADMITTED", "PARTICIPANT_B_ADMITTED",
  "SUBMISSIONS_FINALIZED", "EVALUATED", "RELEASED", "ABANDONED", "EXECUTION_ABORTED",
] as const);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function addressMatches(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function projection(value: unknown): ParticipantProjection | null {
  if (!exactRecord(value, ["admitted", "wallet"])) return null;
  if (typeof value.admitted !== "boolean") return null;
  if (value.wallet !== null && (typeof value.wallet !== "string" || !ADDRESS.test(value.wallet))) return null;
  // A public wallet is meaningful only after a role is admitted. This prevents a
  // response from smuggling an unaudited address into a waiting-role panel.
  if ((value.admitted && value.wallet === null) || (!value.admitted && value.wallet !== null)) return null;
  return Object.freeze({ admitted: value.admitted, wallet: value.wallet as string | null });
}

function admissionProjection(value: unknown): ParticipantAdmissionProjection | null {
  if (!exactRecord(value, [
    "schemaVersion", "caseCode", "runId", "lifecycle", "participantA", "participantB", "bothAdmitted", "abandoned",
  ])) return null;
  if (value.schemaVersion !== PARTICIPANT_CASE_SCHEMA || typeof value.caseCode !== "string" || !CASE_CODE.test(value.caseCode)) return null;
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId)) return null;
  if (typeof value.lifecycle !== "string" || !(LIFECYCLES as readonly string[]).includes(value.lifecycle)) return null;
  if (typeof value.bothAdmitted !== "boolean" || typeof value.abandoned !== "boolean") return null;
  const participantA = projection(value.participantA);
  const participantB = projection(value.participantB);
  if (participantA === null || participantB === null) return null;
  if (participantB.admitted && !participantA.admitted) return null;
  if (value.bothAdmitted !== (participantA.admitted && participantB.admitted)) return null;
  if (value.abandoned && value.bothAdmitted) return null;
  if (value.abandoned !== (value.lifecycle === "ABANDONED")) return null;
  if (!value.abandoned && value.lifecycle !== "EXECUTION_ABORTED") {
    const lifecycle = value.lifecycle;
    const consistent = (lifecycle === "CASE_CREATED_NEUTRAL" || lifecycle === "MATCH_PREPARED")
      ? !participantA.admitted && !participantB.admitted
      : lifecycle === "PARTICIPANT_A_ADMITTED"
        ? participantA.admitted && !participantB.admitted
        : (lifecycle === "PARTICIPANT_B_ADMITTED" || lifecycle === "SUBMISSIONS_FINALIZED"
          || lifecycle === "EVALUATED" || lifecycle === "RELEASED")
          && participantA.admitted && participantB.admitted;
    if (!consistent) return null;
  }
  return Object.freeze({
    schemaVersion: PARTICIPANT_CASE_SCHEMA,
    caseCode: value.caseCode,
    runId: value.runId,
    lifecycle: value.lifecycle as ParticipantAdmissionProjection["lifecycle"],
    participantA,
    participantB,
    bothAdmitted: value.bothAdmitted,
    abandoned: value.abandoned,
  });
}

/** A closed admission lifecycle must remain compatible with the worker's stage. */
function admissionMatchesView(admission: ParticipantAdmissionProjection, view: ManagedWorkerView): boolean {
  if (view.stage === "ABORTED") return admission.lifecycle === "EXECUTION_ABORTED" && !admission.abandoned && view.governedResult === null;
  if (admission.abandoned || admission.lifecycle === "EXECUTION_ABORTED") return false;
  switch (view.stage) {
    case "CASE_CREATED":
      return admission.lifecycle === "CASE_CREATED_NEUTRAL";
    case "MATCH_PREPARED":
      return admission.lifecycle === "MATCH_PREPARED" || admission.lifecycle === "PARTICIPANT_A_ADMITTED";
    case "PARTICIPANT_A_SUBMITTED":
      return admission.lifecycle === "PARTICIPANT_A_ADMITTED" || admission.lifecycle === "PARTICIPANT_B_ADMITTED";
    case "PARTICIPANT_B_PUBLISHED":
      return admission.lifecycle === "PARTICIPANT_B_ADMITTED";
    case "PARTICIPANT_B_SUBMITTED":
      return admission.lifecycle === "SUBMISSIONS_FINALIZED";
    case "EVALUATED":
      return admission.lifecycle === "EVALUATED";
    case "RELEASED":
    case "RECOURSE_OPENED":
    case "CHRONOLOGY_COMPLETE":
    case "COMPLETE":
      return admission.lifecycle === "RELEASED" && admission.bothAdmitted;
  }
}

function publicProgress(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" && value.length <= 160 ? value : null;
}

function carriesForbiddenPublicKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(carriesForbiddenPublicKey);
  if (!record(value)) return false;
  for (const [key, nested] of Object.entries(value)) {
    if ((FORBIDDEN_PUBLIC_KEYS as readonly string[]).includes(key) || carriesForbiddenPublicKey(nested)) return true;
  }
  return false;
}

function participantCase(value: unknown): ParticipantCaseResponse | null {
  if (!exactRecord(value, ["schemaVersion", "view", "admission", "progress"])) return null;
  if (value.schemaVersion !== LIVE_WORKER_SCHEMA || carriesForbiddenPublicKey(value.admission)) return null;
  const view = parseManagedWorkerView(value.view);
  const admission = admissionProjection(value.admission);
  const progress = publicProgress(value.progress);
  if (view === null || admission === null || progress === null || admission.runId !== view.runId
    || !admissionMatchesView(admission, view)) return null;
  return Object.freeze({ view, admission, progress });
}

/** Exact parser for create and read participant-case responses. */
export function parseParticipantCaseResponse(value: unknown): ParticipantCaseResponse | null {
  return participantCase(value);
}

function validClaim(value: unknown): value is AdmissionClaim {
  return record(value)
    && Object.keys(value).length === 2
    && Object.keys(value).includes("activeFrom")
    && Object.keys(value).includes("activeUntil")
    && typeof value.activeFrom === "number"
    && Number.isSafeInteger(value.activeFrom)
    && value.activeFrom >= 0
    && typeof value.activeUntil === "number"
    && Number.isSafeInteger(value.activeUntil)
    && value.activeUntil > value.activeFrom;
}

function expectedTypes(value: unknown): boolean {
  if (!exactRecord(value, [PARTICIPANT_ADMISSION_PRIMARY_TYPE])) return false;
  const fields = value[PARTICIPANT_ADMISSION_PRIMARY_TYPE];
  if (!Array.isArray(fields) || fields.length !== PARTICIPANT_ADMISSION_TYPES.ParticipantAdmissionV1.length) return false;
  return fields.every((field, index) => exactRecord(field, ["name", "type"])
    && field.name === PARTICIPANT_ADMISSION_TYPES.ParticipantAdmissionV1[index].name
    && field.type === PARTICIPANT_ADMISSION_TYPES.ParticipantAdmissionV1[index].type);
}

function authorization(value: unknown): ParticipantAuthorization | null {
  if (!exactRecord(value, [
    "verifyingService", "runId", "fheCaseId", "protectionBindingDigest", "assetIdentityDigest", "role",
    "activeFrom", "activeUntil", "participantWallet", "authorizationNonce", "issuedAt", "expiresAt",
  ])) return null;
  if (typeof value.verifyingService !== "string" || value.verifyingService.length === 0 || value.verifyingService.length > 255) return null;
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId)) return null;
  if (value.role !== "PARTICIPANT_A" && value.role !== "PARTICIPANT_B") return null;
  for (const digest of [value.fheCaseId, value.protectionBindingDigest, value.assetIdentityDigest, value.authorizationNonce]) {
    if (typeof digest !== "string" || !BYTES32.test(digest)) return null;
  }
  const activeFrom = value.activeFrom;
  const activeUntil = value.activeUntil;
  if (typeof activeFrom !== "number" || !Number.isSafeInteger(activeFrom) || activeFrom < 0
    || typeof activeUntil !== "number" || !Number.isSafeInteger(activeUntil) || activeUntil <= activeFrom) return null;
  if (typeof value.participantWallet !== "string" || !ADDRESS.test(value.participantWallet)) return null;
  const issuedAt = value.issuedAt;
  const expiresAt = value.expiresAt;
  if (typeof issuedAt !== "number" || !Number.isSafeInteger(issuedAt) || typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || issuedAt <= 0
    || expiresAt <= issuedAt || expiresAt - issuedAt > 15 * 60) return null;
  return Object.freeze({
    verifyingService: value.verifyingService,
    runId: value.runId,
    fheCaseId: value.fheCaseId as `0x${string}`,
    protectionBindingDigest: value.protectionBindingDigest as `0x${string}`,
    assetIdentityDigest: value.assetIdentityDigest as `0x${string}`,
    role: value.role,
    activeFrom,
    activeUntil,
    participantWallet: value.participantWallet as `0x${string}`,
    authorizationNonce: value.authorizationNonce as `0x${string}`,
    issuedAt,
    expiresAt,
  });
}

export function parseParticipantChallengeResponse(value: unknown, expected: Readonly<{
  runId: string;
  role: WorkerParticipantRole;
  participantWallet: string;
  claim: AdmissionClaim;
  fheCaseId: `0x${string}`;
  assetIdentityDigest: `0x${string}`;
  expectedChainId: number;
  expectedService: string;
  nowUnixSeconds: number;
}>): ParticipantChallenge | null {
  if (!exactRecord(value, ["schemaVersion", "challenge"]) || value.schemaVersion !== LIVE_WORKER_SCHEMA) return null;
  const raw = value.challenge;
  if (!exactRecord(raw, ["schemaVersion", "domain", "primaryType", "types", "message"])) return null;
  if (raw.schemaVersion !== PARTICIPANT_CHALLENGE_SCHEMA || raw.primaryType !== PARTICIPANT_ADMISSION_PRIMARY_TYPE || !expectedTypes(raw.types)) return null;
  if (!exactRecord(raw.domain, ["name", "version", "chainId", "salt"])) return null;
  if (raw.domain.name !== "Mordant Participant Admission" || raw.domain.version !== "1"
    || raw.domain.chainId !== expected.expectedChainId || raw.domain.salt !== PARTICIPANT_ADMISSION_DOMAIN_SALT) return null;
  const message = authorization(raw.message);
  if (message === null) return null;
  if (message.verifyingService !== expected.expectedService || message.runId !== expected.runId || message.role !== expected.role
    || !addressMatches(message.participantWallet, expected.participantWallet)
    || message.activeFrom !== expected.claim.activeFrom || message.activeUntil !== expected.claim.activeUntil
    || message.fheCaseId !== expected.fheCaseId || message.assetIdentityDigest !== expected.assetIdentityDigest
    || message.expiresAt <= expected.nowUnixSeconds) return null;
  return Object.freeze({
    schemaVersion: PARTICIPANT_CHALLENGE_SCHEMA,
    domain: Object.freeze({
      name: "Mordant Participant Admission",
      version: "1",
      chainId: raw.domain.chainId,
      salt: raw.domain.salt as `0x${string}`,
    }),
    primaryType: PARTICIPANT_ADMISSION_PRIMARY_TYPE,
    types: PARTICIPANT_ADMISSION_TYPES,
    message,
  });
}

/** Exact parser for a successful admission response, tied to the one signed role. */
export function parseParticipantAdmissionResponse(value: unknown, expected: Readonly<{
  caseCode: string;
  role: WorkerParticipantRole;
  participantWallet: string;
}>): ParticipantAdmissionResponse | null {
  if (!exactRecord(value, [
    "schemaVersion", "role", "participantWallet", "eligibilityBlock", "newlyAdmitted", "view", "admission", "progress",
  ]) || value.schemaVersion !== LIVE_WORKER_SCHEMA) return null;
  if ((value.role !== "PARTICIPANT_A" && value.role !== "PARTICIPANT_B") || value.role !== expected.role) return null;
  if (typeof value.participantWallet !== "string" || !ADDRESS.test(value.participantWallet)
    || !addressMatches(value.participantWallet, expected.participantWallet)) return null;
  const eligibilityBlock = value.eligibilityBlock;
  if (typeof eligibilityBlock !== "number" || !Number.isSafeInteger(eligibilityBlock) || eligibilityBlock < 0 || typeof value.newlyAdmitted !== "boolean") return null;
  const parsed = participantCase({
    schemaVersion: value.schemaVersion,
    view: value.view,
    admission: value.admission,
    progress: value.progress,
  });
  if (parsed === null || parsed.admission.caseCode !== expected.caseCode) return null;
  const own = expected.role === "PARTICIPANT_A" ? parsed.admission.participantA : parsed.admission.participantB;
  if (!own.admitted || own.wallet === null || !addressMatches(own.wallet, expected.participantWallet)) return null;
  return Object.freeze({
    ...parsed,
    role: expected.role,
    participantWallet: value.participantWallet,
    eligibilityBlock,
    newlyAdmitted: value.newlyAdmitted,
  });
}
