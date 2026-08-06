/**
 * ParticipantAdmissionV1 — the canonical typed-data schema for participant
 * admission, owned by the participant runtime.
 *
 * One A-Pass-eligible wallet authorizes exactly one role in exactly one case.
 * The wallet signs an EIP-712 message; the server validates it through
 * `verifyTypedData`, so a deployed ERC-1271 contract account is accepted on the
 * same path as an EOA rather than being silently excluded by EOA-only recovery.
 *
 * The claim interval is bound directly rather than only through a commitment,
 * because the participant must be able to read in their own wallet exactly which
 * interval they are authorizing. Case, role and wallet sit in the same struct, so
 * a signature for one role in one case satisfies nothing else.
 *
 * Nothing here touches the accepted cryptography. The V2 binding, the Go pledge
 * schema, the fixed BGV circuit and the governed release are untouched: this
 * module decides *who may write a role's private claim*, and the existing engine
 * decides everything that happens to that claim afterwards.
 */

import { getAddress, hashTypedData, keccak256, toHex } from "viem";

import { sha256Digest, type Sha256Digest } from "./cleanverse-asset";
import { CCP_CHAIN_ID } from "./ccp-eligibility";
import type { SupervisedPledgeWindow } from "./supervised-pledge-windows";

export const PARTICIPANT_ADMISSION_SCHEMA = "mordant.participant-admission/1" as const;
export const PARTICIPANT_ADMISSION_PRIMARY_TYPE = "ParticipantAdmissionV1" as const;
export const PARTICIPANT_ADMISSION_DOMAIN_NAME = "Mordant Participant Admission" as const;
export const PARTICIPANT_ADMISSION_DOMAIN_VERSION = "1" as const;

/**
 * A fixed off-chain domain discriminator. There is no adapter deployment this
 * authorization is addressed to, and inventing an unrelated `verifyingContract`
 * to fill the domain would misstate what the signature is for.
 */
export const PARTICIPANT_ADMISSION_SALT = keccak256(toHex(PARTICIPANT_ADMISSION_SCHEMA));

export const PARTICIPANT_ROLES = ["PARTICIPANT_A", "PARTICIPANT_B"] as const;
export type ParticipantRole = (typeof PARTICIPANT_ROLES)[number];

/** Longest authorization lifetime a participant may request. */
export const PARTICIPANT_AUTHORIZATION_MAX_LIFETIME_SECONDS = 15 * 60;

export const PARTICIPANT_ADMISSION_TYPES = {
  ParticipantAdmissionV1: [
    { name: "verifyingService", type: "string" },
    { name: "runId", type: "string" },
    { name: "fheCaseId", type: "bytes32" },
    { name: "protectionBindingDigest", type: "bytes32" },
    { name: "assetIdentityDigest", type: "bytes32" },
    { name: "role", type: "string" },
    { name: "activeFrom", type: "uint64" },
    { name: "activeUntil", type: "uint64" },
    { name: "participantWallet", type: "address" },
    { name: "authorizationNonce", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
  ],
} as const;

export type Bytes32 = `0x${string}`;

export type ParticipantAdmissionMessage = Readonly<{
  verifyingService: string;
  runId: string;
  fheCaseId: Bytes32;
  protectionBindingDigest: Bytes32;
  assetIdentityDigest: Bytes32;
  role: ParticipantRole;
  activeFrom: number;
  activeUntil: number;
  participantWallet: `0x${string}`;
  authorizationNonce: Bytes32;
  issuedAt: number;
  expiresAt: number;
}>;

export class ParticipantAuthorizationError extends Error {
  constructor(readonly code: string, readonly status: number, message: string) {
    super(message);
    this.name = "ParticipantAuthorizationError";
  }
}

function fail(code: string, status: number, message: string): never {
  throw new ParticipantAuthorizationError(code, status, message);
}

function exactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

/** `sha256:<64 hex>` to the `0x<64 hex>` the typed data carries. */
export function digestToBytes32(digest: Sha256Digest): Bytes32 {
  const hex = digest.slice("sha256:".length);
  if (!/^[0-9a-f]{64}$/u.test(hex)) fail("DIGEST", 500, "A 32-byte digest is required");
  return `0x${hex}`;
}

/**
 * A server-side digest of one admitted claim, kept in the durable ledger so the
 * claim stays provably immutable after the interval itself has been pruned.
 * Case and role are inside it, so it identifies one role's claim and no other.
 */
export function participantClaimCommitment(input: Readonly<{
  runId: string;
  role: ParticipantRole;
  claim: SupervisedPledgeWindow;
}>): Bytes32 {
  return digestToBytes32(sha256Digest("MordantParticipantClaim/v1", {
    runId: input.runId,
    role: input.role,
    activeFrom: input.claim.activeFrom,
    activeUntil: input.claim.activeUntil,
  }));
}

export function participantAdmissionDomain(chainId: number = CCP_CHAIN_ID) {
  return {
    name: PARTICIPANT_ADMISSION_DOMAIN_NAME,
    version: PARTICIPANT_ADMISSION_DOMAIN_VERSION,
    chainId,
    salt: PARTICIPANT_ADMISSION_SALT,
  } as const;
}

/** The exact struct viem signs and verifies. One writer, so both sides agree. */
export function participantAdmissionTypedData(
  message: ParticipantAdmissionMessage,
  chainId: number = CCP_CHAIN_ID,
) {
  return {
    domain: participantAdmissionDomain(chainId),
    types: PARTICIPANT_ADMISSION_TYPES,
    primaryType: PARTICIPANT_ADMISSION_PRIMARY_TYPE,
    message: {
      verifyingService: message.verifyingService,
      runId: message.runId,
      fheCaseId: message.fheCaseId,
      protectionBindingDigest: message.protectionBindingDigest,
      assetIdentityDigest: message.assetIdentityDigest,
      role: message.role,
      activeFrom: BigInt(message.activeFrom),
      activeUntil: BigInt(message.activeUntil),
      participantWallet: message.participantWallet,
      authorizationNonce: message.authorizationNonce,
      issuedAt: BigInt(message.issuedAt),
      expiresAt: BigInt(message.expiresAt),
    },
  } as const;
}

export function participantAdmissionDigest(
  message: ParticipantAdmissionMessage,
  chainId: number = CCP_CHAIN_ID,
): Bytes32 {
  return hashTypedData(participantAdmissionTypedData(message, chainId));
}

function exactBytes32(value: unknown, code: string, label: string): Bytes32 {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/u.test(value)) {
    fail(code, 400, `${label} must be 0x followed by 64 lowercase hex characters`);
  }
  return value as Bytes32;
}

function exactUnixSeconds(value: unknown, code: string, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0 || Object.is(value, -0)) {
    fail(code, 400, `${label} must be a positive whole number of seconds`);
  }
  return value;
}

function exactInterval(value: unknown, code: string, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
    fail(code, 400, `${label} must be a non-negative whole number`);
  }
  return value;
}

export function isParticipantRole(value: unknown): value is ParticipantRole {
  return typeof value === "string" && (PARTICIPANT_ROLES as readonly string[]).includes(value);
}

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

/**
 * Exact parse of an untrusted authorization body. No coercion: a missing member,
 * an extra member, a string where a number belongs or a mixed-case digest is a
 * rejection, never a repair.
 */
export function assertParticipantAdmissionMessage(value: unknown): ParticipantAdmissionMessage {
  if (!exactKeys(value, [
    "verifyingService", "runId", "fheCaseId", "protectionBindingDigest", "assetIdentityDigest",
    "role", "activeFrom", "activeUntil", "participantWallet", "authorizationNonce", "issuedAt", "expiresAt",
  ])) {
    fail("AUTHORIZATION_MEMBERS", 400, "The authorization members are not exact");
  }
  if (typeof value.verifyingService !== "string" || value.verifyingService.length === 0 || value.verifyingService.length > 255) {
    fail("AUTHORIZATION_SERVICE", 400, "A verifying service is required");
  }
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId)) {
    fail("AUTHORIZATION_RUN_ID", 400, "A case identifier is required");
  }
  if (!isParticipantRole(value.role)) fail("AUTHORIZATION_ROLE", 400, "The role must be PARTICIPANT_A or PARTICIPANT_B");
  if (typeof value.participantWallet !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value.participantWallet)) {
    fail("AUTHORIZATION_WALLET", 400, "A 0x wallet address is required");
  }
  let participantWallet: `0x${string}`;
  try {
    participantWallet = getAddress(value.participantWallet);
  } catch {
    fail("AUTHORIZATION_WALLET", 400, "A 0x wallet address is required");
  }
  const activeFrom = exactInterval(value.activeFrom, "AUTHORIZATION_ACTIVE_FROM", "activeFrom");
  const activeUntil = exactInterval(value.activeUntil, "AUTHORIZATION_ACTIVE_UNTIL", "activeUntil");
  if (activeFrom >= activeUntil) {
    fail("AUTHORIZATION_INTERVAL", 400, "activeFrom must be strictly before activeUntil");
  }
  const issuedAt = exactUnixSeconds(value.issuedAt, "AUTHORIZATION_ISSUED_AT", "issuedAt");
  const expiresAt = exactUnixSeconds(value.expiresAt, "AUTHORIZATION_EXPIRY", "expiresAt");
  if (expiresAt <= issuedAt) fail("AUTHORIZATION_WINDOW", 400, "expiresAt must be strictly after issuedAt");
  if (expiresAt - issuedAt > PARTICIPANT_AUTHORIZATION_MAX_LIFETIME_SECONDS) {
    fail("AUTHORIZATION_LIFETIME", 400, "The authorization lifetime is too long");
  }
  return Object.freeze({
    verifyingService: value.verifyingService,
    runId: value.runId,
    fheCaseId: exactBytes32(value.fheCaseId, "AUTHORIZATION_FHE_CASE_ID", "fheCaseId"),
    protectionBindingDigest: exactBytes32(value.protectionBindingDigest, "AUTHORIZATION_BINDING", "protectionBindingDigest"),
    assetIdentityDigest: exactBytes32(value.assetIdentityDigest, "AUTHORIZATION_ASSET", "assetIdentityDigest"),
    role: value.role,
    activeFrom,
    activeUntil,
    participantWallet,
    authorizationNonce: exactBytes32(value.authorizationNonce, "AUTHORIZATION_NONCE", "authorizationNonce"),
    issuedAt,
    expiresAt,
  });
}

/**
 * Authoritative validity check for one typed authorization.
 *
 * `verifyTypedData` is used rather than address recovery so a deployed ERC-1271
 * contract account is judged by its own `isValidSignature`. Whether any given
 * wallet actually is such an account is not asserted here, and the demo qualifies
 * only the EOA A-Pass holders that are tested.
 */
export type TypedDataVerifier = (input: Readonly<{
  address: `0x${string}`;
  typedData: ReturnType<typeof participantAdmissionTypedData>;
  signature: `0x${string}`;
}>) => Promise<boolean>;

export type ExpectedAdmissionContext = Readonly<{
  verifyingService: string;
  runId: string;
  fheCaseId: Sha256Digest;
  protectionBindingDigest: Sha256Digest;
  assetIdentityDigest: Sha256Digest;
  role: ParticipantRole;
  /**
   * The private interval that actually arrived. The admission service always
   * supplies it, so the window written to the pledge file is provably the window
   * the wallet signed. It is optional only so the schema can be exercised on its
   * own, without a claim in hand.
   */
  claim?: SupervisedPledgeWindow;
  chainId?: number;
  /** Unix seconds. */
  now: number;
}>;

export type VerifiedParticipantAuthorization = Readonly<{
  schemaVersion: typeof PARTICIPANT_ADMISSION_SCHEMA;
  message: ParticipantAdmissionMessage;
  role: ParticipantRole;
  /** The EIP-712 digest. Also the durable identity of this exact authorization. */
  authorizationDigest: Bytes32;
  signature: `0x${string}`;
  participantWallet: `0x${string}`;
  claimCommitment: Bytes32;
}>;

/**
 * Verifies one wallet authorization against the exact case, role and claim the
 * server is about to act on.
 *
 * Every field is compared against a server-side expectation rather than trusted
 * from the body, including the interval: the window that will be written to the
 * private pledge file must be the window the wallet actually signed.
 */
export async function verifyParticipantAuthorization(
  message: ParticipantAdmissionMessage,
  signature: unknown,
  expected: ExpectedAdmissionContext,
  verifyTypedData: TypedDataVerifier,
): Promise<VerifiedParticipantAuthorization> {
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/u.test(signature) || signature.length % 2 !== 0) {
    fail("SIGNATURE_FORMAT", 400, "A 0x signature is required");
  }
  // An ERC-1271 signature is not fixed length, so only a sane bound is imposed.
  if (signature.length < 132 || signature.length > 4_098) {
    fail("SIGNATURE_FORMAT", 400, "A 0x signature is required");
  }
  if (message.verifyingService !== expected.verifyingService) {
    fail("SERVICE_MISMATCH", 400, "This authorization was not issued for this service");
  }
  if (message.role !== expected.role) {
    fail("ROLE_MISMATCH", 409, "This authorization was signed for a different role");
  }
  if (message.runId !== expected.runId) {
    fail("CASE_MISMATCH", 409, "This authorization was signed for a different case");
  }
  if (message.fheCaseId !== digestToBytes32(expected.fheCaseId)) {
    fail("FHE_CASE_MISMATCH", 409, "This authorization was signed for a different FHE case");
  }
  if (message.protectionBindingDigest !== digestToBytes32(expected.protectionBindingDigest)) {
    fail("BINDING_MISMATCH", 409, "This authorization was signed against a different protection binding");
  }
  if (message.assetIdentityDigest !== digestToBytes32(expected.assetIdentityDigest)) {
    fail("ASSET_MISMATCH", 409, "This authorization was signed for a different asset");
  }
  // The interval that will reach the private pledge file must be the signed one.
  if (expected.claim !== undefined
    && (message.activeFrom !== expected.claim.activeFrom || message.activeUntil !== expected.claim.activeUntil)) {
    fail("CLAIM_MISMATCH", 409, "The submitted claim does not match the authorized claim");
  }
  if (message.expiresAt <= expected.now) {
    fail("AUTHORIZATION_EXPIRED", 401, "This authorization has expired");
  }
  if (message.issuedAt > expected.now + 120) {
    fail("AUTHORIZATION_NOT_YET_VALID", 401, "This authorization is not valid yet");
  }

  const chainId = expected.chainId ?? CCP_CHAIN_ID;
  const authorizationDigest = participantAdmissionDigest(message, chainId);
  let valid: boolean;
  try {
    valid = await verifyTypedData({
      address: message.participantWallet,
      digest: authorizationDigest,
      signature: signature as `0x${string}`,
    });
  } catch {
    fail("SIGNATURE_UNVERIFIABLE", 503, "The wallet signature could not be verified right now");
  }
  if (!valid) fail("SIGNATURE_REJECTED", 401, "The wallet signature was rejected");

  return Object.freeze({
    schemaVersion: PARTICIPANT_ADMISSION_SCHEMA,
    message,
    role: message.role,
    authorizationDigest,
    signature: signature as `0x${string}`,
    participantWallet: getAddress(message.participantWallet),
    claimCommitment: participantClaimCommitment({
      runId: expected.runId,
      role: expected.role,
      claim: expected.claim ?? { activeFrom: message.activeFrom, activeUntil: message.activeUntil },
    }),
  });
}
