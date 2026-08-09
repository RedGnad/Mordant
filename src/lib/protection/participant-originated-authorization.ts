/**
 * Experimental participant-originated authorization chain.
 *
 * This module is deliberately separate from ParticipantAdmissionV1. The
 * existing direct/managed profiles keep their current message and verifier;
 * this protocol is only for the CLI-first participant-originated experiment.
 *
 * The three EIP-712 phases avoid a circular artifact dependency:
 *
 * 0. a wallet registers the digest of one participant-controlled Ed25519 key;
 * 1. the wallet authorizes encryption against one fully pinned client bundle;
 * 2. the wallet authorizes the exact artifact and ciphertext produced later.
 *
 * SECURITY BOUNDARY: the public claim commitment below is hiding only while
 * the participant keeps its 32-byte random salt and claim preimage local. No
 * coordinator request type in this module contains either value.
 *
 * KNOWN SEMANTIC GAP: matching the public commitment carried by a ciphertext
 * to the wallet intent does not prove that the encrypted window equals the
 * commitment preimage. The bounded POC relies on a pinned, honest participant
 * client; this module must never be presented as a semantic-equality proof.
 */

import { createHash, randomBytes } from "node:crypto";

import { getAddress, hashTypedData, keccak256, recoverAddress, toHex } from "viem";

import { canonicalJson } from "./cleanverse-asset";

export const PARTICIPANT_ORIGINATED_CHAIN_ID = 10_143;
export const PARTICIPANT_ORIGINATED_DOMAIN_VERSION = "1" as const;

export const PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA =
  "mordant.participant-signing-key-registration/1" as const;
export const PARTICIPANT_ENCRYPTION_INTENT_SCHEMA =
  "mordant.participant-encryption-intent/1" as const;
export const PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA =
  "mordant.participant-encrypted-admission/1" as const;

export const PARTICIPANT_SIGNING_KEY_REGISTRATION_PRIMARY_TYPE =
  "ParticipantSigningKeyRegistrationV1" as const;
export const PARTICIPANT_ENCRYPTION_INTENT_PRIMARY_TYPE =
  "ParticipantEncryptionIntentV1" as const;
export const PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_PRIMARY_TYPE =
  "ParticipantEncryptedAdmissionV1" as const;

export const PARTICIPANT_SIGNING_KEY_REGISTRATION_DOMAIN_NAME =
  "Mordant Participant Signing Key Registration" as const;
export const PARTICIPANT_ENCRYPTION_INTENT_DOMAIN_NAME =
  "Mordant Participant Encryption Intent" as const;
export const PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_DOMAIN_NAME =
  "Mordant Participant Encrypted Admission" as const;

export const PARTICIPANT_SIGNING_KEY_REGISTRATION_SALT = keccak256(
  toHex(PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA),
);
export const PARTICIPANT_ENCRYPTION_INTENT_SALT = keccak256(
  toHex(PARTICIPANT_ENCRYPTION_INTENT_SCHEMA),
);
export const PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SALT = keccak256(
  toHex(PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA),
);

export const PARTICIPANT_ORIGINATED_ROLES = ["PARTICIPANT_A", "PARTICIPANT_B"] as const;
export type ParticipantOriginatedRole = (typeof PARTICIPANT_ORIGINATED_ROLES)[number];
export type ParticipantOriginatedBytes32 = `0x${string}`;
export type ParticipantOriginatedWallet = `0x${string}`;
export type ParticipantOriginatedEoaSignature = `0x${string}`;

/** The request authorization itself must be short-lived. */
export const PARTICIPANT_ORIGINATED_AUTHORIZATION_MAX_LIFETIME_SECONDS = 15 * 60;
export const PARTICIPANT_ORIGINATED_AUTHORIZATION_CLOCK_SKEW_SECONDS = 120;
/** Matches the existing governed-FHE evaluator's exact participant-object cap. */
export const PARTICIPANT_ORIGINATED_CIPHERTEXT_MAX_BYTES = 192 << 20;
export const PARTICIPANT_CLAIM_SALT_BYTES = 32;
export const PARTICIPANT_ORIGINATED_CLAIM_COMMITMENT_DOMAIN =
  "MordantParticipantOriginatedClaim/v1" as const;

export const PARTICIPANT_ORIGINATED_SEMANTIC_GAP =
  "The authorization chain proves wallet/key/case/role/artifact provenance, but not that the encrypted claim equals the hiding-commitment preimage." as const;

export const PARTICIPANT_SIGNING_KEY_REGISTRATION_TYPES = {
  ParticipantSigningKeyRegistrationV1: [
    { name: "verifyingService", type: "string" },
    { name: "runId", type: "string" },
    { name: "fheCaseId", type: "bytes32" },
    { name: "assetIdentityDigest", type: "bytes32" },
    { name: "policyDigest", type: "bytes32" },
    { name: "role", type: "string" },
    { name: "participantWallet", type: "address" },
    { name: "participantSigningPublicKey", type: "bytes32" },
    { name: "participantSigningKeyDigest", type: "bytes32" },
    { name: "registrationNonce", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
  ],
} as const;

export const PARTICIPANT_ENCRYPTION_INTENT_TYPES = {
  ParticipantEncryptionIntentV1: [
    { name: "verifyingService", type: "string" },
    { name: "runId", type: "string" },
    { name: "fheCaseId", type: "bytes32" },
    { name: "caseBindingDigest", type: "bytes32" },
    { name: "protectionBindingDigest", type: "bytes32" },
    { name: "assetIdentityDigest", type: "bytes32" },
    { name: "policyDigest", type: "bytes32" },
    { name: "circuitId", type: "string" },
    { name: "circuitVersion", type: "uint32" },
    { name: "circuitDigest", type: "bytes32" },
    { name: "parameterProfile", type: "string" },
    { name: "parameterFingerprint", type: "bytes32" },
    { name: "fhePublicKeyDigest", type: "bytes32" },
    { name: "releaseAuthorityId", type: "bytes32" },
    { name: "releaseMode", type: "string" },
    { name: "role", type: "string" },
    { name: "participantWallet", type: "address" },
    { name: "participantSigningKeyDigest", type: "bytes32" },
    { name: "registrationDigest", type: "bytes32" },
    { name: "claimCommitment", type: "bytes32" },
    { name: "clientBundleDigest", type: "bytes32" },
    { name: "clientSourceDigest", type: "bytes32" },
    { name: "clientBuildDigest", type: "bytes32" },
    { name: "clientBinaryDigest", type: "bytes32" },
    { name: "bundleExpiresAt", type: "uint64" },
    { name: "intentNonce", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
  ],
} as const;

export const PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_TYPES = {
  ParticipantEncryptedAdmissionV1: [
    { name: "verifyingService", type: "string" },
    { name: "runId", type: "string" },
    { name: "fheCaseId", type: "bytes32" },
    { name: "role", type: "string" },
    { name: "participantWallet", type: "address" },
    { name: "participantSigningKeyDigest", type: "bytes32" },
    { name: "registrationDigest", type: "bytes32" },
    { name: "clientBundleDigest", type: "bytes32" },
    { name: "encryptionIntentDigest", type: "bytes32" },
    { name: "claimCommitment", type: "bytes32" },
    { name: "encryptedArtifactDigest", type: "bytes32" },
    { name: "ciphertextObjectDigest", type: "bytes32" },
    { name: "ciphertextObjectLength", type: "uint64" },
    { name: "submissionNonce", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
  ],
} as const;

export interface ParticipantSigningKeyRegistrationMessage {
  readonly verifyingService: string;
  readonly runId: string;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly assetIdentityDigest: ParticipantOriginatedBytes32;
  readonly policyDigest: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  /** Raw 32-byte Ed25519 public key, never a private key. */
  readonly participantSigningPublicKey: ParticipantOriginatedBytes32;
  /** SHA-256 of the exact 32 raw public-key bytes. */
  readonly participantSigningKeyDigest: ParticipantOriginatedBytes32;
  readonly registrationNonce: ParticipantOriginatedBytes32;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface ParticipantSigningKeyRegistrationRequest {
  readonly schemaVersion: typeof PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA;
  readonly registration: ParticipantSigningKeyRegistrationMessage;
  readonly signature: ParticipantOriginatedEoaSignature;
}

export interface ParticipantEncryptionIntentMessage {
  readonly verifyingService: string;
  readonly runId: string;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly caseBindingDigest: ParticipantOriginatedBytes32;
  readonly protectionBindingDigest: ParticipantOriginatedBytes32;
  readonly assetIdentityDigest: ParticipantOriginatedBytes32;
  readonly policyDigest: ParticipantOriginatedBytes32;
  readonly circuitId: string;
  readonly circuitVersion: number;
  readonly circuitDigest: ParticipantOriginatedBytes32;
  readonly parameterProfile: string;
  readonly parameterFingerprint: ParticipantOriginatedBytes32;
  readonly fhePublicKeyDigest: ParticipantOriginatedBytes32;
  readonly releaseAuthorityId: ParticipantOriginatedBytes32;
  readonly releaseMode: string;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly participantSigningKeyDigest: ParticipantOriginatedBytes32;
  readonly registrationDigest: ParticipantOriginatedBytes32;
  readonly claimCommitment: ParticipantOriginatedBytes32;
  readonly clientBundleDigest: ParticipantOriginatedBytes32;
  readonly clientSourceDigest: ParticipantOriginatedBytes32;
  readonly clientBuildDigest: ParticipantOriginatedBytes32;
  readonly clientBinaryDigest: ParticipantOriginatedBytes32;
  readonly bundleExpiresAt: number;
  readonly intentNonce: ParticipantOriginatedBytes32;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface ParticipantEncryptionIntentRequest {
  readonly schemaVersion: typeof PARTICIPANT_ENCRYPTION_INTENT_SCHEMA;
  readonly intent: ParticipantEncryptionIntentMessage;
  readonly signature: ParticipantOriginatedEoaSignature;
}

export interface ParticipantFinalEncryptedAdmissionMessage {
  readonly verifyingService: string;
  readonly runId: string;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly participantSigningKeyDigest: ParticipantOriginatedBytes32;
  readonly registrationDigest: ParticipantOriginatedBytes32;
  readonly clientBundleDigest: ParticipantOriginatedBytes32;
  readonly encryptionIntentDigest: ParticipantOriginatedBytes32;
  readonly claimCommitment: ParticipantOriginatedBytes32;
  readonly encryptedArtifactDigest: ParticipantOriginatedBytes32;
  readonly ciphertextObjectDigest: ParticipantOriginatedBytes32;
  readonly ciphertextObjectLength: number;
  readonly submissionNonce: ParticipantOriginatedBytes32;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface ParticipantFinalEncryptedAdmissionRequest {
  readonly schemaVersion: typeof PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA;
  readonly admission: ParticipantFinalEncryptedAdmissionMessage;
  readonly signature: ParticipantOriginatedEoaSignature;
}

/**
 * Participant-local native PlainPledge projection. It is intentionally absent
 * from all coordinator request types.
 *
 * `authorizationCommitment` and `privateMetadataCommitment` are the only native
 * pledge fields omitted: in this profile the client sets them to the Phase-1
 * encryption-intent digest and this function's output respectively. Including
 * either here would create a circular commitment. Every remaining native pledge
 * field is committed, including the normally-zero full-FHE receivable commitment.
 */
export interface ParticipantLocalClaimPreimage {
  readonly activeFrom: number;
  readonly activeUntil: number;
  readonly amount: readonly [number, number, number, number];
  readonly currency: ParticipantOriginatedBytes32;
  readonly obligationId: ParticipantOriginatedBytes32;
  readonly receivableId: ParticipantOriginatedBytes32;
  readonly exclusive: boolean;
  readonly receivableCommitment: ParticipantOriginatedBytes32;
}

export interface ParticipantLocalClaimCommitmentInput {
  readonly runId: string;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly claim: ParticipantLocalClaimPreimage;
  /** A participant-local 32-byte CSPRNG output. Never send it to the coordinator. */
  readonly salt: ParticipantOriginatedBytes32;
}

export interface ParticipantOriginatedBundleContext {
  readonly runId: string;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly caseBindingDigest: ParticipantOriginatedBytes32;
  readonly protectionBindingDigest: ParticipantOriginatedBytes32;
  readonly assetIdentityDigest: ParticipantOriginatedBytes32;
  readonly policyDigest: ParticipantOriginatedBytes32;
  readonly circuitId: string;
  readonly circuitVersion: number;
  readonly circuitDigest: ParticipantOriginatedBytes32;
  readonly parameterProfile: string;
  readonly parameterFingerprint: ParticipantOriginatedBytes32;
  readonly fhePublicKeyDigest: ParticipantOriginatedBytes32;
  readonly releaseAuthorityId: ParticipantOriginatedBytes32;
  readonly releaseMode: string;
  readonly clientBundleDigest: ParticipantOriginatedBytes32;
  readonly clientSourceDigest: ParticipantOriginatedBytes32;
  readonly clientBuildDigest: ParticipantOriginatedBytes32;
  readonly clientBinaryDigest: ParticipantOriginatedBytes32;
  readonly bundleExpiresAt: number;
}

export interface ExpectedParticipantSigningKeyRegistrationContext {
  readonly verifyingService: string;
  readonly runId: string;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly assetIdentityDigest: ParticipantOriginatedBytes32;
  readonly policyDigest: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  /** Unix seconds from a server-controlled clock. */
  readonly now: number;
  readonly chainId?: number;
}

export interface VerifiedParticipantSigningKeyRegistration {
  readonly schemaVersion: typeof PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA;
  readonly registration: ParticipantSigningKeyRegistrationMessage;
  readonly registrationDigest: ParticipantOriginatedBytes32;
  readonly signature: ParticipantOriginatedEoaSignature;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly participantSigningPublicKey: ParticipantOriginatedBytes32;
  readonly participantSigningKeyDigest: ParticipantOriginatedBytes32;
  readonly chainId: number;
}

export interface ExpectedParticipantEncryptionIntentContext extends ParticipantOriginatedBundleContext {
  readonly verifyingService: string;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly registration: VerifiedParticipantSigningKeyRegistration;
  /** Unix seconds from a server-controlled clock. */
  readonly now: number;
  readonly chainId?: number;
}

export interface VerifiedParticipantEncryptionIntent {
  readonly schemaVersion: typeof PARTICIPANT_ENCRYPTION_INTENT_SCHEMA;
  readonly intent: ParticipantEncryptionIntentMessage;
  readonly encryptionIntentDigest: ParticipantOriginatedBytes32;
  readonly signature: ParticipantOriginatedEoaSignature;
  readonly registrationDigest: ParticipantOriginatedBytes32;
  readonly claimCommitment: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly participantSigningKeyDigest: ParticipantOriginatedBytes32;
  readonly chainId: number;
}

/**
 * Values recomputed by the canonical artifact/ciphertext importer. They are not
 * copied from the final wallet message. The authorization layer compares the
 * wallet declaration to these facts after transport hashing and artifact
 * signature/case validation.
 */
export interface RecomputedParticipantEncryptedArtifactContext {
  readonly encryptedArtifactDigest: ParticipantOriginatedBytes32;
  readonly ciphertextObjectDigest: ParticipantOriginatedBytes32;
  readonly ciphertextObjectLength: number;
  readonly fheCaseId: ParticipantOriginatedBytes32;
  readonly caseBindingDigest: ParticipantOriginatedBytes32;
  readonly assetIdentityDigest: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly participantSigningKeyDigest: ParticipantOriginatedBytes32;
  readonly parameterProfile: string;
  readonly parameterFingerprint: ParticipantOriginatedBytes32;
  readonly fhePublicKeyDigest: ParticipantOriginatedBytes32;
  readonly circuitDigest: ParticipantOriginatedBytes32;
  readonly submissionNonce: ParticipantOriginatedBytes32;
  readonly expiresAt: number;
  /** CipherPledge.AuthorizationCommitment, extracted from canonical ciphertext. */
  readonly embeddedEncryptionIntentDigest: ParticipantOriginatedBytes32;
  /** CipherPledge.PrivateMetadataCommitment, extracted from canonical ciphertext. */
  readonly embeddedClaimCommitment: ParticipantOriginatedBytes32;
}

export interface ExpectedParticipantFinalEncryptedAdmissionContext extends ParticipantOriginatedBundleContext {
  readonly verifyingService: string;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly registration: VerifiedParticipantSigningKeyRegistration;
  readonly intent: VerifiedParticipantEncryptionIntent;
  readonly artifact: RecomputedParticipantEncryptedArtifactContext;
  /** Unix seconds from a server-controlled clock. */
  readonly now: number;
  readonly chainId?: number;
}

export interface VerifiedParticipantFinalEncryptedAdmission {
  readonly schemaVersion: typeof PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA;
  readonly admission: ParticipantFinalEncryptedAdmissionMessage;
  readonly finalAdmissionDigest: ParticipantOriginatedBytes32;
  readonly signature: ParticipantOriginatedEoaSignature;
  readonly encryptionIntentDigest: ParticipantOriginatedBytes32;
  readonly encryptedArtifactDigest: ParticipantOriginatedBytes32;
  readonly ciphertextObjectDigest: ParticipantOriginatedBytes32;
  readonly submissionNonce: ParticipantOriginatedBytes32;
  readonly role: ParticipantOriginatedRole;
  readonly participantWallet: ParticipantOriginatedWallet;
  readonly chainId: number;
}

export type ParticipantOriginatedAuthorizationPhase = "REGISTRATION" | "INTENT" | "FINAL_ADMISSION";

export interface ParticipantOriginatedEoaVerifierInput {
  readonly phase: ParticipantOriginatedAuthorizationPhase;
  readonly address: ParticipantOriginatedWallet;
  readonly digest: ParticipantOriginatedBytes32;
  readonly signature: ParticipantOriginatedEoaSignature;
}

/** Injectable for tests; production defaults to pure viem EOA recovery. */
export type ParticipantOriginatedEoaVerifier = (
  input: ParticipantOriginatedEoaVerifierInput,
) => Promise<boolean>;

export interface ParticipantOriginatedNonceReservation {
  readonly phase: ParticipantOriginatedAuthorizationPhase;
  readonly runId: string;
  readonly role: ParticipantOriginatedRole;
  readonly nonce: ParticipantOriginatedBytes32;
  readonly authorizationDigest: ParticipantOriginatedBytes32;
}

/**
 * Optional durable reservation hook. Returning false means the nonce or exact
 * authorization was already consumed/reserved. The final-import implementation
 * must back this with its locked durable journal; an in-memory callback is only
 * suitable for tests.
 */
export type ParticipantOriginatedNonceGuard = (
  reservation: ParticipantOriginatedNonceReservation,
) => Promise<boolean>;

export class ParticipantOriginatedAuthorizationError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ParticipantOriginatedAuthorizationError";
  }
}

function fail(code: string, status: number, message: string): never {
  throw new ParticipantOriginatedAuthorizationError(code, status, message);
}

function exactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const STRICT_BYTES32 = /^0x[0-9a-f]{64}$/u;
const STRICT_EOA_SIGNATURE = /^0x[0-9a-fA-F]{130}$/u;
const BOUNDED_TEXT = /^[\x20-\x7e]+$/u;

function exactText(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 255 || !BOUNDED_TEXT.test(value)) {
    fail(code, 400, `${label} must be non-empty printable ASCII of at most 255 characters`);
  }
  return value;
}

function exactRunId(value: unknown, code: string): string {
  if (typeof value !== "string" || !RUN_ID.test(value)) {
    fail(code, 400, "runId must be a lowercase UUID");
  }
  return value;
}

function exactBytes32(
  value: unknown,
  code: string,
  label: string,
): ParticipantOriginatedBytes32 {
  if (typeof value !== "string" || !STRICT_BYTES32.test(value) || /^0x0{64}$/u.test(value)) {
    fail(code, 400, `${label} must be a non-zero lowercase 32-byte value`);
  }
  return value as ParticipantOriginatedBytes32;
}

function exactBytes32AllowZero(
  value: unknown,
  code: string,
  label: string,
): ParticipantOriginatedBytes32 {
  if (typeof value !== "string" || !STRICT_BYTES32.test(value)) {
    fail(code, 400, `${label} must be a lowercase 32-byte value`);
  }
  return value as ParticipantOriginatedBytes32;
}

function exactWallet(value: unknown, code: string): ParticipantOriginatedWallet {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) {
    fail(code, 400, "participantWallet must be a 0x address");
  }
  try {
    return getAddress(value);
  } catch {
    fail(code, 400, "participantWallet must be a 0x address");
  }
}

function exactRole(value: unknown, code: string): ParticipantOriginatedRole {
  if (typeof value !== "string" || !(PARTICIPANT_ORIGINATED_ROLES as readonly string[]).includes(value)) {
    fail(code, 400, "role must be PARTICIPANT_A or PARTICIPANT_B");
  }
  return value as ParticipantOriginatedRole;
}

function exactPositiveInteger(value: unknown, code: string, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value <= 0
    || value > maximum
    || Object.is(value, -0)
  ) {
    fail(code, 400, `${label} must be a bounded positive whole number`);
  }
  return value;
}

function exactNonNegativeInteger(value: unknown, code: string, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
    fail(code, 400, `${label} must be a non-negative whole number`);
  }
  return value;
}

function exactSignature(value: unknown): ParticipantOriginatedEoaSignature {
  if (typeof value !== "string" || !STRICT_EOA_SIGNATURE.test(value)) {
    fail("SIGNATURE_FORMAT", 400, "A canonical 65-byte EOA signature is required");
  }
  return value as ParticipantOriginatedEoaSignature;
}

function assertAuthorizationWindow(issuedAt: number, expiresAt: number): void {
  if (expiresAt <= issuedAt) {
    fail("AUTHORIZATION_WINDOW", 400, "expiresAt must be strictly after issuedAt");
  }
  if (expiresAt - issuedAt > PARTICIPANT_ORIGINATED_AUTHORIZATION_MAX_LIFETIME_SECONDS) {
    fail("AUTHORIZATION_LIFETIME", 400, "The authorization lifetime is too long");
  }
}

function assertFresh(issuedAt: number, expiresAt: number, now: number, phase: string): void {
  if (!Number.isSafeInteger(now) || now <= 0) {
    fail("SERVER_TIME", 500, "The server clock is invalid");
  }
  if (expiresAt <= now) fail(`${phase}_EXPIRED`, 401, `The ${phase.toLowerCase()} has expired`);
  if (issuedAt > now + PARTICIPANT_ORIGINATED_AUTHORIZATION_CLOCK_SKEW_SECONDS) {
    fail(`${phase}_NOT_YET_VALID`, 401, `The ${phase.toLowerCase()} is not valid yet`);
  }
}

function sameWallet(left: string, right: string): boolean {
  try {
    return getAddress(left) === getAddress(right);
  } catch {
    return false;
  }
}

function expectEqual(actual: unknown, expected: unknown, code: string, message: string): void {
  if (actual !== expected) fail(code, 409, message);
}

function expectWallet(actual: string, expected: string, code: string): void {
  if (!sameWallet(actual, expected)) fail(code, 409, "The authorization wallet does not match this participant");
}

export function sha256ExactBytes(bytes: Uint8Array): ParticipantOriginatedBytes32 {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

export function participantSigningPublicKeyDigest(
  publicKey: ParticipantOriginatedBytes32,
): ParticipantOriginatedBytes32 {
  const exact = exactBytes32(publicKey, "SIGNING_PUBLIC_KEY", "participantSigningPublicKey");
  return sha256ExactBytes(Buffer.from(exact.slice(2), "hex"));
}

/** Creates a participant-local CSPRNG salt. Do not include it in any coordinator request. */
export function generateParticipantClaimSalt(): ParticipantOriginatedBytes32 {
  return `0x${randomBytes(PARTICIPANT_CLAIM_SALT_BYTES).toString("hex")}`;
}

/**
 * Computes the hiding commitment locally. Only the returned commitment crosses
 * the participant/coordinator boundary; `claim` and `salt` must remain local.
 */
export function participantOriginatedClaimCommitment(
  input: ParticipantLocalClaimCommitmentInput,
): ParticipantOriginatedBytes32 {
  const runId = exactRunId(input.runId, "CLAIM_RUN_ID");
  const fheCaseId = exactBytes32(input.fheCaseId, "CLAIM_FHE_CASE_ID", "fheCaseId");
  const role = exactRole(input.role, "CLAIM_ROLE");
  const salt = exactBytes32(input.salt, "CLAIM_SALT", "salt");
  const activeFrom = exactNonNegativeInteger(input.claim?.activeFrom, "CLAIM_ACTIVE_FROM", "activeFrom");
  const activeUntil = exactNonNegativeInteger(input.claim?.activeUntil, "CLAIM_ACTIVE_UNTIL", "activeUntil");
  if (activeFrom >= activeUntil) fail("CLAIM_INTERVAL", 400, "activeFrom must be before activeUntil");
  const amountValue = input.claim?.amount;
  if (!Array.isArray(amountValue) || amountValue.length !== 4) {
    fail("CLAIM_AMOUNT", 400, "amount must contain exactly four uint64 limbs");
  }
  const amount = amountValue.map((limb, index) => (
    exactNonNegativeInteger(limb, "CLAIM_AMOUNT", `amount[${index}]`)
  )) as unknown as readonly [number, number, number, number];
  if (amount.every((limb) => limb === 0)) fail("CLAIM_AMOUNT", 400, "amount must be non-zero");
  if (typeof input.claim?.exclusive !== "boolean") {
    fail("CLAIM_EXCLUSIVE", 400, "exclusive must be a boolean");
  }
  const claim = {
    activeFrom,
    activeUntil,
    amount,
    currency: exactBytes32(input.claim.currency, "CLAIM_CURRENCY", "currency"),
    obligationId: exactBytes32(input.claim.obligationId, "CLAIM_OBLIGATION_ID", "obligationId"),
    receivableId: exactBytes32(input.claim.receivableId, "CLAIM_RECEIVABLE_ID", "receivableId"),
    exclusive: input.claim.exclusive,
    receivableCommitment: exactBytes32AllowZero(
      input.claim.receivableCommitment,
      "CLAIM_RECEIVABLE_COMMITMENT",
      "receivableCommitment",
    ),
  } as const;
  if (!/^0x0{64}$/u.test(claim.receivableCommitment)) {
    fail(
      "CLAIM_RECEIVABLE_COMMITMENT",
      400,
      "receivableCommitment must be the canonical zero value for IdentityFullFHE256",
    );
  }
  const projection = { runId, fheCaseId, role, claim, salt };
  const bytes = Buffer.from(
    `${PARTICIPANT_ORIGINATED_CLAIM_COMMITMENT_DOMAIN}\0${canonicalJson(projection)}`,
    "utf8",
  );
  return sha256ExactBytes(bytes);
}

export function assertParticipantSigningKeyRegistrationMessage(
  value: unknown,
): ParticipantSigningKeyRegistrationMessage {
  if (!exactKeys(value, [
    "verifyingService",
    "runId",
    "fheCaseId",
    "assetIdentityDigest",
    "policyDigest",
    "role",
    "participantWallet",
    "participantSigningPublicKey",
    "participantSigningKeyDigest",
    "registrationNonce",
    "issuedAt",
    "expiresAt",
  ])) {
    fail("REGISTRATION_MEMBERS", 400, "The signing-key registration members are not exact");
  }
  const participantSigningPublicKey = exactBytes32(
    value.participantSigningPublicKey,
    "REGISTRATION_SIGNING_PUBLIC_KEY",
    "participantSigningPublicKey",
  );
  const participantSigningKeyDigestValue = exactBytes32(
    value.participantSigningKeyDigest,
    "REGISTRATION_SIGNING_KEY_DIGEST",
    "participantSigningKeyDigest",
  );
  if (participantSigningPublicKeyDigest(participantSigningPublicKey) !== participantSigningKeyDigestValue) {
    fail(
      "REGISTRATION_SIGNING_KEY_DIGEST",
      400,
      "participantSigningKeyDigest does not hash the supplied Ed25519 public key",
    );
  }
  const issuedAt = exactPositiveInteger(value.issuedAt, "REGISTRATION_ISSUED_AT", "issuedAt");
  const expiresAt = exactPositiveInteger(value.expiresAt, "REGISTRATION_EXPIRES_AT", "expiresAt");
  assertAuthorizationWindow(issuedAt, expiresAt);
  return Object.freeze({
    verifyingService: exactText(value.verifyingService, "REGISTRATION_SERVICE", "verifyingService"),
    runId: exactRunId(value.runId, "REGISTRATION_RUN_ID"),
    fheCaseId: exactBytes32(value.fheCaseId, "REGISTRATION_FHE_CASE_ID", "fheCaseId"),
    assetIdentityDigest: exactBytes32(
      value.assetIdentityDigest,
      "REGISTRATION_ASSET",
      "assetIdentityDigest",
    ),
    policyDigest: exactBytes32(value.policyDigest, "REGISTRATION_POLICY", "policyDigest"),
    role: exactRole(value.role, "REGISTRATION_ROLE"),
    participantWallet: exactWallet(value.participantWallet, "REGISTRATION_WALLET"),
    participantSigningPublicKey,
    participantSigningKeyDigest: participantSigningKeyDigestValue,
    registrationNonce: exactBytes32(
      value.registrationNonce,
      "REGISTRATION_NONCE",
      "registrationNonce",
    ),
    issuedAt,
    expiresAt,
  });
}

export function assertParticipantSigningKeyRegistrationRequest(
  value: unknown,
): ParticipantSigningKeyRegistrationRequest {
  if (!exactKeys(value, ["schemaVersion", "registration", "signature"])) {
    fail("REGISTRATION_REQUEST_MEMBERS", 400, "The registration request members are not exact");
  }
  if (value.schemaVersion !== PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA) {
    fail("REGISTRATION_SCHEMA", 400, "The registration schema is not supported");
  }
  return Object.freeze({
    schemaVersion: PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA,
    registration: assertParticipantSigningKeyRegistrationMessage(value.registration),
    signature: exactSignature(value.signature),
  });
}

export function assertParticipantEncryptionIntentMessage(
  value: unknown,
): ParticipantEncryptionIntentMessage {
  if (!exactKeys(value, [
    "verifyingService",
    "runId",
    "fheCaseId",
    "caseBindingDigest",
    "protectionBindingDigest",
    "assetIdentityDigest",
    "policyDigest",
    "circuitId",
    "circuitVersion",
    "circuitDigest",
    "parameterProfile",
    "parameterFingerprint",
    "fhePublicKeyDigest",
    "releaseAuthorityId",
    "releaseMode",
    "role",
    "participantWallet",
    "participantSigningKeyDigest",
    "registrationDigest",
    "claimCommitment",
    "clientBundleDigest",
    "clientSourceDigest",
    "clientBuildDigest",
    "clientBinaryDigest",
    "bundleExpiresAt",
    "intentNonce",
    "issuedAt",
    "expiresAt",
  ])) {
    fail("INTENT_MEMBERS", 400, "The encryption-intent members are not exact");
  }
  const issuedAt = exactPositiveInteger(value.issuedAt, "INTENT_ISSUED_AT", "issuedAt");
  const expiresAt = exactPositiveInteger(value.expiresAt, "INTENT_EXPIRES_AT", "expiresAt");
  const bundleExpiresAt = exactPositiveInteger(
    value.bundleExpiresAt,
    "INTENT_BUNDLE_EXPIRES_AT",
    "bundleExpiresAt",
  );
  assertAuthorizationWindow(issuedAt, expiresAt);
  if (expiresAt > bundleExpiresAt) {
    fail("INTENT_BUNDLE_EXPIRY", 400, "The encryption intent cannot outlive its client bundle");
  }
  return Object.freeze({
    verifyingService: exactText(value.verifyingService, "INTENT_SERVICE", "verifyingService"),
    runId: exactRunId(value.runId, "INTENT_RUN_ID"),
    fheCaseId: exactBytes32(value.fheCaseId, "INTENT_FHE_CASE_ID", "fheCaseId"),
    caseBindingDigest: exactBytes32(
      value.caseBindingDigest,
      "INTENT_CASE_BINDING",
      "caseBindingDigest",
    ),
    protectionBindingDigest: exactBytes32(
      value.protectionBindingDigest,
      "INTENT_PROTECTION_BINDING",
      "protectionBindingDigest",
    ),
    assetIdentityDigest: exactBytes32(value.assetIdentityDigest, "INTENT_ASSET", "assetIdentityDigest"),
    policyDigest: exactBytes32(value.policyDigest, "INTENT_POLICY", "policyDigest"),
    circuitId: exactText(value.circuitId, "INTENT_CIRCUIT_ID", "circuitId"),
    circuitVersion: exactPositiveInteger(
      value.circuitVersion,
      "INTENT_CIRCUIT_VERSION",
      "circuitVersion",
      0xffff_ffff,
    ),
    circuitDigest: exactBytes32(value.circuitDigest, "INTENT_CIRCUIT_DIGEST", "circuitDigest"),
    parameterProfile: exactText(value.parameterProfile, "INTENT_PARAMETER_PROFILE", "parameterProfile"),
    parameterFingerprint: exactBytes32(
      value.parameterFingerprint,
      "INTENT_PARAMETER_FINGERPRINT",
      "parameterFingerprint",
    ),
    fhePublicKeyDigest: exactBytes32(
      value.fhePublicKeyDigest,
      "INTENT_FHE_PUBLIC_KEY",
      "fhePublicKeyDigest",
    ),
    releaseAuthorityId: exactBytes32(
      value.releaseAuthorityId,
      "INTENT_RELEASE_AUTHORITY",
      "releaseAuthorityId",
    ),
    releaseMode: exactText(value.releaseMode, "INTENT_RELEASE_MODE", "releaseMode"),
    role: exactRole(value.role, "INTENT_ROLE"),
    participantWallet: exactWallet(value.participantWallet, "INTENT_WALLET"),
    participantSigningKeyDigest: exactBytes32(
      value.participantSigningKeyDigest,
      "INTENT_SIGNING_KEY",
      "participantSigningKeyDigest",
    ),
    registrationDigest: exactBytes32(
      value.registrationDigest,
      "INTENT_REGISTRATION_DIGEST",
      "registrationDigest",
    ),
    claimCommitment: exactBytes32(value.claimCommitment, "INTENT_CLAIM_COMMITMENT", "claimCommitment"),
    clientBundleDigest: exactBytes32(
      value.clientBundleDigest,
      "INTENT_CLIENT_BUNDLE",
      "clientBundleDigest",
    ),
    clientSourceDigest: exactBytes32(
      value.clientSourceDigest,
      "INTENT_CLIENT_SOURCE",
      "clientSourceDigest",
    ),
    clientBuildDigest: exactBytes32(
      value.clientBuildDigest,
      "INTENT_CLIENT_BUILD",
      "clientBuildDigest",
    ),
    clientBinaryDigest: exactBytes32(
      value.clientBinaryDigest,
      "INTENT_CLIENT_BINARY",
      "clientBinaryDigest",
    ),
    bundleExpiresAt,
    intentNonce: exactBytes32(value.intentNonce, "INTENT_NONCE", "intentNonce"),
    issuedAt,
    expiresAt,
  });
}

export function assertParticipantEncryptionIntentRequest(
  value: unknown,
): ParticipantEncryptionIntentRequest {
  if (!exactKeys(value, ["schemaVersion", "intent", "signature"])) {
    fail("INTENT_REQUEST_MEMBERS", 400, "The encryption-intent request members are not exact");
  }
  if (value.schemaVersion !== PARTICIPANT_ENCRYPTION_INTENT_SCHEMA) {
    fail("INTENT_SCHEMA", 400, "The encryption-intent schema is not supported");
  }
  return Object.freeze({
    schemaVersion: PARTICIPANT_ENCRYPTION_INTENT_SCHEMA,
    intent: assertParticipantEncryptionIntentMessage(value.intent),
    signature: exactSignature(value.signature),
  });
}

export function assertParticipantFinalEncryptedAdmissionMessage(
  value: unknown,
): ParticipantFinalEncryptedAdmissionMessage {
  if (!exactKeys(value, [
    "verifyingService",
    "runId",
    "fheCaseId",
    "role",
    "participantWallet",
    "participantSigningKeyDigest",
    "registrationDigest",
    "clientBundleDigest",
    "encryptionIntentDigest",
    "claimCommitment",
    "encryptedArtifactDigest",
    "ciphertextObjectDigest",
    "ciphertextObjectLength",
    "submissionNonce",
    "issuedAt",
    "expiresAt",
  ])) {
    fail("FINAL_ADMISSION_MEMBERS", 400, "The final encrypted-admission members are not exact");
  }
  const issuedAt = exactPositiveInteger(value.issuedAt, "FINAL_ADMISSION_ISSUED_AT", "issuedAt");
  const expiresAt = exactPositiveInteger(value.expiresAt, "FINAL_ADMISSION_EXPIRES_AT", "expiresAt");
  assertAuthorizationWindow(issuedAt, expiresAt);
  return Object.freeze({
    verifyingService: exactText(value.verifyingService, "FINAL_ADMISSION_SERVICE", "verifyingService"),
    runId: exactRunId(value.runId, "FINAL_ADMISSION_RUN_ID"),
    fheCaseId: exactBytes32(value.fheCaseId, "FINAL_ADMISSION_FHE_CASE_ID", "fheCaseId"),
    role: exactRole(value.role, "FINAL_ADMISSION_ROLE"),
    participantWallet: exactWallet(value.participantWallet, "FINAL_ADMISSION_WALLET"),
    participantSigningKeyDigest: exactBytes32(
      value.participantSigningKeyDigest,
      "FINAL_ADMISSION_SIGNING_KEY",
      "participantSigningKeyDigest",
    ),
    registrationDigest: exactBytes32(
      value.registrationDigest,
      "FINAL_ADMISSION_REGISTRATION_DIGEST",
      "registrationDigest",
    ),
    clientBundleDigest: exactBytes32(
      value.clientBundleDigest,
      "FINAL_ADMISSION_CLIENT_BUNDLE",
      "clientBundleDigest",
    ),
    encryptionIntentDigest: exactBytes32(
      value.encryptionIntentDigest,
      "FINAL_ADMISSION_INTENT_DIGEST",
      "encryptionIntentDigest",
    ),
    claimCommitment: exactBytes32(
      value.claimCommitment,
      "FINAL_ADMISSION_CLAIM_COMMITMENT",
      "claimCommitment",
    ),
    encryptedArtifactDigest: exactBytes32(
      value.encryptedArtifactDigest,
      "FINAL_ADMISSION_ARTIFACT_DIGEST",
      "encryptedArtifactDigest",
    ),
    ciphertextObjectDigest: exactBytes32(
      value.ciphertextObjectDigest,
      "FINAL_ADMISSION_CIPHERTEXT_DIGEST",
      "ciphertextObjectDigest",
    ),
    ciphertextObjectLength: exactPositiveInteger(
      value.ciphertextObjectLength,
      "FINAL_ADMISSION_CIPHERTEXT_LENGTH",
      "ciphertextObjectLength",
      PARTICIPANT_ORIGINATED_CIPHERTEXT_MAX_BYTES,
    ),
    submissionNonce: exactBytes32(
      value.submissionNonce,
      "FINAL_ADMISSION_SUBMISSION_NONCE",
      "submissionNonce",
    ),
    issuedAt,
    expiresAt,
  });
}

export function assertParticipantFinalEncryptedAdmissionRequest(
  value: unknown,
): ParticipantFinalEncryptedAdmissionRequest {
  if (!exactKeys(value, ["schemaVersion", "admission", "signature"])) {
    fail("FINAL_ADMISSION_REQUEST_MEMBERS", 400, "The final admission request members are not exact");
  }
  if (value.schemaVersion !== PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA) {
    fail("FINAL_ADMISSION_SCHEMA", 400, "The final encrypted-admission schema is not supported");
  }
  return Object.freeze({
    schemaVersion: PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA,
    admission: assertParticipantFinalEncryptedAdmissionMessage(value.admission),
    signature: exactSignature(value.signature),
  });
}

function domain(name: string, salt: ParticipantOriginatedBytes32, chainId: number) {
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    fail("CHAIN_ID", 500, "A positive EIP-712 chain ID is required");
  }
  return {
    name,
    version: PARTICIPANT_ORIGINATED_DOMAIN_VERSION,
    chainId,
    salt,
  } as const;
}

export function participantSigningKeyRegistrationDomain(
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
) {
  return domain(
    PARTICIPANT_SIGNING_KEY_REGISTRATION_DOMAIN_NAME,
    PARTICIPANT_SIGNING_KEY_REGISTRATION_SALT,
    chainId,
  );
}

export function participantEncryptionIntentDomain(
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
) {
  return domain(PARTICIPANT_ENCRYPTION_INTENT_DOMAIN_NAME, PARTICIPANT_ENCRYPTION_INTENT_SALT, chainId);
}

export function participantFinalEncryptedAdmissionDomain(
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
) {
  return domain(
    PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_DOMAIN_NAME,
    PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SALT,
    chainId,
  );
}

/** Exact typed-data builder used by participant wallets and the coordinator. */
export function participantSigningKeyRegistrationTypedData(
  message: ParticipantSigningKeyRegistrationMessage,
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
) {
  return {
    domain: participantSigningKeyRegistrationDomain(chainId),
    types: PARTICIPANT_SIGNING_KEY_REGISTRATION_TYPES,
    primaryType: PARTICIPANT_SIGNING_KEY_REGISTRATION_PRIMARY_TYPE,
    message: {
      verifyingService: message.verifyingService,
      runId: message.runId,
      fheCaseId: message.fheCaseId,
      assetIdentityDigest: message.assetIdentityDigest,
      policyDigest: message.policyDigest,
      role: message.role,
      participantWallet: message.participantWallet,
      participantSigningPublicKey: message.participantSigningPublicKey,
      participantSigningKeyDigest: message.participantSigningKeyDigest,
      registrationNonce: message.registrationNonce,
      issuedAt: BigInt(message.issuedAt),
      expiresAt: BigInt(message.expiresAt),
    },
  } as const;
}

export function participantSigningKeyRegistrationDigest(
  message: ParticipantSigningKeyRegistrationMessage,
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
): ParticipantOriginatedBytes32 {
  return hashTypedData(participantSigningKeyRegistrationTypedData(message, chainId));
}

/** Exact typed-data builder used by participant wallets and the coordinator. */
export function participantEncryptionIntentTypedData(
  message: ParticipantEncryptionIntentMessage,
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
) {
  return {
    domain: participantEncryptionIntentDomain(chainId),
    types: PARTICIPANT_ENCRYPTION_INTENT_TYPES,
    primaryType: PARTICIPANT_ENCRYPTION_INTENT_PRIMARY_TYPE,
    message: {
      verifyingService: message.verifyingService,
      runId: message.runId,
      fheCaseId: message.fheCaseId,
      caseBindingDigest: message.caseBindingDigest,
      protectionBindingDigest: message.protectionBindingDigest,
      assetIdentityDigest: message.assetIdentityDigest,
      policyDigest: message.policyDigest,
      circuitId: message.circuitId,
      circuitVersion: message.circuitVersion,
      circuitDigest: message.circuitDigest,
      parameterProfile: message.parameterProfile,
      parameterFingerprint: message.parameterFingerprint,
      fhePublicKeyDigest: message.fhePublicKeyDigest,
      releaseAuthorityId: message.releaseAuthorityId,
      releaseMode: message.releaseMode,
      role: message.role,
      participantWallet: message.participantWallet,
      participantSigningKeyDigest: message.participantSigningKeyDigest,
      registrationDigest: message.registrationDigest,
      claimCommitment: message.claimCommitment,
      clientBundleDigest: message.clientBundleDigest,
      clientSourceDigest: message.clientSourceDigest,
      clientBuildDigest: message.clientBuildDigest,
      clientBinaryDigest: message.clientBinaryDigest,
      bundleExpiresAt: BigInt(message.bundleExpiresAt),
      intentNonce: message.intentNonce,
      issuedAt: BigInt(message.issuedAt),
      expiresAt: BigInt(message.expiresAt),
    },
  } as const;
}

export function participantEncryptionIntentDigest(
  message: ParticipantEncryptionIntentMessage,
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
): ParticipantOriginatedBytes32 {
  return hashTypedData(participantEncryptionIntentTypedData(message, chainId));
}

/** Exact typed-data builder used by participant wallets and the coordinator. */
export function participantFinalEncryptedAdmissionTypedData(
  message: ParticipantFinalEncryptedAdmissionMessage,
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
) {
  return {
    domain: participantFinalEncryptedAdmissionDomain(chainId),
    types: PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_TYPES,
    primaryType: PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_PRIMARY_TYPE,
    message: {
      verifyingService: message.verifyingService,
      runId: message.runId,
      fheCaseId: message.fheCaseId,
      role: message.role,
      participantWallet: message.participantWallet,
      participantSigningKeyDigest: message.participantSigningKeyDigest,
      registrationDigest: message.registrationDigest,
      clientBundleDigest: message.clientBundleDigest,
      encryptionIntentDigest: message.encryptionIntentDigest,
      claimCommitment: message.claimCommitment,
      encryptedArtifactDigest: message.encryptedArtifactDigest,
      ciphertextObjectDigest: message.ciphertextObjectDigest,
      ciphertextObjectLength: BigInt(message.ciphertextObjectLength),
      submissionNonce: message.submissionNonce,
      issuedAt: BigInt(message.issuedAt),
      expiresAt: BigInt(message.expiresAt),
    },
  } as const;
}

export function participantFinalEncryptedAdmissionDigest(
  message: ParticipantFinalEncryptedAdmissionMessage,
  chainId: number = PARTICIPANT_ORIGINATED_CHAIN_ID,
): ParticipantOriginatedBytes32 {
  return hashTypedData(participantFinalEncryptedAdmissionTypedData(message, chainId));
}

/** Pure, network-free EOA verification. ERC-1271 is intentionally out of scope for this experiment. */
export async function verifyParticipantOriginatedEoaSignature(
  input: ParticipantOriginatedEoaVerifierInput,
): Promise<boolean> {
  try {
    const recovered = await recoverAddress({ hash: input.digest, signature: input.signature });
    return sameWallet(recovered, input.address);
  } catch {
    return false;
  }
}

async function assertEoaSignature(
  phase: ParticipantOriginatedAuthorizationPhase,
  address: ParticipantOriginatedWallet,
  digest: ParticipantOriginatedBytes32,
  signature: ParticipantOriginatedEoaSignature,
  verifier: ParticipantOriginatedEoaVerifier,
): Promise<void> {
  let verified: boolean;
  try {
    verified = await verifier({ phase, address, digest, signature });
  } catch {
    fail(`${phase}_SIGNATURE_UNVERIFIABLE`, 503, "The wallet signature could not be verified");
  }
  if (!verified) fail(`${phase}_SIGNATURE_REJECTED`, 401, "The wallet signature was rejected");
}

async function assertNonceReservation(
  guard: ParticipantOriginatedNonceGuard | undefined,
  reservation: ParticipantOriginatedNonceReservation,
): Promise<void> {
  if (guard === undefined) return;
  let available: boolean;
  try {
    available = await guard(reservation);
  } catch {
    fail(`${reservation.phase}_NONCE_UNAVAILABLE`, 503, "The nonce journal is unavailable");
  }
  if (!available) fail(`${reservation.phase}_REPLAY`, 409, "This authorization nonce was already consumed");
}

function chainIdFrom(value: number | undefined): number {
  const chainId = value ?? PARTICIPANT_ORIGINATED_CHAIN_ID;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) fail("CHAIN_ID", 500, "A positive chain ID is required");
  return chainId;
}

function assertRegistrationContext(
  message: ParticipantSigningKeyRegistrationMessage,
  expected: ExpectedParticipantSigningKeyRegistrationContext,
): void {
  expectEqual(message.verifyingService, expected.verifyingService, "REGISTRATION_SERVICE_MISMATCH", "Wrong service");
  expectEqual(message.runId, expected.runId, "REGISTRATION_RUN_MISMATCH", "Wrong run");
  expectEqual(message.fheCaseId, expected.fheCaseId, "REGISTRATION_CASE_MISMATCH", "Wrong FHE case");
  expectEqual(
    message.assetIdentityDigest,
    expected.assetIdentityDigest,
    "REGISTRATION_ASSET_MISMATCH",
    "Wrong asset",
  );
  expectEqual(message.policyDigest, expected.policyDigest, "REGISTRATION_POLICY_MISMATCH", "Wrong policy");
  expectEqual(message.role, expected.role, "REGISTRATION_ROLE_MISMATCH", "Wrong participant role");
  expectWallet(message.participantWallet, expected.participantWallet, "REGISTRATION_WALLET_MISMATCH");
}

/**
 * Verifies and optionally atomically reserves one Phase-0 nonce. Without a
 * `nonceGuard`, the caller must consume the returned nonce in its own durable
 * create-only transaction before treating the registration as admitted.
 */
export async function verifyParticipantSigningKeyRegistration(
  value: unknown,
  expected: ExpectedParticipantSigningKeyRegistrationContext,
  verifier: ParticipantOriginatedEoaVerifier = verifyParticipantOriginatedEoaSignature,
  nonceGuard?: ParticipantOriginatedNonceGuard,
): Promise<VerifiedParticipantSigningKeyRegistration> {
  const request = assertParticipantSigningKeyRegistrationRequest(value);
  const message = request.registration;
  assertRegistrationContext(message, expected);
  assertFresh(message.issuedAt, message.expiresAt, expected.now, "REGISTRATION");
  const chainId = chainIdFrom(expected.chainId);
  const registrationDigest = participantSigningKeyRegistrationDigest(message, chainId);
  await assertEoaSignature(
    "REGISTRATION",
    message.participantWallet,
    registrationDigest,
    request.signature,
    verifier,
  );
  await assertNonceReservation(nonceGuard, {
    phase: "REGISTRATION",
    runId: message.runId,
    role: message.role,
    nonce: message.registrationNonce,
    authorizationDigest: registrationDigest,
  });
  return Object.freeze({
    schemaVersion: PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA,
    registration: message,
    registrationDigest,
    signature: request.signature,
    role: message.role,
    participantWallet: message.participantWallet,
    participantSigningPublicKey: message.participantSigningPublicKey,
    participantSigningKeyDigest: message.participantSigningKeyDigest,
    chainId,
  });
}

async function assertStoredRegistration(
  stored: VerifiedParticipantSigningKeyRegistration,
  expected: Readonly<{
    verifyingService: string;
    runId: string;
    fheCaseId: ParticipantOriginatedBytes32;
    assetIdentityDigest: ParticipantOriginatedBytes32;
    policyDigest: ParticipantOriginatedBytes32;
    role: ParticipantOriginatedRole;
    participantWallet: ParticipantOriginatedWallet;
    now: number;
  }>,
  chainId: number,
  verifier: ParticipantOriginatedEoaVerifier,
): Promise<VerifiedParticipantSigningKeyRegistration> {
  if (stored.schemaVersion !== PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA) {
    fail("REGISTRATION_CHAIN_SCHEMA", 409, "The stored signing-key registration schema is wrong");
  }
  const message = assertParticipantSigningKeyRegistrationMessage(stored.registration);
  const signature = exactSignature(stored.signature);
  assertRegistrationContext(message, { ...expected, now: message.issuedAt, chainId });
  assertFresh(message.issuedAt, message.expiresAt, expected.now, "REGISTRATION");
  expectEqual(stored.chainId, chainId, "REGISTRATION_CHAIN_ID", "The registration came from another chain");
  const digest = participantSigningKeyRegistrationDigest(message, chainId);
  expectEqual(stored.registrationDigest, digest, "REGISTRATION_CHAIN_DIGEST", "The registration digest is stale");
  expectEqual(stored.role, message.role, "REGISTRATION_CHAIN_ROLE", "The stored registration role is inconsistent");
  expectWallet(stored.participantWallet, message.participantWallet, "REGISTRATION_CHAIN_WALLET");
  expectEqual(
    stored.participantSigningPublicKey,
    message.participantSigningPublicKey,
    "REGISTRATION_CHAIN_PUBLIC_KEY",
    "The stored registration public key is inconsistent",
  );
  expectEqual(
    stored.participantSigningKeyDigest,
    message.participantSigningKeyDigest,
    "REGISTRATION_CHAIN_KEY_DIGEST",
    "The stored registration key digest is inconsistent",
  );
  await assertEoaSignature("REGISTRATION", message.participantWallet, digest, signature, verifier);
  return stored;
}

function assertIntentMatchesBundle(
  message: ParticipantEncryptionIntentMessage,
  expected: ParticipantOriginatedBundleContext,
): void {
  const comparisons: ReadonlyArray<readonly [unknown, unknown, string, string]> = [
    [message.runId, expected.runId, "INTENT_RUN_MISMATCH", "Wrong run"],
    [message.fheCaseId, expected.fheCaseId, "INTENT_CASE_MISMATCH", "Wrong FHE case"],
    [message.caseBindingDigest, expected.caseBindingDigest, "INTENT_CASE_BINDING_MISMATCH", "Wrong case binding"],
    [
      message.protectionBindingDigest,
      expected.protectionBindingDigest,
      "INTENT_PROTECTION_BINDING_MISMATCH",
      "Wrong protection binding",
    ],
    [message.assetIdentityDigest, expected.assetIdentityDigest, "INTENT_ASSET_MISMATCH", "Wrong asset"],
    [message.policyDigest, expected.policyDigest, "INTENT_POLICY_MISMATCH", "Wrong policy"],
    [message.circuitId, expected.circuitId, "INTENT_CIRCUIT_ID_MISMATCH", "Wrong circuit"],
    [message.circuitVersion, expected.circuitVersion, "INTENT_CIRCUIT_VERSION_MISMATCH", "Wrong circuit version"],
    [message.circuitDigest, expected.circuitDigest, "INTENT_CIRCUIT_DIGEST_MISMATCH", "Wrong circuit digest"],
    [message.parameterProfile, expected.parameterProfile, "INTENT_PROFILE_MISMATCH", "Wrong parameter profile"],
    [
      message.parameterFingerprint,
      expected.parameterFingerprint,
      "INTENT_PARAMETER_FINGERPRINT_MISMATCH",
      "Wrong parameter fingerprint",
    ],
    [message.fhePublicKeyDigest, expected.fhePublicKeyDigest, "INTENT_FHE_KEY_MISMATCH", "Wrong FHE public key"],
    [
      message.releaseAuthorityId,
      expected.releaseAuthorityId,
      "INTENT_RELEASE_AUTHORITY_MISMATCH",
      "Wrong release authority",
    ],
    [message.releaseMode, expected.releaseMode, "INTENT_RELEASE_MODE_MISMATCH", "Wrong release mode"],
    [message.clientBundleDigest, expected.clientBundleDigest, "INTENT_BUNDLE_MISMATCH", "Wrong or stale bundle"],
    [message.clientSourceDigest, expected.clientSourceDigest, "INTENT_CLIENT_SOURCE_MISMATCH", "Wrong client source"],
    [message.clientBuildDigest, expected.clientBuildDigest, "INTENT_CLIENT_BUILD_MISMATCH", "Wrong client build"],
    [message.clientBinaryDigest, expected.clientBinaryDigest, "INTENT_CLIENT_BINARY_MISMATCH", "Wrong client binary"],
    [message.bundleExpiresAt, expected.bundleExpiresAt, "INTENT_BUNDLE_EXPIRY_MISMATCH", "Wrong bundle expiry"],
  ];
  for (const [actual, wanted, code, description] of comparisons) {
    expectEqual(actual, wanted, code, description);
  }
}

/**
 * Verifies and optionally atomically reserves one Phase-1 nonce. All bundle,
 * client, case and crypto pins are compared with coordinator-recomputed facts.
 */
export async function verifyParticipantEncryptionIntent(
  value: unknown,
  expected: ExpectedParticipantEncryptionIntentContext,
  verifier: ParticipantOriginatedEoaVerifier = verifyParticipantOriginatedEoaSignature,
  nonceGuard?: ParticipantOriginatedNonceGuard,
): Promise<VerifiedParticipantEncryptionIntent> {
  const request = assertParticipantEncryptionIntentRequest(value);
  const message = request.intent;
  const chainId = chainIdFrom(expected.chainId);
  const registration = await assertStoredRegistration(expected.registration, expected, chainId, verifier);
  expectEqual(message.verifyingService, expected.verifyingService, "INTENT_SERVICE_MISMATCH", "Wrong service");
  assertIntentMatchesBundle(message, expected);
  expectEqual(message.role, expected.role, "INTENT_ROLE_MISMATCH", "Wrong participant role");
  expectWallet(message.participantWallet, expected.participantWallet, "INTENT_WALLET_MISMATCH");
  expectEqual(
    message.participantSigningKeyDigest,
    expected.registration.participantSigningKeyDigest,
    "INTENT_SIGNING_KEY_MISMATCH",
    "Wrong participant signing key",
  );
  expectEqual(
    message.registrationDigest,
    registration.registrationDigest,
    "INTENT_REGISTRATION_MISMATCH",
    "Wrong signing-key registration",
  );
  if (
    message.issuedAt < registration.registration.issuedAt
    || message.expiresAt > registration.registration.expiresAt
  ) {
    fail(
      "INTENT_REGISTRATION_WINDOW",
      409,
      "The encryption intent must remain inside its signing-key registration window",
    );
  }
  if (message.intentNonce === registration.registration.registrationNonce) {
    fail("INTENT_NONCE_REUSE", 409, "The intent nonce must differ from the registration nonce");
  }
  if (expected.bundleExpiresAt <= expected.now) {
    fail("INTENT_STALE_BUNDLE", 409, "The public client bundle has expired");
  }
  assertFresh(message.issuedAt, message.expiresAt, expected.now, "INTENT");
  const encryptionIntentDigest = participantEncryptionIntentDigest(message, chainId);
  await assertEoaSignature("INTENT", message.participantWallet, encryptionIntentDigest, request.signature, verifier);
  await assertNonceReservation(nonceGuard, {
    phase: "INTENT",
    runId: message.runId,
    role: message.role,
    nonce: message.intentNonce,
    authorizationDigest: encryptionIntentDigest,
  });
  return Object.freeze({
    schemaVersion: PARTICIPANT_ENCRYPTION_INTENT_SCHEMA,
    intent: message,
    encryptionIntentDigest,
    signature: request.signature,
    registrationDigest: message.registrationDigest,
    claimCommitment: message.claimCommitment,
    role: message.role,
    participantWallet: message.participantWallet,
    participantSigningKeyDigest: message.participantSigningKeyDigest,
    chainId,
  });
}

function assertArtifactMatchesIntentAndBundle(
  artifact: RecomputedParticipantEncryptedArtifactContext,
  intent: ParticipantEncryptionIntentMessage,
  intentDigest: ParticipantOriginatedBytes32,
  expected: ParticipantOriginatedBundleContext,
  now: number,
): void {
  const comparisons: ReadonlyArray<readonly [unknown, unknown, string, string]> = [
    [artifact.fheCaseId, expected.fheCaseId, "ARTIFACT_CASE_MISMATCH", "Artifact belongs to another case"],
    [
      artifact.caseBindingDigest,
      expected.caseBindingDigest,
      "ARTIFACT_CASE_BINDING_MISMATCH",
      "Artifact has another case binding",
    ],
    [artifact.assetIdentityDigest, expected.assetIdentityDigest, "ARTIFACT_ASSET_MISMATCH", "Artifact has another asset"],
    [artifact.role, intent.role, "ARTIFACT_ROLE_MISMATCH", "Artifact has another role"],
    [
      artifact.participantSigningKeyDigest,
      intent.participantSigningKeyDigest,
      "ARTIFACT_SIGNING_KEY_MISMATCH",
      "Artifact has another participant signer",
    ],
    [artifact.parameterProfile, expected.parameterProfile, "ARTIFACT_PROFILE_MISMATCH", "Artifact has another profile"],
    [
      artifact.parameterFingerprint,
      expected.parameterFingerprint,
      "ARTIFACT_PARAMETER_FINGERPRINT_MISMATCH",
      "Artifact has other parameters",
    ],
    [artifact.fhePublicKeyDigest, expected.fhePublicKeyDigest, "ARTIFACT_FHE_KEY_MISMATCH", "Artifact has another FHE key"],
    [artifact.circuitDigest, expected.circuitDigest, "ARTIFACT_CIRCUIT_MISMATCH", "Artifact has another circuit"],
    [
      artifact.embeddedEncryptionIntentDigest,
      intentDigest,
      "ARTIFACT_INTENT_COMMITMENT_MISMATCH",
      "Ciphertext does not carry this intent digest",
    ],
    [
      artifact.embeddedClaimCommitment,
      intent.claimCommitment,
      "ARTIFACT_CLAIM_COMMITMENT_MISMATCH",
      "Ciphertext does not carry this hiding commitment",
    ],
  ];
  for (const [actual, wanted, code, description] of comparisons) {
    expectEqual(actual, wanted, code, description);
  }
  exactPositiveInteger(
    artifact.ciphertextObjectLength,
    "ARTIFACT_CIPHERTEXT_LENGTH",
    "ciphertextObjectLength",
    PARTICIPANT_ORIGINATED_CIPHERTEXT_MAX_BYTES,
  );
  exactBytes32(artifact.encryptedArtifactDigest, "ARTIFACT_DIGEST", "encryptedArtifactDigest");
  exactBytes32(artifact.ciphertextObjectDigest, "ARTIFACT_CIPHERTEXT_DIGEST", "ciphertextObjectDigest");
  exactBytes32(artifact.submissionNonce, "ARTIFACT_SUBMISSION_NONCE", "submissionNonce");
  if (!Number.isSafeInteger(artifact.expiresAt) || artifact.expiresAt <= now) {
    fail("ARTIFACT_EXPIRED", 401, "The encrypted participant artifact has expired");
  }
  if (artifact.expiresAt > expected.bundleExpiresAt) {
    fail("ARTIFACT_BUNDLE_EXPIRY", 409, "The encrypted artifact outlives its client bundle");
  }
}

/**
 * Verifies and optionally atomically reserves one Phase-2 submission nonce.
 * Artifact and ciphertext digests must come from server-side hashing, and the
 * artifact context must come from the existing canonical Go validator.
 */
export async function verifyParticipantFinalEncryptedAdmission(
  value: unknown,
  expected: ExpectedParticipantFinalEncryptedAdmissionContext,
  verifier: ParticipantOriginatedEoaVerifier = verifyParticipantOriginatedEoaSignature,
  nonceGuard?: ParticipantOriginatedNonceGuard,
): Promise<VerifiedParticipantFinalEncryptedAdmission> {
  const request = assertParticipantFinalEncryptedAdmissionRequest(value);
  const message = request.admission;
  const chainId = chainIdFrom(expected.chainId);
  const intent = await verifyParticipantEncryptionIntent(
    {
      schemaVersion: expected.intent.schemaVersion,
      intent: expected.intent.intent,
      signature: expected.intent.signature,
    },
    { ...expected, registration: expected.registration, now: expected.now, chainId },
    verifier,
  );
  expectEqual(
    expected.intent.encryptionIntentDigest,
    intent.encryptionIntentDigest,
    "FINAL_ADMISSION_STORED_INTENT_DIGEST",
    "The stored intent digest is inconsistent",
  );
  expectEqual(expected.intent.chainId, chainId, "FINAL_ADMISSION_INTENT_CHAIN", "The intent came from another chain");
  assertArtifactMatchesIntentAndBundle(
    expected.artifact,
    intent.intent,
    intent.encryptionIntentDigest,
    expected,
    expected.now,
  );

  const comparisons: ReadonlyArray<readonly [unknown, unknown, string, string]> = [
    [message.verifyingService, expected.verifyingService, "FINAL_ADMISSION_SERVICE_MISMATCH", "Wrong service"],
    [message.runId, expected.runId, "FINAL_ADMISSION_RUN_MISMATCH", "Wrong run"],
    [message.fheCaseId, expected.fheCaseId, "FINAL_ADMISSION_CASE_MISMATCH", "Wrong FHE case"],
    [message.role, expected.role, "FINAL_ADMISSION_ROLE_MISMATCH", "Wrong participant role"],
    [
      message.participantSigningKeyDigest,
      expected.registration.participantSigningKeyDigest,
      "FINAL_ADMISSION_SIGNING_KEY_MISMATCH",
      "Wrong participant signing key",
    ],
    [
      message.registrationDigest,
      expected.registration.registrationDigest,
      "FINAL_ADMISSION_REGISTRATION_MISMATCH",
      "Wrong signing-key registration",
    ],
    [
      message.clientBundleDigest,
      expected.clientBundleDigest,
      "FINAL_ADMISSION_BUNDLE_MISMATCH",
      "Wrong or stale client bundle",
    ],
    [
      message.encryptionIntentDigest,
      intent.encryptionIntentDigest,
      "FINAL_ADMISSION_INTENT_MISMATCH",
      "Wrong encryption intent",
    ],
    [
      message.claimCommitment,
      intent.claimCommitment,
      "FINAL_ADMISSION_CLAIM_COMMITMENT_MISMATCH",
      "Wrong hiding claim commitment",
    ],
    [
      message.encryptedArtifactDigest,
      expected.artifact.encryptedArtifactDigest,
      "FINAL_ADMISSION_ARTIFACT_DIGEST_MISMATCH",
      "Wrong encrypted artifact digest",
    ],
    [
      message.ciphertextObjectDigest,
      expected.artifact.ciphertextObjectDigest,
      "FINAL_ADMISSION_CIPHERTEXT_DIGEST_MISMATCH",
      "Wrong ciphertext digest",
    ],
    [
      message.ciphertextObjectLength,
      expected.artifact.ciphertextObjectLength,
      "FINAL_ADMISSION_CIPHERTEXT_LENGTH_MISMATCH",
      "Wrong ciphertext length",
    ],
    [
      message.submissionNonce,
      expected.artifact.submissionNonce,
      "FINAL_ADMISSION_SUBMISSION_NONCE_MISMATCH",
      "Wrong artifact submission nonce",
    ],
  ];
  for (const [actual, wanted, code, description] of comparisons) {
    expectEqual(actual, wanted, code, description);
  }
  expectWallet(message.participantWallet, expected.participantWallet, "FINAL_ADMISSION_WALLET_MISMATCH");
  if (
    message.submissionNonce === intent.intent.intentNonce
    || message.submissionNonce === expected.registration.registration.registrationNonce
  ) {
    fail("FINAL_ADMISSION_NONCE_REUSE", 409, "The submission nonce must be distinct from earlier phases");
  }
  if (message.issuedAt < intent.intent.issuedAt || message.issuedAt > intent.intent.expiresAt) {
    fail("FINAL_ADMISSION_INTENT_WINDOW", 409, "The final admission was not issued within its intent window");
  }
  if (
    message.expiresAt > intent.intent.expiresAt
    || message.expiresAt > expected.artifact.expiresAt
    || message.expiresAt > expected.bundleExpiresAt
  ) {
    fail("FINAL_ADMISSION_EXPIRY_RELATIONSHIP", 409, "The final admission outlives a prerequisite");
  }
  assertFresh(message.issuedAt, message.expiresAt, expected.now, "FINAL_ADMISSION");
  const finalAdmissionDigest = participantFinalEncryptedAdmissionDigest(message, chainId);
  await assertEoaSignature(
    "FINAL_ADMISSION",
    message.participantWallet,
    finalAdmissionDigest,
    request.signature,
    verifier,
  );
  await assertNonceReservation(nonceGuard, {
    phase: "FINAL_ADMISSION",
    runId: message.runId,
    role: message.role,
    nonce: message.submissionNonce,
    authorizationDigest: finalAdmissionDigest,
  });
  return Object.freeze({
    schemaVersion: PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA,
    admission: message,
    finalAdmissionDigest,
    signature: request.signature,
    encryptionIntentDigest: message.encryptionIntentDigest,
    encryptedArtifactDigest: message.encryptedArtifactDigest,
    ciphertextObjectDigest: message.ciphertextObjectDigest,
    submissionNonce: message.submissionNonce,
    role: message.role,
    participantWallet: message.participantWallet,
    chainId,
  });
}
