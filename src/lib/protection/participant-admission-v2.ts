import { createHash } from "node:crypto";

import { keccak256, toHex } from "viem";

import {
  digestToBytes32,
  isParticipantRole,
  participantAdmissionDomain,
  PARTICIPANT_AUTHORIZATION_MAX_LIFETIME_SECONDS,
  type Bytes32,
  type ParticipantRole,
} from "./participant-authorization";

/**
 * Participant admission V2: the wallet also names the key that will sign for it.
 *
 * V1 proves that a CVI-eligible **wallet** consented to this case, asset and
 * role. The enrollments that authorize a participant's ciphertexts are signed by
 * an **Ed25519 key**, and V1 says nothing about it. So the two identities of one
 * participant were unlinked: a wallet was admitted, a key enrolled ciphertexts,
 * and nothing tied them together.
 *
 * V2 adds one field, the digest of that Ed25519 key. The admitted wallet is then
 * saying "this key acts for me in this case", and an enrollment becomes traceable
 * to a wallet Cleanverse admitted. Removing Cleanverse stops being the removal of
 * a side proof: with no admission there is no authorized signing key, and no
 * enrollment can enter.
 *
 * It is a new type rather than an extra field on V1. Changing V1 would move its
 * EIP-712 type hash and invalidate every retained admission, and the governed
 * path still uses V1.
 */
export const PARTICIPANT_ADMISSION_V2_SCHEMA = "mordant.participant-admission/2" as const;
export const PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE = "ParticipantAdmissionV2" as const;
export const PARTICIPANT_ADMISSION_V2_DOMAIN_VERSION = "2" as const;
export const PARTICIPANT_ADMISSION_V2_SALT = keccak256(toHex(PARTICIPANT_ADMISSION_V2_SCHEMA));

export class ParticipantAdmissionV2Error extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = "ParticipantAdmissionV2Error";
    this.code = code;
    this.status = status;
  }
}

function fail(code: string, status: number, message: string): never {
  throw new ParticipantAdmissionV2Error(code, status, message);
}

/**
 * The same fields V1 carries, in the same order, plus the signing key.
 *
 * The order matters: it is the EIP-712 struct encoding. Appending rather than
 * inserting keeps a V2 message readable next to a V1 one.
 */
export const PARTICIPANT_ADMISSION_V2_TYPES = {
  ParticipantAdmissionV2: [
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
    /** The Ed25519 key this wallet authorizes to sign its enrollments. */
    { name: "participantSigningKeyDigest", type: "bytes32" },
  ],
} as const;

export type ParticipantAdmissionV2Message = Readonly<{
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
  participantSigningKeyDigest: Bytes32;
}>;

const BYTES32 = /^0x[0-9a-f]{64}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;

/**
 * The digest of an Ed25519 signing key, in the same shape the case binding uses.
 *
 * `ParticipantIdentity.signingPublicKey` is base64 in the binding, and its digest
 * is sha256 over the raw key bytes. Deriving it here rather than accepting it
 * from a caller means a V2 admission cannot name a key the binding does not.
 */
export function participantSigningKeyDigest(signingPublicKeyBase64: string): Bytes32 {
  const raw = Buffer.from(signingPublicKeyBase64, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== signingPublicKeyBase64) {
    fail("SIGNING_KEY", 400, "A participant signing key must be a canonical Ed25519 public key");
  }
  return `0x${createHash("sha256").update(raw).digest("hex")}`;
}

export function participantAdmissionV2TypedData(message: ParticipantAdmissionV2Message, chainId?: number) {
  const domain = participantAdmissionDomain(chainId);
  return {
    domain: { ...domain, version: PARTICIPANT_ADMISSION_V2_DOMAIN_VERSION, salt: PARTICIPANT_ADMISSION_V2_SALT },
    types: PARTICIPANT_ADMISSION_V2_TYPES,
    primaryType: PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE,
    message,
  } as const;
}

export function assertParticipantAdmissionV2Message(value: unknown): ParticipantAdmissionV2Message {
  if (typeof value !== "object" || value === null) {
    fail("ADMISSION_SHAPE", 400, "A participant admission object is required");
  }
  const candidate = value as Record<string, unknown>;
  const expectedKeys = PARTICIPANT_ADMISSION_V2_TYPES.ParticipantAdmissionV2.map((field) => field.name);
  const actualKeys = Object.keys(candidate).sort();
  if (actualKeys.length !== expectedKeys.length || [...expectedKeys].sort().some((key, index) => key !== actualKeys[index])) {
    fail("ADMISSION_SHAPE", 400, "The admission carries unexpected or missing fields");
  }
  for (const key of ["fheCaseId", "protectionBindingDigest", "assetIdentityDigest", "authorizationNonce", "participantSigningKeyDigest"]) {
    if (typeof candidate[key] !== "string" || !BYTES32.test(candidate[key] as string)) {
      fail("ADMISSION_FIELD", 400, `${key} must be lower-case 0x bytes32`);
    }
  }
  if (typeof candidate.participantWallet !== "string" || !ADDRESS.test(candidate.participantWallet)) {
    fail("ADMISSION_FIELD", 400, "participantWallet must be an address");
  }
  if (!isParticipantRole(candidate.role)) fail("ADMISSION_FIELD", 400, "role must be a participant role");
  for (const key of ["activeFrom", "activeUntil", "issuedAt", "expiresAt"]) {
    const time = candidate[key];
    if (typeof time !== "number" || !Number.isSafeInteger(time) || time <= 0) {
      fail("ADMISSION_FIELD", 400, `${key} must be a positive integer of Unix seconds`);
    }
  }
  const message = candidate as unknown as ParticipantAdmissionV2Message;
  if (message.expiresAt <= message.issuedAt) fail("ADMISSION_WINDOW", 400, "The admission expires before it is issued");
  if (message.expiresAt - message.issuedAt > PARTICIPANT_AUTHORIZATION_MAX_LIFETIME_SECONDS) {
    fail("ADMISSION_WINDOW", 400, "The admission lifetime exceeds the maximum");
  }
  if (message.activeUntil <= message.activeFrom) fail("ADMISSION_WINDOW", 400, "The claim window is empty");
  return message;
}

/** The participant identity a case binding publishes for one role. */
export type BoundParticipantIdentity = Readonly<{
  id: string;
  role: string;
  signingPublicKey: string;
}>;

export type AdmittedEnrollmentKey = Readonly<{
  role: ParticipantRole;
  participantWallet: `0x${string}`;
  signingKeyDigest: Bytes32;
  admissionDigest: Bytes32;
}>;

/**
 * Asserts that an admission authorizes exactly the key the case binding will
 * accept enrollments from.
 *
 * This is the join the whole version exists for. Without it a case could publish
 * one signing key while a wallet admitted a different one, and the enrollments
 * would verify against a key no eligible wallet ever named.
 *
 * The digest is derived from the binding's own key rather than compared between
 * two supplied values, so an admission cannot name a key the case does not
 * publish.
 */
export function assertAdmissionBindsEnrollmentKey(
  admission: ParticipantAdmissionV2Message,
  identity: BoundParticipantIdentity,
  admissionDigest: Bytes32,
  now: number,
): AdmittedEnrollmentKey {
  if (identity.role !== admission.role) {
    fail("ROLE_MISMATCH", 409, "The admission was signed for a different role than this identity");
  }
  const derived = participantSigningKeyDigest(identity.signingPublicKey);
  if (derived !== admission.participantSigningKeyDigest) {
    fail(
      "SIGNING_KEY_NOT_ADMITTED",
      409,
      "The case publishes a signing key that no admitted wallet authorized for this role",
    );
  }
  // An admission is a statement about a window, not a permanent grant.
  if (now < admission.issuedAt || now > admission.expiresAt) {
    fail("ADMISSION_EXPIRED", 409, "The admission is outside its validity window");
  }
  return Object.freeze({
    role: admission.role,
    participantWallet: admission.participantWallet,
    signingKeyDigest: derived,
    admissionDigest,
  });
}

/**
 * Asserts that both roles of a coalition case are covered by admissions that
 * name exactly the two keys the binding publishes.
 *
 * Coalition cases are the ones this is enforced for. The governed path keeps V1,
 * whose retained evidence must stay verifiable, and gains nothing from a rule it
 * was never built under.
 */
export function assertCoalitionCaseKeysAreAdmitted(
  admissions: readonly AdmittedEnrollmentKey[],
  participantA: BoundParticipantIdentity,
  participantB: BoundParticipantIdentity,
): void {
  const byRole = new Map(admissions.map((admitted) => [admitted.role, admitted]));
  if (byRole.size !== admissions.length) {
    fail("DUPLICATE_ROLE", 409, "Two admissions cover the same role");
  }
  for (const [role, identity] of [
    ["PARTICIPANT_A", participantA],
    ["PARTICIPANT_B", participantB],
  ] as const) {
    const admitted = byRole.get(role);
    if (admitted === undefined) {
      fail("ROLE_NOT_ADMITTED", 409, `No admitted wallet authorized a signing key for ${role}`);
    }
    if (admitted.signingKeyDigest !== participantSigningKeyDigest(identity.signingPublicKey)) {
      fail("SIGNING_KEY_NOT_ADMITTED", 409, `The signing key published for ${role} is not the admitted one`);
    }
  }
  const wallets = new Set(admissions.map((admitted) => admitted.participantWallet.toLowerCase()));
  if (wallets.size !== admissions.length) {
    fail("WALLET_COLLISION", 409, "One wallet cannot hold both sides of a bilateral case");
  }
}
