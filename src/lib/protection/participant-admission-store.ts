/**
 * Durable role admission ledger.
 *
 * One role, one wallet, one authorization, written exactly once. The ledger is
 * the authority for "has this role been admitted"; the engine's execution state
 * is the authority for everything downstream of that.
 *
 * Every admission is create-only (`wx`). A second writer for the same role does
 * not overwrite, does not merge and does not reassign: it either recognises its
 * own exact authorization and becomes idempotent, or it is refused. That is what
 * makes "A cannot overwrite B", "no automatic role reassignment" and "an exact
 * retry is idempotent" the same mechanism rather than three separate hopes.
 *
 * The ledger never stores a private claim. It stores the claim's commitment, so
 * immutability is checkable after the claim itself has been pruned.
 */

import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import type { Bytes32, ParticipantRole } from "./participant-authorization";

export const PARTICIPANT_ADMISSION_RECORD_SCHEMA = "mordant.participant-admission-record/3" as const;
/**
 * The pre-hardening record. It carried only the authorization DIGEST, so a
 * pruned run could never independently re-prove that the wallet actually signed.
 * Readable so historical runs still parse; never written again.
 */
export const PARTICIPANT_ADMISSION_RECORD_SCHEMA_V2 = "mordant.participant-admission-record/2" as const;
export const PARTICIPANT_CASE_CODE_SCHEMA = "mordant.participant-case-code/1" as const;

/** Unambiguous alphabet: no I, L, O, U, and no lowercase. */
const CASE_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const CASE_CODE_LENGTH = 16;
export const CASE_CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{16}$/u;

export type ParticipantAdmissionRecord = Readonly<{
  schemaVersion: typeof PARTICIPANT_ADMISSION_RECORD_SCHEMA | typeof PARTICIPANT_ADMISSION_RECORD_SCHEMA_V2;
  runId: string;
  /**
   * The exact ParticipantAdmissionV1 struct the wallet signed, and its signature.
   * Retained so the authorization stays independently verifiable after pruning.
   * Absent only on historical `/2` records, where it was never captured.
   */
  authorization?: Readonly<Record<string, unknown>>;
  signature?: `0x${string}`;
  role: ParticipantRole;
  participantWallet: `0x${string}`;
  authorizationDigest: Bytes32;
  claimCommitment: Bytes32;
  authorizationNonce: Bytes32;
  /** The chain bound into the verified EIP-712 authorization domain. */
  chainId: number;
  issuedAt: number;
  expiresAt: number;
  /**
   * The Ed25519 key digest this wallet authorized, retained so case creation can
   * refuse to publish a key no admission named. Absent on V1 records.
   */
  participantSigningKeyDigest?: Bytes32;
  /** The Monad block at which the active Cleanverse policy admitted this wallet. */
  eligibilityBlock: number;
  admittedAtUnix: number;
}>;

export class ParticipantAdmissionStoreError extends Error {
  constructor(readonly code: string, readonly status: number, message: string) {
    super(message);
    this.name = "ParticipantAdmissionStoreError";
  }
}

function fail(code: string, status: number, message: string): never {
  throw new ParticipantAdmissionStoreError(code, status, message);
}

/**
 * Create-only durable write. `wx` is the whole guarantee: the filesystem decides
 * the winner of a race, and the loser is told the slot was taken rather than
 * silently clobbering it.
 */
function writeCreateOnly(path: string, value: unknown): boolean {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let file = -1;
  try {
    file = openSync(path, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw error;
  }
  try {
    writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(file);
  } finally {
    closeSync(file);
  }
  let directory = -1;
  try {
    directory = openSync(dirname(path), "r");
    fsyncSync(directory);
  } finally {
    if (directory >= 0) closeSync(directory);
  }
  return true;
}

function readJsonOrNull<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return null;
  }
}

export function admissionRoot(runRoot: string, runId: string): string {
  return join(runRoot, runId, "admissions");
}

export function admissionRecordPath(runRoot: string, runId: string, role: ParticipantRole): string {
  return join(admissionRoot(runRoot, runId), `${role.toLowerCase()}.json`);
}

/**
 * Serializes the only cross-record invariant in this ledger: a wallet and an
 * authorization nonce can occupy no more than one role in a run. The lock is a
 * create-only file, so it is atomic across worker processes sharing the same
 * durable volume.
 *
 * A stranded lock deliberately fails closed. Reclaiming it based on a clock or
 * a PID would guess whether another writer is dead and could reopen the exact
 * cross-role race this lock prevents.
 */
function withRunAdmissionLock<T>(runRoot: string, runId: string, operation: () => T): T {
  const root = admissionRoot(runRoot, runId);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const lockPath = join(root, ".admission.lock");
  let lock = -1;
  try {
    lock = openSync(lockPath, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      fail("ADMISSION_BUSY", 409, "Participant admission is already being recorded for this case");
    }
    throw error;
  }
  try {
    writeFileSync(lock, `${JSON.stringify({ runId })}\n`, "utf8");
    fsyncSync(lock);
    return operation();
  } finally {
    closeSync(lock);
    unlinkSync(lockPath);
  }
}

export function caseCodePath(runRoot: string, caseCode: string): string {
  if (!CASE_CODE_PATTERN.test(caseCode)) fail("CASE_CODE", 404, "Unknown case code");
  return join(runRoot, "case-codes", `${caseCode}.json`);
}

export function generateCaseCode(): string {
  // Rejection-free because 32 divides 256 exactly, so every byte maps uniformly.
  const bytes = randomBytes(CASE_CODE_LENGTH);
  let code = "";
  for (const byte of bytes) code += CASE_CODE_ALPHABET[byte % 32];
  return code;
}

/** Binds a shareable case code to a run, exactly once. */
export function bindCaseCode(runRoot: string, caseCode: string, runId: string): void {
  const created = writeCreateOnly(caseCodePath(runRoot, caseCode), {
    schemaVersion: PARTICIPANT_CASE_CODE_SCHEMA,
    caseCode,
    runId,
  });
  if (!created) {
    const existing = readJsonOrNull<{ runId?: string }>(caseCodePath(runRoot, caseCode));
    // Rebinding the same code to the same run is the lost-response retry.
    if (existing?.runId !== runId) fail("CASE_CODE_TAKEN", 409, "That case code is already in use");
  }
}

export function resolveCaseCode(runRoot: string, caseCode: string): string | null {
  const record = readJsonOrNull<{ schemaVersion?: string; runId?: string }>(caseCodePath(runRoot, caseCode));
  if (record === null || record.schemaVersion !== PARTICIPANT_CASE_CODE_SCHEMA) return null;
  return typeof record.runId === "string" ? record.runId : null;
}

function assertAdmissionRecord(record: ParticipantAdmissionRecord, runId: string, role: ParticipantRole): void {
  if (
    (record.schemaVersion !== PARTICIPANT_ADMISSION_RECORD_SCHEMA
      && record.schemaVersion !== PARTICIPANT_ADMISSION_RECORD_SCHEMA_V2)
    || record.runId !== runId
    || record.role !== role
    || typeof record.participantWallet !== "string"
    || !/^0x[0-9a-fA-F]{40}$/u.test(record.participantWallet)
    || !/^0x[0-9a-f]{64}$/u.test(record.authorizationDigest)
    || !/^0x[0-9a-f]{64}$/u.test(record.claimCommitment)
    || !/^0x[0-9a-f]{64}$/u.test(record.authorizationNonce)
    || !Number.isSafeInteger(record.chainId)
    || record.chainId <= 0
    || !Number.isSafeInteger(record.issuedAt)
    || !Number.isSafeInteger(record.expiresAt)
    || record.issuedAt <= 0
    || record.expiresAt <= record.issuedAt
    || !Number.isSafeInteger(record.eligibilityBlock)
    || record.eligibilityBlock < 0
    || !Number.isSafeInteger(record.admittedAtUnix)
    || record.admittedAtUnix <= 0
  ) {
    fail("ADMISSION_INTEGRITY", 500, "The durable admission record was rejected");
  }
}

export function readAdmission(
  runRoot: string,
  runId: string,
  role: ParticipantRole,
): ParticipantAdmissionRecord | null {
  const record = readJsonOrNull<ParticipantAdmissionRecord>(admissionRecordPath(runRoot, runId, role));
  if (record === null) return null;
  assertAdmissionRecord(record, runId, role);
  return record;
}

export function readAdmissions(
  runRoot: string,
  runId: string,
): Readonly<Partial<Record<ParticipantRole, ParticipantAdmissionRecord>>> {
  const admitted: Partial<Record<ParticipantRole, ParticipantAdmissionRecord>> = {};
  for (const role of ["PARTICIPANT_A", "PARTICIPANT_B"] as const) {
    const record = readAdmission(runRoot, runId, role);
    if (record !== null) admitted[role] = record;
  }
  return Object.freeze(admitted);
}

export type AdmissionOutcome = Readonly<{
  record: ParticipantAdmissionRecord;
  /** False when this exact authorization had already been durably admitted. */
  admitted: boolean;
}>;

function sameAuthorization(
  record: ParticipantAdmissionRecord,
  candidate: Omit<ParticipantAdmissionRecord, "schemaVersion">,
): boolean {
  return record.authorizationDigest === candidate.authorizationDigest
    && record.claimCommitment === candidate.claimCommitment
    && record.participantWallet === candidate.participantWallet
    && record.authorizationNonce === candidate.authorizationNonce
    && record.chainId === candidate.chainId
    && record.issuedAt === candidate.issuedAt
    && record.expiresAt === candidate.expiresAt;
}

/**
 * Admits one role and consumes its nonce in a single create-only write.
 *
 * Role and nonce are one durable object rather than two, so there is no window in
 * which a nonce is consumed but no role admitted, or a role admitted under a
 * nonce that was never claimed. `wx` makes the filesystem the arbiter: a second
 * writer for the same role either recognises its own exact authorization and
 * becomes idempotent, or is refused without changing anything.
 *
 * Nonce reuse is checked against the sibling role, which is the whole population
 * of this case. Reuse across cases is not reachable: `runId` is inside the signed
 * struct, so a signature made for one case verifies for no other.
 */
export function admitParticipantRole(
  runRoot: string,
  candidate: Omit<ParticipantAdmissionRecord, "schemaVersion">,
): AdmissionOutcome {
  const { runId, role } = candidate;
  return withRunAdmissionLock(runRoot, runId, () => {
    const otherRole: ParticipantRole = role === "PARTICIPANT_A" ? "PARTICIPANT_B" : "PARTICIPANT_A";

    const existing = readAdmission(runRoot, runId, role);
    if (existing !== null) {
      if (sameAuthorization(existing, candidate)) return Object.freeze({ record: existing, admitted: false });
      fail("ROLE_OCCUPIED", 409, `${role} has already been admitted for this case`);
    }

    const other = readAdmission(runRoot, runId, otherRole);
    if (role === "PARTICIPANT_B" && other === null) {
      fail("ADMISSION_OUT_OF_ORDER", 409, "Participant B cannot be admitted before Participant A");
    }
    if (role === "PARTICIPANT_A" && other !== null) {
      fail("ADMISSION_INTEGRITY", 500, "Participant B exists without Participant A");
    }
    if (other !== null) {
      if (other.participantWallet.toLowerCase() === candidate.participantWallet.toLowerCase()) {
        fail("DUPLICATE_SIGNER", 409, "That wallet already holds the other role in this case");
      }
      if (other.authorizationNonce === candidate.authorizationNonce) {
        fail("NONCE_REPLAY", 409, "That authorization nonce has already been used");
      }
    }

    const record: ParticipantAdmissionRecord = {
      schemaVersion: PARTICIPANT_ADMISSION_RECORD_SCHEMA,
      ...candidate,
    };
    assertAdmissionRecord(record, runId, role);
    const created = writeCreateOnly(admissionRecordPath(runRoot, runId, role), record);
    if (!created) {
      // Lost a race between the read above and this write. Re-read and apply the
      // same idempotency rule rather than assuming who won.
      const winner = readAdmission(runRoot, runId, role);
      if (winner !== null && sameAuthorization(winner, candidate)) {
        return Object.freeze({ record: winner, admitted: false });
      }
      fail("ROLE_OCCUPIED", 409, `${role} has already been admitted for this case`);
    }
    return Object.freeze({ record, admitted: true });
  });
}

export type AdmissionProgress = Readonly<{
  participantA: boolean;
  participantB: boolean;
  bothAdmitted: boolean;
  wallets: Readonly<{ participantA: `0x${string}` | null; participantB: `0x${string}` | null }>;
}>;

export function admissionProgress(runRoot: string, runId: string): AdmissionProgress {
  const admitted = readAdmissions(runRoot, runId);
  const a = admitted.PARTICIPANT_A ?? null;
  const b = admitted.PARTICIPANT_B ?? null;
  return Object.freeze({
    participantA: a !== null,
    participantB: b !== null,
    bothAdmitted: a !== null && b !== null,
    wallets: Object.freeze({
      participantA: a?.participantWallet ?? null,
      participantB: b?.participantWallet ?? null,
    }),
  });
}

/**
 * Abandonment is a report, never an act. Nothing is deleted here: a case that
 * has run out of time is described as abandoned so the caller can refuse new
 * work on it, and the admitted records stay on disk as evidence of what happened.
 */
export function admissionAbandoned(
  runRoot: string,
  runId: string,
  createdAtUnix: number,
  nowUnix: number,
  lifetimeSeconds: number,
): boolean {
  if (nowUnix - createdAtUnix < lifetimeSeconds) return false;
  return !admissionProgress(runRoot, runId).bothAdmitted;
}

export function admittedRoleCount(runRoot: string, runId: string): number {
  const root = admissionRoot(runRoot, runId);
  if (!existsSync(root)) return 0;
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isFile() && (entry.name === "participant_a.json" || entry.name === "participant_b.json"))
    .length;
}
