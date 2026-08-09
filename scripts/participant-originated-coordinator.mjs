#!/usr/bin/env node
/**
 * Supported, qualified native-CLI participant-originated ciphertext transport.
 *
 * This module is intentionally not imported by mordant-live-worker.mjs.  It
 * accepts only wallet-authorized public metadata and encrypted objects; a
 * participant claim, claim salt, pledge-window bound, or signing private key is
 * never part of this transport's request or durable-state shape.
 */

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  rmdirSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { createServer } from "node:http";
import { basename, dirname, join } from "node:path";
import { Readable } from "node:stream";

export const PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA = "mordant.participant-originated-coordinator/1";
export const PARTICIPANT_ORIGINATED_IMPORT_SCHEMA = "mordant.participant-originated-import/1";
export const PARTICIPANT_ORIGINATED_JOURNAL_SCHEMA = "mordant.participant-originated-import-journal/1";
export const PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE = "application/octet-stream";
export const PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE = "application/json";
export const PARTICIPANT_ORIGINATED_TICKET_HEADER = "x-mordant-import-ticket";
export const PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES = 64 * 1024;
export const PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
export const PARTICIPANT_ORIGINATED_MAX_CIPHERTEXT_BYTES = 192 * 1024 * 1024;
export const PARTICIPANT_ORIGINATED_MAX_AUTH_LIFETIME_SECONDS = 15 * 60;
export const PARTICIPANT_ORIGINATED_CLOCK_SKEW_SECONDS = 120;
export const PARTICIPANT_ORIGINATED_STREAM_IDLE_TIMEOUT_MS = 30 * 1000;
export const PARTICIPANT_ORIGINATED_STREAM_ABSOLUTE_TIMEOUT_MS = 5 * 60 * 1000;

const PARTICIPANT_ORIGINATED_RESERVATION_TRANSACTION_SCHEMA = "mordant.participant-originated-reservation-transaction/1";
const PARTICIPANT_ORIGINATED_RESERVATION_COMMIT_SCHEMA = "mordant.participant-originated-reservation-commit/1";
const ACTIVE_RESERVATION_TRANSACTIONS = new Set();

export const participantOriginatedRoutes = Object.freeze({
  beginImport: "/v1/participant-originated/import/begin",
  ciphertext: "/v1/participant-originated/import/ciphertext",
  artifactManifest: "/v1/participant-originated/import/artifact-manifest",
  status: "/v1/participant-originated/import/status",
});

const ROLE_FILENAMES = Object.freeze({
  PARTICIPANT_A: Object.freeze({ ciphertext: "submission-a.bin", artifactManifest: "submission-a.json" }),
  PARTICIPANT_B: Object.freeze({ ciphertext: "submission-b.bin", artifactManifest: "submission-b.json" }),
});

export function participantFilenames(role) {
  const names = ROLE_FILENAMES[role];
  if (names === undefined) throw new ParticipantOriginatedCoordinatorError(400, "ROLE", "Participant role rejected");
  return names;
}

export class ParticipantOriginatedCoordinatorError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ParticipantOriginatedCoordinatorError";
    this.status = status;
    this.code = code;
  }
}

const METADATA_MEMBERS = Object.freeze([
  "schemaVersion", "runId", "fheCaseId", "role", "participantWallet", "chainId",
  "participantSigningKeyDigest", "registrationDigest", "encryptionIntentDigest",
  "finalAdmissionDigest", "claimCommitment", "clientBundleDigest", "encryptedArtifactDigest",
  "artifactObjectDigest", "artifactObjectLength", "ciphertextObjectDigest", "ciphertextObjectLength", "registrationNonce", "intentNonce",
  "submissionNonce", "issuedAt", "expiresAt", "walletAuthorizationChain",
]);
const AUTHORIZATION_MEMBERS = Object.freeze([
  "registration", "encryptionIntent", "finalAdmission",
]);
const SIGNED_AUTHORIZATION_MEMBERS = Object.freeze(["schemaVersion", "message", "signature"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const SIGNATURE = /^0x(?:[0-9a-fA-F]{2}){1,4096}$/u;
const TICKET = /^[A-Za-z0-9_-]{43}$/u;
const FORBIDDEN_MEMBER = /^(?:claim|activefrom|activeuntil|salt|privatekey|participantprivatekey|artifactsigningprivatekey|signingprivatekey|plaintext|claimpreimage)$/u;

function fail(status, code, message) {
  throw new ParticipantOriginatedCoordinatorError(status, code, message);
}

function exactKeys(value, members) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...members].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function scanForbiddenMembers(value) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) scanForbiddenMembers(item);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[-_]/gu, "");
    if (FORBIDDEN_MEMBER.test(normalized)) fail(400, "PLAINTEXT_FIELD", `Forbidden participant field: ${key}`);
    scanForbiddenMembers(child);
  }
}

function canonicalJson(value, depth = 0) {
  if (depth > 32) fail(400, "JSON_DEPTH", "JSON nesting is too deep");
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail(400, "JSON_NUMBER", "JSON numbers must be safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item, depth + 1)).join(",")}]`;
  if (typeof value !== "object") fail(400, "JSON_VALUE", "Unsupported JSON value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(",")}}`;
}

function parseCanonicalJson(raw, limit, kind, requireTrailingNewline = false) {
  if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > limit) fail(413, `${kind}_SIZE`, `${kind} JSON size rejected`);
  let value;
  try { value = JSON.parse(raw.toString("utf8")); } catch { fail(400, `${kind}_JSON`, `${kind} must be valid JSON`); }
  const canonical = canonicalJson(value);
  const expected = Buffer.from(requireTrailingNewline ? `${canonical}\n` : canonical);
  if (!raw.equals(expected)) fail(400, `${kind}_CANONICAL`, `${kind} JSON must use the exact canonical encoding`);
  return value;
}

function parseGoArtifactManifest(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 3 || raw.length > PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES) fail(413, "MANIFEST_SIZE", "Artifact manifest JSON size rejected");
  if (raw.at(-1) !== 0x0a || raw.at(-2) === 0x0a || raw.includes(0x0d)) fail(400, "MANIFEST_CANONICAL", "Artifact manifest must have exactly one trailing LF");
  let encoded;
  try { encoded = new TextDecoder("utf-8", { fatal: true }).decode(raw); } catch { fail(400, "MANIFEST_JSON", "Artifact manifest must be bounded UTF-8 JSON"); }
  let value;
  try { value = JSON.parse(encoded); } catch { fail(400, "MANIFEST_JSON", "Artifact manifest must contain exactly one JSON value"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(400, "MANIFEST_JSON", "Artifact manifest must be a JSON object");
  return value;
}

function sha256Bytes(value) {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function assertMetadata(value, nowSeconds) {
  scanForbiddenMembers(value);
  if (!exactKeys(value, METADATA_MEMBERS)) fail(400, "METADATA_SHAPE", "Import metadata members are not exact");
  if (value.schemaVersion !== PARTICIPANT_ORIGINATED_IMPORT_SCHEMA) fail(400, "METADATA_SCHEMA", "Import metadata schema rejected");
  if (!UUID.test(value.runId)) fail(400, "RUN_ID", "Run identifier rejected");
  if (!BYTES32.test(value.fheCaseId) || !["PARTICIPANT_A", "PARTICIPANT_B"].includes(value.role)) fail(400, "CASE_ROLE", "Case or role rejected");
  if (!ADDRESS.test(value.participantWallet) || !Number.isSafeInteger(value.chainId) || value.chainId <= 0) fail(400, "WALLET", "Wallet authorization identity rejected");
  for (const field of ["participantSigningKeyDigest", "registrationDigest", "encryptionIntentDigest", "finalAdmissionDigest", "claimCommitment", "clientBundleDigest", "encryptedArtifactDigest", "artifactObjectDigest", "ciphertextObjectDigest", "registrationNonce", "intentNonce", "submissionNonce"]) {
    if (!BYTES32.test(value[field])) fail(400, "DIGEST", `${field} rejected`);
  }
  if (!Number.isSafeInteger(value.ciphertextObjectLength) || value.ciphertextObjectLength <= 0 || value.ciphertextObjectLength > PARTICIPANT_ORIGINATED_MAX_CIPHERTEXT_BYTES) fail(400, "CIPHERTEXT_LENGTH", "Ciphertext object length rejected");
  if (!Number.isSafeInteger(value.artifactObjectLength) || value.artifactObjectLength <= 0 || value.artifactObjectLength > PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES) fail(400, "MANIFEST_LENGTH", "Artifact object length rejected");
  if (!Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) || value.issuedAt <= 0 || value.expiresAt <= value.issuedAt) fail(400, "EXPIRY", "Authorization timing rejected");
  if (value.expiresAt <= nowSeconds) fail(410, "EXPIRED", "Encrypted admission has expired");
  if (value.issuedAt > nowSeconds + PARTICIPANT_ORIGINATED_CLOCK_SKEW_SECONDS || value.expiresAt - value.issuedAt > PARTICIPANT_ORIGINATED_MAX_AUTH_LIFETIME_SECONDS) fail(400, "EXPIRY", "Authorization timing rejected");
  if (!exactKeys(value.walletAuthorizationChain, AUTHORIZATION_MEMBERS)) fail(400, "AUTHORIZATION_SHAPE", "Wallet authorization chain members are not exact");
  for (const member of AUTHORIZATION_MEMBERS) {
    const signed = value.walletAuthorizationChain[member];
    if (!exactKeys(signed, SIGNED_AUTHORIZATION_MEMBERS) || typeof signed.schemaVersion !== "string" || signed.schemaVersion.length === 0 || signed.schemaVersion.length > 128 || signed.message === null || typeof signed.message !== "object" || Array.isArray(signed.message) || !SIGNATURE.test(signed.signature)) fail(400, "AUTHORIZATION", `${member} signed message rejected`);
  }
  return Object.freeze(value);
}

// Reservation keys are derived from the compact top-level metadata. Enforce
// that every such fact which is present in the signed Phase 0/1/2 messages is
// an exact projection before invoking even a correctly-signature-checking but
// otherwise naive authentication adapter.
function assertSignedMetadataProjection(metadata) {
  const registration = metadata.walletAuthorizationChain.registration.message;
  const intent = metadata.walletAuthorizationChain.encryptionIntent.message;
  const admission = metadata.walletAuthorizationChain.finalAdmission.message;
  const comparisons = [
    [metadata.runId, registration.runId], [metadata.runId, intent.runId], [metadata.runId, admission.runId],
    [metadata.fheCaseId, registration.fheCaseId], [metadata.fheCaseId, intent.fheCaseId], [metadata.fheCaseId, admission.fheCaseId],
    [metadata.role, registration.role], [metadata.role, intent.role], [metadata.role, admission.role],
    [metadata.participantWallet, registration.participantWallet], [metadata.participantWallet, intent.participantWallet], [metadata.participantWallet, admission.participantWallet],
    [metadata.participantSigningKeyDigest, registration.participantSigningKeyDigest],
    [metadata.participantSigningKeyDigest, intent.participantSigningKeyDigest],
    [metadata.participantSigningKeyDigest, admission.participantSigningKeyDigest],
    [metadata.registrationDigest, intent.registrationDigest], [metadata.registrationDigest, admission.registrationDigest],
    [metadata.encryptionIntentDigest, admission.encryptionIntentDigest],
    [metadata.claimCommitment, intent.claimCommitment], [metadata.claimCommitment, admission.claimCommitment],
    [metadata.clientBundleDigest, intent.clientBundleDigest], [metadata.clientBundleDigest, admission.clientBundleDigest],
    [metadata.encryptedArtifactDigest, admission.encryptedArtifactDigest],
    [metadata.ciphertextObjectDigest, admission.ciphertextObjectDigest],
    [metadata.ciphertextObjectLength, admission.ciphertextObjectLength],
    [metadata.registrationNonce, registration.registrationNonce],
    [metadata.intentNonce, intent.intentNonce],
    [metadata.submissionNonce, admission.submissionNonce],
    [metadata.issuedAt, admission.issuedAt], [metadata.expiresAt, admission.expiresAt],
  ];
  if (comparisons.some(([actual, expected]) => actual !== expected)) {
    fail(400, "AUTHORIZATION_PROJECTION", "Import metadata is not the exact signed authorization projection");
  }
  return metadata;
}

function ensureDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(500, "STORAGE_SYMLINK", "Coordinator storage directory rejected");
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  closeSync(descriptor);
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function writeCreateOnly(path, value) {
  const parent = dirname(path);
  const temporary = join(parent, `.mordant-state-${randomBytes(16).toString("hex")}`);
  let descriptor;
  let linked = false;
  try {
    descriptor = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    const bytes = Buffer.from(canonicalJson(value));
    writeAll(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporary, path);
    linked = true;
    unlinkSync(temporary);
    fsyncDirectory(parent);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) {
      try { unlinkSync(temporary); fsyncDirectory(parent); } catch { /* retain a visible conservative failure */ }
    }
  }
  if (!linked) fail(500, "STORAGE_WRITE", "Create-only coordinator state was not committed");
}

function readExactJsonFile(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(500, "STORAGE_OBJECT", "Coordinator storage object rejected");
  return parseCanonicalJson(readFileSync(path), PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES, "STATE");
}

function directoryIdentity(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(500, "STORAGE_SYMLINK", "Quarantine directory rejected");
  return `${stat.dev}:${stat.ino}`;
}

function writeAll(descriptor, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const written = writeSync(descriptor, buffer, offset, buffer.length - offset);
    if (!Number.isSafeInteger(written) || written <= 0) {
      const error = new Error("short durable-state write");
      error.code = "EIO";
      throw error;
    }
    offset += written;
  }
}

function validatedStreamTimeouts(options) {
  const idleMs = options.streamIdleTimeoutMs ?? PARTICIPANT_ORIGINATED_STREAM_IDLE_TIMEOUT_MS;
  const absoluteMs = options.streamAbsoluteTimeoutMs ?? PARTICIPANT_ORIGINATED_STREAM_ABSOLUTE_TIMEOUT_MS;
  if (!Number.isSafeInteger(idleMs) || idleMs <= 0 || !Number.isSafeInteger(absoluteMs) || absoluteMs <= 0 || idleMs > absoluteMs) {
    fail(500, "CONFIG", "Coordinator stream timeouts are invalid");
  }
  return Object.freeze({ idleMs, absoluteMs });
}

function timedReadable(readable, kind, timeouts) {
  if (readable === null || typeof readable !== "object" || typeof readable[Symbol.asyncIterator] !== "function") {
    fail(400, `${kind}_STREAM`, `${kind} upload stream rejected`);
  }
  let idleTimer;
  let absoluteTimer;
  let finished = false;
  let output;
  const clearTimers = () => {
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    if (absoluteTimer !== undefined) clearTimeout(absoluteTimer);
    idleTimer = undefined;
    absoluteTimer = undefined;
  };
  const abort = (scope) => {
    if (finished) return;
    finished = true;
    clearTimers();
    const error = new ParticipantOriginatedCoordinatorError(408, `${kind}_STREAM_TIMEOUT`, `${kind} upload exceeded its ${scope} timeout`);
    output.destroy(error);
    if (typeof readable.destroy === "function") readable.destroy(error);
  };
  const resetIdle = () => {
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => abort("idle"), timeouts.idleMs);
  };
  const source = async function* () {
    for await (const value of readable) {
      resetIdle();
      yield value;
    }
  };
  output = Readable.from(source());
  resetIdle();
  absoluteTimer = setTimeout(() => abort("absolute"), timeouts.absoluteMs);
  const finish = () => {
    if (finished) return;
    finished = true;
    clearTimers();
  };
  output.once("end", finish);
  output.once("close", finish);
  return output;
}

async function stageExactStream(readable, target, expectedLength, maximumLength, expectedDigest, kind) {
  if (!Number.isSafeInteger(expectedLength) || expectedLength <= 0 || expectedLength > maximumLength) {
    fail(400, `${kind}_LENGTH`, `${kind} declared length rejected`);
  }
  const parent = dirname(target);
  const identity = directoryIdentity(parent);
  let descriptor;
  let created = false;
  let length = 0;
  const hash = createHash("sha256");
  try {
    try {
      descriptor = openSync(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
      created = true;
    } catch (error) {
      if (error?.code === "EEXIST" || error?.code === "ELOOP") fail(409, `${kind}_REPLAY`, `${kind} object already exists`);
      throw error;
    }
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1) fail(500, "STORAGE_OBJECT", "Quarantine object rejected");
    try {
      for await (const value of readable) {
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        length += chunk.length;
        if (length > expectedLength || length > maximumLength) fail(413, `${kind}_LENGTH`, `${kind} stream exceeded its declared length`);
        hash.update(chunk);
        writeAll(descriptor, chunk);
      }
    } catch (error) {
      if (error instanceof ParticipantOriginatedCoordinatorError) throw error;
      fail(400, `${kind}_TRUNCATED`, `${kind} stream was malformed or truncated`);
    }
    if (length !== expectedLength) fail(400, `${kind}_TRUNCATED`, `${kind} stream length did not match Content-Length`);
    const digest = `0x${hash.digest("hex")}`;
    if (digest !== expectedDigest) fail(422, `${kind}_DIGEST`, `${kind} SHA-256 digest rejected`);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    if (directoryIdentity(parent) !== identity) fail(500, "STORAGE_RACE", "Quarantine directory changed during upload");
    fsyncDirectory(parent);
    return Object.freeze({ path: target, filename: basename(target), length, digest });
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (created) {
      try { unlinkSync(target); fsyncDirectory(parent); } catch { /* retain a visible conservative failure */ }
    }
    throw error;
  }
}

function hashExactRegularFile(path, expectedLength, expectedDigest, kind) {
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.isSymbolicLink?.() || stat.size !== expectedLength) fail(422, `${kind}_LENGTH`, `${kind} staged length rejected`);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    for (;;) {
      const count = readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      total += count;
      hash.update(buffer.subarray(0, count));
    }
    const digest = `0x${hash.digest("hex")}`;
    if (total !== expectedLength || digest !== expectedDigest) fail(422, `${kind}_DIGEST`, `${kind} staged digest rejected`);
    return Object.freeze({ path, filename: basename(path), length: total, digest });
  } catch (error) {
    if (error?.code === "ELOOP") fail(500, "STORAGE_SYMLINK", "Staged symlink rejected");
    throw error;
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function boundedCallbackDigest(value, kind) {
  if (value === undefined || value === null || value === false) fail(422, `${kind}_RESULT`, `${kind} callback returned no durable reference`);
  scanForbiddenMembers(value);
  const encoded = canonicalJson(value);
  if (Buffer.byteLength(encoded) > PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES) fail(422, `${kind}_RESULT`, `${kind} callback reference is too large`);
  return sha256Bytes(Buffer.from(encoded));
}

async function stageWithTrustedCallback(callback, context, expected, kind) {
  let result;
  try { result = await callback(Object.freeze({ ...context, expected: Object.freeze(expected) })); } catch (error) {
    if (error instanceof ParticipantOriginatedCoordinatorError) throw error;
    fail(422, `${kind}_STAGE`, `Pinned external ${kind.toLowerCase()} staging rejected the stream`);
  }
  if (result === null || typeof result !== "object" || Array.isArray(result) || result.path !== expected.filename || result.digest !== expected.digest || result.length !== expected.length) fail(422, `${kind}_STAGE_REFERENCE`, `Pinned external ${kind.toLowerCase()} staging returned another object`);
  return Object.freeze({ path: join(context.quarantineRoot, expected.filename), filename: expected.filename, digest: expected.digest, length: expected.length });
}

function ticketReference(ticket) { return createHash("sha256").update(`MordantImportTicket/v1\0${ticket}`).digest("hex"); }
function caseReference(metadata) { return createHash("sha256").update(`${metadata.runId}\0${metadata.fheCaseId}`).digest("hex"); }
function nonceReference(metadata, phase, nonce) { return createHash("sha256").update(`${phase}\0${metadata.participantWallet.toLowerCase()}\0${nonce}`).digest("hex"); }

function coordinatorPaths(root, publicationRoot) {
  return Object.freeze({
    root,
    quarantine: join(root, "quarantine"), reservations: join(root, "reservations"), roles: join(root, "roles"),
    nonces: join(root, "nonces"), transactions: join(root, "reservation-transactions"),
    stages: join(root, "stages"), failures: join(root, "failures"),
    journal: join(root, "import-journal.ndjson"), publication: publicationRoot,
  });
}

function reservationTransactionPaths(paths, ticketRef) {
  return Object.freeze({
    intent: join(paths.transactions, `${ticketRef}.intent.json`),
    commit: join(paths.transactions, `${ticketRef}.commit.json`),
  });
}

function validateRecoveredReservationRecord(record) {
  if (!exactKeys(record, ["schemaVersion", "ticketRef", "metadata", "createdAt"]) ||
      record.schemaVersion !== PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA ||
      !/^[0-9a-f]{64}$/u.test(record.ticketRef) || !Number.isSafeInteger(record.createdAt) || record.createdAt <= 0 ||
      record.metadata === null || typeof record.metadata !== "object" || Array.isArray(record.metadata)) {
    fail(500, "RESERVATION_INTEGRITY", "Reservation transaction record rejected");
  }
  // Reuse every shape/lifetime invariant without requiring the authorization to
  // remain live at restart time.
  assertMetadata(record.metadata, record.metadata.issuedAt);
  return record;
}

function reservationPlan(paths, record) {
  validateRecoveredReservationRecord(record);
  const metadata = record.metadata;
  const role = Object.freeze({
    path: join(paths.roles, `${caseReference(metadata)}-${metadata.role}.json`),
    value: Object.freeze({ ticketRef: record.ticketRef, runId: metadata.runId, fheCaseId: metadata.fheCaseId, role: metadata.role }),
    conflictCode: "ROLE_OCCUPIED",
  });
  const nonces = [
    ["registration", metadata.registrationNonce], ["intent", metadata.intentNonce], ["submission", metadata.submissionNonce],
  ].map(([phase, nonce]) => Object.freeze({
    path: join(paths.nonces, `${nonceReference(metadata, phase, nonce)}.json`),
    value: Object.freeze({ ticketRef: record.ticketRef, phase }),
    conflictCode: "NONCE_REPLAY",
  }));
  return Object.freeze({
    reservation: Object.freeze({
      path: join(paths.reservations, `${record.ticketRef}.json`), value: record, conflictCode: "TICKET_REPLAY",
    }),
    role,
    nonces: Object.freeze(nonces),
    quarantine: join(paths.quarantine, record.ticketRef),
  });
}

function exactStateEquals(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function createOrVerifyReservationClaim(claim, recovering = false) {
  try {
    writeCreateOnly(claim.path, claim.value);
    return true;
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    let existing;
    try { existing = readExactJsonFile(claim.path); } catch {
      fail(500, "RESERVATION_INTEGRITY", "Reservation claim is not readable canonical state");
    }
    if (!exactStateEquals(existing, claim.value)) {
      if (recovering) fail(500, "RESERVATION_INTEGRITY", "Committed reservation claim was replaced");
      fail(409, claim.conflictCode, claim.conflictCode === "ROLE_OCCUPIED" ? "Participant role is already reserved" : claim.conflictCode === "NONCE_REPLAY" ? "Participant authorization nonce replay rejected" : "Upload ticket replay rejected");
    }
    return false;
  }
}

function removeExactReservationClaim(claim) {
  if (!existsSync(claim.path)) return;
  const existing = readExactJsonFile(claim.path);
  if (!exactStateEquals(existing, claim.value)) return;
  unlinkSync(claim.path);
  fsyncDirectory(dirname(claim.path));
}

function rollbackReservationTransaction(paths, transaction, plan) {
  const transactionPaths = reservationTransactionPaths(paths, transaction.ticketRef);
  if (existsSync(transactionPaths.commit)) fail(500, "RESERVATION_INTEGRITY", "Committed reservation cannot be rolled back");
  for (const claim of [...plan.nonces].reverse()) removeExactReservationClaim(claim);
  removeExactReservationClaim(plan.role);
  removeExactReservationClaim(plan.reservation);
  if (existsSync(plan.quarantine) && readdirSync(plan.quarantine).length === 0) {
    rmdirSync(plan.quarantine);
    fsyncDirectory(paths.quarantine);
  }
  removeExactReservationClaim({ path: transactionPaths.intent, value: transaction });
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

function recoverReservationTransactions(paths) {
  const recovered = [];
  for (const entry of readdirSync(paths.transactions, { withFileTypes: true })) {
    if (!entry.isFile() || !/^[0-9a-f]{64}\.intent\.json$/u.test(entry.name)) continue;
    const transaction = readExactJsonFile(join(paths.transactions, entry.name));
    if (!exactKeys(transaction, ["schemaVersion", "ticketRef", "ownerPid", "record"]) ||
        transaction.schemaVersion !== PARTICIPANT_ORIGINATED_RESERVATION_TRANSACTION_SCHEMA ||
        !/^[0-9a-f]{64}$/u.test(transaction.ticketRef) || !Number.isSafeInteger(transaction.ownerPid) || transaction.ownerPid <= 0) {
      fail(500, "RESERVATION_INTEGRITY", "Reservation transaction intent rejected");
    }
    const record = validateRecoveredReservationRecord(transaction.record);
    if (record.ticketRef !== transaction.ticketRef) fail(500, "RESERVATION_INTEGRITY", "Reservation transaction owner mismatch");
    const transactionPaths = reservationTransactionPaths(paths, transaction.ticketRef);
    const plan = reservationPlan(paths, record);
    if (!existsSync(transactionPaths.commit)) {
      if (ACTIVE_RESERVATION_TRANSACTIONS.has(transaction.ticketRef)) continue;
      if (transaction.ownerPid !== process.pid && processIsAlive(transaction.ownerPid)) continue;
      rollbackReservationTransaction(paths, transaction, plan);
      recovered.push(Object.freeze({ ticketRef: transaction.ticketRef, state: "ROLLED_BACK" }));
      continue;
    }
    const commit = readExactJsonFile(transactionPaths.commit);
    const expectedCommit = {
      schemaVersion: PARTICIPANT_ORIGINATED_RESERVATION_COMMIT_SCHEMA,
      ticketRef: transaction.ticketRef,
      metadataDigest: sha256Bytes(Buffer.from(canonicalJson(record.metadata))),
    };
    if (!exactStateEquals(commit, expectedCommit)) fail(500, "RESERVATION_INTEGRITY", "Reservation commit marker rejected");
    ensureDirectory(plan.quarantine);
    createOrVerifyReservationClaim(plan.reservation, true);
    createOrVerifyReservationClaim(plan.role, true);
    for (const claim of plan.nonces) createOrVerifyReservationClaim(claim, true);
    recovered.push(Object.freeze({ ticketRef: transaction.ticketRef, state: "COMMITTED" }));
  }
  return Object.freeze(recovered);
}

function appendJournal(paths, event) {
  const record = { schemaVersion: PARTICIPANT_ORIGINATED_JOURNAL_SCHEMA, ...event };
  const bytes = Buffer.from(`${canonicalJson(record)}\n`);
  let descriptor;
  try {
    descriptor = openSync(paths.journal, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW, 0o600);
    writeAll(descriptor, bytes);
    fsyncSync(descriptor);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
  fsyncDirectory(paths.root);
}

function restoreJournal(paths) {
  if (!existsSync(paths.journal)) return [];
  const stat = lstatSync(paths.journal);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(500, "JOURNAL_INTEGRITY", "Import journal rejected");
  const raw = readFileSync(paths.journal, "utf8");
  if (raw !== "" && !raw.endsWith("\n")) fail(500, "JOURNAL_INTEGRITY", "Truncated import journal rejected");
  return raw === "" ? [] : raw.slice(0, -1).split("\n").map((line) => {
    const parsed = parseCanonicalJson(Buffer.from(line), PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES, "JOURNAL");
    if (parsed.schemaVersion !== PARTICIPANT_ORIGINATED_JOURNAL_SCHEMA) fail(500, "JOURNAL_INTEGRITY", "Import journal schema rejected");
    return parsed;
  });
}

async function authenticate(callback, context) {
  let result;
  try { result = await callback(context); } catch (error) {
    if (error instanceof ParticipantOriginatedCoordinatorError) throw error;
    fail(401, "AUTHENTICATION", "Participant authentication rejected");
  }
  if (result === false || result === null || result === undefined) fail(401, "AUTHENTICATION", "Participant authentication rejected");
  return result;
}

function publicStatus(record, paths) {
  const names = participantFilenames(record.metadata.role);
  const quarantine = join(paths.quarantine, record.ticketRef);
  const failurePath = join(paths.failures, `${record.ticketRef}.json`);
  const failure = readFailureMarker(record, failurePath);
  const manifestPublished = existsSync(join(paths.stages, `${record.ticketRef}.published.json`));
  const manifestStaged = existsSync(join(quarantine, names.artifactManifest));
  const ciphertextStaged = existsSync(join(quarantine, names.ciphertext));
  return Object.freeze({
    schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA,
    ticketRef: record.ticketRef,
    runId: record.metadata.runId,
    fheCaseId: record.metadata.fheCaseId,
    role: record.metadata.role,
    // An exact published marker is the terminal success state.  A retained
    // RECONCILIATION_REQUIRED marker remains useful audit history, but must not
    // mask a later exact reconciliation.
    state: manifestPublished ? "PUBLISHED" : failure?.state ?? (manifestStaged ? "VERIFYING" : ciphertextStaged ? "CIPHERTEXT_STAGED" : "RESERVED"),
    filenames: names,
    digests: Object.freeze({
      encryptedArtifactDigest: record.metadata.encryptedArtifactDigest,
      artifactObjectDigest: record.metadata.artifactObjectDigest,
      ciphertextObjectDigest: record.metadata.ciphertextObjectDigest,
    }),
    expiresAt: record.metadata.expiresAt,
  });
}

function readFailureMarker(record, path) {
  if (!existsSync(path)) return null;
  const failure = readExactJsonFile(path);
  if (!exactKeys(failure, ["schemaVersion", "ticketRef", "state", "code", "at"]) ||
      failure.schemaVersion !== PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA || failure.ticketRef !== record.ticketRef ||
      !["FAILED", "RECONCILIATION_REQUIRED"].includes(failure.state) || !/^[A-Z][A-Z0-9_]{0,63}$/u.test(failure.code) ||
      !Number.isSafeInteger(failure.at) || failure.at <= 0) {
    fail(500, "STATE_INTEGRITY", "Import failure marker rejected");
  }
  return failure;
}

/**
 * Creates the durable transport. `authenticate` must verify the wallet chain;
 * `verifyArtifact` must invoke the existing Go verifier against the staged
 * paths. Neither callback is permitted to return participant plaintext. HTTP
 * credentials are available only to `authenticate` through the ephemeral
 * request object; its return value and the request are never persisted.
 */
export async function createParticipantOriginatedCoordinator(options) {
  if (options === null || typeof options !== "object") fail(500, "CONFIG", "Coordinator options are required");
  if (typeof options.root !== "string" || options.root === "" || typeof options.authenticate !== "function" || typeof options.verifyArtifact !== "function" || typeof options.publishArtifact !== "function") fail(500, "CONFIG", "Coordinator root and security callbacks are required");
  if (typeof options.stageObject !== "function" && options.allowUnsafeTestStaging !== true) fail(500, "CONFIG", "Pinned external stageObject is required outside explicit test-only staging");
  const now = options.now ?? (() => Date.now());
  const newTicket = options.newTicket ?? (() => randomBytes(32).toString("base64url"));
  const streamTimeouts = validatedStreamTimeouts(options);
  const paths = coordinatorPaths(options.root, options.publicationRoot ?? join(options.root, "published"));
  for (const directory of [paths.root, paths.quarantine, paths.reservations, paths.roles, paths.nonces, paths.transactions, paths.stages, paths.failures, paths.publication]) ensureDirectory(directory);
  const recoveredJournal = restoreJournal(paths);
  const recoveredReservations = recoverReservationTransactions(paths);
  let gate = Promise.resolve();
  const locked = (operation) => {
    const result = gate.then(operation, operation);
    gate = result.catch(() => undefined);
    return result;
  };
  const ticketGates = new Map();
  const lockedTicket = (ticketRef, operation) => {
    const previous = ticketGates.get(ticketRef) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const tail = result.catch(() => undefined);
    ticketGates.set(ticketRef, tail);
    tail.then(() => {
      if (ticketGates.get(ticketRef) === tail) ticketGates.delete(ticketRef);
    });
    return result;
  };

  function reservation(ticket) {
    if (typeof ticket !== "string" || !TICKET.test(ticket)) fail(401, "TICKET", "Upload ticket rejected");
    const ref = ticketReference(ticket);
    const path = join(paths.reservations, `${ref}.json`);
    if (!existsSync(path)) fail(404, "TICKET", "Upload ticket not found");
    const record = readExactJsonFile(path);
    if (record.ticketRef !== ref) fail(500, "STATE_INTEGRITY", "Upload reservation integrity failure");
    const transactionPaths = reservationTransactionPaths(paths, ref);
    if (!existsSync(transactionPaths.commit)) fail(409, "RESERVATION_PENDING", "Upload reservation is not durably committed");
    const commit = readExactJsonFile(transactionPaths.commit);
    const expectedCommit = {
      schemaVersion: PARTICIPANT_ORIGINATED_RESERVATION_COMMIT_SCHEMA,
      ticketRef: ref,
      metadataDigest: sha256Bytes(Buffer.from(canonicalJson(record.metadata))),
    };
    if (!exactStateEquals(commit, expectedCommit)) fail(500, "STATE_INTEGRITY", "Upload reservation commit integrity failure");
    return record;
  }

  async function beginImport(metadata, request) {
    const checked = assertMetadata(metadata, Math.floor(now() / 1000));
    assertSignedMetadataProjection(checked);
    await authenticate(options.authenticate, { operation: "BEGIN_IMPORT", request, metadata: checked, ticketRef: null });
    const ticket = newTicket();
    if (typeof ticket !== "string" || !TICKET.test(ticket)) fail(500, "TICKET_GENERATOR", "Ticket generator returned an invalid ticket");
    return locked(async () => {
      // A second coordinator can safely clean a dead owner's uncommitted WAL
      // before attempting new create-only claims. Live owners are left intact.
      recoverReservationTransactions(paths);
      const ticketRef = ticketReference(ticket);
      const record = { schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA, ticketRef, metadata: checked, createdAt: Math.floor(now() / 1000) };
      const plan = reservationPlan(paths, record);
      const transaction = {
        schemaVersion: PARTICIPANT_ORIGINATED_RESERVATION_TRANSACTION_SCHEMA,
        ticketRef,
        ownerPid: process.pid,
        record,
      };
      const transactionPaths = reservationTransactionPaths(paths, ticketRef);
      let committed = false;
      let intentCreated = false;
      const step = async (name) => {
        if (typeof options.unsafeTestHooks?.afterReservationStep === "function") {
          await options.unsafeTestHooks.afterReservationStep(name, Object.freeze({ ticketRef, transaction, plan }));
        }
      };
      try {
        try {
          writeCreateOnly(transactionPaths.intent, transaction);
          intentCreated = true;
          ACTIVE_RESERVATION_TRANSACTIONS.add(ticketRef);
        } catch (error) {
          if (error?.code === "EEXIST") fail(409, "TICKET_REPLAY", "Upload ticket replay rejected");
          throw error;
        }
        await step("INTENT");
        ensureDirectory(plan.quarantine);
        await step("QUARANTINE");
        createOrVerifyReservationClaim(plan.reservation);
        await step("RESERVATION");
        createOrVerifyReservationClaim(plan.role);
        await step("ROLE");
        for (const claim of plan.nonces) {
          createOrVerifyReservationClaim(claim);
          await step(`NONCE_${claim.value.phase.toUpperCase()}`);
        }
        writeCreateOnly(transactionPaths.commit, {
          schemaVersion: PARTICIPANT_ORIGINATED_RESERVATION_COMMIT_SCHEMA,
          ticketRef,
          metadataDigest: sha256Bytes(Buffer.from(canonicalJson(checked))),
        });
        committed = true;
        if (intentCreated) ACTIVE_RESERVATION_TRANSACTIONS.delete(ticketRef);
        await step("COMMIT");
        appendJournal(paths, { event: "IMPORT_RESERVED", at: Math.floor(now() / 1000), ticketRef, runId: checked.runId, fheCaseId: checked.fheCaseId, role: checked.role, metadataDigest: sha256Bytes(Buffer.from(canonicalJson(checked))) });
      } catch (error) {
        const simulatedCrash = error?.code === "TEST_SIMULATED_CRASH" && typeof options.unsafeTestHooks?.afterReservationStep === "function";
        if (intentCreated) ACTIVE_RESERVATION_TRANSACTIONS.delete(ticketRef);
        if (intentCreated && !committed && !simulatedCrash) rollbackReservationTransaction(paths, transaction, plan);
        throw error;
      }
      return { ...publicStatus(record, paths), ticket };
    });
  }

  async function status(ticket, request) {
    const record = reservation(ticket);
    await authenticate(options.authenticate, { operation: "STATUS", request, metadata: record.metadata, ticketRef: record.ticketRef });
    if (record.metadata.expiresAt <= Math.floor(now() / 1000)) fail(410, "EXPIRED", "Encrypted admission has expired");
    return publicStatus(record, paths);
  }

  function assertUploadAvailable(record) {
    if (record.metadata.expiresAt <= Math.floor(now() / 1000)) fail(410, "EXPIRED", "Encrypted admission has expired");
    if (existsSync(join(paths.stages, `${record.ticketRef}.published.json`))) fail(409, "TICKET_REPLAY", "Import ticket has already been published");
    if (existsSync(join(paths.failures, `${record.ticketRef}.json`))) fail(409, "IMPORT_TERMINAL", "Import ticket is in a terminal failure state");
  }

  function recordTerminalFailure(record, state, error) {
    const marker = join(paths.failures, `${record.ticketRef}.json`);
    if (!existsSync(marker)) {
      writeCreateOnly(marker, {
        schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA,
        ticketRef: record.ticketRef,
        state,
        code: error instanceof ParticipantOriginatedCoordinatorError ? error.code : "CALLBACK_FAILURE",
        at: Math.floor(now() / 1000),
      });
      appendJournal(paths, {
        event: state,
        at: Math.floor(now() / 1000),
        ticketRef: record.ticketRef,
        code: error instanceof ParticipantOriginatedCoordinatorError ? error.code : "CALLBACK_FAILURE",
      });
    }
  }

  function assertUploadDescription(description, contentType, expectedLength, maximumLength, kind) {
    if (description === null || typeof description !== "object") fail(400, `${kind}_HEADERS`, `${kind} upload headers rejected`);
    if (description.contentType !== contentType) fail(415, `${kind}_CONTENT_TYPE`, `${kind} Content-Type rejected`);
    if (!Number.isSafeInteger(description.contentLength) || description.contentLength !== expectedLength || description.contentLength > maximumLength) fail(400, `${kind}_LENGTH`, `${kind} Content-Length rejected`);
    if (description.transferEncoding !== undefined || description.contentDisposition !== undefined || description.filename !== undefined) fail(400, `${kind}_HEADERS`, `${kind} filename, archive, or transfer encoding rejected`);
  }

  async function uploadCiphertext(ticket, readable, description = {}) {
    let record = reservation(ticket);
    assertUploadAvailable(record);
    await authenticate(options.authenticate, { operation: "UPLOAD_CIPHERTEXT", request: description.request, metadata: record.metadata, ticketRef: record.ticketRef });
    return lockedTicket(record.ticketRef, async () => {
      record = reservation(ticket);
      assertUploadAvailable(record);
      try {
        assertUploadDescription(
          description,
          PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE,
          record.metadata.ciphertextObjectLength,
          PARTICIPANT_ORIGINATED_MAX_CIPHERTEXT_BYTES,
          "CIPHERTEXT",
        );
        const names = participantFilenames(record.metadata.role);
        const quarantineRoot = join(paths.quarantine, record.ticketRef);
        const expected = { filename: names.ciphertext, digest: record.metadata.ciphertextObjectDigest, length: description.contentLength };
        const boundedReadable = timedReadable(readable, "CIPHERTEXT", streamTimeouts);
        let reference;
        try {
          reference = typeof options.stageObject === "function"
            ? await stageWithTrustedCallback(options.stageObject, {
              kind: "ciphertext", readable: boundedReadable, metadata: record.metadata, ticketRef: record.ticketRef,
              quarantineRoot, filenames: names,
            }, expected, "CIPHERTEXT")
            : await stageExactStream(
              boundedReadable,
              join(quarantineRoot, names.ciphertext),
              description.contentLength,
              PARTICIPANT_ORIGINATED_MAX_CIPHERTEXT_BYTES,
              record.metadata.ciphertextObjectDigest,
              "CIPHERTEXT",
            );
        } finally {
          if (!boundedReadable.destroyed) boundedReadable.destroy();
        }
        writeCreateOnly(join(paths.stages, `${record.ticketRef}.ciphertext.json`), {
          schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA,
          ticketRef: record.ticketRef,
          filename: names.ciphertext,
          digest: reference.digest,
          length: reference.length,
        });
        appendJournal(paths, { event: "CIPHERTEXT_STAGED", at: Math.floor(now() / 1000), ticketRef: record.ticketRef, filename: names.ciphertext, digest: reference.digest, length: reference.length });
        return publicStatus(record, paths);
      } catch (error) {
        if (!(error instanceof ParticipantOriginatedCoordinatorError && ["CIPHERTEXT_REPLAY", "TICKET_REPLAY", "IMPORT_TERMINAL"].includes(error.code))) recordTerminalFailure(record, "FAILED", error);
        throw error;
      }
    });
  }

  async function finalizeStagedImport(record, recovered = false, publicationUncertain = false) {
    const names = participantFilenames(record.metadata.role);
    const quarantine = join(paths.quarantine, record.ticketRef);
    const ciphertext = hashExactRegularFile(
      join(quarantine, names.ciphertext),
      record.metadata.ciphertextObjectLength,
      record.metadata.ciphertextObjectDigest,
      "CIPHERTEXT",
    );
    const manifestPath = join(quarantine, names.artifactManifest);
    const manifestStat = lstatSync(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size <= 0 || manifestStat.size > PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES) fail(422, "MANIFEST_OBJECT", "Artifact manifest object rejected");
    const manifestRaw = readFileSync(manifestPath);
    if (manifestRaw.length !== record.metadata.artifactObjectLength || sha256Bytes(manifestRaw) !== record.metadata.artifactObjectDigest) fail(422, "MANIFEST_DIGEST", "Artifact manifest object digest rejected");
    // Go's canonical artifact order is its retained struct declaration order,
    // not lexicographic JS object order. The transport enforces framing and
    // exact bytes; the mandatory Go verifier below enforces marshalCanonical.
    const manifest = parseGoArtifactManifest(manifestRaw);
    scanForbiddenMembers(manifest);
    const manifestReference = Object.freeze({ path: manifestPath, filename: names.artifactManifest, length: manifestRaw.length, digest: record.metadata.artifactObjectDigest });
    // Recovery first asks the trusted publication adapter for an exact durable
    // readback.  The Go reconciliation path revalidates the staged artifact at
    // its durable admission instant, so an already-complete publication can be
    // recovered after authorization expiry without a current-time verify.  If
    // a prior callback made publication uncertain and no exact completion is
    // found, publication is never replayed.
    if (recovered && typeof options.reconcilePublication === "function") {
      let reconciled;
      try {
        reconciled = await options.reconcilePublication(Object.freeze({
          operation: "RECOVER_READ_PUBLICATION",
          metadata: record.metadata,
          ticketRef: record.ticketRef,
          filenames: names,
          quarantineRoot: quarantine,
          staged: Object.freeze({ ciphertext, artifactManifest: manifestReference }),
          manifest,
          publicationContract: Object.freeze({ createOnly: true, ciphertextFirst: true, artifactManifestLast: true }),
        }));
      } catch {
        fail(503, "PUBLISH_RECONCILIATION", "Published artifact readback was rejected during recovery");
      }
      if (reconciled !== null && reconciled !== undefined && reconciled !== false) {
        const reconciliationReferenceDigest = boundedCallbackDigest(reconciled, "PUBLICATION_RECONCILIATION");
        writeCreateOnly(join(paths.stages, `${record.ticketRef}.published.json`), {
          schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA,
          ticketRef: record.ticketRef,
          artifactManifest: names.artifactManifest,
          ciphertext: names.ciphertext,
          verificationReferenceDigest: reconciliationReferenceDigest,
          publicationReferenceDigest: reconciliationReferenceDigest,
          publishedAt: Math.floor(now() / 1000),
        });
        appendJournal(paths, {
          event: "IMPORT_RECOVERED_FROM_PUBLICATION",
          at: Math.floor(now() / 1000),
          ticketRef: record.ticketRef,
          ciphertext: names.ciphertext,
          artifactManifest: names.artifactManifest,
          verificationReferenceDigest: reconciliationReferenceDigest,
          publicationReferenceDigest: reconciliationReferenceDigest,
        });
        return publicStatus(record, paths);
      }
    }
    if (publicationUncertain) {
      fail(503, "PUBLISH_RECONCILIATION", "Uncertain publication has no exact durable completion");
    }
    let verification;
    try {
      verification = await options.verifyArtifact(Object.freeze({
        operation: recovered ? "RECOVER_VERIFY" : "VERIFY",
        metadata: record.metadata,
        ticketRef: record.ticketRef,
        filenames: names,
        quarantineRoot: quarantine,
        staged: Object.freeze({ ciphertext, artifactManifest: manifestReference }),
        manifest,
      }));
    } catch (error) {
      if (error instanceof ParticipantOriginatedCoordinatorError) throw error;
      fail(422, "ARTIFACT_VERIFICATION", "Existing governed artifact verification rejected the staged objects");
    }
    const verificationReferenceDigest = boundedCallbackDigest(verification, "VERIFICATION");
    let publication;
    try {
      publication = await options.publishArtifact(Object.freeze({
        operation: recovered ? "RECOVER_PUBLISH" : "PUBLISH",
        metadata: record.metadata,
        ticketRef: record.ticketRef,
        filenames: names,
        quarantineRoot: quarantine,
        staged: Object.freeze({ ciphertext, artifactManifest: manifestReference }),
        verification,
        publicationContract: Object.freeze({ createOnly: true, ciphertextFirst: true, artifactManifestLast: true }),
      }));
    } catch (error) {
      recordTerminalFailure(record, "RECONCILIATION_REQUIRED", error);
      fail(503, "PUBLISH_UNCERTAIN", "Artifact publication requires reconciliation");
    }
    const publicationReferenceDigest = boundedCallbackDigest(publication, "PUBLICATION");
    writeCreateOnly(join(paths.stages, `${record.ticketRef}.published.json`), {
      schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA,
      ticketRef: record.ticketRef,
      artifactManifest: names.artifactManifest,
      ciphertext: names.ciphertext,
      verificationReferenceDigest,
      publicationReferenceDigest,
      publishedAt: Math.floor(now() / 1000),
    });
    appendJournal(paths, {
      event: recovered ? "IMPORT_RECOVERED_AND_PUBLISHED" : "IMPORT_PUBLISHED",
      at: Math.floor(now() / 1000),
      ticketRef: record.ticketRef,
      ciphertext: names.ciphertext,
      artifactManifest: names.artifactManifest,
      verificationReferenceDigest,
      publicationReferenceDigest,
    });
    return publicStatus(record, paths);
  }

  async function uploadArtifactManifest(ticket, readable, description = {}) {
    let record = reservation(ticket);
    assertUploadAvailable(record);
    await authenticate(options.authenticate, { operation: "UPLOAD_ARTIFACT_MANIFEST", request: description.request, metadata: record.metadata, ticketRef: record.ticketRef });
    return lockedTicket(record.ticketRef, async () => {
      record = reservation(ticket);
      assertUploadAvailable(record);
      const ciphertextMarker = join(paths.stages, `${record.ticketRef}.ciphertext.json`);
      if (!existsSync(ciphertextMarker)) fail(409, "MANIFEST_ORDER", "Ciphertext must be staged before the artifact manifest");
      try {
        if (description.contentType !== PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE || !Number.isSafeInteger(description.contentLength) || description.contentLength !== record.metadata.artifactObjectLength || description.contentLength > PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES || description.transferEncoding !== undefined || description.contentDisposition !== undefined || description.filename !== undefined) {
          fail(description.contentType !== PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE ? 415 : 400, "MANIFEST_HEADERS", "Artifact manifest upload headers rejected");
        }
        const names = participantFilenames(record.metadata.role);
        const quarantineRoot = join(paths.quarantine, record.ticketRef);
        const expected = { filename: names.artifactManifest, digest: record.metadata.artifactObjectDigest, length: record.metadata.artifactObjectLength };
        const boundedReadable = timedReadable(readable, "MANIFEST", streamTimeouts);
        try {
          if (typeof options.stageObject === "function") {
            await stageWithTrustedCallback(options.stageObject, {
              kind: "artifact-manifest", readable: boundedReadable, metadata: record.metadata, ticketRef: record.ticketRef,
              quarantineRoot, filenames: names,
            }, expected, "MANIFEST");
          } else {
            await stageExactStream(
              boundedReadable,
              join(quarantineRoot, names.artifactManifest),
              record.metadata.artifactObjectLength,
              PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES,
              record.metadata.artifactObjectDigest,
              "MANIFEST",
            );
          }
        } finally {
          if (!boundedReadable.destroyed) boundedReadable.destroy();
        }
        appendJournal(paths, { event: "MANIFEST_STAGED", at: Math.floor(now() / 1000), ticketRef: record.ticketRef, filename: names.artifactManifest, digest: record.metadata.artifactObjectDigest, length: description.contentLength });
        return await finalizeStagedImport(record, false);
      } catch (error) {
        if (!(error instanceof ParticipantOriginatedCoordinatorError && ["MANIFEST_REPLAY", "TICKET_REPLAY", "IMPORT_TERMINAL", "PUBLISH_UNCERTAIN"].includes(error.code))) recordTerminalFailure(record, "FAILED", error);
        throw error;
      }
    });
  }

  async function recover() {
    return locked(async () => {
      const recovered = [];
      for (const entry of readdirSync(paths.reservations, { withFileTypes: true })) {
        if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) continue;
        const record = readExactJsonFile(join(paths.reservations, entry.name));
        if (!existsSync(reservationTransactionPaths(paths, record.ticketRef).commit)) continue;
        const failurePath = join(paths.failures, `${record.ticketRef}.json`);
        const failure = readFailureMarker(record, failurePath);
        if (existsSync(join(paths.stages, `${record.ticketRef}.published.json`))) continue;
        if (failure !== null && failure.state !== "RECONCILIATION_REQUIRED") continue;
        const names = participantFilenames(record.metadata.role);
        const quarantine = join(paths.quarantine, record.ticketRef);
        const ciphertextPath = join(quarantine, names.ciphertext);
        const manifestPath = join(quarantine, names.artifactManifest);
        if (!existsSync(ciphertextPath)) continue;
        try {
          hashExactRegularFile(ciphertextPath, record.metadata.ciphertextObjectLength, record.metadata.ciphertextObjectDigest, "CIPHERTEXT");
          const ciphertextMarker = join(paths.stages, `${record.ticketRef}.ciphertext.json`);
          if (!existsSync(ciphertextMarker)) writeCreateOnly(ciphertextMarker, { schemaVersion: PARTICIPANT_ORIGINATED_COORDINATOR_SCHEMA, ticketRef: record.ticketRef, filename: names.ciphertext, digest: record.metadata.ciphertextObjectDigest, length: record.metadata.ciphertextObjectLength });
          if (existsSync(manifestPath)) {
            recovered.push(await finalizeStagedImport(record, true, failure?.state === "RECONCILIATION_REQUIRED"));
          }
        } catch (error) {
          recordTerminalFailure(record, "FAILED", error);
        }
      }
      return Object.freeze(recovered);
    });
  }

  const coordinator = {
    paths, recoveredJournal: Object.freeze(recoveredJournal), recoveredReservations,
    beginImport, uploadCiphertext, uploadArtifactManifest, status, recover,
    _reservation: reservation, _locked: locked, _lockedTicket: lockedTicket,
    options, now, streamTimeouts,
  };
  if (options.recover !== false) await recover();
  return Object.freeze(coordinator);
}

function requestHeader(request, name) {
  const value = request.headers[name];
  if (Array.isArray(value)) fail(400, "HEADER", `Duplicate ${name} header rejected`);
  return value;
}

function requestTicket(request) {
  const ticket = requestHeader(request, PARTICIPANT_ORIGINATED_TICKET_HEADER);
  if (typeof ticket !== "string" || !TICKET.test(ticket)) fail(401, "TICKET", "Upload ticket rejected");
  return ticket;
}

function exactContentLength(request, maximum) {
  const raw = requestHeader(request, "content-length");
  if (typeof raw !== "string" || !/^[1-9][0-9]*$/u.test(raw)) fail(411, "CONTENT_LENGTH", "An exact positive Content-Length is required");
  const length = Number(raw);
  if (!Number.isSafeInteger(length) || length > maximum) fail(413, "CONTENT_LENGTH", "Content-Length rejected");
  return length;
}

function uploadDescription(request, maximum) {
  return Object.freeze({
    request,
    contentType: requestHeader(request, "content-type"),
    contentLength: exactContentLength(request, maximum),
    transferEncoding: requestHeader(request, "transfer-encoding"),
    contentDisposition: requestHeader(request, "content-disposition"),
    filename: requestHeader(request, "x-filename") ?? requestHeader(request, "x-file-name"),
  });
}

async function readCanonicalRequestJson(request) {
  if (requestHeader(request, "content-type") !== PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE) fail(415, "METADATA_CONTENT_TYPE", "Import metadata Content-Type rejected");
  if (requestHeader(request, "transfer-encoding") !== undefined || requestHeader(request, "content-disposition") !== undefined || requestHeader(request, "x-filename") !== undefined || requestHeader(request, "x-file-name") !== undefined) fail(400, "METADATA_HEADERS", "Import metadata upload headers rejected");
  const expected = exactContentLength(request, PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES);
  const chunks = [];
  let length = 0;
  try {
    for await (const value of request) {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      length += chunk.length;
      if (length > expected || length > PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES) fail(413, "METADATA_LENGTH", "Import metadata exceeded Content-Length");
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof ParticipantOriginatedCoordinatorError) throw error;
    fail(400, "METADATA_TRUNCATED", "Import metadata was malformed or truncated");
  }
  if (length !== expected) fail(400, "METADATA_TRUNCATED", "Import metadata length did not match Content-Length");
  return parseCanonicalJson(Buffer.concat(chunks, length), PARTICIPANT_ORIGINATED_MAX_METADATA_BYTES, "METADATA");
}

function sendJson(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store, max-age=0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  response.end(body);
}

/**
 * Exactly four request targets are exposed. Upload tickets travel only in the
 * fixed header above, so neither a filename nor a filesystem fragment is ever
 * parsed from the URL.
 */
export function createParticipantOriginatedCoordinatorServer(coordinator) {
  if (coordinator === null || typeof coordinator !== "object" || typeof coordinator.beginImport !== "function" || typeof coordinator.uploadCiphertext !== "function" || typeof coordinator.uploadArtifactManifest !== "function" || typeof coordinator.status !== "function") fail(500, "CONFIG", "A participant-originated coordinator is required");
  const requestHandler = async (request, response) => {
    try {
      if (requestHeader(request, "expect") !== undefined) fail(417, "EXPECTATION", "HTTP expectations are not accepted");
      const url = new URL(request.url ?? "/", "http://participant-originated.invalid");
      if (url.search !== "" || url.hash !== "") fail(400, "ROUTE_QUERY", "Query parameters and fragments are not accepted");
      if (request.method === "POST" && url.pathname === participantOriginatedRoutes.beginImport) {
        const metadata = await readCanonicalRequestJson(request);
        sendJson(response, 201, await coordinator.beginImport(metadata, request));
        return;
      }
      if (request.method === "PUT" && url.pathname === participantOriginatedRoutes.ciphertext) {
        const ticket = requestTicket(request);
        const description = uploadDescription(request, PARTICIPANT_ORIGINATED_MAX_CIPHERTEXT_BYTES);
        sendJson(response, 201, await coordinator.uploadCiphertext(ticket, request, description));
        return;
      }
      if (request.method === "PUT" && url.pathname === participantOriginatedRoutes.artifactManifest) {
        const ticket = requestTicket(request);
        const description = uploadDescription(request, PARTICIPANT_ORIGINATED_MAX_MANIFEST_BYTES);
        sendJson(response, 201, await coordinator.uploadArtifactManifest(ticket, request, description));
        return;
      }
      if (request.method === "GET" && url.pathname === participantOriginatedRoutes.status) {
        if (requestHeader(request, "transfer-encoding") !== undefined || (requestHeader(request, "content-length") !== undefined && requestHeader(request, "content-length") !== "0")) fail(400, "STATUS_BODY", "Status requests cannot carry a body");
        sendJson(response, 200, await coordinator.status(requestTicket(request), request));
        return;
      }
      if (Object.values(participantOriginatedRoutes).includes(url.pathname)) fail(405, "METHOD", "Method rejected for participant-originated route");
      fail(404, "ROUTE", "Participant-originated route not found");
    } catch (error) {
      const known = error instanceof ParticipantOriginatedCoordinatorError;
      const status = known ? error.status : 500;
      const code = known ? error.code : "INTERNAL";
      const message = status >= 500 ? "Participant-originated import failed" : error.message;
      response.shouldKeepAlive = false;
      if (!response.headersSent) {
        sendJson(response, status, { error: { code, message } });
        response.once("finish", () => {
          if (!request.complete && !request.destroyed) request.destroy();
        });
      }
      else response.destroy();
    }
  };
  const server = createServer(requestHandler);
  const absoluteMs = coordinator.streamTimeouts?.absoluteMs ?? PARTICIPANT_ORIGINATED_STREAM_ABSOLUTE_TIMEOUT_MS;
  server.requestTimeout = absoluteMs;
  server.headersTimeout = Math.min(30 * 1000, absoluteMs);
  const rejectExpectation = (request, response) => {
    response.shouldKeepAlive = false;
    sendJson(response, 417, { error: { code: "EXPECTATION", message: "HTTP expectations are not accepted" } });
    response.once("finish", () => {
      if (!request.destroyed) request.destroy();
    });
  };
  server.on("checkContinue", rejectExpectation);
  server.on("checkExpectation", rejectExpectation);
  return server;
}
