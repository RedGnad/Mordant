import { strictEqual, throws } from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";

import {
  assertAdmissionBindsEnrollmentKey,
  assertCoalitionCaseKeysAreAdmitted,
  assertParticipantAdmissionV2Message,
  participantAdmissionV2TypedData,
  participantSigningKeyDigest,
  ParticipantAdmissionV2Error,
  PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE,
  type AdmittedEnrollmentKey,
  type BoundParticipantIdentity,
  type ParticipantAdmissionV2Message,
} from "./participant-admission-v2";

function ed25519KeyBase64(): string {
  const { publicKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return raw.toString("base64");
}

const KEY_A = ed25519KeyBase64();
const KEY_B = ed25519KeyBase64();
const NOW = 1_786_000_000;

function identity(role: string, key: string): BoundParticipantIdentity {
  return { id: `sha256:${"1".repeat(64)}`, role, signingPublicKey: key };
}

function admission(overrides: Partial<ParticipantAdmissionV2Message> = {}): ParticipantAdmissionV2Message {
  return {
    verifyingService: "mordant.participant-admission",
    runId: "run-1",
    fheCaseId: `0x${"a1".repeat(32)}`,
    protectionBindingDigest: `0x${"a2".repeat(32)}`,
    assetIdentityDigest: `0x${"a3".repeat(32)}`,
    role: "PARTICIPANT_A",
    activeFrom: 100,
    activeUntil: 400,
    participantWallet: "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685",
    authorizationNonce: `0x${"a4".repeat(32)}`,
    issuedAt: NOW - 60,
    expiresAt: NOW + 120,
    participantSigningKeyDigest: participantSigningKeyDigest(KEY_A),
    ...overrides,
  };
}

const DIGEST: `0x${string}` = `0x${"dd".repeat(32)}`;

function refuses(code: string, run: () => unknown): void {
  throws(run, (error: unknown) => error instanceof ParticipantAdmissionV2Error && error.code === code, `expected ${code}`);
}

test("the signing key digest is derived from the key the case publishes", () => {
  const expected = `0x${createHash("sha256").update(Buffer.from(KEY_A, "base64")).digest("hex")}`;
  strictEqual(participantSigningKeyDigest(KEY_A), expected);
  refuses("SIGNING_KEY", () => participantSigningKeyDigest("not-base64"));
  refuses("SIGNING_KEY", () => participantSigningKeyDigest(Buffer.alloc(31).toString("base64")));
});

test("V2 is its own EIP-712 type, so a V1 signature cannot be replayed as one", () => {
  const typed = participantAdmissionV2TypedData(admission());
  strictEqual(typed.primaryType, PARTICIPANT_ADMISSION_V2_PRIMARY_TYPE);
  strictEqual(typed.domain.version, "2");
  const names = typed.types.ParticipantAdmissionV2.map((field) => field.name);
  strictEqual(names.at(-1), "participantSigningKeyDigest", "the key must be inside the signed struct");
});

test("an admission binds exactly the key the case will accept enrollments from", () => {
  const admitted = assertAdmissionBindsEnrollmentKey(admission(), identity("PARTICIPANT_A", KEY_A), DIGEST, NOW);
  strictEqual(admitted.signingKeyDigest, participantSigningKeyDigest(KEY_A));
  strictEqual(admitted.role, "PARTICIPANT_A");
});

test("a case publishing a key no wallet admitted is refused", () => {
  // The wallet admitted key A; the case publishes key B.
  refuses("SIGNING_KEY_NOT_ADMITTED", () =>
    assertAdmissionBindsEnrollmentKey(admission(), identity("PARTICIPANT_A", KEY_B), DIGEST, NOW));
});

test("an admission for another role does not cover this identity", () => {
  refuses("ROLE_MISMATCH", () =>
    assertAdmissionBindsEnrollmentKey(admission(), identity("PARTICIPANT_B", KEY_A), DIGEST, NOW));
});

test("an admission outside its window no longer authorizes the key", () => {
  refuses("ADMISSION_EXPIRED", () =>
    assertAdmissionBindsEnrollmentKey(admission(), identity("PARTICIPANT_A", KEY_A), DIGEST, NOW + 10_000));
  refuses("ADMISSION_EXPIRED", () =>
    assertAdmissionBindsEnrollmentKey(admission(), identity("PARTICIPANT_A", KEY_A), DIGEST, NOW - 10_000));
});

test("both sides of a coalition case must be covered by admissions", () => {
  const a = assertAdmissionBindsEnrollmentKey(admission(), identity("PARTICIPANT_A", KEY_A), DIGEST, NOW);
  const b = assertAdmissionBindsEnrollmentKey(
    admission({
      role: "PARTICIPANT_B",
      participantWallet: "0x0f8b9a0c064306f938912658c96c681d8655140b",
      participantSigningKeyDigest: participantSigningKeyDigest(KEY_B),
    }),
    identity("PARTICIPANT_B", KEY_B),
    DIGEST,
    NOW,
  );
  assertCoalitionCaseKeysAreAdmitted([a, b], identity("PARTICIPANT_A", KEY_A), identity("PARTICIPANT_B", KEY_B));

  // One side missing is not a covered case.
  refuses("ROLE_NOT_ADMITTED", () =>
    assertCoalitionCaseKeysAreAdmitted([a], identity("PARTICIPANT_A", KEY_A), identity("PARTICIPANT_B", KEY_B)));
  // One wallet cannot hold both sides.
  const bSameWallet: AdmittedEnrollmentKey = { ...b, participantWallet: a.participantWallet };
  refuses("WALLET_COLLISION", () =>
    assertCoalitionCaseKeysAreAdmitted([a, bSameWallet], identity("PARTICIPANT_A", KEY_A), identity("PARTICIPANT_B", KEY_B)));
});

test("the message shape is exact, so an unbound field cannot ride along", () => {
  strictEqual(assertParticipantAdmissionV2Message(admission()).role, "PARTICIPANT_A");
  refuses("ADMISSION_SHAPE", () => assertParticipantAdmissionV2Message({ ...admission(), extra: 1 }));
  const { participantSigningKeyDigest: _dropped, ...withoutKey } = admission();
  refuses("ADMISSION_SHAPE", () => assertParticipantAdmissionV2Message(withoutKey));
  refuses("ADMISSION_FIELD", () =>
    assertParticipantAdmissionV2Message({ ...admission(), participantSigningKeyDigest: "0xnope" }));
});
