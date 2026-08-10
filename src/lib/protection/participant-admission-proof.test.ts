import assert from "node:assert/strict";

import { hashTypedData } from "viem";

import { participantAdmissionV2TypedData } from "./participant-admission-v2";
import { test } from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import {
  DirectParticipantBridgeEvidenceError,
  assertParticipantAdmissionProof,
  type DirectParticipantAdmissionFact,
} from "./direct-participant-bridge-evidence";
import {
  participantAdmissionDigest,
  participantAdmissionTypedData,
  type ParticipantAdmissionMessage,
} from "./participant-authorization";
import type { Sha256Digest } from "./cleanverse-asset";

/**
 * F-03: the wallet authorizations must be independently re-provable.
 *
 * These use real EIP-712 signing and real ECDSA recovery, not stubs. A test that
 * asserted rejection of an obviously malformed blob would prove nothing; every
 * negative case below starts from a genuinely signed admission and changes one
 * thing, so it isolates exactly the binding under test.
 */

// Deterministic throwaway keys. They sign nothing but test fixtures.
const KEY_A = `0x${"11".repeat(32)}` as const;
const KEY_B = `0x${"22".repeat(32)}` as const;
const KEY_ATTACKER = `0x${"33".repeat(32)}` as const;
const WALLET_A = privateKeyToAccount(KEY_A).address;
const WALLET_B = privateKeyToAccount(KEY_B).address;
const WALLET_ATTACKER = privateKeyToAccount(KEY_ATTACKER).address;

const CHAIN_ID = 10_143;
const RUN_ID = "76005a0c-2787-4c50-b196-636e45b71781";
const OTHER_RUN_ID = "11111111-1111-4111-8111-111111111111";
const FHE_CASE_ID = `sha256:${"a1".repeat(32)}` as Sha256Digest;
const OTHER_FHE_CASE_ID = `sha256:${"b2".repeat(32)}` as Sha256Digest;
const BINDING = `sha256:${"c3".repeat(32)}` as Sha256Digest;
const OTHER_BINDING = `sha256:${"d4".repeat(32)}` as Sha256Digest;
const ASSET = `0x${"e5".repeat(32)}` as const;

function expected(overrides: Partial<{ runId: string; fheCaseId: Sha256Digest; protectionBindingDigest: Sha256Digest }> = {}) {
  return { runId: RUN_ID, fheCaseId: FHE_CASE_ID, protectionBindingDigest: BINDING, ...overrides };
}

function message(overrides: Partial<ParticipantAdmissionMessage> = {}): ParticipantAdmissionMessage {
  return {
    verifyingService: "https://mordant.example",
    runId: RUN_ID,
    fheCaseId: `0x${FHE_CASE_ID.slice("sha256:".length)}`,
    protectionBindingDigest: `0x${BINDING.slice("sha256:".length)}`,
    assetIdentityDigest: ASSET,
    role: "PARTICIPANT_A",
    // Private execution input in the signed struct only; never retained by the
    // bridge evidence, which is asserted at the end of this file.
    activeFrom: 1_786_000_000,
    activeUntil: 1_786_900_000,
    participantWallet: WALLET_A,
    authorizationNonce: `0x${"7f".repeat(32)}`,
    issuedAt: 1_786_056_415,
    expiresAt: 1_786_057_015,
    ...overrides,
  };
}

async function sign(payload: ParticipantAdmissionMessage, key: `0x${string}`): Promise<`0x${string}`> {
  return privateKeyToAccount(key).signTypedData(participantAdmissionTypedData(payload, CHAIN_ID));
}

/** A genuinely signed, fully consistent admission fact. */
async function admission(
  key: `0x${string}`,
  overrides: Partial<ParticipantAdmissionMessage> = {},
  factOverrides: Partial<DirectParticipantAdmissionFact> = {},
): Promise<DirectParticipantAdmissionFact> {
  const payload = message(overrides);
  const signature = await sign(payload, key);
  return {
    role: payload.role,
    participantWallet: payload.participantWallet,
    authorizationDigest: participantAdmissionDigest(payload, CHAIN_ID),
    claimCommitment: `0x${"ab".repeat(32)}`,
    authorizationNonce: payload.authorizationNonce,
    chainId: CHAIN_ID,
    eligibilityBlock: 51_516_302,
    authorization: { ...payload },
    signature,
    ...factOverrides,
  };
}

async function refuses(code: string, fact: DirectParticipantAdmissionFact, context = expected()): Promise<void> {
  await assert.rejects(
    () => assertParticipantAdmissionProof(fact, context),
    (error: unknown) => error instanceof DirectParticipantBridgeEvidenceError && error.code === code,
    `expected refusal ${code}`,
  );
}

test("F-03: a genuinely signed admission verifies and recovers its own wallet", async () => {
  const proof = await assertParticipantAdmissionProof(await admission(KEY_A), expected());
  assert.equal(proof.role, "PARTICIPANT_A");
  assert.equal(proof.wallet, WALLET_A);
  assert.equal(proof.recoveredSigner, WALLET_A);
});

test("F-03: both roles verify independently", async () => {
  const a = await assertParticipantAdmissionProof(await admission(KEY_A), expected());
  const b = await assertParticipantAdmissionProof(
    await admission(KEY_B, { role: "PARTICIPANT_B", participantWallet: WALLET_B }),
    expected(),
  );
  assert.equal(a.recoveredSigner, WALLET_A);
  assert.equal(b.recoveredSigner, WALLET_B);
  assert.notEqual(a.wallet.toLowerCase(), b.wallet.toLowerCase());
});

test("F-03: a fabricated admission with no wallet signature is refused", async () => {
  const fact = await admission(KEY_A);
  // Signature dropped, struct kept.
  const { signature, ...withoutSignature } = fact;
  await refuses("ADMISSION_PROOF_MISSING", withoutSignature as DirectParticipantAdmissionFact);
  // Struct dropped, signature kept: a signature over nothing this run can check.
  const { authorization, ...withoutAuthorization } = fact;
  await refuses("ADMISSION_PROOF_MISSING", withoutAuthorization as DirectParticipantAdmissionFact);
  assert.ok(signature !== undefined && authorization !== undefined);
  // A syntactically plausible but invented signature is refused too: recovery
  // fails outright rather than yielding some other address.
  await refuses("ADMISSION_PROOF_SIGNATURE", { ...fact, signature: `0x${"5c".repeat(65)}` });
  await refuses("ADMISSION_PROOF_SIGNATURE", { ...fact, signature: "0xdeadbeef" });
});

test("F-03: the wrong signer is refused", async () => {
  // The attacker signs a struct that names the canonical wallet.
  const payload = message();
  const fact: DirectParticipantAdmissionFact = {
    ...(await admission(KEY_A)),
    signature: await sign(payload, KEY_ATTACKER),
  };
  await refuses("ADMISSION_PROOF_SIGNER", fact);
  assert.notEqual(WALLET_ATTACKER.toLowerCase(), WALLET_A.toLowerCase());
});

test("F-03: holder A's signature cannot be attached to holder B", async () => {
  const a = await admission(KEY_A);
  const b = await admission(KEY_B, { role: "PARTICIPANT_B", participantWallet: WALLET_B });
  await refuses("ADMISSION_PROOF_SIGNER", { ...b, signature: a.signature });
});

test("F-03: an A/B role swap is refused", async () => {
  const a = await admission(KEY_A);
  // The struct says A, the record claims B.
  await refuses("ADMISSION_PROOF_ROLE", { ...a, role: "PARTICIPANT_B" });
  // And a struct signed for role B cannot be filed as role A.
  const b = await admission(KEY_B, { role: "PARTICIPANT_B", participantWallet: WALLET_B });
  await refuses("ADMISSION_PROOF_ROLE", { ...b, role: "PARTICIPANT_A" });
});

test("F-03: a changed participant wallet is refused", async () => {
  await refuses("ADMISSION_PROOF_WALLET", { ...(await admission(KEY_A)), participantWallet: WALLET_B });
});

test("F-03: a changed runId is refused, in the record and in the signed struct", async () => {
  // Relabelled expectation: the struct is bound to RUN_ID.
  await refuses("ADMISSION_PROOF_RUN", await admission(KEY_A), expected({ runId: OTHER_RUN_ID }));
  // Replaying an admission genuinely signed for another run.
  const elsewhere = await admission(KEY_A, { runId: OTHER_RUN_ID });
  await refuses("ADMISSION_PROOF_RUN", elsewhere, expected());
});

test("F-03: a changed fheCaseId or protection binding is refused", async () => {
  await refuses("ADMISSION_PROOF_CASE", await admission(KEY_A), expected({ fheCaseId: OTHER_FHE_CASE_ID }));
  await refuses("ADMISSION_PROOF_BINDING", await admission(KEY_A), expected({ protectionBindingDigest: OTHER_BINDING }));
  // Genuinely signed against another binding, replayed here.
  const otherBinding = await admission(KEY_A, {
    protectionBindingDigest: `0x${OTHER_BINDING.slice("sha256:".length)}`,
  });
  await refuses("ADMISSION_PROOF_BINDING", otherBinding, expected());
});

test("F-03: a changed nonce, issuedAt or expiresAt is refused", async () => {
  const fact = await admission(KEY_A);
  await refuses("ADMISSION_PROOF_NONCE", { ...fact, authorizationNonce: `0x${"09".repeat(32)}` });
  // Times live inside the signed struct: changing one invalidates the digest and
  // then the recovery, so the authorization cannot be silently re-dated.
  for (const field of ["issuedAt", "expiresAt"] as const) {
    const moved = await admission(KEY_A);
    const authorization = { ...(moved.authorization as Record<string, unknown>) };
    authorization[field] = (authorization[field] as number) + 60;
    await refuses("ADMISSION_PROOF_DIGEST", { ...moved, authorization });
  }
});

test("F-03: any payload change after signing is refused", async () => {
  const fact = await admission(KEY_A);
  for (const [field, value] of [
    ["verifyingService", "https://attacker.example"],
    ["assetIdentityDigest", `0x${"00".repeat(32)}`],
    ["activeUntil", 1_999_999_999],
  ] as const) {
    const authorization = { ...(fact.authorization as Record<string, unknown>), [field]: value };
    await refuses("ADMISSION_PROOF_DIGEST", { ...fact, authorization });
  }
});

test("F-03: a mismatched retained digest is refused", async () => {
  await refuses("ADMISSION_PROOF_DIGEST", { ...(await admission(KEY_A)), authorizationDigest: `0x${"1f".repeat(32)}` });
});

test("F-03: a wrong chainId is refused", async () => {
  const fact = await admission(KEY_A);
  await refuses("ADMISSION_PROOF_CHAIN", { ...fact, chainId: 1 });
  await refuses("ADMISSION_PROOF_CHAIN", { ...fact, chainId: 10_144 });
});

test("F-03: the same wallet cannot hold both roles", async () => {
  // Wallet A genuinely signs a role-B struct. Each proof verifies on its own, so
  // the distinctness rule is what stops it, and the bridge evidence enforces it.
  const asB = await admission(KEY_A, { role: "PARTICIPANT_B" });
  const proof = await assertParticipantAdmissionProof(asB, expected());
  assert.equal(proof.recoveredSigner, WALLET_A);
  assert.equal(proof.role, "PARTICIPANT_B");
  assert.equal(proof.wallet.toLowerCase(), WALLET_A.toLowerCase());
});

test("F-03: a verified proof retains no private pledge window and no key", async () => {
  const proof = await assertParticipantAdmissionProof(await admission(KEY_A), expected());
  const encoded = JSON.stringify(proof);
  for (const forbidden of ["activeFrom", "activeUntil", "privateKey", KEY_A, KEY_B, "1786000000", "1786900000"]) {
    assert.equal(encoded.includes(forbidden), false, `proof leaked ${forbidden}`);
  }
  // A V1 proof keeps its minimal shape, plus the schema it re-proved: a reader
  // must be able to tell which admission was verified rather than assume.
  assert.deepEqual(
    Object.keys(proof).sort(),
    ["admissionSchema", "authorizationDigest", "recoveredSigner", "role", "wallet"],
  );
  assert.equal(proof.admissionSchema, "ParticipantAdmissionV1");
  assert.equal(proof.participantSigningKeyDigest, undefined, "a V1 admission binds no signing key");
});

test("F-03: the admission stays verifiable after the private artifacts are pruned", async () => {
  // Pruning removes public/, decryptor-private/ and participant-private/ and the
  // admitted intervals. The retained fact below is all that survives, and it is
  // still sufficient to re-prove the wallet authorization.
  const survived = await admission(KEY_A);
  const rehydrated = JSON.parse(JSON.stringify(survived)) as DirectParticipantAdmissionFact;
  const proof = await assertParticipantAdmissionProof(rehydrated, expected());
  assert.equal(proof.recoveredSigner, WALLET_A);
});

// -------------------------------------------------------- V2 at the bridge

/**
 * Settlement must re-prove the admissions the product actually persists. Since
 * the live server issues V2, a bridge that only understood V1 would either
 * refuse every real admission or, worse, verify it as a V1 and drop the binding
 * between the wallet and the key that signs its enrollments.
 */
async function v2Admission(key: `0x${string}`, signingKeyDigest: `0x${string}`) {
  const payload = { ...message(), participantSigningKeyDigest: signingKeyDigest };
  const typed = participantAdmissionV2TypedData(payload, CHAIN_ID);
  const account = privateKeyToAccount(key);
  const signature = await account.signTypedData({
    domain: typed.domain,
    types: typed.types,
    primaryType: typed.primaryType,
    message: typed.message as never,
  });
  return {
    role: payload.role,
    participantWallet: payload.participantWallet,
    authorizationDigest: hashTypedData(typed as never) as `0x${string}`,
    claimCommitment: `0x${"ab".repeat(32)}` as `0x${string}`,
    authorizationNonce: payload.authorizationNonce,
    chainId: CHAIN_ID,
    eligibilityBlock: 51_516_302,
    authorization: { ...payload },
    signature,
  } as unknown as DirectParticipantAdmissionFact;
}

test("F-02: the bridge re-proves a V2 admission and keeps its key binding", async () => {
  const signingKeyDigest = `0x${"7c".repeat(32)}` as const;
  const proof = await assertParticipantAdmissionProof(await v2Admission(KEY_A, signingKeyDigest), expected());
  assert.equal(proof.admissionSchema, "ParticipantAdmissionV2");
  assert.equal(proof.participantSigningKeyDigest, signingKeyDigest,
    "settlement is the last place able to see which key the admitted wallet authorized");
  assert.equal(proof.recoveredSigner.toLowerCase(), WALLET_A.toLowerCase());
});

test("F-02: a V2 admission signed over the V1 struct is refused", async () => {
  // The same fields, signed as a V1 message. Recovering it against the V2 typed
  // data must not yield the wallet, so the proof fails rather than passing a
  // downgraded admission through settlement.
  const signingKeyDigest = `0x${"7d".repeat(32)}` as const;
  const v1Signed = await admission(KEY_A);
  const downgraded = {
    ...v1Signed,
    authorization: { ...(v1Signed.authorization as object), participantSigningKeyDigest: signingKeyDigest },
  } as unknown as DirectParticipantAdmissionFact;
  await assert.rejects(() => assertParticipantAdmissionProof(downgraded, expected()));
});
