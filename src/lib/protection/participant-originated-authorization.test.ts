import assert from "node:assert/strict";
import { test } from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import {
  PARTICIPANT_ENCRYPTION_INTENT_PRIMARY_TYPE,
  PARTICIPANT_ENCRYPTION_INTENT_SCHEMA,
  PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_PRIMARY_TYPE,
  PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA,
  PARTICIPANT_ORIGINATED_SEMANTIC_GAP,
  PARTICIPANT_SIGNING_KEY_REGISTRATION_PRIMARY_TYPE,
  PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA,
  ParticipantOriginatedAuthorizationError,
  assertParticipantEncryptionIntentRequest,
  assertParticipantFinalEncryptedAdmissionRequest,
  assertParticipantSigningKeyRegistrationRequest,
  generateParticipantClaimSalt,
  participantEncryptionIntentDigest,
  participantEncryptionIntentTypedData,
  participantFinalEncryptedAdmissionDigest,
  participantFinalEncryptedAdmissionTypedData,
  participantOriginatedClaimCommitment,
  participantSigningKeyRegistrationDigest,
  participantSigningKeyRegistrationTypedData,
  participantSigningPublicKeyDigest,
  sha256ExactBytes,
  verifyParticipantEncryptionIntent,
  verifyParticipantFinalEncryptedAdmission,
  verifyParticipantSigningKeyRegistration,
  type ExpectedParticipantEncryptionIntentContext,
  type ExpectedParticipantFinalEncryptedAdmissionContext,
  type ExpectedParticipantSigningKeyRegistrationContext,
  type ParticipantEncryptionIntentMessage,
  type ParticipantEncryptionIntentRequest,
  type ParticipantFinalEncryptedAdmissionMessage,
  type ParticipantFinalEncryptedAdmissionRequest,
  type ParticipantLocalClaimPreimage,
  type ParticipantOriginatedBundleContext,
  type ParticipantOriginatedBytes32,
  type ParticipantOriginatedNonceGuard,
  type ParticipantSigningKeyRegistrationMessage,
  type ParticipantSigningKeyRegistrationRequest,
  type RecomputedParticipantEncryptedArtifactContext,
  type VerifiedParticipantEncryptionIntent,
  type VerifiedParticipantSigningKeyRegistration,
} from "./participant-originated-authorization";

const WALLET_KEY = `0x${"11".repeat(32)}` as const;
const ATTACKER_KEY = `0x${"22".repeat(32)}` as const;
const wallet = privateKeyToAccount(WALLET_KEY);
const attacker = privateKeyToAccount(ATTACKER_KEY);
const RUN_ID = "8a44f9e0-20d7-4ca3-8762-82bcbfc648af";
const OTHER_RUN_ID = "15a95031-c902-4f71-81a8-f23179625589";
const SERVICE = "https://participant-originated.example";
const CHAIN_ID = 10_143;
const T0 = 1_800_000_000;
const ZERO = `0x${"00".repeat(32)}` as ParticipantOriginatedBytes32;

function bytes32(byte: string): ParticipantOriginatedBytes32 {
  return `0x${byte.repeat(32)}`;
}

const SIGNING_PUBLIC_KEY = bytes32("31");
const SIGNING_KEY_DIGEST = participantSigningPublicKeyDigest(SIGNING_PUBLIC_KEY);
const SIGNING_KEY_DIGEST_GOLDEN =
  "0x8a83665f3798727f14f92ad0e6c99fdab08ee731d6cd644c131223fd2f4fed2a";
const CLAIM_COMMITMENT_GOLDEN =
  "0x07667545fd9d8c81058b4b693bf8c5c8577ede1a0847571bda5355c718950292";

const bundle: ParticipantOriginatedBundleContext = {
  runId: RUN_ID,
  fheCaseId: bytes32("41"),
  caseBindingDigest: bytes32("42"),
  protectionBindingDigest: bytes32("43"),
  assetIdentityDigest: bytes32("44"),
  policyDigest: bytes32("45"),
  circuitId: "mordant.identity-full-fhe-256",
  circuitVersion: 5,
  circuitDigest: bytes32("46"),
  parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1",
  parameterFingerprint: bytes32("47"),
  fhePublicKeyDigest: bytes32("48"),
  releaseAuthorityId: bytes32("49"),
  releaseMode: "governed-decryptor-v1",
  clientBundleDigest: bytes32("4a"),
  clientSourceDigest: bytes32("4b"),
  clientBuildDigest: bytes32("4c"),
  clientBinaryDigest: bytes32("4d"),
  bundleExpiresAt: T0 + 600,
};

const localClaim: ParticipantLocalClaimPreimage = {
  activeFrom: 100,
  activeUntil: 400,
  amount: [0, 0, 0, 100_000_000],
  currency: bytes32("51"),
  obligationId: bytes32("52"),
  receivableId: bytes32("53"),
  exclusive: true,
  receivableCommitment: ZERO,
};

function registrationMessage(
  overrides: Partial<ParticipantSigningKeyRegistrationMessage> = {},
): ParticipantSigningKeyRegistrationMessage {
  return {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: bundle.fheCaseId,
    assetIdentityDigest: bundle.assetIdentityDigest,
    policyDigest: bundle.policyDigest,
    role: "PARTICIPANT_A",
    participantWallet: wallet.address,
    participantSigningPublicKey: SIGNING_PUBLIC_KEY,
    participantSigningKeyDigest: SIGNING_KEY_DIGEST,
    registrationNonce: bytes32("61"),
    issuedAt: T0,
    expiresAt: T0 + 300,
    ...overrides,
  };
}

function registrationExpected(
  overrides: Partial<ExpectedParticipantSigningKeyRegistrationContext> = {},
): ExpectedParticipantSigningKeyRegistrationContext {
  return {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: bundle.fheCaseId,
    assetIdentityDigest: bundle.assetIdentityDigest,
    policyDigest: bundle.policyDigest,
    role: "PARTICIPANT_A",
    participantWallet: wallet.address,
    now: T0 + 5,
    chainId: CHAIN_ID,
    ...overrides,
  };
}

async function registrationRequest(
  message = registrationMessage(),
  signer = wallet,
): Promise<ParticipantSigningKeyRegistrationRequest> {
  return {
    schemaVersion: PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA,
    registration: message,
    signature: await signer.signTypedData(participantSigningKeyRegistrationTypedData(message, CHAIN_ID)),
  };
}

function intentMessage(
  registrationDigest: ParticipantOriginatedBytes32,
  overrides: Partial<ParticipantEncryptionIntentMessage> = {},
): ParticipantEncryptionIntentMessage {
  return {
    verifyingService: SERVICE,
    ...bundle,
    role: "PARTICIPANT_A",
    participantWallet: wallet.address,
    participantSigningKeyDigest: SIGNING_KEY_DIGEST,
    registrationDigest,
    claimCommitment: participantOriginatedClaimCommitment({
      runId: RUN_ID,
      fheCaseId: bundle.fheCaseId,
      role: "PARTICIPANT_A",
      claim: localClaim,
      salt: bytes32("71"),
    }),
    intentNonce: bytes32("62"),
    issuedAt: T0 + 10,
    expiresAt: T0 + 280,
    ...overrides,
  };
}

async function intentRequest(
  message: ParticipantEncryptionIntentMessage,
  signer = wallet,
): Promise<ParticipantEncryptionIntentRequest> {
  return {
    schemaVersion: PARTICIPANT_ENCRYPTION_INTENT_SCHEMA,
    intent: message,
    signature: await signer.signTypedData(participantEncryptionIntentTypedData(message, CHAIN_ID)),
  };
}

function intentExpected(
  registration: VerifiedParticipantSigningKeyRegistration,
  overrides: Partial<ExpectedParticipantEncryptionIntentContext> = {},
): ExpectedParticipantEncryptionIntentContext {
  return {
    verifyingService: SERVICE,
    ...bundle,
    role: "PARTICIPANT_A",
    participantWallet: wallet.address,
    registration,
    now: T0 + 15,
    chainId: CHAIN_ID,
    ...overrides,
  };
}

function artifactContext(intent: VerifiedParticipantEncryptionIntent): RecomputedParticipantEncryptedArtifactContext {
  return {
    encryptedArtifactDigest: sha256ExactBytes(Buffer.from("canonical-artifact-without-newline")),
    ciphertextObjectDigest: sha256ExactBytes(Buffer.from("exact-ciphertext-object")),
    ciphertextObjectLength: 31_459_985,
    fheCaseId: bundle.fheCaseId,
    caseBindingDigest: bundle.caseBindingDigest,
    assetIdentityDigest: bundle.assetIdentityDigest,
    role: "PARTICIPANT_A",
    participantSigningKeyDigest: SIGNING_KEY_DIGEST,
    parameterProfile: bundle.parameterProfile,
    parameterFingerprint: bundle.parameterFingerprint,
    fhePublicKeyDigest: bundle.fhePublicKeyDigest,
    circuitDigest: bundle.circuitDigest,
    submissionNonce: bytes32("63"),
    expiresAt: T0 + 500,
    embeddedEncryptionIntentDigest: intent.encryptionIntentDigest,
    embeddedClaimCommitment: intent.claimCommitment,
  };
}

function finalMessage(
  registration: VerifiedParticipantSigningKeyRegistration,
  intent: VerifiedParticipantEncryptionIntent,
  artifact: RecomputedParticipantEncryptedArtifactContext,
  overrides: Partial<ParticipantFinalEncryptedAdmissionMessage> = {},
): ParticipantFinalEncryptedAdmissionMessage {
  return {
    verifyingService: SERVICE,
    runId: RUN_ID,
    fheCaseId: bundle.fheCaseId,
    role: "PARTICIPANT_A",
    participantWallet: wallet.address,
    participantSigningKeyDigest: SIGNING_KEY_DIGEST,
    registrationDigest: registration.registrationDigest,
    clientBundleDigest: bundle.clientBundleDigest,
    encryptionIntentDigest: intent.encryptionIntentDigest,
    claimCommitment: intent.claimCommitment,
    encryptedArtifactDigest: artifact.encryptedArtifactDigest,
    ciphertextObjectDigest: artifact.ciphertextObjectDigest,
    ciphertextObjectLength: artifact.ciphertextObjectLength,
    submissionNonce: artifact.submissionNonce,
    issuedAt: T0 + 20,
    expiresAt: T0 + 260,
    ...overrides,
  };
}

async function finalRequest(
  message: ParticipantFinalEncryptedAdmissionMessage,
  signer = wallet,
): Promise<ParticipantFinalEncryptedAdmissionRequest> {
  return {
    schemaVersion: PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA,
    admission: message,
    signature: await signer.signTypedData(participantFinalEncryptedAdmissionTypedData(message, CHAIN_ID)),
  };
}

async function fixture() {
  const registration = await verifyParticipantSigningKeyRegistration(
    await registrationRequest(),
    registrationExpected(),
  );
  const intentPayload = intentMessage(registration.registrationDigest);
  const intent = await verifyParticipantEncryptionIntent(
    await intentRequest(intentPayload),
    intentExpected(registration),
  );
  const artifact = artifactContext(intent);
  const admission = finalMessage(registration, intent, artifact);
  const expected: ExpectedParticipantFinalEncryptedAdmissionContext = {
    verifyingService: SERVICE,
    ...bundle,
    role: "PARTICIPANT_A",
    participantWallet: wallet.address,
    registration,
    intent,
    artifact,
    now: T0 + 30,
    chainId: CHAIN_ID,
  };
  return { registration, intent, artifact, admission, expected };
}

async function refusal(
  promise: Promise<unknown>,
  code?: string,
): Promise<ParticipantOriginatedAuthorizationError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ParticipantOriginatedAuthorizationError, `unexpected refusal: ${String(error)}`);
    if (code !== undefined) assert.equal(error.code, code);
    return error;
  }
  throw new Error("expected authorization refusal");
}

test("real viem EOA signatures verify through the complete phase 0 -> 1 -> 2 chain", async () => {
  const values = await fixture();
  const request = await finalRequest(values.admission);
  const verified = await verifyParticipantFinalEncryptedAdmission(request, values.expected);
  assert.equal(verified.participantWallet, wallet.address);
  assert.equal(verified.encryptionIntentDigest, values.intent.encryptionIntentDigest);
  assert.equal(verified.encryptedArtifactDigest, values.artifact.encryptedArtifactDigest);
  assert.equal(verified.chainId, CHAIN_ID);
  assert.equal(participantSigningKeyRegistrationTypedData(registrationMessage()).primaryType,
    PARTICIPANT_SIGNING_KEY_REGISTRATION_PRIMARY_TYPE);
  assert.equal(participantEncryptionIntentTypedData(values.intent.intent).primaryType,
    PARTICIPANT_ENCRYPTION_INTENT_PRIMARY_TYPE);
  assert.equal(participantFinalEncryptedAdmissionTypedData(values.admission).primaryType,
    PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_PRIMARY_TYPE);
});

test("the hiding commitment covers the complete native pledge projection and a 32-byte local salt", () => {
  const saltA = bytes32("71");
  const saltB = bytes32("72");
  const base = participantOriginatedClaimCommitment({
    runId: RUN_ID, fheCaseId: bundle.fheCaseId, role: "PARTICIPANT_A", claim: localClaim, salt: saltA,
  });
  const secondSalt = participantOriginatedClaimCommitment({
    runId: RUN_ID, fheCaseId: bundle.fheCaseId, role: "PARTICIPANT_A", claim: localClaim, salt: saltB,
  });
  assert.equal(base, CLAIM_COMMITMENT_GOLDEN);
  assert.notEqual(base, secondSalt);
  for (const claim of [
    { ...localClaim, activeUntil: 401 },
    { ...localClaim, amount: [0, 0, 0, 100_000_001] as const },
    { ...localClaim, currency: bytes32("54") },
    { ...localClaim, obligationId: bytes32("55") },
    { ...localClaim, receivableId: bytes32("56") },
    { ...localClaim, exclusive: false },
  ]) {
    assert.notEqual(participantOriginatedClaimCommitment({
      runId: RUN_ID, fheCaseId: bundle.fheCaseId, role: "PARTICIPANT_A", claim, salt: saltA,
    }), base);
  }
  assert.throws(
    () => participantOriginatedClaimCommitment({
      runId: RUN_ID,
      fheCaseId: bundle.fheCaseId,
      role: "PARTICIPANT_A",
      claim: { ...localClaim, receivableCommitment: bytes32("57") },
      salt: saltA,
    }),
    (error: unknown) => error instanceof ParticipantOriginatedAuthorizationError
      && error.code === "CLAIM_RECEIVABLE_COMMITMENT",
  );
  const generatedA = generateParticipantClaimSalt();
  const generatedB = generateParticipantClaimSalt();
  assert.match(generatedA, /^0x[0-9a-f]{64}$/u);
  assert.notEqual(generatedA, generatedB);
  assert.match(PARTICIPANT_ORIGINATED_SEMANTIC_GAP, /not.*encrypted claim.*commitment preimage/iu);
});

test("the raw participant signing public key has a fixed SHA-256 digest vector", () => {
  assert.equal(SIGNING_KEY_DIGEST, SIGNING_KEY_DIGEST_GOLDEN);
});

test("coordinator request parsers reject extras, raw windows, claims, salts and preimages", async () => {
  const values = await fixture();
  const requests = [
    await registrationRequest(),
    await intentRequest(values.intent.intent),
    await finalRequest(values.admission),
  ] as const;
  assert.deepEqual(assertParticipantSigningKeyRegistrationRequest(requests[0]), requests[0]);
  assert.deepEqual(assertParticipantEncryptionIntentRequest(requests[1]), requests[1]);
  assert.deepEqual(assertParticipantFinalEncryptedAdmissionRequest(requests[2]), requests[2]);
  for (const request of requests) {
    for (const [field, secret] of [
      ["activeFrom", 100], ["activeUntil", 400], ["claim", localClaim], ["salt", bytes32("71")],
      ["claimPreimage", localClaim], ["participantSigningPrivateKey", bytes32("77")],
    ] as const) {
      if ("registration" in request) {
        const injected = { ...request, registration: { ...request.registration, [field]: secret } };
        assert.throws(
          () => assertParticipantSigningKeyRegistrationRequest(injected),
          ParticipantOriginatedAuthorizationError,
        );
      } else if ("intent" in request) {
        const injected = { ...request, intent: { ...request.intent, [field]: secret } };
        assert.throws(
          () => assertParticipantEncryptionIntentRequest(injected),
          ParticipantOriginatedAuthorizationError,
        );
      } else {
        const injected = { ...request, admission: { ...request.admission, [field]: secret } };
        assert.throws(
          () => assertParticipantFinalEncryptedAdmissionRequest(injected),
          ParticipantOriginatedAuthorizationError,
        );
      }
    }
    const encoded = JSON.stringify(request);
    for (const forbidden of ["activeFrom", "activeUntil", "claimPreimage", "participantSigningPrivateKey", bytes32("71")]) {
      assert.equal(encoded.includes(forbidden), false, `coordinator request leaked ${forbidden}`);
    }
  }
});

test("each phase digest is chain-separated and changes when a security field changes", async () => {
  const values = await fixture();
  const registration = registrationMessage();
  const intent = values.intent.intent;
  const admission = values.admission;
  assert.notEqual(participantSigningKeyRegistrationDigest(registration, CHAIN_ID),
    participantSigningKeyRegistrationDigest(registration, 1));
  assert.notEqual(participantEncryptionIntentDigest(intent, CHAIN_ID), participantEncryptionIntentDigest(intent, 1));
  assert.notEqual(participantFinalEncryptedAdmissionDigest(admission, CHAIN_ID),
    participantFinalEncryptedAdmissionDigest(admission, 1));

  for (const mutation of [
    { runId: OTHER_RUN_ID }, { fheCaseId: bytes32("81") }, { assetIdentityDigest: bytes32("82") },
    { policyDigest: bytes32("83") }, { role: "PARTICIPANT_B" as const },
    { participantWallet: attacker.address }, { participantSigningPublicKey: bytes32("84") },
    { participantSigningKeyDigest: bytes32("85") }, { registrationNonce: bytes32("86") },
    { expiresAt: registration.expiresAt - 1 },
  ]) assert.notEqual(participantSigningKeyRegistrationDigest({ ...registration, ...mutation }),
    participantSigningKeyRegistrationDigest(registration));

  for (const mutation of [
    { caseBindingDigest: bytes32("81") }, { protectionBindingDigest: bytes32("82") },
    { circuitId: "wrong-circuit" }, { circuitVersion: 6 }, { circuitDigest: bytes32("83") },
    { parameterProfile: "wrong-profile" }, { parameterFingerprint: bytes32("84") },
    { fhePublicKeyDigest: bytes32("85") }, { releaseAuthorityId: bytes32("86") },
    { releaseMode: "wrong-release" }, { participantSigningKeyDigest: bytes32("87") },
    { registrationDigest: bytes32("88") }, { claimCommitment: bytes32("89") },
    { clientBundleDigest: bytes32("8a") }, { clientSourceDigest: bytes32("8b") },
    { clientBuildDigest: bytes32("8c") }, { clientBinaryDigest: bytes32("8d") },
    { intentNonce: bytes32("8e") }, { expiresAt: intent.expiresAt - 1 },
  ]) assert.notEqual(participantEncryptionIntentDigest({ ...intent, ...mutation }),
    participantEncryptionIntentDigest(intent));

  for (const mutation of [
    { encryptionIntentDigest: bytes32("91") }, { claimCommitment: bytes32("92") },
    { encryptedArtifactDigest: bytes32("93") }, { ciphertextObjectDigest: bytes32("94") },
    { ciphertextObjectLength: admission.ciphertextObjectLength + 1 }, { submissionNonce: bytes32("95") },
    { clientBundleDigest: bytes32("96") }, { participantSigningKeyDigest: bytes32("97") },
  ]) assert.notEqual(participantFinalEncryptedAdmissionDigest({ ...admission, ...mutation }),
    participantFinalEncryptedAdmissionDigest(admission));
});

test("phase 0 and phase 1 reject wrong signers, key digests and all pinned bundle substitutions", async () => {
  const badKeyMessage = registrationMessage({ participantSigningKeyDigest: bytes32("a1") });
  await refusal(
    verifyParticipantSigningKeyRegistration(await registrationRequest(badKeyMessage), registrationExpected()),
    "REGISTRATION_SIGNING_KEY_DIGEST",
  );
  await refusal(
    verifyParticipantSigningKeyRegistration(await registrationRequest(registrationMessage(), attacker), registrationExpected()),
    "REGISTRATION_SIGNATURE_REJECTED",
  );
  const registration = await verifyParticipantSigningKeyRegistration(await registrationRequest(), registrationExpected());
  const base = intentMessage(registration.registrationDigest);
  const substitutions: ReadonlyArray<Partial<ParticipantEncryptionIntentMessage>> = [
    { runId: OTHER_RUN_ID }, { fheCaseId: bytes32("a2") }, { caseBindingDigest: bytes32("a3") },
    { protectionBindingDigest: bytes32("a4") }, { assetIdentityDigest: bytes32("a5") },
    { policyDigest: bytes32("a6") }, { circuitId: "wrong-circuit" }, { circuitVersion: 6 },
    { circuitDigest: bytes32("a7") }, { parameterProfile: "wrong-profile" },
    { parameterFingerprint: bytes32("a8") }, { fhePublicKeyDigest: bytes32("a9") },
    { releaseAuthorityId: bytes32("aa") }, { releaseMode: "wrong-mode" },
    { role: "PARTICIPANT_B" }, { participantWallet: attacker.address },
    { participantSigningKeyDigest: bytes32("ab") }, { registrationDigest: bytes32("ac") },
    { clientBundleDigest: bytes32("ad") }, { clientSourceDigest: bytes32("ae") },
    { clientBuildDigest: bytes32("af") }, { clientBinaryDigest: bytes32("b1") },
  ];
  for (const substitution of substitutions) {
    const changed = { ...base, ...substitution };
    await refusal(verifyParticipantEncryptionIntent(
      await intentRequest(changed),
      intentExpected(registration),
    ));
  }
});

test("phase 2 compares wallet declarations with recomputed artifact/ciphertext facts", async () => {
  const values = await fixture();
  for (const artifactMutation of [
    { encryptedArtifactDigest: bytes32("c1") },
    { ciphertextObjectDigest: bytes32("c2") },
    { ciphertextObjectLength: values.artifact.ciphertextObjectLength + 1 },
    { submissionNonce: bytes32("c3") },
    { fheCaseId: bytes32("c4") },
    { role: "PARTICIPANT_B" as const },
    { participantSigningKeyDigest: bytes32("c5") },
    { parameterProfile: "wrong-profile" },
    { parameterFingerprint: bytes32("c6") },
    { fhePublicKeyDigest: bytes32("c7") },
    { circuitDigest: bytes32("c8") },
    { embeddedEncryptionIntentDigest: bytes32("c9") },
    { embeddedClaimCommitment: bytes32("ca") },
  ]) {
    await refusal(verifyParticipantFinalEncryptedAdmission(
      await finalRequest(values.admission),
      { ...values.expected, artifact: { ...values.artifact, ...artifactMutation } },
    ));
  }
  await refusal(
    verifyParticipantFinalEncryptedAdmission(await finalRequest(values.admission, attacker), values.expected),
    "FINAL_ADMISSION_SIGNATURE_REJECTED",
  );
});

test("a durable nonce guard rejects final-admission replay", async () => {
  const values = await fixture();
  const request = await finalRequest(values.admission);
  const seen = new Set<string>();
  const guard: ParticipantOriginatedNonceGuard = async ({ phase, runId, role, nonce }) => {
    const key = `${phase}/${runId}/${role}/${nonce}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  };
  await verifyParticipantFinalEncryptedAdmission(request, values.expected, undefined, guard);
  await refusal(
    verifyParticipantFinalEncryptedAdmission(request, values.expected, undefined, guard),
    "FINAL_ADMISSION_REPLAY",
  );
});

test("expired registrations, intents, bundles, artifacts and final admissions fail closed", async () => {
  await refusal(
    verifyParticipantSigningKeyRegistration(await registrationRequest(), registrationExpected({ now: T0 + 300 })),
    "REGISTRATION_EXPIRED",
  );
  const values = await fixture();
  await refusal(verifyParticipantEncryptionIntent(
    await intentRequest(values.intent.intent),
    intentExpected(values.registration, { now: values.registration.registration.expiresAt }),
  ), "REGISTRATION_EXPIRED");
  await refusal(verifyParticipantEncryptionIntent(
    await intentRequest(intentMessage(values.registration.registrationDigest, { issuedAt: T0 - 1 })),
    intentExpected(values.registration),
  ), "INTENT_REGISTRATION_WINDOW");
  await refusal(verifyParticipantEncryptionIntent(
    await intentRequest(intentMessage(values.registration.registrationDigest, { expiresAt: T0 + 301 })),
    intentExpected(values.registration),
  ), "INTENT_REGISTRATION_WINDOW");
  await refusal(verifyParticipantEncryptionIntent(
    await intentRequest(values.intent.intent),
    intentExpected(values.registration, { now: values.intent.intent.expiresAt }),
  ), "INTENT_EXPIRED");
  await refusal(verifyParticipantEncryptionIntent(
    await intentRequest(values.intent.intent),
    intentExpected(values.registration, { bundleExpiresAt: T0 + 14, now: T0 + 15 }),
  ));
  await refusal(verifyParticipantFinalEncryptedAdmission(
    await finalRequest(values.admission),
    { ...values.expected, artifact: { ...values.artifact, expiresAt: values.expected.now } },
  ), "ARTIFACT_EXPIRED");
  const expiredMessage = { ...values.admission, expiresAt: values.expected.now };
  await refusal(verifyParticipantFinalEncryptedAdmission(
    await finalRequest(expiredMessage),
    values.expected,
  ), "FINAL_ADMISSION_EXPIRED");
});
