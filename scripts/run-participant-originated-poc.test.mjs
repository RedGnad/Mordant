import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  PARTICIPANT_ORIGINATED_IMPORT_REQUEST_SCHEMA,
  PARTICIPANT_ORIGINATED_POC_STARTING_SHA,
  assertGoArtifactVerificationMatches,
  buildGoImportRequest,
  buildNeutralFoundationSpec,
  buildPocDryRunPlan,
  buildTransportMetadata,
  bundleContextFrom,
  bytes32ToGoDigest,
  canonicalJson,
  experimentalReceiptDigest,
  goDigestToBytes32,
  minimalChildEnvironment,
  scanCoordinatorState,
  validateGoArtifactVerification,
} from "./run-participant-originated-poc.mjs";

const hex = (character) => `0x${character.repeat(64)}`;
const go = (character) => `sha256:${character.repeat(64)}`;

test("digest bridges keep SHA-256 and EIP bytes32 representations explicit", () => {
  assert.equal(goDigestToBytes32(go("a")), hex("a"));
  assert.equal(bytes32ToGoDigest(hex("b")), go("b"));
  assert.throws(() => goDigestToBytes32(hex("a")), /invalid Go SHA-256 digest/u);
  assert.throws(() => bytes32ToGoDigest(go("a")), /invalid bytes32 digest/u);
  assert.match(PARTICIPANT_ORIGINATED_POC_STARTING_SHA, /^[0-9a-f]{40}$/u);
});

test("Go import mapping separates the semantic artifact digest from newline-bearing object bytes", () => {
  const metadata = {
    role: "PARTICIPANT_A",
    fheCaseId: hex("1"),
    participantSigningKeyDigest: hex("2"),
    clientBundleDigest: hex("3"),
    encryptionIntentDigest: hex("4"),
    claimCommitment: hex("5"),
    submissionNonce: hex("6"),
    encryptedArtifactDigest: hex("7"),
    ciphertextObjectDigest: hex("8"),
    ciphertextObjectLength: 123,
    finalAdmissionDigest: hex("9"),
    artifactObjectDigest: hex("a"),
    artifactObjectLength: 456,
  };
  const mapped = buildGoImportRequest(metadata, { assetIdentityDigest: hex("b"), caseBindingDigest: hex("c") });
  assert.equal(mapped.schemaVersion, PARTICIPANT_ORIGINATED_IMPORT_REQUEST_SCHEMA);
  assert.equal(mapped.encryptedArtifactDigest, hex("7"));
  assert.deepEqual(mapped.artifactObject, { path: "submission-a.json", sha256: go("a"), length: 456 });
  assert.deepEqual(mapped.ciphertextObject, { path: "submission-a.bin", sha256: go("8"), length: 123 });
  assert.notEqual(mapped.artifactObject.sha256, bytes32ToGoDigest(mapped.encryptedArtifactDigest));
});

test("transport mapping retains only the signed chain and exact public object facts", () => {
  const registration = {
    schemaVersion: "registration/1",
    registration: { registrationNonce: hex("1") },
    signature: "0x12",
  };
  const intent = {
    schemaVersion: "intent/1",
    intent: { intentNonce: hex("2") },
    signature: "0x34",
  };
  const admission = {
    runId: "11111111-1111-4111-8111-111111111111",
    fheCaseId: hex("3"), role: "PARTICIPANT_A", participantWallet: `0x${"ab".repeat(20)}`,
    participantSigningKeyDigest: hex("4"), registrationDigest: hex("5"), encryptionIntentDigest: hex("6"),
    claimCommitment: hex("7"), clientBundleDigest: hex("8"), encryptedArtifactDigest: hex("9"),
    ciphertextObjectDigest: hex("a"), ciphertextObjectLength: 12, submissionNonce: hex("b"),
    issuedAt: 100, expiresAt: 200,
  };
  const final = { schemaVersion: "final/1", admission, signature: "0x56" };
  const metadata = buildTransportMetadata({
    registrationRequest: registration,
    intentRequest: intent,
    finalRequest: final,
    finalDigest: hex("c"),
    prepared: {
      artifactObject: { path: "submission-a.json", sha256: go("d"), length: 90 },
      ciphertextObject: { path: "submission-a.bin", sha256: go("a"), length: 12 },
    },
  });
  assert.equal(metadata.artifactObjectDigest, hex("d"));
  assert.equal(metadata.encryptedArtifactDigest, hex("9"));
  assert.equal(metadata.walletAuthorizationChain.finalAdmission.message, admission);
  assert.equal(canonicalJson(metadata).includes("activeFrom"), false);
  assert.equal(canonicalJson(metadata).includes("privateKey"), false);
});

test("strict Go verification bridge rejects missing or malformed recomputed facts", () => {
  const reference = (path, character, length) => ({ path, sha256: go(character), length });
  const verification = {
    schemaVersion: "mordant.participant-originated-artifact-verification/1",
    role: "PARTICIPANT_A",
    caseId: go("1"), assetIdentity: go("2"), caseBindingDigest: go("3"), participantId: go("4"),
    signingKeyDigest: go("5"), bundleDigest: go("6"), parameterProfile: "profile/1",
    parameterFingerprint: go("7"), fhePublicKeyDigest: go("8"), circuitDigest: go("9"),
    encryptionIntentDigest: hex("a"), claimCommitment: go("b"), submissionNonce: go("c"),
    artifactDigest: go("d"), ciphertextDigest: go("e"), finalEncryptedAdmissionDigest: hex("f"),
    artifactObject: reference("submission-a.json", "0", 300),
    ciphertextObject: reference("submission-a.bin", "e", 400),
    expiresAtUnix: 2_000_000_000,
    verifiedAtUnix: 1_900_000_000,
  };
  assert.equal(validateGoArtifactVerification(verification), verification);
  const missing = { ...verification };
  delete missing.parameterFingerprint;
  assert.throws(() => validateGoArtifactVerification(missing), /verification shape rejected/u);
  assert.throws(() => validateGoArtifactVerification({ ...verification, fhePublicKeyDigest: hex("8") }), /invalid Go SHA-256 digest/u);
  assert.throws(() => validateGoArtifactVerification({ ...verification, ciphertextObject: reference("replacement.bin", "e", 400) }), /object reference rejected/u);
  const metadata = {
    role: "PARTICIPANT_A", fheCaseId: hex("1"), participantSigningKeyDigest: hex("5"), clientBundleDigest: hex("6"),
    encryptionIntentDigest: hex("a"), claimCommitment: hex("b"), submissionNonce: hex("c"), encryptedArtifactDigest: hex("d"),
    ciphertextObjectDigest: hex("e"), finalAdmissionDigest: hex("f"), artifactObjectDigest: hex("0"), artifactObjectLength: 300,
    ciphertextObjectLength: 400, expiresAt: 2_000_000_000,
  };
  const context = {
    assetIdentityDigest: hex("2"), caseBindingDigest: hex("3"), parameterProfile: "profile/1",
    parameterFingerprint: hex("7"), fhePublicKeyDigest: hex("8"), circuitDigest: hex("9"),
  };
  assert.equal(assertGoArtifactVerificationMatches(metadata, context, verification), verification);
  assert.throws(
    () => assertGoArtifactVerificationMatches(metadata, context, { ...verification, bundleDigest: go("0") }),
    /did not match authenticated transport facts/u,
  );
});

test("neutral case derivation is deterministic when its public nonce is pinned", () => {
  const participantA = { participantSigningPublicKey: hex("1") };
  const participantB = { participantSigningPublicKey: hex("2") };
  const options = { label: "dry", participantA, participantB, nowSeconds: 1_900_000_000, caseNonce: go("3") };
  const first = buildNeutralFoundationSpec(options);
  const second = buildNeutralFoundationSpec(options);
  assert.deepEqual(first, second);
  assert.equal(first.spec.protectionBinding.productScenario, undefined);
  assert.equal(first.spec.protectionBinding.executionVariant, "CUSTOM_SUPERVISED");
});

test("bundle-to-authorization context maps every Go digest without algorithm-label ambiguity", () => {
  const bundle = {
    runId: "run", role: "PARTICIPANT_B", caseId: go("1"), caseBindingDigest: go("2"),
    protectionBindingDigest: go("3"), assetIdentity: go("4"), policyId: go("5"),
    circuitId: "circuit", circuitVersion: 5, circuitDigest: go("6"), parameterProfile: "profile",
    parameterFingerprint: go("7"), fhePublicKeyDigest: go("8"), releaseAuthorityId: go("9"),
    releaseMode: "governed-decryptor-v1", expectedSourceDigest: go("a"),
    expectedBuildManifestDigest: go("b"), expectedClientBinaryDigest: go("c"), expiresAtUnix: 2_000_000_000,
  };
  const context = bundleContextFrom(bundle, { runId: "run", role: "PARTICIPANT_B", bundleDigest: go("d") }, `0x${"12".repeat(20)}`);
  assert.equal(context.fheCaseId, hex("1"));
  assert.equal(context.clientBundleDigest, hex("d"));
  assert.equal(context.clientSourceDigest, hex("a"));
});

test("dry plan declares two real, sequential cases and no expensive execution", () => {
  const plan = buildPocDryRunPlan("/ABS/poc");
  assert.equal(plan.executesExpensiveFhe, false);
  assert.deepEqual(plan.cases.map(({ name, expectedConflict }) => [name, expectedConflict]), [
    ["conflict", true],
    ["adjacent-no-conflict", false],
  ]);
  assert.deepEqual(plan.cases[0].importOrder, ["ciphertext", "artifact-manifest"]);
  assert.match(plan.cases[0].topology.isolationQualification, /does not claim an ACL/u);
});

test("coordinator scan allows commitments but detects plaintext keys and exact local secret sequences", async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), "mordant-poc-scan-"));
  const coordinator = join(fixtureRoot, "coordinator");
  const participant = join(fixtureRoot, "participant-a");
  mkdirSync(coordinator);
  mkdirSync(participant);
  const secret = Buffer.from("participant-local-secret-sequence");
  const secretPath = join(participant, "claim-salt.bin");
  writeFileSync(secretPath, secret);
  writeFileSync(join(coordinator, "safe.json"), JSON.stringify({ claimCommitment: hex("1"), ciphertext: "opaque" }));
  const safe = scanCoordinatorState(coordinator, [participant], [{ label: "claim-salt-a", path: secretPath }]);
  assert.equal(safe.passed, true);
  assert.equal(safe.byteChecks.find(({ label }) => label === "claim-salt-a").matchCount, 0);
  writeFileSync(join(coordinator, "bad.json"), JSON.stringify({ activeFrom: 100, payload: secret.toString("utf8") }));
  const unsafe = scanCoordinatorState(coordinator, [participant], [{ label: "claim-salt-a", path: secretPath }]);
  assert.equal(unsafe.passed, false);
  assert.equal(unsafe.byteChecks.find(({ label }) => label === "claim-salt-a").matchCount, 1);
  assert.equal(unsafe.forbiddenContents[0].member, "$.activeFrom");
});

test("child environment is an allowlist and never inherits repository secrets", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-poc-env-"));
  const environment = minimalChildEnvironment(root);
  assert.deepEqual(Object.keys(environment).sort(), Object.keys(environment).filter((name) => ["PATH", "TMPDIR", "LANG", "LC_ALL", "GOTOOLCHAIN", "GOCACHE", "GOMODCACHE", "GOPATH"].includes(name)).sort());
  assert.equal("DATABASE_URL" in environment, false);
  assert.equal("PRIVATE_KEY" in environment, false);
  assert.equal(environment.TMPDIR, root);
  assert.equal(typeof environment.GOMODCACHE, "string");
  assert.equal(typeof environment.GOPATH, "string");
});

test("experimental receipt digest is recalculable with its digest member omitted", () => {
  const body = { schemaVersion: "receipt/1", startingSha: PARTICIPANT_ORIGINATED_POC_STARTING_SHA, cases: [] };
  const digest = experimentalReceiptDigest(body);
  assert.match(digest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(experimentalReceiptDigest({ ...body, receiptDigest: digest }), digest);
  assert.notEqual(experimentalReceiptDigest({ ...body, cases: [{ conflict: true }], receiptDigest: digest }), digest);
});
