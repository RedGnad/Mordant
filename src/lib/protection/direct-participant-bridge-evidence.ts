/**
 * Bridge authorization evidence for a qualified direct-participant run.
 *
 * This is NOT `mordant.protection-evidence/4` and must never be confused with
 * it. A direct-participant run is a CUSTOM_SUPERVISED run: it has no
 * `binding.productScenario`, so it cannot honestly produce V4 evidence, and
 * widening V4 to admit it was refused. This schema is the separate, server-side
 * artifact that lets such a run authorize a bridge payload without any V4
 * contract, `assertPublicProtectionEvidence`, `EXPECTED_GOVERNED_FHE_COMMIT`,
 * Go schema, BGV circuit or Ed25519 semantics being touched.
 *
 * What makes it safe to trust is not this file's shape but what it carries: the
 * COMPLETE `GovernedSignedResult` exactly as the decryptor published it,
 * signature included. Every terminal value the bridge needs is read back out of
 * that signed object and verified against it here. Nothing in this artifact can
 * introduce a Boolean, a digest or a holder that the governed authority did not
 * sign, because the verifier re-derives them from the signature it checks.
 *
 * The custom receipt keeps its own role as the product receipt. This artifact is
 * never served publicly.
 */

import { createHash } from "node:crypto";

import { recoverTypedDataAddress } from "viem";

import { canonicalJson, type Sha256Digest } from "./cleanverse-asset";
import {
  assertParticipantAdmissionMessage,
  digestToBytes32,
  participantAdmissionDigest,
  participantAdmissionTypedData,
} from "./participant-authorization";
import { CUSTOM_SUPERVISED_EXECUTION_VARIANT } from "./custom-supervised-v2";
import {
  assertReleaseAuthorityIdentity,
  governedResultDigest,
  verifyGovernedResultSignature,
  type GovernedSignedResult,
} from "./protection-evidence";

export const DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA =
  "mordant.direct-participant-bridge-evidence/1" as const;

export const DIRECT_PARTICIPANT_ROLES = ["PARTICIPANT_A", "PARTICIPANT_B"] as const;
export type DirectParticipantRole = (typeof DIRECT_PARTICIPANT_ROLES)[number];

/**
 * The durable admission facts for one role. Only commitments and observations:
 * the entered interval and the raw pledge never appear here, and the wallet's
 * key is not touched by this module at all.
 */
export type DirectParticipantAdmissionFact = Readonly<{
  role: DirectParticipantRole;
  participantWallet: string;
  authorizationDigest: string;
  claimCommitment: string;
  authorizationNonce: string;
  chainId: number;
  eligibilityBlock: number;
  /**
   * The exact ParticipantAdmissionV1 struct the wallet signed, and its signature.
   *
   * Without these an admission is only an assertion that a digest once existed,
   * which a holder of the evidence file could simply write. With them the
   * authorization is independently re-provable after the run is pruned, which is
   * why settlement requires them.
   */
  authorization?: Readonly<Record<string, unknown>>;
  signature?: string;
}>;

export type VerifiedAdmissionProof = Readonly<{
  role: DirectParticipantRole;
  wallet: string;
  recoveredSigner: string;
  authorizationDigest: string;
}>;

/**
 * Re-proves one wallet admission offline.
 *
 * Recovery is ECDSA over the exact typed data, so it answers for EOAs only. The
 * canonical participants are EOAs; a smart-account participant would need its
 * ERC-1271 answer read from chain, and this deliberately does not pretend to
 * cover that case.
 */
export async function assertParticipantAdmissionProof(
  fact: DirectParticipantAdmissionFact,
  expected: Readonly<{ runId: string; fheCaseId: Sha256Digest; protectionBindingDigest: Sha256Digest }>,
): Promise<VerifiedAdmissionProof> {
  if (fact.authorization === undefined || typeof fact.signature !== "string") {
    fail("ADMISSION_PROOF_MISSING", `${fact.role} carries no signed admission authorization`);
  }
  if (!/^0x[0-9a-fA-F]{130}$/u.test(fact.signature)) {
    fail("ADMISSION_PROOF_SIGNATURE", `${fact.role} admission signature has an unexpected shape`);
  }
  const message = assertParticipantAdmissionMessage(fact.authorization);

  // Every field the wallet signed must be the field this run is acting on.
  if (message.role !== fact.role) fail("ADMISSION_PROOF_ROLE", "The signed admission is for a different role");
  if (message.participantWallet.toLowerCase() !== fact.participantWallet.toLowerCase()) {
    fail("ADMISSION_PROOF_WALLET", "The signed admission is for a different wallet");
  }
  if (message.runId !== expected.runId) fail("ADMISSION_PROOF_RUN", "The signed admission is for a different run");
  if (message.fheCaseId !== digestToBytes32(expected.fheCaseId)) {
    fail("ADMISSION_PROOF_CASE", "The signed admission is for a different FHE case");
  }
  if (message.protectionBindingDigest !== digestToBytes32(expected.protectionBindingDigest)) {
    fail("ADMISSION_PROOF_BINDING", "The signed admission is for a different protection binding");
  }
  if (message.authorizationNonce.toLowerCase() !== fact.authorizationNonce.toLowerCase()) {
    fail("ADMISSION_PROOF_NONCE", "The signed admission carries a different nonce");
  }
  if (fact.chainId !== 10_143) fail("ADMISSION_PROOF_CHAIN", "The admission is not bound to Monad testnet");

  const digest = participantAdmissionDigest(message, fact.chainId);
  if (digest.toLowerCase() !== fact.authorizationDigest.toLowerCase()) {
    fail("ADMISSION_PROOF_DIGEST", "The retained authorization digest is not the digest of the signed struct");
  }

  let recovered: string;
  try {
    // Exactly the struct the server built for signing, so the browser and the
    // verifier cannot disagree about what was authorized.
    recovered = await recoverTypedDataAddress({
      ...participantAdmissionTypedData(message, fact.chainId),
      signature: fact.signature as `0x${string}`,
    });
  } catch {
    fail("ADMISSION_PROOF_SIGNATURE", `${fact.role} admission signature could not be recovered`);
  }
  if (recovered.toLowerCase() !== fact.participantWallet.toLowerCase()) {
    fail("ADMISSION_PROOF_SIGNER", "The admission was signed by a different wallet");
  }
  return Object.freeze({
    role: fact.role,
    wallet: fact.participantWallet,
    recoveredSigner: recovered,
    authorizationDigest: fact.authorizationDigest,
  });
}

/** The fresh FHE case binding fields the governed result must agree with. */
export type DirectParticipantCaseBinding = Readonly<{
  caseId: Sha256Digest;
  assetIdentity: Sha256Digest;
  policyId: Sha256Digest;
  circuitDigest: Sha256Digest;
  parameterFingerprint: Sha256Digest;
  releaseMode: "governed-decryptor-v1";
  releaseAuthorityId: Sha256Digest;
  releaseAuthorityPublicKey: string;
}>;

export type DirectParticipantBridgeEvidence = Readonly<{
  schemaVersion: typeof DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA;
  evidenceDigest: Sha256Digest;
  sourceCommit: string;
  runId: string;
  executionVariant: typeof CUSTOM_SUPERVISED_EXECUTION_VARIANT;
  fheCaseId: Sha256Digest;
  protectionBindingDigest: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  caseBinding: DirectParticipantCaseBinding;
  participants: readonly [DirectParticipantAdmissionFact, DirectParticipantAdmissionFact];
  participantArtifactDigestA: Sha256Digest;
  participantArtifactDigestB: Sha256Digest;
  evaluatedArtifactDigest: Sha256Digest;
  governedResultDigest: Sha256Digest;
  /** The decryptor's published object, byte-for-byte, signature included. */
  governedResult: GovernedSignedResult;
  customReceiptDigest: Sha256Digest;
}>;

/**
 * Names that must never appear in this artifact. The pledge intervals are
 * private execution input, and no key or local path has any business here.
 */
const FORBIDDEN_KEYS = Object.freeze([
  "activeFrom", "activeUntil", "supervisedPledgeWindows", "pledges", "pledge", "claim",
  "privateKey", "signingKey", "secretKey", "decryptorPrivate", "participantPrivate",
  "attestorPrivateKey", "path", "root", "publicRoot", "privateRoot",
]);

const EVIDENCE_FIELDS = Object.freeze([
  "schemaVersion", "evidenceDigest", "sourceCommit", "runId", "executionVariant", "fheCaseId",
  "protectionBindingDigest", "caseBindingDigest", "caseBinding", "participants",
  "participantArtifactDigestA", "participantArtifactDigestB", "evaluatedArtifactDigest",
  "governedResultDigest", "governedResult", "customReceiptDigest",
]);

const ADMISSION_FIELDS = Object.freeze([
  "role", "participantWallet", "authorizationDigest", "claimCommitment",
  "authorizationNonce", "chainId", "eligibilityBlock",
]);
/** Records written after the admission-proof hardening carry two more members. */
const ADMISSION_FIELDS_WITH_PROOF = Object.freeze([...ADMISSION_FIELDS, "authorization", "signature"]);

const CASE_BINDING_FIELDS = Object.freeze([
  "caseId", "assetIdentity", "policyId", "circuitDigest", "parameterFingerprint",
  "releaseMode", "releaseAuthorityId", "releaseAuthorityPublicKey",
]);

export class DirectParticipantBridgeEvidenceError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "DirectParticipantBridgeEvidenceError";
  }
}

function fail(code: string, message: string): never {
  throw new DirectParticipantBridgeEvidenceError(code, message);
}

function exactKeys(value: unknown, expected: readonly string[], code: string, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(code, `${label} must be an object`);
  }
  const actual = Object.keys(value as object).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || !actual.every((key, index) => key === wanted[index])) {
    fail(code, `${label} fields are not exact`);
  }
  return value as Record<string, unknown>;
}

function digest(value: unknown, code: string, label: string): Sha256Digest {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail(code, `${label} must be a sha256 digest`);
  }
  return value as Sha256Digest;
}

function bytes32Hex(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/u.test(value)) {
    fail(code, `${label} must be a lowercase 32-byte hex value`);
  }
  return value;
}

function address(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) {
    fail(code, `${label} must be an address`);
  }
  return value;
}

function wholeNumber(value: unknown, code: string, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(code, `${label} must be a whole number`);
  }
  return value;
}

function exactCommit(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
    fail(code, `${label} must be a full lowercase commit id`);
  }
  return value;
}

export function directParticipantBridgeEvidenceDigest(
  evidence: Omit<DirectParticipantBridgeEvidence, "evidenceDigest">,
): Sha256Digest {
  const encoded = `MordantDirectParticipantBridgeEvidence/v1\0${canonicalJson(evidence)}`;
  return `sha256:${createHash("sha256").update(encoded).digest("hex")}`;
}

/** Everything the verifier must be told from outside the artifact itself. */
export type DirectParticipantBridgeExpectations = Readonly<{
  /** The source commit of the checkout that executed the run. */
  sourceCommit: string;
  /** The canonical receivable this product protects. */
  assetIdentity: Sha256Digest;
  /** Canonical controlled participant wallets, from committed configuration. */
  holderA: string;
  holderB: string;
  /** Wallets that must never appear as a participant, whatever their A-Pass says. */
  excludedWallets: readonly string[];
  /** Optional: the run this evidence must belong to. */
  runId?: string;
}>;

export type VerifiedDirectParticipantBridgeEvidence = Readonly<{
  evidence: DirectParticipantBridgeEvidence;
  /** Read out of the verified signature, never from a field or a caller. */
  conflict: boolean;
  governedResult: GovernedSignedResult;
  holderA: string;
  holderB: string;
}>;

/**
 * Independent, exact verification.
 *
 * Order matters: shape, then provenance, then the Ed25519 signature, then every
 * cross-reference against the signed object, then the wallet admissions. The
 * terminal Boolean is returned only from the signed result, after its signature
 * has been checked, so no caller and no stored field can supply one.
 */
export function assertDirectParticipantBridgeEvidence(
  value: unknown,
  expectations: DirectParticipantBridgeExpectations,
): VerifiedDirectParticipantBridgeEvidence {
  // 1 — exact schema fields.
  const raw = exactKeys(value, EVIDENCE_FIELDS, "EVIDENCE_FIELDS", "bridge evidence");
  if (raw.schemaVersion !== DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA) {
    fail("SCHEMA", "Unsupported direct-participant bridge evidence schema");
  }
  // 3 — the artifact only ever describes a custom-supervised run.
  if (raw.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
    fail("EXECUTION_VARIANT", "Direct-participant bridge evidence must declare CUSTOM_SUPERVISED");
  }
  const evidence = value as DirectParticipantBridgeEvidence;

  // The digest covers every other field, so a later edit to any of them is caught here.
  const { evidenceDigest, ...body } = evidence;
  if (digest(evidenceDigest, "EVIDENCE_DIGEST", "evidenceDigest")
    !== directParticipantBridgeEvidenceDigest(body)) {
    fail("EVIDENCE_DIGEST", "Direct-participant bridge evidence digest mismatch");
  }

  // 2 — provenance is an exact commit and must be the executing checkout.
  const sourceCommit = exactCommit(raw.sourceCommit, "SOURCE_COMMIT", "sourceCommit");
  if (sourceCommit !== exactCommit(expectations.sourceCommit, "SOURCE_COMMIT_PIN", "expected sourceCommit")) {
    fail("SOURCE_COMMIT", "Bridge evidence source commit disagrees with the execution source commit");
  }
  if (typeof raw.runId !== "string"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(raw.runId)) {
    fail("RUN_ID", "Bridge evidence run id rejected");
  }
  if (expectations.runId !== undefined && raw.runId !== expectations.runId) {
    fail("RUN_ID", "Bridge evidence belongs to a different run");
  }

  const fheCaseId = digest(raw.fheCaseId, "CASE_ID", "fheCaseId");
  const protectionBindingDigest = digest(raw.protectionBindingDigest, "PROTECTION_BINDING", "protectionBindingDigest");
  const caseBindingDigest = digest(raw.caseBindingDigest, "CASE_BINDING", "caseBindingDigest");
  const participantArtifactDigestA = digest(raw.participantArtifactDigestA, "ARTIFACT_A", "participantArtifactDigestA");
  const participantArtifactDigestB = digest(raw.participantArtifactDigestB, "ARTIFACT_B", "participantArtifactDigestB");
  const evaluatedArtifactDigest = digest(raw.evaluatedArtifactDigest, "EVALUATED", "evaluatedArtifactDigest");
  const declaredResultDigest = digest(raw.governedResultDigest, "RESULT_DIGEST", "governedResultDigest");
  digest(raw.customReceiptDigest, "RECEIPT_DIGEST", "customReceiptDigest");
  if (protectionBindingDigest === caseBindingDigest) {
    fail("BINDING_DISTINCT", "The protection binding and the FHE case binding must be distinct digests");
  }
  if (participantArtifactDigestA === participantArtifactDigestB) {
    fail("ARTIFACTS_DISTINCT", "The two participant artifacts must be distinct");
  }

  const binding = exactKeys(raw.caseBinding, CASE_BINDING_FIELDS, "CASE_BINDING_FIELDS", "caseBinding");
  const bindingCaseId = digest(binding.caseId, "CASE_BINDING", "caseBinding.caseId");
  const bindingAsset = digest(binding.assetIdentity, "CASE_BINDING", "caseBinding.assetIdentity");
  const bindingCircuit = digest(binding.circuitDigest, "CASE_BINDING", "caseBinding.circuitDigest");
  const bindingParameters = digest(binding.parameterFingerprint, "CASE_BINDING", "caseBinding.parameterFingerprint");
  const bindingAuthority = digest(binding.releaseAuthorityId, "CASE_BINDING", "caseBinding.releaseAuthorityId");
  digest(binding.policyId, "CASE_BINDING", "caseBinding.policyId");
  if (binding.releaseMode !== "governed-decryptor-v1") {
    fail("CASE_BINDING", "caseBinding.releaseMode is not the governed mode");
  }
  if (typeof binding.releaseAuthorityPublicKey !== "string" || binding.releaseAuthorityPublicKey === "") {
    fail("CASE_BINDING", "caseBinding.releaseAuthorityPublicKey is required");
  }

  // 5 — the Ed25519 signature, verified with the existing semantics, unchanged.
  // The check itself is the imported one; only its error type is normalized, so
  // this module presents a single failure surface without softening the refusal.
  const result = evidence.governedResult;
  try {
    verifyGovernedResultSignature(result);
  } catch (error) {
    fail("GOVERNED_RESULT_SIGNATURE", error instanceof Error
      ? `The governed result did not verify: ${error.message}`
      : "The governed result did not verify");
  }

  // 4 — the retained digest must be the digest of that exact signed object.
  const recomputed = governedResultDigest(result);
  if (recomputed !== declaredResultDigest) {
    fail("RESULT_DIGEST", "The governed result digest does not match the signed governed result");
  }

  // 6, 7, 8, 12, 13 — the signed object against the case identity and binding.
  if (result.caseId !== fheCaseId) fail("CASE_ID", "The governed result is for a different case");
  if (result.caseId !== bindingCaseId) fail("CASE_ID", "The case binding is for a different case");
  if (result.caseBindingDigest !== caseBindingDigest) {
    fail("CASE_BINDING", "The governed result is bound to a different FHE case binding");
  }
  if (result.assetIdentity !== bindingAsset) {
    fail("ASSET_IDENTITY", "The governed result and the case binding name different receivables");
  }
  if (result.assetIdentity !== digest(expectations.assetIdentity, "ASSET_PIN", "expected assetIdentity")) {
    fail("ASSET_IDENTITY", "The governed result is not bound to the canonical receivable");
  }
  if (result.releaseMode !== binding.releaseMode) fail("RELEASE_MODE", "Release mode disagrees with the case binding");
  if (result.releaseAuthorityId !== bindingAuthority) {
    fail("RELEASE_AUTHORITY", "The governed result authority is not the authority of this case binding");
  }
  if (result.releaseAuthorityPublicKey !== binding.releaseAuthorityPublicKey) {
    fail("RELEASE_AUTHORITY", "The signing authority key is not the key this case binding designated");
  }
  // The signature above proves only that SOMEONE signed with the embedded key.
  // Without this, a forger supplies their own key, self-signs a syntactically
  // valid result, and keeps the legitimate pinned authority id: both equality
  // checks above pass because the forger controls both sides of them, and the
  // adapter never verifies Ed25519 itself. Deriving the identity from the key
  // that actually signed is what makes the authority pin mean anything.
  try {
    assertReleaseAuthorityIdentity(
      result.releaseAuthorityPublicKey,
      result.releaseMode,
      result.releaseAuthorityId,
      "RELEASE_AUTHORITY_IDENTITY",
    );
  } catch (error) {
    fail("RELEASE_AUTHORITY_IDENTITY", error instanceof Error
      ? `The governed authority identity is not derived from the signing key: ${error.message}`
      : "The governed authority identity is not derived from the signing key");
  }
  if (result.circuitDigest !== bindingCircuit) fail("CIRCUIT", "The governed result circuit is not this case's circuit");
  if (result.parameterFingerprint !== bindingParameters) {
    fail("PARAMETERS", "The governed result parameters are not this case's parameters");
  }

  // 9, 10, 11 — the signed object against this run's artifacts.
  if (result.participantArtifactDigests[0] !== participantArtifactDigestA
    || result.participantArtifactDigests[1] !== participantArtifactDigestB) {
    fail("PARTICIPANT_ARTIFACTS", "The governed result covers different participant artifacts");
  }
  if (result.evaluatedArtifactDigest !== evaluatedArtifactDigest) {
    fail("EVALUATED_ARTIFACT", "The governed result covers a different evaluated artifact");
  }
  if (result.resultCiphertextDigest !== result.resultCiphertextDigest.toLowerCase()) {
    fail("RESULT_CIPHERTEXT", "The result ciphertext digest is not canonical");
  }
  if (typeof result.resultCiphertextCommitment !== "string"
    || !/^sha256:[0-9a-f]{64}$/u.test(result.resultCiphertextCommitment)) {
    fail("RESULT_COMMITMENT", "The result ciphertext commitment is missing");
  }
  if (typeof result.sourceProvenance !== "string"
    || !/^sha256:[0-9a-f]{64}$/u.test(result.sourceProvenance)) {
    fail("SOURCE_PROVENANCE", "The governed result source provenance is missing");
  }

  // 14 to 18 — the durable wallet admissions.
  if (!Array.isArray(raw.participants) || raw.participants.length !== 2) {
    fail("PARTICIPANTS", "Exactly two participant admissions are required");
  }
  const admissions = (raw.participants as readonly unknown[]).map((entry, index) => {
    const label = `participants[${index}]`;
    const hasProof = entry !== null && typeof entry === "object"
      && Object.hasOwn(entry as object, "signature");
    const record = exactKeys(
      entry, hasProof ? ADMISSION_FIELDS_WITH_PROOF : ADMISSION_FIELDS, "ADMISSION_FIELDS", label,
    );
    if (record.role !== DIRECT_PARTICIPANT_ROLES[index]) {
      fail("ADMISSION_ROLE", `${label} must be ${DIRECT_PARTICIPANT_ROLES[index]}`);
    }
    bytes32Hex(record.authorizationDigest, "ADMISSION_AUTHORIZATION", `${label}.authorizationDigest`);
    bytes32Hex(record.claimCommitment, "ADMISSION_COMMITMENT", `${label}.claimCommitment`);
    bytes32Hex(record.authorizationNonce, "ADMISSION_NONCE", `${label}.authorizationNonce`);
    wholeNumber(record.eligibilityBlock, "ADMISSION_ELIGIBILITY", `${label}.eligibilityBlock`);
    if (record.chainId !== 10_143) fail("ADMISSION_CHAIN", `${label} must be admitted on Monad testnet`);
    return {
      role: record.role as DirectParticipantRole,
      wallet: address(record.participantWallet, "ADMISSION_WALLET", `${label}.participantWallet`),
    };
  });

  const [admissionA, admissionB] = admissions as [ {role: DirectParticipantRole; wallet: string}, {role: DirectParticipantRole; wallet: string} ];
  const holderA = address(expectations.holderA, "HOLDER_PIN", "expected holderA");
  const holderB = address(expectations.holderB, "HOLDER_PIN", "expected holderB");
  if (admissionA.wallet.toLowerCase() !== holderA.toLowerCase()) {
    fail("CANONICAL_PARTICIPANT", "PARTICIPANT_A is not the canonical holder A wallet");
  }
  if (admissionB.wallet.toLowerCase() !== holderB.toLowerCase()) {
    fail("CANONICAL_PARTICIPANT", "PARTICIPANT_B is not the canonical holder B wallet");
  }
  // 16 — distinct, checked on the admitted wallets themselves rather than on the
  // canonical pins, so a configuration that collapsed both roles is still caught.
  if (admissionA.wallet.toLowerCase() === admissionB.wallet.toLowerCase()) {
    fail("PARTICIPANTS_DISTINCT", "The two admitted participants must be distinct wallets");
  }
  // 18 — excluded wallets can never hold a role, whatever else they satisfy.
  const excluded = new Set(expectations.excludedWallets.map((entry) => entry.toLowerCase()));
  for (const admission of admissions) {
    if (excluded.has(admission.wallet.toLowerCase())) {
      fail("EXCLUDED_PARTICIPANT", "An excluded wallet cannot be a direct participant");
    }
  }

  // 19 — no private material and no browser-authored interval may ride along.
  const encoded = canonicalJson(evidence);
  for (const forbidden of FORBIDDEN_KEYS) {
    if (encoded.includes(`"${forbidden}"`)) {
      fail("PRIVATE_LEAK", `Bridge evidence must not carry ${forbidden}`);
    }
  }

  // 20 — the Boolean leaves this function only from the verified signed result.
  if (typeof result.conflict !== "boolean") fail("CONFLICT", "The governed result carries no signed Boolean");

  return Object.freeze({
    evidence,
    conflict: result.conflict,
    governedResult: result,
    holderA: admissionA.wallet,
    holderB: admissionB.wallet,
  });
}

export type DirectParticipantBridgeEvidenceInput = Readonly<{
  sourceCommit: string;
  runId: string;
  fheCaseId: Sha256Digest;
  protectionBindingDigest: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  caseBinding: DirectParticipantCaseBinding;
  participants: readonly [DirectParticipantAdmissionFact, DirectParticipantAdmissionFact];
  participantArtifactDigestA: Sha256Digest;
  participantArtifactDigestB: Sha256Digest;
  evaluatedArtifactDigest: Sha256Digest;
  governedResult: GovernedSignedResult;
  customReceiptDigest: Sha256Digest;
}>;

/**
 * Assembles the artifact. The governed result must already have been read from
 * the decryptor's published object and verified by the runtime; it is copied in
 * whole, never rebuilt field by field, so nothing can be silently dropped.
 */
export function buildDirectParticipantBridgeEvidence(
  input: DirectParticipantBridgeEvidenceInput,
): DirectParticipantBridgeEvidence {
  const body: Omit<DirectParticipantBridgeEvidence, "evidenceDigest"> = {
    schemaVersion: DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_SCHEMA,
    sourceCommit: input.sourceCommit,
    runId: input.runId,
    executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT,
    fheCaseId: input.fheCaseId,
    protectionBindingDigest: input.protectionBindingDigest,
    caseBindingDigest: input.caseBindingDigest,
    caseBinding: input.caseBinding,
    participants: input.participants,
    participantArtifactDigestA: input.participantArtifactDigestA,
    participantArtifactDigestB: input.participantArtifactDigestB,
    evaluatedArtifactDigest: input.evaluatedArtifactDigest,
    governedResultDigest: governedResultDigest(input.governedResult),
    governedResult: input.governedResult,
    customReceiptDigest: input.customReceiptDigest,
  };
  return Object.freeze({ ...body, evidenceDigest: directParticipantBridgeEvidenceDigest(body) });
}
