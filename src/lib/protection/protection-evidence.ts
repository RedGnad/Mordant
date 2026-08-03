import { createHash, createPublicKey, verify } from "node:crypto";

import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  SOURCE_CLASSIFICATIONS,
  cleanverseAssetRecordDigest,
  sha256Digest,
  type CleanverseAssetRecord,
  type Sha256Digest,
  type SourceClassification,
} from "./cleanverse-asset";
import {
  assertProtectionBindingDerivations,
  protectionBindingFromCase,
  type MordantProtectionBinding,
  type MordantProtectionCase,
  type ProductScenario,
} from "./protection-case";

export const EXPECTED_GOVERNED_FHE_COMMIT = "3b0247593d022fb18aadd2b554329f85c5a19898";
export const PRODUCT_CLAIM_IDENTIFIER = "mordant.conflicting-pledge-protection/governed-fhe-mvp-v1" as const;

export type PublicObjectReference = Readonly<{
  path: string;
  sha256: Sha256Digest;
  length: number;
}>;

export type EvidenceSource = Readonly<{
  subject: string;
  classification: SourceClassification;
  detail: string;
}>;

export type FheParticipantIdentity = Readonly<{
  id: Sha256Digest;
  role: "PARTICIPANT_A" | "PARTICIPANT_B";
  signingPublicKey: string;
}>;

export type FheCaseBinding = Readonly<{
  schemaVersion: "mordant.fhe-case-binding/1";
  caseId: Sha256Digest;
  assetIdentity: Sha256Digest;
  serviceId: "mordant.private-pledge-matching";
  serviceVersion: 1;
  policyId: Sha256Digest;
  policyVersion: 1;
  circuitId: "mordant.identity-full-fhe-256";
  circuitVersion: number;
  circuitDigest: Sha256Digest;
  parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1";
  parameterFingerprint: Sha256Digest;
  publicKeyDigest: Sha256Digest;
  evaluationKeyManifestDigest: Sha256Digest;
  participantA: FheParticipantIdentity;
  participantB: FheParticipantIdentity;
  participantOrder: readonly [Sha256Digest, Sha256Digest];
  inputSchema: "mordant.encrypted-pledge/governed-fhe-v1";
  resultSchema: "mordant.fixed-conflict-boolean/v1";
  releaseMode: "governed-decryptor-v1";
  releaseAuthorityId: Sha256Digest;
  releaseAuthorityPublicKey: string;
  caseNonce: Sha256Digest;
  createdAtUnix: number;
  expiresAtUnix: number;
}>;

export type ParticipantBindingSignature = Readonly<{
  role: "PARTICIPANT_A" | "PARTICIPANT_B";
  participantId: Sha256Digest;
  bindingDigest: Sha256Digest;
  signature: string;
}>;

export type ProtectionBindingSignature = Readonly<{
  role: "PARTICIPANT_A" | "PARTICIPANT_B";
  participantId: Sha256Digest;
  protectionBindingDigest: Sha256Digest;
  signature: string;
}>;

export type MordantRecourseAttestation = Readonly<{
  schemaVersion: "mordant.recourse-attestation/1";
  protectionBindingDigest: Sha256Digest;
  governedResultDigest: Sha256Digest;
  caseId: Sha256Digest;
  cleanverseAssetRecordDigest: Sha256Digest;
  signedBoolean: boolean;
  recourseRecordDigest: Sha256Digest;
  recourseRefusal: "NONE" | "SIGNED_RESULT_FALSE";
  holderAllocationDigest: Sha256Digest;
  recordDate: string;
  cureDeadline: string | null;
  finalRecourseState: "AVAILABLE" | "REFUSED";
  chronologyDigest: Sha256Digest;
  originalReceivableState: "OUTSTANDING_INTACT";
  reserveAccountingSeparation: Readonly<{
    reserveDomain: "PROTECTION";
    receivableDomain: "RECEIVABLE";
    separate: true;
    claimBurnedOrTransferred: false;
  }>;
  executionClass: "REAL_BGV_FHE";
  deploymentClass: "LOCAL_SINGLE_HOST";
  releaseClass: "GOVERNED_DECRYPTOR";
  recourseClass: "LOCAL_PROTOCOL_DOUBLE";
  productionIsolationProven: false;
  productClaim: typeof PRODUCT_CLAIM_IDENTIFIER;
  releaseAuthorityId: Sha256Digest;
  signature: string;
}>;

export type GovernedSignedResult = Readonly<{
  schemaVersion: "mordant.governed-conflict-result/1";
  caseId: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  assetIdentity: Sha256Digest;
  serviceId: "mordant.private-pledge-matching";
  serviceVersion: 1;
  policyId: Sha256Digest;
  policyVersion: 1;
  circuitId: "mordant.identity-full-fhe-256";
  circuitVersion: number;
  circuitDigest: Sha256Digest;
  parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1";
  parameterFingerprint: Sha256Digest;
  participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
  evaluatedArtifactDigest: Sha256Digest;
  resultCiphertextDigest: Sha256Digest;
  resultCiphertextCommitment: Sha256Digest;
  conflict: boolean;
  releaseOrdinal: 1;
  releaseMode: "governed-decryptor-v1";
  releaseAuthorityId: Sha256Digest;
  releaseAuthorityPublicKey: string;
  releasedAtUnix: number;
  sourceProvenance: Sha256Digest;
  signature: string;
}>;

export type PublicRecourseRecord = Readonly<{
  schemaVersion: "mordant.fhe-recourse-adapter-record/1";
  caseId: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  assetIdentity: Sha256Digest;
  policyId: Sha256Digest;
  policyVersion: 1;
  resultDigest: Sha256Digest;
  releaseMode: "governed-decryptor-v1";
  releaseAuthorityId: Sha256Digest;
  recordDateUnix: number;
  boundAtUnix: number;
  cureDeadlineUnix: number;
  reserveBasisPoints: 1000;
  holderAllocationDigest: Sha256Digest;
  originalReceivableIntact: true;
  open: true;
}>;

type TrustedRecoursePins = Readonly<{
  participantArtifactDigestA: Sha256Digest;
  participantArtifactDigestB: Sha256Digest;
  evaluatedArtifactDigest: Sha256Digest;
  recomputedResultCiphertextDigest: Sha256Digest;
  resultCiphertextCommitment: Sha256Digest;
  decryptorProvenance: Sha256Digest;
  releaseMode: "governed-decryptor-v1";
  releaseAuthorityId: Sha256Digest;
}>;

export type GovernedFhePublicEvidence = Readonly<{
  schemaVersion: "mordant.governed-fhe-public-evidence/2";
  caseId: Sha256Digest;
  assetIdentity: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  caseManifestDigest: Sha256Digest;
  submissionDigests: readonly [Sha256Digest, Sha256Digest];
  evaluatedArtifactDigest: Sha256Digest;
  resultCiphertextDigest: Sha256Digest;
  resultCiphertextCommitment: Sha256Digest;
  evaluatorProvenance: Sha256Digest;
  recomputedResultCiphertextDigest: Sha256Digest;
  decryptorProvenance: Sha256Digest;
  governedResultDigest: Sha256Digest;
  protectionBindingDigest: Sha256Digest;
  recourseAttestationDigest: Sha256Digest;
  recourseRecordDigest: Sha256Digest;
  releaseMode: "governed-decryptor-v1";
  releaseAuthorityId: Sha256Digest;
  conflict: boolean;
  publicStructureValidated: true;
  executionClass: "REAL_BGV_FHE";
  deploymentClass: "LOCAL_SINGLE_HOST";
  releaseClass: "GOVERNED_DECRYPTOR";
  recourseClass: "LOCAL_PROTOCOL_DOUBLE";
  productionIsolationProven: false;
  publicArtifactBytes: number;
  measurements: Readonly<{
    release: Readonly<{
      exactRetry: boolean;
      trustedRecoursePins: TrustedRecoursePins;
      [key: string]: unknown;
    }>;
    [key: string]: unknown;
  }>;
  productClaim: string;
  generatedAtUnix: number;
}>;

export type MordantProtectionEvidence = Readonly<{
  schemaVersion: "mordant.protection-evidence/3";
  manifestDigest: Sha256Digest;
  runId: string;
  sourceCommit: string;
  governedFheCommit: string;
  scenario: ProductScenario;
  cleanverseAsset: CleanverseAssetRecord;
  cleanverseAssetDigest: Sha256Digest;
  sourceClassifications: readonly EvidenceSource[];
  protectionCase: MordantProtectionCase;
  participantPublicIdentities: readonly [
    Readonly<{ role: "PARTICIPANT_A"; id: Sha256Digest; signingPublicKey: string }>,
    Readonly<{ role: "PARTICIPANT_B"; id: Sha256Digest; signingPublicKey: string }>,
  ];
  protectionAuthorization: Readonly<{
    binding: MordantProtectionBinding;
    bindingDigest: Sha256Digest;
    participantSignatures: readonly [ProtectionBindingSignature, ProtectionBindingSignature];
  }>;
  caseAuthorization: Readonly<{
    binding: FheCaseBinding;
    bindingDigest: Sha256Digest;
    participantSignatures: readonly [ParticipantBindingSignature, ParticipantBindingSignature];
  }>;
  fhe: Readonly<{
    caseId: Sha256Digest;
    assetIdentity: Sha256Digest;
    caseBindingDigest: Sha256Digest;
    profile: "mordant.bgv.identity-full-fhe-256.n15/v1";
    circuitId: "mordant.identity-full-fhe-256";
    circuitVersion: number;
    circuitDigest: Sha256Digest;
    publicKey: PublicObjectReference;
    evaluationKeyManifestDigest: Sha256Digest;
    participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
    evaluatedArtifactDigest: Sha256Digest;
    resultCiphertext: PublicObjectReference;
    resultCiphertextCommitment: Sha256Digest;
    evaluatorProvenance: Sha256Digest;
    independentlyRecomputedResultDigest: Sha256Digest;
  }>;
  governedResult: Readonly<{ digest: Sha256Digest } & GovernedSignedResult>;
  chronology: Readonly<{
    recordDate: string;
    holderAllocationDigest: Sha256Digest;
    cureDeadline: string | null;
    events: MordantProtectionCase["timeline"];
  }>;
  recourse: Readonly<{
    classification: "PROTOCOL_DOUBLE";
    opened: boolean;
    refusedReason: "SIGNED_RESULT_FALSE" | null;
    recordDigest: Sha256Digest | null;
    record: PublicRecourseRecord | null;
  }>;
  originalReceivablePreservation: Readonly<{
    state: "OUTSTANDING_INTACT";
    principalMinorUnits: "110000000";
    units: "100000000";
    reserveAccountingSeparate: true;
    claimBurnedOrTransferredByProtection: false;
  }>;
  recourseAttestation: Readonly<{
    digest: Sha256Digest;
    attestation: MordantRecourseAttestation;
  }>;
  governedFheEvidence: GovernedFhePublicEvidence;
  generatedAt: string;
}>;

export class ProtectionEvidenceError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "ProtectionEvidenceError";
  }
}

function fail(code: string, message: string): never {
  throw new ProtectionEvidenceError(code, message);
}

function exactKeys(value: object, expected: readonly string[], code: string): void {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  if (actual.length !== sorted.length || !actual.every((key, index) => key === sorted[index])) {
    fail(code, `${code}: unexpected or missing fields`);
  }
}

function sha256Raw(value: string | Buffer): Sha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function identityValue(identity: FheParticipantIdentity): object {
  return { id: identity.id, role: identity.role, signingPublicKey: identity.signingPublicKey };
}

function protectionBindingValue(binding: MordantProtectionBinding): object {
  return {
    schemaVersion: binding.schemaVersion,
    cleanverseAssetRecordDigest: binding.cleanverseAssetRecordDigest,
    protectionService: binding.protectionService,
    protectionServiceVersion: binding.protectionServiceVersion,
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    productScenario: binding.productScenario,
    fixtureClassification: binding.fixtureClassification,
    protectedAmount: { asset: binding.protectedAmount.asset, minorUnits: binding.protectedAmount.minorUnits },
    reserveBasisPoints: binding.reserveBasisPoints,
    reserveAmount: { asset: binding.reserveAmount.asset, minorUnits: binding.reserveAmount.minorUnits },
    holderRecordDate: binding.holderRecordDate,
    holderSnapshot: binding.holderSnapshot.map((holder) => ({
      holderId: holder.holderId,
      protectedUnits: holder.protectedUnits,
      allocationBps: holder.allocationBps,
    })),
    holderAllocationDigest: binding.holderAllocationDigest,
    caseNonce: binding.caseNonce,
    fheCaseId: binding.fheCaseId,
    governedReleaseMode: binding.governedReleaseMode,
  };
}

export function protectionBindingDigest(binding: MordantProtectionBinding): Sha256Digest {
  return sha256Raw(JSON.stringify(protectionBindingValue(binding)));
}

function protectionSignatureValue(signature: ProtectionBindingSignature): object {
  return {
    role: signature.role,
    participantId: signature.participantId,
    protectionBindingDigest: signature.protectionBindingDigest,
  };
}

function caseBindingValue(binding: FheCaseBinding): object {
  return {
    schemaVersion: binding.schemaVersion,
    caseId: binding.caseId,
    assetIdentity: binding.assetIdentity,
    serviceId: binding.serviceId,
    serviceVersion: binding.serviceVersion,
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    circuitId: binding.circuitId,
    circuitVersion: binding.circuitVersion,
    circuitDigest: binding.circuitDigest,
    parameterProfile: binding.parameterProfile,
    parameterFingerprint: binding.parameterFingerprint,
    publicKeyDigest: binding.publicKeyDigest,
    evaluationKeyManifestDigest: binding.evaluationKeyManifestDigest,
    participantA: identityValue(binding.participantA),
    participantB: identityValue(binding.participantB),
    participantOrder: [...binding.participantOrder],
    inputSchema: binding.inputSchema,
    resultSchema: binding.resultSchema,
    releaseMode: binding.releaseMode,
    releaseAuthorityId: binding.releaseAuthorityId,
    releaseAuthorityPublicKey: binding.releaseAuthorityPublicKey,
    caseNonce: binding.caseNonce,
    createdAtUnix: binding.createdAtUnix,
    expiresAtUnix: binding.expiresAtUnix,
  };
}

function governedResultValue(result: GovernedSignedResult, signing: boolean): object {
  return {
    schemaVersion: result.schemaVersion,
    caseId: result.caseId,
    caseBindingDigest: result.caseBindingDigest,
    assetIdentity: result.assetIdentity,
    serviceId: result.serviceId,
    serviceVersion: result.serviceVersion,
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    circuitId: result.circuitId,
    circuitVersion: result.circuitVersion,
    circuitDigest: result.circuitDigest,
    parameterProfile: result.parameterProfile,
    parameterFingerprint: result.parameterFingerprint,
    participantArtifactDigests: [...result.participantArtifactDigests],
    evaluatedArtifactDigest: result.evaluatedArtifactDigest,
    resultCiphertextDigest: result.resultCiphertextDigest,
    resultCiphertextCommitment: result.resultCiphertextCommitment,
    conflict: result.conflict,
    releaseOrdinal: result.releaseOrdinal,
    releaseMode: result.releaseMode,
    releaseAuthorityId: result.releaseAuthorityId,
    releaseAuthorityPublicKey: result.releaseAuthorityPublicKey,
    releasedAtUnix: result.releasedAtUnix,
    sourceProvenance: result.sourceProvenance,
    signature: signing ? null : result.signature,
  };
}

function chronologyValue(chronology: MordantProtectionEvidence["chronology"]): object {
  return {
    recordDate: chronology.recordDate,
    holderAllocationDigest: chronology.holderAllocationDigest,
    cureDeadline: chronology.cureDeadline,
    events: chronology.events.map((event) => ({
      ordinal: event.ordinal,
      kind: event.kind,
      at: event.at,
      label: event.label,
      classification: event.classification,
      evidenceRef: event.evidenceRef,
    })),
  };
}

function recourseAttestationValue(attestation: MordantRecourseAttestation, signing: boolean): object {
  return {
    schemaVersion: attestation.schemaVersion,
    protectionBindingDigest: attestation.protectionBindingDigest,
    governedResultDigest: attestation.governedResultDigest,
    caseId: attestation.caseId,
    cleanverseAssetRecordDigest: attestation.cleanverseAssetRecordDigest,
    signedBoolean: attestation.signedBoolean,
    recourseRecordDigest: attestation.recourseRecordDigest,
    recourseRefusal: attestation.recourseRefusal,
    holderAllocationDigest: attestation.holderAllocationDigest,
    recordDate: attestation.recordDate,
    cureDeadline: attestation.cureDeadline,
    finalRecourseState: attestation.finalRecourseState,
    chronologyDigest: attestation.chronologyDigest,
    originalReceivableState: attestation.originalReceivableState,
    reserveAccountingSeparation: {
      reserveDomain: attestation.reserveAccountingSeparation.reserveDomain,
      receivableDomain: attestation.reserveAccountingSeparation.receivableDomain,
      separate: attestation.reserveAccountingSeparation.separate,
      claimBurnedOrTransferred: attestation.reserveAccountingSeparation.claimBurnedOrTransferred,
    },
    executionClass: attestation.executionClass,
    deploymentClass: attestation.deploymentClass,
    releaseClass: attestation.releaseClass,
    recourseClass: attestation.recourseClass,
    productionIsolationProven: attestation.productionIsolationProven,
    productClaim: attestation.productClaim,
    releaseAuthorityId: attestation.releaseAuthorityId,
    signature: signing ? null : attestation.signature,
  };
}

export function recourseAttestationDigest(attestation: MordantRecourseAttestation): Sha256Digest {
  return sha256Raw(JSON.stringify(recourseAttestationValue(attestation, false)));
}

export function governedResultDigest(result: GovernedSignedResult): Sha256Digest {
  return sha256Raw(JSON.stringify(governedResultValue(result, false)));
}

export function verifyGovernedResultSignature(result: GovernedSignedResult): void {
  const expectedFields = [
    "schemaVersion", "caseId", "caseBindingDigest", "assetIdentity", "serviceId", "serviceVersion", "policyId",
    "policyVersion", "circuitId", "circuitVersion", "circuitDigest", "parameterProfile", "parameterFingerprint",
    "participantArtifactDigests", "evaluatedArtifactDigest", "resultCiphertextDigest", "resultCiphertextCommitment",
    "conflict", "releaseOrdinal", "releaseMode", "releaseAuthorityId", "releaseAuthorityPublicKey", "releasedAtUnix",
    "sourceProvenance", "signature",
  ];
  if (Object.hasOwn(result, "digest")) expectedFields.push("digest");
  exactKeys(result, expectedFields, "GOVERNED_RESULT_FIELDS");
  verifyGoSignature(
    result.releaseAuthorityPublicKey,
    "MordantGovernedConflictResult/v1",
    governedResultValue(result, true),
    result.signature,
    "GOVERNED_RESULT_SIGNATURE",
  );
}

function recourseRecordValue(record: PublicRecourseRecord): object {
  return {
    schemaVersion: record.schemaVersion,
    caseId: record.caseId,
    caseBindingDigest: record.caseBindingDigest,
    assetIdentity: record.assetIdentity,
    policyId: record.policyId,
    policyVersion: record.policyVersion,
    resultDigest: record.resultDigest,
    releaseMode: record.releaseMode,
    releaseAuthorityId: record.releaseAuthorityId,
    recordDateUnix: record.recordDateUnix,
    boundAtUnix: record.boundAtUnix,
    cureDeadlineUnix: record.cureDeadlineUnix,
    reserveBasisPoints: record.reserveBasisPoints,
    holderAllocationDigest: record.holderAllocationDigest,
    originalReceivableIntact: record.originalReceivableIntact,
    open: record.open,
  };
}

function ed25519Key(rawBase64: string) {
  const raw = Buffer.from(rawBase64, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== rawBase64) fail("SIGNATURE_ENCODING", "Invalid Ed25519 public key");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

function verifyGoSignature(publicKey: string, domain: string, value: object, signature: string, code: string): void {
  const decoded = Buffer.from(signature, "base64");
  if (decoded.length !== 64 || decoded.toString("base64") !== signature) fail(code, `${code}: invalid signature encoding`);
  const message = Buffer.concat([Buffer.from(domain), Buffer.of(0), Buffer.from(JSON.stringify(value))]);
  if (!verify(null, message, ed25519Key(publicKey), decoded)) fail(code, `${code}: Ed25519 verification failed`);
}

function assertParticipantAuthorization(evidence: MordantProtectionEvidence): void {
  const { binding, bindingDigest, participantSignatures } = evidence.caseAuthorization;
  exactKeys(binding, [
    "schemaVersion", "caseId", "assetIdentity", "serviceId", "serviceVersion", "policyId", "policyVersion",
    "circuitId", "circuitVersion", "circuitDigest", "parameterProfile", "parameterFingerprint", "publicKeyDigest",
    "evaluationKeyManifestDigest", "participantA", "participantB", "participantOrder", "inputSchema", "resultSchema",
    "releaseMode", "releaseAuthorityId", "releaseAuthorityPublicKey", "caseNonce", "createdAtUnix", "expiresAtUnix",
  ], "CASE_BINDING_FIELDS");
  const recalculated = sha256Raw(JSON.stringify(caseBindingValue(binding)));
  if (recalculated !== bindingDigest || bindingDigest !== evidence.fhe.caseBindingDigest) {
    fail("CASE_BINDING_DIGEST", "FHE case-binding digest mismatch");
  }
  const identities = [binding.participantA, binding.participantB] as const;
  exactKeys(identities[0], ["id", "role", "signingPublicKey"], "PARTICIPANT_IDENTITY_FIELDS");
  exactKeys(identities[1], ["id", "role", "signingPublicKey"], "PARTICIPANT_IDENTITY_FIELDS");
  if (
    identities[0].role !== "PARTICIPANT_A" || identities[1].role !== "PARTICIPANT_B"
    || binding.participantOrder[0] !== identities[0].id || binding.participantOrder[1] !== identities[1].id
  ) fail("PARTICIPANT_ORDER", "Participant authorization order mismatch");
  for (let index = 0; index < 2; index += 1) {
    const signature = participantSignatures[index];
    const identity = identities[index];
    const projection = evidence.participantPublicIdentities[index];
    exactKeys(signature, ["role", "participantId", "bindingDigest", "signature"], "PARTICIPANT_SIGNATURE_FIELDS");
    if (
      signature.role !== identity.role || signature.participantId !== identity.id || signature.bindingDigest !== bindingDigest
      || projection.role !== identity.role || projection.id !== identity.id || projection.signingPublicKey !== identity.signingPublicKey
    ) fail("PARTICIPANT_AUTHORITY_BINDING", "Participant authorization projection mismatch");
    verifyGoSignature(identity.signingPublicKey, "MordantFHECaseBindingSignature/v1", {
      role: signature.role,
      participantId: signature.participantId,
      bindingDigest: signature.bindingDigest,
    }, signature.signature, "PARTICIPANT_AUTHORITY_SIGNATURE");
  }
  const rawAuthority = Buffer.from(binding.releaseAuthorityPublicKey, "base64");
  const authorityIdentity = sha256Raw(Buffer.concat([
    Buffer.from("MordantReleaseAuthorityIdentity/v1"), Buffer.of(0), Buffer.from(binding.releaseMode), Buffer.of(0), rawAuthority,
  ]));
  if (rawAuthority.length !== 32 || authorityIdentity !== binding.releaseAuthorityId) {
    fail("RELEASE_AUTHORITY_IDENTITY", "Release authority identity mismatch");
  }
}

function assertSignedProtectionBinding(evidence: MordantProtectionEvidence): Sha256Digest {
  const { binding, bindingDigest, participantSignatures } = evidence.protectionAuthorization;
  exactKeys(binding, [
    "schemaVersion", "cleanverseAssetRecordDigest", "protectionService", "protectionServiceVersion", "policyId",
    "policyVersion", "productScenario", "fixtureClassification", "protectedAmount", "reserveBasisPoints",
    "reserveAmount", "holderRecordDate", "holderSnapshot", "holderAllocationDigest", "caseNonce", "fheCaseId",
    "governedReleaseMode",
  ], "PROTECTION_BINDING_FIELDS");
  exactKeys(binding.protectedAmount, ["asset", "minorUnits"], "PROTECTED_AMOUNT_FIELDS");
  exactKeys(binding.reserveAmount, ["asset", "minorUnits"], "RESERVE_AMOUNT_FIELDS");
  if (binding.holderSnapshot.length !== 2) fail("HOLDER_SNAPSHOT", "Complete ordered holder snapshot required");
  for (const holder of binding.holderSnapshot) {
    exactKeys(holder, ["holderId", "protectedUnits", "allocationBps"], "HOLDER_SNAPSHOT_FIELDS");
  }
  try {
    assertProtectionBindingDerivations(binding);
  } catch {
    fail("PROTECTION_BINDING_DERIVATION", "Protection binding deterministic derivation rejected");
  }
  const recalculated = protectionBindingDigest(binding);
  if (bindingDigest !== recalculated) fail("PROTECTION_BINDING_DIGEST", "Protection binding digest mismatch");
  const projected = protectionBindingFromCase(evidence.protectionCase);
  if (JSON.stringify(protectionBindingValue(projected)) !== JSON.stringify(protectionBindingValue(binding))) {
    fail("PROTECTION_CASE_PROJECTION", "Unsigned protection-case projection differs from the signed root");
  }
  const fheBinding = evidence.caseAuthorization.binding;
  const identities = [fheBinding.participantA, fheBinding.participantB] as const;
  for (let index = 0; index < 2; index += 1) {
    const signature = participantSignatures[index];
    const identity = identities[index];
    exactKeys(signature, ["role", "participantId", "protectionBindingDigest", "signature"], "PROTECTION_SIGNATURE_FIELDS");
    if (
      signature.role !== identity.role || signature.participantId !== identity.id
      || signature.protectionBindingDigest !== bindingDigest
    ) fail("PROTECTION_SIGNATURE_BINDING", "Participant protection signature projection mismatch");
    verifyGoSignature(
      identity.signingPublicKey,
      "MordantProtectionBindingSignature/v1",
      protectionSignatureValue(signature),
      signature.signature,
      "PROTECTION_BINDING_SIGNATURE",
    );
  }
  if (
    binding.cleanverseAssetRecordDigest !== fheBinding.assetIdentity || binding.policyId !== fheBinding.policyId
    || binding.policyVersion !== fheBinding.policyVersion || binding.fheCaseId !== fheBinding.caseId
    || binding.caseNonce !== fheBinding.caseNonce || binding.governedReleaseMode !== fheBinding.releaseMode
  ) fail("PROTECTION_FHE_AUTHORIZATION", "Signed protection root does not match accepted FHE authorization");
  return bindingDigest;
}

function assertSignedRecourseAttestation(
  evidence: MordantProtectionEvidence,
  protectionDigest: Sha256Digest,
  resultDigest: Sha256Digest,
): void {
  const { digest, attestation } = evidence.recourseAttestation;
  exactKeys(attestation, [
    "schemaVersion", "protectionBindingDigest", "governedResultDigest", "caseId", "cleanverseAssetRecordDigest",
    "signedBoolean", "recourseRecordDigest", "recourseRefusal", "holderAllocationDigest", "recordDate",
    "cureDeadline", "finalRecourseState", "chronologyDigest", "originalReceivableState",
    "reserveAccountingSeparation", "executionClass", "deploymentClass", "releaseClass", "recourseClass",
    "productionIsolationProven", "productClaim", "releaseAuthorityId", "signature",
  ], "RECOURSE_ATTESTATION_FIELDS");
  exactKeys(attestation.reserveAccountingSeparation, [
    "reserveDomain", "receivableDomain", "separate", "claimBurnedOrTransferred",
  ], "RESERVE_ACCOUNTING_FIELDS");
  const recalculated = recourseAttestationDigest(attestation);
  if (digest !== recalculated) fail("RECOURSE_ATTESTATION_DIGEST", "Recourse attestation digest mismatch");
  verifyGoSignature(
    evidence.governedResult.releaseAuthorityPublicKey,
    "MordantRecourseAttestation/v1",
    recourseAttestationValue(attestation, true),
    attestation.signature,
    "RECOURSE_ATTESTATION_SIGNATURE",
  );
  const chronologyDigest = sha256Raw(JSON.stringify(chronologyValue(evidence.chronology)));
  const expectedRecordDigest = evidence.recourse.recordDigest ?? (`sha256:${"00".repeat(32)}` as Sha256Digest);
  if (
    attestation.protectionBindingDigest !== protectionDigest || attestation.governedResultDigest !== resultDigest
    || attestation.caseId !== evidence.protectionAuthorization.binding.fheCaseId
    || attestation.cleanverseAssetRecordDigest !== evidence.protectionAuthorization.binding.cleanverseAssetRecordDigest
    || attestation.signedBoolean !== evidence.governedResult.conflict
    || attestation.recourseRecordDigest !== expectedRecordDigest
    || attestation.holderAllocationDigest !== evidence.protectionAuthorization.binding.holderAllocationDigest
    || attestation.recordDate !== evidence.protectionAuthorization.binding.holderRecordDate
    || attestation.cureDeadline !== evidence.chronology.cureDeadline
    || attestation.chronologyDigest !== chronologyDigest
    || attestation.originalReceivableState !== evidence.originalReceivablePreservation.state
    || attestation.reserveAccountingSeparation.reserveDomain !== "PROTECTION"
    || attestation.reserveAccountingSeparation.receivableDomain !== "RECEIVABLE"
    || !attestation.reserveAccountingSeparation.separate
    || attestation.reserveAccountingSeparation.claimBurnedOrTransferred
    || attestation.executionClass !== "REAL_BGV_FHE" || attestation.deploymentClass !== "LOCAL_SINGLE_HOST"
    || attestation.releaseClass !== "GOVERNED_DECRYPTOR" || attestation.recourseClass !== "LOCAL_PROTOCOL_DOUBLE"
    || attestation.productionIsolationProven || attestation.productClaim !== PRODUCT_CLAIM_IDENTIFIER
    || attestation.releaseAuthorityId !== evidence.governedResult.releaseAuthorityId
  ) fail("RECOURSE_ATTESTATION_BINDING", "Signed recourse attestation cross-reference mismatch");
  if (attestation.signedBoolean) {
    if (attestation.recourseRefusal !== "NONE" || attestation.finalRecourseState !== "AVAILABLE") {
      fail("RECOURSE_ATTESTATION_STATE", "Conflict attestation must make recourse available");
    }
  } else if (
    attestation.recourseRefusal !== "SIGNED_RESULT_FALSE" || attestation.finalRecourseState !== "REFUSED"
    || attestation.cureDeadline !== null
  ) fail("RECOURSE_ATTESTATION_STATE", "False result attestation must explicitly refuse recourse");
}

export function protectionEvidenceDigest(
  evidence: Omit<MordantProtectionEvidence, "manifestDigest">,
): Sha256Digest {
  return sha256Digest("MordantProtectionEvidence/v3", evidence);
}

export function assertPublicProtectionEvidence(evidence: MordantProtectionEvidence): void {
  if (evidence.schemaVersion !== "mordant.protection-evidence/3") fail("SCHEMA", "Unsupported protection evidence schema");
  exactKeys(evidence, [
    "schemaVersion", "manifestDigest", "runId", "sourceCommit", "governedFheCommit", "scenario", "cleanverseAsset",
    "cleanverseAssetDigest", "sourceClassifications", "protectionCase", "participantPublicIdentities", "protectionAuthorization",
    "caseAuthorization", "fhe", "governedResult", "chronology", "recourse", "originalReceivablePreservation",
    "recourseAttestation", "governedFheEvidence", "generatedAt",
  ], "PROTECTION_EVIDENCE_FIELDS");
  const { manifestDigest, ...value } = evidence;
  // manifestDigest detects transport corruption; authenticity is established
  // only by the three signed canonical roots below.
  if (manifestDigest !== protectionEvidenceDigest(value)) fail("MANIFEST_DIGEST", "Protection evidence digest mismatch");
  if (!/^[0-9a-f]{40}$/.test(evidence.sourceCommit)) fail("SOURCE_COMMIT", "Exact product source commit required");
  if (evidence.governedFheCommit !== EXPECTED_GOVERNED_FHE_COMMIT) fail("GOVERNED_FHE_COMMIT", "Unexpected governed-FHE commit");
  if (!/^[0-9a-f-]{36}$/.test(evidence.runId)) fail("RUN_ID", "Protection evidence run ID rejected");

  const assetDigest = cleanverseAssetRecordDigest(evidence.cleanverseAsset);
  if (
    assetDigest !== CANONICAL_CLEANVERSE_ASSET_DIGEST
    || assetDigest !== evidence.cleanverseAssetDigest
    || assetDigest !== evidence.protectionCase.cleanverseAssetDigest
    || cleanverseAssetRecordDigest(evidence.protectionCase.cleanverseAsset) !== assetDigest
  ) fail("ASSET_RECORD_DIGEST", "Cleanverse asset record digest mismatch");

  assertParticipantAuthorization(evidence);
  const protectionDigest = assertSignedProtectionBinding(evidence);
  if (protectionDigest !== evidence.governedFheEvidence.protectionBindingDigest) {
    fail("PROTECTION_BINDING_CROSS_REFERENCE", "Governed-FHE evidence protection-binding digest mismatch");
  }
  const binding = evidence.caseAuthorization.binding;
  const protectionBinding = evidence.protectionAuthorization.binding;
  const result = evidence.governedResult;
  const governed = evidence.governedFheEvidence;
  exactKeys(governed, [
    "schemaVersion", "caseId", "assetIdentity", "caseBindingDigest", "caseManifestDigest", "submissionDigests",
    "evaluatedArtifactDigest", "resultCiphertextDigest", "resultCiphertextCommitment", "evaluatorProvenance",
    "recomputedResultCiphertextDigest", "decryptorProvenance", "governedResultDigest", "protectionBindingDigest",
    "recourseAttestationDigest", "recourseRecordDigest",
    "releaseMode", "releaseAuthorityId", "conflict", "publicStructureValidated", "executionClass", "deploymentClass",
    "releaseClass", "recourseClass", "productionIsolationProven", "publicArtifactBytes", "measurements", "productClaim",
    "generatedAtUnix",
  ], "GOVERNED_FHE_EVIDENCE_FIELDS");
  const pins = governed.measurements.release.trustedRecoursePins;
  const expectedScenarioConflict = protectionBinding.productScenario === "conflict";
  if (
    evidence.scenario !== protectionBinding.productScenario || evidence.protectionCase.productScenario !== protectionBinding.productScenario
    || result.conflict !== expectedScenarioConflict || governed.conflict !== expectedScenarioConflict
  ) fail("SCENARIO_BINDING", "Scenario and signed Boolean mismatch");

  const caseId = protectionBinding.fheCaseId;
  if (
    evidence.fhe.caseId !== caseId || binding.caseId !== caseId || result.caseId !== caseId || governed.caseId !== caseId
  ) fail("CASE_ID_BINDING", "CaseID mismatch across public evidence");
  const recourseCaseId = evidence.recourse.record?.caseId;
  if (recourseCaseId !== undefined && recourseCaseId !== caseId) fail("RECOURSE_CASE_ID", "Recourse CaseID mismatch");

  if (
    evidence.fhe.assetIdentity !== assetDigest || binding.assetIdentity !== assetDigest || result.assetIdentity !== assetDigest
    || governed.assetIdentity !== assetDigest || (evidence.recourse.record?.assetIdentity ?? assetDigest) !== assetDigest
  ) fail("ASSET_BINDING", "Asset identity mismatch across public evidence");

  if (
    binding.policyId !== protectionBinding.policyId || result.policyId !== binding.policyId
    || binding.policyVersion !== protectionBinding.policyVersion || result.policyVersion !== binding.policyVersion
    || binding.circuitId !== evidence.fhe.circuitId || result.circuitId !== binding.circuitId
    || binding.circuitVersion !== evidence.fhe.circuitVersion || result.circuitVersion !== binding.circuitVersion
    || binding.circuitDigest !== evidence.fhe.circuitDigest || result.circuitDigest !== binding.circuitDigest
    || binding.parameterProfile !== evidence.fhe.profile || result.parameterProfile !== binding.parameterProfile
    || result.parameterFingerprint !== binding.parameterFingerprint
    || binding.publicKeyDigest !== evidence.fhe.publicKey.sha256
    || binding.evaluationKeyManifestDigest !== evidence.fhe.evaluationKeyManifestDigest
  ) fail("CASE_SEMANTICS", "FHE case semantics mismatch");

  if (
    result.caseBindingDigest !== evidence.fhe.caseBindingDigest || governed.caseBindingDigest !== evidence.fhe.caseBindingDigest
  ) fail("CASE_BINDING_CROSS_REFERENCE", "Case-binding cross-reference mismatch");
  if (
    result.participantArtifactDigests[0] !== evidence.fhe.participantArtifactDigests[0]
    || result.participantArtifactDigests[1] !== evidence.fhe.participantArtifactDigests[1]
    || governed.submissionDigests[0] !== evidence.fhe.participantArtifactDigests[0]
    || governed.submissionDigests[1] !== evidence.fhe.participantArtifactDigests[1]
    || pins.participantArtifactDigestA !== evidence.fhe.participantArtifactDigests[0]
    || pins.participantArtifactDigestB !== evidence.fhe.participantArtifactDigests[1]
  ) fail("PARTICIPANT_ARTIFACTS", "Participant artifact digest mismatch");
  if (
    result.evaluatedArtifactDigest !== evidence.fhe.evaluatedArtifactDigest
    || governed.evaluatedArtifactDigest !== evidence.fhe.evaluatedArtifactDigest
    || pins.evaluatedArtifactDigest !== evidence.fhe.evaluatedArtifactDigest
  ) fail("EVALUATED_ARTIFACT", "Evaluated artifact digest mismatch");
  if (
    result.resultCiphertextDigest !== evidence.fhe.resultCiphertext.sha256
    || result.resultCiphertextDigest !== evidence.fhe.independentlyRecomputedResultDigest
    || governed.resultCiphertextDigest !== result.resultCiphertextDigest
    || governed.recomputedResultCiphertextDigest !== result.resultCiphertextDigest
    || pins.recomputedResultCiphertextDigest !== result.resultCiphertextDigest
  ) fail("RESULT_CIPHERTEXT", "Evaluated/recomputed ciphertext digest mismatch");
  if (
    result.resultCiphertextCommitment !== evidence.fhe.resultCiphertextCommitment
    || governed.resultCiphertextCommitment !== result.resultCiphertextCommitment
    || pins.resultCiphertextCommitment !== result.resultCiphertextCommitment
  ) fail("RESULT_COMMITMENT", "Result ciphertext commitment mismatch");
  if (governed.evaluatorProvenance !== evidence.fhe.evaluatorProvenance) fail("EVALUATOR_PROVENANCE", "Evaluator provenance mismatch");
  if (governed.decryptorProvenance !== result.sourceProvenance || pins.decryptorProvenance !== result.sourceProvenance) {
    fail("DECRYPTOR_PROVENANCE", "Decryptor provenance mismatch");
  }

  if (
    binding.releaseMode !== evidence.protectionCase.releaseMode || result.releaseMode !== binding.releaseMode
    || governed.releaseMode !== result.releaseMode || pins.releaseMode !== result.releaseMode
    || binding.releaseAuthorityId !== result.releaseAuthorityId || governed.releaseAuthorityId !== result.releaseAuthorityId
    || pins.releaseAuthorityId !== result.releaseAuthorityId
    || binding.releaseAuthorityPublicKey !== result.releaseAuthorityPublicKey || result.releaseOrdinal !== 1
  ) fail("RELEASE_AUTHORITY_BINDING", "Release mode or authority mismatch");

  const resultDigest = governedResultDigest(result);
  if (resultDigest !== result.digest || governed.governedResultDigest !== result.digest) {
    fail("GOVERNED_RESULT_DIGEST", "Governed-result digest mismatch");
  }
  verifyGovernedResultSignature(result);

  if (
    governed.schemaVersion !== "mordant.governed-fhe-public-evidence/2"
    || governed.productClaim !== PRODUCT_CLAIM_IDENTIFIER
  ) fail("GOVERNED_PRODUCT_PROOF", "Governed public product proof schema or claim mismatch");

  const zeroDigest = `sha256:${"00".repeat(32)}`;
  if (result.conflict) {
    const record = evidence.recourse.record;
    if (
      !evidence.recourse.opened || evidence.recourse.refusedReason !== null || record === null
      || evidence.recourse.recordDigest === null || evidence.protectionCase.recourseState !== "AVAILABLE"
    ) fail("RECOURSE_STATE", "Conflict result must have an available recourse record");
    exactKeys(record, [
      "schemaVersion", "caseId", "caseBindingDigest", "assetIdentity", "policyId", "policyVersion", "resultDigest",
      "releaseMode", "releaseAuthorityId", "recordDateUnix", "boundAtUnix", "cureDeadlineUnix", "reserveBasisPoints",
      "holderAllocationDigest", "originalReceivableIntact", "open",
    ], "RECOURSE_RECORD_FIELDS");
    const recordDigest = sha256Raw(JSON.stringify(recourseRecordValue(record)));
    if (recordDigest !== evidence.recourse.recordDigest || recordDigest !== governed.recourseRecordDigest) {
      fail("RECOURSE_DIGEST", "Recourse record digest mismatch");
    }
    if (
      record.caseBindingDigest !== result.caseBindingDigest || record.assetIdentity !== result.assetIdentity
      || record.policyId !== result.policyId || record.policyVersion !== result.policyVersion
      || record.resultDigest !== result.digest || record.releaseMode !== result.releaseMode
      || record.releaseAuthorityId !== result.releaseAuthorityId
      || record.holderAllocationDigest !== evidence.protectionCase.holderAllocationDigest
      || record.recordDateUnix !== Math.floor(new Date(evidence.protectionCase.holderRecordDate).valueOf() / 1000)
      || record.reserveBasisPoints !== evidence.protectionCase.reserve.basisPoints
      || !record.originalReceivableIntact || !record.open
      || evidence.chronology.cureDeadline !== new Date(record.cureDeadlineUnix * 1000).toISOString()
    ) fail("RECOURSE_PINS", "Recourse record trusted pins mismatch");
  } else if (
    evidence.recourse.opened || evidence.recourse.refusedReason !== "SIGNED_RESULT_FALSE"
    || evidence.recourse.record !== null || evidence.recourse.recordDigest !== null
    || evidence.protectionCase.recourseState !== "REFUSED" || governed.recourseRecordDigest !== zeroDigest
  ) fail("RECOURSE_REFUSAL", "False result must refuse recourse without a record");

  if (
    evidence.chronology.recordDate !== evidence.protectionCase.holderRecordDate
    || evidence.chronology.holderAllocationDigest !== evidence.protectionCase.holderAllocationDigest
  ) fail("CHRONOLOGY_BINDING", "Chronology binding mismatch");
  if (!SOURCE_CLASSIFICATIONS.every((classification) => (
    evidence.sourceClassifications.some((entry) => entry.classification === classification)
  ))) fail("CLASSIFICATIONS", "Protection evidence classifications are incomplete");
  if (
    evidence.originalReceivablePreservation.state !== "OUTSTANDING_INTACT"
    || evidence.protectionCase.originalReceivable.state !== evidence.originalReceivablePreservation.state
    || evidence.originalReceivablePreservation.claimBurnedOrTransferredByProtection
    || !evidence.originalReceivablePreservation.reserveAccountingSeparate
  ) fail("RECEIVABLE_PRESERVATION", "Original receivable preservation is not proven by this manifest");

  if (governed.recourseAttestationDigest !== evidence.recourseAttestation.digest) {
    fail("RECOURSE_ATTESTATION_CROSS_REFERENCE", "Governed-FHE evidence attestation digest mismatch");
  }
  assertSignedRecourseAttestation(evidence, protectionDigest, resultDigest);

  const serialized = JSON.stringify(evidence).toLowerCase();
  for (const forbidden of [
    "secret-key.bin", "decryptor-signing-key.bin", "participant-a.ed25519", "participant-b.ed25519",
    "privateroot", "receivableid", "authorizationcommitment", "privatemetadatacommitment",
  ]) {
    if (serialized.includes(forbidden)) fail("PRIVATE_MATERIAL", `Private material marker found in public evidence: ${forbidden}`);
  }
}
