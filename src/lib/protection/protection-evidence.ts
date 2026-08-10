import { createHash, createPublicKey, verify } from "node:crypto";

import {
  CANONICAL_CLEANVERSE_ASSET_RECORD,
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  cleanverseAssetRecordDigest,
  sha256Digest,
  type CleanverseAssetRecord,
  type Sha256Digest,
} from "./cleanverse-asset";
import {
  assertProtectionBindingDerivations,
  protectionBindingFromCase,
  type MordantProtectionBinding,
  type MordantProtectionCase,
  type ProductScenario,
} from "./protection-case";
import {
  ProtectionEvidenceMetadataError,
  assertRawProtectionEvidenceMetadata,
} from "./protection-evidence-metadata";

export const EXPECTED_GOVERNED_FHE_COMMIT = "3b0247593d022fb18aadd2b554329f85c5a19898";
export const PRODUCT_CLAIM_IDENTIFIER = "mordant.conflicting-pledge-protection/governed-fhe-mvp-v1" as const;
export const EXPECTED_PUBLIC_KEY_BYTES = 7_864_600;

/**
 * One participant enrollment per role, published at submission.
 *
 * Its size is fixed by construction: every field is a digest, an address, a
 * fixed-length Ed25519 signature or a 10-digit unix second, so the file is the
 * same length for either role and from one run to the next.
 *
 * The terminal public-artifact pins below are expressed as a pre-enrollment
 * baseline plus these bytes rather than as one opaque total. When V5 started
 * publishing enrollments the totals moved by exactly this much and the opaque
 * constants silently went stale, which failed every managed run at export.
 * Written this way, a change to the enrollment format moves one number here and
 * both scenarios follow.
 */
export const EXPECTED_ENROLLMENT_BYTES = 940;
const PUBLISHED_ENROLLMENT_BYTES = EXPECTED_ENROLLMENT_BYTES * 2;
export const EXPECTED_RESULT_CIPHERTEXT_BYTES = 6_291_950;

export type PublicObjectReference = Readonly<{
  path: string;
  sha256: Sha256Digest;
  length: number;
}>;

export const CANONICAL_SOURCE_CLASSIFICATION_IDS = Object.freeze([
  "CLEANVERSE_M11_LIVE_OBSERVED",
  "CLEANVERSE_TERMS_DOCUMENTED",
  "N15_GOVERNED_FHE_LOCAL_EXECUTION",
  "RECOURSE_LOCAL_PROTOCOL_DOUBLE",
  "SYNTHETIC_PROTECTED_PLEDGE_FIXTURE",
  "PRODUCTION_CUSTODY_UNPROVEN",
] as const);
export type CanonicalSourceClassificationId = typeof CANONICAL_SOURCE_CLASSIFICATION_IDS[number];
export type ProductClockClass = "REAL_OBSERVED_CLOCK" | "SIMULATED_PROTOCOL_CLOCK";
export type CanonicalChronologyEvent = Readonly<{
  ordinal: number;
  kind: string;
  atUnix: number | null;
  clockSource: string;
  evidenceRef: Sha256Digest;
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
  schemaVersion: "mordant.recourse-attestation/2";
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
  finalRecourseState: "AVAILABLE" | "SIMULATED_AVAILABLE" | "REFUSED";
  finalIncidentState: "CONFLICT_CONFIRMED" | "CLEARED";
  clockClass: ProductClockClass;
  signedAtUnix: number;
  simulationAsOfUnix: number | null;
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
  productClaim:
    | "mordant.conflicting-pledge-protection/governed-fhe-mvp-simulated-protocol-clock-v1"
    | "mordant.conflicting-pledge-protection/governed-fhe-mvp-real-observed-clock-v1";
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
  schemaVersion: "mordant.protection-evidence/4";
  manifestDigest: Sha256Digest;
  runId: string;
  sourceCommit: string;
  governedFheCommit: string;
  scenario: ProductScenario;
  cleanverseAsset: CleanverseAssetRecord;
  cleanverseAssetDigest: Sha256Digest;
  sourceClassifications: readonly CanonicalSourceClassificationId[];
  protectionCase: Omit<MordantProtectionCase, "timeline" | "incidentState" | "cureDeadline" | "recourseState" | "createdAt">;
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
    schemaVersion: "mordant.product-chronology/1";
    clockClass: ProductClockClass;
    signedAtUnix: number;
    simulationAsOfUnix: number | null;
    recordDate: string;
    holderAllocationDigest: Sha256Digest;
    cureDeadlineUnix: number | null;
    finalIncidentState: "CONFLICT_CONFIRMED" | "CLEARED";
    finalRecourseState: "AVAILABLE" | "SIMULATED_AVAILABLE" | "REFUSED";
    events: readonly CanonicalChronologyEvent[];
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

function objectValue(value: unknown, code: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(code, `${code}: expected an object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, `${code}: expected a plain JSON object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: unknown, expected: readonly string[], code: string): asserts value is Record<string, unknown> {
  const actual = Object.keys(objectValue(value, code)).sort();
  const sorted = [...expected].sort();
  if (actual.length !== sorted.length || !actual.every((key, index) => key === sorted[index])) {
    fail(code, `${code}: unexpected or missing fields`);
  }
}

function exactArray(value: unknown, length: number, code: string): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length !== length) {
    fail(code, `${code}: expected exactly ${length} entries`);
  }
}

function exactShape(value: unknown, template: unknown, code: string): void {
  if (Array.isArray(template)) {
    exactArray(value, template.length, code);
    for (let index = 0; index < template.length; index += 1) {
      exactShape(value[index], template[index], code);
    }
    return;
  }
  if (template !== null && typeof template === "object") {
    exactKeys(value, Object.keys(template), code);
    const record = value as Record<string, unknown>;
    for (const [key, nestedTemplate] of Object.entries(template)) {
      exactShape(record[key], nestedTemplate, code);
    }
    return;
  }
  if (value !== null && typeof value === "object") fail(code, `${code}: unexpected nested object`);
}

function exactNonNegativeInteger(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(code, `${code}: expected a non-negative safe integer`);
  }
  return value;
}

function exactSourceCommit(value: unknown, code: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value) || /^0{40}$/.test(value)) {
    fail(code, `${code}: exact non-zero lowercase source commit required`);
  }
  return value;
}

export function resolveProtectionExportSourceCommit(
  expectedSourceCommit: unknown,
  environmentSourceCommit: unknown,
): string {
  const expected = exactSourceCommit(expectedSourceCommit, "SOURCE_COMMIT_PIN");
  const supplied = exactSourceCommit(environmentSourceCommit, "SOURCE_COMMIT_ENV");
  if (supplied !== expected) fail("SOURCE_COMMIT_ENV", "Evidence export source commit disagrees with the server/build pin");
  return expected;
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
    schemaVersion: chronology.schemaVersion,
    clockClass: chronology.clockClass,
    signedAtUnix: chronology.signedAtUnix,
    simulationAsOfUnix: chronology.simulationAsOfUnix,
    recordDate: chronology.recordDate,
    holderAllocationDigest: chronology.holderAllocationDigest,
    cureDeadlineUnix: chronology.cureDeadlineUnix,
    finalIncidentState: chronology.finalIncidentState,
    finalRecourseState: chronology.finalRecourseState,
    events: chronology.events.map((event) => ({
      ordinal: event.ordinal,
      kind: event.kind,
      atUnix: event.atUnix,
      clockSource: event.clockSource,
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
    finalIncidentState: attestation.finalIncidentState,
    clockClass: attestation.clockClass,
    signedAtUnix: attestation.signedAtUnix,
    simulationAsOfUnix: attestation.simulationAsOfUnix,
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

/**
 * The exact fields a Go `SubmissionReport` carries.
 *
 * Exported so there is one list rather than two. The verifier and the Go-to-TS
 * compatibility proof read the same constant, which is what makes a field added
 * on one side fail loudly instead of silently rejecting real evidence: adding
 * `enrollmentBytes` in Go without this list knowing about it made every
 * Go-produced bundle unverifiable here.
 */
export const SUBMISSION_MEASUREMENT_FIELDS = Object.freeze([
  "duration", "ciphertextBytes", "artifactBytes", "enrollmentBytes",
] as const);

/**
 * The shape retained evidence carries, from before submissions issued a V5
 * enrollment.
 *
 * Both shapes are recognised explicitly rather than by relaxing the exact-key
 * check to "at least these fields". Published evidence documents cannot be
 * regenerated without moving digests that are already pinned, and an exact set
 * is what stops an unexpected field riding along; keeping two named sets
 * preserves both properties.
 */
export const LEGACY_SUBMISSION_MEASUREMENT_FIELDS = Object.freeze([
  "duration", "ciphertextBytes", "artifactBytes",
] as const);

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

function expectedCanonicalChronology(evidence: MordantProtectionEvidence): MordantProtectionEvidence["chronology"] {
  const binding = evidence.caseAuthorization.binding;
  const protection = evidence.protectionAuthorization.binding;
  const result = evidence.governedResult;
  const events: CanonicalChronologyEvent[] = [
    { ordinal: 1, kind: "PROTECTED_HOLDER_SNAPSHOT_FIXED", atUnix: Math.floor(new Date(protection.holderRecordDate).valueOf() / 1000), clockSource: "PROTECTION_BINDING_RECORD_DATE", evidenceRef: evidence.protectionAuthorization.bindingDigest },
    { ordinal: 2, kind: "FHE_CASE_CREATED", atUnix: binding.createdAtUnix, clockSource: "SIGNED_FHE_CASE_CLOCK", evidenceRef: evidence.caseAuthorization.bindingDigest },
    { ordinal: 3, kind: "PARTICIPANT_A_ARTIFACT_BOUND", atUnix: null, clockSource: "CRYPTOGRAPHIC_ORDER_ONLY", evidenceRef: result.participantArtifactDigests[0] },
    { ordinal: 4, kind: "PARTICIPANT_B_ARTIFACT_BOUND", atUnix: null, clockSource: "CRYPTOGRAPHIC_ORDER_ONLY", evidenceRef: result.participantArtifactDigests[1] },
    { ordinal: 5, kind: "FHE_EVALUATION_BOUND", atUnix: null, clockSource: "CRYPTOGRAPHIC_ORDER_ONLY", evidenceRef: result.evaluatedArtifactDigest },
    { ordinal: 6, kind: "GOVERNED_RESULT_RELEASED", atUnix: result.releasedAtUnix, clockSource: "SIGNED_GOVERNED_RELEASE_CLOCK", evidenceRef: result.digest },
  ];
  let cureDeadlineUnix: number | null = null;
  let finalIncidentState: "CONFLICT_CONFIRMED" | "CLEARED" = "CLEARED";
  let finalRecourseState: "AVAILABLE" | "SIMULATED_AVAILABLE" | "REFUSED" = "REFUSED";
  let simulationAsOfUnix: number | null = null;
  if (result.conflict) {
    const record = evidence.recourse.record;
    if (record === null || evidence.recourse.recordDigest === null) {
      fail("CHRONOLOGY_RECORD", "Conflict chronology requires the exact durable recourse record");
    }
    cureDeadlineUnix = record.cureDeadlineUnix;
    finalIncidentState = "CONFLICT_CONFIRMED";
    events.push({ ordinal: 7, kind: "RECOURSE_BOUND", atUnix: record.boundAtUnix, clockSource: "DURABLE_RECOURSE_CLOCK", evidenceRef: evidence.recourse.recordDigest });
    if (evidence.chronology.clockClass === "SIMULATED_PROTOCOL_CLOCK") {
      simulationAsOfUnix = record.cureDeadlineUnix + 1;
      finalRecourseState = "SIMULATED_AVAILABLE";
      events.push({ ordinal: 8, kind: "SIMULATED_CURE_WINDOW_COMPLETED", atUnix: simulationAsOfUnix, clockSource: "SIMULATED_PROTOCOL_CLOCK", evidenceRef: evidence.recourse.recordDigest });
    } else {
      if (evidence.chronology.signedAtUnix <= record.cureDeadlineUnix) {
        fail("REAL_CHRONOLOGY_EARLY", "Real observed chronology cannot complete before the cure deadline");
      }
      finalRecourseState = "AVAILABLE";
      events.push({ ordinal: 8, kind: "CURE_WINDOW_COMPLETED", atUnix: evidence.chronology.signedAtUnix, clockSource: "REAL_OBSERVED_CLOCK", evidenceRef: evidence.recourse.recordDigest });
    }
  } else {
    events.push({ ordinal: 7, kind: "RECOURSE_REFUSED_BY_SIGNED_FALSE", atUnix: result.releasedAtUnix, clockSource: "SIGNED_GOVERNED_RELEASE_CLOCK", evidenceRef: result.digest });
  }
  return {
    schemaVersion: "mordant.product-chronology/1",
    clockClass: evidence.chronology.clockClass,
    signedAtUnix: evidence.chronology.signedAtUnix,
    simulationAsOfUnix,
    recordDate: protection.holderRecordDate,
    holderAllocationDigest: protection.holderAllocationDigest,
    cureDeadlineUnix,
    finalIncidentState,
    finalRecourseState,
    events,
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
  assertReleaseAuthorityIdentity(
    binding.releaseAuthorityPublicKey,
    binding.releaseMode,
    binding.releaseAuthorityId,
    "RELEASE_AUTHORITY_IDENTITY",
  );
}

/**
 * The canonical governed-FHE release authority identity.
 *
 * Mirrors `releaseAuthorityIdentity` in fhe-lab/lattigo/governedfhe/types.go:
 * sha256("MordantReleaseAuthorityIdentity/v1" ‖ 0x00 ‖ releaseMode ‖ 0x00 ‖ raw
 * Ed25519 public key). Exported so every verifier binds an authority identity to
 * the key that actually signs, instead of trusting two fields that a forger
 * controls together.
 */
export function releaseAuthorityIdentity(releaseAuthorityPublicKey: string, releaseMode: string): Sha256Digest {
  const raw = Buffer.from(releaseAuthorityPublicKey, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== releaseAuthorityPublicKey) {
    fail("RELEASE_AUTHORITY_KEY", "Invalid Ed25519 release authority public key");
  }
  return sha256Raw(Buffer.concat([
    Buffer.from("MordantReleaseAuthorityIdentity/v1"), Buffer.of(0), Buffer.from(releaseMode), Buffer.of(0), raw,
  ]));
}

/** Requires the claimed authority identity to be the one that key and mode derive. */
export function assertReleaseAuthorityIdentity(
  releaseAuthorityPublicKey: string,
  releaseMode: string,
  claimedAuthorityId: string,
  code = "RELEASE_AUTHORITY_IDENTITY",
): Sha256Digest {
  const derived = releaseAuthorityIdentity(releaseAuthorityPublicKey, releaseMode);
  if (derived !== claimedAuthorityId) fail(code, "Release authority identity mismatch");
  return derived;
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
    "cureDeadline", "finalRecourseState", "finalIncidentState", "clockClass", "signedAtUnix",
    "simulationAsOfUnix", "chronologyDigest", "originalReceivableState",
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
    "MordantRecourseAttestation/v2",
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
    || (attestation.cureDeadline === null ? null : Math.floor(new Date(attestation.cureDeadline).valueOf() / 1000)) !== evidence.chronology.cureDeadlineUnix
    || attestation.clockClass !== evidence.chronology.clockClass
    || attestation.signedAtUnix !== evidence.chronology.signedAtUnix
    || attestation.simulationAsOfUnix !== evidence.chronology.simulationAsOfUnix
    || attestation.finalIncidentState !== evidence.chronology.finalIncidentState
    || attestation.finalRecourseState !== evidence.chronology.finalRecourseState
    || attestation.chronologyDigest !== chronologyDigest
    || attestation.originalReceivableState !== evidence.originalReceivablePreservation.state
    || attestation.reserveAccountingSeparation.reserveDomain !== "PROTECTION"
    || attestation.reserveAccountingSeparation.receivableDomain !== "RECEIVABLE"
    || attestation.reserveAccountingSeparation.separate !== true
    || attestation.reserveAccountingSeparation.claimBurnedOrTransferred !== false
    || attestation.executionClass !== "REAL_BGV_FHE" || attestation.deploymentClass !== "LOCAL_SINGLE_HOST"
    || attestation.releaseClass !== "GOVERNED_DECRYPTOR" || attestation.recourseClass !== "LOCAL_PROTOCOL_DOUBLE"
    || attestation.productionIsolationProven !== false
    || attestation.releaseAuthorityId !== evidence.governedResult.releaseAuthorityId
  ) fail("RECOURSE_ATTESTATION_BINDING", "Signed recourse attestation cross-reference mismatch");
  if (attestation.signedBoolean) {
    const simulated = attestation.clockClass === "SIMULATED_PROTOCOL_CLOCK";
    const expectedClaim = simulated
      ? "mordant.conflicting-pledge-protection/governed-fhe-mvp-simulated-protocol-clock-v1"
      : "mordant.conflicting-pledge-protection/governed-fhe-mvp-real-observed-clock-v1";
    if (
      attestation.recourseRefusal !== "NONE"
      || attestation.finalIncidentState !== "CONFLICT_CONFIRMED"
      || attestation.finalRecourseState !== (simulated ? "SIMULATED_AVAILABLE" : "AVAILABLE")
      || attestation.productClaim !== expectedClaim
    ) {
      fail("RECOURSE_ATTESTATION_STATE", "Conflict attestation clock and recourse state mismatch");
    }
  } else if (
    attestation.recourseRefusal !== "SIGNED_RESULT_FALSE" || attestation.finalRecourseState !== "REFUSED"
    || attestation.finalIncidentState !== "CLEARED" || attestation.cureDeadline !== null
    || attestation.clockClass !== "REAL_OBSERVED_CLOCK" || attestation.simulationAsOfUnix !== null
    || attestation.productClaim !== "mordant.conflicting-pledge-protection/governed-fhe-mvp-real-observed-clock-v1"
  ) fail("RECOURSE_ATTESTATION_STATE", "False result attestation must explicitly refuse recourse");
}

export function protectionEvidenceDigest(
  evidence: Omit<MordantProtectionEvidence, "manifestDigest">,
): Sha256Digest {
  return sha256Digest("MordantProtectionEvidence/v4", evidence);
}

function assertExactPublicEvidenceShape(evidence: MordantProtectionEvidence): void {
  exactKeys(evidence, [
    "schemaVersion", "manifestDigest", "runId", "sourceCommit", "governedFheCommit", "scenario", "cleanverseAsset",
    "cleanverseAssetDigest", "sourceClassifications", "protectionCase", "participantPublicIdentities", "protectionAuthorization",
    "caseAuthorization", "fhe", "governedResult", "chronology", "recourse", "originalReceivablePreservation",
    "recourseAttestation", "governedFheEvidence", "generatedAt",
  ], "PROTECTION_EVIDENCE_FIELDS");

  exactShape(evidence.cleanverseAsset, CANONICAL_CLEANVERSE_ASSET_RECORD, "CLEANVERSE_ASSET_FIELDS");
  exactKeys(evidence.protectionCase, [
    "schemaVersion", "productScenario", "cleanverseAsset", "cleanverseAssetDigest", "service", "serviceVersion",
    "policyId", "policyVersion", "protectedAmount", "reserve", "holderRecordDate", "holderSnapshot",
    "holderAllocationDigest", "caseNonce", "fheCaseId", "releaseMode", "originalReceivable",
    "evidenceReferences",
  ], "PUBLIC_PROTECTION_CASE_FIELDS");
  exactShape(evidence.protectionCase.cleanverseAsset, CANONICAL_CLEANVERSE_ASSET_RECORD, "PROTECTION_CASE_ASSET_FIELDS");
  exactKeys(evidence.protectionCase.protectedAmount, ["asset", "minorUnits"], "PUBLIC_PROTECTED_AMOUNT_FIELDS");
  exactKeys(evidence.protectionCase.reserve, [
    "basisPoints", "minorUnits", "accountingDomain", "executionClassification",
  ], "PUBLIC_RESERVE_FIELDS");
  exactArray(evidence.protectionCase.holderSnapshot, 2, "PUBLIC_HOLDER_SNAPSHOT");
  for (const holder of evidence.protectionCase.holderSnapshot) {
    exactKeys(holder, ["holderId", "protectedUnits", "allocationBps"], "PUBLIC_HOLDER_FIELDS");
  }
  exactKeys(evidence.protectionCase.originalReceivable, [
    "state", "principalMinorUnits", "units", "accountingDomain",
  ], "PUBLIC_RECEIVABLE_FIELDS");
  exactArray(evidence.protectionCase.evidenceReferences, 3, "PUBLIC_EVIDENCE_REFERENCES");

  exactArray(evidence.participantPublicIdentities, 2, "PUBLIC_PARTICIPANT_IDENTITIES");
  for (const identity of evidence.participantPublicIdentities) {
    exactKeys(identity, ["role", "id", "signingPublicKey"], "PUBLIC_PARTICIPANT_IDENTITY_FIELDS");
  }
  exactKeys(evidence.protectionAuthorization, [
    "binding", "bindingDigest", "participantSignatures",
  ], "PROTECTION_AUTHORIZATION_FIELDS");
  exactArray(evidence.protectionAuthorization.participantSignatures, 2, "PROTECTION_SIGNATURES");
  exactKeys(evidence.caseAuthorization, [
    "binding", "bindingDigest", "participantSignatures",
  ], "CASE_AUTHORIZATION_FIELDS");
  exactArray(evidence.caseAuthorization.binding.participantOrder, 2, "PARTICIPANT_ORDER_FIELDS");
  exactArray(evidence.caseAuthorization.participantSignatures, 2, "PARTICIPANT_SIGNATURES");

  exactKeys(evidence.fhe, [
    "caseId", "assetIdentity", "caseBindingDigest", "profile", "circuitId", "circuitVersion", "circuitDigest",
    "publicKey", "evaluationKeyManifestDigest", "participantArtifactDigests", "evaluatedArtifactDigest",
    "resultCiphertext", "resultCiphertextCommitment", "evaluatorProvenance", "independentlyRecomputedResultDigest",
  ], "FHE_FIELDS");
  exactKeys(evidence.fhe.publicKey, ["path", "sha256", "length"], "FHE_PUBLIC_KEY_FIELDS");
  exactKeys(evidence.fhe.resultCiphertext, ["path", "sha256", "length"], "FHE_RESULT_CIPHERTEXT_FIELDS");
  exactArray(evidence.fhe.participantArtifactDigests, 2, "FHE_PARTICIPANT_ARTIFACTS");
  if (
    evidence.fhe.publicKey.path !== "public-key.bin"
    || evidence.fhe.publicKey.length !== EXPECTED_PUBLIC_KEY_BYTES
    || evidence.fhe.resultCiphertext.path !== "result-conflict.bin"
    || evidence.fhe.resultCiphertext.length !== EXPECTED_RESULT_CIPHERTEXT_BYTES
  ) fail("FHE_PUBLIC_OBJECT_METADATA", "Unexpected FHE public-object path or size");

  exactKeys(evidence.governedResult, [
    "schemaVersion", "caseId", "caseBindingDigest", "assetIdentity", "serviceId", "serviceVersion", "policyId",
    "policyVersion", "circuitId", "circuitVersion", "circuitDigest", "parameterProfile", "parameterFingerprint",
    "participantArtifactDigests", "evaluatedArtifactDigest", "resultCiphertextDigest", "resultCiphertextCommitment",
    "conflict", "releaseOrdinal", "releaseMode", "releaseAuthorityId", "releaseAuthorityPublicKey", "releasedAtUnix",
    "sourceProvenance", "signature", "digest",
  ], "GOVERNED_RESULT_FIELDS");
  exactArray(evidence.governedResult.participantArtifactDigests, 2, "GOVERNED_RESULT_PARTICIPANT_ARTIFACTS");

  exactKeys(evidence.chronology, [
    "schemaVersion", "clockClass", "signedAtUnix", "simulationAsOfUnix", "recordDate",
    "holderAllocationDigest", "cureDeadlineUnix", "finalIncidentState", "finalRecourseState", "events",
  ], "CHRONOLOGY_FIELDS");
  if (!Array.isArray(evidence.chronology.events)) fail("CHRONOLOGY_EVENTS", "Chronology events must be an array");
  for (const event of evidence.chronology.events) {
    exactKeys(event, ["ordinal", "kind", "atUnix", "clockSource", "evidenceRef"], "CHRONOLOGY_EVENT_FIELDS");
  }

  exactKeys(evidence.recourse, [
    "classification", "opened", "refusedReason", "recordDigest", "record",
  ], "RECOURSE_FIELDS");
  if (evidence.recourse.record !== null) {
    exactKeys(evidence.recourse.record, [
      "schemaVersion", "caseId", "caseBindingDigest", "assetIdentity", "policyId", "policyVersion", "resultDigest",
      "releaseMode", "releaseAuthorityId", "recordDateUnix", "boundAtUnix", "cureDeadlineUnix", "reserveBasisPoints",
      "holderAllocationDigest", "originalReceivableIntact", "open",
    ], "RECOURSE_RECORD_FIELDS");
  }
  exactKeys(evidence.originalReceivablePreservation, [
    "state", "principalMinorUnits", "units", "reserveAccountingSeparate", "claimBurnedOrTransferredByProtection",
  ], "RECEIVABLE_PRESERVATION_FIELDS");
  exactKeys(evidence.recourseAttestation, ["digest", "attestation"], "RECOURSE_ATTESTATION_ENVELOPE_FIELDS");

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
  exactArray(governed.submissionDigests, 2, "GOVERNED_SUBMISSION_DIGESTS");
  exactKeys(governed.measurements, [
    "keyGeneration", "submissions", "evaluation", "release", "completeDuration", "peakRssBytes",
  ], "GOVERNED_MEASUREMENT_FIELDS");
  const measurements = governed.measurements as Record<string, unknown>;
  exactKeys(measurements.keyGeneration, [
    "duration", "parameterBytes", "publicKeyBytes", "relinearizationKeyBytes", "galoisKeyBytes",
    "publicArtifactBytes", "privateArtifactBytes",
  ], "KEY_GENERATION_MEASUREMENT_FIELDS");
  const keyGeneration = measurements.keyGeneration as Record<string, unknown>;
  exactArray(keyGeneration.galoisKeyBytes, 9, "GALOIS_KEY_MEASUREMENT_FIELDS");
  exactArray(measurements.submissions, 2, "SUBMISSION_MEASUREMENT_FIELDS");
  for (const submission of measurements.submissions) {
    const fields = Object.hasOwn(submission as object, "enrollmentBytes")
      ? SUBMISSION_MEASUREMENT_FIELDS
      : LEGACY_SUBMISSION_MEASUREMENT_FIELDS;
    exactKeys(submission, fields, "SUBMISSION_MEASUREMENT_FIELDS");
  }
  exactKeys(measurements.evaluation, [
    "duration", "resultCiphertextBytes", "artifactBytes",
  ], "EVALUATION_MEASUREMENT_FIELDS");
  exactKeys(measurements.release, [
    "duration", "resultBytes", "exactRetry", "trustedRecoursePins",
  ], "RELEASE_MEASUREMENT_FIELDS");
  const release = measurements.release as Record<string, unknown>;
  exactKeys(release.trustedRecoursePins, [
    "participantArtifactDigestA", "participantArtifactDigestB", "evaluatedArtifactDigest",
    "recomputedResultCiphertextDigest", "resultCiphertextCommitment", "decryptorProvenance",
    "releaseMode", "releaseAuthorityId",
  ], "TRUSTED_RECOURSE_PIN_FIELDS");

  const evaluation = measurements.evaluation as Record<string, unknown>;
  // Retained documents predate V5 and published no enrollment, so their public
  // set is the baseline. A V5 run publishes one per role, and its submission
  // measurement carries `enrollmentBytes` (the same marker the field list uses).
  // Reading the marker rather than the value is deliberate: the value is
  // currently zeroed on the way through measurements.json, while the files are
  // on disk either way, so the count is what the total can be trusted to.
  const publishesEnrollments = (measurements.submissions as unknown[]).some(
    (entry) => Object.hasOwn(entry as object, "enrollmentBytes"),
  );
  const publishedEnrollmentBytes = publishesEnrollments ? PUBLISHED_ENROLLMENT_BYTES : 0;
  const expectedTerminalSizes = evidence.scenario === "conflict"
    ? { releaseResultBytes: 1_750, publicArtifactBytes: 391_684_354 + publishedEnrollmentBytes }
    : evidence.scenario === "no-conflict"
      ? { releaseResultBytes: 1_751, publicArtifactBytes: 391_682_810 + publishedEnrollmentBytes }
      : null;
  if (
    expectedTerminalSizes === null
    || keyGeneration.parameterBytes !== 459
    || keyGeneration.publicKeyBytes !== EXPECTED_PUBLIC_KEY_BYTES
    || keyGeneration.relinearizationKeyBytes !== 31_458_448
    || !(keyGeneration.galoisKeyBytes as unknown[]).every((value) => value === 31_458_464)
    || keyGeneration.publicArtifactBytes !== 322_454_282
    || keyGeneration.privateArtifactBytes !== 3_932_962
    || !(measurements.submissions as unknown[]).every((entry) => {
      const submission = entry as Record<string, unknown>;
      return submission.ciphertextBytes === 31_459_990 && submission.artifactBytes === 1_853;
    })
    || evaluation.resultCiphertextBytes !== EXPECTED_RESULT_CIPHERTEXT_BYTES
    || evaluation.artifactBytes !== 1_347
    || release.resultBytes !== expectedTerminalSizes.releaseResultBytes
    || governed.publicArtifactBytes !== expectedTerminalSizes.publicArtifactBytes
  ) fail("FHE_MEASUREMENT_SIZE", "Unexpected FHE artifact size metadata");
  for (const [code, value] of [
    ["KEY_GENERATION_DURATION", keyGeneration.duration],
    ["COMPLETE_DURATION", measurements.completeDuration],
    ["PEAK_RSS_BYTES", measurements.peakRssBytes],
    ["EVALUATION_DURATION", evaluation.duration],
    ["RELEASE_DURATION", release.duration],
    ["GENERATED_AT_UNIX", governed.generatedAtUnix],
  ] as const) exactNonNegativeInteger(value, code);
  for (const entry of measurements.submissions as unknown[]) {
    exactNonNegativeInteger((entry as Record<string, unknown>).duration, "SUBMISSION_DURATION");
  }
}

function assertPublicProtectionEvidenceUnchecked(
  evidence: MordantProtectionEvidence,
  expectedSourceCommit: unknown,
  expectedCaseManifestDigest?: unknown,
): void {
  if (!Object.hasOwn(objectValue(evidence, "PROTECTION_EVIDENCE_STRUCTURE"), "sourceCommit")) {
    fail("SOURCE_COMMIT", "Protection evidence source commit is missing");
  }
  assertExactPublicEvidenceShape(evidence);
  if (evidence.schemaVersion !== "mordant.protection-evidence/4") fail("SCHEMA", "Unsupported protection evidence schema");
  const { manifestDigest, ...value } = evidence;
  // manifestDigest detects transport corruption; authenticity is established
  // only by the three signed canonical roots below.
  if (manifestDigest !== protectionEvidenceDigest(value)) fail("MANIFEST_DIGEST", "Protection evidence digest mismatch");
  const expectedCommit = exactSourceCommit(expectedSourceCommit, "SOURCE_COMMIT_PIN");
  if (exactSourceCommit(evidence.sourceCommit, "SOURCE_COMMIT") !== expectedCommit) {
    fail("SOURCE_COMMIT", "Protection evidence source commit disagrees with the server/build pin");
  }
  if (evidence.governedFheCommit !== EXPECTED_GOVERNED_FHE_COMMIT) fail("GOVERNED_FHE_COMMIT", "Unexpected governed-FHE commit");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(evidence.runId)) {
    fail("RUN_ID", "Protection evidence run ID rejected");
  }

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
    || governed.publicStructureValidated !== true
    || governed.executionClass !== "REAL_BGV_FHE"
    || governed.deploymentClass !== "LOCAL_SINGLE_HOST"
    || governed.releaseClass !== "GOVERNED_DECRYPTOR"
    || governed.recourseClass !== "LOCAL_PROTOCOL_DOUBLE"
    || governed.productionIsolationProven !== false
  ) fail("GOVERNED_PRODUCT_PROOF", "Governed public product proof schema or claim mismatch");

  if (
    evidence.protectionCase.reserve.accountingDomain !== "PROTECTION"
    || evidence.protectionCase.reserve.executionClassification !== "PROTOCOL_DOUBLE"
    || evidence.protectionCase.originalReceivable.accountingDomain !== "RECEIVABLE"
    || evidence.recourse.classification !== "PROTOCOL_DOUBLE"
  ) fail("PUBLIC_CLASSIFICATION", "Contradictory public execution or accounting classification");

  const zeroDigest = `sha256:${"00".repeat(32)}`;
  if (result.conflict) {
    const record = evidence.recourse.record;
    if (
      evidence.recourse.opened !== true || evidence.recourse.refusedReason !== null || record === null
      || evidence.recourse.recordDigest === null
    ) fail("RECOURSE_STATE", "Conflict result must have a recourse record");
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
      || record.boundAtUnix < result.releasedAtUnix || record.boundAtUnix > binding.expiresAtUnix
      || record.cureDeadlineUnix !== record.boundAtUnix + 24 * 60 * 60
    ) fail("RECOURSE_PINS", "Recourse record trusted pins mismatch");
  } else if (
    evidence.recourse.opened !== false || evidence.recourse.refusedReason !== "SIGNED_RESULT_FALSE"
    || evidence.recourse.record !== null || evidence.recourse.recordDigest !== null
    || governed.recourseRecordDigest !== zeroDigest
  ) fail("RECOURSE_REFUSAL", "False result must refuse recourse without a record");

  exactKeys(evidence.chronology, [
    "schemaVersion", "clockClass", "signedAtUnix", "simulationAsOfUnix", "recordDate",
    "holderAllocationDigest", "cureDeadlineUnix", "finalIncidentState", "finalRecourseState", "events",
  ], "CHRONOLOGY_FIELDS");
  if (
    evidence.chronology.signedAtUnix < result.releasedAtUnix
    || evidence.chronology.signedAtUnix > binding.expiresAtUnix
    || JSON.stringify(chronologyValue(evidence.chronology)) !== JSON.stringify(chronologyValue(expectedCanonicalChronology(evidence)))
  ) fail("CHRONOLOGY_CANONICAL", "Chronology was not reconstructed from the exact signed artifacts");
  for (const event of evidence.chronology.events) {
    exactKeys(event, ["ordinal", "kind", "atUnix", "clockSource", "evidenceRef"], "CHRONOLOGY_EVENT_FIELDS");
  }
  if (
    evidence.sourceClassifications.length !== CANONICAL_SOURCE_CLASSIFICATION_IDS.length
    || !evidence.sourceClassifications.every((value, index) => value === CANONICAL_SOURCE_CLASSIFICATION_IDS[index])
  ) fail("CLASSIFICATIONS", "Canonical source classification IDs changed");
  if (
    evidence.originalReceivablePreservation.state !== "OUTSTANDING_INTACT"
    || evidence.protectionCase.originalReceivable.state !== evidence.originalReceivablePreservation.state
    || evidence.originalReceivablePreservation.claimBurnedOrTransferredByProtection !== false
    || evidence.originalReceivablePreservation.reserveAccountingSeparate !== true
  ) fail("RECEIVABLE_PRESERVATION", "Original receivable preservation is not proven by this manifest");

  if (governed.recourseAttestationDigest !== evidence.recourseAttestation.digest) {
    fail("RECOURSE_ATTESTATION_CROSS_REFERENCE", "Governed-FHE evidence attestation digest mismatch");
  }
  assertSignedRecourseAttestation(evidence, protectionDigest, resultDigest);

  // Raw metadata is validated only after the stronger signed-root and
  // cross-reference checks, but still before a public projection is reachable.
  // This preserves precise cryptographic rejection reasons while ensuring
  // unsigned transport metadata can never enter the projected DTO unchecked.
  assertRawProtectionEvidenceMetadata(evidence, expectedCaseManifestDigest);

  const serialized = JSON.stringify(evidence).toLowerCase();
  for (const forbidden of [
    "secret-key.bin", "decryptor-signing-key.bin", "participant-a.ed25519", "participant-b.ed25519",
    "privateroot", "receivableid", "authorizationcommitment", "privatemetadatacommitment",
  ]) {
    if (serialized.includes(forbidden)) fail("PRIVATE_MATERIAL", `Private material marker found in public evidence: ${forbidden}`);
  }
}

export function assertPublicProtectionEvidence(
  evidence: unknown,
  expectedSourceCommit: unknown,
  expectedCaseManifestDigest?: unknown,
): asserts evidence is MordantProtectionEvidence {
  try {
    objectValue(evidence, "PROTECTION_EVIDENCE_STRUCTURE");
    assertPublicProtectionEvidenceUnchecked(
      evidence as MordantProtectionEvidence,
      expectedSourceCommit,
      expectedCaseManifestDigest,
    );
  } catch (error) {
    if (error instanceof ProtectionEvidenceError) throw error;
    if (error instanceof ProtectionEvidenceMetadataError) fail(error.code, "Protection evidence metadata rejected");
    fail("PROTECTION_EVIDENCE_STRUCTURE", "Malformed protection evidence was rejected");
  }
}
