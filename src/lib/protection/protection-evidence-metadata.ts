import { CANONICAL_CLEANVERSE_ASSET_RECORD, type CleanverseAssetRecord } from "./cleanverse-asset";
import type { MordantProtectionEvidence } from "./protection-evidence";

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RAW_SHA256 = /^[0-9a-f]{64}$/u;
const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ISO_SECOND_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/u;
const DOCUMENTED_TIMESTAMP = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/u;

const RETAINED_CASE_MANIFEST_DIGEST_BY_CASE_ID: Readonly<Record<string, string>> = Object.freeze({
  "sha256:806de678d14adbde33a0048d244389d3404b6c45d0c71163e2fd5a283c60828e":
    "sha256:7646faaf01cbaadaea7bf94f56a2944ec6ba4df38976537b0035080ccd60e58a",
  "sha256:fb2d027624ba82a355765170446e9f537e5746a1a6d319fecc41b8da9f9bbd10":
    "sha256:43bdde391121d6fadbfb8ec885f2a60f8d46d205f606463b3a1af805ade23ba7",
});

const CANONICAL_EVIDENCE_REFERENCES = Object.freeze(
  CANONICAL_CLEANVERSE_ASSET_RECORD.provenance.value.sources.map((source) => source.evidencePath),
);

export class ProtectionEvidenceMetadataError extends Error {
  constructor(readonly code: string) {
    super("Protection evidence metadata rejected");
    this.name = "ProtectionEvidenceMetadataError";
  }
}

function reject(code: string): never {
  throw new ProtectionEvidenceMetadataError(code);
}

function exactLiteral(value: unknown, expected: string | number | boolean, code: string): void {
  if (value !== expected || typeof value !== typeof expected) reject(code);
}

function nonNegativeInteger(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) reject(code);
  return value;
}

function positiveInteger(value: unknown, code: string): number {
  const integer = nonNegativeInteger(value, code);
  if (integer === 0) reject(code);
  return integer;
}

function canonicalDigest(value: unknown, code: string, zeroAllowed = false): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value) || (!zeroAllowed && value === ZERO_DIGEST)) {
    reject(code);
  }
  return value;
}

function canonicalRawSha256(value: unknown, code: string): void {
  if (typeof value !== "string" || !RAW_SHA256.test(value) || /^0{64}$/u.test(value)) reject(code);
}

function canonicalInstant(value: unknown, code: string): number {
  if (typeof value !== "string" || !ISO_INSTANT.test(value)) reject(code);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value) reject(code);
  return parsed.valueOf();
}

function canonicalSecondInstant(value: unknown, code: string): number {
  if (typeof value !== "string" || !ISO_SECOND_INSTANT.test(value)) reject(code);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value.replace(/Z$/u, ".000Z")) reject(code);
  return parsed.valueOf();
}

function canonicalDate(value: unknown, code: string): void {
  if (typeof value !== "string" || !ISO_DATE.test(value)) reject(code);
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString().slice(0, 10) !== value) reject(code);
}

function documentedTimestamp(value: unknown, code: string): void {
  if (typeof value !== "string") reject(code);
  const match = DOCUMENTED_TIMESTAMP.exec(value);
  if (match === null) reject(code);
  const [, year, month, day, hour, minute, second] = match;
  const parsed = new Date(Date.UTC(
    Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second),
  ));
  if (
    parsed.getUTCFullYear() !== Number(year) || parsed.getUTCMonth() + 1 !== Number(month)
    || parsed.getUTCDate() !== Number(day) || parsed.getUTCHours() !== Number(hour)
    || parsed.getUTCMinutes() !== Number(minute) || parsed.getUTCSeconds() !== Number(second)
  ) reject(code);
}

function canonicalRepositoryReference(value: unknown, code: string): string {
  if (
    typeof value !== "string" || value.length === 0 || value.includes("\0") || value.includes("\\")
    || value.startsWith("/") || /^[A-Za-z]:/u.test(value) || value.includes("://")
    || value.includes("?") || value.includes("#") || !/^[A-Za-z0-9._/-]+$/u.test(value)
  ) reject(code);
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) reject(code);
  return value;
}

function validateCleanverseMetadata(record: CleanverseAssetRecord, prefix: string): void {
  exactLiteral(record.schemaVersion, "mordant.cleanverse-asset-record/2", `${prefix}_SCHEMA`);
  for (const [name, value] of [
    ["NETWORK", record.network],
    ["CANONICAL_IDENTITY", record.canonicalAssetIdentity],
    ["TOKEN", record.token],
    ["SOURCE_IDENTITY", record.sourceIdentity],
    ["POLICY", record.policy],
    ["APASS", record.aPass],
    ["SETTLEMENT", record.settlementAsset],
    ["ISSUANCE", record.issuance],
    ["TOKEN_DEPLOYMENT", record.tokenDeployment],
    ["PREFLIGHT", record.preflightObservation],
    ["PROVENANCE", record.provenance],
  ] as const) canonicalInstant(value.observedAt, `${prefix}_${name}_OBSERVED_AT`);
  canonicalDate(record.documentationTerms.observedAt, `${prefix}_DOCUMENTATION_OBSERVED_AT`);
  canonicalDate(record.documentationTerms.value.consultedAtRaw, `${prefix}_DOCUMENTATION_CONSULTED_AT`);
  documentedTimestamp(record.issuance.value.issuedAtRaw, `${prefix}_ISSUED_AT_RAW`);
  canonicalInstant(record.preflightObservation.value.generatedAt, `${prefix}_PREFLIGHT_GENERATED_AT`);
  if (record.preflightObservation.value.generatedAt !== record.preflightObservation.observedAt) {
    reject(`${prefix}_PREFLIGHT_DATE_BINDING`);
  }
  positiveInteger(record.aPass.value.holderAExpirationUnix, `${prefix}_APASS_A_EXPIRY`);
  positiveInteger(record.aPass.value.holderBExpirationUnix, `${prefix}_APASS_B_EXPIRY`);

  const paths = record.provenance.value.sources.map((source, index) => {
    canonicalRawSha256(source.evidenceSha256, `${prefix}_SOURCE_${index}_SHA256`);
    return canonicalRepositoryReference(source.evidencePath, `${prefix}_SOURCE_${index}_PATH`);
  });
  if (
    paths.length !== CANONICAL_EVIDENCE_REFERENCES.length
    || !paths.every((path, index) => path === CANONICAL_EVIDENCE_REFERENCES[index])
  ) reject(`${prefix}_SOURCE_ORDER`);

  for (const [name, source] of [
    ["NETWORK", record.network.source],
    ["CANONICAL_IDENTITY", record.canonicalAssetIdentity.source],
    ["TOKEN", record.token.source],
    ["SOURCE_IDENTITY", record.sourceIdentity.source],
    ["POLICY", record.policy.source],
    ["DOCUMENTATION", record.documentationTerms.source],
    ["APASS", record.aPass.source],
    ["SETTLEMENT", record.settlementAsset.source],
    ["ISSUANCE", record.issuance.source],
    ["TOKEN_DEPLOYMENT", record.tokenDeployment.source],
    ["PREFLIGHT", record.preflightObservation.source],
    ["PROVENANCE", record.provenance.source],
  ] as const) canonicalRepositoryReference(source, `${prefix}_${name}_SOURCE`);
}

function validateSchemaLiterals(evidence: MordantProtectionEvidence): void {
  exactLiteral(evidence.schemaVersion, "mordant.protection-evidence/4", "EVIDENCE_SCHEMA_LITERAL");
  exactLiteral(evidence.protectionCase.schemaVersion, "mordant.protection-case/1", "CASE_SCHEMA_LITERAL");
  exactLiteral(
    evidence.protectionAuthorization.binding.schemaVersion,
    "mordant.protection-binding/1",
    "PROTECTION_BINDING_SCHEMA_LITERAL",
  );
  exactLiteral(
    evidence.caseAuthorization.binding.schemaVersion,
    "mordant.fhe-case-binding/1",
    "FHE_BINDING_SCHEMA_LITERAL",
  );
  exactLiteral(
    evidence.governedResult.schemaVersion,
    "mordant.governed-conflict-result/1",
    "GOVERNED_RESULT_SCHEMA_LITERAL",
  );
  exactLiteral(evidence.chronology.schemaVersion, "mordant.product-chronology/1", "CHRONOLOGY_SCHEMA_LITERAL");
  if (evidence.recourse.record !== null) {
    exactLiteral(
      evidence.recourse.record.schemaVersion,
      "mordant.fhe-recourse-adapter-record/1",
      "RECOURSE_RECORD_SCHEMA_LITERAL",
    );
  }
  exactLiteral(
    evidence.recourseAttestation.attestation.schemaVersion,
    "mordant.recourse-attestation/2",
    "RECOURSE_ATTESTATION_SCHEMA_LITERAL",
  );
  exactLiteral(
    evidence.governedFheEvidence.schemaVersion,
    "mordant.governed-fhe-public-evidence/2",
    "GOVERNED_FHE_SCHEMA_LITERAL",
  );
  validateCleanverseMetadata(evidence.cleanverseAsset, "CLEANVERSE_ASSET");
  validateCleanverseMetadata(evidence.protectionCase.cleanverseAsset, "CASE_CLEANVERSE_ASSET");
}

function validateExactReceivableLiterals(evidence: MordantProtectionEvidence): void {
  exactLiteral(
    evidence.protectionCase.originalReceivable.principalMinorUnits,
    "110000000",
    "CASE_RECEIVABLE_PRINCIPAL_LITERAL",
  );
  exactLiteral(evidence.protectionCase.originalReceivable.units, "100000000", "CASE_RECEIVABLE_UNITS_LITERAL");
  exactLiteral(
    evidence.originalReceivablePreservation.principalMinorUnits,
    "110000000",
    "PRESERVATION_PRINCIPAL_LITERAL",
  );
  exactLiteral(evidence.originalReceivablePreservation.units, "100000000", "PRESERVATION_UNITS_LITERAL");
}

function validateEvidenceReferences(evidence: MordantProtectionEvidence): void {
  if (evidence.protectionCase.evidenceReferences.length !== CANONICAL_EVIDENCE_REFERENCES.length) {
    reject("EVIDENCE_REFERENCE_COUNT");
  }
  const references = evidence.protectionCase.evidenceReferences.map((reference, index) => (
    canonicalRepositoryReference(reference, `EVIDENCE_REFERENCE_${index}`)
  ));
  if (!references.every((reference, index) => reference === CANONICAL_EVIDENCE_REFERENCES[index])) {
    reject("EVIDENCE_REFERENCE_ORDER");
  }
  canonicalRepositoryReference(evidence.fhe.publicKey.path, "PUBLIC_KEY_REFERENCE");
  canonicalRepositoryReference(evidence.fhe.resultCiphertext.path, "RESULT_CIPHERTEXT_REFERENCE");
}

function validateDigests(evidence: MordantProtectionEvidence, expectedCaseManifestDigest: unknown): void {
  const binding = evidence.caseAuthorization.binding;
  const protection = evidence.protectionAuthorization;
  const result = evidence.governedResult;
  const attestation = evidence.recourseAttestation.attestation;
  const governed = evidence.governedFheEvidence;
  const pins = governed.measurements.release.trustedRecoursePins;
  const required: ReadonlyArray<readonly [string, unknown]> = [
    ["MANIFEST_DIGEST_FORMAT", evidence.manifestDigest],
    ["ASSET_DIGEST_FORMAT", evidence.cleanverseAssetDigest],
    ["CASE_ASSET_DIGEST_FORMAT", evidence.protectionCase.cleanverseAssetDigest],
    ["CASE_POLICY_DIGEST_FORMAT", evidence.protectionCase.policyId],
    ["CASE_HOLDER_DIGEST_FORMAT", evidence.protectionCase.holderAllocationDigest],
    ["CASE_NONCE_DIGEST_FORMAT", evidence.protectionCase.caseNonce],
    ["CASE_ID_DIGEST_FORMAT", evidence.protectionCase.fheCaseId],
    ["PARTICIPANT_A_ID_FORMAT", evidence.participantPublicIdentities[0].id],
    ["PARTICIPANT_B_ID_FORMAT", evidence.participantPublicIdentities[1].id],
    ["PROTECTION_ASSET_DIGEST_FORMAT", protection.binding.cleanverseAssetRecordDigest],
    ["PROTECTION_POLICY_DIGEST_FORMAT", protection.binding.policyId],
    ["PROTECTION_HOLDER_DIGEST_FORMAT", protection.binding.holderAllocationDigest],
    ["PROTECTION_NONCE_DIGEST_FORMAT", protection.binding.caseNonce],
    ["PROTECTION_CASE_ID_FORMAT", protection.binding.fheCaseId],
    ["PROTECTION_BINDING_DIGEST_FORMAT", protection.bindingDigest],
    ["PROTECTION_SIGNATURE_A_ID_FORMAT", protection.participantSignatures[0].participantId],
    ["PROTECTION_SIGNATURE_A_DIGEST_FORMAT", protection.participantSignatures[0].protectionBindingDigest],
    ["PROTECTION_SIGNATURE_B_ID_FORMAT", protection.participantSignatures[1].participantId],
    ["PROTECTION_SIGNATURE_B_DIGEST_FORMAT", protection.participantSignatures[1].protectionBindingDigest],
    ["FHE_BINDING_CASE_ID_FORMAT", binding.caseId],
    ["FHE_BINDING_ASSET_FORMAT", binding.assetIdentity],
    ["FHE_BINDING_POLICY_FORMAT", binding.policyId],
    ["FHE_BINDING_CIRCUIT_FORMAT", binding.circuitDigest],
    ["FHE_BINDING_PARAMETER_FORMAT", binding.parameterFingerprint],
    ["FHE_BINDING_PUBLIC_KEY_FORMAT", binding.publicKeyDigest],
    ["FHE_BINDING_EVALUATION_KEYS_FORMAT", binding.evaluationKeyManifestDigest],
    ["FHE_BINDING_PARTICIPANT_A_FORMAT", binding.participantA.id],
    ["FHE_BINDING_PARTICIPANT_B_FORMAT", binding.participantB.id],
    ["FHE_BINDING_ORDER_A_FORMAT", binding.participantOrder[0]],
    ["FHE_BINDING_ORDER_B_FORMAT", binding.participantOrder[1]],
    ["FHE_BINDING_AUTHORITY_FORMAT", binding.releaseAuthorityId],
    ["FHE_BINDING_NONCE_FORMAT", binding.caseNonce],
    ["FHE_BINDING_DIGEST_FORMAT", evidence.caseAuthorization.bindingDigest],
    ["FHE_SIGNATURE_A_ID_FORMAT", evidence.caseAuthorization.participantSignatures[0].participantId],
    ["FHE_SIGNATURE_A_DIGEST_FORMAT", evidence.caseAuthorization.participantSignatures[0].bindingDigest],
    ["FHE_SIGNATURE_B_ID_FORMAT", evidence.caseAuthorization.participantSignatures[1].participantId],
    ["FHE_SIGNATURE_B_DIGEST_FORMAT", evidence.caseAuthorization.participantSignatures[1].bindingDigest],
    ["FHE_CASE_ID_FORMAT", evidence.fhe.caseId],
    ["FHE_ASSET_FORMAT", evidence.fhe.assetIdentity],
    ["FHE_CASE_BINDING_FORMAT", evidence.fhe.caseBindingDigest],
    ["FHE_CIRCUIT_FORMAT", evidence.fhe.circuitDigest],
    ["FHE_PUBLIC_KEY_FORMAT", evidence.fhe.publicKey.sha256],
    ["FHE_EVALUATION_KEYS_FORMAT", evidence.fhe.evaluationKeyManifestDigest],
    ["FHE_PARTICIPANT_A_FORMAT", evidence.fhe.participantArtifactDigests[0]],
    ["FHE_PARTICIPANT_B_FORMAT", evidence.fhe.participantArtifactDigests[1]],
    ["FHE_EVALUATED_FORMAT", evidence.fhe.evaluatedArtifactDigest],
    ["FHE_RESULT_FORMAT", evidence.fhe.resultCiphertext.sha256],
    ["FHE_RESULT_COMMITMENT_FORMAT", evidence.fhe.resultCiphertextCommitment],
    ["FHE_EVALUATOR_PROVENANCE_FORMAT", evidence.fhe.evaluatorProvenance],
    ["FHE_RECOMPUTED_FORMAT", evidence.fhe.independentlyRecomputedResultDigest],
    ["RESULT_DIGEST_FORMAT", result.digest],
    ["RESULT_CASE_ID_FORMAT", result.caseId],
    ["RESULT_CASE_BINDING_FORMAT", result.caseBindingDigest],
    ["RESULT_ASSET_FORMAT", result.assetIdentity],
    ["RESULT_POLICY_FORMAT", result.policyId],
    ["RESULT_CIRCUIT_FORMAT", result.circuitDigest],
    ["RESULT_PARAMETER_FORMAT", result.parameterFingerprint],
    ["RESULT_PARTICIPANT_A_FORMAT", result.participantArtifactDigests[0]],
    ["RESULT_PARTICIPANT_B_FORMAT", result.participantArtifactDigests[1]],
    ["RESULT_EVALUATED_FORMAT", result.evaluatedArtifactDigest],
    ["RESULT_CIPHERTEXT_FORMAT", result.resultCiphertextDigest],
    ["RESULT_COMMITMENT_FORMAT", result.resultCiphertextCommitment],
    ["RESULT_AUTHORITY_FORMAT", result.releaseAuthorityId],
    ["RESULT_PROVENANCE_FORMAT", result.sourceProvenance],
    ["CHRONOLOGY_HOLDER_FORMAT", evidence.chronology.holderAllocationDigest],
    ["ATTESTATION_DIGEST_FORMAT", evidence.recourseAttestation.digest],
    ["ATTESTATION_PROTECTION_FORMAT", attestation.protectionBindingDigest],
    ["ATTESTATION_RESULT_FORMAT", attestation.governedResultDigest],
    ["ATTESTATION_CASE_FORMAT", attestation.caseId],
    ["ATTESTATION_ASSET_FORMAT", attestation.cleanverseAssetRecordDigest],
    ["ATTESTATION_HOLDER_FORMAT", attestation.holderAllocationDigest],
    ["ATTESTATION_CHRONOLOGY_FORMAT", attestation.chronologyDigest],
    ["ATTESTATION_AUTHORITY_FORMAT", attestation.releaseAuthorityId],
    ["GOVERNED_CASE_FORMAT", governed.caseId],
    ["GOVERNED_ASSET_FORMAT", governed.assetIdentity],
    ["GOVERNED_CASE_BINDING_FORMAT", governed.caseBindingDigest],
    ["GOVERNED_SUBMISSION_A_FORMAT", governed.submissionDigests[0]],
    ["GOVERNED_SUBMISSION_B_FORMAT", governed.submissionDigests[1]],
    ["GOVERNED_EVALUATED_FORMAT", governed.evaluatedArtifactDigest],
    ["GOVERNED_RESULT_CIPHERTEXT_FORMAT", governed.resultCiphertextDigest],
    ["GOVERNED_RESULT_COMMITMENT_FORMAT", governed.resultCiphertextCommitment],
    ["GOVERNED_EVALUATOR_FORMAT", governed.evaluatorProvenance],
    ["GOVERNED_RECOMPUTED_FORMAT", governed.recomputedResultCiphertextDigest],
    ["GOVERNED_DECRYPTOR_FORMAT", governed.decryptorProvenance],
    ["GOVERNED_RESULT_FORMAT", governed.governedResultDigest],
    ["GOVERNED_PROTECTION_FORMAT", governed.protectionBindingDigest],
    ["GOVERNED_ATTESTATION_FORMAT", governed.recourseAttestationDigest],
    ["GOVERNED_AUTHORITY_FORMAT", governed.releaseAuthorityId],
    ["PIN_PARTICIPANT_A_FORMAT", pins.participantArtifactDigestA],
    ["PIN_PARTICIPANT_B_FORMAT", pins.participantArtifactDigestB],
    ["PIN_EVALUATED_FORMAT", pins.evaluatedArtifactDigest],
    ["PIN_RECOMPUTED_FORMAT", pins.recomputedResultCiphertextDigest],
    ["PIN_COMMITMENT_FORMAT", pins.resultCiphertextCommitment],
    ["PIN_DECRYPTOR_FORMAT", pins.decryptorProvenance],
    ["PIN_AUTHORITY_FORMAT", pins.releaseAuthorityId],
  ];
  for (const [code, value] of required) canonicalDigest(value, code);
  for (const [index, event] of evidence.chronology.events.entries()) {
    canonicalDigest(event.evidenceRef, `CHRONOLOGY_EVENT_${index}_DIGEST_FORMAT`);
  }
  if (evidence.recourse.recordDigest !== null) canonicalDigest(evidence.recourse.recordDigest, "RECOURSE_DIGEST_FORMAT");
  if (evidence.recourse.record !== null) {
    const record = evidence.recourse.record;
    for (const [code, value] of [
      ["RECOURSE_CASE_FORMAT", record.caseId],
      ["RECOURSE_CASE_BINDING_FORMAT", record.caseBindingDigest],
      ["RECOURSE_ASSET_FORMAT", record.assetIdentity],
      ["RECOURSE_POLICY_FORMAT", record.policyId],
      ["RECOURSE_RESULT_FORMAT", record.resultDigest],
      ["RECOURSE_AUTHORITY_FORMAT", record.releaseAuthorityId],
      ["RECOURSE_HOLDER_FORMAT", record.holderAllocationDigest],
    ] as const) canonicalDigest(value, code);
  }
  canonicalDigest(attestation.recourseRecordDigest, "ATTESTATION_RECOURSE_FORMAT", !result.conflict);
  canonicalDigest(governed.recourseRecordDigest, "GOVERNED_RECOURSE_FORMAT", !result.conflict);

  const pinned = expectedCaseManifestDigest === undefined
    ? RETAINED_CASE_MANIFEST_DIGEST_BY_CASE_ID[evidence.fhe.caseId]
    : expectedCaseManifestDigest;
  const expected = canonicalDigest(pinned, "CASE_MANIFEST_DIGEST_PIN");
  if (canonicalDigest(governed.caseManifestDigest, "CASE_MANIFEST_DIGEST_FORMAT") !== expected) {
    reject("CASE_MANIFEST_DIGEST_CROSS_REFERENCE");
  }
}

function validateDatesAndTerminalMetadata(evidence: MordantProtectionEvidence): void {
  const generatedAt = canonicalInstant(evidence.generatedAt, "GENERATED_AT");
  const holderRecordDate = canonicalInstant(evidence.protectionCase.holderRecordDate, "HOLDER_RECORD_DATE");
  canonicalInstant(evidence.protectionAuthorization.binding.holderRecordDate, "PROTECTION_HOLDER_RECORD_DATE");
  canonicalInstant(evidence.chronology.recordDate, "CHRONOLOGY_RECORD_DATE");
  canonicalInstant(evidence.recourseAttestation.attestation.recordDate, "ATTESTATION_RECORD_DATE");
  if (evidence.recourseAttestation.attestation.cureDeadline !== null) {
    canonicalSecondInstant(evidence.recourseAttestation.attestation.cureDeadline, "ATTESTATION_CURE_DEADLINE");
  }

  const binding = evidence.caseAuthorization.binding;
  const createdAtUnix = positiveInteger(binding.createdAtUnix, "CASE_CREATED_AT_UNIX");
  const expiresAtUnix = positiveInteger(binding.expiresAtUnix, "CASE_EXPIRES_AT_UNIX");
  const releasedAtUnix = positiveInteger(evidence.governedResult.releasedAtUnix, "RESULT_RELEASED_AT_UNIX");
  const signedAtUnix = positiveInteger(evidence.chronology.signedAtUnix, "CHRONOLOGY_SIGNED_AT_UNIX");
  const governedGeneratedAtUnix = positiveInteger(evidence.governedFheEvidence.generatedAtUnix, "GOVERNED_GENERATED_AT_UNIX");
  positiveInteger(evidence.recourseAttestation.attestation.signedAtUnix, "ATTESTATION_SIGNED_AT_UNIX");
  if (evidence.chronology.simulationAsOfUnix !== null) {
    positiveInteger(evidence.chronology.simulationAsOfUnix, "CHRONOLOGY_SIMULATION_AT_UNIX");
  }
  if (evidence.chronology.cureDeadlineUnix !== null) {
    positiveInteger(evidence.chronology.cureDeadlineUnix, "CHRONOLOGY_CURE_DEADLINE_UNIX");
  }
  if (evidence.recourseAttestation.attestation.simulationAsOfUnix !== null) {
    positiveInteger(evidence.recourseAttestation.attestation.simulationAsOfUnix, "ATTESTATION_SIMULATION_AT_UNIX");
  }
  for (const [index, event] of evidence.chronology.events.entries()) {
    positiveInteger(event.ordinal, `CHRONOLOGY_EVENT_${index}_ORDINAL`);
    if (event.atUnix !== null) positiveInteger(event.atUnix, `CHRONOLOGY_EVENT_${index}_AT_UNIX`);
  }
  if (evidence.recourse.record !== null) {
    positiveInteger(evidence.recourse.record.recordDateUnix, "RECOURSE_RECORD_DATE_UNIX");
    positiveInteger(evidence.recourse.record.boundAtUnix, "RECOURSE_BOUND_AT_UNIX");
    positiveInteger(evidence.recourse.record.cureDeadlineUnix, "RECOURSE_CURE_DEADLINE_UNIX");
  }
  if (
    expiresAtUnix !== createdAtUnix + 4 * 60 * 60
    || Math.floor(holderRecordDate / 1000) + 60 !== createdAtUnix
    || releasedAtUnix < createdAtUnix || releasedAtUnix > expiresAtUnix
    || signedAtUnix < releasedAtUnix || signedAtUnix > expiresAtUnix
    || governedGeneratedAtUnix < signedAtUnix || governedGeneratedAtUnix > expiresAtUnix
    || generatedAt < createdAtUnix * 1000 || generatedAt > expiresAtUnix * 1000
    || Math.abs(generatedAt - governedGeneratedAtUnix * 1000) > 1_000
  ) reject("TERMINAL_TIMESTAMP_RELATION");

  const exactRetry = evidence.governedFheEvidence.measurements.release.exactRetry;
  if (typeof exactRetry !== "boolean") reject("EXACT_RETRY_BOOLEAN");
  if (exactRetry && (
    evidence.governedResult.releaseOrdinal !== 1
    || evidence.governedFheEvidence.governedResultDigest !== evidence.governedResult.digest
    || evidence.governedFheEvidence.resultCiphertextDigest !== evidence.governedResult.resultCiphertextDigest
    || !evidence.governedFheEvidence.publicStructureValidated
  )) reject("EXACT_RETRY_TERMINAL_RELATION");
}

export function assertRawProtectionEvidenceMetadata(
  evidence: MordantProtectionEvidence,
  expectedCaseManifestDigest?: unknown,
): void {
  validateSchemaLiterals(evidence);
  validateExactReceivableLiterals(evidence);
  validateEvidenceReferences(evidence);
  validateDigests(evidence, expectedCaseManifestDigest);
  validateDatesAndTerminalMetadata(evidence);
}
