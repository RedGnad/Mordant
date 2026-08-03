import {
  SOURCE_CLASSIFICATIONS,
  sha256Digest,
  type CleanverseAssetRecord,
  type Sha256Digest,
  type SourceClassification,
} from "./cleanverse-asset";
import type { MordantProtectionCase, ProductScenario } from "./protection-case";

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

export type MordantProtectionEvidence = Readonly<{
  schemaVersion: "mordant.protection-evidence/1";
  manifestDigest: Sha256Digest;
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
  governedResult: Readonly<{
    digest: Sha256Digest;
    assetIdentity: Sha256Digest;
    conflict: boolean;
    signature: string;
    releaseMode: "governed-decryptor-v1";
    releaseAuthorityId: Sha256Digest;
    releaseAuthorityPublicKey: string;
    releaseOrdinal: 1;
    releasedAtUnix: number;
  }>;
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
    record: Readonly<Record<string, unknown>> | null;
  }>;
  originalReceivablePreservation: Readonly<{
    state: "OUTSTANDING_INTACT";
    principalMinorUnits: "110000000";
    units: "100000000";
    reserveAccountingSeparate: true;
    claimBurnedOrTransferredByProtection: false;
  }>;
  governedFheEvidence: Readonly<Record<string, unknown>>;
  generatedAt: string;
}>;

export function protectionEvidenceDigest(
  evidence: Omit<MordantProtectionEvidence, "manifestDigest">,
): Sha256Digest {
  return sha256Digest("MordantProtectionEvidence/v1", evidence);
}

export function assertPublicProtectionEvidence(evidence: MordantProtectionEvidence): void {
  if (evidence.schemaVersion !== "mordant.protection-evidence/1") {
    throw new Error("Unsupported protection evidence schema");
  }
  const { manifestDigest, ...value } = evidence;
  if (manifestDigest !== protectionEvidenceDigest(value)) {
    throw new Error("Protection evidence digest mismatch");
  }
  if (
    evidence.cleanverseAssetDigest !== evidence.protectionCase.cleanverseAssetDigest
    || evidence.cleanverseAssetDigest !== evidence.fhe.assetIdentity
    || evidence.cleanverseAssetDigest !== evidence.governedResult.assetIdentity
  ) {
    throw new Error("Protection evidence asset binding mismatch");
  }
  if (
    evidence.protectionCase.fheCaseId !== evidence.fhe.caseId
    || evidence.governedResult.releaseMode !== evidence.protectionCase.releaseMode
  ) {
    throw new Error("Protection evidence case binding mismatch");
  }
  if (!SOURCE_CLASSIFICATIONS.every((classification) => (
    evidence.sourceClassifications.some((entry) => entry.classification === classification)
  ))) {
    throw new Error("Protection evidence classifications are incomplete");
  }
  if (
    evidence.originalReceivablePreservation.state !== "OUTSTANDING_INTACT"
    || evidence.originalReceivablePreservation.claimBurnedOrTransferredByProtection
    || !evidence.originalReceivablePreservation.reserveAccountingSeparate
  ) {
    throw new Error("Original receivable preservation is not proven by this manifest");
  }
  const serialized = JSON.stringify(evidence).toLowerCase();
  for (const forbidden of [
    "secret-key.bin",
    "decryptor-signing-key.bin",
    "participant-a.ed25519",
    "participant-b.ed25519",
    "privateRoot".toLowerCase(),
    "receivableid",
    "authorizationcommitment",
    "privatemetadatacommitment",
  ]) {
    if (serialized.includes(forbidden.toLowerCase())) {
      throw new Error(`Private material marker found in public evidence: ${forbidden}`);
    }
  }
}
