import type { Sha256Digest } from "./cleanverse-asset";
import {
  assertPublicProtectionEvidence,
  type CanonicalSourceClassificationId,
  type MordantProtectionEvidence,
  type ProductClockClass,
} from "./protection-evidence";
import type { MordantProtectionCase, ProductScenario, ReleaseMode } from "./protection-case";

export type PublicProtectionCaseProjection = Readonly<{
  productScenario: ProductScenario;
  cleanverseAssetDigest: Sha256Digest;
  cleanverseAsset: Readonly<{
    token: Readonly<{ address: string }>;
    sourceIdentity: Readonly<{ cleanverseRequestId: string }>;
    documentationTerms: Readonly<{ version: string }>;
    tokenDeployment: Readonly<{ blockNumber: string }>;
    issuance: Readonly<{ transactionHash: string }>;
  }>;
  serviceVersion: number;
  protectedAmount: Readonly<{ asset: "aUSDC"; minorUnits: "100000000" }>;
  reserve: Readonly<{
    basisPoints: 1000;
    minorUnits: "10000000";
    accountingDomain: "PROTECTION";
    executionClassification: "PROTOCOL_DOUBLE";
  }>;
  holderRecordDate: string;
  holderSnapshot: readonly [
    Readonly<{ holderId: string; protectedUnits: string; allocationBps: number }>,
    Readonly<{ holderId: string; protectedUnits: string; allocationBps: number }>,
  ];
  holderAllocationDigest: Sha256Digest;
  fheCaseId: Sha256Digest;
  // The mode the case was created in. `governedResult` below keeps its own
  // literal: that block describes a governed release specifically, and a
  // coalition release is a different shape carrying two facts, not one.
  releaseMode: ReleaseMode;
  originalReceivable: Readonly<{
    state: "OUTSTANDING_INTACT";
    principalMinorUnits: "110000000";
    units: "100000000";
    accountingDomain: "RECEIVABLE";
  }>;
}>;

export type VerifiedPublicProtectionEvidence = Readonly<{
  schemaVersion: "mordant.verified-protection-public-view/1";
  manifestDigest: Sha256Digest;
  runId: string;
  sourceCommit: string;
  governedFheCommit: string;
  scenario: ProductScenario;
  cleanverseAssetDigest: Sha256Digest;
  sourceClassifications: readonly CanonicalSourceClassificationId[];
  protectionCase: PublicProtectionCaseProjection;
  protectionAuthorization: Readonly<{
    bindingDigest: Sha256Digest;
    participantSignatures: readonly [
      Readonly<{ role: "PARTICIPANT_A"; signature: string }>,
      Readonly<{ role: "PARTICIPANT_B"; signature: string }>,
    ];
  }>;
  fhe: Readonly<{
    caseId: Sha256Digest;
    caseBindingDigest: Sha256Digest;
    profile: "mordant.bgv.identity-full-fhe-256.n15/v1";
    circuitId: "mordant.identity-full-fhe-256";
    circuitVersion: number;
    participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
    evaluatedArtifactDigest: Sha256Digest;
    resultCiphertextDigest: Sha256Digest;
    independentlyRecomputedResultDigest: Sha256Digest;
  }>;
  governedResult: Readonly<{
    conflict: boolean;
    digest: Sha256Digest;
    signature: string;
    releaseAuthorityId: Sha256Digest;
    releaseMode: "governed-decryptor-v1";
  }>;
  chronology: Readonly<{
    clockClass: ProductClockClass;
    signedAtUnix: number;
    simulationAsOfUnix: number | null;
    cureDeadlineUnix: number | null;
    finalIncidentState: "CONFLICT_CONFIRMED" | "CLEARED";
    finalRecourseState: "AVAILABLE" | "SIMULATED_AVAILABLE" | "REFUSED";
    events: readonly Readonly<{
      ordinal: number;
      kind: string;
      atUnix: number | null;
    }>[];
  }>;
  recourse: Readonly<{
    opened: boolean;
    refusedReason: "SIGNED_RESULT_FALSE" | null;
    recordDigest: Sha256Digest | null;
    resultDigest: Sha256Digest | null;
  }>;
  recourseAttestation: Readonly<{
    digest: Sha256Digest;
    attestation: Readonly<{
      signature: string;
      chronologyDigest: Sha256Digest;
      finalIncidentState: "CONFLICT_CONFIRMED" | "CLEARED";
      finalRecourseState: "AVAILABLE" | "SIMULATED_AVAILABLE" | "REFUSED";
      clockClass: ProductClockClass;
      simulationAsOfUnix: number | null;
    }>;
  }>;
  originalReceivablePreservation: Readonly<{
    state: "OUTSTANDING_INTACT";
    principalMinorUnits: "110000000";
    units: "100000000";
    reserveAccountingSeparate: true;
    claimBurnedOrTransferredByProtection: false;
  }>;
  execution: Readonly<{
    fhe: "REAL_BGV_FHE";
    deployment: "LOCAL_SINGLE_HOST";
    release: "GOVERNED_DECRYPTOR";
    recourse: "LOCAL_PROTOCOL_DOUBLE";
    productionIsolationProven: false;
  }>;
}>;

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export function projectPublicProtectionCase(
  protectionCase: MordantProtectionCase | MordantProtectionEvidence["protectionCase"],
): PublicProtectionCaseProjection {
  const projected: PublicProtectionCaseProjection = {
    productScenario: protectionCase.productScenario,
    cleanverseAssetDigest: protectionCase.cleanverseAssetDigest,
    cleanverseAsset: {
      token: { address: protectionCase.cleanverseAsset.token.value.address },
      sourceIdentity: { cleanverseRequestId: protectionCase.cleanverseAsset.sourceIdentity.value.cleanverseRequestId },
      documentationTerms: { version: protectionCase.cleanverseAsset.documentationTerms.value.version },
      tokenDeployment: { blockNumber: protectionCase.cleanverseAsset.tokenDeployment.value.blockNumber },
      issuance: { transactionHash: protectionCase.cleanverseAsset.issuance.value.transactionHash },
    },
    serviceVersion: protectionCase.serviceVersion,
    protectedAmount: {
      asset: protectionCase.protectedAmount.asset,
      minorUnits: protectionCase.protectedAmount.minorUnits,
    },
    reserve: {
      basisPoints: protectionCase.reserve.basisPoints,
      minorUnits: protectionCase.reserve.minorUnits,
      accountingDomain: protectionCase.reserve.accountingDomain,
      executionClassification: protectionCase.reserve.executionClassification,
    },
    holderRecordDate: protectionCase.holderRecordDate,
    holderSnapshot: [
      {
        holderId: protectionCase.holderSnapshot[0].holderId,
        protectedUnits: protectionCase.holderSnapshot[0].protectedUnits,
        allocationBps: protectionCase.holderSnapshot[0].allocationBps,
      },
      {
        holderId: protectionCase.holderSnapshot[1].holderId,
        protectedUnits: protectionCase.holderSnapshot[1].protectedUnits,
        allocationBps: protectionCase.holderSnapshot[1].allocationBps,
      },
    ],
    holderAllocationDigest: protectionCase.holderAllocationDigest,
    fheCaseId: protectionCase.fheCaseId,
    releaseMode: protectionCase.releaseMode,
    originalReceivable: {
      state: protectionCase.originalReceivable.state,
      principalMinorUnits: protectionCase.originalReceivable.principalMinorUnits,
      units: protectionCase.originalReceivable.units,
      accountingDomain: protectionCase.originalReceivable.accountingDomain,
    },
  };
  return deepFreeze(projected);
}

function projectVerifiedEvidence(evidence: MordantProtectionEvidence): VerifiedPublicProtectionEvidence {
  const projected: VerifiedPublicProtectionEvidence = {
    schemaVersion: "mordant.verified-protection-public-view/1",
    manifestDigest: evidence.manifestDigest,
    runId: evidence.runId,
    sourceCommit: evidence.sourceCommit,
    governedFheCommit: evidence.governedFheCommit,
    scenario: evidence.scenario,
    cleanverseAssetDigest: evidence.cleanverseAssetDigest,
    sourceClassifications: [...evidence.sourceClassifications],
    protectionCase: projectPublicProtectionCase(evidence.protectionCase),
    protectionAuthorization: {
      bindingDigest: evidence.protectionAuthorization.bindingDigest,
      participantSignatures: [
        {
          role: "PARTICIPANT_A",
          signature: evidence.protectionAuthorization.participantSignatures[0].signature,
        },
        {
          role: "PARTICIPANT_B",
          signature: evidence.protectionAuthorization.participantSignatures[1].signature,
        },
      ],
    },
    fhe: {
      caseId: evidence.fhe.caseId,
      caseBindingDigest: evidence.fhe.caseBindingDigest,
      profile: evidence.fhe.profile,
      circuitId: evidence.fhe.circuitId,
      circuitVersion: evidence.fhe.circuitVersion,
      participantArtifactDigests: [
        evidence.fhe.participantArtifactDigests[0],
        evidence.fhe.participantArtifactDigests[1],
      ],
      evaluatedArtifactDigest: evidence.fhe.evaluatedArtifactDigest,
      resultCiphertextDigest: evidence.fhe.resultCiphertext.sha256,
      independentlyRecomputedResultDigest: evidence.fhe.independentlyRecomputedResultDigest,
    },
    governedResult: {
      conflict: evidence.governedResult.conflict,
      digest: evidence.governedResult.digest,
      signature: evidence.governedResult.signature,
      releaseAuthorityId: evidence.governedResult.releaseAuthorityId,
      releaseMode: evidence.governedResult.releaseMode,
    },
    chronology: {
      clockClass: evidence.chronology.clockClass,
      signedAtUnix: evidence.chronology.signedAtUnix,
      simulationAsOfUnix: evidence.chronology.simulationAsOfUnix,
      cureDeadlineUnix: evidence.chronology.cureDeadlineUnix,
      finalIncidentState: evidence.chronology.finalIncidentState,
      finalRecourseState: evidence.chronology.finalRecourseState,
      events: evidence.chronology.events.map((event) => ({
        ordinal: event.ordinal,
        kind: event.kind,
        atUnix: event.atUnix,
      })),
    },
    recourse: {
      opened: evidence.recourse.opened,
      refusedReason: evidence.recourse.refusedReason,
      recordDigest: evidence.recourse.recordDigest,
      resultDigest: evidence.recourse.record?.resultDigest ?? null,
    },
    recourseAttestation: {
      digest: evidence.recourseAttestation.digest,
      attestation: {
        signature: evidence.recourseAttestation.attestation.signature,
        chronologyDigest: evidence.recourseAttestation.attestation.chronologyDigest,
        finalIncidentState: evidence.recourseAttestation.attestation.finalIncidentState,
        finalRecourseState: evidence.recourseAttestation.attestation.finalRecourseState,
        clockClass: evidence.recourseAttestation.attestation.clockClass,
        simulationAsOfUnix: evidence.recourseAttestation.attestation.simulationAsOfUnix,
      },
    },
    originalReceivablePreservation: {
      state: evidence.originalReceivablePreservation.state,
      principalMinorUnits: evidence.originalReceivablePreservation.principalMinorUnits,
      units: evidence.originalReceivablePreservation.units,
      reserveAccountingSeparate: evidence.originalReceivablePreservation.reserveAccountingSeparate,
      claimBurnedOrTransferredByProtection: evidence.originalReceivablePreservation.claimBurnedOrTransferredByProtection,
    },
    execution: {
      fhe: "REAL_BGV_FHE",
      deployment: "LOCAL_SINGLE_HOST",
      release: "GOVERNED_DECRYPTOR",
      recourse: "LOCAL_PROTOCOL_DOUBLE",
      productionIsolationProven: false,
    },
  };
  return deepFreeze(projected);
}

export function verifyAndProjectPublicProtectionEvidence(
  evidence: unknown,
  expectedSourceCommit: unknown,
  expectedCaseManifestDigest?: unknown,
): VerifiedPublicProtectionEvidence {
  assertPublicProtectionEvidence(evidence, expectedSourceCommit, expectedCaseManifestDigest);
  return projectVerifiedEvidence(evidence);
}
