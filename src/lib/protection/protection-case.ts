import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  CANONICAL_CLEANVERSE_ASSET_RECORD,
  assertCanonicalCleanverseAssetRecord,
  sha256Digest,
  type CleanverseAssetRecord,
  type Sha256Digest,
  type SourceClassification,
} from "./cleanverse-asset";

export const PROTECTION_SERVICE = "Conflicting Pledge Protection" as const;
export const PROTECTION_SERVICE_VERSION = 1 as const;
export const PROTECTION_POLICY_VERSION = 1 as const;
export const GOVERNED_RELEASE_MODE = "governed-decryptor-v1" as const;
export const FHE_PARAMETER_PROFILE = "mordant.bgv.identity-full-fhe-256.n15/v1" as const;
export const FHE_CIRCUIT = "mordant.identity-full-fhe-256" as const;
export const PROTECTION_PRODUCT_CLAIM =
  "Mordant protects a tokenized receivable with a private conflict check and governed recourse. " +
  "The parties’ pledge records are evaluated under BGV fully homomorphic encryption. The evaluator " +
  "cannot inspect the inputs or dictate the released result. A designated governed decryptor " +
  "independently recomputes the fixed circuit, decrypts the final Boolean, and signs it into the " +
  "recourse workflow.";
export const PROTECTION_PRODUCT_DISCLOSURE =
  "The MVP uses a designated trusted decryptor and local single-host execution. Threshold output " +
  "release and production custody isolation remain post-MVP upgrades.";

export type ProductScenario = "conflict" | "no-conflict";
export type IncidentState =
  | "AUTHORIZED"
  | "PRIVATE_MATCH_OPEN"
  | "EVALUATED"
  | "CONFLICT_CONFIRMED"
  | "CLEARED";
export type RecourseState = "NOT_OPEN" | "CURE_WINDOW" | "AVAILABLE" | "REFUSED";
export type OriginalReceivableState = "OUTSTANDING_INTACT";

export type HolderAllocation = Readonly<{
  holderId: "HOLDER_A" | "HOLDER_B";
  protectedUnits: string;
  allocationBps: 6000 | 4000;
}>;

export type ProtectionTimelineEvent = Readonly<{
  ordinal: number;
  kind: string;
  at: string;
  label: string;
  classification: SourceClassification;
  evidenceRef?: string;
}>;

export type MordantProtectionCase = Readonly<{
  schemaVersion: "mordant.protection-case/1";
  productScenario: ProductScenario;
  cleanverseAsset: CleanverseAssetRecord;
  cleanverseAssetDigest: Sha256Digest;
  service: typeof PROTECTION_SERVICE;
  serviceVersion: typeof PROTECTION_SERVICE_VERSION;
  policyId: Sha256Digest;
  policyVersion: typeof PROTECTION_POLICY_VERSION;
  protectedAmount: Readonly<{ asset: "aUSDC"; minorUnits: "100000000" }>;
  reserve: Readonly<{
    basisPoints: 1000;
    minorUnits: "10000000";
    accountingDomain: "PROTECTION";
    executionClassification: "PROTOCOL_DOUBLE";
  }>;
  holderRecordDate: string;
  holderSnapshot: readonly [HolderAllocation, HolderAllocation];
  holderAllocationDigest: Sha256Digest;
  fheCaseId: Sha256Digest;
  releaseMode: typeof GOVERNED_RELEASE_MODE;
  incidentState: IncidentState;
  cureDeadline: string | null;
  recourseState: RecourseState;
  originalReceivable: Readonly<{
    state: OriginalReceivableState;
    principalMinorUnits: "110000000";
    units: "100000000";
    accountingDomain: "RECEIVABLE";
  }>;
  evidenceReferences: readonly string[];
  timeline: readonly ProtectionTimelineEvent[];
  createdAt: string;
}>;

export function protectionPolicyId(): Sha256Digest {
  return sha256Digest("MordantConflictingPledgePolicy/v1", {
    service: PROTECTION_SERVICE,
    serviceVersion: PROTECTION_SERVICE_VERSION,
    policyVersion: PROTECTION_POLICY_VERSION,
  });
}

export function holderAllocationDigest(
  assetDigest: Sha256Digest,
  recordDate: string,
  holders: readonly HolderAllocation[],
): Sha256Digest {
  return sha256Digest("MordantProtectedHolderSnapshot/v1", {
    assetDigest,
    recordDate,
    holders,
  });
}

export function createProtectionCase(options: Readonly<{
  scenario: ProductScenario;
  createdAt: string;
  caseNonce: string;
  assetRecord?: CleanverseAssetRecord;
}>): MordantProtectionCase {
  const asset = options.assetRecord ?? CANONICAL_CLEANVERSE_ASSET_RECORD;
  const assetDigest = assertCanonicalCleanverseAssetRecord(asset);
  const createdAt = new Date(options.createdAt);
  if (Number.isNaN(createdAt.valueOf()) || options.caseNonce.length < 16) {
    throw new RangeError("A valid timestamp and case nonce are required");
  }
  const holderRecordDate = new Date(createdAt.valueOf() - 60_000).toISOString();
  const holders = Object.freeze([
    Object.freeze({ holderId: "HOLDER_A", protectedUnits: "60000000", allocationBps: 6000 }),
    Object.freeze({ holderId: "HOLDER_B", protectedUnits: "40000000", allocationBps: 4000 }),
  ] satisfies [HolderAllocation, HolderAllocation]);
  const allocationDigest = holderAllocationDigest(assetDigest, holderRecordDate, holders);
  const fheCaseId = sha256Digest("MordantProtectionFHECase/v1", {
    assetDigest,
    scenario: options.scenario,
    caseNonce: options.caseNonce,
    policyId: protectionPolicyId(),
    holderAllocationDigest: allocationDigest,
  });
  const protectionCase: MordantProtectionCase = {
    schemaVersion: "mordant.protection-case/1",
    productScenario: options.scenario,
    cleanverseAsset: asset,
    cleanverseAssetDigest: assetDigest,
    service: PROTECTION_SERVICE,
    serviceVersion: PROTECTION_SERVICE_VERSION,
    policyId: protectionPolicyId(),
    policyVersion: PROTECTION_POLICY_VERSION,
    protectedAmount: { asset: "aUSDC", minorUnits: "100000000" },
    reserve: {
      basisPoints: 1000,
      minorUnits: "10000000",
      accountingDomain: "PROTECTION",
      executionClassification: "PROTOCOL_DOUBLE",
    },
    holderRecordDate,
    holderSnapshot: holders,
    holderAllocationDigest: allocationDigest,
    fheCaseId,
    releaseMode: GOVERNED_RELEASE_MODE,
    incidentState: "AUTHORIZED",
    cureDeadline: null,
    recourseState: "NOT_OPEN",
    originalReceivable: {
      state: "OUTSTANDING_INTACT",
      principalMinorUnits: "110000000",
      units: "100000000",
      accountingDomain: "RECEIVABLE",
    },
    evidenceReferences: [asset.provenance.value.evidencePath],
    timeline: [{
      ordinal: 1,
      kind: "PROTECTION_ACTIVATED",
      at: createdAt.toISOString(),
      label: "Mordant protection activated for the canonical Cleanverse asset",
      classification: "LOCAL_EXECUTION",
      evidenceRef: assetDigest,
    }],
    createdAt: createdAt.toISOString(),
  };
  return Object.freeze(protectionCase);
}

export class ProtectionBindingError extends Error {
  constructor(message = "Protection-case binding rejected") {
    super(message);
    this.name = "ProtectionBindingError";
  }
}

export function assertProtectionAssetBinding(
  protectionCase: MordantProtectionCase,
  suppliedAssetDigest: Sha256Digest,
): void {
  assertCanonicalCleanverseAssetRecord(protectionCase.cleanverseAsset);
  if (
    protectionCase.cleanverseAssetDigest !== CANONICAL_CLEANVERSE_ASSET_DIGEST
    || suppliedAssetDigest !== protectionCase.cleanverseAssetDigest
  ) {
    throw new ProtectionBindingError();
  }
}

export function assertParticipantSubmissionAsset(
  protectionCase: MordantProtectionCase,
  suppliedAssetDigest: Sha256Digest,
): void {
  assertProtectionAssetBinding(protectionCase, suppliedAssetDigest);
}

export function assertGovernedResultAsset(
  protectionCase: MordantProtectionCase,
  suppliedAssetDigest: Sha256Digest,
): void {
  assertProtectionAssetBinding(protectionCase, suppliedAssetDigest);
}

export function assertRecourseAsset(
  protectionCase: MordantProtectionCase,
  suppliedAssetDigest: Sha256Digest,
): void {
  assertProtectionAssetBinding(protectionCase, suppliedAssetDigest);
}

export function appendProtectionEvent(
  protectionCase: MordantProtectionCase,
  event: Omit<ProtectionTimelineEvent, "ordinal">,
  patch: Partial<Pick<MordantProtectionCase, "incidentState" | "cureDeadline" | "recourseState">> = {},
): MordantProtectionCase {
  return Object.freeze({
    ...protectionCase,
    ...patch,
    timeline: [...protectionCase.timeline, { ...event, ordinal: protectionCase.timeline.length + 1 }],
  });
}
