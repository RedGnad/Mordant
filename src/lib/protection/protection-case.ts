import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  CANONICAL_CLEANVERSE_ASSET_RECORD,
  assertCanonicalCleanverseAssetRecord,
  sha256Digest,
  type CleanverseAssetRecord,
  type Sha256Digest,
  type SourceClassification,
} from "./cleanverse-asset";
import {
  CUSTOM_SUPERVISED_EXECUTION_VARIANT,
  customSupervisedFheCaseIdV2,
} from "./custom-supervised-v2";

export const PROTECTION_SERVICE = "Conflicting Pledge Protection" as const;
export const PROTECTION_SERVICE_VERSION = 1 as const;
export const PROTECTION_POLICY_VERSION = 1 as const;
export const PROTECTION_FIXTURE_CLASSIFICATION = "SYNTHETIC_HACKATHON_FIXTURE" as const;
export const GOVERNED_RELEASE_MODE = "governed-decryptor-v1" as const;
/**
 * The coalition release. A case created in this mode generates no case secret
 * key at all: a co-located ceremony seals one bundle per operator, and a quorum
 * of them releases the result.
 *
 * It is a second mode rather than a replacement because the governed path is
 * still what every retained run used, and its evidence must keep verifying.
 */
export const COALITION_RELEASE_MODE = "coalition-v5" as const;
export type ReleaseMode = typeof GOVERNED_RELEASE_MODE | typeof COALITION_RELEASE_MODE;
export const FHE_PARAMETER_PROFILE = "mordant.bgv.identity-full-fhe-256.n15/v1" as const;
export const FHE_CIRCUIT = "mordant.identity-full-fhe-256" as const;
export const PROTECTION_PRODUCT_CLAIM =
  "Mordant is the recourse layer for tokenized private credit. In its first implemented workflow, " +
  "Conflicting Pledge Protection, the parties’ pledge records are evaluated under BGV fully " +
  "homomorphic encryption. The evaluator cannot inspect the inputs or dictate the released result. " +
  "A designated governed decryptor independently recomputes the fixed circuit, decrypts the final " +
  "Boolean, and signs conflict status for the precommitted policy.";
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
export type RecourseState = "NOT_OPEN" | "CURE_WINDOW" | "AVAILABLE" | "SIMULATED_AVAILABLE" | "REFUSED";
export type OriginalReceivableState = "OUTSTANDING_INTACT";

export type HolderAllocation = Readonly<{
  holderId: "HOLDER_A" | "HOLDER_B";
  protectedUnits: string;
  allocationBps: 6000 | 4000;
}>;

export type MordantProtectionBinding = Readonly<{
  schemaVersion: "mordant.protection-binding/1";
  cleanverseAssetRecordDigest: Sha256Digest;
  protectionService: typeof PROTECTION_SERVICE;
  protectionServiceVersion: typeof PROTECTION_SERVICE_VERSION;
  policyId: Sha256Digest;
  policyVersion: typeof PROTECTION_POLICY_VERSION;
  productScenario: ProductScenario;
  fixtureClassification: typeof PROTECTION_FIXTURE_CLASSIFICATION;
  protectedAmount: Readonly<{ asset: "aUSDC"; minorUnits: "100000000" }>;
  reserveBasisPoints: 1000;
  reserveAmount: Readonly<{ asset: "aUSDC"; minorUnits: "10000000" }>;
  holderRecordDate: string;
  holderSnapshot: readonly [HolderAllocation, HolderAllocation];
  holderAllocationDigest: Sha256Digest;
  caseNonce: Sha256Digest;
  fheCaseId: Sha256Digest;
  governedReleaseMode: ReleaseMode;
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
  caseNonce: Sha256Digest;
  fheCaseId: Sha256Digest;
  releaseMode: ReleaseMode;
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

export function protectionFheCaseId(options: Readonly<{
  assetDigest: Sha256Digest;
  scenario: ProductScenario;
  caseNonce: Sha256Digest;
  policyId: Sha256Digest;
  holderAllocationDigest: Sha256Digest;
}>): Sha256Digest {
  return sha256Digest("MordantProtectionFHECase/v1", {
    assetDigest: options.assetDigest,
    scenario: options.scenario,
    caseNonce: options.caseNonce,
    policyId: options.policyId,
    holderAllocationDigest: options.holderAllocationDigest,
  });
}

export function protectionBindingFromCase(
  protectionCase: Omit<MordantProtectionCase, "incidentState" | "cureDeadline" | "recourseState" | "timeline" | "createdAt">,
): MordantProtectionBinding {
  return {
    schemaVersion: "mordant.protection-binding/1",
    cleanverseAssetRecordDigest: protectionCase.cleanverseAssetDigest,
    protectionService: protectionCase.service,
    protectionServiceVersion: protectionCase.serviceVersion,
    policyId: protectionCase.policyId,
    policyVersion: protectionCase.policyVersion,
    productScenario: protectionCase.productScenario,
    fixtureClassification: PROTECTION_FIXTURE_CLASSIFICATION,
    protectedAmount: protectionCase.protectedAmount,
    reserveBasisPoints: protectionCase.reserve.basisPoints,
    reserveAmount: { asset: "aUSDC", minorUnits: protectionCase.reserve.minorUnits },
    holderRecordDate: protectionCase.holderRecordDate,
    holderSnapshot: protectionCase.holderSnapshot,
    holderAllocationDigest: protectionCase.holderAllocationDigest,
    caseNonce: protectionCase.caseNonce,
    fheCaseId: protectionCase.fheCaseId,
    governedReleaseMode: protectionCase.releaseMode,
  };
}

export function assertProtectionBindingDerivations(binding: MordantProtectionBinding): void {
  const allocation = holderAllocationDigest(
    binding.cleanverseAssetRecordDigest,
    binding.holderRecordDate,
    binding.holderSnapshot,
  );
  const caseId = protectionFheCaseId({
    assetDigest: binding.cleanverseAssetRecordDigest,
    scenario: binding.productScenario,
    caseNonce: binding.caseNonce,
    policyId: binding.policyId,
    holderAllocationDigest: allocation,
  });
  if (
    binding.schemaVersion !== "mordant.protection-binding/1"
    || binding.protectionService !== PROTECTION_SERVICE
    || binding.protectionServiceVersion !== PROTECTION_SERVICE_VERSION
    || binding.policyId !== protectionPolicyId()
    || binding.policyVersion !== PROTECTION_POLICY_VERSION
    || binding.fixtureClassification !== PROTECTION_FIXTURE_CLASSIFICATION
    || binding.protectedAmount.asset !== "aUSDC" || binding.protectedAmount.minorUnits !== "100000000"
    || binding.reserveBasisPoints !== 1000
    || binding.reserveAmount.asset !== "aUSDC" || binding.reserveAmount.minorUnits !== "10000000"
    || (binding.governedReleaseMode !== GOVERNED_RELEASE_MODE && binding.governedReleaseMode !== COALITION_RELEASE_MODE)
    || allocation !== binding.holderAllocationDigest
    || caseId !== binding.fheCaseId
  ) throw new ProtectionBindingError("Canonical protection binding derivation rejected");
}

export function createProtectionCase(options: Readonly<{
  scenario: ProductScenario;
  createdAt: string;
  caseNonce: string;
  /**
   * Defaults to the governed decryptor, which is what every existing caller and
   * every retained run gets. Naming the coalition mode here is what makes the
   * case generate no secret key at all, so it cannot be changed after creation.
   */
  releaseMode?: ReleaseMode;
  assetRecord?: CleanverseAssetRecord;
  /**
   * Present only for a supervised custom run. When set, the case is authorized
   * under the neutral V2 execution intent: `scenario` becomes an unused
   * placeholder that never reaches the V2 binding, the V2 case identity or the
   * custom receipt, and reading it before governed release is a programming
   * error guarded by `terminalScenarioAfterRelease`.
   */
  executionVariant?: typeof CUSTOM_SUPERVISED_EXECUTION_VARIANT;
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
  const caseNonce = sha256Digest("MordantProtectionCaseNonce/v1", { entropy: options.caseNonce });
  // A custom run derives its identity from the neutral V2 domain. Nothing about
  // an expected result takes part: no scenario, no window, no overlap.
  const fheCaseId = options.executionVariant === CUSTOM_SUPERVISED_EXECUTION_VARIANT
    ? customSupervisedFheCaseIdV2({
      assetDigest,
      caseNonce,
      holderAllocationDigest: allocationDigest,
      policyId: protectionPolicyId(),
    })
    : protectionFheCaseId({
      assetDigest,
      scenario: options.scenario,
      caseNonce,
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
    caseNonce,
    fheCaseId,
    releaseMode: options.releaseMode ?? GOVERNED_RELEASE_MODE,
    incidentState: "AUTHORIZED",
    cureDeadline: null,
    recourseState: "NOT_OPEN",
    originalReceivable: {
      state: "OUTSTANDING_INTACT",
      principalMinorUnits: "110000000",
      units: "100000000",
      accountingDomain: "RECEIVABLE",
    },
    evidenceReferences: asset.provenance.value.sources.map((source) => source.evidencePath),
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
