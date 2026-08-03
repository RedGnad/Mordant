import { createHash } from "node:crypto";

export const SOURCE_CLASSIFICATIONS = [
  "LIVE_OBSERVED",
  "LOCAL_EXECUTION",
  "PROTOCOL_DOUBLE",
  "FIXTURE",
  "UNPROVEN",
] as const;

export type SourceClassification = (typeof SOURCE_CLASSIFICATIONS)[number];
export type Sha256Digest = `sha256:${string}`;

export type ClassifiedField<T> = Readonly<{
  value: T;
  classification: SourceClassification;
  source: string;
  observedAt?: string;
}>;

export type CleanverseAssetRecord = Readonly<{
  schemaVersion: "mordant.cleanverse-asset-record/1";
  network: ClassifiedField<Readonly<{ name: "monad-testnet"; chainId: 10_143 }>>;
  canonicalAssetIdentity: ClassifiedField<string>;
  token: ClassifiedField<Readonly<{
    standard: "Cleanverse A-Token";
    address: string;
    implementation: string;
    name: "Mordant Invoice Note";
    symbol: "MINV01";
    decimals: 6;
    registered: true;
    paused: false;
  }>>;
  sourceIdentity: ClassifiedField<Readonly<{
    cleanverseRequestId: string;
    launchFlow: "LAUNCH";
    adminAddress: string;
  }>>;
  issuerLegalIdentity: ClassifiedField<null>;
  receivableReference: ClassifiedField<Readonly<{
    reference: "MORDANT-MINV01-HACKATHON";
    description: "Synthetic hackathon receivable represented by MINV01";
  }>>;
  policy: ClassifiedField<Readonly<{
    address: string;
    documentedTermsVersion: "Cleanverse API v5.6";
    launchRule: Readonly<{
      allowedGroup: "";
      allowedSubGroup: "";
      minimumTier: 50;
      minimumSubTier: 0;
    }>;
  }>>;
  aPass: ClassifiedField<Readonly<{
    statusAtObservation: "HOLDER_PROFILES_ADMITTED";
    holderAExpirationUnix: 1_816_796_031;
    holderBExpirationUnix: 1_816_796_031;
  }>>;
  settlementAsset: ClassifiedField<Readonly<{
    symbol: "aUSDC";
    address: string;
    decimals: 6;
  }>>;
  issuance: ClassifiedField<Readonly<{
    status: "ISSUED";
    transactionHash: string;
    blockNumber: "48901234";
    issuedAt: "2026-07-29 03:22:22";
  }>>;
  observation: ClassifiedField<Readonly<{
    blockNumber: "48901220";
    blockHash: string;
    generatedAt: "2026-07-28T19:22:28.982Z";
  }>>;
  provenance: ClassifiedField<Readonly<{
    evidencePath: "docs/evidence/monad-invoice-atoken-launch-2026-07-28.json";
    evidenceSha256: string;
  }>>;
}>;

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalize(record[key])}`
  )).join(",")}}`;
}

export function sha256Digest(domain: string, value: unknown): Sha256Digest {
  const encoded = `${domain}\0${canonicalize(value)}`;
  return `sha256:${createHash("sha256").update(encoded).digest("hex")}`;
}

export function cleanverseAssetRecordDigest(record: CleanverseAssetRecord): Sha256Digest {
  return sha256Digest("MordantCleanverseAssetRecord/v1", record);
}

const M11_EVIDENCE = "docs/evidence/monad-invoice-atoken-launch-2026-07-28.json" as const;
const M11_OBSERVED_AT = "2026-07-28T19:22:28.982Z" as const;

export const CANONICAL_CLEANVERSE_ASSET_RECORD: CleanverseAssetRecord = {
  schemaVersion: "mordant.cleanverse-asset-record/1",
  network: {
    value: { name: "monad-testnet", chainId: 10_143 },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  canonicalAssetIdentity: {
    value: "eip155:10143/erc20:0x66f706d1dc820cf09eba5359ce9acd0d290bc17b",
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  token: {
    value: {
      standard: "Cleanverse A-Token",
      address: "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b",
      implementation: "0xce4446801356e7d8acbdfef93816bf62b05d3ebf",
      name: "Mordant Invoice Note",
      symbol: "MINV01",
      decimals: 6,
      registered: true,
      paused: false,
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  sourceIdentity: {
    value: {
      cleanverseRequestId: "IA20260729032221850604",
      launchFlow: "LAUNCH",
      adminAddress: "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45",
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  issuerLegalIdentity: {
    value: null,
    classification: "UNPROVEN",
    source: "The retained Cleanverse evidence identifies an admin address, not a legal issuer.",
  },
  receivableReference: {
    value: {
      reference: "MORDANT-MINV01-HACKATHON",
      description: "Synthetic hackathon receivable represented by MINV01",
    },
    classification: "FIXTURE",
    source: "Mordant product scenario",
  },
  policy: {
    value: {
      address: "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd",
      documentedTermsVersion: "Cleanverse API v5.6",
      launchRule: {
        allowedGroup: "",
        allowedSubGroup: "",
        minimumTier: 50,
        minimumSubTier: 0,
      },
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  aPass: {
    value: {
      statusAtObservation: "HOLDER_PROFILES_ADMITTED",
      holderAExpirationUnix: 1_816_796_031,
      holderBExpirationUnix: 1_816_796_031,
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  settlementAsset: {
    value: {
      symbol: "aUSDC",
      address: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
      decimals: 6,
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  issuance: {
    value: {
      status: "ISSUED",
      transactionHash: "0xd26ba9b1624a6e10127a48e2acabdbbf94cae97e0be071e243c7ee5b08211b8c",
      blockNumber: "48901234",
      issuedAt: "2026-07-29 03:22:22",
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  observation: {
    value: {
      blockNumber: "48901220",
      blockHash: "0x85b5236019fe240ad72eee25ff388435d4faedf40e361ad5e75033045969f9d0",
      generatedAt: M11_OBSERVED_AT,
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  provenance: {
    value: {
      evidencePath: M11_EVIDENCE,
      evidenceSha256: "3919f586ba19a901151225e0d9de83d554566db26658fd301a025625ba02a8d9",
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
};

export const CANONICAL_CLEANVERSE_ASSET_DIGEST = cleanverseAssetRecordDigest(
  CANONICAL_CLEANVERSE_ASSET_RECORD,
);

export class CleanverseAssetBindingError extends Error {
  constructor(message = "Cleanverse asset binding rejected") {
    super(message);
    this.name = "CleanverseAssetBindingError";
  }
}

export function assertCanonicalCleanverseAssetRecord(record: CleanverseAssetRecord): Sha256Digest {
  const digest = cleanverseAssetRecordDigest(record);
  if (digest !== CANONICAL_CLEANVERSE_ASSET_DIGEST) {
    throw new CleanverseAssetBindingError();
  }
  return digest;
}

export function allAssetFieldClassifications(record: CleanverseAssetRecord): readonly SourceClassification[] {
  return Object.entries(record)
    .filter(([key]) => key !== "schemaVersion")
    .map(([, value]) => (value as ClassifiedField<unknown>).classification);
}
