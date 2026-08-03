import { createHash } from "node:crypto";

export const SOURCE_CLASSIFICATIONS = [
  "LIVE_OBSERVED",
  "LOCAL_EXECUTION",
  "PROTOCOL_DOUBLE",
  "FIXTURE",
  "UNPROVEN",
  "DOCUMENTED",
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
  schemaVersion: "mordant.cleanverse-asset-record/2";
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
    launchRule: Readonly<{
      allowedGroup: "";
      allowedSubGroup: "";
      minimumTier: 50;
      minimumSubTier: 0;
    }>;
  }>>;
  documentationTerms: ClassifiedField<Readonly<{
    pageTitle: "Cleanverse API v5.6 - Integration Documentation";
    version: "v5.6";
    consultedAtRaw: "2026-07-27";
    sourceKind: "manual-versioned-transcription";
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
    issuedAtRaw: "2026-07-29 03:22:22";
  }>>;
  tokenDeployment: ClassifiedField<Readonly<{
    blockNumber: "48901234";
  }>>;
  preflightObservation: ClassifiedField<Readonly<{
    preflightPinnedBlock: "48901220";
    blockHash: string;
    generatedAt: "2026-07-28T19:22:28.982Z";
  }>>;
  provenance: ClassifiedField<Readonly<{
    sources: readonly [
      Readonly<{ evidencePath: "docs/evidence/monad-invoice-atoken-launch-2026-07-28.json"; evidenceSha256: string }>,
      Readonly<{ evidencePath: "docs/evidence/cleanverse-monad-2026-07-28.json"; evidenceSha256: string }>,
      Readonly<{ evidencePath: "docs/evidence/monad-m13a-ceremony-2026-07-28.json"; evidenceSha256: string }>,
    ];
  }>>;
}>;

export class StrictJsonError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "StrictJsonError";
  }
}

function canonicalizeStrict(value: unknown, active: Set<object>, path: string): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new StrictJsonError(`${path} contains a non-finite number`);
      return JSON.stringify(value);
    case "undefined":
    case "bigint":
    case "symbol":
    case "function":
      throw new StrictJsonError(`${path} is not valid JSON`);
    case "object":
      break;
  }
  const object = value as object;
  if (active.has(object)) throw new StrictJsonError(`${path} is cyclic`);
  active.add(object);
  try {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new StrictJsonError(`${path} is sparse`);
      }
      return `[${value.map((entry, index) => canonicalizeStrict(entry, active, `${path}[${index}]`)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new StrictJsonError(`${path} is not a plain object`);
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalizeStrict(record[key], active, `${path}.${key}`)}`
    )).join(",")}}`;
  } finally {
    active.delete(object);
  }
}

export function canonicalJson(value: unknown): string {
  return canonicalizeStrict(value, new Set<object>(), "$");
}

export function sha256Digest(domain: string, value: unknown): Sha256Digest {
  if (domain.length === 0) throw new StrictJsonError("Digest domain is required");
  const encoded = `${domain}\0${canonicalJson(value)}`;
  return `sha256:${createHash("sha256").update(encoded).digest("hex")}`;
}

export function cleanverseAssetRecordDigest(record: CleanverseAssetRecord): Sha256Digest {
  return sha256Digest("MordantCleanverseAssetRecord/v2", record);
}

const M11_EVIDENCE = "docs/evidence/monad-invoice-atoken-launch-2026-07-28.json" as const;
const M11_OBSERVED_AT = "2026-07-28T19:22:28.982Z" as const;
const DOCUMENTATION_EVIDENCE = "docs/evidence/cleanverse-monad-2026-07-28.json" as const;
const M13A_EVIDENCE = "docs/evidence/monad-m13a-ceremony-2026-07-28.json" as const;

export const CANONICAL_CLEANVERSE_ASSET_RECORD: CleanverseAssetRecord = {
  schemaVersion: "mordant.cleanverse-asset-record/2",
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
  documentationTerms: {
    value: {
      pageTitle: "Cleanverse API v5.6 - Integration Documentation",
      version: "v5.6",
      consultedAtRaw: "2026-07-27",
      sourceKind: "manual-versioned-transcription",
    },
    classification: "DOCUMENTED",
    source: DOCUMENTATION_EVIDENCE,
    observedAt: "2026-07-27",
  },
  aPass: {
    value: {
      statusAtObservation: "HOLDER_PROFILES_ADMITTED",
      holderAExpirationUnix: 1_816_796_031,
      holderBExpirationUnix: 1_816_796_031,
    },
    classification: "LIVE_OBSERVED",
    source: DOCUMENTATION_EVIDENCE,
    observedAt: "2026-07-27T23:23:14.605Z",
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
      issuedAtRaw: "2026-07-29 03:22:22",
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  tokenDeployment: {
    value: {
      blockNumber: "48901234",
    },
    classification: "LIVE_OBSERVED",
    source: M13A_EVIDENCE,
    observedAt: "2026-07-28T20:52:42.848Z",
  },
  preflightObservation: {
    value: {
      preflightPinnedBlock: "48901220",
      blockHash: "0x85b5236019fe240ad72eee25ff388435d4faedf40e361ad5e75033045969f9d0",
      generatedAt: M11_OBSERVED_AT,
    },
    classification: "LIVE_OBSERVED",
    source: M11_EVIDENCE,
    observedAt: M11_OBSERVED_AT,
  },
  provenance: {
    value: {
      sources: [
        { evidencePath: M11_EVIDENCE, evidenceSha256: "3919f586ba19a901151225e0d9de83d554566db26658fd301a025625ba02a8d9" },
        { evidencePath: DOCUMENTATION_EVIDENCE, evidenceSha256: "6e8a7c742a032ba82272b0931503aed85470cf3f8b39915f763e47cc1bbaf0df" },
        { evidencePath: M13A_EVIDENCE, evidenceSha256: "cd0bcc8944796a18dda32efa618bb5a0a2311b0755cd16c6a5ef657e34e18bb3" },
      ],
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
