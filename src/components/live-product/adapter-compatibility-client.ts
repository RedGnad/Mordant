/**
 * Browser-owned exact parser for the public, read-only Adapter V2 report.
 *
 * This is deliberately separate from the bridge executor: the client receives
 * a JSON boundary, not a TypeScript value. A response that is incomplete,
 * broader than the report schema, or fails any canonical read-only invariant is
 * unavailable to the product surface.
 */

export const ADAPTER_COMPATIBILITY_SCHEMA = "mordant.adapter-v2-compatibility-report/1" as const;
export const MONAD_TESTNET_CHAIN_ID = 10_143 as const;

export type AdapterCompatibilityReport = Readonly<{
  schemaVersion: typeof ADAPTER_COMPATIBILITY_SCHEMA;
  compatible: true;
  adapter: Readonly<{
    address: `0x${string}`;
    chainId: typeof MONAD_TESTNET_CHAIN_ID;
    codeHash: `0x${string}`;
    runtimeBytes: number;
    settlementToken: `0x${string}`;
    cviVerifier: `0x${string}`;
    facility: `0x${string}`;
    availableReserve: string;
    openReserved: string;
    entitledUnpaid: string;
    tokenBalance: string;
    solvent: true;
    roleHolder: 4;
    roleFacility: 3;
  }>;
  participants: Readonly<{
    holderA: `0x${string}`;
    holderB: `0x${string}`;
    payoutA: string;
    payoutB: string;
  }>;
  pins: Readonly<{
    attestor: `0x${string}`;
    governedReleaseAuthorityId: `0x${string}`;
    assetIdentityDigest: `0x${string}`;
    releaseMode: `0x${string}`;
    circuitHash: `0x${string}`;
    parameterFingerprint: `0x${string}`;
  }>;
  eligibility: Readonly<{
    holderA: true;
    holderB: true;
    facility: true;
    negativeControl: false;
    negativeControlCanonicalParticipant: false;
    uncontrolledApassWallet: true;
    uncontrolledApassWalletCanonicalParticipant: false;
  }>;
  digestParity: true;
  retainedVector: Readonly<{
    governedResultDigest: `0x${string}`;
    /** Fixed historical compatibility vector, not a result for this screen's case. */
    conflict: true;
    nonce: string;
    issuedAt: number;
    expiry: number;
    typedDataDigest: `0x${string}`;
    structHash: `0x${string}`;
  }>;
}>;

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const CANONICAL = Object.freeze({
  adapter: "0xbe67db4f8a1a884c809884ea45c4dd4376b01b18",
  codeHash: "0x244c372d9896c267289555b2ebede9ae02ceb6f3d7f42186877088df8bd0099f",
  settlementToken: "0xac0893567d43c3e7e6e35a72803df05416c1f20d",
  cviVerifier: "0xcffa4cbf5117718eb7fc0de2e13e07ce75b840ab",
  facility: "0x344412229b3b581c19572f9bf1f5d08d4ae897e6",
  holderA: "0x3883cbe36be79bd8d1b73ff160b8e7c3cb983685",
  holderB: "0x3dcf732b35406cf5c115bc0f5d40918dfd2acdc9",
  attestor: "0xee3260ba47d097de5a8601107e1b83454593617c",
  governedReleaseAuthorityId: "0xc21276405a249b7c178914508d99e9f0286ce29e5e3bb085ad3697f0cc665c3d",
  assetIdentityDigest: "0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c",
  releaseMode: "0x29d74d033f25761ba7e8fbb0e872d7420cb42498951e9a85e3993b7ef59600fa",
  circuitHash: "0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e",
  parameterFingerprint: "0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6",
  governedResultDigest: "0xf53b9e7a61ecaa88cc202781263f1e05a77c8aabe235240a0d7e5e4d9078b354",
  typedDataDigest: "0xdac5763c3e0020e89d83351db246aa27766337176e2091e189a6d6c1100bb88f",
  structHash: "0x1a5433eca369c6a022dda7847ab2d80e3a0a36feb433bafbb038cf361ea0c825",
});

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function address(value: unknown): value is `0x${string}` {
  return typeof value === "string" && ADDRESS.test(value);
}

/** Refuses every unverified or broadened response instead of rendering its values. */
export function parseAdapterCompatibilityReport(value: unknown): AdapterCompatibilityReport | null {
  if (!exactRecord(value, [
    "schemaVersion", "compatible", "adapter", "participants", "pins", "eligibility", "digestParity", "retainedVector",
  ]) || value.schemaVersion !== ADAPTER_COMPATIBILITY_SCHEMA || value.compatible !== true || value.digestParity !== true) return null;

  if (!exactRecord(value.adapter, [
    "address", "chainId", "codeHash", "runtimeBytes", "settlementToken", "cviVerifier", "facility",
    "availableReserve", "openReserved", "entitledUnpaid", "tokenBalance", "solvent", "roleHolder", "roleFacility",
  ]) || !address(value.adapter.address) || value.adapter.address.toLowerCase() !== CANONICAL.adapter
    || value.adapter.chainId !== MONAD_TESTNET_CHAIN_ID || value.adapter.codeHash !== CANONICAL.codeHash
    || value.adapter.runtimeBytes !== 10_088 || !address(value.adapter.settlementToken)
    || value.adapter.settlementToken.toLowerCase() !== CANONICAL.settlementToken || !address(value.adapter.cviVerifier)
    || value.adapter.cviVerifier.toLowerCase() !== CANONICAL.cviVerifier || !address(value.adapter.facility)
    || value.adapter.facility.toLowerCase() !== CANONICAL.facility
    || value.adapter.availableReserve !== "4000" || value.adapter.openReserved !== "0"
    || value.adapter.entitledUnpaid !== "0" || value.adapter.tokenBalance !== "4000"
    || value.adapter.solvent !== true || value.adapter.roleHolder !== 4 || value.adapter.roleFacility !== 3) return null;

  if (!exactRecord(value.participants, ["holderA", "holderB", "payoutA", "payoutB"])
    || !address(value.participants.holderA) || value.participants.holderA.toLowerCase() !== CANONICAL.holderA
    || !address(value.participants.holderB) || value.participants.holderB.toLowerCase() !== CANONICAL.holderB
    || value.participants.payoutA !== "2400" || value.participants.payoutB !== "1600") return null;

  if (!exactRecord(value.pins, [
    "attestor", "governedReleaseAuthorityId", "assetIdentityDigest", "releaseMode", "circuitHash", "parameterFingerprint",
  ]) || !address(value.pins.attestor) || value.pins.attestor.toLowerCase() !== CANONICAL.attestor
    || value.pins.governedReleaseAuthorityId !== CANONICAL.governedReleaseAuthorityId
    || value.pins.assetIdentityDigest !== CANONICAL.assetIdentityDigest || value.pins.releaseMode !== CANONICAL.releaseMode
    || value.pins.circuitHash !== CANONICAL.circuitHash || value.pins.parameterFingerprint !== CANONICAL.parameterFingerprint) return null;

  if (!exactRecord(value.eligibility, [
    "holderA", "holderB", "facility", "negativeControl", "negativeControlCanonicalParticipant",
    "uncontrolledApassWallet", "uncontrolledApassWalletCanonicalParticipant",
  ]) || value.eligibility.holderA !== true || value.eligibility.holderB !== true || value.eligibility.facility !== true
    || value.eligibility.negativeControl !== false || value.eligibility.negativeControlCanonicalParticipant !== false
    || value.eligibility.uncontrolledApassWallet !== true || value.eligibility.uncontrolledApassWalletCanonicalParticipant !== false) return null;

  if (!exactRecord(value.retainedVector, [
    "governedResultDigest", "conflict", "nonce", "issuedAt", "expiry", "typedDataDigest", "structHash",
  ]) || value.retainedVector.governedResultDigest !== CANONICAL.governedResultDigest || value.retainedVector.conflict !== true
    || value.retainedVector.nonce !== "1" || value.retainedVector.issuedAt !== 1_785_000_000
    || value.retainedVector.expiry !== 1_785_003_600 || value.retainedVector.typedDataDigest !== CANONICAL.typedDataDigest
    || value.retainedVector.structHash !== CANONICAL.structHash) return null;

  return Object.freeze({
    schemaVersion: ADAPTER_COMPATIBILITY_SCHEMA,
    compatible: true,
    adapter: Object.freeze({
      address: value.adapter.address,
      chainId: MONAD_TESTNET_CHAIN_ID,
      codeHash: value.adapter.codeHash,
      runtimeBytes: value.adapter.runtimeBytes,
      settlementToken: value.adapter.settlementToken,
      cviVerifier: value.adapter.cviVerifier,
      facility: value.adapter.facility,
      availableReserve: value.adapter.availableReserve,
      openReserved: value.adapter.openReserved,
      entitledUnpaid: value.adapter.entitledUnpaid,
      tokenBalance: value.adapter.tokenBalance,
      solvent: true,
      roleHolder: 4,
      roleFacility: 3,
    }),
    participants: Object.freeze({
      holderA: value.participants.holderA,
      holderB: value.participants.holderB,
      payoutA: value.participants.payoutA,
      payoutB: value.participants.payoutB,
    }),
    pins: Object.freeze({
      attestor: value.pins.attestor,
      governedReleaseAuthorityId: value.pins.governedReleaseAuthorityId,
      assetIdentityDigest: value.pins.assetIdentityDigest,
      releaseMode: value.pins.releaseMode,
      circuitHash: value.pins.circuitHash,
      parameterFingerprint: value.pins.parameterFingerprint,
    }),
    eligibility: Object.freeze({
      holderA: true,
      holderB: true,
      facility: true,
      negativeControl: false,
      negativeControlCanonicalParticipant: false,
      uncontrolledApassWallet: true,
      uncontrolledApassWalletCanonicalParticipant: false,
    }),
    digestParity: true,
    retainedVector: Object.freeze({
      governedResultDigest: value.retainedVector.governedResultDigest,
      conflict: true,
      nonce: value.retainedVector.nonce,
      issuedAt: value.retainedVector.issuedAt,
      expiry: value.retainedVector.expiry,
      typedDataDigest: value.retainedVector.typedDataDigest,
      structHash: value.retainedVector.structHash,
    }),
  });
}
