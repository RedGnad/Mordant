/**
 * Canonical Adapter V2 compatibility material.
 *
 * This module is intentionally key-free. It only reads the two reviewed public
 * artifacts and derives the values that a server-side admission gate or bridge
 * must use. In particular, it never reads process.env and it never receives a
 * browser payload, a Boolean, a participant, or a payout from a caller.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  encodeAbiParameters,
  getAddress,
  hashTypedData,
  keccak256,
  toHex,
  type Hex,
} from "viem";

import {
  GOVERNED_RELEASE_TYPES,
  RELEASE_TYPEHASH,
  buildGovernedBridgePayload,
  governedReleaseStructHash,
  type AdapterPins,
  type GovernedBridgePayload,
  type VerifiedGovernedRelease,
} from "./governed-recourse-bridge";

export const MONAD_TESTNET_CHAIN_ID = 10_143 as const;
export const RECOURSE_V2_DEMO_CONFIG_PATH =
  "docs/evidence/recourse-v2-demo-config-2026-08-06.json" as const;
export const RUNTIME_CONTRACT_HANDOFF_PATH =
  "docs/evidence/runtime-contract-handoff-2026-08-06.json" as const;
export const BRIDGE_ATTESTOR_ENVIRONMENT_NAME = "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY" as const;

/** Exact bytes reviewed for the public V2 artifacts. */
export const CANONICAL_RECOURSE_CONFIG_SHA256 =
  "c9dd3cec8bad266afd985c5f80d357ee3ab79a3f32cdf20c2d5cb826af2a3126" as const;
export const CANONICAL_RECOURSE_HANDOFF_SHA256 =
  "464667775a871324bac88677d5564f6dc4ea871458a10407ad13caa2504a723f" as const;

type Address = `0x${string}`;
type Bytes32 = Hex;

export class AdapterCompatibilityError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AdapterCompatibilityError";
  }
}

function fail(code: string, message: string): never {
  throw new AdapterCompatibilityError(code, message);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("CANONICAL_SHAPE", `${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function member(value: Record<string, unknown>, name: string, label: string): unknown {
  if (!Object.hasOwn(value, name)) fail("CANONICAL_MISSING", `${label}.${name} is required`);
  return value[name];
}

function section(value: Record<string, unknown>, name: string, label: string): Record<string, unknown> {
  return object(member(value, name, label), `${label}.${name}`);
}

function exactString(value: unknown, code: string, label: string): string {
  if (typeof value !== "string" || value.length === 0) fail(code, `${label} must be a non-empty string`);
  return value;
}

function exactBoolean(value: unknown, code: string, label: string): boolean {
  if (typeof value !== "boolean") fail(code, `${label} must be a boolean`);
  return value;
}

function requiredTrue(value: unknown, label: string): void {
  if (value !== true) fail("CANONICAL_ASSERTION", `${label} must be true`);
}

function requiredFalse(value: unknown, label: string): void {
  if (value !== false) fail("CANONICAL_ASSERTION", `${label} must be false`);
}

function address(value: unknown, code: string, label: string): Address {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) {
    fail(code, `${label} must be a 20-byte address`);
  }
  try {
    return getAddress(value);
  } catch {
    fail(code, `${label} is not a checksum-compatible address`);
  }
}

function bytes32(value: unknown, code: string, label: string): Bytes32 {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(value)) {
    fail(code, `${label} must be a bytes32 value`);
  }
  return value as Bytes32;
}

function sha256(value: unknown, code: string, label: string): `sha256:${string}` {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail(code, `${label} must be a sha256 digest`);
  }
  return value as `sha256:${string}`;
}

function amount(value: unknown, code: string, label: string): bigint {
  if (typeof value === "string" && /^[0-9]+$/u.test(value)) return BigInt(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  fail(code, `${label} must be a non-negative integer amount`);
}

function positiveInteger(value: unknown, code: string, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    fail(code, `${label} must be a positive safe integer`);
  }
  return value;
}

function equalAddress(actual: Address, expected: Address, label: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    fail("CANONICAL_CONFLICT", `${label} disagrees across canonical artifacts`);
  }
}

function equalHex(actual: Hex, expected: Hex, label: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    fail("CANONICAL_CONFLICT", `${label} disagrees across canonical artifacts`);
  }
}

function equalAmount(actual: bigint, expected: bigint, label: string): void {
  if (actual !== expected) fail("CANONICAL_CONFLICT", `${label} disagrees across canonical artifacts`);
}

export type CanonicalRecourseConfiguration = Readonly<{
  schemaVersion: "mordant.recourse-v2-demo-config/1";
  adapter: Readonly<{
    address: Address;
    chainId: typeof MONAD_TESTNET_CHAIN_ID;
    codeHash: Bytes32;
    runtimeBytes: number;
    settlementToken: Address;
    verifier: Address;
    attestor: Address;
    facility: Address;
  }>;
  participants: Readonly<{
    holderA: Address;
    holderB: Address;
    excluded: Readonly<{
      negativeControl: Address;
      uncontrolledApassWallet: Address;
    }>;
    payoutA: bigint;
    payoutB: bigint;
    availableReserve: bigint;
  }>;
  /** Exact baseline liabilities and token balance recorded for the V2 handoff. */
  reserve: Readonly<{
    availableReserve: bigint;
    openReserved: bigint;
    entitledUnpaid: bigint;
    tokenBalance: bigint;
    solvent: true;
  }>;
  cureWindowSeconds: number;
}>;

/**
 * Parses the config's security-relevant V2 fields. This function performs no I/O
 * and no environment access, which makes it safe for a server worker to reuse.
 */
export function parseCanonicalRecourseConfiguration(value: unknown): CanonicalRecourseConfiguration {
  const raw = object(value, "canonical config");
  if (member(raw, "schemaVersion", "canonical config") !== "mordant.recourse-v2-demo-config/1") {
    fail("CANONICAL_SCHEMA", "The canonical config must be mordant.recourse-v2-demo-config/1");
  }
  if (member(raw, "containsNoSecrets", "canonical config") !== true) {
    fail("CANONICAL_SECRETS", "The canonical config must attest that it contains no secrets");
  }

  const network = section(raw, "network", "canonical config");
  if (member(network, "name", "canonical config.network") !== "monad-testnet"
    || member(network, "chainId", "canonical config.network") !== MONAD_TESTNET_CHAIN_ID) {
    fail("CANONICAL_CHAIN", `The canonical config must target Monad testnet ${MONAD_TESTNET_CHAIN_ID}`);
  }

  const contracts = section(raw, "contracts", "canonical config");
  const adapterRecord = section(contracts, "adapter", "canonical config.contracts");
  const adapterAddress = address(member(adapterRecord, "address", "canonical config.contracts.adapter"), "CANONICAL_ADAPTER", "adapter address");
  const codeHash = bytes32(member(adapterRecord, "deployedCodeHash", "canonical config.contracts.adapter"), "CANONICAL_CODE_HASH", "adapter deployedCodeHash");
  const runtimeBytes = positiveInteger(member(adapterRecord, "runtimeBytes", "canonical config.contracts.adapter"), "CANONICAL_RUNTIME_BYTES", "adapter runtimeBytes");
  const verifier = address(member(contracts, "verifier", "canonical config.contracts"), "CANONICAL_VERIFIER", "contracts.verifier");
  const settlementToken = address(
    member(section(contracts, "settlementToken", "canonical config.contracts"), "address", "canonical config.contracts.settlementToken"),
    "CANONICAL_TOKEN",
    "contracts.settlementToken.address",
  );
  const facilityRecord = section(raw, "facility", "canonical config");
  const facility = address(member(facilityRecord, "address", "canonical config.facility"), "CANONICAL_FACILITY", "facility.address");
  const attestor = address(member(section(raw, "bridgeAttestor", "canonical config"), "address", "canonical config.bridgeAttestor"), "CANONICAL_ATTESTOR", "bridgeAttestor.address");
  requiredTrue(member(facilityRecord, "isEligibleForRoleFacility", "canonical config.facility"), "facility.isEligibleForRoleFacility");
  requiredTrue(member(facilityRecord, "cureAuthorizationWillPass", "canonical config.facility"), "facility.cureAuthorizationWillPass");
  const facilityRoleCorrection = section(facilityRecord, "roleCorrection", "canonical config.facility");
  if (member(facilityRoleCorrection, "role", "canonical config.facility.roleCorrection") !== "ROLE_FACILITY (3)") {
    fail("CANONICAL_FACILITY_ROLE", "The canonical facility must be assigned Adapter V2 ROLE_FACILITY (3)");
  }

  const participants = section(raw, "participants", "canonical config");
  const holderARecord = section(participants, "holderA", "canonical config.participants");
  const holderBRecord = section(participants, "holderB", "canonical config.participants");
  const negativeControlRecord = section(participants, "negativeControl", "canonical config.participants");
  const holderA = address(member(holderARecord, "address", "canonical config.participants.holderA"), "CANONICAL_HOLDER_A", "holderA.address");
  const holderB = address(member(holderBRecord, "address", "canonical config.participants.holderB"), "CANONICAL_HOLDER_B", "holderB.address");
  const negativeControl = address(member(negativeControlRecord, "address", "canonical config.participants.negativeControl"), "CANONICAL_NEGATIVE", "negativeControl.address");
  const uncontrolledApassWallet = address(
    member(section(section(raw, "walletControl", "canonical config"), "supersededHolderA", "canonical config.walletControl"), "address", "canonical config.walletControl.supersededHolderA"),
    "CANONICAL_UNCONTROLLED",
    "walletControl.supersededHolderA.address",
  );
  requiredTrue(member(participants, "distinct", "canonical config.participants"), "participants.distinct");
  requiredTrue(member(holderARecord, "roleHolderEligible", "canonical config.participants.holderA"), "holderA.roleHolderEligible");
  requiredTrue(member(holderBRecord, "roleHolderEligible", "canonical config.participants.holderB"), "holderB.roleHolderEligible");
  requiredTrue(member(holderARecord, "keyControlled", "canonical config.participants.holderA"), "holderA.keyControlled");
  requiredTrue(member(holderBRecord, "keyControlled", "canonical config.participants.holderB"), "holderB.keyControlled");

  if (holderA.toLowerCase() === holderB.toLowerCase()) fail("CANONICAL_PARTICIPANTS", "The canonical holders must be distinct");
  for (const excluded of [negativeControl, uncontrolledApassWallet]) {
    if (excluded.toLowerCase() === holderA.toLowerCase() || excluded.toLowerCase() === holderB.toLowerCase()) {
      fail("CANONICAL_EXCLUDED_PARTICIPANT", "An excluded wallet cannot be a canonical participant");
    }
  }

  const settlement = section(raw, "settlement", "canonical config");
  const payoutA = amount(member(settlement, "payoutAAtomic", "canonical config.settlement"), "CANONICAL_PAYOUT_A", "settlement.payoutAAtomic");
  const payoutB = amount(member(settlement, "payoutBAtomic", "canonical config.settlement"), "CANONICAL_PAYOUT_B", "settlement.payoutBAtomic");
  const total = amount(member(settlement, "totalAtomic", "canonical config.settlement"), "CANONICAL_TOTAL", "settlement.totalAtomic");
  const reserve = section(settlement, "reserve", "canonical config.settlement");
  const availableReserve = amount(member(reserve, "availableReserve", "canonical config.settlement.reserve"), "CANONICAL_RESERVE", "settlement.reserve.availableReserve");
  const openReserved = amount(member(reserve, "openReserved", "canonical config.settlement.reserve"), "CANONICAL_RESERVE", "settlement.reserve.openReserved");
  const entitledUnpaid = amount(member(reserve, "entitledUnpaid", "canonical config.settlement.reserve"), "CANONICAL_RESERVE", "settlement.reserve.entitledUnpaid");
  const tokenBalance = amount(member(reserve, "tokenBalance", "canonical config.settlement.reserve"), "CANONICAL_RESERVE", "settlement.reserve.tokenBalance");
  if (payoutA <= 0n || payoutB <= 0n || payoutA + payoutB !== total || total !== availableReserve) {
    fail("CANONICAL_RESERVE", "The canonical payouts must be positive and exactly bounded by the canonical reserve");
  }
  if (openReserved !== 0n || entitledUnpaid !== 0n || tokenBalance !== availableReserve) {
    fail("CANONICAL_RESERVE", "The canonical V2 baseline must have no outstanding liabilities and an exact token balance");
  }
  requiredTrue(member(settlement, "fitsAvailableReserve", "canonical config.settlement"), "settlement.fitsAvailableReserve");
  requiredTrue(member(reserve, "solvent", "canonical config.settlement.reserve"), "settlement.reserve.solvent");

  const transferReadbacks = section(raw, "aUsdcTransferPolicyReadbacks", "canonical config");
  const assertTransfer = (name: string, holder: Address, payout: bigint) => {
    const transfer = section(transferReadbacks, name, "canonical config.aUsdcTransferPolicyReadbacks");
    equalAddress(address(member(transfer, "from", `canonical transfer ${name}`), "CANONICAL_TRANSFER", `${name}.from`), adapterAddress, `${name}.from`);
    equalAddress(address(member(transfer, "to", `canonical transfer ${name}`), "CANONICAL_TRANSFER", `${name}.to`), holder, `${name}.to`);
    equalAmount(amount(member(transfer, "amount", `canonical transfer ${name}`), "CANONICAL_TRANSFER", `${name}.amount`), payout, `${name}.amount`);
    requiredTrue(member(transfer, "allowed", `canonical transfer ${name}`), `${name}.allowed`);
  };
  assertTransfer("adapterToHolderA", holderA, payoutA);
  assertTransfer("adapterToHolderB", holderB, payoutB);

  const gates = section(raw, "gates", "canonical config");
  for (const gate of [
    "holderA A-Pass valid", "holderB A-Pass valid", "holderA holder role", "holderB holder role",
    "holderA and holderB distinct", "adapter to holderA permitted", "adapter to holderB permitted",
    "payouts fit available reserve", "adapter solvent", "negative control still refused",
    "holders separate from privileged roles", "holders are not the uncontrolled A-Pass wallet",
  ]) {
    requiredTrue(member(gates, gate, "canonical config.gates"), `gates.${gate}`);
  }

  const privileged = section(raw, "privilegedAddressesKeptSeparate", "canonical config");
  equalAddress(address(member(privileged, "facility", "canonical config.privilegedAddressesKeptSeparate"), "CANONICAL_PRIVILEGED", "privileged facility"), facility, "privileged facility");
  equalAddress(address(member(privileged, "bridgeAttestor", "canonical config.privilegedAddressesKeptSeparate"), "CANONICAL_PRIVILEGED", "privileged attestor"), attestor, "privileged attestor");
  equalAddress(address(member(privileged, "negativeControl", "canonical config.privilegedAddressesKeptSeparate"), "CANONICAL_PRIVILEGED", "privileged negative control"), negativeControl, "privileged negative control");
  equalAddress(address(member(privileged, "uncontrolledApassWallet", "canonical config.privilegedAddressesKeptSeparate"), "CANONICAL_PRIVILEGED", "privileged uncontrolled A-Pass wallet"), uncontrolledApassWallet, "privileged uncontrolled A-Pass wallet");
  requiredTrue(member(privileged, "noneIsAHolder", "canonical config.privilegedAddressesKeptSeparate"), "privilegedAddressesKeptSeparate.noneIsAHolder");

  const cureWindowSeconds = positiveInteger(
    member(facilityRecord, "cureWindowSeconds", "canonical config.facility"),
    "CANONICAL_CURE_WINDOW",
    "facility.cureWindowSeconds",
  );

  return Object.freeze({
    schemaVersion: "mordant.recourse-v2-demo-config/1",
    adapter: Object.freeze({
      address: adapterAddress,
      chainId: MONAD_TESTNET_CHAIN_ID,
      codeHash,
      runtimeBytes,
      settlementToken,
      verifier,
      attestor,
      facility,
    }),
    participants: Object.freeze({
      holderA,
      holderB,
      excluded: Object.freeze({ negativeControl, uncontrolledApassWallet }),
      payoutA,
      payoutB,
      availableReserve,
    }),
    reserve: Object.freeze({
      availableReserve,
      openReserved,
      entitledUnpaid,
      tokenBalance,
      solvent: true,
    }),
    cureWindowSeconds,
  });
}

function readArtifact(repositoryRoot: string, path: string): string {
  const fullPath = join(repositoryRoot, path);
  if (!existsSync(fullPath)) fail("CANONICAL_MISSING", `The committed artifact is missing at ${path}`);
  return readFileSync(fullPath, "utf8");
}

function artifactHash(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function parseJson(raw: string, label: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    fail("CANONICAL_JSON", `${label} is not valid JSON`);
  }
}

/**
 * Loads only the committed public config. No environment variable, signer, or
 * network read is involved, so admission code can use this as its authority.
 */
export function loadCanonicalRecourseConfiguration(repositoryRoot: string = process.cwd()): CanonicalRecourseConfiguration {
  const raw = readArtifact(repositoryRoot, RECOURSE_V2_DEMO_CONFIG_PATH);
  if (artifactHash(raw) !== CANONICAL_RECOURSE_CONFIG_SHA256) {
    fail("CANONICAL_CONFIG_BYTES", "The canonical V2 config bytes do not match the reviewed artifact");
  }
  return parseCanonicalRecourseConfiguration(parseJson(raw, RECOURSE_V2_DEMO_CONFIG_PATH));
}

export type CanonicalAdapterV2 = Readonly<{
  address: Address;
  chainId: typeof MONAD_TESTNET_CHAIN_ID;
  codeHash: Bytes32;
  runtimeBytes: number;
  settlementToken: Address;
  cviVerifier: Address;
  attestor: Address;
  facility: Address;
  assetIdentityDigest: Bytes32;
  releaseAuthorityId: Bytes32;
  releaseMode: Bytes32;
  circuitHash: Bytes32;
  parameterFingerprint: Bytes32;
  availableReserve: bigint;
  openReserved: bigint;
  entitledUnpaid: bigint;
  tokenBalance: bigint;
  solvent: true;
  domainSeparator: Bytes32;
  roleHolder: number;
  roleFacility: number;
  cureWindowSeconds: number;
}>;

export type CanonicalRecourseBridgeArtifacts = Readonly<{
  configuration: CanonicalRecourseConfiguration;
  adapter: CanonicalAdapterV2;
  /** Public-evidence provenance pin that every runtime release must satisfy. */
  expectedSourceCommit: string;
  release: VerifiedGovernedRelease;
  encodingVector: Readonly<{
    nonce: bigint;
    issuedAt: number;
    expiry: number;
    typedDataDigest: Bytes32;
    structHash: Bytes32;
    domainSeparator: Bytes32;
  }>;
}>;

function releaseFromHandoff(value: Record<string, unknown>): VerifiedGovernedRelease {
  const releaseMode = exactString(member(value, "releaseMode", "handoff.governedResult"), "CANONICAL_RELEASE_MODE", "governedResult.releaseMode");
  if (releaseMode !== "governed-decryptor-v1") fail("CANONICAL_RELEASE_MODE", "The canonical release mode is not Adapter V2's governed mode");
  const conflict = exactBoolean(member(value, "conflict", "handoff.governedResult"), "CANONICAL_CONFLICT_BOOLEAN", "governedResult.conflict");
  return Object.freeze({
    runId: exactString(member(value, "runId", "handoff.governedResult"), "CANONICAL_RUN", "governedResult.runId"),
    fheCaseId: sha256(member(value, "fheCaseId", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.fheCaseId"),
    caseBindingDigest: sha256(member(value, "caseBindingDigest", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.caseBindingDigest"),
    assetIdentity: sha256(member(value, "assetIdentityDigest", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.assetIdentityDigest"),
    governedResultDigest: sha256(member(value, "governedResultDigest", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.governedResultDigest"),
    resultCiphertextDigest: sha256(member(value, "resultCiphertextDigest", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.resultCiphertextDigest"),
    participantArtifactDigests: Object.freeze([
      sha256(member(value, "participantArtifactDigestA", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.participantArtifactDigestA"),
      sha256(member(value, "participantArtifactDigestB", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.participantArtifactDigestB"),
    ]) as readonly [`sha256:${string}`, `sha256:${string}`],
    circuitDigest: sha256(member(value, "circuitDigest", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.circuitDigest"),
    parameterFingerprint: sha256(member(value, "parameterFingerprint", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.parameterFingerprint"),
    releaseAuthorityId: sha256(member(value, "releaseAuthorityId", "handoff.governedResult"), "CANONICAL_DIGEST", "governedResult.releaseAuthorityId"),
    releaseMode,
    conflict,
  });
}

function domainSeparator(chainId: number, verifyingContract: Address): Bytes32 {
  return keccak256(encodeAbiParameters(
    [
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" },
    ],
    [
      keccak256(toHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
      keccak256(toHex("MordantRecourseAdapter")),
      keccak256(toHex("1")),
      BigInt(chainId),
      verifyingContract,
    ],
  ));
}

function expectVectorValue(value: unknown, expected: string | boolean | bigint, label: string): void {
  const normalized = typeof value === "bigint" ? value.toString() : typeof value === "string" ? value.toLowerCase() : value;
  const wanted = typeof expected === "bigint"
    ? expected.toString()
    : typeof expected === "string" && expected.startsWith("0x") ? expected.toLowerCase() : expected;
  if (normalized !== wanted) fail("CANONICAL_VECTOR", `${label} does not reproduce the reviewed encoding vector`);
}

/**
 * Parses and cross-verifies config plus handoff without asserting their raw file
 * hashes. It exists for deterministic unit fixtures; production callers should
 * use loadCanonicalRecourseBridgeArtifacts, which checks the committed bytes too.
 */
export function parseCanonicalRecourseBridgeArtifacts(
  configValue: unknown,
  handoffValue: unknown,
): CanonicalRecourseBridgeArtifacts {
  const configuration = parseCanonicalRecourseConfiguration(configValue);
  const handoff = object(handoffValue, "runtime handoff");
  if (member(handoff, "schemaVersion", "runtime handoff") !== "mordant.runtime-contract-handoff/2") {
    fail("CANONICAL_HANDOFF_SCHEMA", "The runtime handoff must be mordant.runtime-contract-handoff/2");
  }
  requiredTrue(member(handoff, "containsNoSecrets", "runtime handoff"), "handoff.containsNoSecrets");
  const expectedSourceCommit = exactString(
    member(handoff, "sourceCommitPin", "runtime handoff"),
    "CANONICAL_SOURCE_COMMIT",
    "handoff.sourceCommitPin",
  );
  if (!/^[0-9a-f]{40}$/u.test(expectedSourceCommit)) {
    fail("CANONICAL_SOURCE_COMMIT", "The handoff source commit pin must be a full lowercase commit id");
  }

  const canonical = section(handoff, "canonicalConfiguration", "runtime handoff");
  if (member(canonical, "path", "runtime handoff.canonicalConfiguration") !== RECOURSE_V2_DEMO_CONFIG_PATH) {
    fail("CANONICAL_HANDOFF_PATH", "The handoff must bind the exact canonical V2 config path");
  }
  equalAddress(address(member(canonical, "holderA", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_HOLDER", "handoff holderA"), configuration.participants.holderA, "holderA");
  equalAddress(address(member(canonical, "holderB", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_HOLDER", "handoff holderB"), configuration.participants.holderB, "holderB");
  equalAmount(amount(member(canonical, "payoutAAtomic", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_PAYOUT", "handoff payoutA"), configuration.participants.payoutA, "payoutA");
  equalAmount(amount(member(canonical, "payoutBAtomic", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_PAYOUT", "handoff payoutB"), configuration.participants.payoutB, "payoutB");
  equalAmount(amount(member(canonical, "availableReserve", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_RESERVE", "handoff reserve"), configuration.participants.availableReserve, "availableReserve");
  equalAddress(address(member(canonical, "facility", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_FACILITY", "handoff facility"), configuration.adapter.facility, "facility");
  equalAddress(address(member(canonical, "verifier", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_VERIFIER", "handoff verifier"), configuration.adapter.verifier, "verifier");
  equalAddress(address(member(canonical, "settlementToken", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_TOKEN", "handoff settlement token"), configuration.adapter.settlementToken, "settlement token");
  equalAddress(address(member(canonical, "bridgeAttestor", "runtime handoff.canonicalConfiguration"), "CANONICAL_HANDOFF_ATTESTOR", "handoff bridge attestor"), configuration.adapter.attestor, "bridge attestor");
  const excluded = section(canonical, "excludedFromParticipation", "runtime handoff.canonicalConfiguration");
  equalAddress(address(member(excluded, "negativeControl", "runtime handoff.canonicalConfiguration.excludedFromParticipation"), "CANONICAL_HANDOFF_EXCLUDED", "handoff negative control"), configuration.participants.excluded.negativeControl, "negative control");
  equalAddress(address(member(excluded, "uncontrolledApassWallet", "runtime handoff.canonicalConfiguration.excludedFromParticipation"), "CANONICAL_HANDOFF_EXCLUDED", "handoff uncontrolled A-Pass wallet"), configuration.participants.excluded.uncontrolledApassWallet, "uncontrolled A-Pass wallet");

  const adapterRecord = section(handoff, "adapter", "runtime handoff");
  if (member(adapterRecord, "generation", "runtime handoff.adapter") !== "V2") {
    fail("CANONICAL_GENERATION", "The handoff must bind Adapter V2");
  }
  if (member(adapterRecord, "chainId", "runtime handoff.adapter") !== MONAD_TESTNET_CHAIN_ID) {
    fail("CANONICAL_CHAIN", `The handoff must target Monad testnet ${MONAD_TESTNET_CHAIN_ID}`);
  }
  const adapter: CanonicalAdapterV2 = Object.freeze({
    address: address(member(adapterRecord, "address", "runtime handoff.adapter"), "CANONICAL_HANDOFF_ADAPTER", "handoff adapter address"),
    chainId: MONAD_TESTNET_CHAIN_ID,
    codeHash: configuration.adapter.codeHash,
    runtimeBytes: configuration.adapter.runtimeBytes,
    settlementToken: address(member(adapterRecord, "settlementToken", "runtime handoff.adapter"), "CANONICAL_HANDOFF_TOKEN", "handoff adapter settlementToken"),
    cviVerifier: address(member(adapterRecord, "cviVerifier", "runtime handoff.adapter"), "CANONICAL_HANDOFF_VERIFIER", "handoff adapter cviVerifier"),
    attestor: address(member(adapterRecord, "attestor", "runtime handoff.adapter"), "CANONICAL_HANDOFF_ATTESTOR", "handoff adapter attestor"),
    facility: address(member(adapterRecord, "facility", "runtime handoff.adapter"), "CANONICAL_HANDOFF_FACILITY", "handoff adapter facility"),
    assetIdentityDigest: bytes32(member(adapterRecord, "assetIdentityDigest", "runtime handoff.adapter"), "CANONICAL_PIN", "handoff asset identity pin"),
    releaseAuthorityId: bytes32(member(adapterRecord, "expectedGovernedReleaseAuthorityId", "runtime handoff.adapter"), "CANONICAL_PIN", "handoff authority pin"),
    releaseMode: bytes32(member(adapterRecord, "releaseMode", "runtime handoff.adapter"), "CANONICAL_PIN", "handoff release mode pin"),
    circuitHash: bytes32(member(adapterRecord, "circuitHash", "runtime handoff.adapter"), "CANONICAL_PIN", "handoff circuit pin"),
    parameterFingerprint: bytes32(member(adapterRecord, "parameterFingerprint", "runtime handoff.adapter"), "CANONICAL_PIN", "handoff parameter pin"),
    availableReserve: amount(member(adapterRecord, "availableReserve", "runtime handoff.adapter"), "CANONICAL_HANDOFF_RESERVE", "handoff adapter reserve"),
    openReserved: configuration.reserve.openReserved,
    entitledUnpaid: configuration.reserve.entitledUnpaid,
    tokenBalance: configuration.reserve.tokenBalance,
    solvent: configuration.reserve.solvent,
    domainSeparator: bytes32(member(adapterRecord, "domainSeparator", "runtime handoff.adapter"), "CANONICAL_DOMAIN", "handoff adapter domain separator"),
    roleHolder: positiveInteger(member(adapterRecord, "roleHolder", "runtime handoff.adapter"), "CANONICAL_ROLE", "handoff holder role"),
    roleFacility: 3,
    cureWindowSeconds: positiveInteger(member(adapterRecord, "cureWindowSeconds", "runtime handoff.adapter"), "CANONICAL_CURE_WINDOW", "handoff cure window"),
  });
  equalAddress(adapter.address, configuration.adapter.address, "adapter address");
  equalAddress(adapter.settlementToken, configuration.adapter.settlementToken, "adapter settlement token");
  equalAddress(adapter.cviVerifier, configuration.adapter.verifier, "adapter verifier");
  equalAddress(adapter.attestor, configuration.adapter.attestor, "adapter attestor");
  equalAddress(adapter.facility, configuration.adapter.facility, "adapter facility");
  equalAmount(adapter.availableReserve, configuration.reserve.availableReserve, "adapter reserve");
  if (adapter.cureWindowSeconds !== configuration.cureWindowSeconds || adapter.roleHolder !== 4 || adapter.roleFacility !== 3) {
    fail("CANONICAL_ADAPTER_FIELDS", "The handoff carries an unexpected V2 cure window or role constants");
  }

  const expectedSigner = section(handoff, "expectedBridgeSigner", "runtime handoff");
  equalAddress(address(member(expectedSigner, "address", "runtime handoff.expectedBridgeSigner"), "CANONICAL_SIGNER", "expected bridge signer"), adapter.attestor, "expected bridge signer");
  if (member(expectedSigner, "environmentName", "runtime handoff.expectedBridgeSigner") !== BRIDGE_ATTESTOR_ENVIRONMENT_NAME) {
    fail("CANONICAL_SIGNER_ENV", "The handoff must name the one bridge attestor environment variable");
  }

  const eligibility = section(handoff, "participantEligibility", "runtime handoff");
  equalAddress(address(member(eligibility, "verifier", "runtime handoff.participantEligibility"), "CANONICAL_ELIGIBILITY", "eligibility verifier"), adapter.cviVerifier, "eligibility verifier");
  if (member(eligibility, "role", "runtime handoff.participantEligibility") !== adapter.roleHolder) {
    fail("CANONICAL_ELIGIBILITY", "The handoff eligibility role disagrees with Adapter V2");
  }
  for (const [name, holder] of [["holderA", configuration.participants.holderA], ["holderB", configuration.participants.holderB]] as const) {
    const measured = section(eligibility, name, "runtime handoff.participantEligibility");
    equalAddress(address(member(measured, "address", `runtime handoff.participantEligibility.${name}`), "CANONICAL_ELIGIBILITY", `${name} eligibility address`), holder, `${name} eligibility address`);
    requiredTrue(member(measured, "eligible", `runtime handoff.participantEligibility.${name}`), `${name} eligibility`);
  }

  const assertions = section(handoff, "compatibilityAssertions", "runtime handoff");
  for (const assertion of [
    "governedEd25519SignatureVerified", "crossReferencesVerified", "noBrowserSuppliedBoolean",
    "noBrowserSuppliedPayload", "allTwentySignedFieldsPresentInContractOrder",
    "eachSignedFieldMutationChangesDigest", "deterministic", "consumedByBridgeTests",
  ]) requiredTrue(member(assertions, assertion, "runtime handoff.compatibilityAssertions"), `compatibilityAssertions.${assertion}`);
  requiredFalse(member(assertions, "liveBridgeTransactionSent", "runtime handoff.compatibilityAssertions"), "compatibilityAssertions.liveBridgeTransactionSent");

  const release = releaseFromHandoff(section(handoff, "governedResult", "runtime handoff"));
  const vector = section(section(handoff, "encodingVector", "runtime handoff"), "payload", "runtime handoff.encodingVector");
  const vectorDigests = section(section(handoff, "encodingVector", "runtime handoff"), "expectedDigests", "runtime handoff.encodingVector");
  requiredFalse(member(section(handoff, "encodingVector", "runtime handoff"), "participantsAreProvisional", "runtime handoff.encodingVector"), "encodingVector.participantsAreProvisional");

  const nonce = amount(member(vector, "nonce", "runtime handoff.encodingVector.payload"), "CANONICAL_VECTOR", "vector nonce");
  const issuedAt = positiveInteger(Number(amount(member(vector, "issuedAt", "runtime handoff.encodingVector.payload"), "CANONICAL_VECTOR", "vector issuedAt")), "CANONICAL_VECTOR", "vector issuedAt");
  const expiry = positiveInteger(Number(amount(member(vector, "expiry", "runtime handoff.encodingVector.payload"), "CANONICAL_VECTOR", "vector expiry")), "CANONICAL_VECTOR", "vector expiry");
  const pins: AdapterPins = {
    address: adapter.address,
    chainId: adapter.chainId,
    assetIdentityDigest: adapter.assetIdentityDigest,
    releaseAuthorityId: adapter.releaseAuthorityId,
    releaseMode: adapter.releaseMode,
    circuitHash: adapter.circuitHash,
    parameterFingerprint: adapter.parameterFingerprint,
  };
  const payload = buildGovernedBridgePayload({
    release,
    participants: {
      holderA: configuration.participants.holderA,
      holderB: configuration.participants.holderB,
      payoutA: configuration.participants.payoutA,
      payoutB: configuration.participants.payoutB,
    },
    pins,
    interpretation: "PINS_GOVERNED_AUTHORITY",
    nonce,
    issuedAt,
    expiry,
  });
  for (const [name, value] of Object.entries(payload.message)) {
    expectVectorValue(member(vector, name, "runtime handoff.encodingVector.payload"), value, `encoding vector ${name}`);
  }
  const typedDataDigest = hashTypedData({
    domain: payload.domain,
    types: payload.types,
    primaryType: payload.primaryType,
    message: payload.message,
  });
  const structHash = governedReleaseStructHash(payload);
  const computedDomainSeparator = domainSeparator(adapter.chainId, adapter.address);
  equalHex(bytes32(member(vectorDigests, "viemTypedDataDigest", "runtime handoff.encodingVector.expectedDigests"), "CANONICAL_VECTOR", "vector typed digest"), typedDataDigest, "typed data digest");
  equalHex(bytes32(member(vectorDigests, "viemStructHash", "runtime handoff.encodingVector.expectedDigests"), "CANONICAL_VECTOR", "vector struct hash"), structHash, "struct hash");
  equalHex(bytes32(member(vectorDigests, "viemDomainSeparator", "runtime handoff.encodingVector.expectedDigests"), "CANONICAL_VECTOR", "vector domain separator"), computedDomainSeparator, "domain separator");
  equalHex(bytes32(member(vectorDigests, "adapterDomainSeparator", "runtime handoff.encodingVector.expectedDigests"), "CANONICAL_VECTOR", "adapter domain separator"), adapter.domainSeparator, "adapter domain separator");
  equalHex(bytes32(member(vectorDigests, "soliditySolidityHashReleaseResult", "runtime handoff.encodingVector.expectedDigests"), "CANONICAL_VECTOR", "solidity hashRelease result"), typedDataDigest, "hashRelease digest");
  requiredTrue(member(vectorDigests, "byteIdentical", "runtime handoff.encodingVector.expectedDigests"), "encodingVector.expectedDigests.byteIdentical");
  equalHex(adapter.domainSeparator, computedDomainSeparator, "adapter domain separator");

  const eip712 = section(handoff, "eip712", "runtime handoff");
  equalHex(bytes32(member(eip712, "typeHash", "runtime handoff.eip712"), "CANONICAL_TYPE", "handoff EIP-712 type hash"), RELEASE_TYPEHASH, "EIP-712 type hash");
  if (member(eip712, "primaryType", "runtime handoff.eip712") !== "GovernedRelease") {
    fail("CANONICAL_TYPE", "The handoff primary type must be GovernedRelease");
  }
  const fields = member(eip712, "fields", "runtime handoff.eip712");
  if (!Array.isArray(fields) || fields.length !== GOVERNED_RELEASE_TYPES.GovernedRelease.length) {
    fail("CANONICAL_TYPE", "The handoff must retain all twenty GovernedRelease fields");
  }
  fields.forEach((field, index) => {
    const record = object(field, `runtime handoff.eip712.fields[${index}]`);
    if (member(record, "index", `runtime handoff.eip712.fields[${index}]`) !== index
      || member(record, "name", `runtime handoff.eip712.fields[${index}]`) !== GOVERNED_RELEASE_TYPES.GovernedRelease[index]?.name
      || member(record, "type", `runtime handoff.eip712.fields[${index}]`) !== GOVERNED_RELEASE_TYPES.GovernedRelease[index]?.type) {
      fail("CANONICAL_TYPE", `The handoff EIP-712 field ${index} is not in contract order`);
    }
  });

  return Object.freeze({
    configuration,
    adapter,
    expectedSourceCommit,
    release,
    encodingVector: Object.freeze({
      nonce,
      issuedAt,
      expiry,
      typedDataDigest,
      structHash,
      domainSeparator: computedDomainSeparator,
    }),
  });
}

/** Production artifact loader: parse plus byte-for-byte committed-artifact pins. */
export function loadCanonicalRecourseBridgeArtifacts(
  repositoryRoot: string = process.cwd(),
): CanonicalRecourseBridgeArtifacts {
  const configRaw = readArtifact(repositoryRoot, RECOURSE_V2_DEMO_CONFIG_PATH);
  const handoffRaw = readArtifact(repositoryRoot, RUNTIME_CONTRACT_HANDOFF_PATH);
  if (artifactHash(configRaw) !== CANONICAL_RECOURSE_CONFIG_SHA256) {
    fail("CANONICAL_CONFIG_BYTES", "The canonical V2 config bytes do not match the reviewed artifact");
  }
  if (artifactHash(handoffRaw) !== CANONICAL_RECOURSE_HANDOFF_SHA256) {
    fail("CANONICAL_HANDOFF_BYTES", "The canonical runtime handoff bytes do not match the reviewed artifact");
  }
  return parseCanonicalRecourseBridgeArtifacts(
    parseJson(configRaw, RECOURSE_V2_DEMO_CONFIG_PATH),
    parseJson(handoffRaw, RUNTIME_CONTRACT_HANDOFF_PATH),
  );
}

export type AdapterV2ReadOnlyState = Readonly<{
  address: Address;
  chainId: number;
  codeHash: Bytes32;
  runtimeBytes: number;
  settlementToken: Address;
  cviVerifier: Address;
  attestor: Address;
  facility: Address;
  assetIdentityDigest: Bytes32;
  expectedGovernedReleaseAuthorityId: Bytes32;
  releaseMode: Bytes32;
  circuitHash: Bytes32;
  parameterFingerprint: Bytes32;
  availableReserve: bigint;
  openReserved: bigint;
  entitledUnpaid: bigint;
  tokenBalance: bigint;
  solvent: boolean;
  domainSeparator: Bytes32;
  roleHolder: number;
  roleFacility: number;
}>;

/** Only eth_call/getCode style methods are admitted by this compatibility surface. */
export type AdapterV2ReadOnlyReader = Readonly<{
  readAdapterState: () => Promise<AdapterV2ReadOnlyState>;
  isEligible: (verifier: Address, account: Address, role: number) => Promise<boolean>;
  isAssetTransferAllowed: (verifier: Address, asset: Address, from: Address, to: Address, amount: bigint) => Promise<boolean>;
  hashRelease: (payload: GovernedBridgePayload) => Promise<Bytes32>;
  resultConsumed: (governedResultDigest: Bytes32) => Promise<boolean>;
}>;

export type AdapterCompatibilityCheck = Readonly<{
  adapter: AdapterV2ReadOnlyState;
  payload: GovernedBridgePayload;
  typedDataDigest: Bytes32;
  structHash: Bytes32;
  /**
   * Exact, bounded facts established by the live read-only eligibility calls.
   * The uncontrolled A-Pass wallet being eligible is deliberately not enough to
   * make it a participant: canonical participant selection remains fixed above.
   */
  eligibility: Readonly<{
    holderA: true;
    holderB: true;
    facility: true;
    negativeControl: false;
    negativeControlCanonicalParticipant: false;
    uncontrolledApassWallet: true;
    uncontrolledApassWalletCanonicalParticipant: false;
  }>;
}>;

export type AdapterCompatibilityInput = Readonly<{
  /** Produced by the evidence verifier; never supplied as browser literals. */
  release: VerifiedGovernedRelease;
  nonce: bigint;
  issuedAt: number;
  expiry: number;
}>;

/**
 * A bounded retry primitive restricted by type and call site to read-only work.
 * It has no backoff or side effect; mutations, signing, durable writes and any
 * transaction broadcast must never use it.
 */
export async function retryReadOnly<T>(
  operation: () => Promise<T>,
  attempts: number = 3,
): Promise<T> {
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 3) {
    fail("READ_RETRY_BOUND", "Read-only retries must be between one and three attempts");
  }
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

function adapterMismatch(label: string): never {
  fail("ADAPTER_INCOMPATIBLE", `The live Adapter V2 ${label} disagrees with the committed canonical handoff`);
}

function requireStateAddress(actual: Address, expected: Address, label: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) adapterMismatch(label);
}

function requireStateHex(actual: Bytes32, expected: Bytes32, label: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) adapterMismatch(label);
}

/**
 * Reconciles every signing-relevant read against the committed V2 handoff.
 * The function takes only a time/nonce window. Release outcome, holders, payouts,
 * pins, and all cross references come from the parsed artifacts, not its caller.
 */
export async function checkAdapterV2Compatibility(
  reader: AdapterV2ReadOnlyReader,
  canonical: CanonicalRecourseBridgeArtifacts,
  input: AdapterCompatibilityInput,
): Promise<AdapterCompatibilityCheck> {
  const state = await reader.readAdapterState();
  const expected = canonical.adapter;
  requireStateAddress(state.address, expected.address, "address");
  if (state.chainId !== MONAD_TESTNET_CHAIN_ID || state.chainId !== expected.chainId) adapterMismatch("chainId");
  requireStateHex(state.codeHash, expected.codeHash, "deployed code hash");
  if (state.runtimeBytes !== expected.runtimeBytes) adapterMismatch("runtime byte length");
  requireStateAddress(state.settlementToken, expected.settlementToken, "settlement token");
  requireStateAddress(state.cviVerifier, expected.cviVerifier, "CVI verifier");
  requireStateAddress(state.attestor, expected.attestor, "attestor");
  requireStateAddress(state.facility, expected.facility, "facility");
  requireStateHex(state.assetIdentityDigest, expected.assetIdentityDigest, "asset identity pin");
  requireStateHex(state.expectedGovernedReleaseAuthorityId, expected.releaseAuthorityId, "governed authority pin");
  requireStateHex(state.releaseMode, expected.releaseMode, "release mode pin");
  requireStateHex(state.circuitHash, expected.circuitHash, "circuit hash pin");
  requireStateHex(state.parameterFingerprint, expected.parameterFingerprint, "parameter fingerprint pin");
  requireStateHex(state.domainSeparator, expected.domainSeparator, "domain separator");
  if (state.roleHolder !== expected.roleHolder) adapterMismatch("holder role");
  if (state.roleFacility !== expected.roleFacility) adapterMismatch("facility role");
  if (!state.solvent || state.tokenBalance < state.availableReserve + state.openReserved + state.entitledUnpaid) {
    fail("INSOLVENT", "Adapter V2 is not solvent for its full reserve and liability accounting");
  }
  if (
    state.availableReserve !== expected.availableReserve
    || state.openReserved !== expected.openReserved
    || state.entitledUnpaid !== expected.entitledUnpaid
    || state.tokenBalance !== expected.tokenBalance
  ) {
    adapterMismatch("full reserve accounting");
  }

  const participants = canonical.configuration.participants;
  if (participants.holderA.toLowerCase() === participants.holderB.toLowerCase()) {
    fail("CANONICAL_PARTICIPANTS", "The canonical holders are not distinct");
  }
  for (const excluded of Object.values(participants.excluded)) {
    if (excluded.toLowerCase() === participants.holderA.toLowerCase() || excluded.toLowerCase() === participants.holderB.toLowerCase()) {
      fail("CANONICAL_EXCLUDED_PARTICIPANT", "An excluded wallet is configured as a participant");
    }
  }
  const [
    holderAEligible,
    holderBEligible,
    facilityEligible,
    negativeControlEligible,
    uncontrolledApassWalletEligible,
    transferAAllowed,
    transferBAllowed,
  ] = await Promise.all([
    reader.isEligible(state.cviVerifier, participants.holderA, state.roleHolder),
    reader.isEligible(state.cviVerifier, participants.holderB, state.roleHolder),
    reader.isEligible(state.cviVerifier, state.facility, state.roleFacility),
    reader.isEligible(state.cviVerifier, participants.excluded.negativeControl, state.roleHolder),
    reader.isEligible(state.cviVerifier, participants.excluded.uncontrolledApassWallet, state.roleHolder),
    reader.isAssetTransferAllowed(state.cviVerifier, state.settlementToken, state.address, participants.holderA, participants.payoutA),
    reader.isAssetTransferAllowed(state.cviVerifier, state.settlementToken, state.address, participants.holderB, participants.payoutB),
  ]);
  if (!holderAEligible || !holderBEligible) fail("PARTICIPANT_INELIGIBLE", "Every canonical holder must be currently eligible");
  if (!facilityEligible) fail("FACILITY_INELIGIBLE", "The committed facility must currently hold Adapter V2 ROLE_FACILITY");
  if (negativeControlEligible) fail("NEGATIVE_CONTROL_ELIGIBLE", "The canonical negative control must remain ineligible for ROLE_HOLDER");
  if (!uncontrolledApassWalletEligible) fail("UNCONTROLLED_APASS_INELIGIBLE", "The retained uncontrolled A-Pass wallet must remain eligible without becoming a participant");
  if (!transferAAllowed || !transferBAllowed) fail("TRANSFER_POLICY", "Every canonical payout transfer must be currently permitted");

  const pins: AdapterPins = {
    address: state.address,
    chainId: state.chainId,
    assetIdentityDigest: state.assetIdentityDigest,
    releaseAuthorityId: state.expectedGovernedReleaseAuthorityId,
    releaseMode: state.releaseMode,
    circuitHash: state.circuitHash,
    parameterFingerprint: state.parameterFingerprint,
  };
  const payload = buildGovernedBridgePayload({
    release: input.release,
    participants: {
      holderA: participants.holderA,
      holderB: participants.holderB,
      payoutA: participants.payoutA,
      payoutB: participants.payoutB,
    },
    pins,
    interpretation: "PINS_GOVERNED_AUTHORITY",
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiry: input.expiry,
  });
  const typedDataDigest = hashTypedData({
    domain: payload.domain,
    types: payload.types,
    primaryType: payload.primaryType,
    message: payload.message,
  });
  const structHash = governedReleaseStructHash(payload);
  const [onChainDigest, consumed] = await Promise.all([
    reader.hashRelease(payload),
    reader.resultConsumed(payload.message.governedResultDigest),
  ]);
  if (consumed) fail("RESULT_CONSUMED", "The governed result has already been consumed by Adapter V2");
  if (onChainDigest.toLowerCase() !== typedDataDigest.toLowerCase()) {
    fail("DIGEST_MISMATCH", "Adapter V2 hashRelease disagrees with the independently encoded typed-data digest");
  }
  return Object.freeze({
    adapter: state,
    payload,
    typedDataDigest,
    structHash,
    eligibility: Object.freeze({
      holderA: true,
      holderB: true,
      facility: true,
      negativeControl: false,
      negativeControlCanonicalParticipant: false,
      uncontrolledApassWallet: true,
      uncontrolledApassWalletCanonicalParticipant: false,
    }),
  });
}
