import "server-only";

/**
 * Server-only, non-broadcasting Adapter V2 bridge authorization.
 *
 * Preparation is entirely public/read-only and uses only the reviewed canonical
 * config plus handoff. The attestor key is deliberately absent from that path.
 * A key is read only when a real EIP-712 candidate is needed for eth_call
 * simulation, and that candidate never escapes until the successful simulation
 * brands it for a one-time durable authorization.
 */

import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import {
  createPublicClient,
  decodeEventLog,
  getAddress,
  http,
  keccak256,
  parseAbi,
  recoverAddress,
  type Hex,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  AdapterCompatibilityError,
  BRIDGE_ATTESTOR_ENVIRONMENT_NAME,
  MONAD_TESTNET_CHAIN_ID,
  checkAdapterV2Compatibility,
  loadCanonicalRecourseBridgeArtifacts,
  retryReadOnly,
  type AdapterV2ReadOnlyReader,
  type AdapterV2ReadOnlyState,
  type CanonicalRecourseBridgeArtifacts,
} from "./adapter-compatibility";
import type { EnvironmentLike } from "./ccp-eligibility";
import {
  SUPERSEDED_ADAPTER_ADDRESS,
  type GovernedBridgePayload,
  type VerifiedGovernedRelease,
} from "./governed-recourse-bridge";
import {
  assertPublicProtectionEvidence,
  verifyGovernedResultSignature,
  type MordantProtectionEvidence,
} from "./protection-evidence";

export const BRIDGE_EXECUTION_SCHEMA = "mordant.bridge-execution/2" as const;
export const BRIDGE_SIMULATION_MAX_AGE_SECONDS = 30 as const;

/** The only environment names this module ever reads. */
export const BRIDGE_ENVIRONMENT = Object.freeze({
  rpcUrl: "MORDANT_MONAD_RPC_URL",
  adapterAddress: "MORDANT_RECOURSE_ADAPTER_ADDRESS",
  attestorPrivateKey: BRIDGE_ATTESTOR_ENVIRONMENT_NAME,
});

export const ADAPTER_ABI = parseAbi([
  "function settlementToken() view returns (address)",
  "function cviVerifier() view returns (address)",
  "function attestor() view returns (address)",
  "function facility() view returns (address)",
  "function assetIdentityDigest() view returns (bytes32)",
  "function expectedGovernedReleaseAuthorityId() view returns (bytes32)",
  "function releaseMode() view returns (bytes32)",
  "function circuitHash() view returns (bytes32)",
  "function parameterFingerprint() view returns (bytes32)",
  "function availableReserve() view returns (uint256)",
  "function openReserved() view returns (uint256)",
  "function entitledUnpaid() view returns (uint256)",
  "function solvent() view returns (bool)",
  "function domainSeparator() view returns (bytes32)",
  "function resultConsumed(bytes32) view returns (bool)",
  "function ROLE_HOLDER() view returns (uint8)",
  "function ROLE_FACILITY() view returns (uint8)",
  "function hashRelease((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,address,uint256,uint256,bool,bytes32,bytes32,bytes32,bytes32,uint256,uint64,uint64) r) view returns (bytes32)",
  "function consumeGovernedRelease((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,address,uint256,uint256,bool,bytes32,bytes32,bytes32,bytes32,uint256,uint64,uint64) r, bytes signature)",
  "event ReleaseConsumed(bytes32 indexed runId, bool conflict, bytes32 governedResultDigest)",
]);

export const CVI_ABI = parseAbi([
  "function isEligible(address,uint8) view returns (bool)",
  "function isAssetTransferAllowed(address,address,address,uint256) view returns (bool)",
]);

export const ERC20_ABI = parseAbi(["function balanceOf(address) view returns (uint256)"]);

export class BridgeExecutionError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "BridgeExecutionError";
  }
}

function fail(code: string, message: string): never {
  throw new BridgeExecutionError(code, message);
}

function bridgeError(error: unknown, fallbackCode: string, fallbackMessage: string): never {
  if (error instanceof BridgeExecutionError) throw error;
  if (error instanceof AdapterCompatibilityError) throw new BridgeExecutionError(error.code, error.message);
  throw new BridgeExecutionError(fallbackCode, fallbackMessage);
}

export type BridgeConfiguration = Readonly<{
  rpcUrl: string;
  adapterAddress: `0x${string}`;
}>;

/**
 * Reads only read-only connectivity. In particular it does not touch the key
 * property at all, so configuration/compatibility inspection cannot leak or
 * accidentally require a signing secret.
 */
export function readBridgeConfiguration(environment: EnvironmentLike = process.env): BridgeConfiguration {
  const configuredRpcUrl = environment[BRIDGE_ENVIRONMENT.rpcUrl];
  if (typeof configuredRpcUrl !== "string" || configuredRpcUrl.trim() === "") {
    fail("RPC_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.rpcUrl} must be configured`);
  }
  let rpcUrl: string;
  try {
    rpcUrl = new URL(configuredRpcUrl.trim()).toString();
  } catch {
    fail("RPC_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.rpcUrl} must be a URL`);
  }
  const configuredAdapter = environment[BRIDGE_ENVIRONMENT.adapterAddress];
  if (typeof configuredAdapter !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(configuredAdapter.trim())) {
    fail("ADAPTER_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.adapterAddress} must be a 0x adapter address`);
  }
  let adapterAddress: `0x${string}`;
  try {
    adapterAddress = getAddress(configuredAdapter.trim());
  } catch {
    fail("ADAPTER_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.adapterAddress} must be a valid adapter address`);
  }
  if (adapterAddress.toLowerCase() === SUPERSEDED_ADAPTER_ADDRESS.toLowerCase()) {
    fail("SUPERSEDED_ADAPTER", "The configured adapter is the superseded deployment");
  }
  return Object.freeze({ rpcUrl, adapterAddress });
}

/** The exact tuple expected by Adapter V2's hashRelease and consume methods. */
export function releaseTuple(payload: GovernedBridgePayload) {
  const m = payload.message;
  return [
    m.runId, m.fheCaseId, m.caseBindingDigest, m.assetIdentityDigest, m.governedResultDigest,
    m.resultCiphertextDigest, m.participantArtifactDigestA, m.participantArtifactDigestB,
    m.holderA, m.holderB, m.payoutA, m.payoutB, m.conflict, m.releaseAuthorityId,
    m.releaseMode, m.circuitHash, m.parameterFingerprint, m.nonce, m.issuedAt, m.expiry,
  ] as const;
}

export type AdapterState = AdapterV2ReadOnlyState;
export type AdapterReader = AdapterV2ReadOnlyReader & Readonly<{
  /** eth_call simulation only; this module exposes no transaction-mutation equivalent. */
  simulate: (payload: GovernedBridgePayload, signature: Hex, account: `0x${string}`) => Promise<void>;
}>;

/**
 * Builds the live read surface. Every method is a view/getCode/eth_call; retry
 * ownership stays with the executor so a failed read can never turn into a retry
 * of signing, file persistence, or a transaction mutation.
 */
export function createAdapterReader(configuration: BridgeConfiguration): AdapterReader {
  const client = createPublicClient({ transport: http(configuration.rpcUrl) }) as PublicClient;
  const address = configuration.adapterAddress;
  const readContract = client.readContract as unknown as (
    parameters: Readonly<{ address: `0x${string}`; abi: typeof ADAPTER_ABI; functionName: string; args?: readonly unknown[] }>,
  ) => Promise<unknown>;
  const read = <T>(functionName: string, args: readonly unknown[] = []) => (
    readContract({ address, abi: ADAPTER_ABI, functionName, args }) as Promise<T>
  );
  return Object.freeze({
    readAdapterState: async () => {
      const [
        chainId, code, settlementToken, cviVerifier, attestor, facility, assetIdentityDigest,
        expectedGovernedReleaseAuthorityId, releaseMode, circuitHash, parameterFingerprint,
        availableReserve, openReserved, entitledUnpaid, solvent, domainSeparator, roleHolder, roleFacility,
      ] = await Promise.all([
        client.getChainId(),
        client.getCode({ address }),
        read<`0x${string}`>("settlementToken"),
        read<`0x${string}`>("cviVerifier"),
        read<`0x${string}`>("attestor"),
        read<`0x${string}`>("facility"),
        read<Hex>("assetIdentityDigest"),
        read<Hex>("expectedGovernedReleaseAuthorityId"),
        read<Hex>("releaseMode"),
        read<Hex>("circuitHash"),
        read<Hex>("parameterFingerprint"),
        read<bigint>("availableReserve"),
        read<bigint>("openReserved"),
        read<bigint>("entitledUnpaid"),
        read<boolean>("solvent"),
        read<Hex>("domainSeparator"),
        read<number>("ROLE_HOLDER"),
        read<number>("ROLE_FACILITY"),
      ]);
      if (code === undefined || code === "0x") {
        fail("ADAPTER_CODE_UNAVAILABLE", "The configured adapter has no runtime code");
      }
      return Object.freeze({
        address,
        chainId,
        codeHash: keccak256(code),
        runtimeBytes: (code.length - 2) / 2,
        settlementToken: getAddress(settlementToken),
        cviVerifier: getAddress(cviVerifier),
        attestor: getAddress(attestor),
        facility: getAddress(facility),
        assetIdentityDigest,
        expectedGovernedReleaseAuthorityId,
        releaseMode,
        circuitHash,
        parameterFingerprint,
        availableReserve,
        openReserved,
        entitledUnpaid,
        tokenBalance: await client.readContract({
          address: getAddress(settlementToken), abi: ERC20_ABI, functionName: "balanceOf", args: [address],
        }) as bigint,
        solvent,
        domainSeparator,
        roleHolder: Number(roleHolder),
        roleFacility: Number(roleFacility),
      });
    },
    isEligible: (verifier, account, role) => client.readContract({
      address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [account, role],
    }) as Promise<boolean>,
    isAssetTransferAllowed: (verifier, asset, from, to, amount) => client.readContract({
      address: verifier,
      abi: CVI_ABI,
      functionName: "isAssetTransferAllowed",
      args: [asset, from, to, amount],
    }) as Promise<boolean>,
    hashRelease: (payload) => read<Hex>("hashRelease", [releaseTuple(payload)]),
    resultConsumed: (governedResultDigest) => read<boolean>("resultConsumed", [governedResultDigest]),
    simulate: async (payload, signature, account) => {
      await client.simulateContract({
        address,
        abi: ADAPTER_ABI,
        functionName: "consumeGovernedRelease",
        args: [releaseTuple(payload), signature],
        account,
      });
    },
  });
}

type RetriedAdapterReader = AdapterReader;

function withReadOnlyRetries(reader: AdapterReader): RetriedAdapterReader {
  return Object.freeze({
    readAdapterState: () => retryReadOnly(reader.readAdapterState),
    isEligible: (verifier, account, role) => retryReadOnly(() => reader.isEligible(verifier, account, role)),
    isAssetTransferAllowed: (verifier, asset, from, to, amount) => retryReadOnly(() => reader.isAssetTransferAllowed(verifier, asset, from, to, amount)),
    hashRelease: (payload) => retryReadOnly(() => reader.hashRelease(payload)),
    resultConsumed: (digest) => retryReadOnly(() => reader.resultConsumed(digest)),
    simulate: (payload, signature, account) => retryReadOnly(() => reader.simulate(payload, signature, account)),
  });
}

export type PrepareInput = Readonly<{
  /** Full public evidence; production verifies signature and cross-references internally. */
  evidence: unknown;
  nonce: bigint;
  issuedAt: number;
  expiry: number;
}>;

export type PreparedBridge = Readonly<{
  schemaVersion: typeof BRIDGE_EXECUTION_SCHEMA;
  payload: GovernedBridgePayload;
  typedDataDigest: Hex;
  structHash: Hex;
  intentDigest: Hex;
  adapter: AdapterState;
  signerAddress: `0x${string}`;
}>;

type PreparedState = Readonly<{
  prepared: PreparedBridge;
  canonical: CanonicalRecourseBridgeArtifacts;
}>;

function intentDigestOf(input: Readonly<{
  adapter: `0x${string}`;
  chainId: number;
  typedDataDigest: Hex;
  signer: `0x${string}`;
  governedResultDigest: Hex;
}>): Hex {
  const canonical = JSON.stringify({
    adapter: input.adapter.toLowerCase(),
    chainId: input.chainId,
    governedResultDigest: input.governedResultDigest.toLowerCase(),
    signer: input.signer.toLowerCase(),
    typedDataDigest: input.typedDataDigest.toLowerCase(),
  });
  return `0x${createHash("sha256").update(`MordantBridgeIntent/v2\0${canonical}`).digest("hex")}`;
}

function assertConfiguredCanonicalAdapter(configuration: BridgeConfiguration, canonical: CanonicalRecourseBridgeArtifacts): void {
  if (configuration.adapterAddress.toLowerCase() !== canonical.adapter.address.toLowerCase()) {
    fail("ADAPTER_MISMATCH", "The configured adapter is not the adapter in the committed V2 artifacts");
  }
  if (canonical.adapter.chainId !== MONAD_TESTNET_CHAIN_ID) {
    fail("CHAIN_MISMATCH", "The committed bridge artifacts are not pinned to Monad testnet");
  }
}

/**
 * JSON-safe, key-free compatibility report for a server-rendered/read-only edge.
 * It intentionally exposes neither a signed payload nor a signature. The only
 * values it takes from the environment are the RPC URL and adapter address read
 * by readBridgeConfiguration; the retained vector window comes from the canonical
 * handoff, never a UI request.
 */
export type CanonicalAdapterV2CompatibilityReport = Readonly<{
  schemaVersion: "mordant.adapter-v2-compatibility-report/1";
  compatible: true;
  adapter: Readonly<{
    address: `0x${string}`;
    chainId: number;
    codeHash: Hex;
    runtimeBytes: number;
    settlementToken: `0x${string}`;
    cviVerifier: `0x${string}`;
    facility: `0x${string}`;
    availableReserve: string;
    openReserved: string;
    entitledUnpaid: string;
    tokenBalance: string;
    solvent: boolean;
    roleHolder: number;
    roleFacility: number;
  }>;
  participants: Readonly<{
    holderA: `0x${string}`;
    holderB: `0x${string}`;
    payoutA: string;
    payoutB: string;
  }>;
  pins: Readonly<{
    attestor: `0x${string}`;
    governedReleaseAuthorityId: Hex;
    assetIdentityDigest: Hex;
    releaseMode: Hex;
    circuitHash: Hex;
    parameterFingerprint: Hex;
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
    governedResultDigest: Hex;
    conflict: boolean;
    nonce: string;
    issuedAt: number;
    expiry: number;
    typedDataDigest: Hex;
    structHash: Hex;
  }>;
}>;

export async function readCanonicalAdapterV2Compatibility(
  environment: EnvironmentLike = process.env,
  reader?: AdapterReader,
): Promise<CanonicalAdapterV2CompatibilityReport> {
  const configuration = readBridgeConfiguration(environment);
  let canonical: CanonicalRecourseBridgeArtifacts;
  try {
    canonical = loadCanonicalRecourseBridgeArtifacts();
  } catch (error) {
    return bridgeError(error, "CANONICAL_LOAD", "The canonical V2 artifacts could not be loaded");
  }
  assertConfiguredCanonicalAdapter(configuration, canonical);
  let checked: Awaited<ReturnType<typeof checkAdapterV2Compatibility>>;
  try {
    checked = await checkAdapterV2Compatibility(withReadOnlyRetries(reader ?? createAdapterReader(configuration)), canonical, {
      release: canonical.release,
      nonce: canonical.encodingVector.nonce,
      issuedAt: canonical.encodingVector.issuedAt,
      expiry: canonical.encodingVector.expiry,
    });
  } catch (error) {
    return bridgeError(error, "ADAPTER_READ", "The Adapter V2 compatibility check failed");
  }
  const state = checked.adapter;
  const participants = canonical.configuration.participants;
  return Object.freeze({
    schemaVersion: "mordant.adapter-v2-compatibility-report/1",
    compatible: true,
    adapter: Object.freeze({
      address: state.address,
      chainId: state.chainId,
      codeHash: state.codeHash,
      runtimeBytes: state.runtimeBytes,
      settlementToken: state.settlementToken,
      cviVerifier: state.cviVerifier,
      facility: state.facility,
      availableReserve: state.availableReserve.toString(),
      openReserved: state.openReserved.toString(),
      entitledUnpaid: state.entitledUnpaid.toString(),
      tokenBalance: state.tokenBalance.toString(),
      solvent: state.solvent,
      roleHolder: state.roleHolder,
      roleFacility: state.roleFacility,
    }),
    participants: Object.freeze({
      holderA: participants.holderA,
      holderB: participants.holderB,
      payoutA: participants.payoutA.toString(),
      payoutB: participants.payoutB.toString(),
    }),
    pins: Object.freeze({
      attestor: state.attestor,
      governedReleaseAuthorityId: state.expectedGovernedReleaseAuthorityId,
      assetIdentityDigest: state.assetIdentityDigest,
      releaseMode: state.releaseMode,
      circuitHash: state.circuitHash,
      parameterFingerprint: state.parameterFingerprint,
    }),
    // These are bounded facts, not input flags. The checker made every listed
    // eth_call and separately proved that neither excluded address is canonical.
    eligibility: checked.eligibility,
    digestParity: true,
    retainedVector: Object.freeze({
      governedResultDigest: checked.payload.message.governedResultDigest,
      conflict: checked.payload.message.conflict,
      nonce: canonical.encodingVector.nonce.toString(),
      issuedAt: canonical.encodingVector.issuedAt,
      expiry: canonical.encodingVector.expiry,
      typedDataDigest: checked.typedDataDigest,
      structHash: checked.structHash,
    }),
  });
}

/**
 * The only production path from a runtime result to a bridge release. The full
 * public-evidence verifier checks exact structure, digest/cross-reference roots,
 * and the Ed25519 governed signature before any bridge values are derived.
 */
function verifiedReleaseFromEvidence(
  value: unknown,
  canonical: CanonicalRecourseBridgeArtifacts,
): VerifiedGovernedRelease {
  assertPublicProtectionEvidence(value, canonical.expectedSourceCommit);
  const evidence = value as MordantProtectionEvidence;
  // Kept explicit here as a defense-in-depth call and a visible boundary: the
  // attestor never treats a handoff assertion or request Boolean as signature proof.
  verifyGovernedResultSignature(evidence.governedResult);
  const result = evidence.governedResult;
  return Object.freeze({
    runId: evidence.runId,
    fheCaseId: result.caseId,
    caseBindingDigest: result.caseBindingDigest,
    assetIdentity: result.assetIdentity,
    governedResultDigest: result.digest,
    resultCiphertextDigest: result.resultCiphertextDigest,
    participantArtifactDigests: Object.freeze([
      result.participantArtifactDigests[0],
      result.participantArtifactDigests[1],
    ]) as readonly [`sha256:${string}`, `sha256:${string}`],
    circuitDigest: result.circuitDigest,
    parameterFingerprint: result.parameterFingerprint,
    releaseAuthorityId: result.releaseAuthorityId,
    releaseMode: result.releaseMode,
    conflict: result.conflict,
  });
}

async function buildPrepared(
  configuration: BridgeConfiguration,
  reader: AdapterReader,
  input: PrepareInput,
  loadCanonical: () => CanonicalRecourseBridgeArtifacts,
  verifyEvidence: (evidence: unknown, canonical: CanonicalRecourseBridgeArtifacts) => VerifiedGovernedRelease,
): Promise<PreparedState> {
  let canonical: CanonicalRecourseBridgeArtifacts;
  try {
    canonical = loadCanonical();
  } catch (error) {
    return bridgeError(error, "CANONICAL_LOAD", "The canonical V2 artifacts could not be loaded");
  }
  assertConfiguredCanonicalAdapter(configuration, canonical);
  let release: VerifiedGovernedRelease;
  try {
    release = verifyEvidence(input.evidence, canonical);
  } catch (error) {
    return bridgeError(error, "GOVERNED_EVIDENCE", "The governed public evidence was rejected");
  }
  let checked: Awaited<ReturnType<typeof checkAdapterV2Compatibility>>;
  try {
    checked = await checkAdapterV2Compatibility(withReadOnlyRetries(reader), canonical, {
      release,
      nonce: input.nonce,
      issuedAt: input.issuedAt,
      expiry: input.expiry,
    });
  } catch (error) {
    return bridgeError(error, "ADAPTER_READ", "The Adapter V2 compatibility check failed");
  }
  const signerAddress = canonical.adapter.attestor;
  const prepared = Object.freeze({
    schemaVersion: BRIDGE_EXECUTION_SCHEMA,
    payload: checked.payload,
    typedDataDigest: checked.typedDataDigest,
    structHash: checked.structHash,
    intentDigest: intentDigestOf({
      adapter: checked.adapter.address,
      chainId: checked.adapter.chainId,
      typedDataDigest: checked.typedDataDigest,
      signer: signerAddress,
      governedResultDigest: checked.payload.message.governedResultDigest,
    }),
    adapter: checked.adapter,
    signerAddress,
  });
  return Object.freeze({ prepared, canonical });
}

export type BridgeOperationRecord = Readonly<{
  schemaVersion: typeof BRIDGE_EXECUTION_SCHEMA;
  governedResultDigest: Hex;
  adapterAddress: `0x${string}`;
  chainId: number;
  signerAddress: `0x${string}`;
  typedDataDigest: Hex;
  structHash: Hex;
  intentDigest: Hex;
  signature: Hex;
  preparedAtUnix: number;
  submitted: false;
  transactionHash: null;
}>;

const BRIDGE_RECORD_FIELDS = Object.freeze([
  "schemaVersion",
  "governedResultDigest",
  "adapterAddress",
  "chainId",
  "signerAddress",
  "typedDataDigest",
  "structHash",
  "intentDigest",
  "signature",
  "preparedAtUnix",
  "submitted",
  "transactionHash",
] as const);

function recordFailure(message: string): never {
  fail("RECORD_INVALID", message);
}

function canonicalRecordHex(value: unknown, bytes: number, label: string): Hex {
  if (typeof value !== "string" || !new RegExp(`^0x[0-9a-f]{${bytes * 2}}$`, "u").test(value)) {
    recordFailure(`The durable bridge record has an invalid ${label}`);
  }
  return value as Hex;
}

function canonicalRecordAddress(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) {
    recordFailure(`The durable bridge record has an invalid ${label}`);
  }
  try {
    const parsed = getAddress(value);
    if (parsed !== value) recordFailure(`The durable bridge record has a non-canonical ${label}`);
    return parsed;
  } catch {
    recordFailure(`The durable bridge record has an invalid ${label}`);
  }
}

function canonicalRecordInteger(value: unknown, label: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    recordFailure(`The durable bridge record has an invalid ${label}`);
  }
  return value;
}

/**
 * Parses the exact record schema written by this module. A durable record is
 * security input once link(2) reports EEXIST, so it is never recovered with a
 * type assertion or allowed to carry extension fields from another writer.
 */
function parseBridgeOperationRecord(value: unknown, expectedDigest: Hex): BridgeOperationRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    recordFailure("The durable bridge record must be a JSON object");
  }
  const raw = value as Record<string, unknown>;
  const keys = Object.keys(raw).sort();
  const expectedKeys = [...BRIDGE_RECORD_FIELDS].sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    recordFailure("The durable bridge record does not have the exact bridge schema");
  }
  if (raw.schemaVersion !== BRIDGE_EXECUTION_SCHEMA) {
    recordFailure("The durable bridge record has an unsupported schema version");
  }
  const governedResultDigest = canonicalRecordHex(raw.governedResultDigest, 32, "governed result digest");
  const requestedDigest = canonicalRecordHex(expectedDigest, 32, "requested governed result digest");
  if (governedResultDigest !== requestedDigest) {
    recordFailure("The durable bridge record does not match its governed-result path");
  }
  const signature = canonicalRecordHex(raw.signature, 65, "signature");
  if (raw.submitted !== false || raw.transactionHash !== null) {
    recordFailure("The durable bridge record must remain an unsubmitted authorization");
  }
  const chainId = canonicalRecordInteger(raw.chainId, "chain ID", 1);
  if (chainId !== MONAD_TESTNET_CHAIN_ID) {
    recordFailure("The durable bridge record is not for Monad testnet");
  }
  return Object.freeze({
    schemaVersion: BRIDGE_EXECUTION_SCHEMA,
    governedResultDigest,
    adapterAddress: canonicalRecordAddress(raw.adapterAddress, "adapter address"),
    chainId,
    signerAddress: canonicalRecordAddress(raw.signerAddress, "signer address"),
    typedDataDigest: canonicalRecordHex(raw.typedDataDigest, 32, "typed-data digest"),
    structHash: canonicalRecordHex(raw.structHash, 32, "struct hash"),
    intentDigest: canonicalRecordHex(raw.intentDigest, 32, "intent digest"),
    signature,
    preparedAtUnix: canonicalRecordInteger(raw.preparedAtUnix, "prepared timestamp", 0),
    submitted: false,
    transactionHash: null,
  });
}

export function bridgeRecordPath(runRoot: string, governedResultDigest: Hex): string {
  const digest = canonicalRecordHex(governedResultDigest, 32, "governed result digest");
  return join(runRoot, "bridge", `${digest.slice(2)}.json`);
}

export function readBridgeRecord(runRoot: string, governedResultDigest: Hex): BridgeOperationRecord | null {
  const path = bridgeRecordPath(runRoot, governedResultDigest);
  if (!existsSync(path)) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch {
    recordFailure("The durable bridge record is not valid JSON");
  }
  return parseBridgeOperationRecord(raw, governedResultDigest);
}

type SigningCapability = Readonly<{
  signerAddress: `0x${string}`;
  sign: (payload: GovernedBridgePayload) => Promise<Hex>;
}>;

/**
 * The only key read in this module. The key is scoped to this function and is
 * never placed in an object, record, return value, log, or serializable state.
 */
function loadSigningCapability(environment: EnvironmentLike): SigningCapability {
  let account: ReturnType<typeof privateKeyToAccount>;
  {
    const configuredKey = environment[BRIDGE_ENVIRONMENT.attestorPrivateKey];
    if (typeof configuredKey !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(configuredKey.trim())) {
      fail("ATTESTOR_KEY_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.attestorPrivateKey} must be a 0x 32-byte private key`);
    }
    try {
      account = privateKeyToAccount(configuredKey.trim() as Hex);
    } catch {
      fail("ATTESTOR_KEY_INVALID", "The configured bridge attestor key could not be used");
    }
  }
  const capability = {
    signerAddress: account.address,
    sign: (payload: GovernedBridgePayload) => account.signTypedData({
      domain: payload.domain,
      types: payload.types,
      primaryType: payload.primaryType,
      message: payload.message,
    }),
  };
  Object.defineProperty(capability, "toJSON", {
    enumerable: false,
    value: () => ({ signerAddress: capability.signerAddress }),
  });
  return Object.freeze(capability);
}

export type SimulatedBridge = Readonly<{
  schemaVersion: typeof BRIDGE_EXECUTION_SCHEMA;
  intentDigest: Hex;
  typedDataDigest: Hex;
  signerAddress: `0x${string}`;
  simulatedAtUnix: number;
}>;

type SimulationState = Readonly<{
  prepared: PreparedBridge;
  signature: Hex;
  simulatedAtUnix: number;
}>;

export type SignedBridge = Readonly<{
  prepared: PreparedBridge;
  signature: Hex;
  record: BridgeOperationRecord;
  /** False only when the same simulated intent already has a durable record. */
  newlySigned: boolean;
}>;

function validSignature(signature: Hex): boolean {
  return /^0x[0-9a-fA-F]{130}$/u.test(signature);
}

function hasErrnoCode(error: unknown, code: string): boolean {
  return error !== null && typeof error === "object" && "code" in error
    && (error as Readonly<{ code?: unknown }>).code === code;
}

function unlinkIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if (!hasErrnoCode(error, "ENOENT")) throw error;
  }
}

function fsyncDirectory(path: string): void {
  let descriptor = -1;
  try {
    descriptor = openSync(path, "r");
    fsyncSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

/**
 * Atomically publishes a completed record without ever replacing an existing
 * result-digest record. The temporary file is synced first and `link(2)` is the
 * create-only commit point: unlike rename, it fails with EEXIST rather than
 * overwriting another executor's authorization.
 */
function createBridgeRecordOnly(path: string, record: BridgeOperationRecord): boolean {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let descriptor = -1;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, `${JSON.stringify(record, null, 2)}\n`, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    try {
      linkSync(temporary, path);
    } catch (error) {
      if (hasErrnoCode(error, "EEXIST")) return false;
      throw error;
    }
    fsyncDirectory(directory);
    return true;
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
    unlinkIfPresent(temporary);
  }
}

async function assertReusableBridgeRecord(existing: BridgeOperationRecord, prepared: PreparedBridge): Promise<void> {
  const expected = {
    governedResultDigest: prepared.payload.message.governedResultDigest,
    adapterAddress: prepared.adapter.address,
    chainId: prepared.adapter.chainId,
    signerAddress: prepared.signerAddress,
    typedDataDigest: prepared.typedDataDigest,
    structHash: prepared.structHash,
    intentDigest: prepared.intentDigest,
  };
  const crossReferences: readonly (readonly [string, string | number, string | number])[] = [
    ["governedResultDigest", existing.governedResultDigest, expected.governedResultDigest],
    ["adapterAddress", existing.adapterAddress, expected.adapterAddress],
    ["chainId", existing.chainId, expected.chainId],
    ["signerAddress", existing.signerAddress, expected.signerAddress],
    ["typedDataDigest", existing.typedDataDigest, expected.typedDataDigest],
    ["structHash", existing.structHash, expected.structHash],
    ["intentDigest", existing.intentDigest, expected.intentDigest],
  ];
  for (const [name, actual, wanted] of crossReferences) {
    if (typeof actual === "string" && typeof wanted === "string"
      ? actual.toLowerCase() !== wanted.toLowerCase()
      : actual !== wanted) {
      fail("CHANGED_PAYLOAD", `A different ${name} was already authorized for this governed result`);
    }
  }
  let recovered: `0x${string}`;
  try {
    recovered = await recoverAddress({ hash: prepared.typedDataDigest, signature: existing.signature });
  } catch {
    fail("RECORD_SIGNATURE", "The existing bridge authorization has an invalid signature");
  }
  if (recovered.toLowerCase() !== prepared.signerAddress.toLowerCase()) {
    fail("RECORD_SIGNATURE", "The existing bridge authorization was not signed by the committed attestor");
  }
}

async function persistSigned(
  runRoot: string,
  prepared: PreparedBridge,
  signature: Hex,
  now: () => number,
): Promise<SignedBridge> {
  const governedResultDigest = prepared.payload.message.governedResultDigest;
  const record: BridgeOperationRecord = {
    schemaVersion: BRIDGE_EXECUTION_SCHEMA,
    governedResultDigest,
    adapterAddress: prepared.adapter.address,
    chainId: prepared.adapter.chainId,
    signerAddress: prepared.signerAddress,
    typedDataDigest: prepared.typedDataDigest,
    structHash: prepared.structHash,
    intentDigest: prepared.intentDigest,
    signature,
    preparedAtUnix: now(),
    submitted: false,
    transactionHash: null,
  };
  const path = bridgeRecordPath(runRoot, governedResultDigest);
  // One create-only local persistence attempt. It is intentionally never retried.
  if (createBridgeRecordOnly(path, record)) {
    return Object.freeze({ prepared, signature, record, newlySigned: true });
  }
  const existing = readBridgeRecord(runRoot, governedResultDigest);
  if (existing === null) fail("RECORD_RACE", "The concurrent bridge authorization record could not be read");
  await assertReusableBridgeRecord(existing, prepared);
  return Object.freeze({ prepared, signature: existing.signature, record: existing, newlySigned: false });
}

export type BridgeReceipt = Readonly<{
  transactionHash: Hex;
  status: "success";
  /** Present only after the adapter emitted the exact matching ReleaseConsumed event. */
  runId: Hex;
  conflict: boolean;
  governedResultDigest: Hex;
}> | Readonly<{
  transactionHash: Hex;
  status: "reverted";
  /** A reverted receipt proves no release; do not project planned payload fields as success. */
  runId: null;
  conflict: null;
  governedResultDigest: null;
}>;

export function pollBridgeReceipt<T>(readReceipt: () => Promise<T>, attempts: number = 3): Promise<T> {
  return retryReadOnly(readReceipt, attempts);
}

function receiptAddress(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string") fail("RECEIPT_ADAPTER", `The receipt does not carry a ${label}`);
  try {
    return getAddress(value);
  } catch {
    fail("RECEIPT_ADAPTER", `The receipt does not carry a valid ${label}`);
  }
}

function receiptHex(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]*$/u.test(value) || value.length % 2 !== 0) {
    fail("RECEIPT_EVENT", `The receipt has invalid ${label}`);
  }
  return value as Hex;
}

type ReleaseConsumedEvent = Readonly<{
  runId: Hex;
  conflict: boolean;
  governedResultDigest: Hex;
}>;

/**
 * Decodes only ReleaseConsumed logs emitted by the configured adapter. Receipt
 * objects are provider input: a `status: success` literal cannot establish a
 * settlement without this contract-authenticated event.
 */
function releaseConsumedEvents(
  logs: unknown,
  adapterAddress: `0x${string}`,
): readonly ReleaseConsumedEvent[] {
  if (!Array.isArray(logs)) fail("RECEIPT_EVENT", "A successful receipt must carry logs");
  const events: ReleaseConsumedEvent[] = [];
  for (const raw of logs) {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      fail("RECEIPT_EVENT", "A successful receipt carries an invalid log");
    }
    const log = raw as Record<string, unknown>;
    const source = receiptAddress(log.address, "log address");
    if (source.toLowerCase() !== adapterAddress.toLowerCase()) continue;
    const topics = log.topics;
    if (!Array.isArray(topics)) fail("RECEIPT_EVENT", "An adapter receipt log has no topics");
    const decodedTopics = topics.map((topic) => receiptHex(topic, "log topic"));
    if (decodedTopics.length === 0) continue;
    let decoded: ReturnType<typeof decodeEventLog>;
    try {
      decoded = decodeEventLog({
        abi: ADAPTER_ABI,
        data: receiptHex(log.data, "log data"),
        topics: decodedTopics as [Hex, ...Hex[]],
      });
    } catch {
      // The adapter may emit unrelated events during its state transition. They
      // cannot substitute for ReleaseConsumed and are safely ignored here.
      continue;
    }
    if (decoded.eventName !== "ReleaseConsumed") continue;
    const args = decoded.args as Readonly<Record<string, unknown>>;
    const runId = receiptHex(args.runId, "ReleaseConsumed runId");
    const governedResultDigest = receiptHex(args.governedResultDigest, "ReleaseConsumed governed result digest");
    if (runId.length !== 66 || governedResultDigest.length !== 66 || typeof args.conflict !== "boolean") {
      fail("RECEIPT_EVENT", "ReleaseConsumed has an invalid shape");
    }
    events.push(Object.freeze({ runId, conflict: args.conflict, governedResultDigest }));
  }
  return Object.freeze(events);
}

export type BridgeExecutor = Readonly<{
  prepare: (input: PrepareInput) => Promise<PreparedBridge>;
  /** Produces an opaque simulation permit, never a signature. */
  simulate: (prepared: PreparedBridge) => Promise<SimulatedBridge>;
  /** Releases exactly one signature only from a fresh, successful simulation permit. */
  sign: (simulated: SimulatedBridge) => Promise<SignedBridge>;
  /**
   * Compatibility-preserving submission gate. It is intentionally and
   * unconditionally disabled: this server owns no broadcast client or arm flag.
   */
  submit: (signed: SignedBridge) => Promise<never>;
  reconcileReceipt: (signed: SignedBridge, receipt: Readonly<Record<string, unknown>>) => BridgeReceipt;
}>;

type ExecutorDependencies = Readonly<{
  loadCanonical: () => CanonicalRecourseBridgeArtifacts;
  loadSigner: () => SigningCapability;
  verifyEvidence: (evidence: unknown, canonical: CanonicalRecourseBridgeArtifacts) => VerifiedGovernedRelease;
}>;

type ExecutorOptions = Readonly<{
  configuration: BridgeConfiguration;
  reader: AdapterReader;
  runRoot: string;
  now?: () => number;
}>;

function createBridgeExecutorInternal(options: ExecutorOptions, dependencies: ExecutorDependencies): BridgeExecutor {
  const now = options.now ?? (() => Math.floor(Date.now() / 1_000));
  const preparedStates = new WeakMap<object, PreparedState>();
  const simulationStates = new WeakMap<object, SimulationState>();
  const signedStates = new WeakSet<object>();

  const requirePrepared = (prepared: PreparedBridge): PreparedState => {
    const state = preparedStates.get(prepared as object);
    if (state === undefined) fail("PREPARED_UNTRUSTED", "The bridge preparation was not issued by this executor");
    return state;
  };
  const requireSimulation = (simulated: SimulatedBridge): SimulationState => {
    const state = simulationStates.get(simulated as object);
    if (state === undefined) fail("SIMULATION_REQUIRED", "A fresh successful bridge simulation is required before signing");
    return state;
  };

  return Object.freeze({
    prepare: async (input: PrepareInput) => {
      const state = await buildPrepared(
        options.configuration,
        options.reader,
        input,
        dependencies.loadCanonical,
        dependencies.verifyEvidence,
      );
      preparedStates.set(state.prepared as object, state);
      return state.prepared;
    },
    simulate: async (prepared: PreparedBridge) => {
      const state = requirePrepared(prepared);
      let signing: SigningCapability;
      try {
        signing = dependencies.loadSigner();
      } catch (error) {
        return bridgeError(error, "ATTESTOR_KEY_INVALID", "The bridge attestor key could not be loaded");
      }
      if (signing.signerAddress.toLowerCase() !== state.prepared.signerAddress.toLowerCase()) {
        fail("SIGNER_MISMATCH", "The configured bridge attestor key does not match the committed Adapter V2 attestor");
      }
      let candidateSignature: Hex;
      try {
        // A valid candidate is necessary for consumeGovernedRelease eth_call. It stays
        // private until that exact simulation succeeds and brands the permit below.
        candidateSignature = await signing.sign(state.prepared.payload);
      } catch {
        fail("SIGNATURE_FAILED", "The bridge attestor could not create a simulation candidate");
      }
      if (!validSignature(candidateSignature)) fail("SIGNATURE_FORMAT", "The bridge attestor produced an unexpected signature shape");
      try {
        await withReadOnlyRetries(options.reader).simulate(
          state.prepared.payload,
          candidateSignature,
          signing.signerAddress,
        );
      } catch {
        fail("SIMULATION_FAILED", "Adapter V2 rejected the bridge authorization simulation");
      }
      const simulatedAtUnix = now();
      const simulated = Object.freeze({
        schemaVersion: BRIDGE_EXECUTION_SCHEMA,
        intentDigest: state.prepared.intentDigest,
        typedDataDigest: state.prepared.typedDataDigest,
        signerAddress: state.prepared.signerAddress,
        simulatedAtUnix,
      });
      // One prepare produces at most one successful simulation permit.
      preparedStates.delete(prepared as object);
      simulationStates.set(simulated as object, Object.freeze({
        prepared: state.prepared,
        signature: candidateSignature,
        simulatedAtUnix,
      }));
      return simulated;
    },
    sign: async (simulated: SimulatedBridge) => {
      const state = requireSimulation(simulated);
      const signedAtUnix = now();
      if (signedAtUnix < state.simulatedAtUnix
        || signedAtUnix - state.simulatedAtUnix > BRIDGE_SIMULATION_MAX_AGE_SECONDS) {
        simulationStates.delete(simulated as object);
        fail("SIMULATION_STALE", "The successful bridge simulation is no longer fresh enough to authorize signing");
      }
      // Consume the unforgeable permit before the local mutation. A failed write is
      // deliberately not retried; callers must prepare and simulate again.
      simulationStates.delete(simulated as object);
      const signed = await persistSigned(options.runRoot, state.prepared, state.signature, now);
      signedStates.add(signed as object);
      return signed;
    },
    submit: async (_signed: SignedBridge): Promise<never> => {
      fail("SUBMISSION_DISABLED", "Bridge transaction submission is disabled in this executor");
    },
    reconcileReceipt: (signed: SignedBridge, receipt: Readonly<Record<string, unknown>>) => {
      if (!signedStates.has(signed as object)) {
        fail("SIGNED_UNTRUSTED", "The bridge authorization was not issued by this executor");
      }
      const hash = receipt.transactionHash;
      if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(hash)) {
        fail("RECEIPT_HASH", "The receipt does not carry a transaction hash");
      }
      if (receipt.status !== "success" && receipt.status !== "reverted") {
        fail("RECEIPT_STATUS", "The receipt does not carry a known status");
      }
      const receiptAdapter = receiptAddress(receipt.to, "destination adapter");
      if (receiptAdapter.toLowerCase() !== signed.record.adapterAddress.toLowerCase()) {
        fail("RECEIPT_ADAPTER", "The receipt is not for the configured adapter");
      }
      if (receipt.status === "reverted") {
        return Object.freeze({
          transactionHash: hash as Hex,
          status: "reverted" as const,
          runId: null,
          conflict: null,
          governedResultDigest: null,
        });
      }
      const events = releaseConsumedEvents(receipt.logs, signed.record.adapterAddress);
      if (events.length !== 1) {
        fail("RECEIPT_EVENT", "A successful bridge receipt must carry exactly one ReleaseConsumed event");
      }
      const event = events[0]!;
      if (
        event.runId.toLowerCase() !== signed.prepared.payload.message.runId.toLowerCase()
        || event.conflict !== signed.prepared.payload.message.conflict
        || event.governedResultDigest.toLowerCase() !== signed.record.governedResultDigest.toLowerCase()
      ) {
        fail("RECEIPT_EVENT", "ReleaseConsumed does not match the signed bridge authorization");
      }
      return Object.freeze({
        transactionHash: hash as Hex,
        status: "success" as const,
        runId: event.runId,
        conflict: event.conflict,
        governedResultDigest: event.governedResultDigest,
      });
    },
  });
}

/**
 * Production factory. It loads the exact committed artifacts internally and
 * reads the attestor key only at the simulation stage. Its typed submission
 * gate always fails closed, so this API has no broadcast or mutation path.
 */
export function createBridgeExecutor(options: ExecutorOptions & Readonly<{ environment?: EnvironmentLike }>): BridgeExecutor {
  const environment = options.environment ?? process.env;
  return createBridgeExecutorInternal(options, {
    loadCanonical: () => loadCanonicalRecourseBridgeArtifacts(),
    loadSigner: () => loadSigningCapability(environment),
    verifyEvidence: verifiedReleaseFromEvidence,
  });
}

/**
 * Unit-test seam for an already parsed deterministic fixture. Production routes
 * must use createBridgeExecutor; this helper accepts neither raw request values
 * nor a private key, and is kept solely to test opaque-state behavior offline.
 */
export function createBridgeExecutorForTest(options: ExecutorOptions & Readonly<{
  canonical: CanonicalRecourseBridgeArtifacts;
  signerAddress: `0x${string}`;
  sign: (payload: GovernedBridgePayload) => Promise<Hex>;
  verifyEvidence?: (evidence: unknown, canonical: CanonicalRecourseBridgeArtifacts) => VerifiedGovernedRelease;
}>): BridgeExecutor {
  return createBridgeExecutorInternal(options, {
    loadCanonical: () => options.canonical,
    loadSigner: () => Object.freeze({ signerAddress: options.signerAddress, sign: options.sign }),
    verifyEvidence: options.verifyEvidence ?? ((_evidence, canonical) => canonical.release),
  });
}
