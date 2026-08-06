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
  hashTypedData,
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
  loadCanonicalRecourseConfiguration,
  retryReadOnly,
  type AdapterV2ReadOnlyReader,
  type AdapterV2ReadOnlyState,
  type CanonicalRecourseBridgeArtifacts,
  type CanonicalRecourseConfiguration,
} from "./adapter-compatibility";
import { CANONICAL_CLEANVERSE_ASSET_DIGEST } from "./cleanverse-asset";
import type { EnvironmentLike } from "./ccp-eligibility";
import {
  SUPERSEDED_ADAPTER_ADDRESS,
  buildGovernedBridgePayload,
  governedReleaseStructHash,
  type GovernedBridgePayload,
  type VerifiedGovernedRelease,
} from "./governed-recourse-bridge";
import { digestToBytes32 } from "./participant-authorization";
import {
  assertDirectParticipantBridgeEvidence,
  type VerifiedDirectParticipantBridgeEvidence,
} from "./direct-participant-bridge-evidence";
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
/**
 * Minimum spacing between RPC requests, in milliseconds.
 *
 * The public Monad endpoint refuses more than fifteen requests per second, and
 * `readAdapterState` alone issues eighteen reads at once. Without pacing, a
 * perfectly healthy adapter fails its compatibility check for a reason that has
 * nothing to do with the adapter. This paces idempotent reads only; it is not a
 * retry, and no state-changing call passes through here.
 */
const RPC_MIN_INTERVAL_MS = 80;

function pacedQueue(): <T>(operation: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(operation: () => Promise<T>): Promise<T> => {
    const scheduled = tail.then(async () => {
      await new Promise((resolve) => setTimeout(resolve, RPC_MIN_INTERVAL_MS));
      return operation();
    });
    tail = scheduled.then(() => undefined, () => undefined);
    return scheduled as Promise<T>;
  };
}

export function createAdapterReader(configuration: BridgeConfiguration): AdapterReader {
  // Batching collapses concurrent reads into single HTTP requests; the queue
  // below bounds the rate of whatever is left. Neither changes which calls are
  // made or what they return.
  const client = createPublicClient({
    transport: http(configuration.rpcUrl, { batch: { wait: 16 } }),
  }) as PublicClient;
  const paced = pacedQueue();
  const address = configuration.adapterAddress;
  const readContract = client.readContract as unknown as (
    parameters: Readonly<{ address: `0x${string}`; abi: typeof ADAPTER_ABI; functionName: string; args?: readonly unknown[] }>,
  ) => Promise<unknown>;
  const read = <T>(functionName: string, args: readonly unknown[] = []) => paced(
    () => readContract({ address, abi: ADAPTER_ABI, functionName, args }) as Promise<T>,
  );
  return Object.freeze({
    readAdapterState: async () => {
      const [
        chainId, code, settlementToken, cviVerifier, attestor, facility, assetIdentityDigest,
        expectedGovernedReleaseAuthorityId, releaseMode, circuitHash, parameterFingerprint,
        availableReserve, openReserved, entitledUnpaid, solvent, domainSeparator, roleHolder, roleFacility,
      ] = await Promise.all([
        paced(() => client.getChainId()),
        paced(() => client.getCode({ address })),
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
        tokenBalance: await paced(() => client.readContract({
          address: getAddress(settlementToken), abi: ERC20_ABI, functionName: "balanceOf", args: [address],
        })) as bigint,
        solvent,
        domainSeparator,
        roleHolder: Number(roleHolder),
        roleFacility: Number(roleFacility),
      });
    },
    isEligible: (verifier, account, role) => paced(() => client.readContract({
      address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [account, role],
    })) as Promise<boolean>,
    isAssetTransferAllowed: (verifier, asset, from, to, amount) => paced(() => client.readContract({
      address: verifier,
      abi: CVI_ABI,
      functionName: "isAssetTransferAllowed",
      args: [asset, from, to, amount],
    })) as Promise<boolean>,
    hashRelease: (payload) => read<Hex>("hashRelease", [releaseTuple(payload)]),
    resultConsumed: (governedResultDigest) => read<boolean>("resultConsumed", [governedResultDigest]),
    simulate: async (payload, signature, account) => {
      await paced(() => client.simulateContract({
        address,
        abi: ADAPTER_ABI,
        functionName: "consumeGovernedRelease",
        args: [releaseTuple(payload), signature],
        account,
      }));
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
  /**
   * Present only for the retained V4 path. The direct-participant path
   * establishes its release from its own verified evidence, so it has no
   * canonical handoff to carry, and nothing after preparation reads this.
   */
  canonical?: CanonicalRecourseBridgeArtifacts;
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

// ------------------------------------------------- direct-participant bridging

export type DirectParticipantPrepareInput = Readonly<{
  /** The `mordant.direct-participant-bridge-evidence/1` artifact, as read from disk. */
  evidence: unknown;
  /** The source commit of the checkout that executed the run. */
  sourceCommit: string;
  nonce: bigint;
  issuedAt: number;
  expiry: number;
}>;

/**
 * Adapter reconciliation for a case-specific deployment.
 *
 * The retained V4 path reconciles against the one committed adapter, and stays
 * exactly as it was. A direct-participant run has a fresh governed authority, so
 * its adapter is deployed per case and cannot be pinned by a committed address.
 * The run-specific pins therefore come from the VERIFIED signed governed result
 * and from nowhere else, while everything that is not run-specific, the reviewed
 * bytecode, the settlement token, the verifier, the facility, the attestor and
 * the payouts, is still required to equal the committed configuration.
 */
async function checkDirectParticipantAdapter(
  reader: AdapterReader,
  configuration: CanonicalRecourseConfiguration,
  verified: VerifiedDirectParticipantBridgeEvidence,
  release: VerifiedGovernedRelease,
  window: Readonly<{ nonce: bigint; issuedAt: number; expiry: number }>,
): Promise<Readonly<{
  adapter: AdapterState;
  payload: GovernedBridgePayload;
  typedDataDigest: Hex;
  structHash: Hex;
}>> {
  const state = await reader.readAdapterState();
  const expected = configuration.adapter;
  const participants = configuration.participants;

  if (state.chainId !== MONAD_TESTNET_CHAIN_ID) fail("CHAIN_MISMATCH", "The adapter is not on Monad testnet");
  if (state.address.toLowerCase() === SUPERSEDED_ADAPTER_ADDRESS.toLowerCase()) {
    fail("SUPERSEDED_ADAPTER", "The configured adapter is the superseded deployment");
  }
  // Same reviewed contract, different constructor pins. Solidity embeds
  // immutables INTO the runtime code, so a case-specific deployment cannot have
  // the committed deployment's code hash and comparing them would always fail.
  // What is checkable at runtime is the exact runtime length plus every one of
  // the immutables below, which is a complete account of how two deployments of
  // this source may differ. The immutable-masked bytecode equality against the
  // reviewed artifact is proved once at deployment and recorded in evidence,
  // because it needs the compiler's immutable spans, which no RPC exposes.
  if (state.runtimeBytes !== expected.runtimeBytes) {
    fail("ADAPTER_CODE", "Adapter runtime byte length differs from the reviewed artifact");
  }
  if (state.settlementToken.toLowerCase() !== expected.settlementToken.toLowerCase()) {
    fail("ADAPTER_TOKEN", "The case-specific adapter settles a different token");
  }
  if (state.cviVerifier.toLowerCase() !== expected.verifier.toLowerCase()) {
    fail("ADAPTER_VERIFIER", "The case-specific adapter uses a different compliance verifier");
  }
  if (state.facility.toLowerCase() !== expected.facility.toLowerCase()) {
    fail("ADAPTER_FACILITY", "The case-specific adapter names a different facility");
  }
  if (state.attestor.toLowerCase() !== expected.attestor.toLowerCase()) {
    fail("ADAPTER_ATTESTOR", "The case-specific adapter names a different bridge attestor");
  }

  // Run-specific pins, taken from the verified signature and compared literally.
  if (state.assetIdentityDigest.toLowerCase() !== digestToBytes32(release.assetIdentity)) {
    fail("ADAPTER_ASSET", "The adapter asset pin is not the signed receivable");
  }
  if (state.expectedGovernedReleaseAuthorityId.toLowerCase() !== digestToBytes32(release.releaseAuthorityId)) {
    fail("ADAPTER_AUTHORITY", "The adapter authority pin is not this run's signed governed authority");
  }
  if (state.circuitHash.toLowerCase() !== digestToBytes32(release.circuitDigest)) {
    fail("ADAPTER_CIRCUIT", "The adapter circuit pin is not the signed circuit digest");
  }
  if (state.parameterFingerprint.toLowerCase() !== digestToBytes32(release.parameterFingerprint)) {
    fail("ADAPTER_PARAMETERS", "The adapter parameter pin is not the signed parameter fingerprint");
  }

  const payoutTotal = participants.payoutA + participants.payoutB;
  if (!state.solvent || state.tokenBalance < state.availableReserve + state.openReserved + state.entitledUnpaid) {
    fail("INSOLVENT", "The case-specific adapter is not solvent for its reserve and liability accounting");
  }
  if (state.openReserved !== 0n || state.entitledUnpaid !== 0n) {
    fail("OPEN_LIABILITY", "The case-specific adapter must carry no open or entitled liability");
  }
  if (state.availableReserve < payoutTotal) {
    fail("INSUFFICIENT_RESERVE", "The case-specific adapter reserve does not cover the canonical payouts");
  }

  if (participants.holderA.toLowerCase() === participants.holderB.toLowerCase()) {
    fail("CANONICAL_PARTICIPANTS", "The canonical holders are not distinct");
  }
  // The holders are the wallets the evidence verifier reconciled to the canonical
  // configuration, so a payout can only ever reach an admitted canonical wallet.
  if (verified.holderA.toLowerCase() !== participants.holderA.toLowerCase()
    || verified.holderB.toLowerCase() !== participants.holderB.toLowerCase()) {
    fail("CANONICAL_PARTICIPANTS", "The admitted participants are not the canonical holders");
  }
  for (const excluded of Object.values(participants.excluded)) {
    if (excluded.toLowerCase() === participants.holderA.toLowerCase()
      || excluded.toLowerCase() === participants.holderB.toLowerCase()) {
      fail("CANONICAL_EXCLUDED_PARTICIPANT", "An excluded wallet is configured as a participant");
    }
  }

  const [
    holderAEligible, holderBEligible, facilityEligible, negativeControlEligible,
    transferAAllowed, transferBAllowed,
  ] = await Promise.all([
    reader.isEligible(state.cviVerifier, participants.holderA, state.roleHolder),
    reader.isEligible(state.cviVerifier, participants.holderB, state.roleHolder),
    reader.isEligible(state.cviVerifier, state.facility, state.roleFacility),
    reader.isEligible(state.cviVerifier, participants.excluded.negativeControl, state.roleHolder),
    reader.isAssetTransferAllowed(state.cviVerifier, state.settlementToken, state.address, participants.holderA, participants.payoutA),
    reader.isAssetTransferAllowed(state.cviVerifier, state.settlementToken, state.address, participants.holderB, participants.payoutB),
  ]);
  if (!holderAEligible || !holderBEligible) fail("PARTICIPANT_INELIGIBLE", "Every canonical holder must be currently eligible");
  if (!facilityEligible) fail("FACILITY_INELIGIBLE", "The facility must currently hold Adapter V2 ROLE_FACILITY");
  if (negativeControlEligible) fail("NEGATIVE_CONTROL_ELIGIBLE", "The canonical negative control must remain ineligible for ROLE_HOLDER");
  if (!transferAAllowed || !transferBAllowed) fail("TRANSFER_POLICY", "Every canonical payout transfer must be currently permitted");

  const payload = buildGovernedBridgePayload({
    release,
    participants: {
      holderA: participants.holderA,
      holderB: participants.holderB,
      // Payouts come only from the committed deployment configuration.
      payoutA: participants.payoutA,
      payoutB: participants.payoutB,
    },
    pins: {
      address: state.address,
      chainId: state.chainId,
      assetIdentityDigest: state.assetIdentityDigest,
      releaseAuthorityId: state.expectedGovernedReleaseAuthorityId,
      releaseMode: state.releaseMode,
      circuitHash: state.circuitHash,
      parameterFingerprint: state.parameterFingerprint,
    },
    interpretation: "PINS_GOVERNED_AUTHORITY",
    nonce: window.nonce,
    issuedAt: window.issuedAt,
    expiry: window.expiry,
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
  if (consumed) fail("RESULT_CONSUMED", "The governed result has already been consumed by this adapter");
  if (onChainDigest.toLowerCase() !== typedDataDigest.toLowerCase()) {
    fail("DIGEST_MISMATCH", "Adapter hashRelease disagrees with the independently encoded typed-data digest");
  }
  return Object.freeze({ adapter: state, payload, typedDataDigest, structHash });
}

/**
 * Derives the bridge release from the verified direct-participant evidence.
 *
 * Every field is read out of the governed result whose Ed25519 signature the
 * verifier already checked. The terminal Boolean in particular comes from
 * `verified.conflict`, which the verifier returns only after that check.
 */
function directParticipantRelease(verified: VerifiedDirectParticipantBridgeEvidence): VerifiedGovernedRelease {
  const result = verified.governedResult;
  return Object.freeze({
    runId: verified.evidence.runId,
    fheCaseId: result.caseId,
    caseBindingDigest: result.caseBindingDigest,
    assetIdentity: result.assetIdentity,
    governedResultDigest: verified.evidence.governedResultDigest,
    resultCiphertextDigest: result.resultCiphertextDigest,
    participantArtifactDigests: Object.freeze([
      result.participantArtifactDigests[0],
      result.participantArtifactDigests[1],
    ]) as readonly [`sha256:${string}`, `sha256:${string}`],
    circuitDigest: result.circuitDigest,
    parameterFingerprint: result.parameterFingerprint,
    releaseAuthorityId: result.releaseAuthorityId,
    releaseMode: result.releaseMode,
    conflict: verified.conflict,
  });
}

async function buildPreparedDirect(
  configuration: BridgeConfiguration,
  reader: AdapterReader,
  input: DirectParticipantPrepareInput,
  loadConfiguration: () => CanonicalRecourseConfiguration,
): Promise<PreparedBridge> {
  let canonicalConfiguration: CanonicalRecourseConfiguration;
  try {
    canonicalConfiguration = loadConfiguration();
  } catch (error) {
    return bridgeError(error, "CANONICAL_LOAD", "The canonical V2 configuration could not be loaded");
  }
  let verified: VerifiedDirectParticipantBridgeEvidence;
  try {
    verified = assertDirectParticipantBridgeEvidence(input.evidence, {
      sourceCommit: input.sourceCommit,
      assetIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
      holderA: canonicalConfiguration.participants.holderA,
      holderB: canonicalConfiguration.participants.holderB,
      excludedWallets: Object.values(canonicalConfiguration.participants.excluded),
    });
  } catch (error) {
    return bridgeError(error, "DIRECT_EVIDENCE", "The direct-participant bridge evidence was rejected");
  }
  const release = directParticipantRelease(verified);
  let checked: Awaited<ReturnType<typeof checkDirectParticipantAdapter>>;
  try {
    checked = await checkDirectParticipantAdapter(
      withReadOnlyRetries(reader),
      canonicalConfiguration,
      verified,
      release,
      { nonce: input.nonce, issuedAt: input.issuedAt, expiry: input.expiry },
    );
  } catch (error) {
    return bridgeError(error, "ADAPTER_READ", "The case-specific adapter compatibility check failed");
  }
  if (checked.adapter.address.toLowerCase() !== configuration.adapterAddress.toLowerCase()) {
    fail("ADAPTER_MISMATCH", "The reconciled adapter is not the configured adapter");
  }
  return Object.freeze({
    schemaVersion: BRIDGE_EXECUTION_SCHEMA,
    payload: checked.payload,
    typedDataDigest: checked.typedDataDigest,
    structHash: checked.structHash,
    intentDigest: intentDigestOf({
      adapter: checked.adapter.address,
      chainId: checked.adapter.chainId,
      typedDataDigest: checked.typedDataDigest,
      signer: checked.adapter.attestor,
      governedResultDigest: checked.payload.message.governedResultDigest,
    }),
    adapter: checked.adapter,
    signerAddress: checked.adapter.attestor,
  });
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
  /** Retained V4 evidence path. Unchanged. */
  prepare: (input: PrepareInput) => Promise<PreparedBridge>;
  /**
   * Fresh direct-participant path. Accepts ONLY
   * `mordant.direct-participant-bridge-evidence/1`; it never reaches
   * `assertPublicProtectionEvidence` and cannot consume V4 evidence.
   */
  prepareDirect: (input: DirectParticipantPrepareInput) => Promise<PreparedBridge>;
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
  loadConfiguration: () => CanonicalRecourseConfiguration;
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
    prepareDirect: async (input: DirectParticipantPrepareInput) => {
      const prepared = await buildPreparedDirect(
        options.configuration,
        options.reader,
        input,
        dependencies.loadConfiguration,
      );
      // The direct path shares the simulate/sign/reconcile discipline exactly;
      // only how the release was established differs. `canonical` is carried for
      // shape compatibility and is not consulted again after preparation.
      preparedStates.set(prepared as object, Object.freeze({ prepared }));
      return prepared;
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
    loadConfiguration: () => loadCanonicalRecourseConfiguration(),
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
    loadConfiguration: () => options.canonical.configuration,
    loadSigner: () => Object.freeze({ signerAddress: options.signerAddress, sign: options.sign }),
    verifyEvidence: options.verifyEvidence ?? ((_evidence, canonical) => canonical.release),
  });
}
