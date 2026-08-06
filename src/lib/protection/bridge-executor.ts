import "server-only";

/**
 * Server-only governed-release bridge executor.
 *
 * This is the one place that holds the bridge attestor key, and it holds it only
 * in server memory read from the environment. The key never reaches a response, a
 * log line, an evidence file, a durable record or source control: the only value
 * derived from it that is ever written down is the signer's public address, which
 * must equal the adapter's own `attestor` immutable.
 *
 * Everything signed is derived from two places and no others: the Ed25519-verified
 * governed result, and the contract developer's committed demo configuration. No
 * value arrives from a browser. There is no parameter through which a caller could
 * supply the terminal Boolean, a holder, a payout or a digest.
 *
 * This package prepares, simulates and signs. It does NOT broadcast: `submit` is
 * present as a typed integration point and refuses unless explicitly armed, so the
 * integration agent decides when a transaction is sent, not this module.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  createPublicClient,
  getAddress,
  http,
  hashTypedData,
  parseAbi,
  type Hex,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { readCcpRpcUrl, type EnvironmentLike } from "./ccp-eligibility";
import {
  SUPERSEDED_ADAPTER_ADDRESS,
  assertProductionInterpretation,
  buildGovernedBridgePayload,
  governedReleaseStructHash,
  reconcileAdapter,
  type AdapterPins,
  type GovernedBridgePayload,
  type VerifiedGovernedRelease,
} from "./governed-recourse-bridge";
import { writeDurableJsonAtomic } from "./protection-operation-journal";

export const BRIDGE_EXECUTION_SCHEMA = "mordant.bridge-execution/1" as const;
export const RECOURSE_V2_DEMO_CONFIG_PATH =
  "docs/evidence/recourse-v2-demo-config-2026-08-06.json" as const;

/** Exact reviewed environment names. Nothing else is read. */
export const BRIDGE_ENVIRONMENT = Object.freeze({
  rpcUrl: "MORDANT_MONAD_RPC_URL",
  rpcUrlFallback: "MONAD_RPC_URL",
  adapterAddress: "MORDANT_RECOURSE_ADAPTER_ADDRESS",
  attestorPrivateKey: "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY",
  armSubmit: "MORDANT_BRIDGE_SUBMIT_ARMED",
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
  "function cureWindow() view returns (uint64)",
  "function availableReserve() view returns (uint256)",
  "function domainSeparator() view returns (bytes32)",
  "function resultConsumed(bytes32) view returns (bool)",
  "function ROLE_HOLDER() view returns (uint8)",
  "function hashRelease((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,address,uint256,uint256,bool,bytes32,bytes32,bytes32,bytes32,uint256,uint64,uint64) r) view returns (bytes32)",
  "function consumeGovernedRelease((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,address,uint256,uint256,bool,bytes32,bytes32,bytes32,bytes32,uint256,uint64,uint64) r, bytes signature)",
]);

export const CVI_ABI = parseAbi(["function isEligible(address,uint8) view returns (bool)"]);

export class BridgeExecutionError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "BridgeExecutionError";
  }
}

function fail(code: string, message: string): never {
  throw new BridgeExecutionError(code, message);
}

// ------------------------------------------------------------------ configuration

export type BridgeConfiguration = Readonly<{
  rpcUrl: string;
  adapterAddress: `0x${string}`;
  /** Present only in server memory. Never serialized, never logged. */
  attestorPrivateKey: Hex;
  signerAddress: `0x${string}`;
  submitArmed: boolean;
}>;

/**
 * Reads the bridge configuration, failing closed.
 *
 * A missing key or a missing adapter is an error, never a default. The derived
 * signer address is returned; the key itself is kept on the object only so the
 * signing step can reach it, and `toJSON` is defined to guarantee that an
 * accidental `JSON.stringify` of a configuration cannot leak it.
 */
export function readBridgeConfiguration(environment: EnvironmentLike = process.env): BridgeConfiguration {
  const rpcUrl = readCcpRpcUrl(environment);

  const adapter = environment[BRIDGE_ENVIRONMENT.adapterAddress];
  if (typeof adapter !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(adapter.trim())) {
    fail("ADAPTER_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.adapterAddress} must be a 0x adapter address`);
  }
  const adapterAddress = getAddress(adapter.trim());
  if (adapterAddress.toLowerCase() === SUPERSEDED_ADAPTER_ADDRESS.toLowerCase()) {
    fail("SUPERSEDED_ADAPTER", "The configured adapter is the superseded deployment");
  }

  const key = environment[BRIDGE_ENVIRONMENT.attestorPrivateKey];
  if (typeof key !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(key.trim())) {
    fail("ATTESTOR_KEY_NOT_CONFIGURED", `${BRIDGE_ENVIRONMENT.attestorPrivateKey} must be a 0x 32-byte private key`);
  }
  const attestorPrivateKey = key.trim() as Hex;
  let signerAddress: `0x${string}`;
  try {
    signerAddress = privateKeyToAccount(attestorPrivateKey).address;
  } catch {
    // Never echo the key or the underlying parse error.
    fail("ATTESTOR_KEY_INVALID", "The configured bridge attestor key could not be used");
  }

  const configuration = {
    rpcUrl,
    adapterAddress,
    attestorPrivateKey,
    signerAddress,
    submitArmed: environment[BRIDGE_ENVIRONMENT.armSubmit] === "1",
  };
  // Belt and braces: serializing a configuration can never reveal the key.
  Object.defineProperty(configuration, "toJSON", {
    enumerable: false,
    value: () => ({
      adapterAddress,
      signerAddress,
      submitArmed: configuration.submitArmed,
      attestorPrivateKey: "[redacted]",
    }),
  });
  return Object.freeze(configuration);
}

// ------------------------------------------------------------------ demo configuration

/**
 * The contract developer's committed demo configuration.
 *
 * It supplies the values the runtime must not invent: which two A-Pass eligible
 * wallets take the two roles, and the exact bounded payouts. It is read from the
 * repository, never from a request.
 */
export type RecourseDemoConfiguration = Readonly<{
  adapterAddress: `0x${string}`;
  chainId: number;
  holderA: `0x${string}`;
  holderB: `0x${string}`;
  payoutA: bigint;
  payoutB: bigint;
}>;

function exactAddress(value: unknown, code: string, label: string): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) {
    fail(code, `${label} must be a 0x address`);
  }
  return getAddress(value);
}

function exactAmount(value: unknown, code: string, label: string): bigint {
  if (typeof value === "string" && /^[0-9]+$/u.test(value)) return BigInt(value);
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return fail(code, `${label} must be a whole non-negative amount`);
}

export function parseRecourseDemoConfiguration(value: unknown): RecourseDemoConfiguration {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("DEMO_CONFIG_SHAPE", "The demo configuration must be a JSON object");
  }
  const raw = value as Record<string, unknown>;
  const participants = (raw.participants ?? raw) as Record<string, unknown>;
  const payouts = (raw.payouts ?? raw) as Record<string, unknown>;
  const network = (raw.network ?? raw) as Record<string, unknown>;
  const chainId = network.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId <= 0) {
    fail("DEMO_CONFIG_CHAIN", "The demo configuration must declare a chainId");
  }
  return Object.freeze({
    adapterAddress: exactAddress(raw.adapterAddress ?? raw.adapter, "DEMO_CONFIG_ADAPTER", "adapterAddress"),
    chainId,
    holderA: exactAddress(participants.holderA, "DEMO_CONFIG_HOLDER_A", "holderA"),
    holderB: exactAddress(participants.holderB, "DEMO_CONFIG_HOLDER_B", "holderB"),
    payoutA: exactAmount(payouts.payoutA, "DEMO_CONFIG_PAYOUT_A", "payoutA"),
    payoutB: exactAmount(payouts.payoutB, "DEMO_CONFIG_PAYOUT_B", "payoutB"),
  });
}

export function loadRecourseDemoConfiguration(
  repositoryRoot: string = process.cwd(),
  path: string = RECOURSE_V2_DEMO_CONFIG_PATH,
): RecourseDemoConfiguration {
  const full = join(repositoryRoot, path);
  if (!existsSync(full)) {
    fail("DEMO_CONFIG_MISSING", `The committed demo configuration is missing at ${path}`);
  }
  return parseRecourseDemoConfiguration(JSON.parse(readFileSync(full, "utf8")));
}

// ------------------------------------------------------------------ live adapter

export type AdapterState = Readonly<{
  address: `0x${string}`;
  chainId: number;
  settlementToken: `0x${string}`;
  cviVerifier: `0x${string}`;
  attestor: `0x${string}`;
  facility: `0x${string}`;
  assetIdentityDigest: Hex;
  expectedGovernedReleaseAuthorityId: Hex;
  releaseMode: Hex;
  circuitHash: Hex;
  parameterFingerprint: Hex;
  availableReserve: bigint;
  domainSeparator: Hex;
  roleHolder: number;
}>;

/** Minimal read surface, so a test can drive the executor without a network. */
export type AdapterReader = Readonly<{
  readAdapterState: () => Promise<AdapterState>;
  isEligible: (verifier: `0x${string}`, account: `0x${string}`, role: number) => Promise<boolean>;
  hashRelease: (payload: GovernedBridgePayload) => Promise<Hex>;
  resultConsumed: (governedResultDigest: Hex) => Promise<boolean>;
  simulate: (payload: GovernedBridgePayload, signature: Hex, account: `0x${string}`) => Promise<void>;
}>;

export function releaseTuple(payload: GovernedBridgePayload) {
  const m = payload.message;
  return [
    m.runId, m.fheCaseId, m.caseBindingDigest, m.assetIdentityDigest, m.governedResultDigest,
    m.resultCiphertextDigest, m.participantArtifactDigestA, m.participantArtifactDigestB,
    m.holderA, m.holderB, m.payoutA, m.payoutB, m.conflict, m.releaseAuthorityId,
    m.releaseMode, m.circuitHash, m.parameterFingerprint, m.nonce, m.issuedAt, m.expiry,
  ] as const;
}

export function createAdapterReader(configuration: BridgeConfiguration): AdapterReader {
  const client = createPublicClient({ transport: http(configuration.rpcUrl) }) as PublicClient;
  const address = configuration.adapterAddress;
  // viem's per-function argument typing does not survive a generic wrapper, so the
  // call is made through one narrow, explicitly typed indirection rather than
  // widening every call site.
  const readContract = client.readContract as unknown as (
    parameters: Readonly<{ address: `0x${string}`; abi: typeof ADAPTER_ABI; functionName: string; args?: readonly unknown[] }>,
  ) => Promise<unknown>;
  const read = <T>(functionName: string, args: readonly unknown[] = []) => (
    readContract({ address, abi: ADAPTER_ABI, functionName, args }) as Promise<T>
  );
  return {
    readAdapterState: async () => {
      const [
        chainId, settlementToken, cviVerifier, attestor, facility, assetIdentityDigest,
        expectedGovernedReleaseAuthorityId, releaseMode, circuitHash, parameterFingerprint,
        availableReserve, domainSeparator, roleHolder,
      ] = await Promise.all([
        client.getChainId(),
        read<`0x${string}`>("settlementToken"), read<`0x${string}`>("cviVerifier"),
        read<`0x${string}`>("attestor"), read<`0x${string}`>("facility"),
        read<Hex>("assetIdentityDigest"), read<Hex>("expectedGovernedReleaseAuthorityId"),
        read<Hex>("releaseMode"), read<Hex>("circuitHash"), read<Hex>("parameterFingerprint"),
        read<bigint>("availableReserve"), read<Hex>("domainSeparator"), read<number>("ROLE_HOLDER"),
      ]);
      return Object.freeze({
        address, chainId, settlementToken, cviVerifier, attestor, facility,
        assetIdentityDigest, expectedGovernedReleaseAuthorityId, releaseMode, circuitHash,
        parameterFingerprint, availableReserve, domainSeparator, roleHolder: Number(roleHolder),
      });
    },
    isEligible: (verifier, account, role) => client.readContract({
      address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [account, role],
    }) as Promise<boolean>,
    hashRelease: (payload) => read<Hex>("hashRelease", [releaseTuple(payload)]),
    resultConsumed: (governedResultDigest) => read<boolean>("resultConsumed", [governedResultDigest]),
    simulate: async (payload, signature, account) => {
      await client.simulateContract({
        address, abi: ADAPTER_ABI, functionName: "consumeGovernedRelease",
        args: [releaseTuple(payload), signature], account,
      });
    },
  };
}

// ------------------------------------------------------------------ preparation

export type PreparedBridge = Readonly<{
  schemaVersion: typeof BRIDGE_EXECUTION_SCHEMA;
  payload: GovernedBridgePayload;
  typedDataDigest: Hex;
  structHash: Hex;
  /** Identity of the exact transaction this signature authorizes. */
  intentDigest: Hex;
  adapter: AdapterState;
  signerAddress: `0x${string}`;
}>;

function intentDigestOf(input: Readonly<{
  adapter: `0x${string}`; chainId: number; typedDataDigest: Hex; signer: `0x${string}`;
  governedResultDigest: Hex;
}>): Hex {
  const canonical = JSON.stringify({
    adapter: input.adapter.toLowerCase(),
    chainId: input.chainId,
    governedResultDigest: input.governedResultDigest.toLowerCase(),
    signer: input.signer.toLowerCase(),
    typedDataDigest: input.typedDataDigest.toLowerCase(),
  });
  return `0x${createHash("sha256").update(`MordantBridgeIntent/v1\0${canonical}`).digest("hex")}`;
}

export type PrepareInput = Readonly<{
  release: VerifiedGovernedRelease;
  demo: RecourseDemoConfiguration;
  nonce: bigint;
  issuedAt: number;
  expiry: number;
  governedSignatureVerified: true;
  crossReferencesVerified: true;
}>;

/**
 * Reconciles the live adapter, then builds the exact payload it would accept.
 *
 * Every refusal below is a refusal to sign. Nothing is adjusted to fit: a wrong
 * adapter, chain, participant, authority, circuit, parameter, amount or result
 * ends the attempt.
 */
export async function prepareBridge(
  configuration: BridgeConfiguration,
  reader: AdapterReader,
  input: PrepareInput,
): Promise<PreparedBridge> {
  const adapter = await reader.readAdapterState();

  if (adapter.address.toLowerCase() !== input.demo.adapterAddress.toLowerCase()) {
    fail("ADAPTER_MISMATCH", "The configured adapter is not the adapter the demo configuration names");
  }
  if (adapter.chainId !== input.demo.chainId) {
    fail("CHAIN_MISMATCH", "The connected chain is not the chain the demo configuration names");
  }
  // The signer must be the adapter's own attestor. Derived from the key, compared
  // with the immutable; never the other way round.
  if (getAddress(adapter.attestor) !== getAddress(configuration.signerAddress)) {
    fail("SIGNER_MISMATCH", "The configured bridge attestor key does not match the adapter attestor");
  }
  if (await reader.resultConsumed(`0x${input.release.governedResultDigest.slice("sha256:".length)}`)) {
    fail("RESULT_CONSUMED", "This governed result has already been consumed on-chain");
  }

  // Both participants must pass the adapter's own compliance verifier, on-chain,
  // for the holder role the adapter itself declares.
  for (const [label, holder] of [["holderA", input.demo.holderA], ["holderB", input.demo.holderB]] as const) {
    if (!await reader.isEligible(adapter.cviVerifier, holder, adapter.roleHolder)) {
      fail("PARTICIPANT_INELIGIBLE", `${label} does not pass the adapter compliance verifier`);
    }
  }
  if (getAddress(input.demo.holderA) === getAddress(input.demo.holderB)) {
    fail("PARTICIPANT_DUPLICATE", "The two roles must be held by two different wallets");
  }

  const pins: AdapterPins = {
    address: adapter.address,
    chainId: adapter.chainId,
    assetIdentityDigest: adapter.assetIdentityDigest,
    releaseAuthorityId: adapter.expectedGovernedReleaseAuthorityId,
    releaseMode: adapter.releaseMode,
    circuitHash: adapter.circuitHash,
    parameterFingerprint: adapter.parameterFingerprint,
  };
  assertProductionInterpretation("PINS_GOVERNED_AUTHORITY");
  const problems = reconcileAdapter(input.release, pins, "PINS_GOVERNED_AUTHORITY");
  if (problems.length > 0) {
    fail("ADAPTER_INCOMPATIBLE", `The live adapter cannot consume this governed release: ${problems.join("; ")}`);
  }

  const total = input.demo.payoutA + input.demo.payoutB;
  if (input.release.conflict && total > adapter.availableReserve) {
    fail("INSUFFICIENT_RESERVE", "The configured payouts exceed the adapter available reserve");
  }

  const payload = buildGovernedBridgePayload({
    release: input.release,
    participants: {
      holderA: input.demo.holderA,
      holderB: input.demo.holderB,
      payoutA: input.demo.payoutA,
      payoutB: input.demo.payoutB,
    },
    pins,
    interpretation: "PINS_GOVERNED_AUTHORITY",
    nonce: input.nonce,
    issuedAt: input.issuedAt,
    expiry: input.expiry,
    governedSignatureVerified: input.governedSignatureVerified,
    crossReferencesVerified: input.crossReferencesVerified,
  });

  const typedDataDigest = hashTypedData({
    domain: payload.domain, types: payload.types,
    primaryType: payload.primaryType, message: payload.message,
  });
  // The contract's own view is the authority on the encoding. A disagreement here
  // means the runtime and the deployment do not share a struct, and nothing is signed.
  const onChain = await reader.hashRelease(payload);
  if (onChain.toLowerCase() !== typedDataDigest.toLowerCase()) {
    fail("DIGEST_MISMATCH", "The adapter computes a different digest for this payload");
  }

  return Object.freeze({
    schemaVersion: BRIDGE_EXECUTION_SCHEMA,
    payload,
    typedDataDigest,
    structHash: governedReleaseStructHash(payload),
    intentDigest: intentDigestOf({
      adapter: adapter.address,
      chainId: adapter.chainId,
      typedDataDigest,
      signer: configuration.signerAddress,
      governedResultDigest: payload.message.governedResultDigest,
    }),
    adapter,
    signerAddress: configuration.signerAddress,
  });
}

// ------------------------------------------------------------------ durable record

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

export function bridgeRecordPath(runRoot: string, governedResultDigest: Hex): string {
  return join(runRoot, "bridge", `${governedResultDigest.slice(2)}.json`);
}

export function readBridgeRecord(runRoot: string, governedResultDigest: Hex): BridgeOperationRecord | null {
  const path = bridgeRecordPath(runRoot, governedResultDigest);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as BridgeOperationRecord;
}

// ------------------------------------------------------------------ signing

export type SignedBridge = Readonly<{
  prepared: PreparedBridge;
  signature: Hex;
  record: BridgeOperationRecord;
  /** False when an identical record already existed. */
  newlySigned: boolean;
}>;

export type Signer = (input: Readonly<{
  privateKey: Hex;
  payload: GovernedBridgePayload;
}>) => Promise<Hex>;

export const defaultSigner: Signer = async ({ privateKey, payload }) => (
  privateKeyToAccount(privateKey).signTypedData({
    domain: payload.domain,
    types: payload.types,
    primaryType: payload.primaryType,
    message: payload.message,
  })
);

/**
 * Signs once per governed result, idempotently.
 *
 * The durable record is keyed by the governed result digest, so a retry for the
 * same result must produce the same intent digest. If it does not, something
 * upstream changed and the attempt is refused rather than producing a second,
 * differently-shaped authorization for one outcome.
 */
export async function signBridge(
  configuration: BridgeConfiguration,
  runRoot: string,
  prepared: PreparedBridge,
  now: () => number = () => Math.floor(Date.now() / 1_000),
  signer: Signer = defaultSigner,
): Promise<SignedBridge> {
  const governedResultDigest = prepared.payload.message.governedResultDigest;
  const existing = readBridgeRecord(runRoot, governedResultDigest);
  if (existing !== null) {
    if (existing.intentDigest.toLowerCase() !== prepared.intentDigest.toLowerCase()) {
      fail(
        "CHANGED_PAYLOAD",
        "A different bridge payload was already authorized for this governed result",
      );
    }
    return Object.freeze({ prepared, signature: existing.signature, record: existing, newlySigned: false });
  }

  const signature = await signer({ privateKey: configuration.attestorPrivateKey, payload: prepared.payload });
  if (!/^0x[0-9a-fA-F]{130}$/u.test(signature)) {
    fail("SIGNATURE_FORMAT", "The bridge attestor produced an unexpected signature shape");
  }

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
  // The record carries the signature and the intent, and never the private key.
  writeDurableJsonAtomic(bridgeRecordPath(runRoot, governedResultDigest), record);
  return Object.freeze({ prepared, signature, record, newlySigned: true });
}

// ------------------------------------------------------------------ integration surface

export type BridgeReceipt = Readonly<{
  transactionHash: Hex;
  status: "success" | "reverted";
  runId: Hex;
  conflict: boolean;
  governedResultDigest: Hex;
}>;

/**
 * The typed surface the integration agent drives.
 *
 * `submit` is deliberately inert in this package: it refuses unless the
 * environment explicitly arms it, so no code path here can broadcast by accident.
 */
export type BridgeExecutor = Readonly<{
  prepare: (input: PrepareInput) => Promise<PreparedBridge>;
  simulate: (prepared: PreparedBridge, signature: Hex) => Promise<void>;
  sign: (prepared: PreparedBridge) => Promise<SignedBridge>;
  submit: (signed: SignedBridge) => Promise<never>;
  reconcileReceipt: (signed: SignedBridge, receipt: Readonly<Record<string, unknown>>) => BridgeReceipt;
}>;

export function createBridgeExecutor(options: Readonly<{
  configuration: BridgeConfiguration;
  reader: AdapterReader;
  runRoot: string;
  now?: () => number;
  signer?: Signer;
}>): BridgeExecutor {
  const { configuration, reader, runRoot } = options;
  return Object.freeze({
    prepare: (input) => prepareBridge(configuration, reader, input),
    simulate: async (prepared, signature) => {
      // Simulation runs against the live adapter as the configured attestor, so a
      // revert is discovered before anything is broadcast.
      await reader.simulate(prepared.payload, signature, configuration.signerAddress);
    },
    sign: (prepared) => signBridge(configuration, runRoot, prepared, options.now, options.signer),
    submit: async () => fail(
      "SUBMIT_NOT_ENABLED",
      "This package prepares, simulates and signs only; broadcasting belongs to the integration candidate",
    ),
    reconcileReceipt: (signed, receipt) => {
      const hash = receipt.transactionHash;
      if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(hash)) {
        fail("RECEIPT_HASH", "The receipt does not carry a transaction hash");
      }
      if (receipt.status !== "success" && receipt.status !== "reverted") {
        fail("RECEIPT_STATUS", "The receipt does not carry a known status");
      }
      const to = receipt.to;
      if (typeof to !== "string" || getAddress(to) !== getAddress(signed.record.adapterAddress)) {
        fail("RECEIPT_ADAPTER", "The receipt is not for the configured adapter");
      }
      return Object.freeze({
        transactionHash: hash as Hex,
        status: receipt.status,
        runId: signed.prepared.payload.message.runId,
        conflict: signed.prepared.payload.message.conflict,
        governedResultDigest: signed.record.governedResultDigest,
      });
    },
  });
}
