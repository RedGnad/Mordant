import { decodeFunctionResult, encodeFunctionData, keccak256, type Abi } from "viem";

import {
  EvidenceRpcError,
  rpcBlockHash,
  rpcBlockNumber,
  rpcCall,
  rpcChainId,
  rpcGetCode,
  rpcGetStorageAt,
  type RpcTransport,
} from "./rpc";

/**
 * Honesty classes for a piece of evidence. A simulated call is READ-ONLY, a local fork is FORK,
 * and neither may ever be reported as LIVE.
 */
export const EVIDENCE_CLASSIFICATIONS = [
  "LIVE",
  "TRANSACTION CLEANVERSE",
  "READ-ONLY",
  "FORK",
  "PROTOCOL DOUBLE",
  "SYNTHETIC",
  "STORYBOARD",
  "BLOCKED",
  "NOT PROVEN",
] as const;

export type EvidenceClassification = (typeof EVIDENCE_CLASSIFICATIONS)[number];

export type PinnedBlock = Readonly<{
  network: string;
  chainId: number;
  blockNumber: bigint;
  blockHash: `0x${string}`;
}>;

export type OnchainObservation = Readonly<{
  network: string;
  chainId: number;
  blockNumber: string;
  blockHash: string;
  address: string;
  implementation: string | null;
  codeHash: string | null;
  callOrSelector: string;
  result: string;
  classification: EvidenceClassification;
}>;

/** EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1. */
export const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

/** EIP-1967 beacon slot: keccak256("eip1967.proxy.beacon") - 1. */
export const EIP1967_BEACON_SLOT =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50" as const;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export class WrongNetworkError extends Error {
  readonly expectedChainId: number;
  readonly observedChainId: number;

  constructor(expectedChainId: number, observedChainId: number) {
    super(
      `BLOCKED — WRONG NETWORK: expected chain ${expectedChainId}, RPC answered ${observedChainId}`,
    );
    this.name = "WrongNetworkError";
    this.expectedChainId = expectedChainId;
    this.observedChainId = observedChainId;
  }
}

/**
 * The network gate. Nothing else may be read until the RPC proves which chain it serves.
 */
export async function assertExpectedChain(
  client: RpcTransport,
  expectedChainId: number,
): Promise<number> {
  const observed = await rpcChainId(client);
  if (observed !== expectedChainId) {
    throw new WrongNetworkError(expectedChainId, observed);
  }
  return observed;
}

/**
 * Pins one block for the whole run so every reading describes a single, citable chain state.
 * @param confirmations how far behind the head to pin, so a reorg cannot invalidate the report
 */
export async function pinBlock(
  client: RpcTransport,
  network: string,
  chainId: number,
  confirmations = 20n,
): Promise<PinnedBlock> {
  const head = await rpcBlockNumber(client);
  const blockNumber = head > confirmations ? head - confirmations : head;
  const blockHash = await rpcBlockHash(client, blockNumber);
  return Object.freeze({ network, chainId, blockNumber, blockHash });
}

function storageSlotToAddress(word: string): string | null {
  if (word.length < 42) {
    return null;
  }
  const address = `0x${word.slice(-40)}`;
  return address.toLowerCase() === ZERO_ADDRESS ? null : address;
}

export type DeployedCode = Readonly<{
  address: string;
  hasBytecode: boolean;
  byteLength: number;
  codeHash: string | null;
  implementation: string | null;
  beacon: string | null;
  implementationCode: string | null;
  implementationCodeHash: string | null;
}>;

/**
 * Reads bytecode, its hash, and any EIP-1967 proxy target. A proxy without an implementation
 * is reported as such rather than silently treated as a plain contract.
 */
export async function observeDeployedCode(
  client: RpcTransport,
  address: string,
  block: PinnedBlock,
): Promise<DeployedCode> {
  const code = await rpcGetCode(client, address, block.blockNumber);
  const hasBytecode = code !== "0x" && code.length > 2;

  if (!hasBytecode) {
    return Object.freeze({
      address,
      hasBytecode: false,
      byteLength: 0,
      codeHash: null,
      implementation: null,
      beacon: null,
      implementationCode: null,
      implementationCodeHash: null,
    });
  }

  const implementationSlot = await rpcGetStorageAt(
    client,
    address,
    EIP1967_IMPLEMENTATION_SLOT,
    block.blockNumber,
  );
  const beaconSlot = await rpcGetStorageAt(
    client,
    address,
    EIP1967_BEACON_SLOT,
    block.blockNumber,
  );
  const implementation = storageSlotToAddress(implementationSlot);
  const implementationCode = implementation === null
    ? null
    : await rpcGetCode(client, implementation, block.blockNumber);

  return Object.freeze({
    address,
    hasBytecode: true,
    byteLength: (code.length - 2) / 2,
    codeHash: keccak256(code as `0x${string}`),
    implementation,
    beacon: storageSlotToAddress(beaconSlot),
    implementationCode,
    implementationCodeHash: implementationCode === null || implementationCode === "0x"
      ? null
      : keccak256(implementationCode as `0x${string}`),
  });
}

export function functionSelector(signature: string): `0x${string}` {
  return keccak256(new TextEncoder().encode(signature)).slice(0, 10) as `0x${string}`;
}

/**
 * Looks for a `PUSH4 <selector>` sequence in runtime bytecode. This is a dispatch-table scan,
 * not a proof of callability, and callers must classify it as such.
 */
export function bytecodeContainsSelector(code: string, selector: string): boolean {
  const normalized = selector.toLowerCase().replace(/^0x/, "");
  if (normalized.length !== 8) {
    throw new Error(`Expected a 4-byte selector, received "${selector}"`);
  }
  return code.toLowerCase().includes(`63${normalized}`);
}

export type ViewCallOutcome = Readonly<{
  signature: string;
  selector: string;
  ok: boolean;
  value: string;
  /** Custom-error selector when the call reverted with data. */
  revertSelector: string | null;
}>;

/**
 * Revert selectors worth naming in a report. A reverting policy is not a broken surface: it is
 * the contract answering "no" in a way a boolean return cannot express.
 */
const KNOWN_REVERT_SELECTORS: Readonly<Record<string, string>> = Object.freeze({
  "0x8a4e1859": "ComplianceFailed(address)",
  "0x08c379a0": "Error(string)",
  "0x4e487b71": "Panic(uint256)",
});

export function describeRevertSelector(selector: string | null): string {
  if (selector === null) {
    return "no revert data";
  }
  const known = KNOWN_REVERT_SELECTORS[selector.toLowerCase()];
  return known === undefined ? `custom error ${selector}` : `${known} [${selector}]`;
}

export type ParsedSignature = Readonly<{
  name: string;
  /** Canonical form used to derive the selector, e.g. `isValidAPass(address)`. */
  canonical: string;
  abi: Abi;
}>;

const SIGNATURE_PATTERN =
  /^\s*(\w+)\s*\(([^)]*)\)\s*(?:(?:view|pure|nonpayable|payable)\s*)*(?:returns\s*\(([^)]*)\))?\s*$/;

/**
 * Parses a human-readable signature at runtime. viem's `parseAbi` needs literal types, which a
 * data-driven observation plan cannot provide.
 */
export function parseViewSignature(signature: string): ParsedSignature {
  const match = SIGNATURE_PATTERN.exec(signature);
  if (match === null) {
    throw new Error(`Unsupported function signature: "${signature}"`);
  }
  const [, name, rawInputs, rawOutputs] = match;
  const split = (raw: string | undefined): readonly string[] =>
    (raw ?? "").split(",").map((part) => part.trim()).filter((part) => part.length !== 0);

  const inputs = split(rawInputs).map((type, index) => ({ name: `arg${index}`, type }));
  const outputs = split(rawOutputs).map((type, index) => ({ name: `out${index}`, type }));

  return Object.freeze({
    name,
    canonical: `${name}(${inputs.map((input) => input.type).join(",")})`,
    abi: [{ type: "function", name, inputs, outputs, stateMutability: "view" }] as Abi,
  });
}

/**
 * Calls one view function at the pinned block. A revert is recorded as an outcome, not thrown:
 * "this deployment refuses that surface" is itself evidence.
 */
export async function observeViewCall(
  client: RpcTransport,
  address: string,
  signature: string,
  args: readonly unknown[],
  block: PinnedBlock,
): Promise<ViewCallOutcome> {
  const { name, canonical, abi } = parseViewSignature(signature);
  const selector = functionSelector(canonical);

  try {
    const data = encodeFunctionData({ abi, functionName: name, args: args as readonly unknown[] });
    const raw = await rpcCall(client, address, data, block.blockNumber);
    const decoded: unknown = decodeFunctionResult({ abi, functionName: name, data: raw });
    return Object.freeze({
      signature,
      selector,
      ok: true,
      value: Array.isArray(decoded)
        ? decoded.map((item) => String(item)).join(", ")
        : String(decoded),
      revertSelector: null,
    });
  } catch (error) {
    const revertData = error instanceof EvidenceRpcError ? error.data : null;
    const revertSelector = revertData !== null && revertData.length >= 10
      ? revertData.slice(0, 10)
      : null;
    return Object.freeze({
      signature,
      selector,
      ok: false,
      value: revertSelector === null
        ? `call failed without revert data (${error instanceof Error ? error.name : "unknown"})`
        : `reverted with ${describeRevertSelector(revertSelector)}`,
      revertSelector,
    });
  }
}
