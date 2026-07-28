import { encodeDeployData, keccak256, type Abi, type Address, type Hex } from "viem";

import { EvidenceRpcError, createHttpRpcTransport, type RpcTransport } from "../evidence/rpc";

/**
 * Monad deployment preflight.
 *
 * Builds the exact creation payload for each contract from the Foundry artifacts and asks the Monad
 * RPC what it would cost and whether it would succeed. Nothing is signed and nothing is broadcast:
 * a successful estimate is not a deployment and must never be reported as one.
 *
 * The evidence gate's transport allowlist is deliberately left untouched. This preflight needs
 * `eth_estimateGas` and `debug_traceCall`, which that gate does not permit, so it declares its own
 * narrower list here rather than widening a security control to fit a new feature.
 */

export const MONAD_TESTNET_CHAIN_ID = 10_143 as const;

/** Ethereum's EIP-170 runtime limit, for the portability comparison. */
export const EIP170_RUNTIME_LIMIT = 24_576 as const;

/** Monad's documented limits: 128 KB of runtime code, 256 KB of init code. */
export const MONAD_RUNTIME_LIMIT = 131_072 as const;
export const MONAD_INIT_CODE_LIMIT = 262_144 as const;

const PREFLIGHT_RPC_METHODS: readonly string[] = Object.freeze([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_call",
  "eth_estimateGas",
  "debug_traceCall",
]);

export class ForbiddenPreflightMethodError extends Error {
  constructor(method: string) {
    super(`Preflight refuses the non read-only method ${method}`);
    this.name = "ForbiddenPreflightMethodError";
  }
}

export class WrongNetworkError extends Error {
  constructor(expected: number, observed: number) {
    super(`BLOCKED — WRONG NETWORK: expected chain ${expected}, RPC answered ${observed}`);
    this.name = "WrongNetworkError";
  }
}

/** Enforces the read-only method set before anything reaches the network. */
export function createPreflightRpcClient(transport: RpcTransport): RpcTransport {
  return async (method, params) => {
    if (!PREFLIGHT_RPC_METHODS.includes(method)) {
      throw new ForbiddenPreflightMethodError(method);
    }
    return transport(method, params);
  };
}

export function createPreflightTransport(rpcUrl: string): RpcTransport {
  return createPreflightRpcClient(createHttpRpcTransport({ url: rpcUrl }));
}

/** Reports the RPC endpoint without its path, so an embedded key never reaches an artifact. */
export function describeRpcEndpoint(rpcUrl: string): string {
  try {
    const url = new URL(rpcUrl);
    const hasCredentialPath = url.pathname.replace(/\/+$/, "").length > 0;
    return `${url.protocol}//${url.host}${hasCredentialPath ? "/[REDACTED PATH]" : ""}`;
  } catch {
    return "[REDACTED ENDPOINT]";
  }
}

export type ArtifactRef = Readonly<{
  key: string;
  file: string;
  name: string;
  /** Constructor arguments, or null when the contract cannot be constructed directly. */
  args: readonly unknown[] | null;
  /** Why those arguments were chosen, so a reviewer can judge the measurement. */
  argumentNote: string;
}>;

export type LoadedArtifact = Readonly<{
  key: string;
  name: string;
  abi: Abi;
  bytecode: Hex;
  deployedBytecode: Hex;
  compiler: string;
}>;

export type PreflightProbe = Readonly<{
  method: string;
  ok: boolean;
  result: string;
  classification: "READ-ONLY RPC SIMULATION" | "RPC METHOD UNSUPPORTED" | "FAILED";
}>;

export type ContractPreflight = Readonly<{
  contract: string;
  constructorArguments: string;
  argumentNote: string;
  initCodeBytes: number;
  runtimeBytes: number;
  initCodeHash: string;
  withinMonadLimit: boolean;
  withinEip170: boolean;
  estimatedGas: string | null;
  probes: readonly PreflightProbe[];
  status: "PASSED" | "FAILED" | "RPC METHOD UNSUPPORTED" | "NOT DIRECTLY CONSTRUCTIBLE";
}>;

function describeError(error: unknown): string {
  if (error instanceof EvidenceRpcError) {
    const data = error.data === null ? "" : ` data=${error.data.slice(0, 74)}`;
    return `${error.message}${data}`.slice(0, 300);
  }
  return (error instanceof Error ? error.message : String(error)).slice(0, 300);
}

function isUnsupported(error: unknown): boolean {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  return message.includes("not supported") || message.includes("method not found")
    || message.includes("unsupported") || message.includes("does not exist");
}

export async function assertMonadTestnet(client: RpcTransport): Promise<number> {
  const raw = await client("eth_chainId", []);
  const observed = Number(BigInt(String(raw)));
  if (observed !== MONAD_TESTNET_CHAIN_ID) {
    throw new WrongNetworkError(MONAD_TESTNET_CHAIN_ID, observed);
  }
  return observed;
}

export async function pinBlock(client: RpcTransport, confirmations = 20n) {
  const head = BigInt(String(await client("eth_blockNumber", [])));
  const number = head > confirmations ? head - confirmations : head;
  const block = await client("eth_getBlockByNumber", [`0x${number.toString(16)}`, false]) as
    { hash?: string } | null;
  if (block === null || typeof block.hash !== "string") {
    throw new EvidenceRpcError("eth_getBlockByNumber returned no block");
  }
  return { number, hash: block.hash, tag: `0x${number.toString(16)}` };
}

/**
 * Runs the creation payload against the RPC. `from` is a plain address used only as the caller of
 * a simulation; no key exists for it and nothing is signed.
 */
export async function preflightContract(
  client: RpcTransport,
  artifact: LoadedArtifact,
  args: readonly unknown[] | null,
  argumentNote: string,
  from: Address,
  blockTag: string,
): Promise<ContractPreflight> {
  const runtimeBytes = (artifact.deployedBytecode.length - 2) / 2;

  if (args === null) {
    return {
      contract: artifact.name,
      constructorArguments: "not directly constructible",
      argumentNote,
      initCodeBytes: (artifact.bytecode.length - 2) / 2,
      runtimeBytes,
      initCodeHash: keccak256(artifact.bytecode),
      withinMonadLimit: runtimeBytes <= MONAD_RUNTIME_LIMIT,
      withinEip170: runtimeBytes <= EIP170_RUNTIME_LIMIT,
      estimatedGas: null,
      probes: [{
        method: "not-attempted",
        ok: false,
        result: argumentNote,
        classification: "FAILED",
      }],
      status: "NOT DIRECTLY CONSTRUCTIBLE",
    };
  }

  const initCode = encodeDeployData({
    abi: artifact.abi,
    bytecode: artifact.bytecode,
    args: args as never,
  });
  const initCodeBytes = (initCode.length - 2) / 2;
  const call = { from, data: initCode };
  const probes: PreflightProbe[] = [];
  let estimatedGas: string | null = null;

  try {
    const raw = await client("eth_estimateGas", [call, blockTag]);
    estimatedGas = BigInt(String(raw)).toString();
    probes.push({
      method: "eth_estimateGas",
      ok: true,
      result: `${estimatedGas} gas`,
      classification: "READ-ONLY RPC SIMULATION",
    });
  } catch (error) {
    probes.push({
      method: "eth_estimateGas",
      ok: false,
      result: describeError(error),
      classification: isUnsupported(error) ? "RPC METHOD UNSUPPORTED" : "FAILED",
    });
  }

  try {
    const raw = String(await client("eth_call", [call, blockTag]));
    const returnedBytes = (raw.length - 2) / 2;
    // A creation call returns the runtime code the constructor would install.
    const matchesRuntime = returnedBytes === runtimeBytes;
    probes.push({
      method: "eth_call",
      ok: true,
      result: `returned ${returnedBytes} bytes of runtime code`
        + `${matchesRuntime ? ", matching the compiled runtime" : ", differing from the compiled runtime"}`,
      classification: "READ-ONLY RPC SIMULATION",
    });
  } catch (error) {
    probes.push({
      method: "eth_call",
      ok: false,
      result: describeError(error),
      classification: isUnsupported(error) ? "RPC METHOD UNSUPPORTED" : "FAILED",
    });
  }

  try {
    await client("debug_traceCall", [call, blockTag, { tracer: "callTracer" }]);
    probes.push({
      method: "debug_traceCall",
      ok: true,
      result: "trace returned",
      classification: "READ-ONLY RPC SIMULATION",
    });
  } catch (error) {
    probes.push({
      method: "debug_traceCall",
      ok: false,
      result: describeError(error),
      classification: isUnsupported(error) ? "RPC METHOD UNSUPPORTED" : "FAILED",
    });
  }

  const business = probes.filter((probe) => probe.method !== "debug_traceCall");
  const status = business.every((probe) => probe.ok)
    ? "PASSED"
    : business.every((probe) => probe.classification === "RPC METHOD UNSUPPORTED")
      ? "RPC METHOD UNSUPPORTED"
      : "FAILED";

  return {
    contract: artifact.name,
    constructorArguments: args.map((value) => String(value)).join(", "),
    argumentNote,
    initCodeBytes,
    runtimeBytes,
    initCodeHash: keccak256(initCode),
    withinMonadLimit: runtimeBytes <= MONAD_RUNTIME_LIMIT
      && initCodeBytes <= MONAD_INIT_CODE_LIMIT,
    withinEip170: runtimeBytes <= EIP170_RUNTIME_LIMIT,
    estimatedGas,
    probes,
    status,
  };
}
