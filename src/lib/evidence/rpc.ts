/**
 * A deliberately crippled JSON-RPC client: it can only read. Write methods are rejected before
 * the request is built, so an evidence run cannot change public state even by mistake.
 */

export type RpcParams = readonly unknown[];

export type RpcTransport = (method: string, params: RpcParams) => Promise<unknown>;

/** Every method an evidence run is allowed to issue. */
export const READ_ONLY_RPC_METHODS: readonly string[] = Object.freeze([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_call",
  "eth_getBalance",
  "net_version",
]);

/**
 * Methods that would sign, broadcast or mutate chain state. Listed explicitly so the failure
 * message names the reason rather than "unknown method".
 */
const FORBIDDEN_RPC_METHOD_PATTERNS: readonly RegExp[] = Object.freeze([
  /^eth_send/i,
  /^eth_sign/i,
  /^personal_/i,
  /^eth_accounts$/i,
  /^(anvil|hardhat|evm|tenderly)_/i,
  /^debug_/i,
  /^miner_/i,
  /^admin_/i,
]);

export class ForbiddenRpcMethodError extends Error {
  readonly method: string;

  constructor(method: string) {
    super(`Refusing a non read-only JSON-RPC method: ${method}`);
    this.name = "ForbiddenRpcMethodError";
    this.method = method;
  }
}

export class EvidenceRpcError extends Error {
  /** Raw revert payload, when the node returned one. Carries the custom-error selector. */
  readonly data: string | null;

  constructor(message: string, data: string | null = null) {
    super(message);
    this.name = "EvidenceRpcError";
    this.data = data;
  }
}

export function assertReadOnlyRpcMethod(method: string): void {
  if (FORBIDDEN_RPC_METHOD_PATTERNS.some((pattern) => pattern.test(method))) {
    throw new ForbiddenRpcMethodError(method);
  }
  if (!READ_ONLY_RPC_METHODS.includes(method)) {
    throw new ForbiddenRpcMethodError(method);
  }
}

/**
 * Wraps any transport so the allowlist is enforced before the underlying transport is reached.
 * This is the only transport the evidence pipeline is allowed to consume.
 */
export function createReadOnlyRpcClient(transport: RpcTransport): RpcTransport {
  return async (method, params) => {
    assertReadOnlyRpcMethod(method);
    return transport(method, params);
  };
}

export type HttpRpcTransportOptions = Readonly<{
  url: string;
  fetchImplementation?: typeof fetch;
  timeoutMilliseconds?: number;
}>;

export function createHttpRpcTransport(options: HttpRpcTransportOptions): RpcTransport {
  const fetchImplementation = options.fetchImplementation ?? fetch;
  const timeoutMilliseconds = options.timeoutMilliseconds ?? 30_000;
  let requestId = 0;

  return async (method, params) => {
    requestId += 1;
    const response = await fetchImplementation(options.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
      signal: AbortSignal.timeout(timeoutMilliseconds),
    });

    if (!response.ok) {
      throw new EvidenceRpcError(`RPC ${method} failed with HTTP ${response.status}`);
    }

    const payload: unknown = await response.json();
    if (typeof payload !== "object" || payload === null) {
      throw new EvidenceRpcError(`RPC ${method} returned a malformed envelope`);
    }
    if ("error" in payload) {
      const error = (payload as { error: unknown }).error;
      const message = typeof error === "object" && error !== null && "message" in error
        ? String((error as { message: unknown }).message)
        : "unknown RPC error";
      // A revert payload is evidence in itself: it names the custom error the contract raised.
      const data = typeof error === "object" && error !== null && "data" in error
        && typeof (error as { data: unknown }).data === "string"
        ? (error as { data: string }).data
        : null;
      throw new EvidenceRpcError(`RPC ${method} returned an error: ${message}`, data);
    }
    if (!("result" in payload)) {
      throw new EvidenceRpcError(`RPC ${method} returned no result`);
    }
    return (payload as { result: unknown }).result;
  };
}

function expectHexString(value: unknown, method: string): `0x${string}` {
  if (typeof value !== "string" || !value.startsWith("0x")) {
    throw new EvidenceRpcError(`RPC ${method} returned a non-hex result`);
  }
  return value as `0x${string}`;
}

export async function rpcChainId(client: RpcTransport): Promise<number> {
  return Number(BigInt(expectHexString(await client("eth_chainId", []), "eth_chainId")));
}

export async function rpcBlockNumber(client: RpcTransport): Promise<bigint> {
  return BigInt(expectHexString(await client("eth_blockNumber", []), "eth_blockNumber"));
}

export async function rpcBlockHash(client: RpcTransport, blockNumber: bigint): Promise<`0x${string}`> {
  const block: unknown = await client("eth_getBlockByNumber", [`0x${blockNumber.toString(16)}`, false]);
  if (typeof block !== "object" || block === null || !("hash" in block)) {
    throw new EvidenceRpcError("eth_getBlockByNumber returned no block");
  }
  return expectHexString((block as { hash: unknown }).hash, "eth_getBlockByNumber");
}

export async function rpcGetCode(
  client: RpcTransport,
  address: string,
  blockNumber: bigint,
): Promise<`0x${string}`> {
  return expectHexString(
    await client("eth_getCode", [address, `0x${blockNumber.toString(16)}`]),
    "eth_getCode",
  );
}

export async function rpcGetStorageAt(
  client: RpcTransport,
  address: string,
  slot: string,
  blockNumber: bigint,
): Promise<`0x${string}`> {
  return expectHexString(
    await client("eth_getStorageAt", [address, slot, `0x${blockNumber.toString(16)}`]),
    "eth_getStorageAt",
  );
}

/** A non-view target reached this way is a READ-ONLY SIMULATION, never a live transaction. */
export async function rpcCall(
  client: RpcTransport,
  to: string,
  data: string,
  blockNumber: bigint,
): Promise<`0x${string}`> {
  return expectHexString(
    await client("eth_call", [{ to, data }, `0x${blockNumber.toString(16)}`]),
    "eth_call",
  );
}
