// The bounded relayer process.
//
// The relayer publishes the opaque session commitment. That is the entire job.
// It must never learn the intent, the signatures, the salt, the scopes, the
// controllers or the source records, because knowing any of them would let the
// party that publishes the session identify its participants, which is the
// property the opaque commitment exists to provide.
//
// So the boundary is an object, not a convention. The runner holds a handle
// that accepts exactly two values and exposes exactly one method. There is no
// field on it that could carry an intent, and no method that could carry
// arbitrary calldata.
import { encodeFunctionData, getAddress, toFunctionSelector } from "viem";

/// The one selector this process will ever produce.
export const COMMIT_SESSION_SIGNATURE = "commitSession(bytes32,bytes32)";
export const COMMIT_SESSION_SELECTOR = toFunctionSelector(COMMIT_SESSION_SIGNATURE);

/// Bounds the relayer accepts. A request outside them is refused locally,
/// before signing, so a compromised runner cannot drain the relayer through
/// gas.
export const RELAY_MAX_GAS = 500_000n;
export const RELAY_MAX_FEE_WEI = 500_000_000_000n;

export class RelayerRefused extends Error {
  constructor(code, detail) {
    super(`RELAYER_REFUSED_${code}${detail ? `: ${detail}` : ""}`);
    this.code = `RELAYER_REFUSED_${code}`;
    this.name = "RelayerRefused";
  }
}

/// Fields whose presence in a request is, by itself, a protocol violation.
///
/// The relayer does not merely ignore them: it refuses, because a runner that
/// sent one is a runner that believes the relayer should see it, and that
/// belief needs to fail loudly rather than silently.
const FORBIDDEN_KEYS = Object.freeze([
  "intent", "signatures", "signature", "salt", "sessionSalt", "scopes", "scopeCommitmentA",
  "scopeCommitmentB", "controllers", "controllerA", "controllerB", "sourceRecordCommitmentA",
  "sourceRecordCommitmentB", "sourceRecords", "governanceRecordA", "governanceRecordB",
  "anchor", "vault", "calldata", "data", "to", "target", "value", "selector", "method",
  "abi", "functionName", "args",
]);

/// Creates a relayer process bound to one registry on one chain.
///
/// `account` is the relayer's own signer. It is a closure variable: nothing
/// returned from this function exposes it, so the runner holding the handle
/// cannot read the key, enumerate it, or ask it to sign anything else.
export function createRelayerProcess({
  account, client, walletFor, registry, chainId, sourcesAbi, governanceAbi,
  maxGas = RELAY_MAX_GAS, maxFeeWei = RELAY_MAX_FEE_WEI, broadcast,
}) {
  const boundRegistry = getAddress(registry);
  const boundChainId = Number(chainId);

  async function publishSessionCommitment(request) {
    if (request === null || typeof request !== "object" || Array.isArray(request)) {
      throw new RelayerRefused("MALFORMED_REQUEST", typeof request);
    }
    // Refuse anything beyond the two values this process is allowed to see.
    const keys = Object.keys(request);
    for (const key of keys) {
      if (FORBIDDEN_KEYS.includes(key)) {
        throw new RelayerRefused("FORBIDDEN_FIELD", key);
      }
    }
    const permitted = ["chainId", "sessionCommitment", "sessionNullifier"];
    const unexpected = keys.filter((key) => !permitted.includes(key));
    if (unexpected.length > 0) {
      throw new RelayerRefused("UNEXPECTED_FIELD", unexpected.join(", "));
    }
    const { chainId: requestChainId, sessionCommitment, sessionNullifier } = request;

    if (Number(requestChainId) !== boundChainId) {
      throw new RelayerRefused("WRONG_CHAIN", `${requestChainId} != ${boundChainId}`);
    }
    for (const [name, value] of [["sessionCommitment", sessionCommitment], ["sessionNullifier", sessionNullifier]]) {
      if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
        throw new RelayerRefused("MALFORMED_VALUE", name);
      }
    }

    // Everything below is verified by the relayer itself, locally, against the
    // chain. It does not trust the runner for any of it.
    const liveChainId = await client.getChainId();
    if (liveChainId !== boundChainId) {
      throw new RelayerRefused("RPC_CHAIN_MISMATCH", `${liveChainId} != ${boundChainId}`);
    }
    const authorized = await client.readContract({
      address: boundRegistry, abi: governanceAbi, functionName: "authorizedRelayer",
      args: [account.address],
    });
    if (!authorized) throw new RelayerRefused("NOT_AUTHORIZED", account.address);

    const existing = await client.readContract({
      address: boundRegistry, abi: governanceAbi, functionName: "commitment",
      args: [sessionCommitment],
    });
    if (existing?.exists) {
      throw new RelayerRefused("ALREADY_PUBLISHED", sessionCommitment);
    }

    // The relayer constructs its own calldata. It never accepts calldata.
    const data = encodeFunctionData({
      abi: governanceAbi, functionName: "commitSession",
      args: [sessionCommitment, sessionNullifier],
    });
    if (!data.startsWith(COMMIT_SESSION_SELECTOR)) {
      throw new RelayerRefused("SELECTOR_MISMATCH", data.slice(0, 10));
    }

    const gas = await client.estimateGas({
      account: account.address, to: boundRegistry, data, value: 0n,
    });
    const bounded = (gas * 130n) / 100n;
    if (bounded > maxGas) throw new RelayerRefused("GAS_CEILING", `${bounded} > ${maxGas}`);

    const block = await client.getBlock();
    const base = block.baseFeePerGas ?? 1_000_000_000n;
    const maxFeePerGas = base * 2n + 1_000_000_000n;
    if (maxFeePerGas > maxFeeWei) {
      throw new RelayerRefused("FEE_CEILING", `${maxFeePerGas} > ${maxFeeWei}`);
    }

    const hash = await broadcast("relayer commitSession", async () =>
      walletFor(account).sendTransaction({
        account, to: boundRegistry, data, value: 0n, gas: bounded,
        maxFeePerGas, maxPriorityFeePerGas: 1_000_000_000n,
      }));

    const receipt = await client.waitForTransactionReceipt({ hash });
    // Public status only. No calldata, no signature, no internal state.
    return Object.freeze({
      transactionHash: hash,
      status: receipt.status,
      blockNumber: Number(receipt.blockNumber),
      blockHash: receipt.blockHash,
      gasUsed: String(receipt.gasUsed),
    });
  }

  // The handle. One method, and an address for the runner to authorize.
  return Object.freeze({
    address: account.address,
    registry: boundRegistry,
    chainId: boundChainId,
    publishSessionCommitment,
  });
}
