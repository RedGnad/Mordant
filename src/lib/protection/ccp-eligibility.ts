import "server-only";

import { createPublicClient, getAddress, http, parseAbi } from "viem";

/**
 * Cleanverse Compliance Policy eligibility, read directly from Monad testnet.
 *
 * The verdict this returns is the same one the Cleanverse verify API returns, so it is
 * read on-chain rather than through the encrypted API: one RPC call, no shared secret in
 * the request path, and nothing to rotate. The encrypted API stays reserved for the
 * operations that genuinely mutate policy.
 *
 * Every address is pinned here rather than configured, because a mistyped validator or
 * gate would silently answer about a different policy.
 */

export const CCP_CHAIN_ID = 10_143;
export const CCP_VALIDATOR_ADDRESS = "0xaC7e5179C2C7f03f209136886c172eb34F161792";
export const CCP_GATE_ADDRESS = "0x3ffb28a13fd6dc372ae952f15b55263285d5a280";

/** The public UAT holder Cleanverse issued an A-Pass to, offered on the live page. */
export const CCP_PUBLIC_TEST_HOLDER = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";

const VALIDATOR_ABI = parseAbi([
  "function isRegistered(address) view returns (bool)",
  "function complianceVerify(address,address) view returns (bool)",
]);

export type CcpEligibility = Readonly<{
  schemaVersion: "mordant.ccp-eligibility/1";
  chainId: number;
  validatorAddress: string;
  gateAddress: string;
  holderAddress: string;
  eligible: boolean;
  observedBlock: number;
}>;

export type CcpEligibilityCode = "ADDRESS" | "CHAIN" | "GATE" | "UPSTREAM";

/** Only the lookup shape is needed here, not Next's augmented ProcessEnv. */
export type EnvironmentLike = Readonly<Record<string, string | undefined>>;

export class CcpEligibilityError extends Error {
  readonly code: CcpEligibilityCode;
  readonly status: number;

  constructor(code: CcpEligibilityCode, status: number, message: string) {
    super(message);
    this.name = "CcpEligibilityError";
    this.code = code;
    this.status = status;
  }
}

/** Minimal surface this module needs, so a test can drive it without a network. */
export type CcpReader = Readonly<{
  getChainId: () => Promise<number>;
  getBlockNumber: () => Promise<bigint>;
  isRegistered: (gate: `0x${string}`) => Promise<boolean>;
  complianceVerify: (gate: `0x${string}`, holder: `0x${string}`) => Promise<boolean>;
}>;

export function readCcpRpcUrl(environment: EnvironmentLike = process.env): string {
  const url = environment.MORDANT_MONAD_RPC_URL ?? environment.MONAD_RPC_URL;
  if (typeof url !== "string" || url.trim() === "") {
    throw new CcpEligibilityError("UPSTREAM", 503, "Compliance checking is not configured");
  }
  let parsed: URL;
  try {
    parsed = new URL(url.trim());
  } catch {
    throw new CcpEligibilityError("UPSTREAM", 503, "Compliance checking is not configured");
  }
  if (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    throw new CcpEligibilityError("UPSTREAM", 503, "Compliance checking is not configured");
  }
  return parsed.toString();
}

export function createCcpReader(environment: EnvironmentLike = process.env): CcpReader {
  const client = createPublicClient({ transport: http(readCcpRpcUrl(environment)) });
  return {
    getChainId: () => client.getChainId(),
    getBlockNumber: () => client.getBlockNumber(),
    isRegistered: (gate) =>
      client.readContract({ address: CCP_VALIDATOR_ADDRESS, abi: VALIDATOR_ABI, functionName: "isRegistered", args: [gate] }),
    complianceVerify: (gate, holder) =>
      client.readContract({ address: CCP_VALIDATOR_ADDRESS, abi: VALIDATOR_ABI, functionName: "complianceVerify", args: [gate, holder] }),
  };
}

/** Normalizes to a checksummed address, refusing anything that is not one. */
export function normalizeHolderAddress(candidate: unknown): `0x${string}` {
  if (typeof candidate !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(candidate.trim())) {
    throw new CcpEligibilityError("ADDRESS", 400, "Enter a valid 0x wallet address.");
  }
  try {
    return getAddress(candidate.trim());
  } catch {
    throw new CcpEligibilityError("ADDRESS", 400, "Enter a valid 0x wallet address.");
  }
}

export async function verifyCcpEligibility(
  holderCandidate: unknown,
  reader: CcpReader,
): Promise<CcpEligibility> {
  const holderAddress = normalizeHolderAddress(holderCandidate);

  let chainId: number;
  try {
    chainId = await reader.getChainId();
  } catch {
    // Never surface the upstream error: it can carry the RPC URL and provider detail.
    throw new CcpEligibilityError("UPSTREAM", 503, "The compliance network is unreachable right now.");
  }
  if (chainId !== CCP_CHAIN_ID) {
    throw new CcpEligibilityError("CHAIN", 503, "The compliance network is unavailable right now.");
  }

  let eligible: boolean;
  let observedBlock: bigint;
  try {
    const registered = await reader.isRegistered(CCP_GATE_ADDRESS);
    if (registered !== true) {
      throw new CcpEligibilityError("GATE", 503, "The compliance policy is unavailable right now.");
    }
    eligible = await reader.complianceVerify(CCP_GATE_ADDRESS, holderAddress);
    observedBlock = await reader.getBlockNumber();
  } catch (error) {
    if (error instanceof CcpEligibilityError) throw error;
    throw new CcpEligibilityError("UPSTREAM", 503, "The compliance network is unreachable right now.");
  }

  return Object.freeze({
    schemaVersion: "mordant.ccp-eligibility/1" as const,
    chainId: CCP_CHAIN_ID,
    validatorAddress: CCP_VALIDATOR_ADDRESS,
    gateAddress: CCP_GATE_ADDRESS,
    holderAddress,
    eligible: eligible === true,
    observedBlock: Number(observedBlock),
  });
}
