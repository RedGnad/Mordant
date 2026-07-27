import { z } from "zod";

import type { CleanverseMonadTargets } from "./cleanverse-monad";

/**
 * Parses the unauthenticated Cleanverse chain configuration into Mordant's target addresses.
 *
 * Every address in that payload is a plain hex string, so a mis-mapped key produces a report that
 * looks perfectly well-formed while naming the wrong contract. Each role is therefore bound to
 * exactly one source key, and the parser refuses a payload that would let two roles collapse onto
 * the same address.
 */

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/, "Expected a 20-byte hex address");
const optionalAddressSchema = z.union([addressSchema, z.literal("")]);

const tokenSchema = z.object({
  symbol: z.string(),
  /** The A-Token or origin token contract. Never the AccessCore address. */
  token_address: addressSchema,
  decimals: z.number().int(),
  /** "atoken" for a wrapped/issued A-Token, "token" for the origin asset. */
  token_category: z.string(),
  /** The AccessCore custody contract for this token. Never the token itself. */
  access_core: optionalAddressSchema.optional(),
  deposit_gateway: optionalAddressSchema.optional(),
});

const chainSchema = z.object({
  chain: z.string(),
  chain_id: z.number().int(),
  /** Chain-level A-Pass registry. Never a token address. */
  apass_address: addressSchema,
  tokens: z.array(tokenSchema),
});

export const chainConfigSchema = z.object({
  code: z.string(),
  data: z.object({ chains: z.array(chainSchema) }),
});

export type ChainConfigToken = z.output<typeof tokenSchema>;

export class ChainConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainConfigError";
  }
}

/** Roles Mordant resolves from the configuration, each bound to one and only one source key. */
export const CHAIN_CONFIG_ROLE_SOURCES = Object.freeze({
  apass: "chain.apass_address",
  usdc: 'tokens[symbol="usdc"].token_address',
  aUsdc: 'tokens[symbol="ausdc"].token_address',
  accessCore: 'tokens[symbol="ausdc"].access_core',
  depositGateway: 'tokens[symbol="ausdc"].deposit_gateway',
});

export type ResolvedChainTargets = Readonly<{
  chainId: number;
  apass: string;
  usdc: string;
  aUsdc: string;
  accessCore: string;
  depositGateway: string;
  aUsdcDecimals: number;
}>;

function requireToken(
  tokens: readonly ChainConfigToken[],
  symbol: string,
  expectedCategory: string,
): ChainConfigToken {
  const matches = tokens.filter(
    (token) => token.symbol.toLowerCase() === symbol.toLowerCase(),
  );
  if (matches.length === 0) {
    throw new ChainConfigError(`Chain configuration has no "${symbol}" token entry`);
  }
  if (matches.length > 1) {
    throw new ChainConfigError(`Chain configuration has ${matches.length} "${symbol}" entries`);
  }
  const token = matches[0];
  if (token.token_category !== expectedCategory) {
    throw new ChainConfigError(
      `"${symbol}" is category "${token.token_category}", expected "${expectedCategory}"`,
    );
  }
  return token;
}

/**
 * @param payload the raw `GET /api/skills/query_chain_config` body
 * @param chainSlug the chain to resolve, e.g. "monad"
 */
export function resolveChainTargets(payload: unknown, chainSlug: string): ResolvedChainTargets {
  const parsed = chainConfigSchema.safeParse(payload);
  if (!parsed.success) {
    throw new ChainConfigError("Chain configuration payload is malformed");
  }

  const chain = parsed.data.data.chains.find(
    (candidate) => candidate.chain.toLowerCase() === chainSlug.toLowerCase(),
  );
  if (chain === undefined) {
    throw new ChainConfigError(`Chain configuration has no "${chainSlug}" entry`);
  }

  const usdc = requireToken(chain.tokens, "usdc", "token");
  const aUsdc = requireToken(chain.tokens, "ausdc", "atoken");

  // AccessCore is a custody contract published ALONGSIDE the token, never in token_address.
  const accessCore = aUsdc.access_core ?? "";
  if (accessCore === "") {
    throw new ChainConfigError("aUSDC entry publishes no access_core address");
  }
  const depositGateway = aUsdc.deposit_gateway ?? "";
  if (depositGateway === "") {
    throw new ChainConfigError("aUSDC entry publishes no deposit_gateway address");
  }

  const resolved: ResolvedChainTargets = Object.freeze({
    chainId: chain.chain_id,
    apass: chain.apass_address,
    usdc: usdc.token_address,
    aUsdc: aUsdc.token_address,
    accessCore,
    depositGateway,
    aUsdcDecimals: aUsdc.decimals,
  });

  assertDistinctRoles(resolved);
  return resolved;
}

/**
 * Fails closed when two roles resolve to the same address. Without this, an upstream payload that
 * repeats one address under two keys would silently produce a report naming the wrong contract.
 */
export function assertDistinctRoles(targets: ResolvedChainTargets): void {
  const roles: readonly (readonly [string, string])[] = [
    ["apass", targets.apass],
    ["usdc", targets.usdc],
    ["aUsdc", targets.aUsdc],
    ["accessCore", targets.accessCore],
    ["depositGateway", targets.depositGateway],
  ];

  const seen = new Map<string, string>();
  for (const [role, address] of roles) {
    const normalized = address.toLowerCase();
    const previous = seen.get(normalized);
    if (previous !== undefined) {
      throw new ChainConfigError(
        `Roles "${previous}" and "${role}" resolve to the same address; refusing an ambiguous map`,
      );
    }
    seen.set(normalized, role);
  }
}

/**
 * Cross-checks resolved configuration against the addresses compiled into the evidence gate.
 * Returns the roles that disagree, so a silent upstream change is visible instead of assumed.
 */
export function diffAgainstConfiguredTargets(
  resolved: ResolvedChainTargets,
  configured: CleanverseMonadTargets,
): readonly string[] {
  const pairs: readonly (readonly [string, string, string])[] = [
    ["apass", resolved.apass, configured.apass],
    ["usdc", resolved.usdc, configured.usdc],
    ["aUsdc", resolved.aUsdc, configured.aUsdc],
    ["accessCore", resolved.accessCore, configured.accessCore],
    ["depositGateway", resolved.depositGateway, configured.depositGateway],
  ];

  return Object.freeze(
    pairs
      .filter(([, left, right]) => left.toLowerCase() !== right.toLowerCase())
      .map(([role]) => role),
  );
}
