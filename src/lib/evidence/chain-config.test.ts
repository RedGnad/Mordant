import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ChainConfigError,
  assertDistinctRoles,
  diffAgainstConfiguredTargets,
  resolveChainTargets,
} from "./chain-config";
import { DEFAULT_CLEANVERSE_MONAD_TARGETS } from "./cleanverse-monad";

/**
 * Shape recorded from the unauthenticated `GET /api/skills/query_chain_config` response for Monad.
 * Only the fields the parser consumes are kept; no rpc_url is stored, because that field carries a
 * third-party provider key upstream.
 */
const MONAD_CONFIG = Object.freeze({
  code: "0000",
  data: {
    chains: [
      {
        chain: "base",
        chain_id: 84_532,
        apass_address: "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9",
        tokens: [
          {
            symbol: "usdc",
            token_address: "0x543b96420d072BF587B63C41C0B0922762E986Ce",
            decimals: 6,
            token_category: "token",
            access_core: "",
            deposit_gateway: "",
          },
        ],
      },
      {
        chain: "monad",
        chain_id: 10_143,
        apass_address: "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9",
        tokens: [
          {
            symbol: "usdc",
            token_address: "0x534b2f3A21130d7a60830c2Df862319e593943A3",
            decimals: 6,
            token_category: "token",
            access_core: "",
            deposit_gateway: "",
          },
          {
            symbol: "ausdc",
            token_address: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
            decimals: 6,
            token_category: "atoken",
            access_core: "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC",
            deposit_gateway: "0x8e084646080a35347B2D053Dd72F550f12245c8B",
          },
        ],
      },
    ],
  },
});

// Every address in the payload is an indistinguishable hex string. A swapped key would produce a
// report that names the wrong contract while looking perfectly well-formed.
test("the A-Token field becomes aUSDC and access_core becomes AccessCore", () => {
  const resolved = resolveChainTargets(MONAD_CONFIG, "monad");

  assert.equal(resolved.chainId, 10_143);
  assert.equal(resolved.aUsdc, "0xaC0893567D43C3E7e6e35a72803df05416C1f20D");
  assert.equal(resolved.accessCore, "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC");
  assert.equal(resolved.usdc, "0x534b2f3A21130d7a60830c2Df862319e593943A3");
  assert.equal(resolved.depositGateway, "0x8e084646080a35347B2D053Dd72F550f12245c8B");
  assert.equal(resolved.apass, "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9");
  assert.equal(resolved.aUsdcDecimals, 6);

  // The two most confusable roles must never hold each other's value.
  assert.notEqual(resolved.aUsdc, resolved.accessCore);
  assert.notEqual(resolved.aUsdc.toLowerCase(), resolved.accessCore.toLowerCase());
});

test("the resolved map matches the addresses compiled into the evidence gate", () => {
  const resolved = resolveChainTargets(MONAD_CONFIG, "monad");
  assert.deepEqual(
    diffAgainstConfiguredTargets(resolved, DEFAULT_CLEANVERSE_MONAD_TARGETS),
    [],
    "configured targets drifted from the published chain configuration",
  );
});

test("a swapped access_core is detected instead of silently accepted", () => {
  const resolved = resolveChainTargets(MONAD_CONFIG, "monad");
  const swapped = {
    ...DEFAULT_CLEANVERSE_MONAD_TARGETS,
    aUsdc: DEFAULT_CLEANVERSE_MONAD_TARGETS.accessCore,
    accessCore: DEFAULT_CLEANVERSE_MONAD_TARGETS.aUsdc,
  };
  assert.deepEqual(diffAgainstConfiguredTargets(resolved, swapped), ["aUsdc", "accessCore"]);
});

test("one address cannot fill two roles", () => {
  assert.throws(
    () => assertDistinctRoles({
      chainId: 10_143,
      apass: "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9",
      usdc: "0x534b2f3A21130d7a60830c2Df862319e593943A3",
      // AccessCore repeated as the token address: exactly the inversion this guard exists for.
      aUsdc: "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC",
      accessCore: "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC",
      depositGateway: "0x8e084646080a35347B2D053Dd72F550f12245c8B",
      aUsdcDecimals: 6,
    }),
    (error: unknown) => {
      assert.ok(error instanceof ChainConfigError);
      assert.match(error.message, /same address/);
      return true;
    },
  );
});

test("the aUSDC role refuses an entry that is not an A-Token", () => {
  const miscategorised = {
    ...MONAD_CONFIG,
    data: {
      chains: MONAD_CONFIG.data.chains.map((chain) => chain.chain !== "monad" ? chain : {
        ...chain,
        tokens: chain.tokens.map((token) => token.symbol !== "ausdc"
          ? token
          : { ...token, token_category: "token" }),
      }),
    },
  };
  assert.throws(() => resolveChainTargets(miscategorised, "monad"), /expected "atoken"/);
});

test("a missing access_core is an error, never an empty address", () => {
  const withoutAccessCore = {
    ...MONAD_CONFIG,
    data: {
      chains: MONAD_CONFIG.data.chains.map((chain) => chain.chain !== "monad" ? chain : {
        ...chain,
        tokens: chain.tokens.map((token) => token.symbol !== "ausdc"
          ? token
          : { ...token, access_core: "" }),
      }),
    },
  };
  assert.throws(() => resolveChainTargets(withoutAccessCore, "monad"), /no access_core/);
});

test("the parser resolves the requested chain, not the first one", () => {
  const resolved = resolveChainTargets(MONAD_CONFIG, "monad");
  assert.notEqual(resolved.usdc, "0x543b96420d072BF587B63C41C0B0922762E986Ce");
  assert.throws(() => resolveChainTargets(MONAD_CONFIG, "solana"), /no "solana" entry/);
});

test("a duplicated symbol is refused rather than arbitrarily picked", () => {
  const duplicated = {
    ...MONAD_CONFIG,
    data: {
      chains: MONAD_CONFIG.data.chains.map((chain) => chain.chain !== "monad" ? chain : {
        ...chain,
        tokens: [...chain.tokens, chain.tokens[1]],
      }),
    },
  };
  assert.throws(() => resolveChainTargets(duplicated, "monad"), /2 "ausdc" entries/);
});
