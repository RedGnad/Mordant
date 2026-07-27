import {
  ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG,
  ATOKEN_LAUNCH_SELECTOR_TEN_ARG,
  DEFAULT_CLEANVERSE_MONAD_TARGETS,
  ERC20_BURN_SELECTOR,
  ERC20_MINT_SELECTOR,
  MONAD_TESTNET_CHAIN_ID,
} from "./cleanverse-monad";
import { EIP1967_BEACON_SLOT, EIP1967_IMPLEMENTATION_SLOT } from "./observe";
import { EvidenceRpcError, type RpcTransport } from "./rpc";

/**
 * A recorded, offline chain used by the tests and by the default `evidence:cleanverse` run.
 * Fixture output is never presented as a live observation: the report records `mode: "fixture"`.
 */
export type FixtureAccount = Readonly<{
  code: string;
  implementation?: string;
  beacon?: string;
}>;

export type FixtureChain = Readonly<{
  chainId: number;
  headBlock: bigint;
  blockHash: `0x${string}`;
  accounts: Readonly<Record<string, FixtureAccount>>;
  /** Keyed by `address:calldata` first, then `address:selector`. */
  calls: Readonly<Record<string, string>>;
}>;

const EMPTY_WORD = `0x${"00".repeat(32)}`;

/** Prefix marking a recorded call that answers by reverting with custom-error data. */
export const REVERT_PREFIX = "revert:" as const;

function word(value: bigint | number): string {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function addressWord(address: string): string {
  return `0x${address.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
}

function boolWord(value: boolean): string {
  return word(value ? 1 : 0);
}

/** Minimal runtime bytecode containing the given selectors in a PUSH4 dispatch position. */
export function fixtureBytecodeWithSelectors(selectors: readonly string[], padding = 32): string {
  const dispatch = selectors
    .map((selector) => `63${selector.toLowerCase().replace(/^0x/, "")}14`)
    .join("");
  return `0x6080604052${dispatch}${"00".repeat(padding)}`;
}

const APASS_IMPLEMENTATION = "0x9406f5d46268ee6617f7ab28ed8ae0767d3415a3";
const AUSDC_IMPLEMENTATION = "0x5a520e9992d30416c33e2dcdc2d8f3befce426da";
const FACTORY_IMPLEMENTATION = "0x21084e6ca8d65d3f1a3d27cac9c1abe06f1582ea";
const AUSDC_POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";
const MINTER_ROLE = "0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6";

const PROXY_CODE = fixtureBytecodeWithSelectors([], 24);

/** A healthy Monad testnet fixture: proxies resolve, tokens answer, launch selectors present. */
export function createMonadFixtureChain(): FixtureChain {
  const targets = DEFAULT_CLEANVERSE_MONAD_TARGETS;

  return Object.freeze({
    chainId: MONAD_TESTNET_CHAIN_ID,
    headBlock: 48_645_484n,
    blockHash: `0x${"ab".repeat(32)}` as `0x${string}`,
    accounts: Object.freeze({
      [targets.apass.toLowerCase()]: { code: PROXY_CODE, implementation: APASS_IMPLEMENTATION },
      [APASS_IMPLEMENTATION]: { code: fixtureBytecodeWithSelectors(["0xf480b6f5"]) },
      [targets.aUsdc.toLowerCase()]: { code: PROXY_CODE, implementation: AUSDC_IMPLEMENTATION },
      [AUSDC_IMPLEMENTATION]: {
        code: fixtureBytecodeWithSelectors([ERC20_MINT_SELECTOR, ERC20_BURN_SELECTOR]),
      },
      [targets.usdc.toLowerCase()]: { code: fixtureBytecodeWithSelectors([]) },
      [targets.accessCore.toLowerCase()]: { code: fixtureBytecodeWithSelectors([]) },
      [targets.depositGateway.toLowerCase()]: { code: fixtureBytecodeWithSelectors([]) },
      [targets.aTokenFactoryProxy.toLowerCase()]: {
        code: PROXY_CODE,
        implementation: FACTORY_IMPLEMENTATION,
      },
      [FACTORY_IMPLEMENTATION]: {
        code: fixtureBytecodeWithSelectors([
          ATOKEN_LAUNCH_SELECTOR_TEN_ARG,
          ATOKEN_LAUNCH_SELECTOR_EIGHT_ARG,
        ]),
      },
      [AUSDC_POLICY.toLowerCase()]: { code: fixtureBytecodeWithSelectors(["0x6d62a4fe"]) },
    }),
    calls: Object.freeze({
      // decimals() / policy() / MINTER_ROLE() / totalSupply() on aUSDC
      [`${targets.aUsdc.toLowerCase()}:0x313ce567`]: word(6),
      [`${targets.aUsdc.toLowerCase()}:0x0505c8c9`]: addressWord(AUSDC_POLICY),
      [`${targets.aUsdc.toLowerCase()}:0xd5391393`]: MINTER_ROLE,
      [`${targets.aUsdc.toLowerCase()}:0x18160ddd`]: word(112_140_000),
      [`${targets.aUsdc.toLowerCase()}:0x70a08231`]: word(0),
      [`${targets.aUsdc.toLowerCase()}:0x91d14854`]: boolWord(false),
      // isValidAPass(address): only the burn address carries a record in this fixture.
      [`${targets.apass.toLowerCase()}:0xf480b6f5`]: boolWord(false),
      [`${targets.apass.toLowerCase()}:0xf480b6f5${"0".repeat(24)}000000000000000000000000000000000000dead`]:
        boolWord(true),
      // canTransfer(address,address,address,uint256)
      [`${AUSDC_POLICY.toLowerCase()}:0x6d62a4fe`]: boolWord(true),
    }),
  });
}

export type FixtureTransportOptions = Readonly<{
  chain?: FixtureChain;
  /** Overrides merged over the base chain, for negative-path tests. */
  overrides?: Partial<FixtureChain>;
}>;

/**
 * A transport that never touches the network. Unknown reads fail loudly rather than returning a
 * plausible default, so a fixture gap can never masquerade as an observation.
 */
export function createFixtureTransport(options: FixtureTransportOptions = {}): RpcTransport {
  const base = options.chain ?? createMonadFixtureChain();
  const chain: FixtureChain = Object.freeze({ ...base, ...options.overrides });

  return async (method, params) => {
    switch (method) {
      case "eth_chainId":
        return `0x${chain.chainId.toString(16)}`;

      case "eth_blockNumber":
        return `0x${chain.headBlock.toString(16)}`;

      case "eth_getBlockByNumber":
        return { number: params[0], hash: chain.blockHash };

      case "eth_getCode": {
        const address = String(params[0]).toLowerCase();
        return chain.accounts[address]?.code ?? "0x";
      }

      case "eth_getStorageAt": {
        const address = String(params[0]).toLowerCase();
        const slot = String(params[1]).toLowerCase();
        const account = chain.accounts[address];
        if (account === undefined) {
          return EMPTY_WORD;
        }
        if (slot === EIP1967_IMPLEMENTATION_SLOT.toLowerCase()) {
          return account.implementation === undefined
            ? EMPTY_WORD
            : addressWord(account.implementation);
        }
        if (slot === EIP1967_BEACON_SLOT.toLowerCase()) {
          return account.beacon === undefined ? EMPTY_WORD : addressWord(account.beacon);
        }
        return EMPTY_WORD;
      }

      case "eth_call": {
        const request = params[0] as { to?: string; data?: string };
        const to = String(request.to ?? "").toLowerCase();
        const data = String(request.data ?? "").toLowerCase();
        const exact = chain.calls[`${to}:${data}`];
        const bySelector = chain.calls[`${to}:${data.slice(0, 10)}`];
        const recorded = exact ?? bySelector;
        if (recorded !== undefined) {
          // `revert:0x...` records a contract that answers by reverting with custom-error data.
          if (recorded.startsWith(REVERT_PREFIX)) {
            throw new EvidenceRpcError(
              "execution reverted",
              recorded.slice(REVERT_PREFIX.length),
            );
          }
          return recorded;
        }
        throw new EvidenceRpcError(
          `Fixture has no recorded result for ${data.slice(0, 10)} at ${to}`,
        );
      }

      default:
        throw new EvidenceRpcError(`Fixture transport does not implement ${method}`);
    }
  };
}
