/**
 * M-05 runner internals.
 *
 * Split out from the CLI so every gate is directly testable: chain gate, broadcast authorization,
 * key loading, funding, gas-price cap, cure-deadline polling and artifact writing.
 *
 * Nothing here broadcasts by itself. The CLI decides whether sending is permitted, and it only ever
 * does so after the chain gate and the authorization gate have both passed.
 */
import { renameSync, writeFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export const MONAD_CHAIN_ID = 10_143;
export const BROADCAST_CEREMONY = "yes-i-authorize-monad-protocol-double";
export const DEFAULT_MAX_GAS_PRICE_WEI = 200_000_000_000n; // 200 gwei

/** Budgeted MON per spending wallet, from the plan's 2x margin column. */
export const BUDGET = Object.freeze({
  deployer: 2_486_000_000_000_000_000n,
  buyer: 1_365_400_000_000_000_000n,
  facilityA: 107_400_000_000_000_000n,
  facilityB: 103_200_000_000_000_000n,
  holderA: 143_100_000_000_000_000n,
  holderB: 69_300_000_000_000_000n,
});

export const KEY_ENV = Object.freeze({
  deployer: "MORDANT_KEY_DEPLOYER",
  buyer: "MORDANT_KEY_BUYER",
  facilityA: "MORDANT_KEY_FACILITY_A",
  facilityB: "MORDANT_KEY_FACILITY_B",
  holderA: "MORDANT_KEY_HOLDER_A",
  holderB: "MORDANT_KEY_HOLDER_B",
});

export const ADDRESS_ENV = Object.freeze({
  deployer: "MORDANT_ADDRESS_DEPLOYER",
  buyer: "MORDANT_ADDRESS_BUYER",
  facilityA: "MORDANT_ADDRESS_FACILITY_A",
  facilityB: "MORDANT_ADDRESS_FACILITY_B",
  holderA: "MORDANT_ADDRESS_HOLDER_A",
  holderB: "MORDANT_ADDRESS_HOLDER_B",
});

export class RunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = "RunnerError";
  }
}

/**
 * The first gate. It runs before authorization is examined and before any key is read, so a
 * misconfigured endpoint can never reach the point where secret material is loaded.
 */
export async function assertChainId(publicClient, expected = MONAD_CHAIN_ID) {
  const observed = await publicClient.getChainId();
  if (observed !== expected) {
    throw new RunnerError(`BLOCKED — WRONG NETWORK: expected chain ${expected}, RPC answered ${observed}`);
  }
  return observed;
}

/** Broadcasting needs an explicit ceremony string, never a bare flag. */
export function assertBroadcastAuthorized(mode, env) {
  if (mode !== "broadcast") {
    return;
  }
  if (env.MORDANT_BROADCAST_AUTHORIZED !== BROADCAST_CEREMONY) {
    throw new RunnerError(
      "REFUSED: --broadcast requires MORDANT_BROADCAST_AUTHORIZED to be set to the exact ceremony"
      + " string. Broadcasting is not authorized.",
    );
  }
}

/** A run whose gas price exceeds the cap stops rather than silently overspending the budget. */
export async function assertGasPriceUnderCap(publicClient, cap = DEFAULT_MAX_GAS_PRICE_WEI) {
  const price = await publicClient.getGasPrice();
  if (price > cap) {
    throw new RunnerError(
      `BLOCKED — GAS PRICE ${price} wei exceeds the cap of ${cap} wei. Raise`
      + " MORDANT_MAX_GAS_PRICE_GWEI deliberately or wait.",
    );
  }
  return price;
}

/**
 * Anvil's published development keys, used only for the fork so the runner is testable end to end.
 * A check or broadcast run never falls back to them.
 */
const FORK_KEYS = Object.freeze({
  deployer: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  buyer: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  originator: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  facilityA: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  facilityB: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  holderA: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  holderB: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
});

/**
 * Resolves signers. Called only after the chain gate has passed.
 *
 * The originator signs both pledges, and the pledge contents depend on the vault address, the
 * invoice root and on-chain timestamps that only exist mid-run. It therefore needs its key here.
 * An offline prepare/resume flow is a separate mission, not a claim this runner can make today.
 */
export function loadAccounts(mode, env, toAccount) {
  const accounts = {};
  for (const [role, variable] of Object.entries(KEY_ENV)) {
    const key = env[variable];
    if (key) {
      accounts[role] = toAccount(key);
    } else if (mode === "fork") {
      accounts[role] = toAccount(FORK_KEYS[role]);
    } else if (mode === "check") {
      // A check signs nothing, so a public address is enough.
      const address = env[ADDRESS_ENV[role]];
      if (!address) {
        throw new RunnerError(
          `BLOCKED — ${role} is not configured. Set ${variable} or ${ADDRESS_ENV[role]}.`,
        );
      }
      accounts[role] = { address, readOnly: true };
    } else {
      throw new RunnerError(`BLOCKED — ${variable} is not set. Every spending wallet needs its key.`);
    }
  }

  const originatorKey = env.MORDANT_KEY_ORIGINATOR ?? (mode === "fork" ? FORK_KEYS.originator : undefined);
  if (!originatorKey) {
    if (mode === "check") {
      const address = env.MORDANT_ADDRESS_ORIGINATOR;
      if (!address) {
        throw new RunnerError(
          "BLOCKED — originator is not configured. Set MORDANT_KEY_ORIGINATOR or"
          + " MORDANT_ADDRESS_ORIGINATOR.",
        );
      }
      return { accounts, originator: { address, readOnly: true }, secrets: [] };
    }
    throw new RunnerError(
      "BLOCKED — MORDANT_KEY_ORIGINATOR is required. The originator signs pledges whose contents"
      + " depend on the vault address, invoice root and on-chain timestamps, none of which exist"
      + " before the run starts, so a pre-computed signature cannot be supplied.",
    );
  }

  const secrets = Object.values(KEY_ENV)
    .map((variable) => env[variable])
    .concat(originatorKey)
    .filter((value) => typeof value === "string" && value.length > 0);

  return { accounts, originator: toAccount(originatorKey), secrets };
}

/** Every spending wallet must hold its budget before Phase 1 starts. */
export async function assertFunded(publicClient, accounts, budgets = BUDGET) {
  const results = [];
  const short = [];
  for (const [role, budget] of Object.entries(budgets)) {
    const address = accounts[role]?.address;
    if (!address) {
      short.push(role);
      results.push({ role, address: null, balance: null, budget: budget.toString(), ok: false });
      continue;
    }
    const balance = await publicClient.getBalance({ address });
    const ok = balance >= budget;
    if (!ok) short.push(role);
    results.push({ role, address, balance: balance.toString(), budget: budget.toString(), ok });
  }
  if (short.length > 0) {
    throw new RunnerError(
      `BLOCKED — underfunded or unconfigured wallet(s): ${short.join(", ")}.`
      + " Fund them externally before running Phase 1.",
      { cause: results },
    );
  }
  return results;
}

/**
 * Waits for the cure window by reading the deadline the contract actually recorded and polling
 * blocks until chain time passes it. A wall-clock sleep proves nothing about chain state.
 */
export async function waitForCureDeadline(publicClient, readCureDeadline, options = {}) {
  const { intervalMs = 2_000, maxWaitMs = 600_000, onPoll } = options;
  const deadline = await readCureDeadline();
  if (deadline === 0n) {
    throw new RunnerError("BLOCKED — cureDeadline is zero: the conflict was never revealed.");
  }
  const started = Date.now();
  for (;;) {
    const block = await publicClient.getBlock();
    if (onPoll) onPoll(block.number, block.timestamp, deadline);
    if (block.timestamp > deadline) {
      return { deadline, observedTimestamp: block.timestamp, block: block.number };
    }
    if (Date.now() - started > maxWaitMs) {
      throw new RunnerError(
        `BLOCKED — cure window did not elapse within ${maxWaitMs} ms.`
        + ` Chain time ${block.timestamp}, deadline ${deadline}.`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** Fields whose value is legitimately a 32-byte hex string. Anything else of that shape is a leak. */
const HEX32_ALLOWED_KEYS = new Set([
  "hash", "invoiceRoot", "commitment", "digest", "salt", "blockHash", "matchFingerprint",
]);

/**
 * Removes any known secret and refuses to return a report that still carries key-shaped material in
 * an unexpected place. Called before every write, including checkpoints written mid-failure.
 */
export function scrubReport(report, secrets = []) {
  const seen = [];
  const walk = (value, key) => {
    if (typeof value === "string") {
      if (secrets.some((secret) => secret && value.toLowerCase() === secret.toLowerCase())) {
        return "[REDACTED]";
      }
      if (/^0x[0-9a-fA-F]{64}$/.test(value) && !HEX32_ALLOWED_KEYS.has(key)) {
        seen.push(key);
        return "[REDACTED]";
      }
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((item) => walk(item, key));
    }
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, walk(v, k)]));
    }
    return value;
  };
  const scrubbed = walk(report, "root");
  return { scrubbed, redactedKeys: seen };
}

export function assertNoSecretInReport(serialized, secrets = []) {
  for (const secret of secrets) {
    if (secret && serialized.toLowerCase().includes(secret.toLowerCase())) {
      throw new RunnerError("BLOCKED — refusing to write an artifact containing secret material.");
    }
  }
}

/**
 * Atomic checkpoint. Writes to a temporary file then renames, so a crash mid-write cannot leave a
 * truncated artifact, and a failed run still leaves the hashes already broadcast on disk.
 */
export function writeCheckpoint(pathPrefix, report, secrets = []) {
  const { scrubbed } = scrubReport(report, secrets);
  const serialized = `${JSON.stringify(scrubbed, null, 2)}\n`;
  assertNoSecretInReport(serialized, secrets);
  const target = `${pathPrefix}.json`;
  mkdirSync(dirname(target), { recursive: true });
  const temporary = `${target}.tmp`;
  writeFileSync(temporary, serialized, "utf8");
  renameSync(temporary, target);
  return target;
}
