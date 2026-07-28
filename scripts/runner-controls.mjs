/**
 * The controls every writing runner shares.
 *
 * M-05, M-07 and M-08 each grew their own version of the same seven guards, with three different
 * authorization schemes and two different gas rules. One divergent copy is one place a guard can be
 * weaker than it looks, so they are defined once here and imported.
 *
 * The seven controls:
 *
 *   1. an explicit flag, `--run` or `--broadcast`, is required to write anything;
 *   2. the chain is 10143, checked before any key is read;
 *   3. `--out` is mandatory whenever a run can write, so spending always leaves an artifact;
 *   4. the signing key must derive the configured address;
 *   5. prechecks and a simulation run before the send;
 *   6. gas is fail-closed: absent, zero or abnormal stops the run;
 *   7. the transaction hash is checkpointed before the receipt is awaited.
 *
 * On the authorization variables that used to sit in front of these: they were introduced when the
 * standing rule was that nothing could ever be broadcast, and they earned nothing afterwards. On
 * Monad testnet the explicit flag is already a deliberate act by the person typing the command, and
 * the guards that actually caught mistakes are the substantive ones below, chiefly the key
 * derivation check. They are deliberately not replaced by a global variable: a durable
 * "authorized: yes" sitting in an environment file is a weaker control than a flag typed per run.
 *
 * This module never broadcasts. It only decides whether a caller may.
 */
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export const MONAD_CHAIN_ID = 10_143;
export const DEFAULT_MAX_GAS_PRICE_WEI = 200_000_000_000n; // 200 gwei

export class ControlError extends Error {
  constructor(message) {
    super(message);
    this.name = "ControlError";
  }
}

const refuse = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/**
 * Control 2, and the first thing any runner does. It runs before authorization is examined and
 * before any key is read, so a misconfigured endpoint can never reach the point where secret
 * material is loaded. It is also what stands between a testnet script and a mainnet wallet.
 */
export async function assertChainId(publicClient, expected = MONAD_CHAIN_ID) {
  const observed = await publicClient.getChainId();
  if (observed !== expected) {
    refuse(`WRONG NETWORK: expected chain ${expected}, the RPC answered ${observed}.`);
  }
  return observed;
}

/**
 * Controls 1 and 3. A writing mode requires the explicit flag the caller passed, and an output
 * prefix, so a run that can move value or spend gas can always say what it did, including when it
 * stops partway.
 *
 * @param mode      the resolved mode, e.g. "check" or "broadcast"
 * @param writeMode the mode name that writes, e.g. "broadcast" or "run"
 */
export function assertWriteAllowed(mode, writeMode, out) {
  if (mode !== writeMode) return false;
  if (!out) {
    refuse(`--out <prefix> is required with --${writeMode}, so the transaction hash is`
      + " checkpointed before the receipt is awaited and a stop still leaves an artifact.");
  }
  return true;
}

/**
 * Control 4. The key belongs to the wallet owner; a runner reads it and never generates, derives,
 * requests or persists one. This check caught a real pair of swapped keys, which would otherwise
 * have signed from a wallet holding none of the intended balance.
 *
 * @param toAccount an injected deriver, so this stays testable without touching a real key
 */
export function assertKeyMatchesAddress(role, key, expectedAddress, toAccount) {
  if (!key) {
    refuse(`MORDANT_KEY_${role} is required to sign. It is supplied by the wallet owner; this`
      + " runner never generates or derives one.");
  }
  let derived;
  try {
    derived = toAccount(key).address;
  } catch (error) {
    refuse(`MORDANT_KEY_${role} is not a usable private key: ${String(error.message).slice(0, 80)}.`
      + " A key must be 32 bytes of hex with a 0x prefix.");
  }
  if (String(derived).toLowerCase() !== String(expectedAddress).toLowerCase()) {
    refuse(`MORDANT_KEY_${role} derives a different address from the configured ${expectedAddress}.`
      + " Refusing to sign for an unintended wallet.");
  }
  return derived;
}

/**
 * Control 6. An estimate that could not be produced, a zero or missing price, a non-bigint, or a
 * budget of zero all stop the run: proceeding would mean spending without knowing the cost.
 */
export function assertGasUsable(gas, gasPrice, ceilingGas, ceilingPriceWei = DEFAULT_MAX_GAS_PRICE_WEI) {
  if (typeof gas !== "bigint" || gas <= 0n) {
    refuse("gas could not be estimated. Nothing is sent on an absent or zero estimate.");
  }
  if (typeof gasPrice !== "bigint" || gasPrice <= 0n) {
    refuse("gas price could not be read. Nothing is sent on an absent or zero price.");
  }
  if (gas > ceilingGas) {
    refuse(`estimated gas ${gas} exceeds the ${ceilingGas} ceiling. This is not the transaction`
      + " the run intends to send.");
  }
  if (gasPrice > ceilingPriceWei) {
    refuse(`gas price ${gasPrice} wei exceeds the ${ceilingPriceWei} wei ceiling.`);
  }
  const budget = gas * gasPrice;
  if (budget <= 0n) refuse("the computed MON budget is zero, which cannot be right.");
  return budget;
}

/** Refuses to spend when the wallet cannot cover the measured budget. */
export function assertFundedFor(address, balance, budget) {
  if (typeof balance !== "bigint" || balance < budget) {
    refuse(`${address} holds ${balance} wei, needs at least ${budget} wei.`);
  }
  return balance;
}

/**
 * Strips anything credential-shaped, including the magickLink Cleanverse returns on verify_apass.
 * An absent credential stays absent rather than becoming a placeholder, so a reader can tell the
 * difference between "redacted" and "was never there".
 */
export function scrub(value) {
  if (value === null || typeof value !== "object") return value;
  const out = Array.isArray(value) ? [] : {};
  for (const [key, item] of Object.entries(value)) {
    out[key] = /magick?link|token|secret|apikey|api_key|authorization|cookie|privatekey|password/i.test(key)
      ? (item ? "[REDACTED]" : item)
      : scrub(item);
  }
  return out;
}

/**
 * Control 7's storage half. Writes atomically through a temporary file, so a reader never observes
 * a partial artifact and a crash mid-write cannot destroy the previous one.
 *
 * Secrets are detected by comparing against the actual configured values rather than by shape:
 * transaction hashes and log topics are also 64 hex characters, so a shape rule would either miss
 * keys or reject block hashes. The values are only ever compared, never written or printed.
 */
export function writeArtifact(out, report, env = process.env) {
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  const secrets = Object.entries(env)
    .filter(([name]) => /^MORDANT_KEY_|^DEPLOYER_PRIVATE_KEY$|^CLEANVERSE_API_KEY$/.test(name))
    .map(([, value]) => value)
    .filter((value) => typeof value === "string" && value.length >= 16);
  if (secrets.some((secret) => serialized.includes(secret))) {
    throw new ControlError("STOP — refusing to write an artifact containing secret material.");
  }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(`${out}.json.tmp`, serialized, "utf8");
  renameSync(`${out}.json.tmp`, `${out}.json`);
  return `${out}.json`;
}

/**
 * Control 7. Records a hash the moment it exists, before anything is awaited. From that point the
 * transaction exists whether or not this process survives, so the artifact has to say so: a run
 * that dies here must never look like a run that never sent.
 */
export function checkpointPending(report, hash, out, env = process.env) {
  report.execution = { ...(report.execution ?? {}), hash, status: "PENDING", receipt: null };
  report.generatedAt = new Date().toISOString();
  if (out) writeArtifact(out, report, env);
  return report;
}
