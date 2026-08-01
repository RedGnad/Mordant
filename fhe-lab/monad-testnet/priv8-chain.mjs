// Chain plumbing shared by the M-PRIV8 runner: crash-safe journalling, Monad's
// fee handling, artifact loading and derived lab role accounts.
//
// Split out of the runner so the transaction discipline is one thing, reviewed
// once, rather than repeated at every call site.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, defineChain, http, getAddress, keccak256, encodePacked, encodeDeployData } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(HERE, "../..");

export const CHAIN_ID = 10_143;
export const MAX_GAS = 30_000_000n;
export const MAX_GAS_PRICE_WEI = 500_000_000_000n;

export class RunError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.code = code; }
}
export const fail = (code, detail) => { throw new RunError(code, detail); };

/* ------------------------------------------------------------------ journal */

export async function writeAtomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`);
  await rename(temporary, path);
}

export async function readJournal(path, schema) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    if (parsed?.schemaVersion !== schema) fail("JOURNAL_SCHEMA", String(parsed?.schemaVersion));
    if (Number(parsed?.chainId) !== CHAIN_ID) fail("JOURNAL_CHAIN", String(parsed?.chainId));
    return parsed;
  } catch (error) {
    if (error instanceof RunError) throw error;
    if (error?.code !== "ENOENT") throw error;
    return null;
  }
}

export function emptyJournal(schema) {
  return { schemaVersion: schema, chainId: CHAIN_ID, testAssetsOnly: true, steps: {}, history: [] };
}

/**
 * Records a step's transaction hash BEFORE its receipt is awaited.
 *
 * A crash between broadcast and receipt therefore leaves a hash on disk rather
 * than an orphaned transaction, and a resumed run reconciles it instead of
 * resubmitting. An unreconciled hash stops the run: an ambiguous chain state is
 * never resolved by guessing.
 */
export async function step(journal, path, name, send) {
  const existing = journal.steps[name];
  if (existing?.status === "success") return { hash: existing.hash, replayed: true, meta: existing };
  if (existing?.hash) fail("STEP_UNRECONCILED", `${name}:${existing.hash}`);
  const { hash, meta } = await send();
  journal.steps[name] = { hash, status: null, ...meta };
  journal.history.push({ name, hash, at: new Date().toISOString() });
  await writeAtomic(path, journal);
  return { hash, replayed: false, meta };
}

export async function settle(journal, path, name, client, hash, meta = {}) {
  if (journal.steps[name]?.status === "success") return journal.steps[name];
  const receipt = await client.waitForTransactionReceipt({ hash, pollingInterval: 1_000, retryDelay: 1_000 });
  if (receipt.status !== "success") fail("STEP_REVERTED", `${name}:${hash}`);
  journal.steps[name] = {
    hash, status: receipt.status, block: String(receipt.blockNumber),
    gasUsed: String(receipt.gasUsed), contractAddress: receipt.contractAddress ?? null, ...meta,
  };
  await writeAtomic(path, journal);
  return journal.steps[name];
}

/* -------------------------------------------------------------------- chain */

export function monadChain(rpc) {
  return defineChain({
    id: CHAIN_ID, name: "Monad testnet",
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
  });
}

export async function artifact(name, path) {
  const raw = await readFile(resolve(REPO, `contracts/out/${path}/${name}.json`), "utf8");
  const parsed = JSON.parse(raw);
  const bytecode = parsed?.bytecode?.object;
  if (!parsed?.abi || typeof bytecode !== "string" || !bytecode.startsWith("0x")) {
    fail("ARTIFACT_INVALID", name);
  }
  return { abi: parsed.abi, bytecode, deployed: parsed?.deployedBytecode?.object ?? null };
}

/// Lab role accounts derived from the deployer key so one operator can reproduce
/// them and nobody else can. They hold test MON only, and they are the vault's
/// ECONOMIC roles: they are deliberately not part of the privacy topology.
export function deriveRole(deployerKey, label) {
  const key = keccak256(encodePacked(["string", "bytes32", "string"], ["mordant.priv8.role/", deployerKey, label]));
  return privateKeyToAccount(key);
}

export function config(env = process.env) {
  const deployerKey = env.FHE_MONAD_DEPLOYER_PRIVATE_KEY;
  if (typeof deployerKey !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(deployerKey)) fail("CONFIG_DEPLOYER_KEY");
  const rpc = env.FHE_MONAD_RPC_URL;
  if (!rpc) fail("CONFIG_RPC_URL");
  return {
    rpc,
    deployerKey,
    deployer: privateKeyToAccount(deployerKey),
    buyer: deriveRole(deployerKey, "buyer"),
    originator: deriveRole(deployerKey, "originator"),
    facility: deriveRole(deployerKey, "facility"),
    holder: deriveRole(deployerKey, "holder"),
  };
}

/**
 * Monad rejects a transaction whose sender cannot cover gas_limit * maxFeePerGas.
 *
 * When viem fills the fee fields before estimating, the node applies that check
 * against the whole block gas limit and reports it as "Signer had insufficient
 * balance". Estimating without fee fields and then sending with an explicit gas
 * limit and explicit fees avoids that entirely and makes every transaction's
 * cost ceiling deterministic.
 */
export function transactor(client, walletFor) {
  const fees = async () => {
    const block = await client.getBlock();
    const priority = 2_000_000_000n;
    const base = block.baseFeePerGas ?? (await client.getGasPrice());
    const maxFeePerGas = base * 2n + priority;
    if (maxFeePerGas > MAX_GAS_PRICE_WEI) fail("GAS_PRICE_CEILING", String(maxFeePerGas));
    return { maxPriorityFeePerGas: priority, maxFeePerGas };
  };

  const boundedGas = async (estimate) => {
    const gas = (estimate * 130n) / 100n;
    if (gas > MAX_GAS) fail("GAS_LIMIT", String(gas));
    return gas;
  };

  return {
    fees,
    async deploy(account, art, args) {
      const gas = await boundedGas(await client.estimateGas({
        account, data: encodeDeployData({ abi: art.abi, bytecode: art.bytecode, args }),
      }));
      return walletFor(account).deployContract({ abi: art.abi, bytecode: art.bytecode, args, gas, ...(await fees()) });
    },
    async write(account, request) {
      const gas = await boundedGas(await client.estimateContractGas({ ...request, account }));
      return walletFor(account).writeContract({ ...request, account, gas, ...(await fees()) });
    },
    async send(account, request) {
      const gas = await boundedGas(await client.estimateGas({ ...request, account }));
      return walletFor(account).sendTransaction({ ...request, account, gas, ...(await fees()) });
    },
  };
}

export function walletFactory(chain, rpc) {
  const cache = new Map();
  return (account) => {
    const key = account.address;
    if (!cache.has(key)) cache.set(key, createWalletClient({ account, chain, transport: http(rpc) }));
    return cache.get(key);
  };
}

/**
 * Monad's public RPC caps reads at 15/sec and answers a burst with an error
 * rather than a queue. One paced fetch is installed for the whole process so
 * every read, wherever it is issued from, shares the same budget.
 */
let paced = false;
export function paceRpc(rpc) {
  if (paced) return;
  paced = true;
  const host = new URL(rpc).host;
  const original = globalThis.fetch;
  let chain = Promise.resolve();
  let last = 0;
  const MIN_INTERVAL_MS = 90;
  globalThis.fetch = (input, init) => {
    const url = typeof input === "string" ? input : input?.url ?? "";
    if (!url.includes(host)) return original(input, init);
    const attempt = async (tries) => {
      const wait = Math.max(0, MIN_INTERVAL_MS - (Date.now() - last));
      if (wait > 0) await new Promise((done) => setTimeout(done, wait));
      last = Date.now();
      const response = await original(input, init);
      if (response.status === 429 && tries < 6) {
        await new Promise((done) => setTimeout(done, 500 * (tries + 1)));
        return attempt(tries + 1);
      }
      return response;
    };
    const queued = chain.then(() => attempt(0));
    chain = queued.then(() => undefined, () => undefined);
    return queued;
  };
}

export function publicClient(chain, rpc) {
  paceRpc(rpc);
  return createPublicClient({
    chain,
    transport: http(rpc, { batch: false, retryCount: 8, retryDelay: 400, timeout: 60_000 }),
  });
}

export { getAddress };
