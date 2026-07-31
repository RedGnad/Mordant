#!/usr/bin/env node

// Deploys and activates a real MordantInvoiceVault on Monad testnet as the
// tokenized-receivable anchor for the V4 product gate.
//
// This is the product's own receivable contract, not a token invented for the
// wording: the vault IS an ERC-20 whose units are the tokenized receivable, it
// carries the invoice root, currency, buyer, originator and receivable state,
// and its Pledge type is the same commercial-term set the confidential policy
// evaluates. The settlement and CVA tokens are protocol doubles required by the
// vault's own accounting, and they hold test assets only.
//
// The runner is crash-safe: every transaction hash is journalled with atomic
// temp-and-rename before its receipt is awaited, and a persisted hash is
// reconciled rather than resubmitted.

import { readFile, mkdir, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, defineChain, http, getAddress, keccak256, encodePacked, stringToHex, parseEventLogs, encodeDeployData } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../..");

export const CHAIN_ID = 10_143;
export const JOURNAL_PATH = resolve(HERE, "artifacts/anchor-journal.json");
export const JOURNAL_SCHEMA = "mordant.receivable-anchor-journal/1";
export const REPORT_SCHEMA = "mordant.receivable-anchor/1";

const ROLE_BUYER = 1, ROLE_ORIGINATOR = 2, ROLE_FACILITY = 3, ROLE_HOLDER = 4;
const UNITS = 100_000_000n;      // 100.000000 receivable units (6 decimals)
const ADVANCE = 100_000_000n;    // advance paid into the vault
const FACE = 110_000_000n;       // face value at maturity
const BOND_BPS = 1_000;          // 10% exclusivity bond
const REVEAL_PERIOD = 3_600n;
const CURE_PERIOD = 3_600n;
const PROTECTION_DAYS = 30n;
const MAX_GAS = 30_000_000n;
// Monad requires the sender to hold gas_limit * gas_price up front, and the
// buyer's createInvoiceVault deploys a whole vault. Fund role accounts well
// above the estimated ceiling; unspent test MON simply stays on the account.
const FUND_WEI = 4_000_000_000_000_000_000n; // 4 MON per role account

export class AnchorError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.code = code; }
}
const fail = (code, detail) => { throw new AnchorError(code, detail); };

/* ------------------------------------------------------------------ journal */

export async function writeAtomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`);
  await rename(temporary, path);
}

export async function readJournal(path) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    return parsed?.schemaVersion === JOURNAL_SCHEMA ? parsed : null;
  } catch { return null; }
}

export function emptyJournal() {
  return { schemaVersion: JOURNAL_SCHEMA, chainId: CHAIN_ID, testAssetsOnly: true, steps: {}, history: [] };
}

// Records a step's hash before the receipt is awaited so a crash can never
// orphan a broadcast transaction.
async function step(journal, path, name, send) {
  const existing = journal.steps[name];
  if (existing?.status === "success") return existing;
  if (existing?.hash) fail("ANCHOR_STEP_UNRECONCILED", `${name}:${existing.hash}`);
  const { hash, meta } = await send();
  journal.steps[name] = { hash, status: null, ...meta };
  journal.history.push({ name, hash, at: new Date().toISOString() });
  await writeAtomic(path, journal);
  return { hash, meta };
}

async function settle(journal, path, name, client, hash, meta = {}) {
  const receipt = await client.waitForTransactionReceipt({ hash, pollingInterval: 1_000, retryDelay: 1_000 });
  if (receipt.status !== "success") fail("ANCHOR_STEP_REVERTED", `${name}:${hash}`);
  journal.steps[name] = {
    hash, status: receipt.status, block: String(receipt.blockNumber),
    gasUsed: String(receipt.gasUsed), contractAddress: receipt.contractAddress ?? null, ...meta,
  };
  await writeAtomic(path, journal);
  return receipt;
}

/* ------------------------------------------------------------------ config */

export function monadChain(rpc) {
  return defineChain({
    id: CHAIN_ID, name: "Monad testnet",
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
  });
}

export async function artifact(relativePath, name) {
  const raw = await readFile(resolve(REPO, `contracts/out/${relativePath}/${name}.json`), "utf8");
  const parsed = JSON.parse(raw);
  const bytecode = parsed?.bytecode?.object;
  if (!parsed?.abi || typeof bytecode !== "string" || !bytecode.startsWith("0x")) {
    fail("ANCHOR_ARTIFACT_INVALID", name);
  }
  return { abi: parsed.abi, bytecode };
}

// Lab role accounts are derived from the deployer key so the same operator can
// reproduce them, and nobody else can. They hold test MON only.
export function deriveRole(deployerKey, label) {
  const key = keccak256(encodePacked(["string", "bytes32", "string"], ["mordant.v4.anchor-role/", deployerKey, label]));
  return privateKeyToAccount(key);
}

export function config(env = process.env) {
  const deployerKey = env.FHE_MONAD_DEPLOYER_PRIVATE_KEY;
  if (typeof deployerKey !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(deployerKey)) fail("CONFIG_DEPLOYER_KEY");
  const rpc = env.FHE_MONAD_RPC_URL;
  if (!rpc) fail("CONFIG_RPC_URL");
  const deployer = privateKeyToAccount(deployerKey);
  return {
    rpc, deployer,
    buyer: deriveRole(deployerKey, "buyer"),
    originator: deriveRole(deployerKey, "originator"),
    facilityA: deriveRole(deployerKey, "facility-a"),
    facilityB: deriveRole(deployerKey, "facility-b"),
    holder: deriveRole(deployerKey, "holder"),
  };
}

function encodeDeploy(art, args) {
  return encodeDeployData({ abi: art.abi, bytecode: art.bytecode, args });
}

/* --------------------------------------------------------------------- run */

export async function run(options = parseArgs(process.argv.slice(2))) {
  const settings = config();
  const chain = monadChain(settings.rpc);
  const client = createPublicClient({ chain, transport: http(settings.rpc) });
  const wallet = (account) => createWalletClient({ account, chain, transport: http(settings.rpc) });

  const chainId = await client.getChainId();
  if (chainId !== CHAIN_ID) fail("CHAIN_ID_MISMATCH", String(chainId));
  const balance = await client.getBalance({ address: settings.deployer.address });
  if (balance < 5_000_000_000_000_000_000n) fail("DEPLOYER_BALANCE_LOW", String(balance));

  const artifacts = {
    eligibility: await artifact("MockEligibility.sol", "MockEligibility"),
    erc20: await artifact("MockERC20.sol", "MockERC20"),
    adapter: await artifact("MockCvaAdapter.sol", "MockCvaAdapter"),
    factory: await artifact("MordantFactory.sol", "MordantFactory"),
    vault: await artifact("MordantInvoiceVault.sol", "MordantInvoiceVault"),
  };

  if (options.mode === "check") {
    return {
      classification: "ANCHOR_PREFLIGHT",
      chainId, deployer: settings.deployer.address,
      balance: balance.toString(),
      roles: {
        buyer: settings.buyer.address, originator: settings.originator.address,
        facilityA: settings.facilityA.address, facilityB: settings.facilityB.address,
        holder: settings.holder.address,
      },
      artifactsResolved: Object.keys(artifacts),
    };
  }

  const journal = (await readJournal(options.journal)) ?? emptyJournal();
  const deployerWallet = wallet(settings.deployer);

  // Monad rejects a transaction whose sender cannot cover gas_limit *
  // maxFeePerGas. When viem fills the fee fields before estimating, the node
  // applies that check against the whole block gas limit and reports it as
  // "Signer had insufficient balance". Estimating without fee fields and then
  // sending with an explicit gas limit and explicit fees avoids that entirely
  // and makes every transaction's cost ceiling deterministic.
  const fees = async () => {
    const block = await client.getBlock();
    const priority = 2_000_000_000n;
    const base = block.baseFeePerGas ?? (await client.getGasPrice());
    return { maxPriorityFeePerGas: priority, maxFeePerGas: base * 2n + priority };
  };
  const bounded = async (account, request) => {
    const estimate = await client.estimateContractGas({ ...request, account });
    const gas = (estimate * 130n) / 100n;
    if (gas > MAX_GAS) fail("ANCHOR_GAS_LIMIT", String(gas));
    return { ...request, gas, ...(await fees()) };
  };

  // 0. Fund the three role accounts that must send their own transactions.
  for (const [label, account] of [["buyer", settings.buyer], ["facilityA", settings.facilityA], ["holder", settings.holder]]) {
    const current = await client.getBalance({ address: account.address });
    if (current >= FUND_WEI / 2n) continue;
    // The step name carries the target so raising it opens a fresh top-up step
    // instead of being short-circuited by an earlier, smaller funding.
    const name = `fund:${label}@${FUND_WEI}`;
    const { hash } = await step(journal, options.journal, name, async () => ({
      hash: await deployerWallet.sendTransaction({ to: account.address, value: FUND_WEI - current }),
      meta: { role: label, to: account.address },
    }));
    await settle(journal, options.journal, name, client, hash, { role: label, to: account.address });
  }

  // 1. Dependencies the vault's own accounting requires.
  const deploy = async (name, art, args) => {
    const { hash } = await step(journal, options.journal, `deploy:${name}`, async () => {
      const estimate = await client.estimateGas({
        account: settings.deployer,
        data: art.bytecode === "0x" ? undefined : encodeDeploy(art, args),
      });
      const gas = (estimate * 130n) / 100n;
      if (gas > MAX_GAS) fail("ANCHOR_GAS_LIMIT", String(gas));
      return {
        hash: await deployerWallet.deployContract({ abi: art.abi, bytecode: art.bytecode, args, gas, ...(await fees()) }),
        meta: { contract: name },
      };
    });
    const receipt = await settle(journal, options.journal, `deploy:${name}`, client, hash, { contract: name });
    return getAddress(receipt.contractAddress);
  };

  const eligibility = journal.steps["deploy:eligibility"]?.contractAddress
    ? getAddress(journal.steps["deploy:eligibility"].contractAddress)
    : await deploy("eligibility", artifacts.eligibility, []);
  const settlement = journal.steps["deploy:settlement"]?.contractAddress
    ? getAddress(journal.steps["deploy:settlement"].contractAddress)
    : await deploy("settlement", artifacts.erc20, ["Mordant lab settlement", "labUSD", 6]);
  const cvaToken = journal.steps["deploy:cvaToken"]?.contractAddress
    ? getAddress(journal.steps["deploy:cvaToken"].contractAddress)
    : await deploy("cvaToken", artifacts.erc20, ["Mordant lab invoice A-token", "labINV", 6]);
  const adapter = journal.steps["deploy:adapter"]?.contractAddress
    ? getAddress(journal.steps["deploy:adapter"].contractAddress)
    : await deploy("adapter", artifacts.adapter, [cvaToken]);
  const factory = journal.steps["deploy:factory"]?.contractAddress
    ? getAddress(journal.steps["deploy:factory"].contractAddress)
    : await deploy("factory", artifacts.factory, [settings.deployer.address, eligibility]);

  // 2. Roles and allowlists.
  const send = async (name, account, request) => {
    const signer = wallet(account);
    const { hash } = await step(journal, options.journal, name, async () => ({
      hash: await signer.writeContract(await bounded(account, request)),
      meta: { from: account.address },
    }));
    return settle(journal, options.journal, name, client, hash, { from: account.address });
  };

  const eligibilityCalls = [
    ["buyer", settings.buyer.address, ROLE_BUYER],
    ["originator", settings.originator.address, ROLE_ORIGINATOR],
    ["facilityA", settings.facilityA.address, ROLE_FACILITY],
    ["facilityB", settings.facilityB.address, ROLE_FACILITY],
    ["holder", settings.holder.address, ROLE_HOLDER],
  ];
  for (const [label, address, role] of eligibilityCalls) {
    await send(`eligible:${label}`, settings.deployer, {
      address: eligibility, abi: artifacts.eligibility.abi, functionName: "setEligible", args: [address, role, true],
    });
  }
  for (const [label, address] of [["facilityA", settings.facilityA.address], ["facilityB", settings.facilityB.address]]) {
    await send(`factory:facility:${label}`, settings.deployer, {
      address: factory, abi: artifacts.factory.abi, functionName: "setFacility", args: [address, true],
    });
  }
  await send("factory:adapter", settings.deployer, {
    address: factory, abi: artifacts.factory.abi, functionName: "setCvaAdapter", args: [adapter, true],
  });
  await send("factory:settlement", settings.deployer, {
    address: factory, abi: artifacts.factory.abi, functionName: "setSettlementToken", args: [settlement, true],
  });

  // 3. The buyer creates the receivable vault. The invoice root is unique to
  //    this laboratory receivable.
  const invoiceRoot = journal.invoiceRoot ?? keccak256(stringToHex(`mordant.v4.receivable/${Date.now()}/${settings.deployer.address}`));
  journal.invoiceRoot = invoiceRoot;
  const currency = stringToHex("USD", { size: 32 });
  const latest = await client.getBlock();
  // The journal round-trips through JSON, so a persisted value returns as a
  // string. Coerce before any arithmetic: string + bigint would concatenate.
  const protectionEnd = BigInt(journal.protectionEnd ?? BigInt(latest.timestamp) + PROTECTION_DAYS * 86_400n);
  journal.protectionEnd = String(protectionEnd);
  await writeAtomic(options.journal, journal);

  let vault = journal.steps["vault:create"]?.vault ? getAddress(journal.steps["vault:create"].vault) : null;
  if (!vault) {
    const invoiceConfig = {
      cvaAdapter: adapter, settlementToken: settlement, invoiceRoot, currency,
      buyer: settings.buyer.address, originatorTreasury: settings.originator.address,
      initialOriginatorSigner: settings.originator.address,
      initialUnits: UNITS, advanceAmount: ADVANCE, faceValue: FACE, bondBps: BOND_BPS,
      protectionEnd, revealPeriod: REVEAL_PERIOD, curePeriod: CURE_PERIOD,
    };
    const buyerWallet = wallet(settings.buyer);
    const { hash } = await step(journal, options.journal, "vault:create", async () => ({
      hash: await buyerWallet.writeContract(await bounded(settings.buyer, {
        address: factory, abi: artifacts.factory.abi, functionName: "createInvoiceVault", args: [invoiceConfig],
      })),
      meta: { from: settings.buyer.address },
    }));
    const receipt = await settle(journal, options.journal, "vault:create", client, hash, { from: settings.buyer.address });
    const created = parseEventLogs({ abi: artifacts.factory.abi, logs: receipt.logs, eventName: "InvoiceVaultCreated", strict: true });
    if (created.length !== 1) fail("ANCHOR_VAULT_EVENT_MISSING");
    vault = getAddress(created[0].args.vault);
    journal.steps["vault:create"].vault = vault;
    await writeAtomic(options.journal, journal);
  }

  // 4. The vault must carry a valid identity and its CVA units before activation.
  await send("eligible:vaultIdentity", settings.deployer, {
    address: eligibility, abi: artifacts.eligibility.abi, functionName: "setIdentityValid", args: [vault, true],
  });
  await send("eligible:holderAsset", settings.deployer, {
    address: eligibility, abi: artifacts.eligibility.abi, functionName: "setAssetEligible", args: [settings.holder.address, ROLE_HOLDER, true],
  });
  await send("cva:mint", settings.deployer, {
    address: cvaToken, abi: artifacts.erc20.abi, functionName: "mint", args: [settings.deployer.address, UNITS],
  });
  await send("cva:approve", settings.deployer, {
    address: cvaToken, abi: artifacts.erc20.abi, functionName: "approve", args: [adapter, UNITS],
  });
  await send("cva:credit", settings.deployer, {
    address: adapter, abi: artifacts.adapter.abi, functionName: "creditVault", args: [vault, UNITS],
  });
  await send("settlement:mint", settings.deployer, {
    address: settlement, abi: artifacts.erc20.abi, functionName: "mint", args: [settings.holder.address, ADVANCE],
  });
  await send("settlement:approve", settings.holder, {
    address: settlement, abi: artifacts.erc20.abi, functionName: "approve", args: [vault, ADVANCE],
  });

  // 5. The originator signs the funding pledge; facility A activates. This is
  //    what moves the receivable to Outstanding and mints the tokenized units.
  // The vault's EIP-712 domain is EIP712("Mordant", "1") and the pledge amount
  // it validates is the face value, not the advance.
  const domain = { name: "Mordant", version: "1", chainId: CHAIN_ID, verifyingContract: vault };
  const types = {
    Pledge: [
      { name: "invoiceRoot", type: "bytes32" }, { name: "originatorSigner", type: "address" },
      { name: "facility", type: "address" }, { name: "obligationId", type: "bytes32" },
      { name: "amount", type: "uint256" }, { name: "currency", type: "bytes32" },
      { name: "activeFrom", type: "uint64" }, { name: "activeUntil", type: "uint64" },
      { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint64" },
      { name: "exclusive", type: "bool" },
    ],
  };
  const now = BigInt((await client.getBlock()).timestamp);
  const pledge = {
    invoiceRoot, originatorSigner: settings.originator.address, facility: settings.facilityA.address,
    obligationId: keccak256(stringToHex("mordant.v4.funding-obligation")),
    amount: FACE, currency,
    activeFrom: now - 60n, activeUntil: protectionEnd + 86_400n,
    nonce: 1n, deadline: now + 3_600n, exclusive: true,
  };
  const signature = await settings.originator.signTypedData({ domain, types, primaryType: "Pledge", message: pledge });
  await send("vault:activate", settings.facilityA, {
    address: vault, abi: artifacts.vault.abi, functionName: "activate",
    args: [pledge, signature, settings.holder.address, [settings.holder.address], [UNITS]],
  });

  // 6. Readbacks straight from chain.
  // The public endpoint caps reads at 15/sec; the readback sweep is serialised
  // behind a small interval so a rate limit can never mask a real state check.
  const pause = (ms) => new Promise((done) => setTimeout(done, ms));
  const read = async (functionName, args = []) => {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const value = await client.readContract({ address: vault, abi: artifacts.vault.abi, functionName, args });
        await pause(120);
        return value;
      } catch (error) {
        if (attempt >= 5 || !/limited|rate|429/i.test(String(error?.message ?? ""))) throw error;
        await pause(1_000 * (attempt + 1));
      }
    }
  };
  const anchor = {
    vault,
    invoiceRoot: await read("invoiceRoot"),
    currency: await read("currency"),
    buyer: await read("buyer"),
    originatorTreasury: await read("originatorTreasury"),
    receivableState: Number(await read("receivableState")),
    protectionState: Number(await read("protectionState")),
    totalSupply: (await read("totalSupply")).toString(),
    holderUnits: (await read("balanceOf", [settings.holder.address])).toString(),
    tokenName: await read("name"),
    tokenSymbol: await read("symbol"),
    tokenDecimals: Number(await read("decimals")),
    faceValue: (await read("faceValue")).toString(),
    advanceAmount: (await read("advanceAmount")).toString(),
    protectionEnd: (await read("protectionEnd")).toString(),
    curePeriod: (await read("curePeriod")).toString(),
    protectedFacility: await read("protectedFacility"),
    cvaToken: await read("cvaToken"),
    settlementToken: await read("settlementToken"),
    code: (await client.getCode({ address: vault }))?.length ?? 0,
  };
  if (anchor.receivableState !== 1) fail("ANCHOR_NOT_OUTSTANDING", String(anchor.receivableState));
  if (anchor.protectionState !== 1) fail("ANCHOR_NOT_ACTIVE", String(anchor.protectionState));
  if (anchor.totalSupply !== UNITS.toString()) fail("ANCHOR_UNITS_MISMATCH", anchor.totalSupply);

  const report = {
    schemaVersion: REPORT_SCHEMA,
    classification: "TOKENIZED RECEIVABLE ANCHOR: ACTIVE (TEST ASSETS ONLY)",
    testAssetsOnly: true,
    network: { chainId, deployer: settings.deployer.address },
    infrastructure: { eligibility, settlement, cvaToken, adapter, factory },
    roles: {
      buyer: settings.buyer.address, originator: settings.originator.address,
      facilityA: settings.facilityA.address, facilityB: settings.facilityB.address,
      holder: settings.holder.address,
    },
    anchor,
    transactions: Object.fromEntries(Object.entries(journal.steps).map(([k, v]) => [k, { hash: v.hash, block: v.block ?? null }])),
    generatedAt: new Date().toISOString(),
  };
  await writeAtomic(options.out, report);
  return report;
}

export function parseArgs(argv) {
  let mode = null, out = resolve(HERE, "artifacts/receivable-anchor.json"), journal = JOURNAL_PATH;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--check") { mode = "check"; continue; }
    if (argv[index] === "--run") { mode = "run"; continue; }
    if (argv[index] === "--out" && argv[index + 1]) { out = resolve(process.cwd(), argv[++index]); continue; }
    if (argv[index] === "--journal" && argv[index + 1]) { journal = resolve(process.cwd(), argv[++index]); continue; }
  }
  if (!mode) fail("ANCHOR_MODE_REQUIRED");
  return { mode, out, journal };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    const report = await run();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, code: error.code ?? error.message })}\n`);
    process.exitCode = 1;
  }
}
