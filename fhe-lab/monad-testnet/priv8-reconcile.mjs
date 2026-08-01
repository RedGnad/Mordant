// Reconciles the interrupted M-PRIV8 journal against Monad chain state.
//
// It answers three questions and refuses to guess at any of them:
//   1. does every journalled hash exist on-chain, and with what status;
//   2. does the deployer's transaction count exceed the highest journalled
//      nonce, which would mean a broadcast the journal never recorded;
//   3. are there nonces consumed by any sender that the journal does not name.

import { readFile, writeFile } from "node:fs/promises";
import { createPublicClient, defineChain, http, getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const JOURNAL = process.argv[2];
const env = {};
for (const line of (await readFile("/Users/red.g/CascadeProjects/Master/Mordant/.env", "utf8")).split("\n")) {
  const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
}
const chain = defineChain({
  id: 10_143, name: "Monad testnet",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: [env.FHE_MONAD_RPC_URL] } },
});
const client = createPublicClient({ chain, transport: http(env.FHE_MONAD_RPC_URL) });

// The RPC caps reads at roughly 15/sec, so every call goes through one throttle.
let last = 0;
async function throttled(work, attempt = 0) {
  const wait = Math.max(0, 80 - (Date.now() - last));
  if (wait > 0) await new Promise((done) => setTimeout(done, wait));
  last = Date.now();
  try {
    return await work();
  } catch (error) {
    if (attempt >= 5) throw error;
    await new Promise((done) => setTimeout(done, 400 * (attempt + 1)));
    return throttled(work, attempt + 1);
  }
}

const journal = JSON.parse(await readFile(JOURNAL, "utf8"));
const deployerKey = env.FHE_MONAD_DEPLOYER_PRIVATE_KEY;
const deployer = privateKeyToAccount(deployerKey).address;

const rows = [];
for (const [name, entry] of Object.entries(journal.steps)) {
  if (!entry?.hash) { rows.push({ name, hash: null, note: "no hash recorded" }); continue; }
  const transaction = await throttled(() => client.getTransaction({ hash: entry.hash }).catch(() => null));
  const receipt = await throttled(() => client.getTransactionReceipt({ hash: entry.hash }).catch(() => null));
  rows.push({
    name,
    hash: entry.hash,
    journalStatus: entry.status ?? null,
    onChain: Boolean(transaction),
    sender: transaction ? getAddress(transaction.from) : null,
    nonce: transaction ? Number(transaction.nonce) : null,
    receiptStatus: receipt ? receipt.status : null,
    block: receipt ? String(receipt.blockNumber) : null,
    contractAddress: receipt?.contractAddress ? getAddress(receipt.contractAddress) : null,
    journalContract: entry.contractAddress ?? null,
  });
}

// Every sender the journal used, and whether its on-chain nonce is fully
// explained by journalled transactions.
const senders = new Map();
for (const row of rows) {
  if (!row.sender) continue;
  if (!senders.has(row.sender)) senders.set(row.sender, new Set());
  senders.get(row.sender).add(row.nonce);
}
const senderReport = [];
for (const [address, nonces] of senders) {
  const count = await throttled(() => client.getTransactionCount({ address }));
  const highest = Math.max(...nonces);
  const missing = [];
  for (let index = 0; index < count; index += 1) if (!nonces.has(index)) missing.push(index);
  senderReport.push({
    address,
    onChainTransactionCount: count,
    journalledNonces: [...nonces].sort((a, b) => a - b),
    highestJournalledNonce: highest,
    noncesConsumedButNotJournalled: missing,
    unexplainedTail: count - 1 > highest ? { from: highest + 1, to: count - 1 } : null,
  });
}
const deployerCount = await throttled(() => client.getTransactionCount({ address: deployer }));

const report = {
  journal: JOURNAL,
  chainId: await throttled(() => client.getChainId()),
  deployer,
  deployerTransactionCount: deployerCount,
  steps: rows,
  senders: senderReport,
  summary: {
    stepsJournalled: rows.length,
    stepsOnChain: rows.filter((row) => row.onChain).length,
    stepsMissingFromChain: rows.filter((row) => row.hash && !row.onChain).map((row) => row.name),
    stepsReverted: rows.filter((row) => row.receiptStatus === "reverted").map((row) => row.name),
    stepsWithoutStatusInJournal: rows.filter((row) => row.hash && row.journalStatus !== "success").map((row) => row.name),
    contractAddressMismatch: rows.filter((row) => row.contractAddress && row.journalContract && row.contractAddress !== getAddress(row.journalContract)).map((row) => row.name),
  },
};
await writeFile(process.argv[3], `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report.summary, null, 2));
console.log("senders:", JSON.stringify(report.senders, null, 2));
