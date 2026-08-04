#!/usr/bin/env node

// Bounded Monad testnet non-regression for private matching V4, run from main.
//
// Read-only by construction: it opens no wallet, holds no key and sends no
// transaction. Every negative is an `eth_call`. The point is to prove that the
// merged main tree still describes the chain it claims to describe — that the
// contracts on main compile to the bytecode that is actually deployed, and that
// the published evidence still reads back off the live chain.
//
// It reads the published evidence bundle rather than a run journal, because the
// journal is a run artifact and is deliberately not tracked.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, defineChain, http, getAddress, keccak256 } from "viem";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BUNDLE = resolve(REPO, "docs/evidence/private-matching-v4");
const EXPECTED_CHAIN_ID = 10_143;

const bundle = async (name) => JSON.parse(await readFile(resolve(BUNDLE, name), "utf8"));

const env = {};
for (const line of (await readFile(resolve(REPO, ".env"), "utf8").catch(() => ""))?.split("\n") ?? []) {
  const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
}
const rpc = process.env.FHE_MONAD_RPC_URL ?? env.FHE_MONAD_RPC_URL;
if (!rpc) {
  process.stderr.write("NON_REGRESSION_SKIPPED: no FHE_MONAD_RPC_URL\n");
  process.exit(2);
}

const chain = defineChain({
  id: EXPECTED_CHAIN_ID, name: "Monad testnet",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: [rpc] } },
});

// The public RPC answers a burst with an error rather than a queue, so every
// read goes through one pacer.
let last = 0;
const original = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const wait = Math.max(0, 90 - (Date.now() - last));
  if (wait > 0) await new Promise((done) => setTimeout(done, wait));
  last = Date.now();
  return original(input, init);
};
const client = createPublicClient({ chain, transport: http(rpc, { batch: false, retryCount: 8, retryDelay: 400 }) });

const abi = async (name, file) =>
  JSON.parse(await readFile(resolve(REPO, `contracts/out/${file}/${name}.json`), "utf8"));

const checks = [];
const check = (name, ok, detail) => { checks.push({ name, ok: Boolean(ok), detail }); };

/* ------------------------------------------------------------------ chain */

const transactions = await bundle("transactions.json");
const readbacks = await bundle("readbacks.json");
const codeHashes = await bundle("code-hashes.json");

const onChainId = await client.getChainId();
check("chain is Monad testnet", onChainId === EXPECTED_CHAIN_ID, `chainId ${onChainId}`);

/* ----------------------------- deployed bytecode still matches main's tree */

// Blank exactly the immutable spans named by each artifact, then compare.
const blank = (hex, spans) => {
  const bytes = Buffer.from(hex.slice(2), "hex");
  for (const span of spans) bytes.fill(0, span.start, span.start + span.length);
  return bytes.toString("hex");
};

const GUARDED = [
  ["MordantScopeGovernanceRegistry", "MordantScopeGovernanceRegistry.sol", transactions.deployments.governance],
  ["ECDSAQuorumMatchVerifierV4", "ECDSAQuorumMatchVerifierV4.sol", transactions.deployments.verifier],
  ["PrivateMatchBinder", "PrivateMatchBinder.sol", transactions.deployments.binder],
  ["MordantFactoryV2", "MordantFactoryV2.sol", transactions.deployments.factory],
  ["MordantSourceIdentityRegistry", "MordantSourceIdentityRegistry.sol", transactions.deployments.sources],
  ["MordantIssuerRegistry", "MordantIssuerRegistry.sol", transactions.deployments.issuerRegistry],
  ["MordantInvoiceVaultV2", "MordantInvoiceVaultV2.sol", transactions.anchor.vault],
];

for (const [name, file, address] of GUARDED) {
  const artifact = await abi(name, file);
  const spans = Object.values(artifact.deployedBytecode.immutableReferences ?? {}).flat();
  const deployed = await client.getBytecode({ address: getAddress(address) });
  const same = deployed !== undefined
    && blank(deployed, spans) === blank(artifact.deployedBytecode.object, spans);
  check(`${name} on chain matches main's compiled artifact`, same, address);
}

// And the published code hashes still describe the same chain state.
for (const entry of codeHashes.contracts) {
  if (!entry.address) continue;
  const deployed = await client.getBytecode({ address: getAddress(entry.address) });
  check(
    `${entry.contract} code hash unchanged since the evidence run`,
    deployed !== undefined && keccak256(deployed) === entry.onChainCodeHash,
    entry.address,
  );
}

/* ------------------------------------------------------- evidence readback */

const binderAbi = (await abi("PrivateMatchBinder", "PrivateMatchBinder.sol")).abi;
const verifierAbi = (await abi("ECDSAQuorumMatchVerifierV4", "ECDSAQuorumMatchVerifierV4.sol")).abi;
const governanceAbi = (await abi("MordantScopeGovernanceRegistry", "MordantScopeGovernanceRegistry.sol")).abi;
const vaultAbi = (await abi("MordantInvoiceVaultV2", "MordantInvoiceVaultV2.sol")).abi;

const binder = getAddress(transactions.deployments.binder);
const verifier = getAddress(transactions.deployments.verifier);
const governance = getAddress(transactions.deployments.governance);
const vault = getAddress(transactions.anchor.vault);
const session = transactions.sessionCommitment;

const record = await client.readContract({
  address: binder, abi: binderAbi, functionName: "recourseOf", args: [session],
});
const published = readbacks.recourseRecord;
check("recourse record still open", record.open === true);
check("recourse session commitment unchanged", record.sessionCommitment === published.sessionCommitment);
check("recourse result commitment unchanged", record.resultCommitment === published.resultCommitment);
check("recourse match commitment unchanged", record.matchCommitment === published.matchCommitment);
check("recourse anchor commitment unchanged", record.anchorCommitment === published.anchorCommitment);
check("recourse counterparty commitment unchanged", record.counterpartyCommitment === published.counterpartyCommitment);
check("recourse anchor unchanged", getAddress(record.anchor) === getAddress(published.anchor));
check("conflict still recorded", record.conflictConfirmed === true);
check(
  "cure deadline still derived on-chain",
  Number(record.cureDeadline) - Number(record.boundAt) === 3600,
  `${Number(record.cureDeadline) - Number(record.boundAt)}s`,
);

const anchorLive = await client.readContract({
  address: binder, abi: binderAbi, functionName: "anchorLive", args: [session],
});
check("anchor still live", anchorLive === true);
check(
  "anchor still Outstanding with active protection",
  Number(await client.readContract({ address: vault, abi: vaultAbi, functionName: "receivableState" })) === 1
    && Number(await client.readContract({ address: vault, abi: vaultAbi, functionName: "protectionState" })) === 1,
);

/* ------------------------------------------------- one-time identities held */

const commitment = await client.readContract({
  address: governance, abi: governanceAbi, functionName: "commitment", args: [session],
});
check("session commitment still consumed", commitment.consumed === true);
check("session commitment submitter unchanged", getAddress(commitment.submitter) === getAddress(transactions.commitment.relayer));

for (const [label, fn, arg] of [
  ["match commitment", "consumedMatchCommitments", published.matchCommitment],
  ["provider proof commitment", "consumedProviderProofCommitments", published.providerProofCommitment],
]) {
  const consumed = await client.readContract({ address: verifier, abi: verifierAbi, functionName: fn, args: [arg] });
  check(`${label} still consumed`, consumed === true);
}

/* ------------------------------------------------------ replay still refused */

// A bare re-bind attempt with the published session must still revert. This is
// an eth_call: nothing is broadcast.
let replayRejected = false;
let replayError = null;
try {
  await client.simulateContract({
    address: binder, abi: binderAbi, functionName: "recourseOf", args: [session],
  });
  // recourseOf is a view; the meaningful negative is that the session is bound
  // and its commitment consumed, both asserted above. Additionally confirm the
  // registry refuses to re-publish the same commitment.
  await client.simulateContract({
    address: governance, abi: governanceAbi, functionName: "commitSession", args: [session],
    account: getAddress(transactions.commitment.relayer),
  });
} catch (error) {
  replayRejected = true;
  replayError = String(error?.shortMessage ?? error?.message ?? error).split("\n")[0].slice(0, 120);
}
check("re-publishing the same session commitment is refused", replayRejected, replayError);

/* -------------------------------------------------------------------- report */

const failed = checks.filter((entry) => !entry.ok);
const report = {
  schema: "mordant.private-matching.non-regression/1",
  ranAt: new Date().toISOString(),
  network: { name: "Monad testnet", chainId: onChainId },
  readOnly: true,
  transactionsSent: 0,
  sessionCommitment: session,
  checks,
  passed: checks.length - failed.length,
  total: checks.length,
  ok: failed.length === 0,
};

const out = process.argv[2];
if (out) await writeFile(out, `${JSON.stringify(report, null, 2)}\n`);

for (const entry of checks) {
  process.stdout.write(`${entry.ok ? "ok  " : "FAIL"}  ${entry.name}${entry.detail ? `  (${entry.detail})` : ""}\n`);
}
process.stdout.write(`\n${report.passed}/${report.total} checks passed, ${report.transactionsSent} transactions sent\n`);
if (!report.ok) {
  process.stderr.write("NON_REGRESSION_FAILED\n");
  process.exitCode = 1;
}
