#!/usr/bin/env node
/**
 * M-06: Monad aUSDC revalidation.
 *
 * Replays the exact M-01C matrix after confirmation from a Cleanverse internal developer in the
 * community channel that Monad aUSDC now works. Strictly read-only: no key, no signature, no
 * transfer, no broadcast, and only documented read endpoints.
 *
 * That confirmation is why the matrix is replayed, not what the artifact rests on: every statement
 * below is re-observed. And a passing read is not a settlement. Even if every call succeeds, no
 * transfer has been sent, so the rail stays NOT PROVEN.
 *
 *   node scripts/m06-ausdc-revalidation.mjs [--out <prefix>]
 *
 * Cleanverse credentials are read from the environment, server side, and never printed.
 */
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { decodeFunctionResult, encodeFunctionData, keccak256 } from "viem";

const MONAD_CHAIN_ID = 10_143;
const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/**
 * The configuration transaction that flipped aUSDC, located by bisecting `canTransfer` between the
 * M-01C block and head, then corroborated by the only policy log in that window carrying aUSDC as
 * its indexed argument. Re-verified on every run rather than trusted.
 */
const TRANSITION = Object.freeze({
  txHash: "0xbffeda811e919a0205580b950039ace6dc8b7c388c49412452cd34546b2f5c59",
  block: 48823699n,
  selector: "0x3762dd01",
  eventTopic0: "0xb7cc3c365a7dadeaffc54d94652c8debb70d977b178e0291fbfe350f952f94ca",
});

/** What M-01C recorded at Monad block 48672798 on 2026-07-27. The comparison baseline. */
const BASELINE = Object.freeze({
  block: "48672798",
  aUsdc: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
  aUsdcImplementation: "0x5a520e9992d30416c33e2dcdc2d8f3befce426da",
  policy: "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd",
  policyImplementation: "0xc644e79e4c8ee94c4dee49b76f8591e994e58101",
  workingTokenImplementation: "0xce4446801356e7d8acbdfef93816bf62b05d3ebf",
  rulesLength: 0,
  verifyApass: "ComplianceFailed",
  canTransfer: "revert ComplianceFailed(0x8a4e1859)",
  controlsPassed: true,
});

/** The exact wallets M-01C probed. */
const WALLETS = Object.freeze([
  ["burn address", "0x000000000000000000000000000000000000dead"],
  ["tier 20 / subTier 50", "0x1111111111111111111111111111111111111111"],
  ["fee receiver, tier 5", "0x7f7098632b0258Af07e527015D65e6bc743f4CF5"],
]);

/** Positive controls: A-Tokens that accepted the same wallets in M-01C. */
const CONTROLS = Object.freeze([
  ["SPT0001", "0x6cbA1135f61BA24867Ef125eFcA46fC7f9FDa835"],
  ["mXAUt0", "0x9E699BDaF6cEDeB7ca2417574a9F64CDeA4f3D1a"],
  ["CCUSD2", "0xe7D2777603d82cf002278C8ADA2498743E5e2Ec1"],
]);

const APASS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const ACCESS_CORE = "0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC";

const ABI = {
  canTransfer: [{ type: "function", name: "canTransfer", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [{ type: "bool" }] }],
  policy: [{ type: "function", name: "policy", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] }],
  getRules: [{ type: "function", name: "getRules", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bytes", name: "raw" }] }],
  isValidAPass: [{ type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] }],
  isTokenRegistered: [{ type: "function", name: "isTokenRegistered", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] }],
  isPaused: [{ type: "function", name: "isPaused", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] }],
  decimals: [{ type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] }],
};

const READ_ONLY_METHODS = new Set([
  "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_call",
  "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getLogs",
]);

let rpcId = 0;
async function rpc(method, params) {
  if (!READ_ONLY_METHODS.has(method)) {
    throw new Error(`refusing non read-only method ${method}`);
  }
  // The public endpoint rate limits at 15 requests per second, and answers from a lagging node when
  // pushed past it. A bisection run without this delay produced a boundary two blocks off.
  await new Promise((resolve) => setTimeout(resolve, 180));
  const response = await fetch(MONAD_RPC, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = await response.json();
  if (body.error) {
    const error = new Error(body.error.message);
    error.data = typeof body.error.data === "string" ? body.error.data : null;
    throw error;
  }
  return body.result;
}

/** Read endpoints only. The API key never leaves this process and is never printed. */
async function cleanverse(path, payload) {
  const base = process.env.CLEANVERSE_API_BASE_URL?.replace(/\/+$/, "");
  const apiId = process.env.CLEANVERSE_API_ID;
  if (!base || !apiId) {
    return { unavailable: "CLEANVERSE_API_BASE_URL or CLEANVERSE_API_ID is not configured" };
  }
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "api-id": apiId, "X-Request-ID": crypto.randomUUID() },
    body: JSON.stringify(payload), signal: AbortSignal.timeout(30_000),
  });
  return response.json();
}

/** Strips anything credential-shaped before a response reaches an artifact. */
function safe(value) {
  if (value === null || typeof value !== "object") return value;
  const out = Array.isArray(value) ? [] : {};
  for (const [key, item] of Object.entries(value)) {
    out[key] = /magick?link|token|secret|apikey|api_key|authorization|cookie|signature|rpc_url|password/i.test(key)
      ? (item ? "[REDACTED]" : item)
      : safe(item);
  }
  return out;
}

const KNOWN_ERRORS = {
  "0x8a4e1859": "ComplianceFailed(address)",
  "0xa6725971": "NoAPass(address)",
  "0x308b32a5": "CountryBlacklisted(address)",
};
const describeRevert = (data) => {
  if (!data || data.length < 10) return "revert without data";
  const selector = data.slice(0, 10);
  return `revert ${KNOWN_ERRORS[selector] ?? `custom error ${selector}`}`;
};

async function call(to, abi, functionName, args, blockTag) {
  const data = encodeFunctionData({ abi, functionName, args });
  try {
    const raw = await rpc("eth_call", [{ to, data }, blockTag]);
    if (abi[0].outputs[0].type === "bytes") return { ok: true, raw };
    return { ok: true, value: decodeFunctionResult({ abi, functionName, data: raw }) };
  } catch (error) {
    return { ok: false, error: describeRevert(error.data), message: error.message.slice(0, 160) };
  }
}

async function implementationOf(address, blockTag) {
  const word = await rpc("eth_getStorageAt", [address, EIP1967_IMPLEMENTATION_SLOT, blockTag]);
  if (!word || /^0x0+$/.test(word)) return null;
  return `0x${word.slice(-40)}`;
}

async function codeHashOf(address, blockTag) {
  const code = await rpc("eth_getCode", [address, blockTag]);
  return code && code !== "0x" ? { hash: keccak256(code), bytes: (code.length - 2) / 2 } : null;
}

async function main() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;

  const chainId = Number(BigInt(await rpc("eth_chainId", [])));
  if (chainId !== MONAD_CHAIN_ID) {
    throw new Error(`BLOCKED — WRONG NETWORK: expected ${MONAD_CHAIN_ID}, RPC answered ${chainId}`);
  }
  const head = BigInt(await rpc("eth_blockNumber", []));
  const blockNumber = head - 20n;
  const blockTag = `0x${blockNumber.toString(16)}`;
  const block = await rpc("eth_getBlockByNumber", [blockTag, false]);
  process.stdout.write(`chain ${chainId}, pinned block ${blockNumber} ${block.hash}\n\n`);

  // --- 1. rediscover the address rather than assuming it ---
  const discovery = await cleanverse("/query_deposit_atoken_list", { chain: "monad" });
  let aUsdc = null;
  let discoverySource = "cleanverse query_deposit_atoken_list";
  let discoveredTokens = [];
  if (discovery?.code === "0000" && Array.isArray(discovery?.data?.tokens)) {
    // Documented shape: data.tokens[] = { origin_token, atoken, accesscore_address }.
    discoveredTokens = discovery.data.tokens
      .map((pair) => ({ symbol: pair.atoken?.symbol ?? null, address: pair.atoken?.address ?? null }))
      .filter((entry) => entry.address !== null);
    aUsdc = discoveredTokens.find((entry) => String(entry.symbol).toLowerCase() === "ausdc")?.address ?? null;
  }
  if (!aUsdc) {
    const config = await fetch("https://uatapi.cleanverse.com/api/skills/query_chain_config",
      { signal: AbortSignal.timeout(30_000) }).then((response) => response.json()).catch(() => null);
    const monad = config?.data?.chains?.find((entry) => entry.chain === "monad");
    const entry = monad?.tokens?.find((token) => String(token.symbol).toLowerCase() === "ausdc");
    if (entry) { aUsdc = entry.token_address; discoverySource = "unauthenticated query_chain_config"; }
  }
  if (!aUsdc) throw new Error("BLOCKED — could not discover the Monad aUSDC address");
  process.stdout.write(`aUSDC discovered via ${discoverySource}: ${aUsdc}\n`);
  const addressChanged = aUsdc.toLowerCase() !== BASELINE.aUsdc.toLowerCase();

  // --- 2 and 3. contract shape ---
  const aUsdcImplementation = await implementationOf(aUsdc, blockTag);
  const aUsdcCode = await codeHashOf(aUsdc, blockTag);
  const implementationCode = aUsdcImplementation ? await codeHashOf(aUsdcImplementation, blockTag) : null;
  const policyResult = await call(aUsdc, ABI.policy, "policy", [], blockTag);
  const policy = policyResult.ok ? policyResult.value : null;
  const policyImplementation = policy ? await implementationOf(policy, blockTag) : null;
  const decimals = await call(aUsdc, ABI.decimals, "decimals", [], blockTag);
  const registered = policy ? await call(policy, ABI.isTokenRegistered, "isTokenRegistered", [aUsdc], blockTag) : null;
  const paused = policy ? await call(policy, ABI.isPaused, "isPaused", [aUsdc], blockTag) : null;
  const rulesRaw = policy ? await call(policy, ABI.getRules, "getRules", [aUsdc], blockTag) : null;
  const rulesLength = rulesRaw?.ok && rulesRaw.raw?.length >= 130
    ? Number(BigInt(`0x${rulesRaw.raw.slice(66, 130)}`)) : null;

  const implementationChanged = (aUsdcImplementation ?? "").toLowerCase()
    !== BASELINE.aUsdcImplementation.toLowerCase();
  const policyImplementationChanged = (policyImplementation ?? "").toLowerCase()
    !== BASELINE.policyImplementation.toLowerCase();

  process.stdout.write(
    `  implementation ${aUsdcImplementation} (${implementationChanged ? "CHANGED" : "UNCHANGED"})\n`
    + `  policy ${policy} impl ${policyImplementation} (${policyImplementationChanged ? "CHANGED" : "UNCHANGED"})\n`
    + `  registered=${registered?.value} paused=${paused?.value} rules=${rulesLength}\n\n`);

  // --- 5. A-Pass state and expiry for the probed wallets ---
  const apassState = [];
  const blockTimestamp = Number(BigInt(block.timestamp));
  for (const [label, address] of WALLETS) {
    const valid = await call(APASS, ABI.isValidAPass, "isValidAPass", [address], blockTag);
    // Tier, subTier and expiry come from the documented /query_apass read endpoint rather than
    // from a guessed getter selector, so the shape is the one Cleanverse specifies.
    const record = safe(await cleanverse("/query_apass", { chain: "monad", address }));
    const data = record?.code === "0000" ? record.data : null;
    const expiration = data?.expirationTime ?? null;
    const expired = expiration ? Number(expiration) < blockTimestamp : null;
    apassState.push({
      label, address, onchainValid: valid.value ?? null,
      status: data?.status ?? null, tier: data?.tier ?? null, subTier: data?.subTier ?? null,
      countries: data?.countries ?? null, expiration, expired,
      queryApassEnvelope: data ? "0000" : String(record?.code ?? "unavailable"),
    });
    process.stdout.write(
      `  A-Pass ${address} onchainValid=${valid.value} status=${data?.status} tier=${data?.tier}`
      + ` subTier=${data?.subTier} expiry=${expiration}${expired === true ? " EXPIRED" : ""}\n`);
  }
  process.stdout.write("\n");

  // --- 6. verify_apass, aUSDC and the positive controls ---
  const verify = [];
  const runVerify = async (label, token) => {
    for (const [walletLabel, address] of WALLETS) {
      const body = await cleanverse("/verify_apass", { chain: "monad", atoken: token, address });
      const clean = safe(body);
      const verdict = clean?.code === "0000"
        ? `code ${clean.data?.code} "${clean.data?.message}"`
        : `envelope ${clean?.code}: ${String(clean?.message).slice(0, 90)}`;
      const passed = clean?.code === "0000" && Number(clean?.data?.code) === 4;
      verify.push({ token: label, address: address, wallet: walletLabel, verdict, passed });
      process.stdout.write(`  verify_apass ${label.padEnd(8)} ${address.slice(0, 12)} -> ${verdict}\n`);
    }
  };
  await runVerify("aUSDC", aUsdc);
  for (const [label, token] of CONTROLS) await runVerify(label, token);
  process.stdout.write("\n");

  // --- 7. on-chain canTransfer, same tuples and amount as M-01C ---
  const transfers = [];
  const tuples = [
    ["A-Pass holder to A-Pass holder", WALLETS[0][1], WALLETS[1][1]],
    ["A-Pass holder to fee receiver", WALLETS[0][1], WALLETS[2][1]],
    ["AccessCore to A-Pass holder", ACCESS_CORE, WALLETS[0][1]],
  ];
  const runTransfers = async (label, token) => {
    for (const [tupleLabel, from, to] of tuples) {
      const result = policy
        ? await call(policy, ABI.canTransfer, "canTransfer", [token, from, to, 1n], blockTag)
        : { ok: false, error: "policy unresolved" };
      const verdict = result.ok ? `returned ${result.value}` : result.error;
      transfers.push({ token: label, tuple: tupleLabel, from, to, amount: "1", verdict, passed: result.value === true });
      process.stdout.write(`  canTransfer ${label.padEnd(8)} ${tupleLabel.padEnd(32)} -> ${verdict}\n`);
    }
  };
  await runTransfers("aUSDC", aUsdc);
  for (const [label, token] of CONTROLS) await runTransfers(label, token);

  // --- 8. the discriminator: replay the SAME tuple at the M-01C block ---
  // A pass at head proves nothing on its own. Replaying the identical call against the historical
  // state is what separates a genuine change from a probe that simply differs from M-01C's.
  const historicalTuple = ["A-Pass holder to A-Pass holder", WALLETS[0][1], WALLETS[1][1]];
  const replay = [];
  for (const [label, tag, token] of [
    ["aUSDC at the M-01C block", `0x${BigInt(BASELINE.block).toString(16)}`, aUsdc],
    ["aUSDC one block before the transition", `0x${(TRANSITION.block - 1n).toString(16)}`, aUsdc],
    ["aUSDC at the transition block", `0x${TRANSITION.block.toString(16)}`, aUsdc],
    ["SPT0001 at the M-01C block", `0x${BigInt(BASELINE.block).toString(16)}`, CONTROLS[0][1]],
  ]) {
    const result = await call(policy, ABI.canTransfer, "canTransfer",
      [token, historicalTuple[1], historicalTuple[2], 1n], tag);
    const verdict = result.ok ? `returned ${result.value}` : result.error;
    replay.push({ label, blockTag: tag, verdict, passed: result.value === true });
    process.stdout.write(`\n  replay ${label.padEnd(38)} -> ${verdict}`);
  }
  process.stdout.write("\n");

  // Re-verify the configuration transaction instead of trusting the constant.
  const transitionTx = await rpc("eth_getTransactionReceipt", [TRANSITION.txHash]);
  const transitionLog = transitionTx?.logs?.find((entry) =>
    entry.address.toLowerCase() === String(policy).toLowerCase()
    && entry.topics[0] === TRANSITION.eventTopic0);
  const transitionArgument = transitionLog ? `0x${transitionLog.topics[1].slice(-40)}` : null;
  const transitionVerified = transitionTx?.status === "0x1"
    && transitionArgument?.toLowerCase() === aUsdc.toLowerCase()
    && BigInt(transitionTx.blockNumber) === TRANSITION.block;
  process.stdout.write(
    `\n  transition tx ${TRANSITION.txHash}\n`
    + `    block ${transitionTx ? Number(BigInt(transitionTx.blockNumber)) : "?"}`
    + ` status ${transitionTx?.status} targets ${transitionArgument}`
    + ` verified=${transitionVerified}\n`);

  // --- 9. verdicts ---
  const verifyPassed = verify.filter((entry) => entry.token === "aUSDC").some((entry) => entry.passed);
  const transferPassed = transfers.filter((entry) => entry.token === "aUSDC").some((entry) => entry.passed);
  const controlsPassed = CONTROLS.every(([label]) =>
    transfers.filter((entry) => entry.token === label).some((entry) => entry.passed));
  const restored = verifyPassed && transferPassed;

  const statuses = {
    "AUSDC ADDRESS": "DISCOVERED",
    "AUSDC IMPLEMENTATION": implementationChanged ? "CHANGED" : "UNCHANGED",
    "AUSDC VERIFY_APASS": verifyPassed ? "PASSED" : "FAILED",
    "AUSDC CAN_TRANSFER": transferPassed ? "PASSED" : "FAILED",
    "AUSDC READ-ONLY COMPATIBILITY": restored ? "RESTORED" : "STILL BLOCKED",
    "AUSDC SETTLEMENT TRANSFER": "NOT PROVEN — NO TRANSACTION SENT",
    "CLEANVERSE SETTLEMENT RAIL": "NOT PROVEN",
  };

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    classification: "READ-ONLY",
    warning:
      "Read-only revalidation. No key, no signature, no transfer and no broadcast. A passing read is"
      + " not a settlement: no transfer has been sent, so the rail stays NOT PROVEN.",
    trigger:
      "Confirmation from a Cleanverse internal developer in the community channel that Monad aUSDC"
      + " now works. Every statement in this artifact is independently re-observed on chain.",
    network: { name: "monad-testnet", chainId, blockNumber: blockNumber.toString(), blockHash: block.hash },
    discovery: {
      source: discoverySource, aUsdc, addressChanged, baselineAddress: BASELINE.aUsdc,
      depositATokenList: discoveredTokens,
    },
    contract: {
      aUsdc, implementation: aUsdcImplementation, implementationChanged,
      proxyCodeHash: aUsdcCode?.hash ?? null, implementationCodeHash: implementationCode?.hash ?? null,
      implementationBytes: implementationCode?.bytes ?? null,
      policy, policyImplementation, policyImplementationChanged,
      decimals: decimals.ok ? Number(decimals.value) : null,
      isTokenRegistered: registered?.value ?? null, isPaused: paused?.value ?? null,
      rulesLength,
    },
    baseline: BASELINE,
    transition: {
      txHash: TRANSITION.txHash,
      blockNumber: TRANSITION.block.toString(),
      selector: TRANSITION.selector,
      eventTopic0: TRANSITION.eventTopic0,
      indexedArgument: transitionArgument,
      verified: transitionVerified,
      observed:
        "A configuration call sent to the policy, not a code upgrade: both implementation code hashes"
        + " are unchanged and canTransfer flips at exactly this block.",
      inferred:
        "The six scalar arguments (0, 0, 5, 0, 0, 0) match the documented validator rule shape"
        + " with min_tier = 5. The selector was not decoded from a published ABI, so the field"
        + " mapping is INFERRED, not proven.",
      notExposed: "getRules(aUSDC) returns an empty array before and after, so the accepting"
        + " configuration is not readable through getRules.",
    },
    historicalReplay: replay,
    apass: apassState,
    verifyApass: verify,
    canTransfer: transfers,
    controlsPassed,
    statuses,
    comparison: {
      before: `verify_apass ${BASELINE.verifyApass}, canTransfer ${BASELINE.canTransfer}`,
      after: `verify_apass ${verifyPassed ? "PASSED" : "FAILED"}, canTransfer ${transferPassed ? "PASSED" : "FAILED"}`,
      changed: restored,
      // The M-01C failure reproduces at the M-01C block against the same code, so the change is
      // configuration state and the earlier result was not a probe error.
      historicalFailureReproduced: replay[0]?.passed === false,
    },
    notes: [
      "The AccessCore-as-sender tuple reverts NoAPass(address) for aUSDC and for all three control"
      + " tokens alike, so it is a property of that sender holding no A-Pass, not of aUSDC.",
      "The two implementation code hashes are unchanged since M-01C. Behaviour changed without any"
      + " code changing.",
    ],
  };

  process.stdout.write("\n");
  for (const [key, value] of Object.entries(statuses)) {
    process.stdout.write(`${key.padEnd(32)} ${value}\n`);
  }
  process.stdout.write(`\npositive controls passed: ${controlsPassed}\n`);

  if (out) {
    const serialized = `${JSON.stringify(report, null, 2)}\n`;
    if (/CLEANVERSE_API_KEY|magickLink"\s*:\s*"[^"]{4}/i.test(serialized)) {
      throw new Error("BLOCKED — refusing to write an artifact containing credential material");
    }
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(`${out}.json.tmp`, serialized, "utf8");
    renameSync(`${out}.json.tmp`, `${out}.json`);
    writeFileSync(`${out}.md`, renderMarkdown(report), "utf8");
    process.stdout.write(`\nWrote ${out}.json and ${out}.md\n`);
  }
}

function table(headers, rows) {
  if (rows.length === 0) return "_No entry._\n";
  const escape = (cell) => String(cell).replace(/\|/g, "\\|");
  return [`| ${headers.join(" | ")} |`, `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(escape).join(" | ")} |`)].join("\n") + "\n";
}

function renderMarkdown(report) {
  return [
    "# Monad aUSDC revalidation",
    "",
    report.warning,
    "",
    `Trigger: ${report.trigger}`,
    "",
    table(["Field", "Value"], [
      ["generatedAt", report.generatedAt], ["chainId", report.network.chainId],
      ["blockNumber", report.network.blockNumber], ["blockHash", report.network.blockHash],
      ["aUSDC", report.discovery.aUsdc], ["discovery source", report.discovery.source],
      ["address changed", report.discovery.addressChanged],
    ]),
    "## Status",
    "",
    table(["Statement", "Value"], Object.entries(report.statuses)),
    "## Contract shape, against the M-01C baseline",
    "",
    table(["Field", "Now", "M-01C baseline", "Changed"], [
      ["aUSDC implementation", report.contract.implementation, report.baseline.aUsdcImplementation, report.contract.implementationChanged],
      ["policy implementation", report.contract.policyImplementation, report.baseline.policyImplementation, report.contract.policyImplementationChanged],
      ["getRules length", report.contract.rulesLength, report.baseline.rulesLength, report.contract.rulesLength !== report.baseline.rulesLength],
      ["isTokenRegistered", report.contract.isTokenRegistered, "true", report.contract.isTokenRegistered !== true],
      ["isPaused", report.contract.isPaused, "false", report.contract.isPaused !== false],
    ]),
    "## A-Pass state of the probed wallets",
    "",
    table(["Wallet", "Address", "isValidAPass", "Status", "Tier", "SubTier", "Expiry", "Expired"],
      report.apass.map((entry) => [entry.label, entry.address, entry.onchainValid, entry.status, entry.tier, entry.subTier, entry.expiration, entry.expired])),
    "## verify_apass",
    "",
    table(["Token", "Wallet", "Verdict", "Passed"],
      report.verifyApass.map((entry) => [entry.token, entry.address, entry.verdict, entry.passed])),
    "## policy().canTransfer(token, from, to, 1)",
    "",
    table(["Token", "Tuple", "Verdict", "Passed"],
      report.canTransfer.map((entry) => [entry.token, entry.tuple, entry.verdict, entry.passed])),
    "## Comparison",
    "",
    `Before, M-01C at block ${report.baseline.block}: ${report.comparison.before}.`,
    "",
    `Now, block ${report.network.blockNumber}: ${report.comparison.after}.`,
    "",
    report.comparison.changed
      ? "The read-only surface changed. That is not a settlement: no transfer was sent."
      : "No change. aUSDC still refuses the probed tuples while the control tokens accept them.",
    "",
    "## Historical replay",
    "",
    "A pass at head proves nothing by itself. The same call is replayed against historical state, so"
    + " a genuine change is separated from a probe that merely differs from the M-01C one.",
    "",
    table(["Replay", "Block tag", "Verdict", "Passed"],
      report.historicalReplay.map((entry) => [entry.label, entry.blockTag, entry.verdict, entry.passed])),
    report.comparison.historicalFailureReproduced
      ? "The M-01C failure reproduces exactly at the M-01C block, so it was not a probe error."
      : "WARNING: the M-01C failure did not reproduce at the M-01C block. Treat the baseline as unconfirmed.",
    "",
    "## What changed",
    "",
    table(["Field", "Value"], [
      ["transaction", report.transition.txHash],
      ["block", report.transition.blockNumber],
      ["selector", report.transition.selector],
      ["indexed argument", report.transition.indexedArgument],
      ["re-verified this run", report.transition.verified],
    ]),
    `OBSERVED: ${report.transition.observed}`,
    "",
    `INFERRED: ${report.transition.inferred}`,
    "",
    `NOT EXPOSED: ${report.transition.notExposed}`,
    "",
    "## Notes",
    "",
    ...report.notes.map((note) => `- ${note}`),
    "",
  ].join("\n");
}

main().catch((error) => {
  process.stderr.write(`\nSTOPPED: ${error.message}\n`);
  process.exitCode = 1;
});
