#!/usr/bin/env node
/**
 * M-07: the smallest possible live aUSDC write proof.
 *
 * One aUSDC transfer between two wallets holding a valid A-Pass. Nothing else.
 * This is deliberately not a Mordant settlement: no vault, no adapter, no pledge, no invoice
 * A-Token. It proves the Cleanverse token rail accepts a real transfer, and that alone.
 *
 *   node --env-file=.env scripts/m07-ausdc-transfer.mjs --check       read-only, the default
 *   node --env-file=.env scripts/m07-ausdc-transfer.mjs --broadcast --out <prefix>
 *
 * In broadcast mode --out is mandatory: a run that can send value must leave an artifact behind,
 * including when it stops. The shared controls in ./runner-controls.mjs enforce the rest.
 *
 * Every gate below is fail-closed and runs before any key is read. If the aUSDC address, the policy,
 * either implementation, the A-Pass state or the precheck differs from what M-06 recorded, the run
 * stops and sends nothing: a changed rail must be re-observed, not transacted against.
 *
 * The signing key belongs to the wallet owner. This runner reads it from the environment and never
 * generates, derives, requests or persists one.
 *
 * No private key, seed phrase or other secret material is logged or persisted. Public addresses,
 * signatures, transaction hashes, blocks and readbacks may be recorded where required.
 */
import { createPublicClient, createWalletClient, http, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  ControlError, DEFAULT_MAX_GAS_PRICE_WEI, assertChainId, assertFundedFor, assertGasUsable,
  assertKeyMatchesAddress, assertWriteAllowed, checkpointPending, scrub, writeArtifact,
} from "./runner-controls.mjs";

const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

/**
 * Pinned from the M-06 artifact, at Monad block 48860447. These are not configuration authority:
 * they are the expectation each run re-observes and refuses to proceed without.
 */
const EXPECTED = Object.freeze({
  aUsdc: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
  aUsdcImplementation: "0x5a520e9992d30416c33e2dcdc2d8f3befce426da",
  policy: "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd",
  policyImplementation: "0xc644e79e4c8ee94c4dee49b76f8591e994e58101",
  decimals: 6,
});

const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * The smallest transfer the token can express: one atomic unit, 0.000001 aUSDC at six decimals.
 * A minimum is the point. A larger amount would prove nothing more and would consume faucet supply.
 */
const TRANSFER_AMOUNT = 1n;

/**
 * Gas ceilings. The estimate is measured against real state at run time and is fail-closed: an
 * estimate that cannot be produced, or that lands outside these bounds, stops the run rather than
 * letting it proceed on a guess. A compliance-checked transfer of one atomic unit measured 319,513
 * gas on 28 July 2026, so the ceiling leaves headroom without being wide enough to hide an
 * unexpected code path.
 */
const GAS_LIMIT_CEILING = 400_000n;

/** The A-Pass status value observed on every accepted wallet in M-01C and M-06. */
const APASS_STATUS_ACTIVE = 1;

const ERC20_ABI = [
  { type: "function", name: "transfer", stateMutability: "nonpayable",
    inputs: [{ name: "to", type: "address" }, { name: "value", type: "uint256" }],
    outputs: [{ type: "bool" }] },
  { type: "function", name: "balanceOf", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
  { type: "function", name: "policy", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "event", name: "Transfer",
    inputs: [{ name: "from", type: "address", indexed: true }, { name: "to", type: "address", indexed: true },
      { name: "value", type: "uint256", indexed: false }] },
];

const POLICY_ABI = [
  { type: "function", name: "canTransfer", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [{ type: "bool" }] },
  { type: "function", name: "isTokenRegistered", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "isPaused", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const APASS_ADDRESS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";

/** Re-exported so callers and tests have one error type to catch across every runner. */
export { ControlError as StopError } from "./runner-controls.mjs";

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/** Fail-closed comparison. Anything other than an exact match halts the run. */
export function assertUnchanged(label, observed, expected) {
  if (String(observed ?? "").toLowerCase() !== String(expected).toLowerCase()) {
    stop(`${label} changed since M-06. Observed ${observed}, expected ${expected}.`
      + " Re-run pnpm revalidate:ausdc and review before transacting.");
  }
}

/** A transfer to yourself would satisfy every gate and prove nothing about the policy. */
export function assertDistinct(sender, recipient) {
  if (!sender || !recipient) stop("sender and recipient must both be configured.");
  if (sender.toLowerCase() === recipient.toLowerCase()) {
    stop("sender and recipient are the same wallet. A self-transfer proves nothing.");
  }
}

/**
 * The A-Pass gate. A successful envelope is not enough: the record must be present, the status
 * active, the expiration present and in the future, and the on-chain credential must agree.
 * Anything missing is treated as absent, never as acceptable.
 */
export function assertAPassUsable(role, address, envelope, onchainValid, blockTimestamp) {
  if (envelope?.code !== "0000") {
    stop(`query_apass did not succeed for ${role} ${address}: envelope ${envelope?.code ?? "none"}.`);
  }
  const data = envelope.data;
  if (!data || typeof data !== "object") {
    stop(`query_apass returned no A-Pass record for ${role} ${address}.`);
  }
  if (Number(data.status) !== APASS_STATUS_ACTIVE) {
    stop(`${role} ${address} has A-Pass status ${data.status}, expected ${APASS_STATUS_ACTIVE}.`);
  }
  const expiration = Number(data.expirationTime);
  if (!Number.isFinite(expiration) || expiration <= 0) {
    stop(`${role} ${address} has no usable A-Pass expiration (${data.expirationTime}).`
      + " An absent expiration is not treated as unlimited.");
  }
  if (expiration <= Number(blockTimestamp)) {
    stop(`${role} ${address} holds an A-Pass that expired at ${expiration},`
      + ` at or before the current block timestamp ${blockTimestamp}.`);
  }
  if (onchainValid !== true) {
    stop(`isValidAPass is ${onchainValid} on chain for ${role} ${address}.`
      + " Issue or repair the A-Pass before attempting a transfer.");
  }
  return { status: Number(data.status), tier: data.tier ?? null, subTier: data.subTier ?? null,
    expirationTime: expiration, secondsRemaining: expiration - Number(blockTimestamp) };
}

/**
 * Rebuilds what actually moved from the aUSDC Transfer events, then reconciles that against the
 * measured balance deltas. Counterparties are discovered from the events: no address is assumed to
 * be the fee receiver, and burns are read as transfers to the zero address.
 *
 * @param events   decoded aUSDC Transfer events, [{ from, to, value }]
 * @param measured address -> measured balance delta, as bigint
 */
export function reconcileTransfer({ events, amount, sender, recipient, measured }) {
  const key = (address) => String(address).toLowerCase();
  const reasons = [];
  if (events.length === 0) reasons.push("no aUSDC Transfer event was emitted");

  const net = new Map();
  for (const event of events) {
    const value = BigInt(event.value);
    net.set(key(event.from), (net.get(key(event.from)) ?? 0n) - value);
    net.set(key(event.to), (net.get(key(event.to)) ?? 0n) + value);
  }

  const senderDebit = -(net.get(key(sender)) ?? 0n);
  const recipientCredit = net.get(key(recipient)) ?? 0n;
  // A credit to the zero address is a burn; a debit from it would be a mint.
  const zeroNet = net.get(key(ZERO_ADDRESS)) ?? 0n;
  const burned = zeroNet > 0n ? zeroNet : 0n;
  if (zeroNet < 0n) reasons.push(`aUSDC was minted during the transfer, net ${-zeroNet}`);

  // Every address the events touched that is neither side of the intended transfer.
  const counterparties = [...net.entries()]
    .filter(([address, value]) => address !== key(sender) && address !== key(recipient) && value !== 0n)
    .map(([address, value]) => ({ address, net: value.toString(), isBurn: address === key(ZERO_ADDRESS) }));

  if (senderDebit !== BigInt(amount)) {
    reasons.push(`events debit the sender ${senderDebit}, expected exactly ${amount}`);
  }
  if (recipientCredit <= 0n) {
    reasons.push(`events credit the recipient ${recipientCredit}, expected a positive amount`);
  }

  // Transfer events conserve value by construction, so a non-zero total means a log was missed.
  const total = [...net.values()].reduce((sum, value) => sum + value, 0n);
  if (total !== 0n) reasons.push(`the Transfer events do not balance, net ${total}`);

  // Every address whose balance we measured must match what the logs say happened to it.
  const mismatches = [];
  for (const [address, delta] of Object.entries(measured)) {
    const fromEvents = net.get(key(address)) ?? 0n;
    if (fromEvents !== BigInt(delta)) {
      mismatches.push({ address, fromEvents: fromEvents.toString(), measured: String(delta) });
    }
  }
  if (mismatches.length > 0) {
    reasons.push(`balance deltas disagree with the events for ${mismatches.length} address(es)`);
  }

  return {
    senderDebit: senderDebit.toString(),
    recipientCredit: recipientCredit.toString(),
    burned: burned.toString(),
    counterparties,
    feeCharged: counterparties.some((entry) => !entry.isBurn && BigInt(entry.net) > 0n),
    mismatches,
    ok: reasons.length === 0,
    reasons,
  };
}

/** Read endpoints only. The API key never leaves this process and is never printed. */
async function cleanverse(path, payload) {
  const base = process.env.CLEANVERSE_API_BASE_URL?.replace(/\/+$/, "");
  const apiId = process.env.CLEANVERSE_API_ID;
  if (!base || !apiId) return { unavailable: true };
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "api-id": apiId, "X-Request-ID": crypto.randomUUID() },
    body: JSON.stringify(payload), signal: AbortSignal.timeout(30_000),
  });
  return response.json();
}

const format = (units) => `${(Number(units) / 10 ** EXPECTED.decimals).toFixed(EXPECTED.decimals)} aUSDC`;

async function main() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const mode = argv.includes("--broadcast") ? "broadcast" : "check";
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  const runStartedAt = new Date().toISOString();
  const steps = [];
  const note = (label, detail) => {
    steps.push({ label, detail });
    process.stdout.write(`  ${label.padEnd(38)} ${detail}\n`);
  };

  /** Mutable run record, so a stop at any point can still be written out. */
  const report = {
    schemaVersion: 2,
    runStartedAt,
    generatedAt: null,
    mode,
    status: "RUNNING",
    classification: mode === "broadcast" ? "PENDING" : "READ-ONLY PREFLIGHT — NO TRANSACTION SENT",
    scope:
      "One aUSDC transfer between two wallets holding a valid A-Pass. This is NOT a Mordant"
      + " settlement: no vault, adapter, pledge or invoice A-Token is involved, and nothing here"
      + " may be described as MORDANT SETTLEMENT.",
    steps,
  };
  const checkpoint = () => {
    if (!out) return;
    report.generatedAt = new Date().toISOString();
    writeArtifact(out, report, process.env);
  };
  // Made available to the failure handler so a stop is recorded rather than only printed.
  main.checkpointOnFailure = (message) => {
    if (!out) return;
    report.status = "STOPPED";
    report.stopReason = message;
    if (report.execution?.hash && !report.execution.receipt) {
      report.classification = "AUSDC LIVE TRANSFER ATTEMPT — RECEIPT UNCONFIRMED";
    } else if (mode === "broadcast" && !report.execution) {
      report.classification = "NO TRANSACTION SENT";
    }
    checkpoint();
  };

  process.stdout.write(`M-07 minimal aUSDC transfer, mode=${mode}\n\n`);

  const client = createPublicClient({ transport: http(MONAD_RPC) });

  // Gate 1: the network, before anything else and before any key is read.
  const chainId = await assertChainId(client);
  assertWriteAllowed(mode, "broadcast", out);
  note("network", `chain ${chainId}`);

  // Gate 2: rediscover the address rather than trusting the constant.
  const discovery = await cleanverse("/query_deposit_atoken_list", { chain: "monad" });
  const discovered = Array.isArray(discovery?.data?.tokens)
    ? discovery.data.tokens.find((pair) => String(pair.atoken?.symbol).toLowerCase() === "ausdc")?.atoken?.address
    : null;
  if (!discovered) stop("could not rediscover the Monad aUSDC address from query_deposit_atoken_list.");
  assertUnchanged("aUSDC address", discovered, EXPECTED.aUsdc);
  const aUsdc = discovered;
  note("aUSDC address", `${aUsdc} (rediscovered, unchanged)`);

  const blockNumber = await client.getBlockNumber();
  const block = await client.getBlock({ blockNumber });
  note("pinned block", `${blockNumber} ${block.hash}`);

  // Gate 3: the code behind the proxies is the code M-06 observed.
  const readImplementation = async (address) => {
    const word = await client.getStorageAt({ address, slot: EIP1967_IMPLEMENTATION_SLOT });
    return word && !/^0x0+$/.test(word) ? `0x${word.slice(-40)}` : null;
  };
  const aUsdcImplementation = await readImplementation(aUsdc);
  assertUnchanged("aUSDC implementation", aUsdcImplementation, EXPECTED.aUsdcImplementation);
  const policy = await client.readContract({ address: aUsdc, abi: ERC20_ABI, functionName: "policy" });
  assertUnchanged("policy address", policy, EXPECTED.policy);
  const policyImplementation = await readImplementation(policy);
  assertUnchanged("policy implementation", policyImplementation, EXPECTED.policyImplementation);
  note("implementations", "aUSDC and policy both unchanged since M-06");

  const decimals = await client.readContract({ address: aUsdc, abi: ERC20_ABI, functionName: "decimals" });
  if (Number(decimals) !== EXPECTED.decimals) {
    stop(`aUSDC reports ${decimals} decimals, expected ${EXPECTED.decimals}. The amount arithmetic`
      + " in this runner assumes six, so it must not proceed.");
  }
  const registered = await client.readContract({
    address: policy, abi: POLICY_ABI, functionName: "isTokenRegistered", args: [aUsdc] });
  const paused = await client.readContract({
    address: policy, abi: POLICY_ABI, functionName: "isPaused", args: [aUsdc] });
  if (!registered) stop("aUSDC is not registered with the policy.");
  if (paused) stop("aUSDC is paused at the policy.");
  note("token state", `decimals ${decimals}, registered ${registered}, paused ${paused}`);

  report.network = { name: "monad-testnet", chainId, blockNumber: blockNumber.toString(),
    blockHash: block.hash, blockTimestamp: block.timestamp.toString() };
  report.token = { aUsdc, implementation: aUsdcImplementation, policy, policyImplementation,
    decimals: Number(decimals), isTokenRegistered: registered, isPaused: paused,
    rediscovered: true, unchangedSinceM06: true };
  checkpoint();

  // Gate 4: two distinct wallets, whose keys belong to their owner.
  const senderRole = process.env.MORDANT_M07_SENDER_ROLE ?? "HOLDER_A";
  const recipientRole = process.env.MORDANT_M07_RECIPIENT_ROLE ?? "HOLDER_B";
  const senderAddress = process.env[`MORDANT_ADDRESS_${senderRole}`];
  const recipientAddress = process.env[`MORDANT_ADDRESS_${recipientRole}`];
  if (!senderAddress || !recipientAddress) {
    stop(`MORDANT_ADDRESS_${senderRole} and MORDANT_ADDRESS_${recipientRole} must both be set.`);
  }
  assertDistinct(senderAddress, recipientAddress);
  note("wallets", `${senderRole} ${senderAddress} -> ${recipientRole} ${recipientAddress}`);
  report.participants = { senderRole, senderAddress, recipientRole, recipientAddress };

  // Gate 5: both wallets hold an active, unexpired A-Pass, per Cleanverse and on chain.
  const apass = [];
  for (const [role, address] of [[senderRole, senderAddress], [recipientRole, recipientAddress]]) {
    const onchainValid = await client.readContract({
      address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [address] });
    const record = scrub(await cleanverse("/query_apass", { chain: "monad", address }));
    const checked = assertAPassUsable(role, address, record, onchainValid, block.timestamp);
    apass.push({ role, address, onchainValid, ...checked });
    note(`A-Pass ${role}`, `isValidAPass=${onchainValid} status=${checked.status} tier=${checked.tier}`
      + ` subTier=${checked.subTier} expires in ${checked.secondsRemaining}s`);
  }
  report.apass = apass;

  // Gate 6: Cleanverse verify_apass for the exact token, immediately before the transfer.
  const verify = [];
  for (const [role, address] of [[senderRole, senderAddress], [recipientRole, recipientAddress]]) {
    const body = scrub(await cleanverse("/verify_apass", { chain: "monad", atoken: aUsdc, address }));
    const code = body?.code === "0000" ? Number(body.data?.code) : null;
    verify.push({ role, address, code, message: body?.data?.message ?? String(body?.message ?? "") });
    note(`verify_apass ${role}`, `code ${code} "${body?.data?.message}"`);
    if (code !== 4) stop(`verify_apass returned code ${code} for ${role} ${address}, expected 4.`);
  }
  report.verifyApass = verify;

  // Gate 7: the on-chain precheck for the exact tuple and the exact amount.
  let canTransfer = null;
  try {
    canTransfer = await client.readContract({
      address: policy, abi: POLICY_ABI, functionName: "canTransfer",
      args: [aUsdc, senderAddress, recipientAddress, TRANSFER_AMOUNT] });
  } catch (error) {
    stop(`canTransfer reverted for the exact transfer tuple: ${error.shortMessage ?? error.message}`);
  }
  if (canTransfer !== true) stop(`canTransfer returned ${canTransfer} for the exact transfer tuple.`);
  note("canTransfer", `true for (aUSDC, ${senderRole}, ${recipientRole}, ${TRANSFER_AMOUNT})`);
  report.precheck = { canTransfer, amount: TRANSFER_AMOUNT.toString(), amountHuman: format(TRANSFER_AMOUNT) };
  checkpoint();

  // Gate 8: funding, in both the token and the gas.
  const balanceOf = (address, blockNumberAt) => client.readContract({
    address: aUsdc, abi: ERC20_ABI, functionName: "balanceOf", args: [address],
    ...(blockNumberAt === undefined ? {} : { blockNumber: blockNumberAt }) });
  const before = {
    sender: await balanceOf(senderAddress),
    recipient: await balanceOf(recipientAddress),
    senderNative: await client.getBalance({ address: senderAddress }),
  };
  note("balances before", `sender ${format(before.sender)}, recipient ${format(before.recipient)}`);
  note("sender MON", `${before.senderNative} wei`);

  if (before.sender < TRANSFER_AMOUNT) {
    stop(`sender holds ${format(before.sender)}, needs at least ${format(TRANSFER_AMOUNT)}.`
      + " Fund it before broadcasting; see docs/m07-minimal-ausdc-transfer-plan.md.");
  }

  // Fail-closed: the estimate is measured against real state, and any failure stops the run.
  let gasEstimate;
  let gasPrice;
  try {
    gasEstimate = await client.estimateContractGas({
      address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [recipientAddress, TRANSFER_AMOUNT], account: senderAddress });
  } catch (error) {
    stop(`gas could not be estimated: ${(error.shortMessage ?? error.message).slice(0, 160)}.`
      + " A broadcast must never proceed without a measured cost.");
  }
  try {
    gasPrice = await client.getGasPrice();
  } catch (error) {
    stop(`gas price could not be read: ${(error.shortMessage ?? error.message).slice(0, 160)}.`);
  }
  const budget = assertGasUsable(gasEstimate, gasPrice, GAS_LIMIT_CEILING);
  note("gas", `estimate ${gasEstimate}, price ${gasPrice} wei, budget ${budget} wei`);
  assertFundedFor(senderAddress, before.senderNative, budget);

  report.gas = { estimate: gasEstimate.toString(), price: gasPrice.toString(),
    budgetWei: budget.toString(), ceilingGas: GAS_LIMIT_CEILING.toString(),
    ceilingPriceWei: DEFAULT_MAX_GAS_PRICE_WEI.toString() };
  report.balances = { before: { sender: before.sender.toString(),
    recipient: before.recipient.toString(), senderNativeWei: before.senderNative.toString() } };
  checkpoint();

  // --- the transfer ---
  if (mode !== "broadcast") {
    report.status = "COMPLETE";
    report.generatedAt = new Date().toISOString();
    process.stdout.write(`\n${"CLASSIFICATION".padEnd(38)} ${report.classification}\n`);
    process.stdout.write(`${"BROADCAST".padEnd(38)} check mode does not send; pass --broadcast --out to send\n`);
    if (out) { checkpoint(); process.stdout.write(`\nWrote ${out}.json\n`); }
    return;
  }

  const key = process.env[`MORDANT_KEY_${senderRole}`];
  assertKeyMatchesAddress(senderRole, key, senderAddress, privateKeyToAccount);
  const account = privateKeyToAccount(key);
  // Simulate against current state first: a revert here costs nothing.
  await client.simulateContract({
    address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
    args: [recipientAddress, TRANSFER_AMOUNT], account });

  const wallet = createWalletClient({ account, transport: http(MONAD_RPC) });
  const hash = await wallet.writeContract({
    address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
    args: [recipientAddress, TRANSFER_AMOUNT], chain: null });

  // Checkpoint the hash before awaiting anything. From here on the transaction exists whether or
  // not this process survives, so the artifact must say so.
  report.classification = "AUSDC LIVE TRANSFER ATTEMPT — RECEIPT PENDING";
  checkpointPending(report, hash, out, process.env);
  process.stdout.write(`\n  broadcast hash ${hash}, checkpointed PENDING, awaiting receipt\n`);

  const receipt = await client.waitForTransactionReceipt({ hash });
  const aUsdcLogs = receipt.logs.filter((log) => log.address.toLowerCase() === aUsdc.toLowerCase());
  const transferEvents = parseEventLogs({ abi: ERC20_ABI, eventName: "Transfer", logs: aUsdcLogs })
    .map((event) => ({ from: event.args.from, to: event.args.to, value: event.args.value.toString() }));

  report.execution = {
    hash, status: receipt.status, blockNumber: receipt.blockNumber.toString(),
    blockHash: receipt.blockHash, gasUsed: receipt.gasUsed.toString(),
    effectiveGasPrice: receipt.effectiveGasPrice?.toString() ?? null,
    feeWei: receipt.effectiveGasPrice ? (receipt.gasUsed * receipt.effectiveGasPrice).toString() : null,
    logCount: receipt.logs.length,
    aUsdcTransferEvents: transferEvents,
    otherLogs: receipt.logs
      .filter((log) => !aUsdcLogs.includes(log))
      .map((log) => ({ address: log.address, topic0: log.topics[0] })),
    receipt: true,
  };
  checkpoint();
  if (receipt.status !== "success") stop(`the transfer reverted. Hash ${hash}.`);
  note("transfer", `${hash} in block ${receipt.blockNumber}, gasUsed ${receipt.gasUsed}`);

  // --- readbacks ---
  // Counterparties are discovered from the events, so no address is assumed to be the fee receiver.
  // Their "before" balance is read at the parent block, which is exact and needs no advance guess.
  const parentBlock = receipt.blockNumber - 1n;
  const touched = new Set([senderAddress.toLowerCase(), recipientAddress.toLowerCase()]);
  for (const event of transferEvents) {
    touched.add(String(event.from).toLowerCase());
    touched.add(String(event.to).toLowerCase());
  }
  touched.delete(ZERO_ADDRESS);

  const measured = {};
  const balancesAfter = {};
  const balancesBefore = {};
  for (const address of touched) {
    const atParent = await balanceOf(address, parentBlock);
    const atReceipt = await balanceOf(address, receipt.blockNumber);
    balancesBefore[address] = atParent.toString();
    balancesAfter[address] = atReceipt.toString();
    measured[address] = (atReceipt - atParent).toString();
  }
  note("balances after", `sender ${format(balancesAfter[senderAddress.toLowerCase()])},`
    + ` recipient ${format(balancesAfter[recipientAddress.toLowerCase()])}`);

  const reconciliation = reconcileTransfer({
    events: transferEvents, amount: TRANSFER_AMOUNT,
    sender: senderAddress, recipient: recipientAddress, measured });
  note("reconciliation", reconciliation.ok
    ? `sender -${reconciliation.senderDebit}, recipient +${reconciliation.recipientCredit},`
      + ` ${reconciliation.counterparties.length} other counterparty(ies), logs match balances`
    : `FAILED: ${reconciliation.reasons.join("; ")}`);
  for (const counterparty of reconciliation.counterparties) {
    note("counterparty", `${counterparty.address} net ${counterparty.net}`
      + `${counterparty.isBurn ? " (burn)" : ""}`);
  }

  // The policy is read again afterwards: a rail that stops accepting right after a transfer is a
  // finding, not a detail.
  const canTransferAfter = await client.readContract({
    address: policy, abi: POLICY_ABI, functionName: "canTransfer",
    args: [aUsdc, senderAddress, recipientAddress, TRANSFER_AMOUNT] }).catch(() => "reverted");

  report.balances = {
    discoveredFromEvents: true,
    parentBlock: parentBlock.toString(),
    before: { ...balancesBefore, senderNativeWei: before.senderNative.toString() },
    after: balancesAfter,
    deltas: measured,
  };
  report.reconciliation = reconciliation;
  report.policyReadbackAfter = String(canTransferAfter);

  // A live transfer is only claimed when the receipt succeeded, the events say the sender paid
  // exactly the intended amount, the recipient was credited, and the logs match the balances.
  report.classification = reconciliation.ok
    ? "AUSDC LIVE TRANSFER"
    : "AUSDC LIVE TRANSFER ATTEMPT";
  report.status = "COMPLETE";
  report.generatedAt = new Date().toISOString();

  process.stdout.write(`\n${"CLASSIFICATION".padEnd(38)} ${report.classification}\n`);
  checkpoint();
  process.stdout.write(`\nWrote ${out}.json\n`);
}

const invokedDirectly = process.argv[1]?.endsWith("m07-ausdc-transfer.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    const message = error instanceof ControlError ? error.message : `STOP — ${error.message}`;
    try {
      main.checkpointOnFailure?.(message);
    } catch (writeError) {
      process.stderr.write(`\nartifact could not be written: ${writeError.message}\n`);
    }
    process.stderr.write(`\n${message}\n`);
    process.exitCode = 1;
  });
}
