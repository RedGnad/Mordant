#!/usr/bin/env node
/**
 * M-07: the smallest possible live aUSDC write proof.
 *
 * One aUSDC transfer between two wallets we control, both holding a valid A-Pass. Nothing else.
 * This is deliberately not a Mordant settlement: no vault, no adapter, no pledge, no invoice
 * A-Token. It proves the Cleanverse token rail accepts a real transfer, and that alone.
 *
 *   node --env-file=.env scripts/m07-ausdc-transfer.mjs --check       read-only, the default
 *   node --env-file=.env scripts/m07-ausdc-transfer.mjs --broadcast   sends one transaction
 *
 * --broadcast additionally requires MORDANT_M07_BROADCAST_AUTHORIZED=yes in the environment. Both
 * the flag and the variable are required, so neither a stray flag nor a stale variable can send a
 * transaction on its own.
 *
 * Every gate below is fail-closed and runs before any key is read. If the aUSDC address, the policy,
 * either implementation, the A-Pass state or the precheck differs from what M-06 recorded, the run
 * stops and sends nothing: a changed rail must be re-observed, not transacted against.
 *
 * No private key, seed phrase or other secret material is logged or persisted. Public addresses,
 * signatures, transaction hashes, blocks and readbacks may be recorded where required.
 */
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { createPublicClient, createWalletClient, decodeEventLog, http, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const MONAD_CHAIN_ID = 10_143;
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

/**
 * The smallest transfer the token can express: one atomic unit, 0.000001 aUSDC at six decimals.
 * A minimum is the point. A larger amount would prove nothing more and would consume faucet supply.
 */
const TRANSFER_AMOUNT = 1n;

/**
 * Gas budget. Measured by eth_estimateGas at run time; this is the ceiling a run refuses to exceed,
 * so an abnormal estimate stops the run instead of quietly spending. A compliance-checked transfer
 * of one atomic unit measured 319,513 gas on 28 July 2026, so the ceiling leaves headroom without
 * being wide enough to hide an unexpected code path.
 */
const GAS_LIMIT_CEILING = 400_000n;
const GAS_PRICE_CEILING_WEI = 200_000_000_000n; // 200 gwei

const ERC20_ABI = [
  { type: "function", name: "transfer", stateMutability: "nonpayable",
    inputs: [{ name: "to", type: "address" }, { name: "value", type: "uint256" }],
    outputs: [{ type: "bool" }] },
  { type: "function", name: "balanceOf", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
  { type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
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

/**
 * This address held 0.5 aUSDC on 28 July 2026 with no other visible role, which is consistent with
 * the rail charging a transfer fee. The runner therefore measures its balance across the transfer
 * instead of assuming the recipient receives exactly what the sender paid.
 */
const FEE_RECEIVER = "0x7f7098632b0258Af07e527015D65e6bc743f4CF5";

export class StopError extends Error {
  constructor(message) {
    super(message);
    this.name = "StopError";
  }
}

const stop = (message) => {
  throw new StopError(`STOP — ${message}`);
};

/** Fail-closed comparison. Anything other than an exact match halts the run. */
export function assertUnchanged(label, observed, expected) {
  if (String(observed ?? "").toLowerCase() !== String(expected).toLowerCase()) {
    stop(`${label} changed since M-06. Observed ${observed}, expected ${expected}.`
      + " Re-run pnpm revalidate:ausdc and review before transacting.");
  }
}

/**
 * Both the flag and the environment variable are required. Neither alone can send a transaction.
 */
export function assertBroadcastAuthorized(mode, env) {
  if (mode !== "broadcast") return;
  if (env.MORDANT_M07_BROADCAST_AUTHORIZED !== "yes") {
    stop("broadcast is not authorized. --broadcast additionally requires"
      + " MORDANT_M07_BROADCAST_AUTHORIZED=yes, set deliberately by the owner.");
  }
}

/** A transfer to yourself would satisfy every gate and prove nothing about the policy. */
export function assertDistinct(sender, recipient) {
  if (!sender || !recipient) stop("sender and recipient must both be configured.");
  if (sender.toLowerCase() === recipient.toLowerCase()) {
    stop("sender and recipient are the same wallet. A self-transfer proves nothing.");
  }
}

export function assertWithinCeilings(gas, gasPrice) {
  if (gas > GAS_LIMIT_CEILING) {
    stop(`estimated gas ${gas} exceeds the ${GAS_LIMIT_CEILING} ceiling.`
      + " An ERC-20 transfer costing this much is not the transaction this run intends to send.");
  }
  if (gasPrice > GAS_PRICE_CEILING_WEI) {
    stop(`gas price ${gasPrice} wei exceeds the ${GAS_PRICE_CEILING_WEI} wei ceiling.`);
  }
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

/** Drops anything credential-shaped, including the magickLink verify_apass returns. */
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

  process.stdout.write(`M-07 minimal aUSDC transfer, mode=${mode}\n\n`);

  const client = createPublicClient({ transport: http(MONAD_RPC) });

  // Gate 1: the network, before anything else and before any key is read.
  const chainId = await client.getChainId();
  if (chainId !== MONAD_CHAIN_ID) {
    stop(`wrong network. Expected chain ${MONAD_CHAIN_ID}, the RPC answered ${chainId}.`);
  }
  assertBroadcastAuthorized(mode, process.env);
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

  // Gate 4: two distinct wallets we control.
  const senderRole = process.env.MORDANT_M07_SENDER_ROLE ?? "HOLDER_A";
  const recipientRole = process.env.MORDANT_M07_RECIPIENT_ROLE ?? "HOLDER_B";
  const senderAddress = process.env[`MORDANT_ADDRESS_${senderRole}`];
  const recipientAddress = process.env[`MORDANT_ADDRESS_${recipientRole}`];
  if (!senderAddress || !recipientAddress) {
    stop(`MORDANT_ADDRESS_${senderRole} and MORDANT_ADDRESS_${recipientRole} must both be set.`);
  }
  assertDistinct(senderAddress, recipientAddress);
  note("wallets", `${senderRole} ${senderAddress} -> ${recipientRole} ${recipientAddress}`);

  // Gate 5: both wallets hold a valid A-Pass, on chain and per Cleanverse.
  const apass = [];
  for (const [role, address] of [[senderRole, senderAddress], [recipientRole, recipientAddress]]) {
    const onchainValid = await client.readContract({
      address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [address] });
    const record = scrub(await cleanverse("/query_apass", { chain: "monad", address }));
    const data = record?.code === "0000" ? record.data : null;
    const expired = data?.expirationTime
      ? Number(data.expirationTime) < Number(block.timestamp) : null;
    apass.push({ role, address, onchainValid, status: data?.status ?? null, tier: data?.tier ?? null,
      subTier: data?.subTier ?? null, expirationTime: data?.expirationTime ?? null, expired });
    note(`A-Pass ${role}`, `isValidAPass=${onchainValid} status=${data?.status} tier=${data?.tier}`
      + ` subTier=${data?.subTier} expiry=${data?.expirationTime ?? "none"}`);
    if (!onchainValid) {
      stop(`${role} ${address} holds no valid A-Pass. Issue one with /generate_apass before`
        + " attempting a transfer; a transfer without it will be refused by the policy.");
    }
    if (expired === true) stop(`${role} ${address} holds an expired A-Pass.`);
  }

  // Gate 6: Cleanverse verify_apass for the exact token, immediately before the transfer.
  const verify = [];
  for (const [role, address] of [[senderRole, senderAddress], [recipientRole, recipientAddress]]) {
    const body = scrub(await cleanverse("/verify_apass", { chain: "monad", atoken: aUsdc, address }));
    const code = body?.code === "0000" ? Number(body.data?.code) : null;
    verify.push({ role, address, code, message: body?.data?.message ?? String(body?.message ?? "") });
    note(`verify_apass ${role}`, `code ${code} "${body?.data?.message}"`);
    if (code !== 4) {
      stop(`verify_apass returned code ${code} for ${role} ${address}, expected 4.`);
    }
  }

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

  // Gate 8: funding. Both the token and the gas.
  const balanceOf = (address) => client.readContract({
    address: aUsdc, abi: ERC20_ABI, functionName: "balanceOf", args: [address] });
  const before = {
    sender: await balanceOf(senderAddress),
    recipient: await balanceOf(recipientAddress),
    feeReceiver: await balanceOf(FEE_RECEIVER),
    senderNative: await client.getBalance({ address: senderAddress }),
  };
  note("balances before", `sender ${format(before.sender)}, recipient ${format(before.recipient)}`);
  note("sender MON", `${before.senderNative} wei`);

  if (before.sender < TRANSFER_AMOUNT) {
    stop(`sender holds ${format(before.sender)}, needs at least ${format(TRANSFER_AMOUNT)}.`
      + " Fund it with POST /faucet {chain:\"monad\", symbol:\"ausdc\", depositAddress:<sender>,"
      + " amount:<small amount>} before broadcasting.");
  }

  // Gas is estimated against the real state, so the budget is measured rather than assumed.
  let gasEstimate = null;
  let gasPrice = null;
  try {
    gasEstimate = await client.estimateContractGas({
      address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [recipientAddress, TRANSFER_AMOUNT], account: senderAddress });
    gasPrice = await client.getGasPrice();
    assertWithinCeilings(gasEstimate, gasPrice);
    note("gas", `estimate ${gasEstimate}, price ${gasPrice} wei, budget ${gasEstimate * gasPrice} wei`);
  } catch (error) {
    if (error instanceof StopError) throw error;
    note("gas", `not estimable: ${(error.shortMessage ?? error.message).slice(0, 120)}`);
  }

  const budget = gasEstimate && gasPrice ? gasEstimate * gasPrice : null;
  if (budget !== null && before.senderNative < budget) {
    stop(`sender holds ${before.senderNative} wei MON, needs at least ${budget} wei for gas.`);
  }

  // --- the transfer ---
  let execution = null;
  if (mode === "broadcast") {
    const key = process.env[`MORDANT_KEY_${senderRole}`];
    if (!key) stop(`MORDANT_KEY_${senderRole} is required to sign the transfer.`);
    const account = privateKeyToAccount(key);
    if (account.address.toLowerCase() !== senderAddress.toLowerCase()) {
      stop(`MORDANT_KEY_${senderRole} derives ${account.address}, which is not the configured`
        + ` sender ${senderAddress}.`);
    }
    // Simulate against current state first: a revert here costs nothing.
    await client.simulateContract({
      address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [recipientAddress, TRANSFER_AMOUNT], account });
    const wallet = createWalletClient({ account, transport: http(MONAD_RPC) });
    const hash = await wallet.writeContract({
      address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [recipientAddress, TRANSFER_AMOUNT], chain: null });
    process.stdout.write(`\n  broadcast hash ${hash}, awaiting receipt\n`);
    const receipt = await client.waitForTransactionReceipt({ hash });
    const transferLogs = parseEventLogs({ abi: ERC20_ABI, eventName: "Transfer", logs: receipt.logs });
    execution = {
      hash, status: receipt.status, blockNumber: receipt.blockNumber.toString(),
      blockHash: receipt.blockHash, gasUsed: receipt.gasUsed.toString(),
      effectiveGasPrice: receipt.effectiveGasPrice?.toString() ?? null,
      feeWei: receipt.effectiveGasPrice ? (receipt.gasUsed * receipt.effectiveGasPrice).toString() : null,
      logCount: receipt.logs.length,
      events: receipt.logs.map((log) => {
        try {
          const decoded = decodeEventLog({ abi: ERC20_ABI, data: log.data, topics: log.topics });
          return { address: log.address, name: decoded.eventName,
            args: Object.fromEntries(Object.entries(decoded.args).map(([k, v]) => [k, String(v)])) };
        } catch {
          return { address: log.address, name: null, topic0: log.topics[0] };
        }
      }),
      transferEventPresent: transferLogs.length > 0,
    };
    if (receipt.status !== "success") stop(`the transfer reverted. Hash ${hash}.`);
    note("transfer", `${hash} in block ${receipt.blockNumber}, gasUsed ${receipt.gasUsed}`);
  }

  // --- readbacks ---
  const after = execution
    ? { sender: await balanceOf(senderAddress), recipient: await balanceOf(recipientAddress),
        feeReceiver: await balanceOf(FEE_RECEIVER),
        senderNative: await client.getBalance({ address: senderAddress }) }
    : null;
  let deltas = null;
  if (after) {
    const senderDelta = before.sender - after.sender;
    const recipientDelta = after.recipient - before.recipient;
    const feeDelta = after.feeReceiver - before.feeReceiver;
    deltas = {
      sender: senderDelta.toString(), recipient: recipientDelta.toString(), fee: feeDelta.toString(),
      senderPaidExactly: senderDelta === TRANSFER_AMOUNT,
      // Value is conserved whether or not the rail takes a cut, so this holds under both models.
      conserved: senderDelta === recipientDelta + feeDelta,
      feeCharged: feeDelta > 0n,
    };
    note("balances after", `sender ${format(after.sender)}, recipient ${format(after.recipient)}`);
    note("deltas", `sender -${senderDelta}, recipient +${recipientDelta}, fee +${feeDelta}`
      + ` (conserved ${deltas.conserved})`);
  }
  // The policy is read again afterwards: a rail that stops accepting right after a transfer is a
  // finding, not a detail.
  const canTransferAfter = execution
    ? await client.readContract({ address: policy, abi: POLICY_ABI, functionName: "canTransfer",
        args: [aUsdc, senderAddress, recipientAddress, TRANSFER_AMOUNT] }).catch(() => "reverted")
    : null;

  const classification = execution
    ? (execution.status === "success" && deltas?.senderPaidExactly && deltas?.conserved
      ? "AUSDC LIVE TRANSFER"
      : "AUSDC LIVE TRANSFER ATTEMPT")
    : "READ-ONLY PREFLIGHT — NO TRANSACTION SENT";

  const report = {
    schemaVersion: 1,
    runStartedAt,
    generatedAt: new Date().toISOString(),
    mode,
    classification,
    scope:
      "One aUSDC transfer between two wallets holding a valid A-Pass. This is NOT a Mordant"
      + " settlement: no vault, adapter, pledge or invoice A-Token is involved, and nothing here"
      + " may be described as MORDANT SETTLEMENT.",
    network: { name: "monad-testnet", chainId, blockNumber: blockNumber.toString(), blockHash: block.hash },
    token: { aUsdc, implementation: aUsdcImplementation, policy, policyImplementation,
      decimals: Number(decimals), isTokenRegistered: registered, isPaused: paused,
      rediscovered: true, unchangedSinceM06: true },
    participants: { senderRole, senderAddress, recipientRole, recipientAddress },
    apass,
    verifyApass: verify,
    precheck: { canTransfer, amount: TRANSFER_AMOUNT.toString(), amountHuman: format(TRANSFER_AMOUNT) },
    gas: { estimate: gasEstimate?.toString() ?? null, price: gasPrice?.toString() ?? null,
      budgetWei: budget?.toString() ?? null, ceilingGas: GAS_LIMIT_CEILING.toString(),
      ceilingPriceWei: GAS_PRICE_CEILING_WEI.toString() },
    balances: {
      feeReceiver: FEE_RECEIVER,
      before: { sender: before.sender.toString(), recipient: before.recipient.toString(),
        feeReceiver: before.feeReceiver.toString(), senderNativeWei: before.senderNative.toString() },
      after: after
        ? { sender: after.sender.toString(), recipient: after.recipient.toString(),
            feeReceiver: after.feeReceiver.toString(),
            senderNativeWei: after.senderNative.toString() }
        : null,
      deltas,
    },
    execution,
    policyReadbackAfter: canTransferAfter === null ? null : String(canTransferAfter),
    steps,
  };

  process.stdout.write(`\n${"CLASSIFICATION".padEnd(38)} ${classification}\n`);
  if (mode === "check") {
    process.stdout.write(`${"BROADCAST".padEnd(38)} NOT AUTHORIZED, nothing was sent\n`);
  }

  if (out) {
    const serialized = `${JSON.stringify(report, null, 2)}\n`;
    // Compare against the actual secret values rather than a shape: transaction hashes and log
    // topics are also 64 hex characters, so a shape rule would either miss keys or block hashes.
    // The values are only ever compared, never written or printed.
    const secrets = Object.entries(process.env)
      .filter(([name]) => /^MORDANT_KEY_|^CLEANVERSE_API_KEY$/.test(name))
      .map(([, value]) => value)
      .filter((value) => typeof value === "string" && value.length >= 16);
    if (secrets.some((secret) => serialized.includes(secret))) {
      stop("refusing to write an artifact containing secret material.");
    }
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(`${out}.json.tmp`, serialized, "utf8");
    renameSync(`${out}.json.tmp`, `${out}.json`);
    process.stdout.write(`\nWrote ${out}.json\n`);
  }
}

const invokedDirectly = process.argv[1]?.endsWith("m07-ausdc-transfer.mjs");
if (invokedDirectly) {
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof StopError ? error.message : `STOP — ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
