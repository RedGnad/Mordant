#!/usr/bin/env node
/**
 * M-10: can a contract actually HOLD and RETURN an A-Token?
 *
 * M-08 established that an A-Pass can be issued to a contract and that the policy answers `true` in
 * both directions. Both of those are reads. This moves real value: one atomic unit of aUSDC out to
 * the probe, then back again through the probe's own `sweep`. It is the difference between a policy
 * saying a transfer is permitted and a contract having custody of something and giving it back.
 *
 *   node --env-file=.env scripts/m10-custody-roundtrip.mjs --check     read-only, the default
 *   node --env-file=.env scripts/m10-custody-roundtrip.mjs --run --out <prefix>
 *
 * Scope is deliberately narrow. It reuses the probe M-08 deployed and deploys nothing, issues no
 * A-Pass, and makes no Cleanverse write call: the only Cleanverse requests are the documented read
 * endpoints used to confirm the credentials still hold immediately before and after.
 *
 * This is NOT a Mordant settlement and must never be described as one. No vault, no adapter, no
 * pledge, no invoice A-Token.
 *
 * If the outbound transfer succeeds and the return does not, the run records what is stranded and
 * what a recovery would need, as data rather than as a runnable command, and sends nothing further.
 * If the return's hash exists but its receipt never resolved, it offers no recovery at all: the
 * transaction may still land, and acting on a snapshot would risk sending the same unit twice.
 *
 * The signing key belongs to the wallet owner. This runner reads it from the environment and never
 * generates, derives, requests or persists one.
 *
 * No private key, seed phrase or other secret material is logged or persisted. Public addresses,
 * signatures, transaction hashes, blocks and readbacks may be recorded where required.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient, createWalletClient, encodeFunctionData, http, keccak256, parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { reconcileTransfer } from "./m07-ausdc-transfer.mjs";
import {
  ControlError, DEFAULT_MAX_GAS_PRICE_WEI, assertChainId, assertFundedFor, assertGasUsable,
  assertKeyMatchesAddress, assertWriteAllowed, checkpointPending, scrub, writeArtifact,
} from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const COMPILED = join(ROOT, "contracts/out/CleanverseAPassProbe.sol/CleanverseAPassProbe.json");

const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";

/** The probe M-08 deployed. This mission uses it and deploys nothing. */
const PROBE = "0x0f8b9a0c064306f938912658c96c681d8655140b";

/** Pinned from M-06 and M-08. Each run re-observes these and refuses to proceed on a change. */
const EXPECTED = Object.freeze({
  aUsdc: "0xaC0893567D43C3E7e6e35a72803df05416C1f20D",
  aUsdcImplementation: "0x5a520e9992d30416c33e2dcdc2d8f3befce426da",
  policy: "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd",
  policyImplementation: "0xc644e79e4c8ee94c4dee49b76f8591e994e58101",
  decimals: 6,
});

const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const APASS_ADDRESS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";

/** One atomic unit, 0.000001 aUSDC. A minimum is the point of the exercise. */
const AMOUNT = 1n;

/** A transfer measured 319,513 gas; a sweep adds a hop, so the ceiling covers both. */
const GAS_LIMIT_CEILING = 600_000n;

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

const PROBE_ABI = [
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "sweep", stateMutability: "nonpayable",
    inputs: [{ name: "token", type: "address" }, { name: "to", type: "address" },
      { name: "amount", type: "uint256" }], outputs: [] },
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

export { ControlError as StopError } from "./runner-controls.mjs";

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/** Fail-closed comparison. Anything other than an exact match halts the run. */
export function assertUnchanged(label, observed, expected) {
  if (String(observed ?? "").toLowerCase() !== String(expected).toLowerCase()) {
    stop(`${label} changed. Observed ${observed}, expected ${expected}.`
      + " Re-run pnpm revalidate:ausdc and review before transacting.");
  }
}

/**
 * Preflight 4. The probe must be the contract we compiled, not merely an address with code: a
 * different contract at this address would take custody under rules we have not reviewed.
 */
export function assertProbeCodeMatches(onchainCode, compiledDeployedBytecode) {
  if (!onchainCode || onchainCode === "0x") {
    stop(`${PROBE} has no code. The probe M-08 deployed must exist before value is sent to it.`);
  }
  const onchainSize = (onchainCode.length - 2) / 2;
  const expectedSize = (compiledDeployedBytecode.length - 2) / 2;
  if (onchainSize !== expectedSize) {
    stop(`probe code is ${onchainSize} bytes, the compiled artifact is ${expectedSize}.`);
  }
  if (onchainCode.toLowerCase() !== compiledDeployedBytecode.toLowerCase()) {
    stop(`probe code hash ${keccak256(onchainCode)} does not match the compiled`
      + ` ${keccak256(compiledDeployedBytecode)}. This is not the reviewed contract.`);
  }
  return { size: onchainSize, hash: keccak256(onchainCode) };
}

/**
 * Preflight 5. Only the owner may sweep, so a probe owned by anyone else could take the outbound
 * unit and never give it back.
 */
export function assertProbeOwnedBy(observedOwner, signer) {
  if (String(observedOwner ?? "").toLowerCase() !== String(signer).toLowerCase()) {
    stop(`the probe reports owner ${observedOwner}, not the signer ${signer}.`
      + " Only the owner can sweep, so the return leg could not be executed.");
  }
  return observedOwner;
}

/**
 * Preflight 6. An A-Pass that is inactive, expired or unconfirmed on chain is not usable, and an
 * absent expiration is never read as unlimited.
 */
export function assertApassUsable(label, address, envelope, onchainValid, blockTimestamp) {
  if (envelope?.code !== "0000") {
    stop(`query_apass did not succeed for ${label} ${address}: envelope ${envelope?.code ?? "none"}.`);
  }
  const data = envelope.data;
  if (!data || typeof data !== "object") stop(`query_apass returned no record for ${label} ${address}.`);
  if (Number(data.status) !== 1) {
    stop(`${label} ${address} has A-Pass status ${data.status}, expected 1.`);
  }
  const expiration = Number(data.expirationTime);
  if (!Number.isFinite(expiration) || expiration <= 0) {
    stop(`${label} ${address} has no usable A-Pass expiration (${data.expirationTime}).`);
  }
  if (expiration <= Number(blockTimestamp)) {
    stop(`${label} ${address} holds an A-Pass that expired at ${expiration}.`);
  }
  if (onchainValid !== true) stop(`isValidAPass is ${onchainValid} on chain for ${label} ${address}.`);
  return { status: Number(data.status), tier: data.tier ?? null, subTier: data.subTier ?? null,
    expirationTime: expiration, secondsRemaining: expiration - Number(blockTimestamp) };
}

/**
 * The verdict.
 *
 * A round trip is proven only when value went out, came back, and the probe ends empty.
 *
 * `RETURN PENDING` is separated from `FUNDS IN PROBE` because they call for opposite responses. A
 * return whose hash exists but whose receipt never resolved may still land: the balance reading as
 * stranded is a snapshot, not a conclusion, and proposing a recovery against a transaction that is
 * still in flight invites sending the same unit twice. So that state offers no recovery at all
 * until the receipt is resolved.
 */
export function classifyRoundTrip({ outbound, inbound, probeFinalBalance, inboundHash, inboundReceiptResolved }) {
  if (!outbound?.ok) return "CONTRACT AUSDC CUSTODY ROUND-TRIP: OUTBOUND FAILED";
  if (inboundHash && !inboundReceiptResolved) {
    return "CONTRACT AUSDC CUSTODY ROUND-TRIP: PARTIAL — RETURN PENDING";
  }
  if (!inbound?.ok) return "CONTRACT AUSDC CUSTODY ROUND-TRIP: PARTIAL — FUNDS IN PROBE";
  if (probeFinalBalance !== 0n) {
    return "CONTRACT AUSDC CUSTODY ROUND-TRIP: PARTIAL — FUNDS IN PROBE";
  }
  return "CONTRACT AUSDC CUSTODY ROUND-TRIP: PROVEN";
}

/**
 * What a recovery would need, recorded as data rather than as a runnable command.
 *
 * A shell line containing `--private-key $MORDANT_KEY_...` puts the key into the arguments of a
 * process, where it is visible to anything that can list processes and lands in shell history. The
 * artifact therefore records the target, function, arguments and calldata, and says plainly that a
 * recovery must read the key from the environment through a dedicated mode.
 */
export function describeRecovery({ probe, token, owner, strandedUnits, encodeCalldata }) {
  return {
    strandedAtomicUnits: strandedUnits.toString(),
    target: probe,
    signature: "sweep(address,address,uint256)",
    arguments: [token, owner, strandedUnits.toString()],
    calldata: encodeCalldata(),
    mustBeSignedBy: owner,
    note: "Not executed automatically, and deliberately not expressed as a runnable command: a"
      + " recovery must read the signing key from the environment, never from process arguments.",
  };
}

/** Read endpoints only. This mission makes no Cleanverse write call. */
async function cleanverseRead(path, body) {
  const base = process.env.CLEANVERSE_API_BASE_URL?.replace(/\/+$/, "");
  const apiId = process.env.CLEANVERSE_API_ID;
  if (!base || !apiId) return { unavailable: true };
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "api-id": apiId, "X-Request-ID": crypto.randomUUID() },
    body: JSON.stringify(body), signal: AbortSignal.timeout(30_000),
  });
  return response.json();
}

const format = (units) => `${(Number(units) / 10 ** EXPECTED.decimals).toFixed(EXPECTED.decimals)} aUSDC`;

async function main() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const mode = argv.includes("--run") ? "run" : "check";
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  const steps = [];
  const note = (label, detail) => {
    steps.push({ label, detail });
    process.stdout.write(`  ${label.padEnd(32)} ${detail}\n`);
  };

  const report = {
    schemaVersion: 1,
    runStartedAt: new Date().toISOString(),
    generatedAt: null,
    mode,
    status: "RUNNING",
    classification: mode === "check"
      ? "READ-ONLY PREFLIGHT — NO TRANSACTION SENT" : "PENDING",
    scope:
      "One atomic unit of aUSDC sent to the probe M-08 deployed, then returned through its own"
      + " sweep. Nothing is deployed, no A-Pass is issued and no Cleanverse write call is made."
      + " This is NOT a Mordant settlement: no vault, adapter, pledge or invoice A-Token is"
      + " involved, and it may never be described as MORDANT SETTLEMENT.",
    probe: PROBE,
    steps,
  };
  const checkpoint = () => {
    if (!out) return;
    report.generatedAt = new Date().toISOString();
    writeArtifact(out, report, process.env);
  };
  main.checkpointOnFailure = (message) => {
    if (!out) return;
    report.status = "STOPPED";
    report.stopReason = message;
    checkpoint();
  };

  process.stdout.write(`M-10 contract custody round trip, mode=${mode}\n\n`);
  const client = createPublicClient({ transport: http(MONAD_RPC) });

  // --- preflight 1: chain, before any key is read ---
  const chainId = await assertChainId(client);
  assertWriteAllowed(mode, "run", out);
  note("network", `chain ${chainId}`);

  const blockNumber = await client.getBlockNumber();
  const block = await client.getBlock({ blockNumber });
  note("pinned block", `${blockNumber} ${block.hash}`);

  // --- preflight 2 and 3: the token and the policy are the ones we reviewed ---
  const discovery = await cleanverseRead("/query_deposit_atoken_list", { chain: "monad" });
  const discovered = Array.isArray(discovery?.data?.tokens)
    ? discovery.data.tokens.find((pair) => String(pair.atoken?.symbol).toLowerCase() === "ausdc")?.atoken?.address
    : null;
  if (!discovered) stop("could not rediscover the Monad aUSDC address.");
  assertUnchanged("aUSDC address", discovered, EXPECTED.aUsdc);
  const aUsdc = discovered;

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
  const decimals = await client.readContract({ address: aUsdc, abi: ERC20_ABI, functionName: "decimals" });
  if (Number(decimals) !== EXPECTED.decimals) stop(`aUSDC reports ${decimals} decimals.`);
  const registered = await client.readContract({
    address: policy, abi: POLICY_ABI, functionName: "isTokenRegistered", args: [aUsdc] });
  const paused = await client.readContract({
    address: policy, abi: POLICY_ABI, functionName: "isPaused", args: [aUsdc] });
  if (!registered) stop("aUSDC is not registered with the policy.");
  if (paused) stop("aUSDC is paused at the policy.");
  note("aUSDC", `${aUsdc}, implementation and policy unchanged`);

  // --- preflight 4: the probe is the contract we compiled ---
  const compiled = JSON.parse(readFileSync(COMPILED, "utf8"));
  const probeCode = await client.getCode({ address: PROBE });
  const codeFacts = assertProbeCodeMatches(probeCode, compiled.deployedBytecode.object);
  note("probe code", `${codeFacts.size} bytes, hash matches the compiled artifact`);

  // --- preflight 5: the signer owns the probe ---
  const ownerRole = process.env.MORDANT_M10_OWNER_ROLE ?? "HOLDER_A";
  const ownerAddress = process.env[`MORDANT_ADDRESS_${ownerRole}`];
  if (!ownerAddress) stop(`MORDANT_ADDRESS_${ownerRole} must be set.`);
  const probeOwner = await client.readContract({ address: PROBE, abi: PROBE_ABI, functionName: "owner" });
  assertProbeOwnedBy(probeOwner, ownerAddress);
  note("probe owner", `${probeOwner} matches the signer`);

  // --- preflight 6 and 7: both credentials still hold ---
  const credentials = [];
  for (const [label, address] of [["owner", ownerAddress], ["probe", PROBE]]) {
    const onchainValid = await client.readContract({
      address: APASS_ADDRESS, abi: APASS_ABI, functionName: "isValidAPass", args: [address] });
    const record = scrub(await cleanverseRead("/query_apass", { chain: "monad", address }));
    const checked = assertApassUsable(label, address, record, onchainValid, block.timestamp);
    const verify = scrub(await cleanverseRead("/verify_apass", { chain: "monad", atoken: aUsdc, address }));
    const verifyCode = verify?.code === "0000" ? Number(verify.data?.code) : null;
    if (verifyCode !== 4) stop(`verify_apass returned code ${verifyCode} for ${label} ${address}.`);
    credentials.push({ label, address, onchainValid, verifyCode, ...checked });
    note(`A-Pass ${label}`, `valid, status ${checked.status}, tier ${checked.tier}, verify code 4`);
  }

  // --- preflight 8 and 9: both directions permitted, for the exact amount ---
  const precheck = async (label, from, to) => {
    try {
      const answer = await client.readContract({
        address: policy, abi: POLICY_ABI, functionName: "canTransfer", args: [aUsdc, from, to, AMOUNT] });
      if (answer !== true) stop(`canTransfer ${label} returned ${answer}.`);
      return answer;
    } catch (error) {
      if (error instanceof ControlError) throw error;
      stop(`canTransfer ${label} reverted: ${(error.shortMessage ?? error.message).slice(0, 140)}`);
    }
    return null;
  };
  const canOutbound = await precheck("owner -> probe", ownerAddress, PROBE);
  const canInbound = await precheck("probe -> owner", PROBE, ownerAddress);
  note("canTransfer", `owner->probe ${canOutbound}, probe->owner ${canInbound}`);

  // --- preflight 10: the owner holds the unit ---
  const balanceOf = (address, at) => client.readContract({
    address: aUsdc, abi: ERC20_ABI, functionName: "balanceOf", args: [address],
    ...(at === undefined ? {} : { blockNumber: at }) });
  const startingOwner = await balanceOf(ownerAddress);
  const startingProbe = await balanceOf(PROBE);
  if (startingOwner < AMOUNT) {
    stop(`owner holds ${format(startingOwner)}, needs at least ${format(AMOUNT)}.`);
  }
  note("balances", `owner ${format(startingOwner)}, probe ${format(startingProbe)}`);

  // --- preflight 11: both legs are costed, fail-closed ---
  let outboundGas;
  let gasPrice;
  try {
    outboundGas = await client.estimateContractGas({
      address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [PROBE, AMOUNT], account: ownerAddress });
  } catch (error) {
    stop(`outbound gas could not be estimated: ${(error.shortMessage ?? error.message).slice(0, 140)}`);
  }
  try {
    gasPrice = await client.getGasPrice();
  } catch (error) {
    stop(`gas price could not be read: ${(error.shortMessage ?? error.message).slice(0, 140)}`);
  }
  const outboundBudget = assertGasUsable(outboundGas, gasPrice, GAS_LIMIT_CEILING);

  // The sweep can only be estimated once the probe holds the unit, so before the outbound leg it is
  // bounded by the ceiling rather than measured. That is stated rather than glossed over.
  let sweepEstimatePreflight = null;
  try {
    sweepEstimatePreflight = await client.estimateContractGas({
      address: PROBE, abi: PROBE_ABI, functionName: "sweep",
      args: [aUsdc, ownerAddress, AMOUNT], account: ownerAddress });
  } catch {
    sweepEstimatePreflight = null;
  }
  const worstCaseSweep = sweepEstimatePreflight ?? GAS_LIMIT_CEILING;
  const totalBudget = outboundBudget + worstCaseSweep * gasPrice;
  const ownerNative = await client.getBalance({ address: ownerAddress });
  assertFundedFor(ownerAddress, ownerNative, totalBudget);
  note("gas", `outbound ${outboundGas}, sweep ${sweepEstimatePreflight ?? `not estimable before funding,`
    + ` budgeted at the ${GAS_LIMIT_CEILING} ceiling`}, price ${gasPrice} wei`);
  note("total MON budget", `${totalBudget} wei, owner holds ${ownerNative} wei`);

  report.network = { name: "monad-testnet", chainId, blockNumber: blockNumber.toString(),
    blockHash: block.hash, blockTimestamp: block.timestamp.toString() };
  report.token = { aUsdc, implementation: aUsdcImplementation, policy, policyImplementation,
    decimals: Number(decimals), isTokenRegistered: registered, isPaused: paused };
  report.probeFacts = { address: PROBE, codeSize: codeFacts.size, codeHash: codeFacts.hash,
    matchesCompiledArtifact: true, owner: probeOwner };
  report.participants = { ownerRole, ownerAddress, probe: PROBE };
  report.credentials = credentials;
  report.precheck = { canOutbound, canInbound, amount: AMOUNT.toString(), amountHuman: format(AMOUNT) };
  report.gas = { outboundEstimate: outboundGas.toString(),
    sweepEstimatePreflight: sweepEstimatePreflight?.toString() ?? null,
    price: gasPrice.toString(), totalBudgetWei: totalBudget.toString(),
    ceilingGas: GAS_LIMIT_CEILING.toString(), ceilingPriceWei: DEFAULT_MAX_GAS_PRICE_WEI.toString() };
  report.balances = { start: { owner: startingOwner.toString(), probe: startingProbe.toString() } };
  checkpoint();

  if (mode !== "run") {
    report.status = "COMPLETE";
    process.stdout.write(`\n${"CLASSIFICATION".padEnd(32)} ${report.classification}\n`);
    process.stdout.write(`${"EXECUTION".padEnd(32)} check mode sends nothing; pass --run --out\n`);
    if (out) { checkpoint(); process.stdout.write(`\nWrote ${out}.json\n`); }
    return;
  }

  const key = process.env[`MORDANT_KEY_${ownerRole}`];
  assertKeyMatchesAddress(ownerRole, key, ownerAddress, privateKeyToAccount);
  const account = privateKeyToAccount(key);
  const wallet = createWalletClient({ account, transport: http(MONAD_RPC) });

  /** Runs one leg: simulate, send, checkpoint the hash, await, reconcile. */
  const runLeg = async ({ field, label, simulate, send, from, to }) => {
    await simulate();
    const hash = await send();
    checkpointPending(report, hash, out, process.env, { field });
    process.stdout.write(`\n  ${label} hash ${hash}, checkpointed PENDING\n`);

    const receipt = await client.waitForTransactionReceipt({ hash });
    const aUsdcLogs = receipt.logs.filter((log) => log.address.toLowerCase() === aUsdc.toLowerCase());
    const events = parseEventLogs({ abi: ERC20_ABI, eventName: "Transfer", logs: aUsdcLogs })
      .map((event) => ({ from: event.args.from, to: event.args.to, value: event.args.value.toString() }));

    // Balances are read at the parent and receipt blocks for every address the events touched, so
    // the reconciliation needs no advance guess about who else was involved.
    const parent = receipt.blockNumber - 1n;
    const touched = new Set([from.toLowerCase(), to.toLowerCase()]);
    for (const event of events) {
      touched.add(String(event.from).toLowerCase());
      touched.add(String(event.to).toLowerCase());
    }
    touched.delete("0x0000000000000000000000000000000000000000");
    const measured = {};
    const before = {};
    const after = {};
    for (const address of touched) {
      const atParent = await balanceOf(address, parent);
      const atReceipt = await balanceOf(address, receipt.blockNumber);
      before[address] = atParent.toString();
      after[address] = atReceipt.toString();
      measured[address] = (atReceipt - atParent).toString();
    }
    const reconciliation = reconcileTransfer({ events, amount: AMOUNT, sender: from, recipient: to, measured });
    const leg = {
      hash, status: receipt.status, blockNumber: receipt.blockNumber.toString(),
      blockHash: receipt.blockHash, gasUsed: receipt.gasUsed.toString(),
      effectiveGasPrice: receipt.effectiveGasPrice?.toString() ?? null,
      feeWei: receipt.effectiveGasPrice ? (receipt.gasUsed * receipt.effectiveGasPrice).toString() : null,
      aUsdcTransferEvents: events, balancesBefore: before, balancesAfter: after, deltas: measured,
      reconciliation, receipt: true,
      ok: receipt.status === "success" && reconciliation.ok,
    };
    report[field] = leg;
    checkpoint();
    note(label, leg.ok
      ? `${receipt.status}, block ${receipt.blockNumber}, reconciled`
      : `${receipt.status}, NOT reconciled: ${reconciliation.reasons.join("; ")}`);
    return leg;
  };

  // --- transaction 1: owner -> probe ---
  const outbound = await runLeg({
    field: "outbound", label: "outbound transfer", from: ownerAddress, to: PROBE,
    simulate: () => client.simulateContract({ address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [PROBE, AMOUNT], account }),
    send: () => wallet.writeContract({ address: aUsdc, abi: ERC20_ABI, functionName: "transfer",
      args: [PROBE, AMOUNT], chain: null }),
  });

  if (!outbound.ok) {
    report.classification = "CONTRACT AUSDC CUSTODY ROUND-TRIP: OUTBOUND FAILED";
    report.status = "STOPPED";
    checkpoint();
    stop(`the outbound transfer did not settle cleanly. Hash ${outbound.hash}. No sweep was attempted.`);
  }

  // --- cost the sweep for real, now that the probe holds the unit ---
  // The preflight could only bound this at the ceiling, because estimating a sweep of a balance the
  // probe did not yet hold reverts. Now it is measurable, so it is measured rather than assumed.
  let sweepGas;
  let sweepGasPrice;
  try {
    sweepGas = await client.estimateContractGas({
      address: PROBE, abi: PROBE_ABI, functionName: "sweep",
      args: [aUsdc, ownerAddress, AMOUNT], account: ownerAddress });
  } catch (error) {
    stop(`the sweep could not be estimated after funding the probe:`
      + ` ${(error.shortMessage ?? error.message).slice(0, 140)}.`
      + ` One atomic unit is now held at ${PROBE}; no further transaction was sent.`);
  }
  try {
    sweepGasPrice = await client.getGasPrice();
  } catch (error) {
    stop(`the gas price could not be re-read before the sweep:`
      + ` ${(error.shortMessage ?? error.message).slice(0, 140)}.`
      + ` One atomic unit is now held at ${PROBE}; no further transaction was sent.`);
  }
  const sweepBudget = assertGasUsable(sweepGas, sweepGasPrice, GAS_LIMIT_CEILING);
  const remainingNative = await client.getBalance({ address: ownerAddress });
  assertFundedFor(ownerAddress, remainingNative, sweepBudget);
  report.gas = { ...report.gas, sweepEstimateMeasured: sweepGas.toString(),
    sweepPrice: sweepGasPrice.toString(), sweepBudgetWei: sweepBudget.toString(),
    ownerNativeBeforeSweepWei: remainingNative.toString() };
  checkpoint();
  note("sweep gas, measured", `${sweepGas} at ${sweepGasPrice} wei, budget ${sweepBudget} wei`);

  // --- transaction 2: probe -> owner, through the probe's own sweep ---
  let inbound = null;
  let inboundError = null;
  try {
    inbound = await runLeg({
      field: "inbound", label: "sweep back", from: PROBE, to: ownerAddress,
      simulate: () => client.simulateContract({ address: PROBE, abi: PROBE_ABI, functionName: "sweep",
        args: [aUsdc, ownerAddress, AMOUNT], account }),
      send: () => wallet.writeContract({ address: PROBE, abi: PROBE_ABI, functionName: "sweep",
        args: [aUsdc, ownerAddress, AMOUNT], chain: null }),
    });
  } catch (error) {
    inboundError = (error.shortMessage ?? error.message).slice(0, 300);
    note("sweep back", `did not complete: ${inboundError}`);
  }
  // A hash that exists without a resolved receipt is not a failure, it is an unknown. The
  // checkpoint wrote it before the wait, so it survives here.
  const inboundHash = report.inbound?.hash ?? null;
  const inboundReceiptResolved = report.inbound?.receipt === true;

  // --- final readbacks ---
  const finalOwner = await balanceOf(ownerAddress);
  const finalProbe = await balanceOf(PROBE);
  const afterPrecheck = {};
  for (const [label, from, to] of [["outbound", ownerAddress, PROBE], ["inbound", PROBE, ownerAddress]]) {
    afterPrecheck[label] = await client.readContract({
      address: policy, abi: POLICY_ABI, functionName: "canTransfer", args: [aUsdc, from, to, AMOUNT] })
      .catch((error) => `reverted: ${(error.shortMessage ?? error.message).slice(0, 80)}`);
  }
  const verifyAfter = [];
  for (const [label, address] of [["owner", ownerAddress], ["probe", PROBE]]) {
    const verify = scrub(await cleanverseRead("/verify_apass", { chain: "monad", atoken: aUsdc, address }));
    verifyAfter.push({ label, address, code: verify?.code === "0000" ? Number(verify.data?.code) : null });
  }

  report.balances = { ...report.balances,
    final: { owner: finalOwner.toString(), probe: finalProbe.toString() } };
  report.readbackAfter = { canTransfer: afterPrecheck, verifyApass: verifyAfter };
  report.classification = classifyRoundTrip({
    outbound, inbound, probeFinalBalance: finalProbe, inboundHash, inboundReceiptResolved });
  report.status = "COMPLETE";
  if (inboundError) report.inboundError = inboundError;

  if (report.classification.includes("RETURN PENDING")) {
    // The return may still land. Treating this balance as stranded and acting on it risks sending
    // the same unit twice, so no recovery is offered until the receipt resolves.
    report.pendingReturn = {
      hash: inboundHash,
      probeBalanceAtSnapshot: finalProbe.toString(),
      note: "The return transaction exists but its receipt was not resolved. No recovery is"
        + " offered and none may be attempted until this receipt is resolved: the balance above"
        + " is a snapshot, not a conclusion.",
      inboundError,
    };
    process.stdout.write(`\n  RETURN PENDING: ${inboundHash}\n`);
    process.stdout.write("  Resolve this receipt before considering any recovery.\n");
  } else if (report.classification.includes("FUNDS IN PROBE")) {
    // The unit is in the contract and the return is known not to have landed. What a recovery
    // needs is recorded as data; it is deliberately not a runnable command.
    report.recovery = describeRecovery({
      probe: PROBE, token: aUsdc, owner: ownerAddress, strandedUnits: finalProbe,
      encodeCalldata: () => encodeFunctionData({
        abi: PROBE_ABI, functionName: "sweep", args: [aUsdc, ownerAddress, finalProbe] }),
    });
    report.recovery.strandedHuman = format(finalProbe);
    process.stdout.write(`\n  FUNDS IN PROBE: ${format(finalProbe)} at ${PROBE}\n`);
    process.stdout.write("  No further transaction was sent. See report.recovery.\n");
  }

  note("final balances", `owner ${format(finalOwner)}, probe ${format(finalProbe)}`);
  process.stdout.write(`\n${"CLASSIFICATION".padEnd(32)} ${report.classification}\n`);
  checkpoint();
  process.stdout.write(`\nWrote ${out}.json\n`);
}

const invokedDirectly = process.argv[1]?.endsWith("m10-custody-roundtrip.mjs");
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
