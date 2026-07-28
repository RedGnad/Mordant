#!/usr/bin/env node
/**
 * M-13C: activation and the two terminal adapter paths, on a pinned Monad fork.
 *
 * M-13A proved the A-Pass call shape and the supply and role ceremony. This continues from there
 * to the part that makes it Mordant: a production vault bound to the adapter, then both ways the
 * custody can end, each from its own snapshot so neither can contaminate the other.
 *
 *   node scripts/m13c-activation-terminal.mjs [--out <prefix>]
 *
 * Scenario A, cash redemption: the buyer funds the face value, a holder redeems, and the adapter
 * BURNS the invoice units it held.
 *
 * Scenario B, default release: protection closes with units outstanding, and the adapter TRANSFERS
 * its units to the holders. The token supply does not fall on that path; the vault's own receipt
 * units are burned instead. Both are checked, because confusing the two would be easy and wrong.
 *
 * aUSDC is moved on the fork by impersonating addresses that really hold it, at amounts derived
 * from what really exists. Nothing is minted into existence to make the numbers work.
 *
 * Nothing public is touched: loopback Anvil only, no Cleanverse endpoint, no anvil_setStorageAt.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient, createTestClient, createWalletClient, http, keccak256, parseEventLogs, toBytes,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { runControlA } from "./m13-control-a.mjs";
import {
  APASS_REGISTRY, M13_FORK_BLOCK, M13_FORK_BLOCK_HASH, OBSERVED_ISSUANCE, OBSERVED_ISSUER,
  assertAnvilClient, assertForkChain, assertIssuanceMintEvent, assertLoopbackRpc, assertPinnedBlock,
  assertSubstitutionBounded, assertUpstreamSeparate, diffCalldata, substituteSubjectAddress,
} from "./m13-fork-lib.mjs";
import { ControlError, writeArtifact } from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UPSTREAM = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const FORK_PORT = Number(process.env.M13C_FORK_PORT ?? 8_550);
const FORK_RPC = `http://127.0.0.1:${FORK_PORT}`;

const MINV01 = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const MINV01_ADMIN = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const AUSDC = "0xaC0893567D43C3E7e6e35a72803df05416C1f20D";
const HOLDER_A = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const HOLDER_B = "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6";

/**
 * The largest real aUSDC holder we can impersonate on the fork. Every settlement figure below is
 * sized to fit inside what it actually holds, so no balance is invented.
 */
const AUSDC_SOURCE = "0x7f7098632b0258Af07e527015D65e6bc743f4CF5";

/** Atomic units throughout. Both tokens carry six decimals. */
const INITIAL_UNITS = 100_000n;
const ADVANCE_AMOUNT = 100_000n;
const FACE_VALUE = 110_000n;
const BOND_BPS = 1_000;
/** Advance plus face value, so the buyer can both fund activation and later fund redemption. */
const BUYER_FUNDING = ADVANCE_AMOUNT + FACE_VALUE;
/** The vault retains the bond out of the advance, so the originator receives the remainder. */
const BOND = (ADVANCE_AMOUNT * BigInt(BOND_BPS)) / 10_000n;
const NET_PROCEEDS = ADVANCE_AMOUNT - BOND;
/** Two holders, each allocated half, so each is owed half the face value. */
const HOLDER_SHARE = FACE_VALUE / 2n;

const MINTER_ROLE = keccak256(toBytes("MINTER_ROLE"));
const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
const INVOICE_ROOT = `0x${"c3".repeat(32)}`;

/** Anvil development keys. A fork only, never a real wallet. */
const FORK_KEYS = Object.freeze({
  deployer: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  issuanceMinter: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  buyer: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  originator: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  facility: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  /** A second, distinct facility: a conflict may only be raised by someone other than the protected one. */
  facilityTwo: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  /** The vault refuses a funder that is also the buyer, so advancing cash is its own role. */
  funder: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
});

const ERC20_ABI = [
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "totalSupply", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "hasRole", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "grantRole", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "revokeRole", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "mint", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
];

const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const ADAPTER_ABI = [
  { type: "function", name: "bindVault", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
  { type: "function", name: "boundVault", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "token", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "apass", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "availableBalance", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "issuedSupply", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
];

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

const artifact = (file, name) => {
  const parsed = JSON.parse(readFileSync(join(ROOT, `contracts/out/${file}/${name}.json`), "utf8"));
  return { abi: parsed.abi, bytecode: parsed.bytecode.object };
};

/**
 * Every precondition bindVault itself will check, verified beforehand so a refusal is diagnosed
 * here rather than as an opaque revert.
 */
export function checkBindPreconditions({
  adapterApass, vaultApass, participantApass, policyTuples, totalSupply, adapterBalance,
  expectedUnits, adapterIsMinter, adapterToken, adapterApassRegistry, vaultAdapter, vaultToken,
  vaultUnits, boundVault, expected,
}) {
  const reasons = [];
  if (adapterApass !== true) reasons.push("the adapter holds no valid A-Pass");
  if (vaultApass !== true) reasons.push("the vault holds no valid A-Pass");
  const missing = Object.entries(participantApass ?? {}).filter(([, valid]) => valid !== true);
  if (missing.length > 0) reasons.push(`participants without an A-Pass: ${missing.map(([name]) => name).join(", ")}`);
  const failedTuples = (policyTuples ?? []).filter((tuple) => tuple.answer !== true);
  if (failedTuples.length > 0) reasons.push(`policy refuses: ${failedTuples.map((tuple) => tuple.label).join(", ")}`);
  if (BigInt(totalSupply ?? -1n) !== BigInt(expectedUnits)) reasons.push(`totalSupply ${totalSupply}, expected ${expectedUnits}`);
  if (BigInt(adapterBalance ?? -1n) !== BigInt(expectedUnits)) reasons.push(`adapter holds ${adapterBalance}, expected ${expectedUnits}`);
  if (adapterIsMinter !== true) reasons.push("the adapter does not hold MINTER_ROLE");
  const same = (a, b) => String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
  if (!same(adapterToken, expected.token)) reasons.push(`adapter.token() is ${adapterToken}`);
  if (!same(adapterApassRegistry, expected.apass)) reasons.push(`adapter.apass() is ${adapterApassRegistry}`);
  if (!same(vaultAdapter, expected.adapter)) reasons.push(`vault.cvaAdapter() is ${vaultAdapter}`);
  if (!same(vaultToken, expected.token)) reasons.push(`vault.cvaToken() is ${vaultToken}`);
  if (BigInt(vaultUnits ?? -1n) !== BigInt(expectedUnits)) reasons.push(`vault.initialUnits() is ${vaultUnits}`);
  if (!same(boundVault, "0x0000000000000000000000000000000000000000")) {
    reasons.push(`the adapter is already bound to ${boundVault}`);
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Validates the SHAPE of the token deltas a burn should produce: supply and the adapter's balance
 * both falling by exactly the units.
 *
 * This is a delta-shape validator, not a proof of the vault's invariants. It says nothing about
 * custodyCredit, cvaAccounted, cvaBurned, the redemption escrow or the settlement leg; those are
 * checked when the scenario actually runs, in M-13C.
 */
export function validateBurnTokenDeltaShape({ supplyBefore, supplyAfter, adapterBefore, adapterAfter, units }) {
  const reasons = [];
  const expected = BigInt(units);
  if (BigInt(supplyBefore) - BigInt(supplyAfter) !== expected) {
    reasons.push(`supply fell by ${BigInt(supplyBefore) - BigInt(supplyAfter)}, expected ${expected}`);
  }
  if (BigInt(adapterBefore) - BigInt(adapterAfter) !== expected) {
    reasons.push(`the adapter balance fell by ${BigInt(adapterBefore) - BigInt(adapterAfter)}, expected ${expected}`);
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Validates the SHAPE of the token deltas a default release should produce: the adapter's balance
 * falls and the holder's rises, but the token supply does NOT, because this is a transfer. What is
 * burned is the vault's receipt unit.
 *
 * A delta-shape validator, not a proof of the vault's invariants. cvaReleasedFace, cvaAccounted and
 * the escrow refund are checked when the scenario runs, in M-13C.
 */
export function validateReleaseTokenDeltaShape({
  supplyBefore, supplyAfter, adapterBefore, adapterAfter, holderBefore, holderAfter,
  receiptBefore, receiptAfter, units,
}) {
  const reasons = [];
  const expected = BigInt(units);
  if (BigInt(supplyBefore) !== BigInt(supplyAfter)) {
    reasons.push(`the token supply changed by ${BigInt(supplyAfter) - BigInt(supplyBefore)};`
      + " a default release transfers, it does not burn");
  }
  if (BigInt(adapterBefore) - BigInt(adapterAfter) !== expected) {
    reasons.push(`the adapter balance fell by ${BigInt(adapterBefore) - BigInt(adapterAfter)}, expected ${expected}`);
  }
  if (BigInt(holderAfter) - BigInt(holderBefore) !== expected) {
    reasons.push(`the holder received ${BigInt(holderAfter) - BigInt(holderBefore)}, expected ${expected}`);
  }
  if (BigInt(receiptBefore) - BigInt(receiptAfter) !== expected) {
    reasons.push(`receipt units burned ${BigInt(receiptBefore) - BigInt(receiptAfter)}, expected ${expected}`);
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Activation is judged on the settlement it produced, not only on not reverting: the exact net
 * proceeds and bond, the receipt allocation, the vault's own accounting figures, and the adapter's
 * view of the credit it now owes the vault.
 */
export function validateActivation(observed, expected) {
  const reasons = [];
  const eq = (label, actual, want) => {
    if (BigInt(actual ?? -1n) !== BigInt(want)) reasons.push(`${label} ${actual}, expected ${want}`);
  };
  eq("net proceeds", observed.netProceedsReceived, expected.netProceeds);
  eq("bond locked", observed.bondLocked, expected.bond);
  eq("holderA receipts", observed.receiptHolderA, expected.allocation);
  eq("holderB receipts", observed.receiptHolderB, expected.allocation);
  eq("receipt supply", observed.receiptSupply, expected.units);
  eq("cvaAccounted", observed.cvaAccounted, expected.units);
  eq("adapter available", observed.adapterAvailable, expected.units);
  if (observed.protectionState !== expected.protectionState) {
    reasons.push(`protectionState ${observed.protectionState}, expected ${expected.protectionState}`);
  }
  if (observed.receivableState !== expected.receivableState) {
    reasons.push(`receivableState ${observed.receivableState}, expected ${expected.receivableState}`);
  }
  if (observed.assertAccounting !== true) reasons.push("assertAccounting() did not succeed");
  return { ok: reasons.length === 0, reasons };
}

/**
 * The burn path in full. The token deltas are necessary but nowhere near sufficient: a vault that
 * burned the right units while leaving escrow or cvaAccounted behind would still be broken.
 */
export function validateScenarioA(observed, expected) {
  const reasons = [];
  const eq = (label, actual, want) => {
    if (BigInt(actual ?? -1n) !== BigInt(want)) reasons.push(`${label} ${actual}, expected ${want}`);
  };
  for (const holder of observed.redeemed ?? []) {
    eq(`${holder.label} cash`, holder.cashReceived, expected.holderCash);
    eq(`${holder.label} receipts after`, holder.receiptsAfter, 0n);
  }
  if ((observed.redeemed ?? []).length !== 2) reasons.push(`${(observed.redeemed ?? []).length} redemptions, expected 2`);
  eq("MINV01 supply", observed.supplyAfter, 0n);
  eq("adapter balance", observed.adapterAfter, 0n);
  eq("receipt supply", observed.receiptSupplyAfter, 0n);
  eq("cvaAccounted", observed.cvaAccounted, 0n);
  eq("cvaBurned", observed.cvaBurned, expected.units);
  eq("redeemedFace", observed.redeemedFace, expected.faceValue);
  eq("redemptionEscrow", observed.redemptionEscrow, 0n);
  if (observed.deltaShape?.ok !== true) reasons.push("the token delta shape is wrong");
  if (observed.assertAccounting !== true) reasons.push("assertAccounting() did not succeed");
  return { ok: reasons.length === 0, reasons };
}

/**
 * The release path in full. The supply staying flat is the discriminator, but it is only one of the
 * conditions: the adapter must be emptied, the receipts burned, and the released face recorded.
 */
export function validateScenarioB(observed, expected) {
  const reasons = [];
  const eq = (label, actual, want) => {
    if (BigInt(actual ?? -1n) !== BigInt(want)) reasons.push(`${label} ${actual}, expected ${want}`);
  };
  for (const holder of observed.releases ?? []) {
    eq(`${holder.label} tokens`, holder.tokenReceived, expected.holderUnits);
    eq(`${holder.label} receipts after`, holder.receiptsAfter, 0n);
  }
  if ((observed.releases ?? []).length !== 2) reasons.push(`${(observed.releases ?? []).length} releases, expected 2`);
  eq("MINV01 supply", observed.supplyAfter, expected.units);
  if (BigInt(observed.supplyBefore ?? -1n) !== BigInt(observed.supplyAfter ?? -2n)) {
    reasons.push("the MINV01 supply changed; a default release transfers, it does not burn");
  }
  eq("adapter balance", observed.adapterAfter, 0n);
  eq("receipt supply", observed.receiptSupplyAfter, 0n);
  eq("cvaAccounted", observed.cvaAccounted, 0n);
  eq("cvaReleasedFace", observed.cvaReleasedFace, expected.faceValue);
  if (observed.defaultCvaReleaseStarted !== true) reasons.push("defaultCvaReleaseStarted is not true");
  if (observed.deltaShape?.ok !== true) reasons.push("the token delta shape is wrong");
  if (observed.assertAccounting !== true) reasons.push("assertAccounting() did not succeed");
  return { ok: reasons.length === 0, reasons };
}

/** The full rehearsal verdict. Every stage must hold; any gap leaves it NOT PROVEN. */
export function classifyRehearsal({ controlA, forkPinned, binding, activation, scenarioA, scenarioB }) {
  const missing = [];
  if (controlA !== true) missing.push("control A");
  if (forkPinned !== true) missing.push("the pinned fork");
  if (binding !== true) missing.push("vault binding");
  if (activation !== true) missing.push("activation");
  if (scenarioA !== true) missing.push("scenario A");
  if (scenarioB !== true) missing.push("scenario B");
  return missing.length === 0
    ? { classification: "M-13 PINNED MONAD FORK REHEARSAL: PROVEN", missing }
    : { classification: "M-13 PINNED MONAD FORK REHEARSAL: NOT PROVEN", missing };
}

async function main() {
  const argv = process.argv.slice(2);
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  const steps = [];
  const note = (label, detail) => {
    steps.push({ label, detail });
    process.stdout.write(`  ${label.padEnd(30)} ${detail}\n`);
  };

  assertLoopbackRpc(FORK_RPC);
  assertUpstreamSeparate(UPSTREAM, FORK_RPC);

  process.stdout.write("  running control A first, as a precondition\n");
  const controlA = await runControlA({});
  if (!controlA.proven) stop("control A did not prove the exact replay; the substitution must not run.");
  note("control A", controlA.classification);

  const report = {
    schemaVersion: 1, generatedAt: new Date().toISOString(), classification: "PENDING",
    scope: "Local fork only. No public transaction, no Cleanverse endpoint, no anvil_setStorageAt."
      + " Nothing here is a live Mordant settlement.",
    controlA: { classification: controlA.classification, proven: controlA.proven },
    steps,
  };

  const fork = spawn("anvil", [
    "--fork-url", UPSTREAM, "--fork-block-number", String(M13_FORK_BLOCK),
    "--port", String(FORK_PORT), "--host", "127.0.0.1", "--chain-id", "10143",
    "--code-size-limit", "131072", "--silent",
  ], { stdio: ["ignore", "ignore", "inherit"] });
  const stopFork = () => { if (!fork.killed) fork.kill("SIGTERM"); };
  process.on("SIGINT", () => { stopFork(); process.exit(0); });

  try {
    const transport = http(FORK_RPC);
    const client = createPublicClient({ transport });
    const test = createTestClient({ mode: "anvil", transport });
    for (let attempt = 0; ; attempt += 1) {
      try { await client.getBlockNumber(); break; }
      catch (error) {
        if (attempt > 120) stop(`the fork never became reachable: ${error.message}`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    const clientVersion = await client.request({ method: "web3_clientVersion" });
    assertAnvilClient(clientVersion);
    const chainId = assertForkChain(await client.getChainId());
    const block = await client.getBlock({ blockNumber: await client.getBlockNumber() });
    const pinned = assertPinnedBlock("M-13C", block, M13_FORK_BLOCK, M13_FORK_BLOCK_HASH);
    report.hygiene = { writeRpc: FORK_RPC, loopback: true, upstreamSeparate: true, clientVersion,
      chainId, forkBlock: pinned.number, forkBlockHash: pinned.hash, pinnedByNumberAndHash: true };
    note("fork", `${clientVersion}, chain ${chainId}, block ${pinned.number}`);

    const accounts = Object.fromEntries(
      Object.entries(FORK_KEYS).map(([role, key]) => [role, privateKeyToAccount(key)]));
    for (const account of Object.values(accounts)) {
      await test.setBalance({ address: account.address, value: 10n ** 20n });
    }
    const walletFor = (account) => createWalletClient({ account, transport });
    const send = async (wallet, address, abi, functionName, args) => {
      const hash = await wallet.writeContract({ address, abi, functionName, args, chain: null });
      const receipt = await client.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") stop(`${functionName} reverted on the fork. Hash ${hash}.`);
      return receipt;
    };
    const impersonate = async (address) => {
      await test.impersonateAccount({ address });
      await test.setBalance({ address, value: 10n ** 19n });
      return createWalletClient({ account: address, transport });
    };

    // --- the M-13A ceremony, replayed here so this fork stands on its own ---
    const adapterArtifact = artifact("CleanverseCvaAdapter.sol", "CleanverseCvaAdapter");
    const deployerWallet = walletFor(accounts.deployer);
    const adapterDeploy = await client.waitForTransactionReceipt({
      hash: await deployerWallet.deployContract({ abi: adapterArtifact.abi,
        bytecode: adapterArtifact.bytecode, args: [MINV01_ADMIN, MINV01, APASS_REGISTRY], chain: null }) });
    const adapter = adapterDeploy.contractAddress;
    if (adapterDeploy.status !== "success" || !adapter) stop("the adapter deployment failed.");
    note("adapter deployed", adapter);

    const issuerWallet = await impersonate(OBSERVED_ISSUER);
    const issueApassFor = async (subject, label) => {
      const substituted = substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, subject);
      assertSubstitutionBounded(diffCalldata(OBSERVED_ISSUANCE.calldata, substituted));
      const receipt = await client.waitForTransactionReceipt({
        hash: await issuerWallet.sendTransaction({
          to: APASS_REGISTRY, data: substituted, value: 0n, chain: null, gas: 2_000_000n }) });
      if (receipt.status !== "success") stop(`the A-Pass issuance for ${label} reverted.`);
      assertIssuanceMintEvent(receipt.logs, APASS_REGISTRY, subject);
      const valid = await client.readContract({
        address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass", args: [subject] });
      if (valid !== true) stop(`${label} still holds no valid A-Pass after issuance.`);
      return { subject, label, hash: receipt.transactionHash, isValidAPass: valid };
    };

    const issued = [await issueApassFor(adapter, "adapter")];
    note("adapter A-Pass", `issued, isValidAPass ${issued[0].isValidAPass}`);

    // Fork-local A-Passes for the participants that do not already hold one.
    const participants = { buyer: accounts.buyer.address, originator: accounts.originator.address,
      facility: accounts.facility.address, funder: accounts.funder.address };
    for (const [label, address] of Object.entries(participants)) {
      const already = await client.readContract({
        address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass", args: [address] });
      if (already === true) continue;
      issued.push(await issueApassFor(address, label));
    }
    note("participant A-Passes", `${issued.length - 1} issued fork-local`);
    report.apassIssued = issued;

    // Supply and role ceremony.
    const adminWallet = await impersonate(MINV01_ADMIN);
    await send(adminWallet, MINV01, ERC20_ABI, "grantRole", [MINTER_ROLE, accounts.issuanceMinter.address]);
    await send(walletFor(accounts.issuanceMinter), MINV01, ERC20_ABI, "mint", [adapter, INITIAL_UNITS]);
    await send(adminWallet, MINV01, ERC20_ABI, "revokeRole", [MINTER_ROLE, accounts.issuanceMinter.address]);
    await send(adminWallet, MINV01, ERC20_ABI, "grantRole", [MINTER_ROLE, adapter]);
    note("supply ceremony", `${INITIAL_UNITS} units minted to the adapter, roles settled`);

    // --- aUSDC, moved from an address that really holds it ---
    const sourceBalance = await client.readContract({
      address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [AUSDC_SOURCE] });
    if (sourceBalance < BUYER_FUNDING) {
      stop(`the aUSDC source holds ${sourceBalance}, less than the ${BUYER_FUNDING} the buyer needs.`
        + " Amounts are derived from what exists and nothing is minted to make them work.");
    }
    const sourceWallet = await impersonate(AUSDC_SOURCE);
    const transferAbi = [{ type: "event", name: "Transfer", inputs: [
      { name: "from", type: "address", indexed: true }, { name: "to", type: "address", indexed: true },
      { name: "value", type: "uint256", indexed: false }] }];

    /** One reconciled leg: receipt, a single matching Transfer, and both exact deltas. */
    const fundLeg = async (label, recipient, amount) => {
      const sourceBefore = await client.readContract({
        address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [AUSDC_SOURCE] });
      const recipientBefore = await client.readContract({
        address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [recipient] });
      const receipt = await send(sourceWallet, AUSDC, ERC20_ABI, "transfer", [recipient, amount]);
      const events = parseEventLogs({ abi: transferAbi, eventName: "Transfer",
        logs: receipt.logs.filter((log) => String(log.address).toLowerCase() === AUSDC.toLowerCase()) })
        .map((event) => ({ from: event.args.from, to: event.args.to, value: event.args.value.toString() }));
      const sourceAfter = await client.readContract({
        address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [AUSDC_SOURCE] });
      const recipientAfter = await client.readContract({
        address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [recipient] });
      const reasons = [];
      if (receipt.status !== "success") reasons.push(`receipt status ${receipt.status}`);
      if (events.length !== 1) reasons.push(`${events.length} Transfer events, expected 1`);
      const [only] = events;
      if (only && (String(only.from).toLowerCase() !== AUSDC_SOURCE.toLowerCase()
        || String(only.to).toLowerCase() !== String(recipient).toLowerCase()
        || BigInt(only.value) !== amount)) {
        reasons.push("the Transfer event does not match the intended source, recipient and amount");
      }
      if (sourceAfter - sourceBefore !== -amount) reasons.push(`source delta ${sourceAfter - sourceBefore}, expected -${amount}`);
      if (recipientAfter - recipientBefore !== amount) reasons.push(`recipient delta ${recipientAfter - recipientBefore}, expected ${amount}`);
      if (reasons.length > 0) stop(`the ${label} funding leg did not reconcile: ${reasons.join("; ")}`);
      note(`funding leg ${label}`, `${amount} reconciled, source -${amount}, ${label} +${amount}`);
      return { label, recipient, amount: amount.toString(), hash: receipt.transactionHash,
        status: receipt.status, blockNumber: receipt.blockNumber.toString(),
        gasUsed: receipt.gasUsed.toString(), transferEvents: events,
        sourceBefore: sourceBefore.toString(), sourceAfter: sourceAfter.toString(),
        recipientBefore: recipientBefore.toString(), recipientAfter: recipientAfter.toString(),
        sourceDelta: (sourceAfter - sourceBefore).toString(),
        recipientDelta: (recipientAfter - recipientBefore).toString(), reconciled: true };
    };

    // Two payers, two roles: the funder advances at activation, the buyer settles at maturity.
    const legFunder = await fundLeg("funder", accounts.funder.address, ADVANCE_AMOUNT);
    const legBuyer = await fundLeg("buyer", accounts.buyer.address, FACE_VALUE);

    // The aggregate must hold as well as each leg, or a compensating pair of errors could hide.
    const aggregate = {
      sourceDelta: (BigInt(legFunder.sourceDelta) + BigInt(legBuyer.sourceDelta)).toString(),
      funderDelta: legFunder.recipientDelta, buyerDelta: legBuyer.recipientDelta,
    };
    if (aggregate.sourceDelta !== (-BUYER_FUNDING).toString()
      || aggregate.funderDelta !== ADVANCE_AMOUNT.toString()
      || aggregate.buyerDelta !== FACE_VALUE.toString()) {
      stop(`the aggregate funding does not reconcile: ${JSON.stringify(aggregate)}`);
    }
    note("funding aggregate", `source ${aggregate.sourceDelta}, funder +${aggregate.funderDelta},`
      + ` buyer +${aggregate.buyerDelta}`);
    report.aUsdcFunding = { source: AUSDC_SOURCE, legs: [legFunder, legBuyer], aggregate,
      note: "impersonated an address that really holds aUSDC; no balance was invented" };

    // --- production Mordant contracts ---
    const verifierArtifact = artifact("CleanverseAPassVerifier.sol", "CleanverseAPassVerifier");
    const factoryArtifact = artifact("MordantFactory.sol", "MordantFactory");
    const deployFor = async ({ abi, bytecode }, args) => {
      const receipt = await client.waitForTransactionReceipt({
        hash: await deployerWallet.deployContract({ abi, bytecode, args, chain: null }) });
      if (receipt.status !== "success") stop("a production contract deployment reverted.");
      return receipt.contractAddress;
    };
    // Role mask 16 opens role 4, holders, to any eligible A-Pass; institutional roles stay granted.
    const verifier = await deployFor(verifierArtifact, [accounts.deployer.address, APASS_REGISTRY, 16n]);
    const factory = await deployFor(factoryArtifact, [accounts.deployer.address, verifier]);
    note("production contracts", `verifier ${verifier}, factory ${factory}`);

    for (const [role, account] of [[1, accounts.buyer.address], [2, accounts.originator.address],
      [3, accounts.facility.address]]) {
      await send(deployerWallet, verifier, verifierArtifact.abi, "setRoleEligibility", [account, role, true]);
    }
    for (const [fn, args] of [["setFacility", [accounts.facility.address, true]],
      ["setCvaAdapter", [adapter, true]], ["setSettlementToken", [AUSDC, true]]]) {
      await send(deployerWallet, factory, factoryArtifact.abi, fn, args);
    }
    note("factory configured", "roles, facility, adapter and settlement token allowlisted");

    const now = (await client.getBlock()).timestamp;
    const protectionEnd = now + 30n * 24n * 3_600n;
    const createReceipt = await send(walletFor(accounts.buyer), factory, factoryArtifact.abi,
      "createInvoiceVault", [{
        cvaAdapter: adapter, settlementToken: AUSDC, invoiceRoot: INVOICE_ROOT, currency: CURRENCY,
        buyer: accounts.buyer.address, originatorTreasury: accounts.originator.address,
        initialOriginatorSigner: accounts.originator.address,
        initialUnits: INITIAL_UNITS, advanceAmount: ADVANCE_AMOUNT, faceValue: FACE_VALUE,
        bondBps: BOND_BPS, protectionEnd, revealPeriod: 3_600n, curePeriod: 3_600n,
      }]);
    const [created] = parseEventLogs({ abi: factoryArtifact.abi, eventName: "InvoiceVaultCreated",
      logs: createReceipt.logs });
    const vault = created.args.vault;
    note("vault created", vault);

    // The vault needs its own A-Pass before it can settle, and its address exists only now.
    issued.push(await issueApassFor(vault, "vault"));
    note("vault A-Pass", "issued fork-local");

    // --- every bindVault precondition, checked before the call ---
    const readAdapter = (fn, args) => client.readContract({ address: adapter, abi: ADAPTER_ABI, functionName: fn, args });
    const vaultAbi = artifact("MordantInvoiceVault.sol", "MordantInvoiceVault").abi;
    const readVault = (fn, args) => client.readContract({ address: vault, abi: vaultAbi, functionName: fn, args });
    const validApass = (address) => client.readContract({
      address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass", args: [address] });
    const policyAbi = [{ type: "function", name: "canTransfer", stateMutability: "view",
      inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
      outputs: [{ type: "bool" }] }];
    const policy = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";
    const can = async (token, from, to, amount, label) => ({ label, token, from, to,
      amount: amount.toString(),
      answer: await client.readContract({ address: policy, abi: policyAbi,
        functionName: "canTransfer", args: [token, from, to, amount] }).catch(() => false) });
    const ZERO = "0x0000000000000000000000000000000000000000";
    const policyTuples = [
      await can(MINV01, ZERO, adapter, INITIAL_UNITS, "MINV01 mint to adapter"),
      await can(MINV01, adapter, ZERO, INITIAL_UNITS, "MINV01 burn from adapter"),
      await can(MINV01, adapter, HOLDER_A, INITIAL_UNITS / 2n, "MINV01 release to holderA"),
      await can(MINV01, adapter, HOLDER_B, INITIAL_UNITS / 2n, "MINV01 release to holderB"),
      // The buyer pays twice: the advance at activation, then the face value to fund redemption.
      await can(AUSDC, accounts.funder.address, vault, ADVANCE_AMOUNT, "aUSDC activation advance in"),
      // Net proceeds are the advance less the bond the vault retains, not the whole advance.
      await can(AUSDC, vault, accounts.originator.address, NET_PROCEEDS, "aUSDC net proceeds out"),
      await can(AUSDC, accounts.buyer.address, vault, FACE_VALUE, "aUSDC redemption funding in"),
      // Cash redemption pays the HOLDERS. There is no vault-to-buyer leg here: a flow back to the
      // buyer could only be a refund of genuine excess, with its own amount, and none arises.
      await can(AUSDC, vault, HOLDER_A, HOLDER_SHARE, "aUSDC redemption to holderA"),
      await can(AUSDC, vault, HOLDER_B, HOLDER_SHARE, "aUSDC redemption to holderB"),
    ];
    for (const tuple of policyTuples) note(`policy ${tuple.label}`, String(tuple.answer));

    const preconditions = checkBindPreconditions({
      adapterApass: await validApass(adapter), vaultApass: await validApass(vault),
      participantApass: {
        buyer: await validApass(accounts.buyer.address),
        funder: await validApass(accounts.funder.address),
        originator: await validApass(accounts.originator.address),
        holderA: await validApass(HOLDER_A), holderB: await validApass(HOLDER_B),
      },
      policyTuples,
      totalSupply: await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" }),
      adapterBalance: await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] }),
      expectedUnits: INITIAL_UNITS,
      adapterIsMinter: await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "hasRole", args: [MINTER_ROLE, adapter] }),
      adapterToken: await readAdapter("token"), adapterApassRegistry: await readAdapter("apass"),
      vaultAdapter: await readVault("cvaAdapter"), vaultToken: await readVault("cvaToken"),
      vaultUnits: await readVault("initialUnits"), boundVault: await readAdapter("boundVault"),
      expected: { token: MINV01, apass: APASS_REGISTRY, adapter },
    });
    report.bindPreconditions = { ...preconditions, policyTuples };
    note("bind preconditions", preconditions.ok ? "all pass" : preconditions.reasons.join("; "));
    if (!preconditions.ok) stop(`bindVault preconditions unmet: ${preconditions.reasons.join("; ")}`);

    // Everything the preconditions were computed from, recorded rather than summarised, so the
    // artifact can be re-checked without rerunning the fork.
    const apassProvenance = {
      adapter: { address: adapter, isValidAPass: await validApass(adapter),
        provenance: "issued fork-local by bounded substitution of the observed call" },
      vault: { address: vault, isValidAPass: await validApass(vault),
        provenance: "issued fork-local after creation, since the address does not exist before" },
      funder: { address: accounts.funder.address, isValidAPass: await validApass(accounts.funder.address),
        provenance: "issued fork-local; the vault refuses a funder that is also the buyer" },
      buyer: { address: accounts.buyer.address, isValidAPass: await validApass(accounts.buyer.address),
        provenance: issued.some((entry) => entry.subject === accounts.buyer.address)
          ? "issued fork-local" : "already valid in the forked state" },
      originator: { address: accounts.originator.address,
        isValidAPass: await validApass(accounts.originator.address),
        provenance: issued.some((entry) => entry.subject === accounts.originator.address)
          ? "issued fork-local" : "already valid in the forked state" },
      facility: { address: accounts.facility.address,
        isValidAPass: await validApass(accounts.facility.address),
        provenance: issued.some((entry) => entry.subject === accounts.facility.address)
          ? "issued fork-local" : "already valid in the forked state" },
      holderA: { address: HOLDER_A, isValidAPass: await validApass(HOLDER_A),
        provenance: "issued live in M-11, preserved by the fork" },
      holderB: { address: HOLDER_B, isValidAPass: await validApass(HOLDER_B),
        provenance: "issued live in M-11, preserved by the fork" },
    };
    const beforeBind = {
      totalSupply: (await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" })).toString(),
      adapterBalance: (await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] })).toString(),
      adapterIsMinter: await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "hasRole", args: [MINTER_ROLE, adapter] }),
      adminIsMinter: await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "hasRole", args: [MINTER_ROLE, MINV01_ADMIN] }),
      issuanceWalletIsMinter: await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "hasRole", args: [MINTER_ROLE, accounts.issuanceMinter.address] }),
      adapterReadback: { token: await readAdapter("token"), apass: await readAdapter("apass"),
        owner: await readAdapter("owner"), boundVault: await readAdapter("boundVault"),
        issuedSupply: (await readAdapter("issuedSupply")).toString() },
      vaultReadback: { cvaAdapter: await readVault("cvaAdapter"), cvaToken: await readVault("cvaToken"),
        initialUnits: (await readVault("initialUnits")).toString(),
        settlementToken: await readVault("settlementToken"),
        faceValue: (await readVault("faceValue")).toString(),
        advanceAmount: (await readVault("advanceAmount")).toString() },
    };

    const bindReceipt = await send(adminWallet, adapter, ADAPTER_ABI, "bindVault", [vault, INITIAL_UNITS]);
    const [bound] = parseEventLogs({ abi: adapterArtifact.abi, eventName: "VaultBound",
      logs: bindReceipt.logs });
    const boundTo = await readAdapter("boundVault");
    if (String(boundTo).toLowerCase() !== String(vault).toLowerCase()) {
      stop(`bindVault did not bind to the vault; boundVault is ${boundTo}.`);
    }
    if (!bound || String(bound.args.vault).toLowerCase() !== String(vault).toLowerCase()
      || BigInt(bound.args.units) !== INITIAL_UNITS) {
      stop("bindVault emitted no VaultBound event matching the intended vault and units.");
    }
    const afterBind = {
      boundVault: boundTo,
      availableBalance: (await readAdapter("availableBalance", [vault])).toString(),
      issuedSupply: (await readAdapter("issuedSupply")).toString(),
      adapterBalance: (await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] })).toString(),
      totalSupply: (await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" })).toString(),
    };
    note("bindVault", `bound to ${boundTo}, availableBalance ${afterBind.availableBalance}`);
    note("VaultBound", `vault ${bound.args.vault}, units ${bound.args.units},`
      + ` block ${bindReceipt.blockNumber}`);

    report.apassProvenance = apassProvenance;
    report.binding = {
      before: beforeBind, after: afterBind,
      transaction: { hash: bindReceipt.transactionHash, status: bindReceipt.status,
        blockNumber: bindReceipt.blockNumber.toString(), blockHash: bindReceipt.blockHash,
        gasUsed: bindReceipt.gasUsed.toString() },
      vaultBoundEvent: { vault: bound.args.vault, units: bound.args.units.toString() },
    };

    report.vault = { address: vault, verifier, factory, boundVault: boundTo,
      initialUnits: INITIAL_UNITS.toString(), advanceAmount: ADVANCE_AMOUNT.toString(),
      faceValue: FACE_VALUE.toString(), bondBps: BOND_BPS, protectionEnd: protectionEnd.toString() };
    report.statuses = {
      "FORK APASS REGISTRY ISSUE": "PROVEN",
      "PRODUCTION VAULT BINDING": "PROVEN ON FORK",
      "ADAPTER BURN PATH": "NOT ATTEMPTED YET",
      "ADAPTER DEFAULT RELEASE": "NOT ATTEMPTED YET",
      "PUBLIC ADAPTER DEPLOYMENT": "NOT DONE",
      "MORDANT SETTLEMENT": "NOT PROVEN LIVE",
    };
    // --- a second, distinct facility, since a conflict cannot come from the protected one ---
    // Order matters: setFacility asks the verifier whether the address is eligible, and the
    // verifier consults the live A-Pass. The credential must exist before the allowlist entry.
    if (await validApass(accounts.facilityTwo.address) !== true) {
      issued.push(await issueApassFor(accounts.facilityTwo.address, "facilityTwo"));
    }
    await send(deployerWallet, verifier, verifierArtifact.abi, "setRoleEligibility",
      [accounts.facilityTwo.address, 3, true]);
    await send(deployerWallet, factory, factoryArtifact.abi, "setFacility",
      [accounts.facilityTwo.address, true]);
    note("second facility", `${accounts.facilityTwo.address}, eligible and allowlisted`);

    const snapshotAfterBind = await test.snapshot();
    note("snapshot", `post-binding ${snapshotAfterBind}`);

    // --- activation ---
    const domain = { name: "Mordant", version: "1", chainId: 10_143, verifyingContract: vault };
    const pledgeTypes = { Pledge: [
      { name: "invoiceRoot", type: "bytes32" }, { name: "originatorSigner", type: "address" },
      { name: "facility", type: "address" }, { name: "obligationId", type: "bytes32" },
      { name: "amount", type: "uint256" }, { name: "currency", type: "bytes32" },
      { name: "activeFrom", type: "uint64" }, { name: "activeUntil", type: "uint64" },
      { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint64" },
      { name: "exclusive", type: "bool" }] };
    const buildPledge = (facilityAddress, nonce, obligationId) => ({
      invoiceRoot: INVOICE_ROOT, originatorSigner: accounts.originator.address,
      facility: facilityAddress, obligationId, amount: FACE_VALUE, currency: CURRENCY,
      activeFrom: now - 3_600n, activeUntil: protectionEnd + 30n * 24n * 3_600n,
      nonce, deadline: protectionEnd + 60n * 24n * 3_600n, exclusive: true });
    const signPledge = (pledge) => accounts.originator.signTypedData({
      domain, types: pledgeTypes, primaryType: "Pledge", message: pledge });

    const receipts = {};
    const record = (label, receipt, extra = {}) => {
      receipts[label] = { hash: receipt.transactionHash, status: receipt.status,
        blockNumber: receipt.blockNumber.toString(), blockHash: receipt.blockHash,
        gasUsed: receipt.gasUsed.toString(),
        adapterEvents: parseEventLogs({ abi: adapterArtifact.abi,
          logs: receipt.logs.filter((log) => String(log.address).toLowerCase() === String(adapter).toLowerCase()) })
          .map((event) => ({ name: event.eventName,
            args: Object.fromEntries(Object.entries(event.args ?? {}).map(([k, v]) => [k, String(v)])) })),
        ...extra };
      return receipt;
    };

    const pledge = buildPledge(accounts.facility.address, 1n, `0x${"a1".repeat(32)}`);
    const pledgeSignature = await signPledge(pledge);
    await send(walletFor(accounts.funder), AUSDC, ERC20_ABI, "approve", [vault, ADVANCE_AMOUNT]);
    const originatorBefore = await client.readContract({
      address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [accounts.originator.address] });
    const allocation = INITIAL_UNITS / 2n;
    record("activate", await send(walletFor(accounts.facility), vault, vaultAbi, "activate",
      [pledge, pledgeSignature, accounts.funder.address, [HOLDER_A, HOLDER_B], [allocation, allocation]]));

    const originatorAfter = await client.readContract({
      address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [accounts.originator.address] });
    const activation = {
      netProceedsReceived: (originatorAfter - originatorBefore).toString(),
      expectedNetProceeds: NET_PROCEEDS.toString(),
      bondLocked: (await readVault("bondLocked")).toString(), expectedBond: BOND.toString(),
      receiptHolderA: (await readVault("balanceOf", [HOLDER_A])).toString(),
      receiptHolderB: (await readVault("balanceOf", [HOLDER_B])).toString(),
      receiptSupply: (await readVault("totalSupply")).toString(),
      cvaAccounted: (await readVault("cvaAccounted")).toString(),
      adapterAvailable: (await readAdapter("availableBalance", [vault])).toString(),
      protectionState: Number(await readVault("protectionState")),
      receivableState: Number(await readVault("receivableState")),
      assertAccounting: await readVault("assertAccounting").then(() => true).catch(() => false),
    };
    // ProtectionState.Active is 1 and ReceivableState.Outstanding is 1 in the vault's enums.
    const activationResult = validateActivation(activation, { netProceeds: NET_PROCEEDS, bond: BOND,
      allocation, units: INITIAL_UNITS, protectionState: 1, receivableState: 1 });
    if (!activationResult.ok) stop(`activation did not settle as intended: ${activationResult.reasons.join("; ")}`);
    report.activation = { ...activation, validation: activationResult, ok: activationResult.ok };
    note("activated", `net proceeds ${activation.netProceedsReceived}, bond ${activation.bondLocked},`
      + ` receipts ${activation.receiptHolderA}/${activation.receiptHolderB}`);

    const snapshotAfterActivation = await test.snapshot();
    note("snapshot", `post-activation ${snapshotAfterActivation}`);

    // --- scenario A: cash redemption and burn ---
    const supplyBeforeA = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" });
    const adapterBeforeA = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] });
    await send(walletFor(accounts.buyer), AUSDC, ERC20_ABI, "approve", [vault, FACE_VALUE]);
    record("fundRedemption", await send(walletFor(accounts.buyer), vault, vaultAbi, "fundRedemption", [FACE_VALUE]));
    const redeemed = [];
    for (const [label, holder] of [["holderA", HOLDER_A], ["holderB", HOLDER_B]]) {
      const wallet = await impersonate(holder);
      const cashBefore = await client.readContract({ address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [holder] });
      const receiptUnits = await readVault("balanceOf", [holder]);
      record(`redeem_${label}`, await send(wallet, vault, vaultAbi, "redeem", [receiptUnits]));
      const cashAfter = await client.readContract({ address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [holder] });
      redeemed.push({ label, holder, units: receiptUnits.toString(),
        cashReceived: (cashAfter - cashBefore).toString(),
        receiptsAfter: (await readVault("balanceOf", [holder])).toString() });
      note(`redeem ${label}`, `${receiptUnits} units, received ${cashAfter - cashBefore} aUSDC`);
    }
    const supplyAfterA = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" });
    const adapterAfterA = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] });
    const burnShape = validateBurnTokenDeltaShape({ supplyBefore: supplyBeforeA, supplyAfter: supplyAfterA,
      adapterBefore: adapterBeforeA, adapterAfter: adapterAfterA, units: INITIAL_UNITS });
    const scenarioA = {
      supplyBefore: supplyBeforeA.toString(), supplyAfter: supplyAfterA.toString(),
      adapterBefore: adapterBeforeA.toString(), adapterAfter: adapterAfterA.toString(),
      redeemed, deltaShape: burnShape,
      receiptSupplyAfter: (await readVault("totalSupply")).toString(),
      cvaAccounted: (await readVault("cvaAccounted")).toString(),
      cvaBurned: (await readVault("cvaBurned")).toString(),
      redeemedFace: (await readVault("redeemedFace")).toString(),
      redemptionEscrow: (await readVault("redemptionEscrow")).toString(),
      assertAccounting: await readVault("assertAccounting").then(() => true).catch(() => false),
    };
    const scenarioAResult = validateScenarioA(scenarioA,
      { holderCash: HOLDER_SHARE, units: INITIAL_UNITS, faceValue: FACE_VALUE });
    scenarioA.validation = scenarioAResult;
    scenarioA.ok = scenarioAResult.ok;
    if (!scenarioAResult.ok) stop(`scenario A did not settle as intended: ${scenarioAResult.reasons.join("; ")}`);
    report.scenarioA = scenarioA;
    note("scenario A", `MINV01 supply ${supplyAfterA}, receipts ${scenarioA.receiptSupplyAfter},`
      + ` cvaBurned ${scenarioA.cvaBurned}`);

    // --- scenario B: conflict, default, release. From the post-activation snapshot. ---
    await test.revert({ id: snapshotAfterActivation });
    note("reverted", "to the post-activation snapshot, so neither branch contaminates the other");

    const conflicting = buildPledge(accounts.facilityTwo.address, 2n, `0x${"b2".repeat(32)}`);
    const conflictingSignature = await signPledge(conflicting);
    const salt = `0x${"5a".repeat(32)}`;
    const commitment = await client.readContract({ address: vault, abi: vaultAbi,
      functionName: "conflictCommitment",
      args: [await client.readContract({ address: vault, abi: vaultAbi, functionName: "hashPledge", args: [conflicting] }),
        keccak256(conflictingSignature), accounts.facilityTwo.address, salt] });
    record("commitConflict", await send(walletFor(accounts.facilityTwo), vault, vaultAbi, "commitConflict", [commitment]));
    record("revealConflict", await send(walletFor(accounts.facilityTwo), vault, vaultAbi, "revealConflict",
      [conflicting, conflictingSignature, salt]));
    note("conflict", "committed and revealed by the second facility");

    await test.increaseTime({ seconds: 3_601 });
    await test.mine({ blocks: 1 });
    record("finalizeConflict", await send(walletFor(accounts.deployer), vault, vaultAbi, "finalizeConflict", []));
    note("finalized", "past the cure deadline");

    await test.increaseTime({ seconds: Number(protectionEnd - (await client.getBlock()).timestamp) + 60 });
    await test.mine({ blocks: 1 });
    record("markDefault", await send(walletFor(accounts.deployer), vault, vaultAbi, "markDefault", []));
    note("default", "marked past protectionEnd");

    const supplyBeforeB = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" });
    const adapterBeforeB = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] });
    const releases = [];
    for (const [label, holder] of [["holderA", HOLDER_A], ["holderB", HOLDER_B]]) {
      const wallet = await impersonate(holder);
      const tokenBefore = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [holder] });
      const receiptsBefore = await readVault("balanceOf", [holder]);
      record(`releaseDefaultCva_${label}`, await send(wallet, vault, vaultAbi, "releaseDefaultCva", [receiptsBefore]));
      const tokenAfter = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [holder] });
      releases.push({ label, holder, units: receiptsBefore.toString(),
        tokenReceived: (tokenAfter - tokenBefore).toString(),
        receiptsAfter: (await readVault("balanceOf", [holder])).toString() });
      note(`release ${label}`, `${receiptsBefore} units, received ${tokenAfter - tokenBefore} MINV01`);
    }
    const supplyAfterB = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "totalSupply" });
    const adapterAfterB = await client.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [adapter] });
    const releaseShape = validateReleaseTokenDeltaShape({
      supplyBefore: supplyBeforeB, supplyAfter: supplyAfterB,
      adapterBefore: adapterBeforeB, adapterAfter: adapterAfterB,
      holderBefore: 0n, holderAfter: BigInt(releases[0].tokenReceived) + BigInt(releases[1].tokenReceived),
      receiptBefore: INITIAL_UNITS, receiptAfter: await readVault("totalSupply"), units: INITIAL_UNITS });
    const scenarioB = {
      supplyBefore: supplyBeforeB.toString(), supplyAfter: supplyAfterB.toString(),
      adapterBefore: adapterBeforeB.toString(), adapterAfter: adapterAfterB.toString(),
      releases, deltaShape: releaseShape,
      receiptSupplyAfter: (await readVault("totalSupply")).toString(),
      cvaReleasedFace: (await readVault("cvaReleasedFace")).toString(),
      cvaAccounted: (await readVault("cvaAccounted")).toString(),
      defaultCvaReleaseStarted: await readVault("defaultCvaReleaseStarted"),
      assertAccounting: await readVault("assertAccounting").then(() => true).catch(() => false),
    };
    const scenarioBResult = validateScenarioB(scenarioB,
      { holderUnits: INITIAL_UNITS / 2n, units: INITIAL_UNITS, faceValue: FACE_VALUE });
    scenarioB.validation = scenarioBResult;
    scenarioB.ok = scenarioBResult.ok;
    if (!scenarioBResult.ok) stop(`scenario B did not settle as intended: ${scenarioBResult.reasons.join("; ")}`);
    report.scenarioB = scenarioB;
    note("scenario B", `MINV01 supply unchanged at ${supplyAfterB}, cvaReleasedFace`
      + ` ${scenarioB.cvaReleasedFace}, receipts ${scenarioB.receiptSupplyAfter}`);

    report.statuses = {
      "FORK APASS REGISTRY ISSUE": "PROVEN",
      "TEMPORARY ISSUANCE MINTER": "GRANTED / REVOKED",
      "ADAPTER MINTER ROLE": "GRANTED ON FORK",
      "EXACT SUPPLY CEREMONY": "PROVEN",
      "PRODUCTION VAULT BINDING": "PROVEN ON FORK",
      "ADAPTER BURN PATH": scenarioA.ok ? "PROVEN ON FORK" : "NOT PROVEN",
      "ADAPTER DEFAULT RELEASE": scenarioB.ok ? "PROVEN ON FORK" : "NOT PROVEN",
      "PUBLIC ADAPTER DEPLOYMENT": "NOT DONE",
      "LIVE ADAPTER APASS": "NOT PROVEN FOR THIS ADDRESS",
      "LIVE MINTER ROLE / MINT / BIND": "NOT DONE",
      "MORDANT SETTLEMENT": "NOT PROVEN LIVE",
    };
    const verdict = classifyRehearsal({
      controlA: controlA.proven === true,
      forkPinned: report.hygiene.pinnedByNumberAndHash === true,
      binding: report.binding?.after?.boundVault?.toLowerCase() === String(vault).toLowerCase(),
      activation: activationResult.ok, scenarioA: scenarioAResult.ok, scenarioB: scenarioBResult.ok });
    report.verdict = verdict;
    report.receipts = receipts;
    report.classification = verdict.classification;
    process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);

    if (out) { writeArtifact(out, report, process.env); process.stdout.write(`\nWrote ${out}.json\n`); }
  } finally {
    stopFork();
  }
}

const invokedDirectly = process.argv[1]?.endsWith("m13c-activation-terminal.mjs");
if (invokedDirectly) {
  process.stdout.write("M-13C: vault binding and terminal adapter paths\n\n");
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof ControlError ? error.message : `STOP — ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
