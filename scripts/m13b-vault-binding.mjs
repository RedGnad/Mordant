#!/usr/bin/env node
/**
 * M-13B: vault binding and the two terminal adapter paths, on a pinned Monad fork.
 *
 * M-13A proved the A-Pass call shape and the supply and role ceremony. This continues from there
 * to the part that makes it Mordant: a production vault bound to the adapter, then both ways the
 * custody can end, each from its own snapshot so neither can contaminate the other.
 *
 *   node scripts/m13b-vault-binding.mjs [--out <prefix>]
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
const FORK_PORT = Number(process.env.M13B_FORK_PORT ?? 8_549);
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
/** Advance plus face value, so the buyer can both fund and later redeem. */
const BUYER_FUNDING = ADVANCE_AMOUNT + FACE_VALUE;

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

/** Scenario A: the burn path. Supply and the adapter's balance must both fall by exactly the units. */
export function checkBurnPath({ supplyBefore, supplyAfter, adapterBefore, adapterAfter, units }) {
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
 * Scenario B: the release path. The adapter's balance falls and the holder's rises, but the token
 * supply does NOT: this is a transfer, not a burn. What is burned is the vault's receipt unit.
 */
export function checkReleasePath({
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
    const pinned = assertPinnedBlock("M-13B", block, M13_FORK_BLOCK, M13_FORK_BLOCK_HASH);
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
      facility: accounts.facility.address };
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
    await send(sourceWallet, AUSDC, ERC20_ABI, "transfer", [accounts.buyer.address, BUYER_FUNDING]);
    const buyerAUsdc = await client.readContract({
      address: AUSDC, abi: ERC20_ABI, functionName: "balanceOf", args: [accounts.buyer.address] });
    note("aUSDC funding", `${BUYER_FUNDING} moved from a real holder, buyer now holds ${buyerAUsdc}`);
    report.aUsdcFunding = { source: AUSDC_SOURCE, sourceBalanceBefore: sourceBalance.toString(),
      moved: BUYER_FUNDING.toString(), buyerBalance: buyerAUsdc.toString(),
      note: "impersonated a real holder; no balance was invented" };

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
      await can(AUSDC, accounts.buyer.address, vault, ADVANCE_AMOUNT, "aUSDC advance in"),
      await can(AUSDC, vault, accounts.originator.address, ADVANCE_AMOUNT, "aUSDC net proceeds out"),
      await can(AUSDC, vault, HOLDER_A, FACE_VALUE / 2n, "aUSDC settlement to holderA"),
      await can(AUSDC, vault, HOLDER_B, FACE_VALUE / 2n, "aUSDC settlement to holderB"),
      await can(AUSDC, vault, accounts.buyer.address, FACE_VALUE, "aUSDC cash redemption to buyer"),
    ];
    for (const tuple of policyTuples) note(`policy ${tuple.label}`, String(tuple.answer));

    const preconditions = checkBindPreconditions({
      adapterApass: await validApass(adapter), vaultApass: await validApass(vault),
      participantApass: {
        buyer: await validApass(accounts.buyer.address),
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

    await send(adminWallet, adapter, ADAPTER_ABI, "bindVault", [vault, INITIAL_UNITS]);
    const boundTo = await readAdapter("boundVault");
    if (String(boundTo).toLowerCase() !== String(vault).toLowerCase()) {
      stop(`bindVault did not bind to the vault; boundVault is ${boundTo}.`);
    }
    note("bindVault", `bound to ${boundTo}, availableBalance ${await readAdapter("availableBalance", [vault])}`);

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
    report.classification = "M-13B PRODUCTION VAULT BINDING: PROVEN ON FORK";

    if (out) { writeArtifact(out, report, process.env); process.stdout.write(`\nWrote ${out}.json\n`); }
  } finally {
    stopFork();
  }
}

const invokedDirectly = process.argv[1]?.endsWith("m13b-vault-binding.mjs");
if (invokedDirectly) {
  process.stdout.write("M-13B: vault binding and terminal adapter paths\n\n");
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof ControlError ? error.message : `STOP — ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
