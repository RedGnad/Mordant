#!/usr/bin/env node
/**
 * M-05 dry run, local side.
 *
 * Measures the gas of the configuration and journey transactions that cannot be estimated against a
 * remote RPC, because they need deployed contracts. Runs the exact sequence the plan describes and
 * reports gas per wallet, so the funding budget follows from measurement rather than a guess.
 *
 * Local measurement, not a Monad observation. Nothing is broadcast to Monad, no Cleanverse endpoint
 * is called, and the accounts used are Anvil's published development accounts.
 *
 * Requires a local chain:
 *   anvil --port 8547 --code-size-limit 131072 --silent &
 *   node scripts/m05-dryrun-local.mjs
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, createWalletClient, http, keccak256, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RPC = process.env.DRYRUN_RPC_URL ?? "http://127.0.0.1:8547";

/** Vault timing used by the plan. curePeriod is DEMO-ONLY; revealPeriod stays at its real value. */
const REVEAL_PERIOD = 3_600n;
const CURE_PERIOD = 60n;

const UNIT = 1_000_000n;
const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
const INVOICE_ROOT = `0x${"a1".repeat(32)}`;

const artifact = (file, name) => {
  const parsed = JSON.parse(readFileSync(join(ROOT, "contracts", "out", file, `${name}.json`), "utf8"));
  return { abi: parsed.abi, bytecode: parsed.bytecode.object };
};

const KEYS = [
  ["deployer", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"],
  ["buyer", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"],
  ["originator", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"],
  ["facilityA", "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"],
  ["facilityB", "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"],
  ["holderA", "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"],
  ["holderB", "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"],
];

const account = Object.fromEntries(KEYS.map(([role, key]) => [role, privateKeyToAccount(key)]));
const transport = http(RPC);
const publicClient = createPublicClient({ chain: anvil, transport });
const walletFor = (role) => createWalletClient({ account: account[role], chain: anvil, transport });

const rows = [];
const note = (phase, role, label, gas) => {
  rows.push({ phase, role, label, gas });
  process.stdout.write(`  ${phase}  ${role.padEnd(11)}${label.padEnd(28)}${String(gas).padStart(9)}\n`);
};

async function deploy(role, art, args, label) {
  const hash = await walletFor(role).deployContract({ ...art, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`${label} reverted`);
  note("P1", role, label, receipt.gasUsed);
  return receipt.contractAddress;
}

async function send(phase, role, address, abi, functionName, args, label) {
  const hash = await walletFor(role).writeContract({ address, abi, functionName, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`${label} reverted`);
  note(phase, role, label, receipt.gasUsed);
  return receipt;
}

async function main() {
  const eligibilityArt = artifact("MockEligibility.sol", "MockEligibility");
  const erc20Art = artifact("MockERC20.sol", "MockERC20");
  const adapterArt = artifact("MockCvaAdapter.sol", "MockCvaAdapter");
  const factoryArt = artifact("MordantFactory.sol", "MordantFactory");
  const vaultArt = artifact("MordantInvoiceVault.sol", "MordantInvoiceVault");

  process.stdout.write("\nPhase 1, deployments\n");
  const eligibility = await deploy("deployer", eligibilityArt, [], "MockEligibility");
  const settlement = await deploy("deployer", erc20Art,
    ["Mordant Demo Settlement (double)", "dSETTLE", 6], "settlement double");
  const cva = await deploy("deployer", erc20Art,
    ["Mordant Demo Invoice A-Token (double)", "dINV", 6], "CVA double");
  const adapter = await deploy("deployer", adapterArt, [cva], "MockCvaAdapter");
  const factory = await deploy("deployer", factoryArt,
    [account.deployer.address, eligibility], "MordantFactory");

  process.stdout.write("\nPhase 2, configuration\n");
  for (const [role, id] of [["buyer", 1], ["originator", 2], ["facilityA", 3], ["facilityB", 3],
    ["holderA", 4], ["holderB", 4]]) {
    await send("P2", "deployer", eligibility, eligibilityArt.abi, "setEligible",
      [account[role].address, id, true], `setEligible ${role}`);
  }
  for (const role of ["facilityA", "facilityB"]) {
    await send("P2", "deployer", factory, factoryArt.abi, "setFacility",
      [account[role].address, true], `setFacility ${role}`);
  }
  await send("P2", "deployer", factory, factoryArt.abi, "setCvaAdapter", [adapter, true], "setCvaAdapter");
  await send("P2", "deployer", factory, factoryArt.abi, "setSettlementToken", [settlement, true], "setSettlementToken");

  const opening = await publicClient.getBlock();
  const protectionEnd = opening.timestamp + 30n * 24n * 3_600n;
  const created = await send("P2", "buyer", factory, factoryArt.abi, "createInvoiceVault", [{
    cvaAdapter: adapter,
    settlementToken: settlement,
    invoiceRoot: INVOICE_ROOT,
    currency: CURRENCY,
    buyer: account.buyer.address,
    originatorTreasury: account.originator.address,
    initialOriginatorSigner: account.originator.address,
    initialUnits: 100n * UNIT,
    advanceAmount: 100n * UNIT,
    faceValue: 110n * UNIT,
    bondBps: 1_000,
    protectionEnd,
    revealPeriod: REVEAL_PERIOD,
    curePeriod: CURE_PERIOD,
  }], "createInvoiceVault");
  const vault = parseEventLogs({
    abi: factoryArt.abi, eventName: "InvoiceVaultCreated", logs: created.logs,
  })[0].args.vault;

  await send("P2", "deployer", eligibility, eligibilityArt.abi, "setIdentityValid", [vault, true], "setIdentityValid(vault)");
  await send("P2", "deployer", cva, erc20Art.abi, "mint", [account.deployer.address, 100n * UNIT], "mint CVA supply");
  await send("P2", "deployer", cva, erc20Art.abi, "approve", [adapter, 100n * UNIT], "approve adapter");
  await send("P2", "deployer", adapter, adapterArt.abi, "creditVault", [vault, 100n * UNIT], "creditVault");
  await send("P2", "deployer", settlement, erc20Art.abi, "mint", [account.holderA.address, 100n * UNIT], "mint settlement funder");
  await send("P2", "deployer", settlement, erc20Art.abi, "mint", [account.buyer.address, 110n * UNIT], "mint settlement buyer");

  process.stdout.write("\nPhase 3, journey\n");
  const domain = { name: "Mordant", version: "1", chainId: anvil.id, verifyingContract: vault };
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
  const now = (await publicClient.getBlock()).timestamp;
  const pledge = (facility, nonce) => ({
    invoiceRoot: INVOICE_ROOT, originatorSigner: account.originator.address, facility,
    obligationId: `0x${nonce.toString(16).padStart(64, "0")}`, amount: 110n * UNIT,
    currency: CURRENCY, activeFrom: now - 1n, activeUntil: protectionEnd + 1n,
    nonce: BigInt(nonce), deadline: now + 172_800n, exclusive: true,
  });
  // The originator only ever signs. It sends no transaction and therefore needs no MON.
  const sign = (message) => walletFor("originator")
    .signTypedData({ account: account.originator, domain, types, primaryType: "Pledge", message });

  const first = pledge(account.facilityA.address, 1);
  const firstSignature = await sign(first);
  await send("P3", "holderA", settlement, erc20Art.abi, "approve", [vault, 100n * UNIT], "approve funding");
  await send("P3", "facilityA", vault, vaultArt.abi, "activate",
    [first, firstSignature, account.holderA.address, [account.holderA.address], [100n * UNIT]], "activate 90/10");
  await send("P3", "holderA", vault, vaultArt.abi, "transfer", [account.holderB.address, 40n * UNIT], "transfer 40 units");

  const second = pledge(account.facilityB.address, 2);
  const secondSignature = await sign(second);
  const digest = await publicClient.readContract({
    address: vault, abi: vaultArt.abi, functionName: "hashPledge", args: [second],
  });
  const salt = `0x${"5a".repeat(32)}`;
  const commitment = await publicClient.readContract({
    address: vault, abi: vaultArt.abi, functionName: "conflictCommitment",
    args: [digest, keccak256(secondSignature), account.facilityB.address, salt],
  });
  await send("P3", "facilityB", vault, vaultArt.abi, "commitConflict", [commitment], "commitConflict");
  await send("P3", "facilityB", vault, vaultArt.abi, "revealConflict", [second, secondSignature, salt], "revealConflict");

  // Wait out curePeriod. On Monad this is real elapsed time, which is why curePeriod is short.
  await fetch(RPC, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "evm_increaseTime", params: [Number(CURE_PERIOD) + 10] },
      { jsonrpc: "2.0", id: 2, method: "evm_mine", params: [] },
    ]),
  });

  await send("P3", "facilityB", vault, vaultArt.abi, "finalizeConflict", [], "finalizeConflict");
  await send("P3", "holderA", vault, vaultArt.abi, "claimBond", [], "claimBond A");
  await send("P3", "holderB", vault, vaultArt.abi, "claimBond", [], "claimBond B");
  await send("P3", "buyer", settlement, erc20Art.abi, "approve", [vault, 110n * UNIT], "approve redemption");
  await send("P3", "buyer", vault, vaultArt.abi, "fundRedemption", [110n * UNIT], "fundRedemption");
  await send("P3", "holderA", vault, vaultArt.abi, "redeem", [60n * UNIT], "redeem A");
  await send("P3", "holderB", vault, vaultArt.abi, "redeem", [40n * UNIT], "redeem B");

  const byPhase = {};
  const byWallet = {};
  for (const row of rows) {
    byPhase[row.phase] = (byPhase[row.phase] ?? 0n) + row.gas;
    byWallet[row.role] = (byWallet[row.role] ?? 0n) + row.gas;
  }
  const total = rows.reduce((sum, row) => sum + row.gas, 0n);

  process.stdout.write(`\nvault ${vault}\n`);
  process.stdout.write(`revealPeriod ${REVEAL_PERIOD}  curePeriod ${CURE_PERIOD} (DEMO-ONLY)\n`);
  process.stdout.write("\nper phase\n");
  for (const [phase, gas] of Object.entries(byPhase)) {
    process.stdout.write(`  ${phase}  ${String(gas).padStart(10)}\n`);
  }
  process.stdout.write("\nper wallet\n");
  for (const [role] of KEYS) {
    const gas = byWallet[role] ?? 0n;
    const count = rows.filter((row) => row.role === role).length;
    process.stdout.write(
      `  ${role.padEnd(11)} ${String(count).padStart(2)} tx  ${String(gas).padStart(10)} gas`
      + `${gas === 0n ? "   signs only, needs no MON" : ""}\n`,
    );
  }
  process.stdout.write(`\nTOTAL ${total} gas over ${rows.length} transactions\n`);
}

main().catch((error) => {
  process.stderr.write(`dry run failed: ${error.message}\n`);
  process.exitCode = 1;
});
