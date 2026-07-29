#!/usr/bin/env node
/**
 * Deterministic local deal-room chain.
 *
 * Starts a fresh Anvil, deploys the existing Mordant contracts together with the project's
 * Cleanverse protocol doubles, and writes the resulting addresses to `.dealroom/deployment.json`.
 *
 * Nothing here is live. The settlement token is a local MockERC20 labelled PROTOCOL DOUBLE and must
 * never be presented as Cleanverse aUSDC. No Monad deployment and no Cleanverse call is performed.
 *
 * Usage:
 *   node scripts/localnet.mjs          start the chain, deploy, then stay in the foreground
 *   node scripts/localnet.mjs --once   deploy against an already running chain, then exit
 */
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, createWalletClient, http, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RPC_URL = process.env.DEALROOM_RPC_URL ?? "http://127.0.0.1:8545";
const OUTPUT = join(ROOT, ".dealroom", "deployment.json");

/**
 * Anvil's published deterministic development accounts. These are printed by `anvil` on every
 * start and are documented test keys with no value on any real network. They exist so the demo is
 * reproducible from an empty chain; they are never used against a public network.
 */
const DEV_ACCOUNTS = [
  ["deployer", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"],
  ["buyer", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"],
  ["originator", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"],
  ["facilityA", "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"],
  ["facilityB", "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"],
  ["holderA", "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"],
  ["holderB", "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"],
];

const UNIT = 1_000_000n;              // six decimals, matching the vault
const INITIAL_UNITS = 100n * UNIT;    // 100 invoice units
const ADVANCE = 100n * UNIT;          // 100 financing
const FACE = 110n * UNIT;             // 110 face value
const BOND_BPS = 1_000;               // 10% reserve
const REVEAL_PERIOD = 3_600n;
const CURE_PERIOD = 3_600n;
const PROTECTION_WINDOW = 24n * 3_600n; // the protocol's 24-hour duration, never shortened
const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
const INVOICE_ROOT = `0x${"a1".repeat(32)}`;

/**
 * Monad's documented maximum contract code size: 128 KB, against Ethereum's 24.5 KB. The local
 * chain is configured to that figure so the deployment budget here matches the target network
 * rather than an arbitrary value. Anvil remains a local chain, not a Monad simulation.
 */
const MONAD_DOCUMENTED_CODE_SIZE_LIMIT = 131_072;

function artifact(file, name) {
  const path = join(ROOT, "contracts", "out", file, `${name}.json`);
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  return { abi: parsed.abi, bytecode: parsed.bytecode.object };
}

function log(step, detail) {
  process.stdout.write(`  ${step.padEnd(34)} ${detail}\n`);
}

async function waitForChain(publicClient, attempts = 60) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await publicClient.getBlockNumber();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error(`Anvil did not become ready at ${RPC_URL}`);
}

async function deploy() {
  const transport = http(RPC_URL);
  const publicClient = createPublicClient({ chain: anvil, transport });
  await waitForChain(publicClient);

  const accounts = Object.fromEntries(
    DEV_ACCOUNTS.map(([role, key]) => [role, privateKeyToAccount(key)]),
  );
  const wallets = Object.fromEntries(
    Object.entries(accounts).map(([role, account]) => [
      role,
      createWalletClient({ account, chain: anvil, transport }),
    ]),
  );

  async function deployContract(role, { abi, bytecode }, args) {
    const hash = await wallets[role].deployContract({ abi, bytecode, args });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success" || !receipt.contractAddress) {
      throw new Error("deployment reverted");
    }
    return receipt.contractAddress;
  }

  async function send(role, address, abi, functionName, args) {
    const hash = await wallets[role].writeContract({ address, abi, functionName, args });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") {
      throw new Error(`${functionName} reverted`);
    }
    return receipt;
  }

  const eligibilityArtifact = artifact("MockEligibility.sol", "MockEligibility");
  const erc20Artifact = artifact("MockERC20.sol", "MockERC20");
  const adapterArtifact = artifact("MockCvaAdapter.sol", "MockCvaAdapter");
  const factoryArtifact = artifact("MordantFactory.sol", "MordantFactory");

  const eligibility = await deployContract("deployer", eligibilityArtifact, []);
  log("MockEligibility", eligibility);

  // PROTOCOL DOUBLE. Deliberately not named aUSDC so no screenshot can imply the Cleanverse asset.
  const settlement = await deployContract("deployer", erc20Artifact, [
    "Demo Settlement Token (protocol double)", "dSETTLE", 6,
  ]);
  log("settlement token (double)", settlement);

  const cva = await deployContract("deployer", erc20Artifact, [
    "Demo Invoice A-Token (protocol double)", "dINV", 6,
  ]);
  log("CVA token (double)", cva);

  const adapter = await deployContract("deployer", adapterArtifact, [cva]);
  log("MockCvaAdapter", adapter);

  const factory = await deployContract("deployer", factoryArtifact, [
    accounts.deployer.address, eligibility,
  ]);
  log("MordantFactory", factory);

  // Roles: 1 buyer, 2 originator, 3 facility, 4 holder.
  const grants = [
    [accounts.buyer.address, 1], [accounts.originator.address, 2],
    [accounts.facilityA.address, 3], [accounts.facilityB.address, 3],
    [accounts.holderA.address, 4], [accounts.holderB.address, 4],
  ];
  for (const [account, role] of grants) {
    await send("deployer", eligibility, eligibilityArtifact.abi, "setEligible", [account, role, true]);
  }
  await send("deployer", factory, factoryArtifact.abi, "setFacility", [accounts.facilityA.address, true]);
  await send("deployer", factory, factoryArtifact.abi, "setFacility", [accounts.facilityB.address, true]);
  await send("deployer", factory, factoryArtifact.abi, "setCvaAdapter", [adapter, true]);
  await send("deployer", factory, factoryArtifact.abi, "setSettlementToken", [settlement, true]);
  log("roles, facilities, allowlists", "configured");

  const latest = await publicClient.getBlock();
  const protectionEnd = latest.timestamp + PROTECTION_WINDOW;

  const createReceipt = await send("buyer", factory, factoryArtifact.abi, "createInvoiceVault", [{
    cvaAdapter: adapter,
    settlementToken: settlement,
    invoiceRoot: INVOICE_ROOT,
    currency: CURRENCY,
    buyer: accounts.buyer.address,
    originatorTreasury: accounts.originator.address,
    initialOriginatorSigner: accounts.originator.address,
    initialUnits: INITIAL_UNITS,
    advanceAmount: ADVANCE,
    faceValue: FACE,
    bondBps: BOND_BPS,
    protectionEnd,
    revealPeriod: REVEAL_PERIOD,
    curePeriod: CURE_PERIOD,
  }]);

  const [created] = parseEventLogs({
    abi: factoryArtifact.abi,
    eventName: "InvoiceVaultCreated",
    logs: createReceipt.logs,
  });
  const vault = created.args.vault;
  log("MordantInvoiceVault", vault);

  await send("deployer", eligibility, eligibilityArtifact.abi, "setIdentityValid", [vault, true]);

  // Custody: `creditVault` pulls the dedicated supply from the caller, so mint to the deployer and
  // approve the adapter before crediting.
  await send("deployer", cva, erc20Artifact.abi, "mint", [accounts.deployer.address, INITIAL_UNITS]);
  await send("deployer", cva, erc20Artifact.abi, "approve", [adapter, INITIAL_UNITS]);
  await send("deployer", adapter, adapterArtifact.abi, "creditVault", [vault, INITIAL_UNITS]);
  log("CVA custody credited", `${INITIAL_UNITS / UNIT} units`);

  // Working balances for the funder and the buyer. The funder still has to approve from the UI.
  await send("deployer", settlement, erc20Artifact.abi, "mint", [accounts.holderA.address, ADVANCE]);
  await send("deployer", settlement, erc20Artifact.abi, "mint", [accounts.buyer.address, FACE]);
  log("settlement balances minted", "funder 100, buyer 110");

  // Reset does not redeploy or invent a second deal. Reverting to this Anvil snapshot preserves the
  // same vault, invoice root and participants, then the server immediately takes a replacement
  // snapshot because `evm_revert` consumes the previous id.
  const resetSnapshotId = await publicClient.request({ method: "evm_snapshot" });
  log("canonical reset snapshot", String(resetSnapshotId));

  const deployment = {
    label: "LOCAL / PROTOCOL DOUBLE / SYNTHETIC",
    warning:
      "Local Anvil deployment. The settlement and CVA tokens are protocol doubles, not Cleanverse"
      + " assets. Nothing here is live and no Cleanverse endpoint was called.",
    generatedAt: new Date().toISOString(),
    resetSnapshotId: String(resetSnapshotId),
    rpcUrl: RPC_URL,
    chainId: anvil.id,
    contracts: { eligibility, settlement, cva, adapter, factory, vault },
    invoice: {
      invoiceRoot: INVOICE_ROOT,
      currency: CURRENCY,
      initialUnits: INITIAL_UNITS.toString(),
      advanceAmount: ADVANCE.toString(),
      faceValue: FACE.toString(),
      bondBps: BOND_BPS,
      protectionEnd: protectionEnd.toString(),
      revealPeriod: REVEAL_PERIOD.toString(),
      curePeriod: CURE_PERIOD.toString(),
    },
    accounts: Object.fromEntries(
      DEV_ACCOUNTS.map(([role, key]) => [role, { address: accounts[role].address, key }]),
    ),
  };

  mkdirSync(dirname(OUTPUT), { recursive: true });
  writeFileSync(OUTPUT, `${JSON.stringify(deployment, null, 2)}\n`);
  log("deployment written", OUTPUT);
  return deployment;
}

async function main() {
  const once = process.argv.includes("--once");

  if (once) {
    await deploy();
    return;
  }

  process.stdout.write("Starting deterministic local chain (Anvil)\n");
  // MordantFactory (40382 bytes) and MordantInvoiceVault (31312 bytes) exceed Ethereum's EIP-170
  // 24576-byte runtime limit, so a default Anvil refuses to deploy them. They are well inside
  // Monad's documented 128 KB limit, so this is a standard-EVM portability constraint and not a
  // Monad blocker. Anvil is configured to the Monad figure to keep the local budget aligned with
  // the target network; it stays a local chain and does not simulate Monad.
  const chain = spawn(
    "anvil",
    [
      "--host", "127.0.0.1", "--port", "8545", "--chain-id", String(anvil.id),
      "--code-size-limit", String(MONAD_DOCUMENTED_CODE_SIZE_LIMIT), "--silent",
    ],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  const stop = () => { if (!chain.killed) chain.kill("SIGTERM"); };
  process.on("SIGINT", () => { stop(); process.exit(0); });
  process.on("SIGTERM", () => { stop(); process.exit(0); });
  chain.on("exit", (code) => {
    if (code !== 0 && code !== null) {
      process.stderr.write(`anvil exited with code ${code}\n`);
      process.exit(code);
    }
  });

  await deploy();
  process.stdout.write("\nLocal deal room ready. LOCAL / PROTOCOL DOUBLE / SYNTHETIC.\n");
  await new Promise(() => {});
}

main().catch((error) => {
  process.stderr.write(`localnet failed: ${error.message}\n`);
  process.exitCode = 1;
});
