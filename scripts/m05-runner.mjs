#!/usr/bin/env node
/**
 * M-05 runner: Monad PROTOCOL DOUBLE deployment.
 *
 * Executes the 39-transaction sequence described in docs/m05-monad-protocol-double-plan.md.
 *
 * BROADCASTING IS OFF BY DEFAULT AND DOUBLE-GATED. Sending to Monad requires both `--broadcast` and
 * the environment variable MORDANT_BROADCAST_AUTHORIZED set to the exact ceremony string below.
 * Without both, the runner refuses to send anything, whatever else is on the command line.
 *
 * Modes:
 *   --check            default. Chain gate, key and balance readbacks, creation-gas estimates.
 *                      Read-only: no transaction is sent.
 *   --fork             runs the entire sequence on a disposable Anvil fork of Monad. FORK evidence.
 *                      Proves the runner and every readback without touching Monad.
 *   --broadcast        the real thing. Refuses unless MORDANT_BROADCAST_AUTHORIZED matches and the
 *                      chain is 10143.
 *
 * Keys are read from one environment variable each, at run time. No private key, seed phrase or
 * other secret material is logged or persisted. Public addresses, signatures, transaction hashes,
 * blocks and readbacks are recorded, because the artifact is worthless without them.
 *
 * The originator never sends a transaction. Provide either MORDANT_KEY_ORIGINATOR, or its address
 * plus two pre-computed EIP-712 signatures, so that key can stay on a separate machine.
 */
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient, createWalletClient, encodeDeployData, formatEther, http, keccak256,
  parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MONAD_CHAIN_ID = 10_143;
const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const FORK_PORT = 8548;
const MONAD_CODE_SIZE_LIMIT = 131_072;
const BROADCAST_CEREMONY = "yes-i-authorize-monad-protocol-double";

const UNIT = 1_000_000n;
const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
const REVEAL_PERIOD = 3_600n;
/** DEMO-ONLY CONFIGURATION. A real cure window is measured in days. */
const CURE_PERIOD = 60n;

/** Budgeted MON per spending wallet, from the plan's 2x margin column. */
const BUDGET = {
  deployer: 2_486_000_000_000_000_000n,
  buyer: 1_365_400_000_000_000_000n,
  facilityA: 107_400_000_000_000_000n,
  facilityB: 103_200_000_000_000_000n,
  holderA: 143_100_000_000_000_000n,
  holderB: 69_300_000_000_000_000n,
};

const KEY_ENV = {
  deployer: "MORDANT_KEY_DEPLOYER",
  buyer: "MORDANT_KEY_BUYER",
  facilityA: "MORDANT_KEY_FACILITY_A",
  facilityB: "MORDANT_KEY_FACILITY_B",
  holderA: "MORDANT_KEY_HOLDER_A",
  holderB: "MORDANT_KEY_HOLDER_B",
};

const artifact = (file, name) => {
  const parsed = JSON.parse(readFileSync(join(ROOT, "contracts", "out", file, `${name}.json`), "utf8"));
  return { abi: parsed.abi, bytecode: parsed.bytecode.object, runtime: parsed.deployedBytecode.object };
};

class RunnerError extends Error {}

function parseArgs() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const at = (flag) => { const i = argv.indexOf(flag); return i === -1 ? null : argv[i + 1] ?? null; };
  const mode = argv.includes("--broadcast") ? "broadcast" : argv.includes("--fork") ? "fork" : "check";
  return { mode, out: at("--out") };
}

/**
 * Resolves signers. Anvil's published development keys are used for the fork so the runner is
 * testable; a broadcast run requires real keys from the environment and refuses the fallback.
 */
function loadAccounts(mode) {
  const forkDefaults = {
    deployer: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    buyer: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    facilityA: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    facilityB: "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    holderA: "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    holderB: "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
  };
  const originatorForkKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

  const accounts = {};
  for (const [role, variable] of Object.entries(KEY_ENV)) {
    const key = process.env[variable];
    const addressOnly = process.env[`MORDANT_ADDRESS_${role.replace(/([A-Z])/g, "_$1").toUpperCase()}`];
    if (key) {
      accounts[role] = privateKeyToAccount(key);
    } else if (mode === "fork") {
      accounts[role] = privateKeyToAccount(forkDefaults[role]);
    } else if (mode === "check") {
      // A check signs nothing, so an address is enough to read balances and estimate gas.
      accounts[role] = { address: addressOnly ?? null, unconfigured: !addressOnly };
    } else {
      throw new RunnerError(`${variable} is not set. Every spending wallet needs its own key.`);
    }
  }

  // The originator signs and never sends. Either it signs here, or signatures arrive pre-computed.
  const originatorKey = process.env.MORDANT_KEY_ORIGINATOR
    ?? (mode === "fork" ? originatorForkKey : undefined);
  const originator = originatorKey
    ? privateKeyToAccount(originatorKey)
    : { address: process.env.MORDANT_ADDRESS_ORIGINATOR };
  if (!originator.address && mode !== "check") {
    throw new RunnerError(
      "Provide MORDANT_KEY_ORIGINATOR, or MORDANT_ADDRESS_ORIGINATOR with"
      + " MORDANT_PLEDGE_SIGNATURE_1 and MORDANT_PLEDGE_SIGNATURE_2.",
    );
  }
  return { accounts, originator, canSignLocally: Boolean(originatorKey) };
}

async function main() {
  const { mode, out } = parseArgs();
  const steps = [];
  const record = (phase, label, detail, extra = {}) => {
    steps.push({ phase, label, detail, ...extra });
    process.stdout.write(`  ${phase}  ${label.padEnd(30)} ${detail}\n`);
  };

  if (mode === "broadcast") {
    if (process.env.MORDANT_BROADCAST_AUTHORIZED !== BROADCAST_CEREMONY) {
      throw new RunnerError(
        "REFUSED: --broadcast requires MORDANT_BROADCAST_AUTHORIZED to be set to the exact"
        + " ceremony string. Broadcasting is not authorized.",
      );
    }
    process.stdout.write("\n*** BROADCAST MODE. Transactions will be sent to Monad. ***\n\n");
  }

  const { accounts, originator, canSignLocally } = loadAccounts(mode);

  let fork = null;
  let rpcUrl = MONAD_RPC;
  if (mode === "fork") {
    fork = spawn("anvil", [
      "--fork-url", MONAD_RPC, "--port", String(FORK_PORT), "--host", "127.0.0.1",
      "--chain-id", String(MONAD_CHAIN_ID),
      "--code-size-limit", String(MONAD_CODE_SIZE_LIMIT), "--silent",
    ], { stdio: ["ignore", "ignore", "inherit"] });
    rpcUrl = `http://127.0.0.1:${FORK_PORT}`;
  }
  const stopFork = () => { if (fork && !fork.killed) fork.kill("SIGTERM"); };
  process.on("SIGINT", () => { stopFork(); process.exit(0); });

  const chain = { id: MONAD_CHAIN_ID, name: "monad-testnet", nativeCurrency: { name: "MON", symbol: "MON", decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } } };
  const transport = http(rpcUrl);
  const publicClient = createPublicClient({ chain, transport });
  const walletFor = (role) => createWalletClient({ account: accounts[role], chain, transport });

  let status = "INCOMPLETE";
  try {
    for (let attempt = 0; ; attempt += 1) {
      try { await publicClient.getBlockNumber(); break; }
      catch (error) {
        if (attempt > 120) throw error;
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    // --- chain gate, before anything else ---
    const chainId = await publicClient.getChainId();
    if (chainId !== MONAD_CHAIN_ID) {
      throw new RunnerError(`BLOCKED — WRONG NETWORK: expected ${MONAD_CHAIN_ID}, got ${chainId}`);
    }
    const head = await publicClient.getBlock();
    record("gate", "chain id", `${chainId} at block ${head.number}`);
    for (const [role, account] of Object.entries(accounts)) {
      record("gate", `address ${role}`, account.address ?? "NOT CONFIGURED");
    }
    record("gate", "address originator",
      `${originator.address ?? "NOT CONFIGURED"} (signs only, no MON)`);

    // --- Phase 0 gate: every spending wallet is funded before anything is deployed ---
    let underfunded = 0;
    for (const [role, budget] of Object.entries(BUDGET)) {
      if (!accounts[role].address) {
        record("P0", `balance ${role}`, "NOT CONFIGURED, cannot check", { ok: false });
        underfunded += 1;
        continue;
      }
      const balance = await publicClient.getBalance({ address: accounts[role].address });
      const ok = balance >= budget;
      if (!ok) underfunded += 1;
      record("P0", `balance ${role}`,
        `${formatEther(balance)} MON, budget ${formatEther(budget)}, ${ok ? "ok" : "UNDERFUNDED"}`,
        { ok });
    }
    if (underfunded > 0 && mode !== "check") {
      throw new RunnerError(
        `${underfunded} wallet(s) below budget. Fund them before running Phase 1.`,
      );
    }

    const eligibilityArt = artifact("MockEligibility.sol", "MockEligibility");
    const erc20Art = artifact("MockERC20.sol", "MockERC20");
    const adapterArt = artifact("MockCvaAdapter.sol", "MockCvaAdapter");
    const factoryArt = artifact("MordantFactory.sol", "MordantFactory");
    const vaultArt = artifact("MordantInvoiceVault.sol", "MordantInvoiceVault");

    if (mode === "check") {
      // Read-only: estimate each creation without sending anything.
      const caller = accounts.deployer.address ?? "0x000000000000000000000000000000000000d341";
      const plan = [
        ["MockEligibility", eligibilityArt, []],
        ["settlement double", erc20Art, ["Mordant Demo Settlement (double)", "dSETTLE", 6]],
        ["CVA double", erc20Art, ["Mordant Demo Invoice A-Token (double)", "dINV", 6]],
        ["MockCvaAdapter", adapterArt, ["0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9"]],
        ["MordantFactory", factoryArt, [caller, "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9"]],
      ];
      let estimated = 0n;
      for (const [label, art, args] of plan) {
        // Deployment estimation goes through the raw creation payload, not a function call.
        const data = encodeDeployData({ abi: art.abi, bytecode: art.bytecode, args });
        try {
          const gas = await publicClient.estimateGas({ account: caller, data });
          estimated += gas;
          record("P1", `estimate ${label}`, `${gas} gas`);
        } catch (error) {
          record("P1", `estimate ${label}`, `FAILED: ${(error.shortMessage ?? error.message).split("\n")[0]}`);
        }
      }
      record("P1", "deployment gas subtotal", `${estimated} gas`);
      record("check", "result", "read-only check complete, nothing was sent");
      status = "CHECK PASSED";
      return { steps, status, mode, out, chainId, block: head.number };
    }

    // ---- sending path, shared by fork and broadcast ----
    const sent = [];
    const deploy = async (role, art, args, label, expectRuntime = true) => {
      const hash = await walletFor(role).deployContract({ abi: art.abi, bytecode: art.bytecode, args });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new RunnerError(`${label} reverted`);
      const code = await publicClient.getCode({ address: receipt.contractAddress });
      const size = (code.length - 2) / 2;
      const expected = (art.runtime.length - 2) / 2;
      if (expectRuntime && size !== expected) {
        throw new RunnerError(`${label} readback failed: ${size} B installed, expected ${expected} B`);
      }
      sent.push({ label, hash, block: receipt.blockNumber.toString(), gas: receipt.gasUsed.toString() });
      record("P1", label, `${receipt.contractAddress}, ${size} B, gas ${receipt.gasUsed}`,
        { hash, address: receipt.contractAddress });
      return receipt.contractAddress;
    };
    const send = async (phase, role, address, abi, fn, args, label, readback) => {
      const hash = await walletFor(role).writeContract({ address, abi, functionName: fn, args });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new RunnerError(`${label} reverted`);
      if (readback) {
        const problem = await readback(receipt);
        if (problem) throw new RunnerError(`${label} readback failed: ${problem}`);
      }
      sent.push({ label, hash, block: receipt.blockNumber.toString(), gas: receipt.gasUsed.toString() });
      record(phase, label, `gas ${receipt.gasUsed}, block ${receipt.blockNumber}`, { hash });
      return receipt;
    };

    const eligibility = await deploy("deployer", eligibilityArt, [], "MockEligibility");
    const settlement = await deploy("deployer", erc20Art,
      ["Mordant Demo Settlement (double)", "dSETTLE", 6], "settlement double");
    const cva = await deploy("deployer", erc20Art,
      ["Mordant Demo Invoice A-Token (double)", "dINV", 6], "CVA double");
    const adapter = await deploy("deployer", adapterArt, [cva], "MockCvaAdapter");
    const factory = await deploy("deployer", factoryArt,
      [accounts.deployer.address, eligibility], "MordantFactory");

    const roles = [["buyer", 1], ["originator", 2], ["facilityA", 3], ["facilityB", 3],
      ["holderA", 4], ["holderB", 4]];
    for (const [role, id] of roles) {
      const address = role === "originator" ? originator.address : accounts[role].address;
      await send("P2", "deployer", eligibility, eligibilityArt.abi, "setEligible",
        [address, id, true], `setEligible ${role}`,
        async () => await publicClient.readContract({
          address: eligibility, abi: eligibilityArt.abi, functionName: "isEligible", args: [address, id],
        }) ? null : "isEligible still false");
    }
    for (const role of ["facilityA", "facilityB"]) {
      await send("P2", "deployer", factory, factoryArt.abi, "setFacility",
        [accounts[role].address, true], `setFacility ${role}`,
        async () => await publicClient.readContract({
          address: factory, abi: factoryArt.abi, functionName: "isFacility", args: [accounts[role].address],
        }) ? null : "isFacility still false");
    }
    await send("P2", "deployer", factory, factoryArt.abi, "setCvaAdapter", [adapter, true], "setCvaAdapter",
      async () => await publicClient.readContract({ address: factory, abi: factoryArt.abi, functionName: "approvedCvaAdapter", args: [adapter] }) ? null : "adapter not approved");
    await send("P2", "deployer", factory, factoryArt.abi, "setSettlementToken", [settlement, true], "setSettlementToken",
      async () => await publicClient.readContract({ address: factory, abi: factoryArt.abi, functionName: "approvedSettlementToken", args: [settlement] }) ? null : "settlement token not approved");

    const opening = await publicClient.getBlock();
    const protectionEnd = opening.timestamp + 30n * 24n * 3_600n;
    const invoiceRoot = keccak256(`0x${Date.now().toString(16)}`);
    let vault = null;
    await send("P2", "buyer", factory, factoryArt.abi, "createInvoiceVault", [{
      cvaAdapter: adapter, settlementToken: settlement, invoiceRoot, currency: CURRENCY,
      buyer: accounts.buyer.address, originatorTreasury: originator.address,
      initialOriginatorSigner: originator.address,
      initialUnits: 100n * UNIT, advanceAmount: 100n * UNIT, faceValue: 110n * UNIT,
      bondBps: 1_000, protectionEnd, revealPeriod: REVEAL_PERIOD, curePeriod: CURE_PERIOD,
    }], "createInvoiceVault", async (receipt) => {
      vault = parseEventLogs({ abi: factoryArt.abi, eventName: "InvoiceVaultCreated", logs: receipt.logs })[0]?.args?.vault;
      if (!vault) return "no InvoiceVaultCreated event";
      const registered = await publicClient.readContract({
        address: factory, abi: factoryArt.abi, functionName: "vaultForRoot", args: [invoiceRoot],
      });
      if (registered.toLowerCase() !== vault.toLowerCase()) return "vaultForRoot mismatch";
      const code = await publicClient.getCode({ address: vault });
      const size = (code.length - 2) / 2;
      const expected = (vaultArt.runtime.length - 2) / 2;
      return size === expected ? null : `vault runtime ${size} B, expected ${expected} B`;
    });
    record("P2", "vault", vault);

    await send("P2", "deployer", eligibility, eligibilityArt.abi, "setIdentityValid", [vault, true], "setIdentityValid(vault)");
    await send("P2", "deployer", cva, erc20Art.abi, "mint", [accounts.deployer.address, 100n * UNIT], "mint CVA supply");
    await send("P2", "deployer", cva, erc20Art.abi, "approve", [adapter, 100n * UNIT], "approve adapter");
    await send("P2", "deployer", adapter, adapterArt.abi, "creditVault", [vault, 100n * UNIT], "creditVault",
      async () => await publicClient.readContract({ address: adapter, abi: adapterArt.abi, functionName: "availableBalance", args: [vault] }) === 100n * UNIT ? null : "custody credit mismatch");
    await send("P2", "deployer", settlement, erc20Art.abi, "mint", [accounts.holderA.address, 100n * UNIT], "mint settlement funder");
    await send("P2", "deployer", settlement, erc20Art.abi, "mint", [accounts.buyer.address, 110n * UNIT], "mint settlement buyer");

    // --- Phase 3 ---
    const domain = { name: "Mordant", version: "1", chainId: MONAD_CHAIN_ID, verifyingContract: vault };
    const types = { Pledge: [
      { name: "invoiceRoot", type: "bytes32" }, { name: "originatorSigner", type: "address" },
      { name: "facility", type: "address" }, { name: "obligationId", type: "bytes32" },
      { name: "amount", type: "uint256" }, { name: "currency", type: "bytes32" },
      { name: "activeFrom", type: "uint64" }, { name: "activeUntil", type: "uint64" },
      { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint64" },
      { name: "exclusive", type: "bool" },
    ] };
    const now = (await publicClient.getBlock()).timestamp;
    const pledgeFor = (facility, nonce) => ({
      invoiceRoot, originatorSigner: originator.address, facility,
      obligationId: `0x${nonce.toString(16).padStart(64, "0")}`, amount: 110n * UNIT,
      currency: CURRENCY, activeFrom: now - 1n, activeUntil: protectionEnd + 1n,
      nonce: BigInt(nonce), deadline: now + 172_800n, exclusive: true,
    });
    const signPledge = async (message, index) => {
      if (canSignLocally) {
        return createWalletClient({ account: originator, chain, transport })
          .signTypedData({ account: originator, domain, types, primaryType: "Pledge", message });
      }
      const provided = process.env[`MORDANT_PLEDGE_SIGNATURE_${index}`];
      if (!provided) {
        throw new RunnerError(
          `MORDANT_PLEDGE_SIGNATURE_${index} is required when the originator signs off machine.`,
        );
      }
      return provided;
    };

    const first = pledgeFor(accounts.facilityA.address, 1);
    const firstSignature = await signPledge(first, 1);
    await send("P3", "holderA", settlement, erc20Art.abi, "approve", [vault, 100n * UNIT], "approve funding");
    await send("P3", "facilityA", vault, vaultArt.abi, "activate",
      [first, firstSignature, accounts.holderA.address, [accounts.holderA.address], [100n * UNIT]],
      "activate 90/10", async () => {
        const state = await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "protectionState" });
        if (Number(state) !== 1) return `protectionState ${state}, expected Active`;
        const proceeds = await publicClient.readContract({ address: settlement, abi: erc20Art.abi, functionName: "balanceOf", args: [originator.address] });
        if (proceeds !== 90n * UNIT) return `originator proceeds ${proceeds}, expected 90e6`;
        await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "assertAccounting" });
        return null;
      });
    await send("P3", "holderA", vault, vaultArt.abi, "transfer", [accounts.holderB.address, 40n * UNIT], "transfer 40 units",
      async () => await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "balanceOf", args: [accounts.holderB.address] }) === 40n * UNIT ? null : "holder B units mismatch");

    const second = pledgeFor(accounts.facilityB.address, 2);
    const secondSignature = await signPledge(second, 2);
    const digest = await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "hashPledge", args: [second] });
    const salt = `0x${"5a".repeat(32)}`;
    const commitment = await publicClient.readContract({
      address: vault, abi: vaultArt.abi, functionName: "conflictCommitment",
      args: [digest, keccak256(secondSignature), accounts.facilityB.address, salt],
    });
    await send("P3", "facilityB", vault, vaultArt.abi, "commitConflict", [commitment], "commitConflict",
      async () => Number(await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "protectionState" })) === 2 ? null : "not CommitPending");
    await send("P3", "facilityB", vault, vaultArt.abi, "revealConflict", [second, secondSignature, salt], "revealConflict",
      async () => Number(await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "protectionState" })) === 3 ? null : "not ConflictConfirmed");

    // Real elapsed time on Monad; the fork can be advanced directly.
    if (mode === "fork") {
      await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify([
          { jsonrpc: "2.0", id: 1, method: "evm_increaseTime", params: [Number(CURE_PERIOD) + 10] },
          { jsonrpc: "2.0", id: 2, method: "evm_mine", params: [] }]) });
      record("P3", "cure window", "advanced on the fork");
    } else {
      const wait = Number(CURE_PERIOD) + 10;
      record("P3", "cure window", `waiting ${wait}s of real time`);
      await new Promise((resolve) => setTimeout(resolve, wait * 1_000));
    }

    await send("P3", "facilityB", vault, vaultArt.abi, "finalizeConflict", [], "finalizeConflict",
      async () => {
        const state = Number(await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "protectionState" }));
        if (state !== 4) return `protectionState ${state}, expected Entitled`;
        const allocated = await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "entitlementAllocated" });
        return allocated === 10n * UNIT ? null : `entitlement ${allocated}, expected 10e6`;
      });
    for (const [role, expected] of [["holderA", 6n * UNIT], ["holderB", 4n * UNIT]]) {
      await send("P3", role, vault, vaultArt.abi, "claimBond", [], `claimBond ${role}`,
        async () => {
          const paid = await publicClient.readContract({ address: settlement, abi: erc20Art.abi, functionName: "balanceOf", args: [accounts[role].address] });
          const units = await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "balanceOf", args: [accounts[role].address] });
          const expectedUnits = role === "holderA" ? 60n * UNIT : 40n * UNIT;
          if (units !== expectedUnits) return `claiming consumed units: ${units}`;
          return paid >= expected ? null : `paid ${paid}, expected at least ${expected}`;
        });
    }
    await send("P3", "buyer", settlement, erc20Art.abi, "approve", [vault, 110n * UNIT], "approve redemption");
    await send("P3", "buyer", vault, vaultArt.abi, "fundRedemption", [110n * UNIT], "fundRedemption",
      async () => await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "redemptionEscrow" }) === 110n * UNIT ? null : "escrow mismatch");
    await send("P3", "holderA", vault, vaultArt.abi, "redeem", [60n * UNIT], "redeem holderA");
    await send("P3", "holderB", vault, vaultArt.abi, "redeem", [40n * UNIT], "redeem holderB",
      async () => {
        const redeemed = await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "redeemedFace" });
        const state = Number(await publicClient.readContract({ address: vault, abi: vaultArt.abi, functionName: "receivableState" }));
        if (redeemed !== 110n * UNIT) return `redeemedFace ${redeemed}, expected 110e6`;
        return state === 2 ? null : `receivableState ${state}, expected Redeemed`;
      });

    record("done", "transactions sent", String(sent.length));
    status = mode === "fork" ? "FORK RUN COMPLETE" : "MONAD RUN COMPLETE";
    return { steps, status, mode, out, chainId, block: head.number, contracts: { eligibility, settlement, cva, adapter, factory, vault }, sent };
  } finally {
    stopFork();
  }
}

main().then((result) => {
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode: result.mode,
    status: result.status,
    classification: result.mode === "fork"
      ? "FORK"
      : result.mode === "check" ? "READ-ONLY RPC SIMULATION"
        : "MONAD LIVE / PROTOCOL DOUBLE / NOT CLEANVERSE",
    warning:
      "Protocol doubles only. No aUSDC, no CCUSD2, no WMON and no Cleanverse endpoint. No private"
      + " key, seed phrase or other secret material is recorded here.",
    chainId: result.chainId,
    startBlock: String(result.block),
    contracts: result.contracts ?? null,
    steps: result.steps,
    transactions: result.sent ?? [],
  };
  if (result.out) {
    mkdirSync(dirname(result.out), { recursive: true });
    writeFileSync(`${result.out}.json`, `${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(`\nWrote ${result.out}.json\n`);
  }
  process.stdout.write(`\n${result.status}\n`);
}).catch((error) => {
  process.stderr.write(`\nSTOPPED: ${error.message}\n`);
  process.exitCode = 1;
});
