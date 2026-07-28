#!/usr/bin/env node
/**
 * M-05 runner: Monad PROTOCOL DOUBLE deployment.
 *
 * Executes the 34 transactions the runner owns, out of the 39 in the full ceremony. The five
 * prefunding transfers are external: the runner never sends them, it only gates on the resulting
 * balances before Phase 1.
 *
 * BROADCASTING IS OFF BY DEFAULT AND DOUBLE-GATED. Sending requires `--broadcast` and
 * the explicit --broadcast flag together with --out. The chain gate runs first, before
 * authorization is examined and before any private key is read.
 *
 * Modes:
 *   --check      default. Chain gate, gas-price cap, balance readbacks, creation-gas estimates.
 *                Fail-closed: any failed estimate, missing address, underfunded wallet, wrong chain
 *                or excessive gas price stops the run. Sends nothing and needs no key.
 *   --fork       the whole sequence on a disposable Anvil fork of Monad. FORK evidence.
 *   --broadcast  the real thing. Requires --out, and checkpoints the artifact after every
 *                transaction and readback so an interrupted run still records what was sent.
 *
 * No private key, seed phrase or other secret material is logged or persisted. Public addresses,
 * signatures, transaction hashes, blocks and readbacks are recorded.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient, createWalletClient, encodeDeployData, formatEther, http, keccak256,
  parseEventLogs,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  DEFAULT_MAX_GAS_PRICE_WEI, MONAD_CHAIN_ID, RunnerError, assertBroadcastAuthorized,
  assertChainId, assertDistinctRoles, assertFunded, assertGasPriceUnderCap, classifyRun,
  loadAccounts, waitForCureDeadline, writeCheckpoint,
} from "./m05-runner-lib.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MONAD_RPC = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const FORK_PORT = 8548;
const MONAD_CODE_SIZE_LIMIT = 131_072;

const UNIT = 1_000_000n;
const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
const REVEAL_PERIOD = 3_600n;
/** DEMO-ONLY CONFIGURATION. A real cure window is measured in days. */
const CURE_PERIOD = 60n;

const artifact = (file, name) => {
  const parsed = JSON.parse(readFileSync(join(ROOT, "contracts", "out", file, `${name}.json`), "utf8"));
  return { abi: parsed.abi, bytecode: parsed.bytecode.object, runtime: parsed.deployedBytecode.object };
};

function parseArgs() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const at = (flag) => { const i = argv.indexOf(flag); return i === -1 ? null : argv[i + 1] ?? null; };
  const mode = argv.includes("--broadcast") ? "broadcast" : argv.includes("--fork") ? "fork" : "check";
  return { mode, out: at("--out") };
}

async function main() {
  const { mode, out } = parseArgs();
  const steps = [];
  const sent = [];
  let secrets = [];
  let checkpointPath = out;
  let status = "STOPPED";

  const record = (phase, label, detail, extra = {}) => {
    steps.push({ phase, label, detail, ...extra });
    process.stdout.write(`  ${phase.padEnd(6)}${label.padEnd(30)} ${detail}\n`);
  };
  const snapshot = () => ({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode,
    status,
    // A stopped or partial broadcast is an attempt, never a live deployment.
    classification: classifyRun(mode, status, sent.filter((tx) => tx.status === "CONFIRMED").length),
    warning:
      "Protocol doubles only. No aUSDC, no CCUSD2, no WMON and no Cleanverse endpoint. The five"
      + " prefunding transfers are external to this runner; it executes 34 of the 39 ceremony"
      + " transactions.",
    transactionAccounting: {
      externalPrefundingTransfers: 5,
      executedByRunner: sent.length,
      runnerOwns: 34,
      fullCeremony: 39,
    },
    steps,
    transactions: sent,
  });
  const checkpoint = () => {
    if (checkpointPath) writeCheckpoint(checkpointPath, snapshot(), secrets);
  };

  let fork = null;
  let rpcUrl = MONAD_RPC;
  if (mode === "fork") {
    // Spawning the fork needs no key. Keys are still not loaded at this point.
    fork = spawn("anvil", [
      "--fork-url", MONAD_RPC, "--port", String(FORK_PORT), "--host", "127.0.0.1",
      "--chain-id", String(MONAD_CHAIN_ID), "--code-size-limit", String(MONAD_CODE_SIZE_LIMIT),
      "--silent",
    ], { stdio: ["ignore", "ignore", "inherit"] });
    rpcUrl = `http://127.0.0.1:${FORK_PORT}`;
  }
  const stopFork = () => { if (fork && !fork.killed) fork.kill("SIGTERM"); };
  process.on("SIGINT", () => { stopFork(); process.exit(0); });

  const chain = {
    id: MONAD_CHAIN_ID, name: "monad-testnet",
    nativeCurrency: { name: "MON", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  };
  const transport = http(rpcUrl);
  const publicClient = createPublicClient({ chain, transport });

  try {
    for (let attempt = 0; ; attempt += 1) {
      try { await publicClient.getBlockNumber(); break; }
      catch (error) {
        if (attempt > 120) throw new RunnerError(`BLOCKED — RPC unreachable: ${error.message}`);
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    // --- gate 1: chain id, before authorization and before any key is read ---
    const chainId = await assertChainId(publicClient);
    const head = await publicClient.getBlock();
    record("gate", "chain id", `${chainId} at block ${head.number}`);

    // --- gate 2: authorization ---
    assertBroadcastAuthorized(mode, process.env, out);
    if (mode === "broadcast") {
      process.stdout.write("\n*** BROADCAST MODE. Transactions will be sent to Monad. ***\n\n");
    }

    // --- gate 3: gas price ---
    const cap = process.env.MORDANT_MAX_GAS_PRICE_GWEI
      ? BigInt(process.env.MORDANT_MAX_GAS_PRICE_GWEI) * 1_000_000_000n
      : DEFAULT_MAX_GAS_PRICE_WEI;
    const gasPrice = await assertGasPriceUnderCap(publicClient, cap);
    record("gate", "gas price", `${gasPrice} wei, cap ${cap} wei`);

    // --- gate 4: keys, only now ---
    const loaded = loadAccounts(mode, process.env, privateKeyToAccount);
    const accounts = loaded.accounts;
    const originator = loaded.originator;
    secrets = loaded.secrets;
    for (const [role, entry] of Object.entries(accounts)) {
      record("gate", `address ${role}`, entry.address);
    }
    record("gate", "address originator", `${originator.address} (signs only, sends nothing)`);

    // --- gate 5: every role is a distinct wallet ---
    const distinct = assertDistinctRoles(accounts, originator);
    record("gate", "role uniqueness", `${distinct} roles, all distinct addresses`);

    // --- Phase 0 gate: balances. The five transfers themselves are external. ---
    const funding = await assertFunded(publicClient, accounts);
    for (const entry of funding) {
      record("P0", `balance ${entry.role}`,
        `${formatEther(BigInt(entry.balance))} MON, budget ${formatEther(BigInt(entry.budget))}, ok`);
    }
    checkpoint();

    const eligibilityArt = artifact("MockEligibility.sol", "MockEligibility");
    const erc20Art = artifact("MockERC20.sol", "MockERC20");
    const adapterArt = artifact("MockCvaAdapter.sol", "MockCvaAdapter");
    const factoryArt = artifact("MordantFactory.sol", "MordantFactory");
    const vaultArt = artifact("MordantInvoiceVault.sol", "MordantInvoiceVault");

    if (mode === "check") {
      const caller = accounts.deployer.address;
      const plan = [
        ["MockEligibility", eligibilityArt, []],
        ["settlement double", erc20Art, ["Mordant Demo Settlement (double)", "dSETTLE", 6]],
        ["CVA double", erc20Art, ["Mordant Demo Invoice A-Token (double)", "dINV", 6]],
        ["MockCvaAdapter", adapterArt, ["0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9"]],
        ["MordantFactory", factoryArt, [caller, "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9"]],
      ];
      let estimated = 0n;
      for (const [label, art, args] of plan) {
        const data = encodeDeployData({ abi: art.abi, bytecode: art.bytecode, args });
        // Fail-closed: a failed estimate stops the check rather than being reported as a note.
        const gas = await publicClient.estimateGas({ account: caller, data }).catch((error) => {
          throw new RunnerError(
            `BLOCKED — creation gas estimate failed for ${label}:`
            + ` ${(error.shortMessage ?? error.message).split("\n")[0]}`,
          );
        });
        estimated += gas;
        record("P1", `estimate ${label}`, `${gas} gas`);
      }
      record("P1", "deployment gas subtotal", `${estimated} gas`);
      status = "CHECK PASSED";
      checkpoint();
      return { status, out: checkpointPath };
    }

    // ---------- sending path ----------
    const deploy = async (role, art, args, label) => {
      const hash = await createWalletClient({ account: accounts[role], chain, transport })
        .deployContract({ abi: art.abi, bytecode: art.bytecode, args });
      // Checkpoint the hash the instant it exists. An interruption between broadcast and receipt
      // must still leave a record of what was sent.
      const entry = { label, role, hash, status: "PENDING", block: null, gas: null, readback: null };
      sent.push(entry);
      checkpoint();
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      entry.block = receipt.blockNumber.toString();
      entry.gas = receipt.gasUsed.toString();
      entry.status = receipt.status === "success" ? "CONFIRMED" : "REVERTED";
      checkpoint();
      if (receipt.status !== "success") throw new RunnerError(`${label} reverted`);
      const code = await publicClient.getCode({ address: receipt.contractAddress });
      const size = (code.length - 2) / 2;
      const expected = (art.runtime.length - 2) / 2;
      if (size !== expected) {
        entry.readback = "FAILED";
        checkpoint();
        throw new RunnerError(`${label} readback failed: ${size} B installed, expected ${expected} B`);
      }
      entry.readback = "PASSED";
      entry.address = receipt.contractAddress;
      record("P1", label, `${receipt.contractAddress}, ${size} B, gas ${receipt.gasUsed}`);
      checkpoint();
      return receipt.contractAddress;
    };

    const send = async (phase, role, address, abi, fn, args, label, readback) => {
      const hash = await createWalletClient({ account: accounts[role], chain, transport })
        .writeContract({ address, abi, functionName: fn, args });
      // Same rule as deployments: the hash is recorded before the receipt is awaited.
      const entry = { label, role, hash, status: "PENDING", block: null, gas: null, readback: null };
      sent.push(entry);
      checkpoint();
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      entry.block = receipt.blockNumber.toString();
      entry.gas = receipt.gasUsed.toString();
      entry.status = receipt.status === "success" ? "CONFIRMED" : "REVERTED";
      checkpoint();
      if (receipt.status !== "success") throw new RunnerError(`${label} reverted`);
      if (readback) {
        const problem = await readback(receipt);
        if (problem) {
          entry.readback = "FAILED";
          checkpoint();
          throw new RunnerError(`${label} readback failed: ${problem}`);
        }
        entry.readback = "PASSED";
      }
      record(phase, label, `gas ${receipt.gasUsed}, block ${receipt.blockNumber}`);
      checkpoint();
      return receipt;
    };

    const read = (address, abi, functionName, args = []) =>
      publicClient.readContract({ address, abi, functionName, args });

    const eligibility = await deploy("deployer", eligibilityArt, [], "MockEligibility");
    const settlement = await deploy("deployer", erc20Art,
      ["Mordant Demo Settlement (double)", "dSETTLE", 6], "settlement double");
    const cva = await deploy("deployer", erc20Art,
      ["Mordant Demo Invoice A-Token (double)", "dINV", 6], "CVA double");
    const adapter = await deploy("deployer", adapterArt, [cva], "MockCvaAdapter");
    const factory = await deploy("deployer", factoryArt, [accounts.deployer.address, eligibility], "MordantFactory");

    const assertAccounting = (vault) => read(vault, vaultArt.abi, "assertAccounting");

    for (const [role, id] of [["buyer", 1], ["originator", 2], ["facilityA", 3], ["facilityB", 3],
      ["holderA", 4], ["holderB", 4]]) {
      const address = role === "originator" ? originator.address : accounts[role].address;
      await send("P2", "deployer", eligibility, eligibilityArt.abi, "setEligible", [address, id, true],
        `setEligible ${role}`,
        async () => await read(eligibility, eligibilityArt.abi, "isEligible", [address, id])
          ? null : "isEligible still false");
    }
    for (const role of ["facilityA", "facilityB"]) {
      await send("P2", "deployer", factory, factoryArt.abi, "setFacility", [accounts[role].address, true],
        `setFacility ${role}`,
        async () => await read(factory, factoryArt.abi, "isFacility", [accounts[role].address])
          ? null : "isFacility still false");
    }
    await send("P2", "deployer", factory, factoryArt.abi, "setCvaAdapter", [adapter, true], "setCvaAdapter",
      async () => await read(factory, factoryArt.abi, "approvedCvaAdapter", [adapter]) ? null : "adapter not approved");
    await send("P2", "deployer", factory, factoryArt.abi, "setSettlementToken", [settlement, true], "setSettlementToken",
      async () => await read(factory, factoryArt.abi, "approvedSettlementToken", [settlement]) ? null : "token not approved");

    const opening = await publicClient.getBlock();
    const protectionEnd = opening.timestamp + 30n * 24n * 3_600n;
    const invoiceRoot = keccak256(`0x${Date.now().toString(16)}`);
    let vault = null;
    await send("P2", "buyer", factory, factoryArt.abi, "createInvoiceVault", [{
      cvaAdapter: adapter, settlementToken: settlement, invoiceRoot, currency: CURRENCY,
      buyer: accounts.buyer.address, originatorTreasury: originator.address,
      initialOriginatorSigner: originator.address, initialUnits: 100n * UNIT,
      advanceAmount: 100n * UNIT, faceValue: 110n * UNIT, bondBps: 1_000,
      protectionEnd, revealPeriod: REVEAL_PERIOD, curePeriod: CURE_PERIOD,
    }], "createInvoiceVault", async (receipt) => {
      vault = parseEventLogs({ abi: factoryArt.abi, eventName: "InvoiceVaultCreated", logs: receipt.logs })[0]?.args?.vault;
      if (!vault) return "no InvoiceVaultCreated event";
      const registered = await read(factory, factoryArt.abi, "vaultForRoot", [invoiceRoot]);
      if (registered.toLowerCase() !== vault.toLowerCase()) return "vaultForRoot mismatch";
      const code = await publicClient.getCode({ address: vault });
      const size = (code.length - 2) / 2;
      const expected = (vaultArt.runtime.length - 2) / 2;
      if (size !== expected) return `vault runtime ${size} B, expected ${expected} B`;
      // Vault identity: the economics must be exactly what was requested.
      for (const [fn, want] of [["faceValue", 110n * UNIT], ["initialUnits", 100n * UNIT],
        ["advanceAmount", 100n * UNIT], ["initialBond", 10n * UNIT]]) {
        const got = await read(vault, vaultArt.abi, fn);
        if (got !== want) return `${fn} is ${got}, expected ${want}`;
      }
      if (Number(await read(vault, vaultArt.abi, "bondBps")) !== 1_000) return "bondBps mismatch";
      if ((await read(vault, vaultArt.abi, "invoiceRoot")).toLowerCase() !== invoiceRoot.toLowerCase()) {
        return "invoiceRoot mismatch";
      }
      return null;
    });
    record("P2", "vault", vault);

    await send("P2", "deployer", eligibility, eligibilityArt.abi, "setIdentityValid", [vault, true],
      "setIdentityValid(vault)",
      async () => await read(eligibility, eligibilityArt.abi, "hasValidIdentity", [vault]) ? null : "vault identity invalid");
    await send("P2", "deployer", cva, erc20Art.abi, "mint", [accounts.deployer.address, 100n * UNIT], "mint CVA supply",
      async () => await read(cva, erc20Art.abi, "totalSupply") === 100n * UNIT ? null : "CVA supply mismatch");
    await send("P2", "deployer", cva, erc20Art.abi, "approve", [adapter, 100n * UNIT], "approve adapter",
      async () => await read(cva, erc20Art.abi, "allowance", [accounts.deployer.address, adapter]) === 100n * UNIT
        ? null : "adapter allowance mismatch");
    await send("P2", "deployer", adapter, adapterArt.abi, "creditVault", [vault, 100n * UNIT], "creditVault",
      async () => {
        const available = await read(adapter, adapterArt.abi, "availableBalance", [vault]);
        if (available !== 100n * UNIT) return `custody credit ${available}, expected 100e6`;
        const issued = await read(adapter, adapterArt.abi, "issuedSupply");
        if (issued !== 100n * UNIT) return `issuedSupply ${issued}, expected 100e6`;
        const held = await read(cva, erc20Art.abi, "balanceOf", [adapter]);
        return held === 100n * UNIT ? null : `adapter holds ${held}, expected 100e6`;
      });
    await send("P2", "deployer", settlement, erc20Art.abi, "mint", [accounts.holderA.address, 100n * UNIT], "mint settlement funder",
      async () => await read(settlement, erc20Art.abi, "balanceOf", [accounts.holderA.address]) === 100n * UNIT
        ? null : "funder balance mismatch");
    await send("P2", "deployer", settlement, erc20Art.abi, "mint", [accounts.buyer.address, 110n * UNIT], "mint settlement buyer",
      async () => await read(settlement, erc20Art.abi, "balanceOf", [accounts.buyer.address]) === 110n * UNIT
        ? null : "buyer balance mismatch");

    // ---------- Phase 3 ----------
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
    const signPledge = (message) => createWalletClient({ account: originator, chain, transport })
      .signTypedData({ account: originator, domain, types, primaryType: "Pledge", message });

    const first = pledgeFor(accounts.facilityA.address, 1);
    const firstSignature = await signPledge(first);
    await send("P3", "holderA", settlement, erc20Art.abi, "approve", [vault, 100n * UNIT], "approve funding",
      async () => await read(settlement, erc20Art.abi, "allowance", [accounts.holderA.address, vault]) === 100n * UNIT
        ? null : "funding allowance mismatch");
    await send("P3", "facilityA", vault, vaultArt.abi, "activate",
      [first, firstSignature, accounts.holderA.address, [accounts.holderA.address], [100n * UNIT]],
      "activate 90/10", async () => {
        if (Number(await read(vault, vaultArt.abi, "protectionState")) !== 1) return "not Active";
        if (Number(await read(vault, vaultArt.abi, "receivableState")) !== 1) return "not Outstanding";
        const proceeds = await read(settlement, erc20Art.abi, "balanceOf", [originator.address]);
        if (proceeds !== 90n * UNIT) return `originator proceeds ${proceeds}, expected 90e6`;
        const vaultCash = await read(settlement, erc20Art.abi, "balanceOf", [vault]);
        if (vaultCash !== 10n * UNIT) return `vault holds ${vaultCash}, expected 10e6`;
        if (await read(vault, vaultArt.abi, "bondLocked") !== 10n * UNIT) return "bondLocked mismatch";
        if (await read(vault, vaultArt.abi, "totalSupply") !== 100n * UNIT) return "totalSupply mismatch";
        if (await read(vault, vaultArt.abi, "cvaAccounted") !== 100n * UNIT) return "cvaAccounted mismatch";
        await assertAccounting(vault);
        return null;
      });
    await send("P3", "holderA", vault, vaultArt.abi, "transfer", [accounts.holderB.address, 40n * UNIT], "transfer 40 units",
      async () => {
        if (await read(vault, vaultArt.abi, "balanceOf", [accounts.holderA.address]) !== 60n * UNIT) return "holder A units";
        if (await read(vault, vaultArt.abi, "balanceOf", [accounts.holderB.address]) !== 40n * UNIT) return "holder B units";
        await assertAccounting(vault);
        return null;
      });

    const second = pledgeFor(accounts.facilityB.address, 2);
    const secondSignature = await signPledge(second);
    const digest = await read(vault, vaultArt.abi, "hashPledge", [second]);
    const salt = `0x${"5a".repeat(32)}`;
    const commitment = await read(vault, vaultArt.abi, "conflictCommitment",
      [digest, keccak256(secondSignature), accounts.facilityB.address, salt]);
    await send("P3", "facilityB", vault, vaultArt.abi, "commitConflict", [commitment], "commitConflict",
      async () => {
        if (Number(await read(vault, vaultArt.abi, "protectionState")) !== 2) return "not CommitPending";
        const pending = await read(vault, vaultArt.abi, "pendingConflict");
        return pending[0].toLowerCase() === commitment.toLowerCase() ? null : "commitment mismatch";
      });
    await send("P3", "facilityB", vault, vaultArt.abi, "revealConflict", [second, secondSignature, salt], "revealConflict",
      async () => {
        if (Number(await read(vault, vaultArt.abi, "protectionState")) !== 3) return "not ConflictConfirmed";
        const pending = await read(vault, vaultArt.abi, "pendingConflict");
        return pending[7] > 0n ? null : "cureDeadline not set";
      });

    if (mode === "fork") {
      await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify([
          { jsonrpc: "2.0", id: 1, method: "evm_increaseTime", params: [Number(CURE_PERIOD) + 10] },
          { jsonrpc: "2.0", id: 2, method: "evm_mine", params: [] }]) });
    }
    // Proof comes from the deadline the contract recorded and from chain time passing it.
    const cure = await waitForCureDeadline(publicClient,
      async () => (await read(vault, vaultArt.abi, "pendingConflict"))[7],
      { onPoll: (block, timestamp, deadline) => {
        if (timestamp <= deadline) {
          process.stdout.write(`  P3    cure window                    block ${block}, ${deadline - timestamp}s remaining\n`);
        }
      } });
    record("P3", "cure window elapsed", `deadline ${cure.deadline}, chain time ${cure.observedTimestamp}, block ${cure.block}`);

    await send("P3", "facilityB", vault, vaultArt.abi, "finalizeConflict", [], "finalizeConflict",
      async () => {
        if (Number(await read(vault, vaultArt.abi, "protectionState")) !== 4) return "not Entitled";
        const allocated = await read(vault, vaultArt.abi, "entitlementAllocated");
        if (allocated !== 10n * UNIT) return `entitlement ${allocated}, expected 10e6`;
        await assertAccounting(vault);
        return null;
      });

    for (const [role, payout, units] of [["holderA", 6n * UNIT, 60n * UNIT], ["holderB", 4n * UNIT, 40n * UNIT]]) {
      const before = await read(settlement, erc20Art.abi, "balanceOf", [accounts[role].address]);
      await send("P3", role, vault, vaultArt.abi, "claimBond", [], `claimBond ${role}`, async () => {
        const after = await read(settlement, erc20Art.abi, "balanceOf", [accounts[role].address]);
        if (after - before !== payout) return `paid ${after - before}, expected ${payout}`;
        const held = await read(vault, vaultArt.abi, "balanceOf", [accounts[role].address]);
        if (held !== units) return `claiming consumed units: ${held}, expected ${units}`;
        await assertAccounting(vault);
        return null;
      });
    }

    await send("P3", "buyer", settlement, erc20Art.abi, "approve", [vault, 110n * UNIT], "approve redemption",
      async () => await read(settlement, erc20Art.abi, "allowance", [accounts.buyer.address, vault]) === 110n * UNIT
        ? null : "redemption allowance mismatch");
    await send("P3", "buyer", vault, vaultArt.abi, "fundRedemption", [110n * UNIT], "fundRedemption",
      async () => {
        if (await read(vault, vaultArt.abi, "redemptionEscrow") !== 110n * UNIT) return "escrow mismatch";
        await assertAccounting(vault);
        return null;
      });

    for (const [role, units, cash] of [["holderA", 60n * UNIT, 66n * UNIT], ["holderB", 40n * UNIT, 44n * UNIT]]) {
      const before = await read(settlement, erc20Art.abi, "balanceOf", [accounts[role].address]);
      await send("P3", role, vault, vaultArt.abi, "redeem", [units], `redeem ${role}`, async () => {
        const after = await read(settlement, erc20Art.abi, "balanceOf", [accounts[role].address]);
        if (after - before !== cash) return `redeemed ${after - before}, expected ${cash}`;
        await assertAccounting(vault);
        return null;
      });
    }

    const redeemed = await read(vault, vaultArt.abi, "redeemedFace");
    if (redeemed !== 110n * UNIT) throw new RunnerError(`final readback: redeemedFace ${redeemed}`);
    if (Number(await read(vault, vaultArt.abi, "receivableState")) !== 2) {
      throw new RunnerError("final readback: receivable is not Redeemed");
    }
    record("done", "final readback", "redeemedFace 110e6, receivable Redeemed");
    record("done", "transactions sent", `${sent.length} of the 34 the runner owns`);
    const confirmed = sent.filter((tx) => tx.status === "CONFIRMED").length;
    if (confirmed !== sent.length) {
      throw new RunnerError(`final readback: ${sent.length - confirmed} transaction(s) not confirmed`);
    }
    status = mode === "fork" ? "FORK RUN COMPLETE" : "MONAD RUN COMPLETE";
    checkpoint();
    return { status, out: checkpointPath };
  } catch (error) {
    status = "STOPPED";
    record("stop", "run stopped", error.message.split("\n")[0].slice(0, 200));
    checkpoint();
    throw error;
  } finally {
    stopFork();
  }
}

main().then((result) => {
  if (result.out) process.stdout.write(`\nArtifact: ${result.out}.json\n`);
  process.stdout.write(`\n${result.status}\n`);
}).catch((error) => {
  process.stderr.write(`\nSTOPPED: ${error.message}\n`);
  process.exitCode = 1;
});
