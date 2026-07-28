#!/usr/bin/env node
/**
 * M-13: pinned Monad fork rehearsal.
 *
 * Everything Mordant needs before it can settle, rehearsed against real deployed Cleanverse
 * contracts on a local fork: adapter deployment, A-Pass issuance to that adapter, the supply and
 * role ceremony, vault binding, and both the burn and default-release paths.
 *
 *   node scripts/m13-rehearsal.mjs [--out <prefix>]
 *
 * Nothing public is touched. Writes go only to a loopback Anvil; the Monad endpoint is a fork
 * source and receives no transaction; no Cleanverse endpoint is called. No anvil_setStorageAt: the
 * A-Pass is issued by replaying the observed issuance call, whose exact-replay reproducibility
 * control A proves first.
 *
 * `0xb8dd3664` is never named `issue`. It is the observed issuance call selector, and its ABI is
 * unpublished and not claimed.
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient, createTestClient, createWalletClient, http, keccak256, parseEventLogs,
  toBytes,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  APASS_REGISTRY, OBSERVED_ISSUANCE, OBSERVED_ISSUER, assertAnvilClient, assertForkChain,
  assertLoopbackRpc, assertSubstitutionBounded, assertUpstreamSeparate, assumptionRegister,
  diffCalldata, substituteSubjectAddress,
} from "./m13-fork-lib.mjs";
import { ControlError, writeArtifact } from "./runner-controls.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UPSTREAM = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const FORK_PORT = Number(process.env.M13_FORK_PORT ?? 8_548);
const FORK_RPC = `http://127.0.0.1:${FORK_PORT}`;

const MINV01 = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const MINV01_ADMIN = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const POLICY = "0x36489bE45fa84f70a0c2BDB11D824Be608CB12Dd";
const ZERO = "0x0000000000000000000000000000000000000000";

/** MINV01's issuing block, so the fork starts after the token exists. */
const MINV01_ISSUE_BLOCK = 48_901_500n;

/** Anvil's published development keys. A fork only, never a real wallet. */
const FORK_KEYS = Object.freeze({
  issuanceMinter: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  deployer: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
});

const INITIAL_UNITS = 1_000_000n;

const MINTER_ROLE = keccak256(toBytes("MINTER_ROLE"));

const TOKEN_ABI = [
  { type: "function", name: "totalSupply", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "hasRole", stateMutability: "view", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "grantRole", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "revokeRole", stateMutability: "nonpayable", inputs: [{ type: "bytes32" }, { type: "address" }], outputs: [] },
  { type: "function", name: "mint", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [] },
  { type: "event", name: "RoleGranted", inputs: [
    { name: "role", type: "bytes32", indexed: true }, { name: "account", type: "address", indexed: true },
    { name: "sender", type: "address", indexed: true }] },
  { type: "event", name: "RoleRevoked", inputs: [
    { name: "role", type: "bytes32", indexed: true }, { name: "account", type: "address", indexed: true },
    { name: "sender", type: "address", indexed: true }] },
];

const POLICY_ABI = [
  { type: "function", name: "canTransfer", stateMutability: "view",
    inputs: [{ type: "address" }, { type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [{ type: "bool" }] },
];

const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const ADAPTER_ABI_VIEW = [
  { type: "function", name: "token", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "apass", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "boundVault", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
];

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

const artifact = (file, name) => JSON.parse(
  readFileSync(join(ROOT, `contracts/out/${file}/${name}.json`), "utf8"));

/**
 * Reconstructs every role change on MINV01 since it was issued, so the final minter set is read
 * from events rather than assumed. If the history cannot be reconstructed, exclusivity is NOT
 * PROVEN and the caller must not bind the vault.
 */
export function deriveActiveMinters(events) {
  const active = new Set();
  const ordered = [...events].sort((a, b) => {
    if (a.blockNumber !== b.blockNumber) return a.blockNumber < b.blockNumber ? -1 : 1;
    return Number(a.logIndex) - Number(b.logIndex);
  });
  for (const event of ordered) {
    if (String(event.role).toLowerCase() !== MINTER_ROLE.toLowerCase()) continue;
    const account = String(event.account).toLowerCase();
    if (event.name === "RoleGranted") active.add(account);
    if (event.name === "RoleRevoked") active.delete(account);
  }
  return [...active];
}

/** Exclusivity holds only when the active minter set is exactly the adapter. */
export function classifyMinterExclusivity(activeMinters, adapterAddress) {
  if (!Array.isArray(activeMinters)) return "NOT PROVEN";
  const expected = String(adapterAddress).toLowerCase();
  const unexpected = activeMinters.filter((address) => address !== expected);
  if (unexpected.length > 0) return "NOT PROVEN";
  if (!activeMinters.includes(expected)) return "NOT PROVEN";
  return "PROVEN";
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

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    classification: "PENDING",
    scope: "Local fork only. No public transaction, no Cleanverse endpoint, no anvil_setStorageAt."
      + " Nothing here is a live Mordant settlement.",
    steps,
  };

  const fork = spawn("anvil", [
    "--fork-url", UPSTREAM, "--fork-block-number", String(MINV01_ISSUE_BLOCK),
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
    const head = await client.getBlockNumber();
    const block = await client.getBlock({ blockNumber: head });
    report.hygiene = { writeRpc: FORK_RPC, loopback: true, upstreamSeparate: true, clientVersion,
      chainId, forkBlock: head.toString(), forkBlockHash: block.hash };
    note("fork", `${clientVersion}, chain ${chainId}, block ${head}`);

    const deployer = privateKeyToAccount(FORK_KEYS.deployer);
    const issuanceMinter = privateKeyToAccount(FORK_KEYS.issuanceMinter);
    await test.setBalance({ address: deployer.address, value: 10n ** 20n });
    await test.setBalance({ address: issuanceMinter.address, value: 10n ** 20n });
    const deployerWallet = createWalletClient({ account: deployer, transport });

    // --- 1. deploy the production adapter ---
    const adapterArtifact = artifact("CleanverseCvaAdapter.sol", "CleanverseCvaAdapter");
    const deployHash = await deployerWallet.deployContract({
      abi: adapterArtifact.abi, bytecode: adapterArtifact.bytecode.object,
      args: [MINV01_ADMIN, MINV01, APASS_REGISTRY], chain: null });
    const deployReceipt = await client.waitForTransactionReceipt({ hash: deployHash });
    const adapter = deployReceipt.contractAddress;
    if (deployReceipt.status !== "success" || !adapter) stop("the adapter deployment failed on the fork.");
    note("adapter deployed", adapter);

    // --- 2. issue its A-Pass by bounded substitution of the observed call ---
    const substituted = substituteSubjectAddress(OBSERVED_ISSUANCE.calldata, adapter);
    const diff = diffCalldata(OBSERVED_ISSUANCE.calldata, substituted);
    assertSubstitutionBounded(diff);
    report.substitution = {
      original: OBSERVED_ISSUANCE.calldata, substituted,
      originalHash: keccak256(OBSERVED_ISSUANCE.calldata), substitutedHash: keccak256(substituted),
      selector: OBSERVED_ISSUANCE.selector, registry: APASS_REGISTRY, issuer: OBSERVED_ISSUER,
      diff,
      selectorNaming: "observed issuance call selector; its ABI is unpublished and not claimed",
    };
    note("substitution", `only word 0 differs, ${diff.wordCount} words, same selector and length`);

    await test.impersonateAccount({ address: OBSERVED_ISSUER });
    await test.setBalance({ address: OBSERVED_ISSUER, value: 10n ** 19n });
    const issuerWallet = createWalletClient({ account: OBSERVED_ISSUER, transport });
    const apassBefore = await client.readContract({
      address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass", args: [adapter] });
    const issueHash = await issuerWallet.sendTransaction({
      to: APASS_REGISTRY, data: substituted, value: 0n, chain: null, gas: 2_000_000n });
    const issueReceipt = await client.waitForTransactionReceipt({ hash: issueHash });
    const apassAfter = await client.readContract({
      address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass", args: [adapter] });
    if (issueReceipt.status !== "success" || apassBefore !== false || apassAfter !== true) {
      stop(`the substituted issuance did not produce an A-Pass for the adapter`
        + ` (before ${apassBefore}, after ${apassAfter}, status ${issueReceipt.status}).`);
    }
    report.adapterApass = { adapter, before: apassBefore, after: apassAfter, hash: issueHash,
      logCount: issueReceipt.logs.length,
      logs: issueReceipt.logs.map((entry) => ({ address: entry.address, topic0: entry.topics[0] })) };
    note("adapter A-Pass", `isValidAPass ${apassBefore} -> ${apassAfter}, ${issueReceipt.logs.length} logs`);

    // --- 3. the policy must permit the adapter's three MINV01 directions ---
    const holderA = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
    const holderB = "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6";
    const can = async (from, to, amount) => client.readContract({
      address: POLICY, abi: POLICY_ABI, functionName: "canTransfer",
      args: [MINV01, from, to, amount] }).catch((error) => `reverted: ${(error.shortMessage ?? error.message).slice(0, 60)}`);
    const adapterTuples = [
      { label: "mint to adapter", from: ZERO, to: adapter, amount: INITIAL_UNITS },
      { label: "burn from adapter", from: adapter, to: ZERO, amount: INITIAL_UNITS },
      { label: "release to holderA", from: adapter, to: holderA, amount: INITIAL_UNITS / 2n },
      { label: "release to holderB", from: adapter, to: holderB, amount: INITIAL_UNITS / 2n },
    ];
    for (const tuple of adapterTuples) {
      tuple.answer = await can(tuple.from, tuple.to, tuple.amount);
      note(`policy ${tuple.label}`, String(tuple.answer));
    }
    report.adapterPolicyTuples = adapterTuples.map((tuple) => ({ ...tuple, amount: tuple.amount.toString() }));
    const failedTuples = adapterTuples.filter((tuple) => tuple.answer !== true);
    if (failedTuples.length > 0) {
      stop(`the policy refuses ${failedTuples.map((tuple) => tuple.label).join(", ")}.`);
    }

    // --- 4 to 8. the supply and role ceremony ---
    await test.impersonateAccount({ address: MINV01_ADMIN });
    await test.setBalance({ address: MINV01_ADMIN, value: 10n ** 19n });
    const adminWallet = createWalletClient({ account: MINV01_ADMIN, transport });
    const send = async (wallet, functionName, args) => {
      const hash = await wallet.writeContract({
        address: MINV01, abi: TOKEN_ABI, functionName, args, chain: null });
      const receipt = await client.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") stop(`${functionName} reverted on the fork. Hash ${hash}.`);
      return { hash, blockNumber: receipt.blockNumber };
    };

    const grantTemp = await send(adminWallet, "grantRole", [MINTER_ROLE, issuanceMinter.address]);
    note("grant temporary minter", `${issuanceMinter.address} at block ${grantTemp.blockNumber}`);
    const minterWallet = createWalletClient({ account: issuanceMinter, transport });
    const mint = await send(minterWallet, "mint", [adapter, INITIAL_UNITS]);
    note("mint", `${INITIAL_UNITS} to the adapter at block ${mint.blockNumber}`);
    const revokeTemp = await send(adminWallet, "revokeRole", [MINTER_ROLE, issuanceMinter.address]);
    note("revoke temporary minter", `at block ${revokeTemp.blockNumber}`);
    const grantAdapter = await send(adminWallet, "grantRole", [MINTER_ROLE, adapter]);
    note("grant adapter minter", `at block ${grantAdapter.blockNumber}`);

    const roleState = {
      adminIsMinter: await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole", args: [MINTER_ROLE, MINV01_ADMIN] }),
      issuanceWalletIsMinter: await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole", args: [MINTER_ROLE, issuanceMinter.address] }),
      adapterIsMinter: await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "hasRole", args: [MINTER_ROLE, adapter] }),
      totalSupply: (await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "totalSupply" })).toString(),
      adapterBalance: (await client.readContract({ address: MINV01, abi: TOKEN_ABI, functionName: "balanceOf", args: [adapter] })).toString(),
    };
    report.roleCeremony = { issuanceWallet: issuanceMinter.address, initialUnits: INITIAL_UNITS.toString(),
      grantTemp: grantTemp.hash, mint: mint.hash, revokeTemp: revokeTemp.hash, grantAdapter: grantAdapter.hash,
      ...roleState };
    note("role state", `admin ${roleState.adminIsMinter}, issuance ${roleState.issuanceWalletIsMinter},`
      + ` adapter ${roleState.adapterIsMinter}`);
    note("supply", `total ${roleState.totalSupply}, adapter holds ${roleState.adapterBalance}`);
    if (roleState.adminIsMinter !== false || roleState.issuanceWalletIsMinter !== false
      || roleState.adapterIsMinter !== true) {
      stop("the role state after the ceremony is not the intended one.");
    }
    if (roleState.totalSupply !== INITIAL_UNITS.toString()
      || roleState.adapterBalance !== INITIAL_UNITS.toString()) {
      stop("the supply ceremony did not place exactly the intended units in the adapter.");
    }

    // --- minter exclusivity, reconstructed from events since MINV01 was issued ---
    const roleEvents = [];
    let reconstructionComplete = true;
    try {
      const fromBlock = MINV01_ISSUE_BLOCK - 400n;
      for (let start = fromBlock; start <= await client.getBlockNumber(); start += 100n) {
        const logs = await client.getLogs({ address: MINV01, fromBlock: start,
          toBlock: start + 99n });
        const parsed = parseEventLogs({ abi: TOKEN_ABI, logs });
        for (const entry of parsed) {
          if (entry.eventName !== "RoleGranted" && entry.eventName !== "RoleRevoked") continue;
          roleEvents.push({ name: entry.eventName, role: entry.args.role, account: entry.args.account,
            sender: entry.args.sender, blockNumber: entry.blockNumber, logIndex: entry.logIndex });
        }
      }
    } catch (error) {
      reconstructionComplete = false;
      note("role history", `could not be reconstructed: ${(error.shortMessage ?? error.message).slice(0, 90)}`);
    }
    const activeMinters = reconstructionComplete ? deriveActiveMinters(roleEvents) : null;
    const exclusivity = reconstructionComplete
      ? classifyMinterExclusivity(activeMinters, adapter) : "NOT PROVEN";
    report.minterExclusivity = { reconstructionComplete, eventCount: roleEvents.length,
      events: roleEvents.map((entry) => ({ ...entry, blockNumber: entry.blockNumber.toString() })),
      activeMinters, classification: exclusivity };
    note("minter exclusivity", `${exclusivity}, active: ${(activeMinters ?? []).join(", ") || "none"}`);

    report.assumptions = assumptionRegister({
      controlA: "FORK-PROVEN", stepB: "FORK-PROVEN",
      minterExclusivity: (activeMinters ?? []).join(", ") || "unestablished",
      minterExclusivityGrade: exclusivity === "PROVEN" ? "FORK-PROVEN" : "NOT PROVEN",
      tuples: `${adapterTuples.length} adapter tuples pass`, tuplesGrade: "FORK-PROVEN",
    });

    report.statuses = {
      "FORK APASS REGISTRY ISSUE": "PROVEN",
      "FORK APASS ISSUE TO NEW CONTRACT": "PROVEN VIA OBSERVED CALL SHAPE",
      "APASS ISSUANCE ABI": "UNPUBLISHED / NOT CLAIMED",
      "APASS ON-CHAIN FORK READBACK": "PROVEN",
      "CLEANVERSE API READBACK": "NOT APPLICABLE TO FORK-LOCAL STATE",
      "TEMPORARY ISSUANCE MINTER": "GRANTED / REVOKED",
      "ADAPTER MINTER ROLE": "GRANTED ON FORK",
      "EXACT SUPPLY CEREMONY": "PROVEN",
      "MINTER EXCLUSIVITY": exclusivity,
      "PUBLIC ADAPTER DEPLOYMENT": "NOT DONE",
      "LIVE ADAPTER APASS": "NOT PROVEN FOR THIS ADDRESS",
      "LIVE CLEANVERSE GATEWAY ISSUE FOR ADAPTER": "NOT PROVEN",
      "LIVE MINTER ROLE / MINT / BIND": "NOT DONE",
      "MORDANT SETTLEMENT": "NOT PROVEN LIVE",
    };
    report.adapter = { address: adapter,
      token: await client.readContract({ address: adapter, abi: ADAPTER_ABI_VIEW, functionName: "token" }),
      apass: await client.readContract({ address: adapter, abi: ADAPTER_ABI_VIEW, functionName: "apass" }),
      owner: await client.readContract({ address: adapter, abi: ADAPTER_ABI_VIEW, functionName: "owner" }),
      boundVault: await client.readContract({ address: adapter, abi: ADAPTER_ABI_VIEW, functionName: "boundVault" }) };

    report.classification = exclusivity === "PROVEN"
      ? "M-13 SUPPLY AND ROLE CEREMONY: PROVEN ON FORK"
      : "M-13 SUPPLY AND ROLE CEREMONY: PROVEN ON FORK, MINTER EXCLUSIVITY NOT PROVEN";
    process.stdout.write(`\n${"CLASSIFICATION".padEnd(30)} ${report.classification}\n`);
    if (out) { writeArtifact(out, report, process.env); process.stdout.write(`\nWrote ${out}.json\n`); }
  } finally {
    stopFork();
  }
}

const invokedDirectly = process.argv[1]?.endsWith("m13-rehearsal.mjs");
if (invokedDirectly) {
  process.stdout.write("M-13 pinned Monad fork rehearsal\n\n");
  main().catch((error) => {
    process.stderr.write(`\n${error instanceof ControlError ? error.message : `STOP — ${error.message}`}\n`);
    process.exitCode = 1;
  });
}
