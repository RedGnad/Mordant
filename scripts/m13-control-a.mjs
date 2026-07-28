#!/usr/bin/env node
/**
 * M-13 control A: replay the observed A-Pass issuance call, byte for byte.
 *
 * The gate for everything after it. If the exact recorded calldata, sent from the impersonated
 * issuer at the parent block, does not reproduce the A-Pass, then the call shape is not
 * reproducible and the rehearsal stops rather than proceeding on a reinterpretation.
 *
 *   node scripts/m13-control-a.mjs [--out <prefix>]
 *
 * Nothing here names `0xb8dd3664`. Cleanverse publishes no ABI for it and none is claimed: it is
 * the observed issuance call selector, replayed as opaque bytes.
 *
 * Writes go only to a loopback Anvil. The upstream Monad endpoint is a fork source and receives no
 * transaction. No Cleanverse endpoint is called at all.
 */
import { spawn } from "node:child_process";

import { createPublicClient, createTestClient, createWalletClient, http, keccak256 } from "viem";

import {
  APASS_REGISTRY, OBSERVED_ISSUANCE, OBSERVED_ISSUER, assertAnvilClient, assertForkChain,
  assertLoopbackRpc, assertUpstreamSeparate,
} from "./m13-fork-lib.mjs";
import { ControlError, writeArtifact } from "./runner-controls.mjs";

const UPSTREAM = process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz";
const FORK_PORT = Number(process.env.M13_FORK_PORT ?? 8_547);
const FORK_RPC = `http://127.0.0.1:${FORK_PORT}`;

const APASS_ABI = [
  { type: "function", name: "isValidAPass", stateMutability: "view",
    inputs: [{ type: "address" }], outputs: [{ type: "bool" }] },
];

const stop = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

export async function runControlA({ out = null, log = () => {} } = {}) {
  // Hygiene first, before anything is spawned or sent.
  assertLoopbackRpc(FORK_RPC);
  assertUpstreamSeparate(UPSTREAM, FORK_RPC);

  const fork = spawn("anvil", [
    "--fork-url", UPSTREAM,
    "--fork-block-number", String(OBSERVED_ISSUANCE.parentBlockNumber),
    "--port", String(FORK_PORT), "--host", "127.0.0.1",
    "--chain-id", "10143", "--silent",
  ], { stdio: ["ignore", "ignore", "inherit"] });
  const stopFork = () => { if (!fork.killed) fork.kill("SIGTERM"); };

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

    // The write endpoint must identify itself as Anvil before it receives a transaction.
    const clientVersion = await client.request({ method: "web3_clientVersion" });
    assertAnvilClient(clientVersion);
    const chainId = assertForkChain(await client.getChainId());
    const head = await client.getBlockNumber();
    const block = await client.getBlock({ blockNumber: head });
    log("fork", `${clientVersion}, chain ${chainId}, block ${head} ${block.hash}`);

    if (head !== OBSERVED_ISSUANCE.parentBlockNumber) {
      stop(`the fork head is ${head}, expected the parent block`
        + ` ${OBSERVED_ISSUANCE.parentBlockNumber}.`);
    }

    // The A-Pass must not exist yet, or the replay would prove nothing.
    const before = await client.readContract({
      address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass",
      args: [OBSERVED_ISSUANCE.subject] });
    log("before replay", `isValidAPass(subject) = ${before}`);
    if (before !== false) {
      stop(`the subject already holds a valid A-Pass at the parent block, so replaying the call`
        + " would demonstrate nothing.");
    }

    await test.impersonateAccount({ address: OBSERVED_ISSUER });
    await test.setBalance({ address: OBSERVED_ISSUER, value: 10n ** 19n });
    const wallet = createWalletClient({ account: OBSERVED_ISSUER, transport });

    // Sent as opaque bytes: no ABI, no function name, exactly what was recorded.
    const hash = await wallet.sendTransaction({
      to: APASS_REGISTRY, data: OBSERVED_ISSUANCE.calldata, value: 0n, chain: null, gas: 2_000_000n });
    const receipt = await client.waitForTransactionReceipt({ hash });
    log("replay", `${hash}, status ${receipt.status}, ${receipt.logs.length} logs`);

    const after = await client.readContract({
      address: APASS_REGISTRY, abi: APASS_ABI, functionName: "isValidAPass",
      args: [OBSERVED_ISSUANCE.subject] });
    log("after replay", `isValidAPass(subject) = ${after}`);

    const proven = receipt.status === "success" && before === false && after === true;
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      control: "A",
      classification: proven
        ? "OBSERVED APASS ISSUANCE CALL — EXACT REPLAY: PROVEN"
        : "OBSERVED APASS ISSUANCE CALL — EXACT REPLAY: NOT PROVEN",
      scope: "Local fork only. No public transaction, no Cleanverse endpoint, no anvil_setStorageAt.",
      hygiene: { writeRpc: FORK_RPC, loopback: true, upstreamSeparate: true,
        clientVersion, chainId, forkBlock: head.toString(), forkBlockHash: block.hash },
      observedCall: {
        sourceTransaction: OBSERVED_ISSUANCE.txHash,
        issuer: OBSERVED_ISSUER, registry: APASS_REGISTRY,
        selector: OBSERVED_ISSUANCE.selector,
        selectorNaming: "observed issuance call selector. Cleanverse publishes no ABI for it and"
          + " none is claimed here.",
        calldata: OBSERVED_ISSUANCE.calldata,
        calldataHash: keccak256(OBSERVED_ISSUANCE.calldata),
        calldataBytes: (OBSERVED_ISSUANCE.calldata.length - 2) / 2,
      },
      replay: { hash, status: receipt.status, gasUsed: receipt.gasUsed.toString(),
        logCount: receipt.logs.length,
        logs: receipt.logs.map((entry) => ({ address: entry.address, topic0: entry.topics[0],
          topicCount: entry.topics.length })) },
      readback: { subject: OBSERVED_ISSUANCE.subject, isValidAPassBefore: before, isValidAPassAfter: after },
      proven,
    };
    if (out) writeArtifact(out, report, process.env);
    return report;
  } finally {
    stopFork();
  }
}

const invokedDirectly = process.argv[1]?.endsWith("m13-control-a.mjs");
if (invokedDirectly) {
  const argv = process.argv.slice(2);
  const outIndex = argv.indexOf("--out");
  const out = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  process.stdout.write("M-13 control A: exact replay of the observed issuance call\n\n");
  runControlA({ out, log: (label, detail) => process.stdout.write(`  ${label.padEnd(16)} ${detail}\n`) })
    .then((report) => {
      process.stdout.write(`\n${"CLASSIFICATION".padEnd(16)} ${report.classification}\n`);
      if (out) process.stdout.write(`\nWrote ${out}.json\n`);
      if (!report.proven) process.exitCode = 1;
    })
    .catch((error) => {
      process.stderr.write(`\n${error instanceof ControlError ? error.message : `STOP — ${error.message}`}\n`);
      process.exitCode = 1;
    });
}
