#!/usr/bin/env node
/**
 * Consumes one verified direct-participant governed release on its case-specific
 * Adapter V2.
 *
 * Every authorization decision belongs to the server-side executor: it verifies
 * the bridge evidence, reconciles the adapter, builds the payload, simulates,
 * and only then releases exactly one signature from a fresh simulation permit.
 * This script supplies no holder, no payout, no digest and no Boolean; it
 * broadcasts the already-authorized transaction and reconciles the receipt.
 *
 *   node scripts/activation-bridge-consume.mjs --run <runId> [--out <path>]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, createWalletClient, getAddress, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function argument(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

function required(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${name} is required`);
  return value.trim();
}

async function main() {
  const runId = argument("--run") ?? required("MORDANT_ACTIVATION_RUN_ID");
  const outPath = argument("--out");
  const runRoot = argument("--run-root", join(ROOT, ".mordant", "worker", "runs"));

  const executorModule = await import("../.product-test-dist/src/lib/protection/bridge-executor.js");
  // Read only to report the evidence digest. The executor is NOT given it: the
  // artifact and its source commit are trust anchors, so it loads the evidence
  // from the durable run root itself and takes the commit from the server pin.
  const evidence = JSON.parse(readFileSync(
    join(runRoot, runId, "direct-participant-bridge-evidence.json"), "utf8",
  ));

  const configuration = executorModule.readBridgeConfiguration(process.env);
  const reader = executorModule.createAdapterReader(configuration);
  const executor = executorModule.createBridgeExecutor({ configuration, reader, runRoot });

  const issuedAt = Math.floor(Date.now() / 1_000) - 60;
  const expiry = issuedAt + 3_600;
  const prepared = await executor.prepareDirect({ runId, nonce: 1n, issuedAt, expiry });
  process.stdout.write(
    `prepared adapter=${prepared.adapter.address} signer=${prepared.signerAddress}\n`
    + `  typedDataDigest ${prepared.typedDataDigest}\n`
    + `  structHash      ${prepared.structHash}\n`
    + `  intentDigest    ${prepared.intentDigest}\n`
    + `  conflict        ${prepared.payload.message.conflict}\n`
    + `  holderA/payoutA ${prepared.payload.message.holderA} / ${prepared.payload.message.payoutA}\n`
    + `  holderB/payoutB ${prepared.payload.message.holderB} / ${prepared.payload.message.payoutB}\n`,
  );

  const simulated = await executor.simulate(prepared);
  process.stdout.write(`simulated ok at ${simulated.simulatedAtUnix}\n`);
  const signed = await executor.sign(simulated);
  process.stdout.write(`signed (newly=${signed.newlySigned}) record ${signed.record.intentDigest}\n`);

  // Broadcast. The attestor signs; any account may relay, so the funded owner
  // pays gas. Exactly one send, then reconcile before considering anything else.
  const publicClient = createPublicClient({ transport: http(configuration.rpcUrl) });
  const relayer = privateKeyToAccount(required("MORDANT_KEY_HOLDER_A"));
  const wallet = createWalletClient({ account: relayer, transport: http(configuration.rpcUrl) });

  const { request } = await publicClient.simulateContract({
    address: configuration.adapterAddress,
    abi: executorModule.ADAPTER_ABI,
    functionName: "consumeGovernedRelease",
    args: [executorModule.releaseTuple(signed.prepared.payload), signed.signature],
    account: relayer,
    chain: null,
  });
  const hash = await wallet.writeContract({ ...request, chain: null });
  process.stdout.write(`broadcast once: ${hash}\n`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 300_000 });
  const reconciled = executor.reconcileReceipt(signed, receipt);
  if (reconciled.status !== "success") throw new Error(`the release reverted: ${hash}`);

  const block = await publicClient.getBlock({ blockNumber: receipt.blockNumber });
  const caseState = await publicClient.readContract({
    address: configuration.adapterAddress,
    abi: [{ type: "function", name: "caseOf", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{
      type: "tuple",
      components: [
        { name: "state", type: "uint8" }, { name: "paidA", type: "bool" }, { name: "paidB", type: "bool" },
        { name: "cureDeadline", type: "uint64" },
        { name: "holderA", type: "address" }, { name: "holderB", type: "address" },
        { name: "payoutA", type: "uint256" }, { name: "payoutB", type: "uint256" },
      ],
    }] }],
    functionName: "caseOf",
    args: [signed.prepared.payload.message.runId],
  });

  const report = {
    schemaVersion: "mordant.activation-release-consumed/1",
    runId,
    adapter: configuration.adapterAddress,
    bridgeEvidenceDigest: evidence.evidenceDigest,
    governedResultDigest: reconciled.governedResultDigest,
    bridgeRunId: reconciled.runId,
    signedConflict: reconciled.conflict,
    signerAddress: signed.prepared.signerAddress,
    typedDataDigest: signed.record.typedDataDigest,
    structHash: signed.record.structHash,
    intentDigest: signed.record.intentDigest,
    nonce: "1",
    issuedAt,
    expiry,
    transactionHash: hash,
    blockNumber: Number(receipt.blockNumber),
    blockTimestamp: Number(block.timestamp),
    gasUsed: receipt.gasUsed.toString(),
    releaseConsumed: true,
    caseState: {
      holderA: getAddress(caseState.holderA),
      holderB: getAddress(caseState.holderB),
      payoutA: caseState.payoutA.toString(),
      payoutB: caseState.payoutB.toString(),
      cureDeadlineUnix: Number(caseState.cureDeadline),
      cureDeadlineIso: new Date(Number(caseState.cureDeadline) * 1_000).toISOString(),
      state: Number(caseState.state),
      stateName: ["None", "CureOpen", "Cured", "Entitled", "Claimed"][Number(caseState.state)] ?? "unknown",
      cureWindowSeconds: Number(caseState.cureDeadline) - Number(block.timestamp),
    },
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`activation-bridge-consume: ${error.message}\n`);
  process.exitCode = 1;
});
