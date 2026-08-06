#!/usr/bin/env node
/**
 * Terminal recourse for a consumed direct-participant release.
 *
 * The conflict is deliberately NOT cured: the real cure window is allowed to
 * expire, then anyone may finalize. `finalize` and `claim` are both
 * permissionless by design, and `claim` takes no recipient: the adapter pays the
 * holder recorded in the signed case, so this script cannot redirect a payout.
 *
 *   node scripts/activation-terminal-recourse.mjs --release <report.json> [--out <path>]
 */
import { readFileSync, writeFileSync } from "node:fs";

import { createPublicClient, createWalletClient, getAddress, http, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ADAPTER_ABI = parseAbi([
  "function finalize(bytes32 runId)",
  "function claim(bytes32 runId, bool holderIsA)",
  "function availableReserve() view returns (uint256)",
  "function openReserved() view returns (uint256)",
  "function entitledUnpaid() view returns (uint256)",
  "function solvent() view returns (bool)",
  "function settlementToken() view returns (address)",
  "event EntitlementOpened(bytes32 indexed runId, uint256 amount)",
  "event Claimed(bytes32 indexed runId, address indexed holder, uint256 amount)",
]);
const CASE_ABI = [{
  type: "function", name: "caseOf", stateMutability: "view", inputs: [{ type: "bytes32" }],
  outputs: [{
    type: "tuple",
    components: [
      { name: "state", type: "uint8" }, { name: "paidA", type: "bool" }, { name: "paidB", type: "bool" },
      { name: "cureDeadline", type: "uint64" },
      { name: "holderA", type: "address" }, { name: "holderB", type: "address" },
      { name: "payoutA", type: "uint256" }, { name: "payoutB", type: "uint256" },
    ],
  }],
}];
const ERC20_ABI = parseAbi(["function balanceOf(address) view returns (uint256)"]);
const MINV01 = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const STATE_NAMES = ["None", "CureOpen", "Cured", "Entitled", "Claimed"];

let chain = Promise.resolve();
function paced(operation) {
  const scheduled = chain.then(async () => {
    await new Promise((resolve) => setTimeout(resolve, 90));
    return operation();
  });
  chain = scheduled.then(() => undefined, () => undefined);
  return scheduled;
}

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
  const release = JSON.parse(readFileSync(argument("--release"), "utf8"));
  const outPath = argument("--out");
  const address = getAddress(release.adapter);
  const runId = release.bridgeRunId;

  const rpcUrl = required("MORDANT_MONAD_RPC_URL");
  const publicClient = createPublicClient({ transport: http(rpcUrl) });
  // Permissionless caller. It is neither holder, facility nor owner of the case.
  const caller = privateKeyToAccount(required("MORDANT_KEY_HOLDER_A"));
  const wallet = createWalletClient({ account: caller, transport: http(rpcUrl) });

  const token = getAddress(await paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName: "settlementToken" })));
  const caseBefore = await paced(() => publicClient.readContract({ address, abi: CASE_ABI, functionName: "caseOf", args: [runId] }));
  const holderA = getAddress(caseBefore.holderA);
  const holderB = getAddress(caseBefore.holderB);

  const balance = (who) => paced(() => publicClient.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [who] }));
  const minv01Of = (who) => paced(() => publicClient.readContract({ address: MINV01, abi: ERC20_ABI, functionName: "balanceOf", args: [who] }));
  const before = {
    adapter: await balance(address),
    holderA: await balance(holderA),
    holderB: await balance(holderB),
    adapterMinv01: await minv01Of(address),
  };

  // The window must have genuinely expired against chain time, not wall clock.
  const head = await paced(() => publicClient.getBlock({ blockTag: "latest" }));
  if (Number(head.timestamp) <= Number(caseBefore.cureDeadline)) {
    throw new Error(`the cure window is still open: chain ${head.timestamp} <= deadline ${caseBefore.cureDeadline}`);
  }
  if (Number(caseBefore.state) !== 1) throw new Error(`case is ${STATE_NAMES[Number(caseBefore.state)]}, expected CureOpen`);

  const send = async (functionName, args) => {
    const { request } = await paced(() => publicClient.simulateContract({
      address, abi: ADAPTER_ABI, functionName, args, account: caller, chain: null,
    }));
    const hash = await wallet.writeContract({ ...request, chain: null });
    const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 300_000 });
    if (receipt.status !== "success") throw new Error(`${functionName} reverted: ${hash}`);
    return { hash, receipt };
  };

  const finalized = await send("finalize", [runId]);
  const entitlementLogs = finalized.receipt.logs.filter((log) => (
    getAddress(log.address).toLowerCase() === address.toLowerCase()
  ));
  const afterFinalize = await paced(() => publicClient.readContract({ address, abi: CASE_ABI, functionName: "caseOf", args: [runId] }));
  if (Number(afterFinalize.state) !== 3) throw new Error(`expected Entitled, got ${STATE_NAMES[Number(afterFinalize.state)]}`);
  const entitledUnpaidAfterFinalize = await paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName: "entitledUnpaid" }));

  const claimA = await send("claim", [runId, true]);
  const claimB = await send("claim", [runId, false]);

  const after = {
    adapter: await balance(address),
    holderA: await balance(holderA),
    holderB: await balance(holderB),
    adapterMinv01: await minv01Of(address),
  };
  const finalCase = await paced(() => publicClient.readContract({ address, abi: CASE_ABI, functionName: "caseOf", args: [runId] }));
  const [availableReserve, openReserved, entitledUnpaid, solvent] = [
    await paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName: "availableReserve" })),
    await paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName: "openReserved" })),
    await paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName: "entitledUnpaid" })),
    await paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName: "solvent" })),
  ];

  const payoutA = caseBefore.payoutA;
  const payoutB = caseBefore.payoutB;
  const reconciliation = {
    holderADelta: (after.holderA - before.holderA).toString(),
    holderBDelta: (after.holderB - before.holderB).toString(),
    adapterDelta: (after.adapter - before.adapter).toString(),
    expectedHolderADelta: payoutA.toString(),
    expectedHolderBDelta: payoutB.toString(),
    expectedAdapterDelta: (-(payoutA + payoutB)).toString(),
    exact: after.holderA - before.holderA === payoutA
      && after.holderB - before.holderB === payoutB
      && before.adapter - after.adapter === payoutA + payoutB,
  };
  if (!reconciliation.exact) throw new Error("aUSDC reconciliation is not exact");
  if (before.adapterMinv01 !== 0n || after.adapterMinv01 !== 0n) throw new Error("MINV01 was touched");

  const report = {
    schemaVersion: "mordant.activation-terminal-recourse/1",
    runId: release.runId,
    adapter: address,
    bridgeRunId: runId,
    settlementToken: token,
    cured: false,
    cureDeadlineUnix: Number(caseBefore.cureDeadline),
    finalizedAtChainTime: Number(head.timestamp),
    permissionlessCaller: caller.address,
    callerIsHolder: caller.address.toLowerCase() === holderA.toLowerCase()
      || caller.address.toLowerCase() === holderB.toLowerCase(),
    finalize: {
      transactionHash: finalized.hash,
      blockNumber: Number(finalized.receipt.blockNumber),
      adapterLogs: entitlementLogs.length,
      entitlementOpened: true,
      entitledUnpaidAfterFinalize: entitledUnpaidAfterFinalize.toString(),
      stateAfter: STATE_NAMES[Number(afterFinalize.state)],
    },
    claims: {
      holderA: { address: holderA, transactionHash: claimA.hash, blockNumber: Number(claimA.receipt.blockNumber), amount: payoutA.toString() },
      holderB: { address: holderB, transactionHash: claimB.hash, blockNumber: Number(claimB.receipt.blockNumber), amount: payoutB.toString() },
    },
    balances: {
      before: { adapter: before.adapter.toString(), holderA: before.holderA.toString(), holderB: before.holderB.toString() },
      after: { adapter: after.adapter.toString(), holderA: after.holderA.toString(), holderB: after.holderB.toString() },
    },
    reconciliation,
    terminal: {
      state: STATE_NAMES[Number(finalCase.state)],
      paidA: finalCase.paidA,
      paidB: finalCase.paidB,
      availableReserve: availableReserve.toString(),
      openReserved: openReserved.toString(),
      entitledUnpaid: entitledUnpaid.toString(),
      solvent,
      reservedLiabilityCleared: openReserved === 0n,
      unpaidEntitlementCleared: entitledUnpaid === 0n,
    },
    minv01: {
      address: MINV01,
      adapterBalanceBefore: before.adapterMinv01.toString(),
      adapterBalanceAfter: after.adapterMinv01.toString(),
      touched: false,
    },
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`activation-terminal-recourse: ${error.message}\n`);
  process.exitCode = 1;
});
