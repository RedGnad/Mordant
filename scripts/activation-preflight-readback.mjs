#!/usr/bin/env node
/**
 * Activation preflight: a read-only re-read of live Monad state for the deployed
 * Adapter V2, checked against the committed canonical evidence on this checkpoint.
 *
 * Every expected value is loaded from the committed artifacts, never from a literal
 * typed here and never from chat. The script writes nothing on chain, signs no
 * transaction, and never prints, serializes or returns a private key: the attestor
 * check derives a public address and compares it with the adapter's immutable.
 *
 *   node scripts/activation-preflight-readback.mjs [--out <path>]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, getAddress, http, keccak256, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const EVIDENCE = join(ROOT, "docs", "evidence");

const MONAD_TESTNET_CHAIN_ID = 10_143;

const ADAPTER_ABI = parseAbi([
  "function settlementToken() view returns (address)",
  "function cviVerifier() view returns (address)",
  "function attestor() view returns (address)",
  "function facility() view returns (address)",
  "function owner() view returns (address)",
  "function assetIdentityDigest() view returns (bytes32)",
  "function expectedGovernedReleaseAuthorityId() view returns (bytes32)",
  "function releaseMode() view returns (bytes32)",
  "function circuitHash() view returns (bytes32)",
  "function parameterFingerprint() view returns (bytes32)",
  "function cureWindow() view returns (uint64)",
  "function availableReserve() view returns (uint256)",
  "function openReserved() view returns (uint256)",
  "function entitledUnpaid() view returns (uint256)",
  "function solvent() view returns (bool)",
  "function domainSeparator() view returns (bytes32)",
  "function resultConsumed(bytes32) view returns (bool)",
  "function ROLE_HOLDER() view returns (uint8)",
  "function ROLE_FACILITY() view returns (uint8)",
]);
const CVI_ABI = parseAbi([
  "function isEligible(address,uint8) view returns (bool)",
  "function isAssetTransferAllowed(address,address,address,uint256) view returns (bool)",
]);
const ERC20_ABI = parseAbi(["function balanceOf(address) view returns (uint256)"]);

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** sha256:<hex> as carried by the governed result, to the bytes32 the adapter pins. */
function digestToBytes32(digest) {
  const [scheme, hex] = String(digest).split(":");
  if (scheme !== "sha256" || !/^[0-9a-f]{64}$/u.test(hex ?? "")) {
    throw new Error(`not a sha256 digest: ${digest}`);
  }
  return `0x${hex}`;
}

/**
 * The public Monad testnet RPC refuses more than 15 requests per second, so every
 * read goes through one bounded queue. Reads are idempotent; this paces them, it
 * never retries a state-changing call.
 */
const RPC_MIN_INTERVAL_MS = 90;
let rpcChain = Promise.resolve();
function paced(operation) {
  const scheduled = rpcChain.then(async () => {
    await new Promise((resolve) => setTimeout(resolve, RPC_MIN_INTERVAL_MS));
    return operation();
  });
  rpcChain = scheduled.then(() => undefined, () => undefined);
  return scheduled;
}

const checks = [];
function check(name, actual, expected, { compare = "exact" } = {}) {
  const normalize = (value) => (
    compare === "address" || compare === "hex" ? String(value).toLowerCase() : value
  );
  const ok = normalize(actual) === normalize(expected);
  checks.push({ name, actual: String(actual), expected: String(expected), ok });
  return ok;
}

async function main() {
  const outIndex = process.argv.indexOf("--out");
  const outPath = outIndex >= 0 ? process.argv[outIndex + 1] : null;

  const deployment = readJson(join(EVIDENCE, "recourse-adapter-v2-deployment-2026-08-06.json"));
  const config = readJson(join(EVIDENCE, "recourse-v2-demo-config-2026-08-06.json"));
  const handoff = readJson(join(EVIDENCE, "runtime-contract-handoff-2026-08-06.json"));

  const rpcUrl = process.env.MORDANT_MONAD_RPC_URL;
  if (typeof rpcUrl !== "string" || rpcUrl.trim() === "") {
    throw new Error("MORDANT_MONAD_RPC_URL is not configured");
  }
  const configuredAdapter = process.env.MORDANT_RECOURSE_ADAPTER_ADDRESS;
  if (typeof configuredAdapter !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(configuredAdapter)) {
    throw new Error("MORDANT_RECOURSE_ADAPTER_ADDRESS is not configured");
  }

  const address = getAddress(deployment.deployed.address);
  check("configured adapter == committed adapter", getAddress(configuredAdapter), address, { compare: "address" });

  const client = createPublicClient({ transport: http(rpcUrl.trim()) });
  const read = (functionName, args = []) => paced(() => client.readContract({ address, abi: ADAPTER_ABI, functionName, args }));

  const chainId = await paced(() => client.getChainId());
  check("chainId", chainId, MONAD_TESTNET_CHAIN_ID);

  const blockNumber = await paced(() => client.getBlockNumber());
  const code = await paced(() => client.getCode({ address }));
  if (code === undefined || code === "0x") throw new Error("the configured adapter has no runtime code");

  const [
    settlementToken, cviVerifier, attestor, facility, owner,
    assetIdentityDigest, expectedGovernedReleaseAuthorityId, releaseMode, circuitHash, parameterFingerprint,
    cureWindow, availableReserve, openReserved, entitledUnpaid, solvent, domainSeparator, roleHolder, roleFacility,
  ] = await Promise.all([
    read("settlementToken"), read("cviVerifier"), read("attestor"), read("facility"), read("owner"),
    read("assetIdentityDigest"), read("expectedGovernedReleaseAuthorityId"), read("releaseMode"),
    read("circuitHash"), read("parameterFingerprint"), read("cureWindow"),
    read("availableReserve"), read("openReserved"), read("entitledUnpaid"), read("solvent"),
    read("domainSeparator"), read("ROLE_HOLDER"), read("ROLE_FACILITY"),
  ]);

  const immutables = deployment.immutables;
  check("deployed code hash", keccak256(code), deployment.deployed.deployedCodeHash, { compare: "hex" });
  check("runtime bytes", (code.length - 2) / 2, deployment.deployed.runtimeBytes);
  check("settlementToken", getAddress(settlementToken), getAddress(immutables.settlementToken), { compare: "address" });
  check("cviVerifier", getAddress(cviVerifier), getAddress(immutables.cviVerifier), { compare: "address" });
  check("attestor immutable", getAddress(attestor), getAddress(immutables.attestor), { compare: "address" });
  check("facility immutable", getAddress(facility), getAddress(immutables.facility), { compare: "address" });
  check("owner immutable", getAddress(owner), getAddress(immutables.owner), { compare: "address" });
  check("assetIdentityDigest", assetIdentityDigest, immutables.assetIdentityDigest, { compare: "hex" });
  check("governed authority pin", expectedGovernedReleaseAuthorityId, immutables.expectedGovernedReleaseAuthorityId, { compare: "hex" });
  check("releaseMode", releaseMode, immutables.releaseMode, { compare: "hex" });
  check("circuitHash", circuitHash, immutables.circuitHash, { compare: "hex" });
  check("parameterFingerprint", parameterFingerprint, immutables.parameterFingerprint, { compare: "hex" });
  check("cureWindowSeconds", Number(cureWindow), immutables.cureWindowSeconds);
  check("domainSeparator", domainSeparator, handoff.encodingVector.expectedDigests.adapterDomainSeparator, { compare: "hex" });

  // The governed result the adapter's authority pin was derived from.
  const governedResultDigest = digestToBytes32(handoff.governedResult.governedResultDigest);
  const governedAuthorityId = digestToBytes32(handoff.governedResult.releaseAuthorityId);
  check("retained governed authority == on-chain pin", governedAuthorityId, expectedGovernedReleaseAuthorityId, { compare: "hex" });
  const retainedResultConsumed = await read("resultConsumed", [governedResultDigest]);
  checks.push({
    name: "retained governed result already consumed",
    actual: String(retainedResultConsumed), expected: "false", ok: retainedResultConsumed === false,
  });

  // Attestor key control: derivation only. The secret is never printed or returned.
  const attestorKey = process.env.MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY;
  let derivedSigner = null;
  if (typeof attestorKey === "string" && /^0x[0-9a-fA-F]{64}$/u.test(attestorKey.trim())) {
    derivedSigner = privateKeyToAccount(attestorKey.trim()).address;
    check("derived signer == adapter attestor immutable", derivedSigner, getAddress(attestor), { compare: "address" });
  } else {
    checks.push({ name: "derived signer == adapter attestor immutable", actual: "key not configured", expected: "equal", ok: false });
  }

  const verifier = getAddress(cviVerifier);
  const token = getAddress(settlementToken);
  const participants = config.participants;
  const holderA = getAddress(participants.holderA.address);
  const holderB = getAddress(participants.holderB.address);
  const negativeControl = getAddress(participants.negativeControl.address);
  const uncontrolled = getAddress(config.walletControl.supersededHolderA.address);
  const facilityAddress = getAddress(config.facility.address);
  const minv01 = getAddress(config.minv01.address);

  const eligible = (account, role) => paced(() => client.readContract({
    address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [account, role],
  }));
  const transferAllowed = (from, to, amount) => paced(() => client.readContract({
    address: verifier, abi: CVI_ABI, functionName: "isAssetTransferAllowed", args: [token, from, to, amount],
  }));
  const balanceOf = (asset, account) => paced(() => client.readContract({
    address: asset, abi: ERC20_ABI, functionName: "balanceOf", args: [account],
  }));

  const holderRole = Number(roleHolder);
  const facilityRole = Number(roleFacility);
  const payoutA = BigInt(config.settlement.payoutAAtomic);
  const payoutB = BigInt(config.settlement.payoutBAtomic);
  const payoutTotal = BigInt(config.settlement.totalAtomic);

  const [
    holderAEligible, holderBEligible, facilityEligible, negativeEligible, uncontrolledEligible,
    toHolderA, toHolderB, toNegative,
    adapterBalance, holderABalance, holderBBalance, adapterMinv01,
  ] = await Promise.all([
    eligible(holderA, holderRole), eligible(holderB, holderRole), eligible(facilityAddress, facilityRole),
    eligible(negativeControl, holderRole), eligible(uncontrolled, holderRole),
    transferAllowed(address, holderA, payoutA), transferAllowed(address, holderB, payoutB),
    transferAllowed(address, negativeControl, payoutB),
    balanceOf(token, address), balanceOf(token, holderA), balanceOf(token, holderB), balanceOf(minv01, address),
  ]);

  const gate = (name, actual, expected) => checks.push({ name, actual: String(actual), expected: String(expected), ok: actual === expected });
  gate("holderA ROLE_HOLDER eligible", holderAEligible, true);
  gate("holderB ROLE_HOLDER eligible", holderBEligible, true);
  gate("facility ROLE_FACILITY eligible", facilityEligible, true);
  gate("negative control excluded (not ROLE_HOLDER)", negativeEligible, false);
  gate("adapter -> holderA permitted", toHolderA, true);
  gate("adapter -> holderB permitted", toHolderB, true);
  gate("adapter -> negative control refused", toNegative, false);
  gate("adapter solvent", solvent, true);
  gate("openReserved is zero", openReserved, 0n);
  gate("entitledUnpaid is zero", entitledUnpaid, 0n);
  gate("availableReserve covers payout total", availableReserve >= payoutTotal, true);
  gate("MINV01 balance of adapter unchanged (0)", adapterMinv01, 0n);
  gate("holders distinct", holderA.toLowerCase() !== holderB.toLowerCase(), true);

  const report = {
    schemaVersion: "mordant.activation-preflight-readback/1",
    observedAtIso: new Date().toISOString(),
    network: { chainId, blockNumber: Number(blockNumber) },
    adapter: {
      address,
      codeHash: keccak256(code),
      runtimeBytes: (code.length - 2) / 2,
      settlementToken: getAddress(settlementToken),
      cviVerifier: verifier,
      attestor: getAddress(attestor),
      facility: getAddress(facility),
      owner: getAddress(owner),
      assetIdentityDigest,
      expectedGovernedReleaseAuthorityId,
      releaseMode,
      circuitHash,
      parameterFingerprint,
      cureWindowSeconds: Number(cureWindow),
      domainSeparator,
      roleHolder: holderRole,
      roleFacility: facilityRole,
    },
    reserve: {
      availableReserve: availableReserve.toString(),
      openReserved: openReserved.toString(),
      entitledUnpaid: entitledUnpaid.toString(),
      tokenBalance: adapterBalance.toString(),
      solvent,
      payoutA: payoutA.toString(),
      payoutB: payoutB.toString(),
      payoutTotal: payoutTotal.toString(),
    },
    participants: {
      holderA: { address: holderA, roleHolderEligible: holderAEligible, aUsdcBalance: holderABalance.toString() },
      holderB: { address: holderB, roleHolderEligible: holderBEligible, aUsdcBalance: holderBBalance.toString() },
      facility: { address: facilityAddress, roleFacilityEligible: facilityEligible },
      negativeControl: { address: negativeControl, roleHolderEligible: negativeEligible, adapterTransferPermitted: toNegative },
      uncontrolledApassWallet: { address: uncontrolled, roleHolderEligible: uncontrolledEligible, canonicalParticipant: false },
    },
    minv01: { address: minv01, adapterBalance: adapterMinv01.toString(), touched: adapterMinv01 !== 0n },
    retainedGovernedResult: {
      runId: handoff.governedResult.runId,
      governedResultDigest,
      releaseAuthorityId: governedAuthorityId,
      conflict: handoff.governedResult.conflict,
      consumed: retainedResultConsumed,
    },
    bridgeAttestor: {
      runtimeVariableName: "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY",
      derivedSignerAddress: derivedSigner,
      deployedAttestorAddress: getAddress(attestor),
      equality: derivedSigner !== null && derivedSigner.toLowerCase() === getAddress(attestor).toLowerCase(),
      note: "Derivation only. The private key is never printed, serialized, returned or written.",
    },
    checks,
    allChecksPass: checks.every((entry) => entry.ok),
  };

  const width = Math.max(...checks.map((entry) => entry.name.length));
  for (const entry of checks) {
    process.stdout.write(`${entry.ok ? "ok  " : "FAIL"} ${entry.name.padEnd(width)}  ${entry.actual}\n`);
  }
  process.stdout.write(`\nblock ${blockNumber}  checks ${checks.filter((e) => e.ok).length}/${checks.length}\n`);
  if (outPath) {
    writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(`wrote ${outPath}\n`);
  }
  if (!report.allChecksPass) process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`activation-preflight-readback: ${error.message}\n`);
  process.exitCode = 1;
});
