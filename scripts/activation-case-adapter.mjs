#!/usr/bin/env node
/**
 * Case-specific Adapter V2 for a qualified direct-participant run.
 *
 * The governed release authority is minted per FHE case, and Adapter V2 pins it
 * as an immutable, so a fresh run needs its own deployment of the SAME reviewed
 * contract. Nothing about the contract changes: only the constructor pins do,
 * and every run-specific pin is derived from the VERIFIED bridge evidence, never
 * typed here.
 *
 * Modes, each explicit and separately invoked:
 *   --plan       read-only: masked-bytecode proof, derived pins, funding plan
 *   --withdraw   controlled reserve withdrawal from a superseded adapter
 *   --deploy     deploy the case-specific adapter
 *   --configure  A-Pass, policy readbacks and reserve funding
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient, createWalletClient, encodeAbiParameters, getAddress, http, keccak256, parseAbi,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ARTIFACT = join(ROOT, "contracts", "out", "MordantRecourseAdapter.sol", "MordantRecourseAdapter.json");
const DEPLOYMENT = join(ROOT, "docs", "evidence", "recourse-adapter-v2-deployment-2026-08-06.json");
const CONFIG = join(ROOT, "docs", "evidence", "recourse-v2-demo-config-2026-08-06.json");

const CHAIN_ID = 10_143;
const RPC_MIN_INTERVAL_MS = 90;

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
  "function fundReserve(uint256 amount)",
  "function withdrawAvailable(address to, uint256 amount)",
]);
const ERC20_ABI = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function approve(address spender, uint256 value) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
]);
const CVI_ABI = parseAbi([
  "function isEligible(address,uint8) view returns (bool)",
  "function isAssetTransferAllowed(address,address,address,uint256) view returns (bool)",
  "function isValidAPass(address) view returns (bool)",
]);

let chain = Promise.resolve();
function paced(operation) {
  const scheduled = chain.then(async () => {
    await new Promise((resolve) => setTimeout(resolve, RPC_MIN_INTERVAL_MS));
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

function digestToBytes32(digest) {
  const [scheme, hex] = String(digest).split(":");
  if (scheme !== "sha256" || !/^[0-9a-f]{64}$/u.test(hex ?? "")) throw new Error(`not a sha256 digest: ${digest}`);
  return `0x${hex}`;
}

/**
 * Hashes the runtime bytecode with every immutable span zeroed.
 *
 * Immutables are written INTO the runtime code, so two deployments of the same
 * source differ exactly at those spans. Masking them is what makes "the same
 * reviewed contract" a checkable claim across deployments.
 */
function maskedRuntimeHash(hexCode, immutableReferences) {
  const bytes = Buffer.from(hexCode.replace(/^0x/u, ""), "hex");
  let spans = 0;
  for (const references of Object.values(immutableReferences ?? {})) {
    for (const { start, length } of references) {
      bytes.fill(0, start, start + length);
      spans += 1;
    }
  }
  return { hash: keccak256(`0x${bytes.toString("hex")}`), spans, bytes: bytes.length };
}

async function loadVerifiedEvidence(runId) {
  const runRoot = argument("--run-root", join(ROOT, ".mordant", "worker", "runs"));
  const evidence = JSON.parse(readFileSync(join(runRoot, runId, "direct-participant-bridge-evidence.json"), "utf8"));
  const bridgeEvidence = await import("../.product-test-dist/src/lib/protection/direct-participant-bridge-evidence.js");
  const compatibility = await import("../.product-test-dist/src/lib/protection/adapter-compatibility.js");
  const asset = await import("../.product-test-dist/src/lib/protection/cleanverse-asset.js");
  const configuration = compatibility.loadCanonicalRecourseConfiguration(ROOT);
  const verified = bridgeEvidence.assertDirectParticipantBridgeEvidence(evidence, {
    sourceCommit: evidence.sourceCommit,
    assetIdentity: asset.CANONICAL_CLEANVERSE_ASSET_DIGEST,
    holderA: configuration.participants.holderA,
    holderB: configuration.participants.holderB,
    excludedWallets: Object.values(configuration.participants.excluded),
    runId,
  });
  return { evidence, verified, configuration };
}

function client() {
  return createPublicClient({ transport: http(required("MORDANT_MONAD_RPC_URL")) });
}

function ownerAccount() {
  // The deployer/owner of the reviewed deployment. Its key name is read here and
  // its value is never printed, serialized or written.
  return privateKeyToAccount(required("MORDANT_KEY_HOLDER_A"));
}

async function plan() {
  const runId = required("MORDANT_ACTIVATION_RUN_ID");
  const { evidence, verified, configuration } = await loadVerifiedEvidence(runId);

  execFileSync("forge", ["build", "--root", "contracts"], { cwd: ROOT, stdio: "inherit" });
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8"));
  const deployment = JSON.parse(readFileSync(DEPLOYMENT, "utf8"));
  const config = JSON.parse(readFileSync(CONFIG, "utf8"));

  const masked = maskedRuntimeHash(
    artifact.deployedBytecode.object,
    artifact.deployedBytecode.immutableReferences,
  );
  const reviewedMasked = deployment.deployed.artifactMaskedHash;
  const matchesReviewed = masked.hash.toLowerCase() === reviewedMasked.toLowerCase();

  const result = verified.governedResult;
  const pins = {
    settlementToken: getAddress(deployment.immutables.settlementToken),
    cviVerifier: getAddress(deployment.immutables.cviVerifier),
    attestor: getAddress(deployment.immutables.attestor),
    facility: getAddress(deployment.immutables.facility),
    owner: getAddress(deployment.immutables.owner),
    // Run-specific: every one derived from the verified signed governed result.
    assetIdentityDigest: digestToBytes32(result.assetIdentity),
    expectedGovernedReleaseAuthorityId: digestToBytes32(result.releaseAuthorityId),
    releaseMode: keccak256(Buffer.from(result.releaseMode, "utf8")),
    circuitHash: digestToBytes32(result.circuitDigest),
    parameterFingerprint: digestToBytes32(result.parameterFingerprint),
    cureWindow: deployment.immutables.cureWindowSeconds,
  };
  // The release-mode label convention is unchanged from the reviewed deployment.
  if (pins.releaseMode.toLowerCase() !== deployment.immutables.releaseMode.toLowerCase()) {
    throw new Error("release mode pin diverged from the reviewed deployment convention");
  }

  const constructorArgs = encodeAbiParameters(
    [
      { type: "address" }, { type: "address" }, { type: "address" }, { type: "address" }, { type: "address" },
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" },
      { type: "uint64" },
    ],
    [
      pins.settlementToken, pins.cviVerifier, pins.attestor, pins.facility, pins.owner,
      pins.assetIdentityDigest, pins.expectedGovernedReleaseAuthorityId, pins.releaseMode,
      pins.circuitHash, pins.parameterFingerprint, BigInt(pins.cureWindow),
    ],
  );

  const publicClient = client();
  const owner = ownerAccount();
  const token = pins.settlementToken;
  const superseded = getAddress(deployment.deployed.address);
  const payoutTotal = BigInt(config.settlement.totalAtomic);

  const [ownerBalance, supersededAvailable, supersededOpen, supersededEntitled, supersededOwner, ownerMon] =
    await Promise.all([
      paced(() => publicClient.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [owner.address] })),
      paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "availableReserve" })),
      paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "openReserved" })),
      paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "entitledUnpaid" })),
      paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "owner" })),
      paced(() => publicClient.getBalance({ address: owner.address })),
    ]);

  const shortfall = payoutTotal > ownerBalance ? payoutTotal - ownerBalance : 0n;
  const report = {
    schemaVersion: "mordant.activation-case-adapter-plan/1",
    generatedAt: new Date().toISOString(),
    runId,
    sourceCommit: evidence.sourceCommit,
    reviewedBytecode: {
      artifactMaskedHash: masked.hash,
      reviewedArtifactMaskedHash: reviewedMasked,
      immutableSpansMasked: masked.spans,
      runtimeBytes: masked.bytes,
      reviewedRuntimeBytes: deployment.deployed.runtimeBytes,
      matchesReviewedArtifact: matchesReviewed,
    },
    pins,
    constructorArgs,
    funding: {
      payoutTotal: payoutTotal.toString(),
      ownerAddress: owner.address,
      ownerSettlementBalance: ownerBalance.toString(),
      ownerMonWei: ownerMon.toString(),
      shortfall: shortfall.toString(),
      withdrawalRequired: shortfall > 0n,
      supersededAdapter: {
        address: superseded,
        owner: getAddress(supersededOwner),
        ownerControlsIt: getAddress(supersededOwner).toLowerCase() === owner.address.toLowerCase(),
        availableReserve: supersededAvailable.toString(),
        openReserved: supersededOpen.toString(),
        entitledUnpaid: supersededEntitled.toString(),
        liabilitiesZero: supersededOpen === 0n && supersededEntitled === 0n,
        withdrawable: supersededAvailable >= shortfall,
      },
    },
  };
  if (!matchesReviewed) throw new Error("the built artifact is not the reviewed Adapter V2 bytecode");
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const outPath = argument("--out");
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

async function withdraw() {
  const amount = BigInt(required("MORDANT_ACTIVATION_WITHDRAW_ATOMIC"));
  const deployment = JSON.parse(readFileSync(DEPLOYMENT, "utf8"));
  const superseded = getAddress(deployment.deployed.address);
  const publicClient = client();
  const owner = ownerAccount();
  const wallet = createWalletClient({ account: owner, transport: http(required("MORDANT_MONAD_RPC_URL")) });
  const token = getAddress(deployment.immutables.settlementToken);

  const [open, entitled, available] = await Promise.all([
    paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "openReserved" })),
    paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "entitledUnpaid" })),
    paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "availableReserve" })),
  ]);
  if (open !== 0n) throw new Error(`refusing: openReserved is ${open}`);
  if (entitled !== 0n) throw new Error(`refusing: entitledUnpaid is ${entitled}`);
  if (available < amount) throw new Error(`refusing: availableReserve ${available} < ${amount}`);

  const before = await paced(() => publicClient.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [owner.address] }));
  const { request } = await paced(() => publicClient.simulateContract({
    address: superseded, abi: ADAPTER_ABI, functionName: "withdrawAvailable",
    args: [owner.address, amount], account: owner, chain: null,
  }));
  process.stdout.write("simulation ok; broadcasting exactly once\n");
  const hash = await wallet.writeContract({ ...request, chain: null });
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 180_000 });
  const [after, availableAfter] = await Promise.all([
    paced(() => publicClient.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [owner.address] })),
    paced(() => publicClient.readContract({ address: superseded, abi: ADAPTER_ABI, functionName: "availableReserve" })),
  ]);
  const report = {
    schemaVersion: "mordant.activation-reserve-withdrawal/1",
    supersededAdapter: superseded,
    to: owner.address,
    amount: amount.toString(),
    transactionHash: hash,
    blockNumber: Number(receipt.blockNumber),
    status: receipt.status,
    ownerBalanceBefore: before.toString(),
    ownerBalanceAfter: after.toString(),
    ownerDelta: (after - before).toString(),
    supersededAvailableBefore: available.toString(),
    supersededAvailableAfter: availableAfter.toString(),
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const outPath = argument("--out");
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
}

async function deploy() {
  const planned = JSON.parse(readFileSync(required("MORDANT_ACTIVATION_PLAN"), "utf8"));
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8"));
  const publicClient = client();
  const owner = ownerAccount();
  const wallet = createWalletClient({ account: owner, transport: http(required("MORDANT_MONAD_RPC_URL")) });

  const chainId = await paced(() => publicClient.getChainId());
  if (chainId !== CHAIN_ID) throw new Error(`refusing: chain ${chainId}`);

  const hash = await wallet.deployContract({
    abi: artifact.abi,
    bytecode: artifact.bytecode.object,
    args: [
      planned.pins.settlementToken, planned.pins.cviVerifier, planned.pins.attestor,
      planned.pins.facility, planned.pins.owner, planned.pins.assetIdentityDigest,
      planned.pins.expectedGovernedReleaseAuthorityId, planned.pins.releaseMode,
      planned.pins.circuitHash, planned.pins.parameterFingerprint, BigInt(planned.pins.cureWindow),
    ],
    chain: null,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 300_000 });
  if (receipt.status !== "success" || receipt.contractAddress == null) {
    throw new Error(`deployment failed: ${receipt.status}`);
  }
  const address = getAddress(receipt.contractAddress);
  const code = await paced(() => publicClient.getCode({ address }));
  const deployedMasked = maskedRuntimeHash(code, artifact.deployedBytecode.immutableReferences);

  const read = (functionName) => paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName }));
  const immutables = {
    settlementToken: getAddress(await read("settlementToken")),
    cviVerifier: getAddress(await read("cviVerifier")),
    attestor: getAddress(await read("attestor")),
    facility: getAddress(await read("facility")),
    owner: getAddress(await read("owner")),
    assetIdentityDigest: await read("assetIdentityDigest"),
    expectedGovernedReleaseAuthorityId: await read("expectedGovernedReleaseAuthorityId"),
    releaseMode: await read("releaseMode"),
    circuitHash: await read("circuitHash"),
    parameterFingerprint: await read("parameterFingerprint"),
    cureWindow: Number(await read("cureWindow")),
  };
  const mismatches = Object.entries(planned.pins).filter(([key, expected]) => (
    String(immutables[key]).toLowerCase() !== String(expected).toLowerCase()
  )).map(([key]) => key);
  if (mismatches.length > 0) throw new Error(`deployed immutables differ: ${mismatches.join(", ")}`);

  const report = {
    schemaVersion: "mordant.activation-case-adapter-deployment/1",
    runId: planned.runId,
    address,
    transactionHash: hash,
    blockNumber: Number(receipt.blockNumber),
    runtimeBytes: (code.length - 2) / 2,
    deployedCodeHash: keccak256(code),
    deployedMaskedHash: deployedMasked.hash,
    artifactMaskedHash: planned.reviewedBytecode.artifactMaskedHash,
    maskedMatchesReviewedArtifact: deployedMasked.hash.toLowerCase() === planned.reviewedBytecode.artifactMaskedHash.toLowerCase(),
    immutableSpansMasked: deployedMasked.spans,
    immutables,
    immutablesMatchPlan: true,
  };
  if (!report.maskedMatchesReviewedArtifact) throw new Error("deployed masked bytecode is not the reviewed artifact");
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const outPath = argument("--out");
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
}

async function configure() {
  const deployed = JSON.parse(readFileSync(required("MORDANT_ACTIVATION_DEPLOYMENT"), "utf8"));
  const config = JSON.parse(readFileSync(CONFIG, "utf8"));
  const address = getAddress(deployed.address);
  const publicClient = client();
  const owner = ownerAccount();
  const wallet = createWalletClient({ account: owner, transport: http(required("MORDANT_MONAD_RPC_URL")) });
  const token = getAddress(deployed.immutables.settlementToken);
  const verifier = getAddress(deployed.immutables.cviVerifier);
  const holderA = getAddress(config.participants.holderA.address);
  const holderB = getAddress(config.participants.holderB.address);
  const payoutA = BigInt(config.settlement.payoutAAtomic);
  const payoutB = BigInt(config.settlement.payoutBAtomic);
  const total = payoutA + payoutB;

  const registry = getAddress(config.contracts.apassRegistry);
  const apassValid = await paced(() => publicClient.readContract({
    address: registry, abi: CVI_ABI, functionName: "isValidAPass", args: [address],
  }));
  if (!apassValid) throw new Error("the case-specific adapter has no valid A-Pass yet");

  const gates = {
    adapterApass: apassValid,
    holderAEligible: await paced(() => publicClient.readContract({ address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [holderA, 4] })),
    holderBEligible: await paced(() => publicClient.readContract({ address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [holderB, 4] })),
    facilityEligible: await paced(() => publicClient.readContract({ address: verifier, abi: CVI_ABI, functionName: "isEligible", args: [getAddress(deployed.immutables.facility), 3] })),
    funderToAdapter: await paced(() => publicClient.readContract({ address: verifier, abi: CVI_ABI, functionName: "isAssetTransferAllowed", args: [token, owner.address, address, total] })),
    adapterToHolderA: await paced(() => publicClient.readContract({ address: verifier, abi: CVI_ABI, functionName: "isAssetTransferAllowed", args: [token, address, holderA, payoutA] })),
    adapterToHolderB: await paced(() => publicClient.readContract({ address: verifier, abi: CVI_ABI, functionName: "isAssetTransferAllowed", args: [token, address, holderB, payoutB] })),
  };
  for (const [name, ok] of Object.entries(gates)) if (!ok) throw new Error(`gate failed: ${name}`);

  const approveHash = await wallet.writeContract({
    address: token, abi: ERC20_ABI, functionName: "approve", args: [address, total], chain: null,
  });
  await publicClient.waitForTransactionReceipt({ hash: approveHash, timeout: 180_000 });
  const { request } = await paced(() => publicClient.simulateContract({
    address, abi: ADAPTER_ABI, functionName: "fundReserve", args: [total], account: owner, chain: null,
  }));
  const fundHash = await wallet.writeContract({ ...request, chain: null });
  const fundReceipt = await publicClient.waitForTransactionReceipt({ hash: fundHash, timeout: 180_000 });

  const read = (functionName) => paced(() => publicClient.readContract({ address, abi: ADAPTER_ABI, functionName }));
  const report = {
    schemaVersion: "mordant.activation-case-adapter-configuration/1",
    address,
    gates,
    approveTx: approveHash,
    fundTx: fundHash,
    fundBlock: Number(fundReceipt.blockNumber),
    availableReserve: (await read("availableReserve")).toString(),
    openReserved: (await read("openReserved")).toString(),
    entitledUnpaid: (await read("entitledUnpaid")).toString(),
    tokenBalance: (await paced(() => publicClient.readContract({ address: token, abi: ERC20_ABI, functionName: "balanceOf", args: [address] }))).toString(),
    solvent: await read("solvent"),
    payoutTotal: total.toString(),
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const outPath = argument("--out");
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
}

/**
 * Requests a real A-Pass for the deployed adapter, through the same encrypted
 * Cleanverse route the reviewed deployment used. The API key is used to encrypt
 * one body and is never printed or stored.
 */
async function apass() {
  const deployed = JSON.parse(readFileSync(required("MORDANT_ACTIVATION_DEPLOYMENT"), "utf8"));
  const address = getAddress(deployed.address);
  // isValidAPass lives on the Cleanverse A-Pass registry, not on the CVI verifier.
  const registry = getAddress(JSON.parse(readFileSync(CONFIG, "utf8")).contracts.apassRegistry);
  const publicClient = client();

  const already = await paced(() => publicClient.readContract({
    address: registry, abi: CVI_ABI, functionName: "isValidAPass", args: [address],
  }));
  if (already) {
    process.stdout.write(`${JSON.stringify({ address, alreadyValid: true }, null, 2)}\n`);
    return;
  }

  const { createCipheriv, randomUUID } = await import("node:crypto");
  const base = required("CLEANVERSE_API_BASE_URL").replace(/\/+$/u, "");
  const key = Buffer.from(required("CLEANVERSE_API_KEY"), "base64");
  const customerId = `mordantcase${address.slice(2, 14)}`.replace(/[^A-Za-z0-9]/gu, "").slice(0, 40);
  const expirationTime = Math.floor(Date.now() / 1_000) + 365 * 24 * 3_600;
  const payload = { customerId, expirationTime, wallet: { chain: "monad", address } };
  const cipher = createCipheriv(`aes-${key.byteLength * 8}-cbc`, key, Buffer.alloc(16, 0));
  cipher.setAutoPadding(true);
  const body = {
    data: Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload), "utf8")), cipher.final()]).toString("base64"),
  };
  const response = await fetch(`${base}/generate_apass`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "api-id": required("CLEANVERSE_API_ID"),
      "X-Request-ID": randomUUID(),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const result = await response.json();

  let valid = false;
  for (let attempt = 0; attempt < 20 && !valid; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 6_000));
    valid = await paced(() => publicClient.readContract({
      address: registry, abi: CVI_ABI, functionName: "isValidAPass", args: [address],
    }));
  }
  const report = {
    schemaVersion: "mordant.activation-case-adapter-apass/1",
    address,
    customerId,
    expirationTimeRequested: expirationTime,
    envelopeCode: result?.code ?? null,
    message: String(result?.message ?? "").slice(0, 200),
    isValidAPassOnChain: valid,
    observedAtBlock: Number(await paced(() => publicClient.getBlockNumber())),
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const outPath = argument("--out");
  if (outPath) writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
  if (!valid) throw new Error("the adapter A-Pass did not become valid on chain");
}

const modes = { "--plan": plan, "--withdraw": withdraw, "--deploy": deploy, "--apass": apass, "--configure": configure };
const mode = Object.keys(modes).find((name) => process.argv.includes(name));
if (mode === undefined) {
  process.stderr.write("one of --plan, --withdraw, --deploy, --configure is required\n");
  process.exitCode = 64;
} else {
  modes[mode]().catch((error) => {
    process.stderr.write(`activation-case-adapter: ${error.message}\n`);
    process.exitCode = 1;
  });
}
