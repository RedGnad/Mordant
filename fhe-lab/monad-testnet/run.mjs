#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, mkdir, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import {
  createPublicClient,
  createWalletClient,
  decodeErrorResult,
  defineChain,
  encodeAbiParameters,
  encodeDeployData,
  encodeFunctionData,
  getAddress,
  getContractAddress,
  http,
  isAddress,
  parseEventLogs,
  recoverTypedDataAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  ATTESTATION_TYPES,
  EIP712_NAME,
  EIP712_VERSION,
  computeAttestationDigest,
  computeResultDigest,
} from "../shared/scripts/canonical.mjs";
import { normalizeProviderOutput } from "../workflow/workflow.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const LAB = resolve(HERE, "..");
const ARTIFACT_PATH = resolve(
  LAB,
  "monad-adapter/out/ECDSAQuorumConfidentialPolicyVerifier.sol/" +
    "ECDSAQuorumConfidentialPolicyVerifier.json",
);

export const MONAD_TESTNET_CHAIN_ID = 10_143;
export const MONAD_MAX_CREATION_BYTES = 131_072;
export const MONAD_MAX_TRANSACTION_GAS = 30_000_000n;
export const MAX_GAS_PRICE_WEI = 200_000_000_000n;
export const VALIDATOR_COUNT = 3;
export const QUORUM = 2;
export const POLICY_VERSION = 1;
export const POLICY_ID = "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540";
export const RESULT_TTL_SECONDS = 900n;
export const CURE_PERIOD_SECONDS = 3_600n;
export const REPORT_SCHEMA = "mordant.fhe-monad-testnet-acceptance/1";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const MAX_FHE_STDOUT_BYTES = 64 * 1024;
const PRIVATE_FIELD = /plaintext|private.?key|secret|share|credential|certificate/i;

export class AcceptanceError extends Error {
  constructor(code) {
    super(code);
    this.name = "AcceptanceError";
    this.code = code;
  }
}

function fail(code) {
  throw new AcceptanceError(code);
}

function asNonEmpty(value, code) {
  if (typeof value !== "string" || value.trim() === "") fail(code);
  return value.trim();
}

function asPrivateKey(value, code) {
  const key = asNonEmpty(value, code);
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) fail(code);
  return key;
}

function asAddress(value, code) {
  const address = asNonEmpty(value, code);
  if (!isAddress(address) || address.toLowerCase() === ZERO_ADDRESS) fail(code);
  return getAddress(address);
}

function asOutPath(value) {
  const out = asNonEmpty(value, "CLI_OUT_REQUIRED");
  return resolve(process.cwd(), out);
}

export function parseArgs(argv) {
  let mode = null;
  let out = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--check" || argument === "--run") {
      if (mode !== null) fail("CLI_MODE_CONFLICT");
      mode = argument.slice(2);
      continue;
    }
    if (argument === "--out") {
      if (out !== null || index + 1 >= argv.length) fail("CLI_OUT_REQUIRED");
      out = asOutPath(argv[++index]);
      continue;
    }
    fail("CLI_ARGUMENT");
  }
  if (mode === null) fail("CLI_MODE_REQUIRED");
  if (mode === "run" && out === null) fail("CLI_OUT_REQUIRED");
  if (mode === "check" && out !== null) fail("CLI_CHECK_HAS_OUT");
  return { mode, out };
}

export function loadConfig(env = process.env) {
  const rpcUrl = asNonEmpty(env.FHE_MONAD_RPC_URL ?? env.MONAD_RPC_URL, "CONFIG_RPC_URL");
  const deployerKey = asPrivateKey(env.FHE_MONAD_DEPLOYER_PRIVATE_KEY, "CONFIG_DEPLOYER_KEY");
  const deployerExpected = asAddress(env.FHE_MONAD_DEPLOYER_ADDRESS, "CONFIG_DEPLOYER_ADDRESS");
  const vault = asAddress(env.FHE_MONAD_TEST_VAULT, "CONFIG_TEST_VAULT");
  const deployer = privateKeyToAccount(deployerKey);
  if (deployer.address.toLowerCase() !== deployerExpected.toLowerCase()) {
    fail("DEPLOYER_ADDRESS_MISMATCH");
  }

  const validators = [1, 2, 3].map((index) => privateKeyToAccount(asPrivateKey(
    env[`FHE_MONAD_VALIDATOR_${index}_PRIVATE_KEY`],
    `CONFIG_VALIDATOR_${index}_KEY`,
  )));
  const unique = new Set(validators.map((validator) => validator.address.toLowerCase()));
  if (unique.size !== VALIDATOR_COUNT || unique.has(deployer.address.toLowerCase())) {
    fail("VALIDATOR_IDENTITIES_INVALID");
  }
  return { rpcUrl, deployer, vault, validators };
}

function monadChain(rpcUrl) {
  return defineChain({
    id: MONAD_TESTNET_CHAIN_ID,
    name: "Monad testnet",
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

async function loadArtifact() {
  let raw;
  try {
    raw = await readFile(ARTIFACT_PATH, "utf8");
  } catch {
    fail("VERIFIER_ARTIFACT_MISSING");
  }
  let artifact;
  try {
    artifact = JSON.parse(raw);
  } catch {
    fail("VERIFIER_ARTIFACT_INVALID");
  }
  if (!Array.isArray(artifact.abi) || typeof artifact.bytecode?.object !== "string") {
    fail("VERIFIER_ARTIFACT_INVALID");
  }
  if (!/^0x[0-9a-fA-F]+$/.test(artifact.bytecode.object)) fail("VERIFIER_ARTIFACT_INVALID");
  return { abi: artifact.abi, bytecode: artifact.bytecode.object };
}

function byteLength(hex) {
  if (typeof hex !== "string" || !hex.startsWith("0x") || hex.length % 2 !== 0) fail("HEX_ENCODING");
  return (hex.length - 2) / 2;
}

function publicResultArgument(result) {
  return {
    chainId: BigInt(result.chainId),
    vault: result.vault,
    policyId: result.policyId,
    policyVersion: Number(result.policyVersion),
    inputCommitmentA: result.inputCommitmentA,
    inputCommitmentB: result.inputCommitmentB,
    conflictConfirmed: result.conflictConfirmed,
    responsibleRole: result.responsibleRole,
    cureDeadline: BigInt(result.cureDeadline),
    nonce: BigInt(result.nonce),
    validUntil: BigInt(result.validUntil),
    providerProofCommitment: result.providerProofCommitment,
    resultCommitment: result.resultCommitment,
  };
}

function createReport({ config, artifact, deploymentInitCode }) {
  return {
    schemaVersion: REPORT_SCHEMA,
    status: "PREFLIGHT",
    classification: "MONAD TESTNET FHE RESULT ACCEPTANCE: NOT PROVEN",
    testAssetsOnly: true,
    network: { name: "Monad testnet", chainId: String(MONAD_TESTNET_CHAIN_ID) },
    publicAddresses: {
      deployer: config.deployer.address,
      syntheticVaultAnchor: config.vault,
      validators: config.validators.map((validator) => validator.address),
      verifier: null,
    },
    policy: { id: null, version: String(POLICY_VERSION) },
    gates: {},
    limits: {
      runtimeBytecodeBytes: byteLength(artifact.bytecode),
      deploymentInitCodeBytes: byteLength(deploymentInitCode),
      monadCreationLimitBytes: MONAD_MAX_CREATION_BYTES,
      monadTransactionGasLimit: MONAD_MAX_TRANSACTION_GAS.toString(),
    },
    transactions: { deployment: null, policyConfiguration: null, acceptance: null },
    result: null,
    readbacks: null,
    replaySimulation: null,
    performance: null,
  };
}

function assertPublicArtifact(value) {
  const serialized = JSON.stringify(value);
  if (PRIVATE_FIELD.test(serialized)) fail("ARTIFACT_PRIVATE_MATERIAL");
}

async function writeReport(out, report) {
  assertPublicArtifact(report);
  await mkdir(dirname(out), { recursive: true });
  const temporary = `${out}.tmp`;
  await writeFile(temporary, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await rename(temporary, out);
}

function setGate(report, gate, value) {
  report.gates[gate] = value;
}

function publicErrorCode(error) {
  return error instanceof AcceptanceError ? error.code : "MONAD_FHE_ACCEPTANCE_FAILED";
}

function ensureCreationWithinLimit(report) {
  if (
    report.limits.runtimeBytecodeBytes > MONAD_MAX_CREATION_BYTES ||
    report.limits.deploymentInitCodeBytes > MONAD_MAX_CREATION_BYTES
  ) {
    fail("MONAD_CODE_SIZE_LIMIT");
  }
}

async function estimateAndFund({ publicClient, account, request, label, report }) {
  let gas;
  let gasPrice;
  try {
    [gas, gasPrice] = await Promise.all([
      publicClient.estimateGas({ ...request, account: account.address }),
      publicClient.getGasPrice(),
    ]);
  } catch {
    fail(`${label}_GAS_UNAVAILABLE`);
  }
  if (gas <= 0n || gas > MONAD_MAX_TRANSACTION_GAS) fail(`${label}_GAS_LIMIT`);
  if (gasPrice <= 0n || gasPrice > MAX_GAS_PRICE_WEI) fail(`${label}_GAS_PRICE`);
  const budget = gas * gasPrice;
  const balance = await publicClient.getBalance({ address: account.address });
  if (balance < budget) fail(`${label}_INSUFFICIENT_MON`);
  setGate(report, `${label.toLowerCase()}Gas`, {
    estimatedGas: gas.toString(), gasPriceWei: gasPrice.toString(), budgetWei: budget.toString(),
  });
  return { gas, gasPrice, balance };
}

async function sendTracked({ walletClient, publicClient, account, request, estimate, report, out, field }) {
  const hash = await walletClient.sendTransaction({
    account,
    ...request,
    gas: estimate.gas,
    gasPrice: estimate.gasPrice,
  });
  report.transactions[field] = { hash, status: "PENDING", receipt: null };
  await writeReport(out, report);
  const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 1 });
  if (receipt.status !== "success") fail(`${field.toUpperCase()}_TRANSACTION_REVERTED`);
  report.transactions[field] = {
    hash,
    status: "CONFIRMED",
    receipt: {
      blockNumber: receipt.blockNumber.toString(), blockHash: receipt.blockHash,
      gasUsed: receipt.gasUsed.toString(),
    },
  };
  await writeReport(out, report);
  return receipt;
}

function freshNonce() {
  let nonce = BigInt(`0x${randomBytes(8).toString("hex")}`);
  if (nonce === 0n) nonce = 1n;
  return nonce;
}

async function runFreshFhe({ vault, now, nonce, validUntil, cureDeadline }) {
  const args = [
    "run", "./cmd/workflow", "--fresh", "--chain-id", String(MONAD_TESTNET_CHAIN_ID),
    "--vault", vault, "--now", now.toString(), "--nonce", nonce.toString(),
    "--valid-until", validUntil.toString(), "--cure-deadline", cureDeadline.toString(),
  ];
  const child = spawn("go", args, {
    cwd: resolve(LAB, "lattigo"), stdio: ["ignore", "pipe", "ignore"], env: process.env,
  });
  const exited = onceExit(child);
  const chunks = [];
  let total = 0;
  for await (const chunk of child.stdout) {
    total += chunk.length;
    if (total > MAX_FHE_STDOUT_BYTES) {
      child.kill("SIGKILL");
      fail("FHE_OUTPUT_TOO_LARGE");
    }
    chunks.push(chunk);
  }
  const [code] = await exited;
  if (code !== 0) fail("FHE_WORKFLOW_FAILED");
  let output;
  try {
    output = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    fail("FHE_OUTPUT_INVALID");
  }
  return normalizeProviderOutput(output);
}

function onceExit(child) {
  return new Promise((resolveExit) => child.once("exit", (...args) => resolveExit(args)));
}

async function signQuorum({ result, verifier, validatorSetId, validators }) {
  const domain = {
    name: EIP712_NAME, version: EIP712_VERSION, chainId: MONAD_TESTNET_CHAIN_ID,
    verifyingContract: verifier,
  };
  const resultDigest = computeResultDigest(result, verifier);
  const message = { validatorSetId, resultDigest };
  const signed = await Promise.all(validators.slice(0, QUORUM).map(async (validator) => {
    const signature = await validator.signTypedData({
      domain, types: ATTESTATION_TYPES, primaryType: "ConfidentialPolicyAttestation", message,
    });
    const recovered = await recoverTypedDataAddress({
      domain, types: ATTESTATION_TYPES, primaryType: "ConfidentialPolicyAttestation", message, signature,
    });
    if (recovered.toLowerCase() !== validator.address.toLowerCase()) fail("ATTESTATION_SIGNER_MISMATCH");
    return { validator: validator.address.toLowerCase(), signature };
  }));
  signed.sort((left, right) => left.validator.localeCompare(right.validator));
  return {
    resultDigest,
    attestationDigest: computeAttestationDigest(result, verifier, validatorSetId, resultDigest),
    attestation: encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes[]" }],
      [validatorSetId, signed.map(({ signature }) => signature)],
    ),
  };
}

function eventMatches({ logs, abi, result }) {
  const events = parseEventLogs({ abi, logs, eventName: "ConfidentialPolicyResultAccepted", strict: true });
  if (events.length !== 1) fail("ACCEPTANCE_EVENT_MISSING");
  const event = events[0].args;
  if (
    event.resultCommitment !== result.resultCommitment ||
    event.providerProofCommitment !== result.providerProofCommitment ||
    event.policyId !== result.policyId ||
    event.vault.toLowerCase() !== result.vault.toLowerCase() ||
    event.policyVersion !== Number(result.policyVersion) ||
    event.nonce !== BigInt(result.nonce)
  ) fail("ACCEPTANCE_EVENT_MISMATCH");
}

function isReplayRevert(error, abi) {
  const queue = [error];
  const visited = new Set();
  while (queue.length > 0) {
    const value = queue.pop();
    if (value === null || value === undefined || visited.has(value)) continue;
    if (typeof value === "object") {
      visited.add(value);
      if (typeof value.data === "string" && value.data.startsWith("0x")) {
        try {
          return decodeErrorResult({ abi, data: value.data }).errorName === "ReplayAlreadyConsumed";
        } catch {
          // Some RPCs omit custom-error data; the call still has to revert below.
        }
      }
      for (const child of Object.values(value)) queue.push(child);
    }
  }
  return false;
}

export async function runAcceptance({ args, env = process.env } = {}) {
  const options = args ?? parseArgs(process.argv.slice(2));
  const config = loadConfig(env);
  const artifact = await loadArtifact();
  const deploymentInitCode = encodeDeployData({
    abi: artifact.abi, bytecode: artifact.bytecode,
    args: [config.deployer.address, config.validators.map((validator) => validator.address), BigInt(QUORUM)],
  });
  const report = createReport({ config, artifact, deploymentInitCode });
  ensureCreationWithinLimit(report);

  const chain = monadChain(config.rpcUrl);
  const publicClient = createPublicClient({ chain, transport: http(config.rpcUrl) });
  const walletClient = createWalletClient({ chain, account: config.deployer, transport: http(config.rpcUrl) });
  const chainId = await publicClient.getChainId();
  if (chainId !== MONAD_TESTNET_CHAIN_ID) fail("CHAIN_ID_MISMATCH");
  setGate(report, "chain", { chainId: String(chainId), rpc: "responded" });
  const latest = await publicClient.getBlock();
  if (latest.hash === null) fail("LATEST_BLOCK_UNAVAILABLE");

  const deploymentNonce = await publicClient.getTransactionCount({ address: config.deployer.address, blockTag: "pending" });
  const expectedVerifier = getContractAddress({ from: config.deployer.address, nonce: deploymentNonce });
  const existingCode = await publicClient.getCode({ address: expectedVerifier });
  if (existingCode !== undefined && existingCode !== "0x") fail("VERIFIER_ADDRESS_ALREADY_OCCUPIED");
  report.publicAddresses.verifier = expectedVerifier;
  setGate(report, "sender", { derivedAddress: config.deployer.address, expectedAddress: config.deployer.address });
  setGate(report, "verifierAddress", { predicted: expectedVerifier, deployerNonce: deploymentNonce.toString() });

  const deploymentEstimate = await estimateAndFund({
    publicClient, account: config.deployer, request: { data: deploymentInitCode }, label: "DEPLOYMENT", report,
  });
  if (options.mode === "check") {
    report.status = "CHECKED";
    report.classification = "MONAD TESTNET FHE RESULT ACCEPTANCE: NOT PROVEN";
    return report;
  }

  const deploymentReceipt = await sendTracked({
    walletClient, publicClient, account: config.deployer, request: { data: deploymentInitCode },
    estimate: deploymentEstimate, report, out: options.out, field: "deployment",
  });
  if (deploymentReceipt.contractAddress === null || deploymentReceipt.contractAddress.toLowerCase() !== expectedVerifier.toLowerCase()) {
    fail("VERIFIER_DEPLOYMENT_ADDRESS_MISMATCH");
  }
  const verifier = deploymentReceipt.contractAddress;
  report.publicAddresses.verifier = verifier;
  const runtimeCode = await publicClient.getCode({ address: verifier });
  if (runtimeCode === undefined || runtimeCode === "0x" || byteLength(runtimeCode) > MONAD_MAX_CREATION_BYTES) {
    fail("VERIFIER_RUNTIME_CODE_INVALID");
  }
  setGate(report, "verifierRuntime", { bytecodeBytes: byteLength(runtimeCode), address: verifier });

  const policyId = POLICY_ID;
  report.policy.id = policyId;
  const policyData = encodeFunctionData({
    abi: artifact.abi, functionName: "setPolicyVersion", args: [config.vault, policyId, POLICY_VERSION],
  });
  const policyEstimate = await estimateAndFund({
    publicClient, account: config.deployer, request: { to: verifier, data: policyData }, label: "POLICY", report,
  });
  await publicClient.call({ account: config.deployer.address, to: verifier, data: policyData });
  await sendTracked({
    walletClient, publicClient, account: config.deployer, request: { to: verifier, data: policyData },
    estimate: policyEstimate, report, out: options.out, field: "policyConfiguration",
  });

  const [validatorSetId, quorum, validatorCount, configuredPolicy, ...activeValidators] = await Promise.all([
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "validatorSetId" }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "quorum" }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "validatorCount" }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "currentPolicyVersion", args: [config.vault, policyId] }),
    ...config.validators.map((validator) => publicClient.readContract({
      address: verifier, abi: artifact.abi, functionName: "validators", args: [validator.address],
    })),
  ]);
  if (
    validatorSetId === `0x${"00".repeat(32)}` || quorum !== BigInt(QUORUM) ||
    validatorCount !== BigInt(VALIDATOR_COUNT) || configuredPolicy !== POLICY_VERSION ||
    activeValidators.some((active) => active !== true)
  ) fail("VERIFIER_CONFIGURATION_DIVERGENCE");
  setGate(report, "verifierConfiguration", {
    validatorSetId, validatorCount: validatorCount.toString(), quorum: quorum.toString(),
    policyVersion: String(configuredPolicy),
  });

  const resultNonce = freshNonce();
  const resultNow = (await publicClient.getBlock()).timestamp;
  const validUntil = resultNow + RESULT_TTL_SECONDS;
  const cureDeadline = resultNow + CURE_PERIOD_SECONDS;
  const fheStartedAt = performance.now();
  const normalized = await runFreshFhe({
    vault: config.vault, now: resultNow, nonce: resultNonce, validUntil, cureDeadline,
  });
  const fheFinishedAt = performance.now();
  const result = normalized.result;
  if (
    result.chainId !== String(MONAD_TESTNET_CHAIN_ID) || result.vault.toLowerCase() !== config.vault.toLowerCase() ||
    result.policyId !== policyId || result.policyVersion !== String(POLICY_VERSION) ||
    BigInt(result.validUntil) <= resultNow || BigInt(result.nonce) !== resultNonce
  ) fail("FRESH_RESULT_CONTEXT_MISMATCH");
  const resultArgument = publicResultArgument(result);
  const [replayKey, decisionKey] = await Promise.all([
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "replayKey", args: [resultArgument] }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "decisionKey", args: [resultArgument] }),
  ]);
  const [replayUsed, decisionUsed, proofUsed] = await Promise.all([
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "consumedReplayKeys", args: [replayKey] }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "consumedDecisionKeys", args: [decisionKey] }),
    publicClient.readContract({
      address: verifier, abi: artifact.abi, functionName: "consumedProviderProofCommitments",
      args: [result.providerProofCommitment],
    }),
  ]);
  if (replayUsed || decisionUsed || proofUsed) fail("RESULT_REPLAY_NOT_FREE");
  setGate(report, "freshResult", { nonce: result.nonce, validUntil: result.validUntil, replayFree: true });

  const signed = await signQuorum({ result, verifier, validatorSetId, validators: config.validators });
  const canonicalDigest = await publicClient.readContract({
    address: verifier, abi: artifact.abi, functionName: "resultDigest", args: [resultArgument],
  });
  if (canonicalDigest !== signed.resultDigest) fail("RESULT_DIGEST_MISMATCH");
  const acceptCalldata = encodeFunctionData({
    abi: artifact.abi, functionName: "acceptResult", args: [resultArgument, signed.attestation],
  });
  report.result = {
    inputCommitments: [result.inputCommitmentA, result.inputCommitmentB],
    resultCommitment: result.resultCommitment, providerProofCommitment: result.providerProofCommitment,
    attestationDigest: signed.attestationDigest, nonce: result.nonce, validUntil: result.validUntil,
  };
  if (PRIVATE_FIELD.test(JSON.stringify(report.result))) fail("PUBLIC_RESULT_BOUNDARY");
  const acceptanceEstimate = await estimateAndFund({
    publicClient, account: config.deployer, request: { to: verifier, data: acceptCalldata }, label: "ACCEPTANCE", report,
  });
  await publicClient.simulateContract({
    account: config.deployer, address: verifier, abi: artifact.abi, functionName: "acceptResult",
    args: [resultArgument, signed.attestation],
  });
  setGate(report, "acceptance", { calldataBytes: byteLength(acceptCalldata), simulation: "accepted" });

  const acceptanceStartedAt = performance.now();
  const acceptanceReceipt = await sendTracked({
    walletClient, publicClient, account: config.deployer, request: { to: verifier, data: acceptCalldata },
    estimate: acceptanceEstimate, report, out: options.out, field: "acceptance",
  });
  const acceptedAt = performance.now();
  eventMatches({ logs: acceptanceReceipt.logs, abi: artifact.abi, result });
  const acceptedBlock = await publicClient.getBlock({ blockNumber: acceptanceReceipt.blockNumber });
  if (acceptedBlock.hash !== acceptanceReceipt.blockHash) fail("ACCEPTANCE_BLOCK_HASH_MISMATCH");
  const [acceptedReplay, acceptedProof, currentSet, acceptedPolicy] = await Promise.all([
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "consumedReplayKeys", args: [replayKey] }),
    publicClient.readContract({
      address: verifier, abi: artifact.abi, functionName: "consumedProviderProofCommitments",
      args: [result.providerProofCommitment],
    }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "validatorSetId" }),
    publicClient.readContract({ address: verifier, abi: artifact.abi, functionName: "currentPolicyVersion", args: [config.vault, policyId] }),
  ]);
  if (!acceptedReplay || !acceptedProof || currentSet !== validatorSetId || acceptedPolicy !== POLICY_VERSION) {
    fail("POST_ACCEPTANCE_READBACK_DIVERGENCE");
  }

  let replayRejected = false;
  let replaySelectorObserved = false;
  try {
    await publicClient.call({ account: config.deployer.address, to: verifier, data: acceptCalldata });
  } catch (error) {
    replayRejected = true;
    replaySelectorObserved = isReplayRevert(error, artifact.abi);
  }
  if (!replayRejected) fail("REPLAY_SIMULATION_ACCEPTED");

  report.status = "PROVEN";
  report.classification = [
    "MONAD TESTNET FHE RESULT ACCEPTANCE: PROVEN",
    "FHE POLICY EXECUTION: QUORUM-AUTHENTICATED",
    "CORRECT-COMPUTATION PUBLIC PROOF: NOT PROVIDED",
    "MORDANT VAULT INTEGRATION: NOT STARTED",
    "PRODUCTION FUNDS: NOT AUTHORIZED",
  ];
  report.readbacks = {
    acceptedResultCommitment: result.resultCommitment,
    nonceConsumed: acceptedReplay,
    providerProofConsumed: acceptedProof,
    validatorSetId: currentSet,
    policyVersion: String(acceptedPolicy),
    acceptanceEventObserved: true,
    blockNumber: acceptanceReceipt.blockNumber.toString(),
    blockHash: acceptanceReceipt.blockHash,
  };
  report.replaySimulation = {
    mode: "eth_call", secondTransactionBroadcast: false, rejected: true,
    replayAlreadyConsumedSelectorObserved: replaySelectorObserved,
  };
  report.performance = {
    fheMilliseconds: Number((fheFinishedAt - fheStartedAt).toFixed(3)),
    resultToReceiptMilliseconds: Number((acceptedAt - fheFinishedAt).toFixed(3)),
    acceptanceReceiptMilliseconds: Number((acceptedAt - acceptanceStartedAt).toFixed(3)),
    calldataBytes: byteLength(acceptCalldata), gasUsed: acceptanceReceipt.gasUsed.toString(),
  };
  await writeReport(options.out, report);
  return report;
}

async function main() {
  try {
    const report = await runAcceptance();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      schemaVersion: REPORT_SCHEMA, ok: false, classification: "MONAD TESTNET FHE RESULT ACCEPTANCE: NOT PROVEN",
      failedGate: publicErrorCode(error),
    })}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
