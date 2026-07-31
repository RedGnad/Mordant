import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  http,
  parseEventLogs,
  recoverTypedDataAddress,
} from "viem";

import {
  ATTESTATION_TYPES,
  EIP712_NAME,
  EIP712_VERSION,
  RESULT_SCHEMA_VERSION,
  ZERO_BYTES32,
  computeAttestationDigest,
  computeProviderProofCommitment,
  computeResultCommitment,
  computeResultDigest,
} from "../shared/scripts/canonical.mjs";

const WORKFLOW_DIR = dirname(fileURLToPath(import.meta.url));
const LAB_DIR = resolve(WORKFLOW_DIR, "..");
const DEFAULT_ARTIFACT_PATH = resolve(
  LAB_DIR,
  "monad-adapter/out/ECDSAQuorumConfidentialPolicyVerifier.sol/" +
    "ECDSAQuorumConfidentialPolicyVerifier.json",
);
const MANIFEST_PATH = resolve(LAB_DIR, "shared/test-vectors/manifest.json");

const CHAIN_ID = 31_337;
const QUORUM = 2;
const VALIDATOR_COUNT = 3;
const MAX_INPUT_BYTES = 64 * 1024;
const UINT32_MAX = (1n << 32n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const HEX_32 = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export const PROVIDER_OUTPUT_SCHEMA_VERSION = "mordant.fhe-provider-output/1";
export const PROVIDER_PROOF_SCHEMA_VERSION = "mordant.fhe-provider-proof/1";
export const WORKFLOW_METRICS_SCHEMA_VERSION = "mordant.fhe-adapter-workflow-metrics/2";

const RESULT_KEYS = [
  "schemaVersion",
  "chainId",
  "vault",
  "policyId",
  "policyVersion",
  "inputCommitmentA",
  "inputCommitmentB",
  "conflictConfirmed",
  "responsibleRole",
  "cureDeadline",
  "nonce",
  "validUntil",
  "providerProofCommitment",
  "resultCommitment",
];
const PROVIDER_PROOF_KEYS = [
  "schemaVersion",
  "resultCiphertextCommitment",
  "thresholdTranscriptCommitment",
  "thresholdSessionId",
  "thresholdKeyCommitment",
  "policyCircuitCommitment",
  "providerProofCommitment",
];

export class WorkflowError extends Error {
  constructor(code) {
    super(code);
    this.name = "WorkflowError";
    this.code = code;
  }
}

function fail(code) {
  throw new WorkflowError(code);
}

function asObject(value, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  return value;
}

function exactKeys(value, expected, code, optional = []) {
  const actual = Object.keys(value).sort();
  const allowed = [...expected, ...optional].sort();
  if (actual.some((key) => !allowed.includes(key))) fail(code);
  if (expected.some((key) => !actual.includes(key))) fail(code);
}

function asBytes32(value, code) {
  if (typeof value !== "string" || !HEX_32.test(value)) fail(code);
  return value.toLowerCase();
}

function asAddress(value, code) {
  if (typeof value !== "string" || !ADDRESS.test(value)) fail(code);
  return getAddress(value).toLowerCase();
}

function asUintString(value, maximum, code) {
  let normalized;
  if (typeof value === "bigint") {
    normalized = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    normalized = BigInt(value);
  } else if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    normalized = BigInt(value);
  } else {
    fail(code);
  }
  if (normalized < 0n || normalized > maximum) fail(code);
  return normalized.toString();
}

function roundMs(value) {
  return Number(value.toFixed(3));
}

function calldataBytes(data) {
  if (typeof data !== "string" || !data.startsWith("0x") || data.length % 2 !== 0) {
    fail("CALLDATA_ENCODING");
  }
  return (data.length - 2) / 2;
}

async function loadJson(path, code) {
  let contents;
  try {
    contents = await readFile(path, "utf8");
  } catch {
    fail(code);
  }
  try {
    return JSON.parse(contents);
  } catch {
    fail(code);
  }
}

export async function loadFixtureProviderOutput() {
  const manifest = asObject(await loadJson(MANIFEST_PATH, "MANIFEST_INVALID"), "MANIFEST_INVALID");
  const canonical = asObject(
    asObject(manifest.canonicalEncodingVector, "MANIFEST_INVALID"),
    "MANIFEST_INVALID",
  );
  return {
    schemaVersion: PROVIDER_OUTPUT_SCHEMA_VERSION,
    ok: true,
    result: asObject(canonical.result, "MANIFEST_INVALID"),
    providerProof: asObject(canonical.providerProof, "MANIFEST_INVALID"),
  };
}

/**
 * Accepts only the provider-neutral public success envelope. This boundary is deliberately
 * fail-closed: provider errors, missing fields, unknown fields, and private payloads are rejected
 * before Anvil starts. `providerProof` is mandatory and its domain-separated commitment is bound
 * into both the result commitment and the EIP-712 attestation. This binds endorsed evidence; it
 * does not independently prove that the FHE computation was correct.
 */
export function normalizeProviderOutput(candidate) {
  const input = asObject(candidate, "INPUT_OBJECT");
  if (input.ok === false) fail("INPUT_PROVIDER_FAILED");
  exactKeys(input, ["schemaVersion", "ok", "result", "providerProof"], "INPUT_FIELDS");
  if (input.schemaVersion !== PROVIDER_OUTPUT_SCHEMA_VERSION) fail("INPUT_SCHEMA_VERSION");
  if (input.ok !== true) fail("INPUT_SUCCESS_BOOL");

  const suppliedResult = asObject(input.result, "INPUT_RESULT_OBJECT");
  exactKeys(suppliedResult, RESULT_KEYS, "INPUT_RESULT_FIELDS");
  if (suppliedResult.schemaVersion !== RESULT_SCHEMA_VERSION) fail("INPUT_RESULT_SCHEMA_VERSION");

  const conflictConfirmed = suppliedResult.conflictConfirmed;
  if (typeof conflictConfirmed !== "boolean") fail("INPUT_CONFLICT_BOOL");
  const responsibleRole = asBytes32(suppliedResult.responsibleRole, "INPUT_RESPONSIBLE_ROLE");
  const cureDeadline = asUintString(
    suppliedResult.cureDeadline,
    UINT64_MAX,
    "INPUT_CURE_DEADLINE",
  );
  if (conflictConfirmed) {
    if (responsibleRole === ZERO_BYTES32 || cureDeadline === "0") fail("INPUT_POSITIVE_OUTPUTS");
  } else if (responsibleRole !== ZERO_BYTES32 || cureDeadline !== "0") {
    fail("INPUT_NEGATIVE_OUTPUTS");
  }

  const result = {
    schemaVersion: RESULT_SCHEMA_VERSION,
    chainId: asUintString(suppliedResult.chainId, UINT256_MAX, "INPUT_CHAIN_ID"),
    vault: asAddress(suppliedResult.vault, "INPUT_VAULT"),
    policyId: asBytes32(suppliedResult.policyId, "INPUT_POLICY_ID"),
    policyVersion: asUintString(
      suppliedResult.policyVersion,
      UINT32_MAX,
      "INPUT_POLICY_VERSION",
    ),
    inputCommitmentA: asBytes32(suppliedResult.inputCommitmentA, "INPUT_COMMITMENT_A"),
    inputCommitmentB: asBytes32(suppliedResult.inputCommitmentB, "INPUT_COMMITMENT_B"),
    conflictConfirmed,
    responsibleRole,
    cureDeadline,
    nonce: asUintString(suppliedResult.nonce, UINT256_MAX, "INPUT_NONCE"),
    validUntil: asUintString(suppliedResult.validUntil, UINT64_MAX, "INPUT_VALID_UNTIL"),
    providerProofCommitment: asBytes32(
      suppliedResult.providerProofCommitment,
      "INPUT_PROVIDER_PROOF_COMMITMENT",
    ),
    resultCommitment: asBytes32(
      suppliedResult.resultCommitment,
      "INPUT_RESULT_COMMITMENT",
    ),
  };
  if (computeResultCommitment(result) !== result.resultCommitment) {
    fail("INPUT_RESULT_COMMITMENT_MISMATCH");
  }

  const suppliedProof = asObject(input.providerProof, "INPUT_PROVIDER_PROOF_OBJECT");
  exactKeys(suppliedProof, PROVIDER_PROOF_KEYS, "INPUT_PROVIDER_PROOF_FIELDS");
  if (suppliedProof.schemaVersion !== PROVIDER_PROOF_SCHEMA_VERSION) {
    fail("INPUT_PROVIDER_PROOF_SCHEMA_VERSION");
  }
  const providerProof = {
    schemaVersion: PROVIDER_PROOF_SCHEMA_VERSION,
    resultCiphertextCommitment: asBytes32(
      suppliedProof.resultCiphertextCommitment,
      "INPUT_RESULT_CIPHERTEXT_COMMITMENT",
    ),
    thresholdTranscriptCommitment: asBytes32(
      suppliedProof.thresholdTranscriptCommitment,
      "INPUT_THRESHOLD_TRANSCRIPT_COMMITMENT",
    ),
    thresholdSessionId: asBytes32(
      suppliedProof.thresholdSessionId,
      "INPUT_THRESHOLD_SESSION_ID",
    ),
    thresholdKeyCommitment: asBytes32(
      suppliedProof.thresholdKeyCommitment,
      "INPUT_THRESHOLD_KEY_COMMITMENT",
    ),
    policyCircuitCommitment: asBytes32(
      suppliedProof.policyCircuitCommitment,
      "INPUT_POLICY_CIRCUIT_COMMITMENT",
    ),
    providerProofCommitment: asBytes32(
      suppliedProof.providerProofCommitment,
      "INPUT_PROVIDER_PROOF_COMMITMENT",
    ),
  };
  for (const [field, value] of Object.entries(providerProof)) {
    if (field !== "schemaVersion" && value === ZERO_BYTES32) fail("INPUT_PROVIDER_PROOF_ZERO");
  }
  const computedProof = computeProviderProofCommitment({
    resultCiphertextCommitment: providerProof.resultCiphertextCommitment,
    thresholdTranscriptCommitment: providerProof.thresholdTranscriptCommitment,
    thresholdSessionId: providerProof.thresholdSessionId,
    thresholdKeyCommitment: providerProof.thresholdKeyCommitment,
    policyCircuitCommitment: providerProof.policyCircuitCommitment,
  });
  if (
    computedProof !== providerProof.providerProofCommitment ||
    computedProof !== result.providerProofCommitment
  ) {
    fail("INPUT_PROVIDER_PROOF_MISMATCH");
  }

  return { result, providerProof };
}

export async function readPublicJson(stream) {
  let byteLength = 0;
  const chunks = [];
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    byteLength += bytes.length;
    if (byteLength > MAX_INPUT_BYTES) fail("INPUT_TOO_LARGE");
    chunks.push(bytes);
  }
  const contents = Buffer.concat(chunks).toString("utf8").trim();
  if (contents === "") fail("INPUT_EMPTY");
  try {
    return asObject(JSON.parse(contents), "INPUT_JSON");
  } catch (error) {
    if (error instanceof WorkflowError) throw error;
    fail("INPUT_JSON");
  }
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    fail("LOCAL_PORT");
  }
  const port = address.port;
  await new Promise((resolveClose, reject) => {
    server.close((error) => error ? reject(error) : resolveClose());
  });
  return port;
}

async function startAnvil() {
  const port = await reservePort();
  const child = spawn(
    "anvil",
    [
      "--host", "127.0.0.1",
      "--port", String(port),
      "--chain-id", String(CHAIN_ID),
      "--accounts", "4",
      "--balance", "10000",
      "--silent",
    ],
    {
      cwd: WORKFLOW_DIR,
      env: process.env,
      stdio: ["ignore", "ignore", "ignore"],
    },
  );

  let processFailure = null;
  child.once("error", () => {
    processFailure = "ANVIL_START";
  });
  child.once("exit", (code, signal) => {
    if (code !== 0 && signal !== "SIGTERM" && signal !== "SIGKILL") {
      processFailure = "ANVIL_EXIT";
    }
  });

  const rpcUrl = `http://127.0.0.1:${port}`;
  const probe = createPublicClient({ transport: http(rpcUrl) });
  const deadline = performance.now() + 8_000;
  while (performance.now() < deadline) {
    if (processFailure !== null) {
      await stopAnvil(child);
      fail(processFailure);
    }
    try {
      if (await probe.getChainId() === CHAIN_ID) return { child, rpcUrl };
    } catch {
      // The loopback RPC has not bound yet.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 40));
  }
  await stopAnvil(child);
  fail("ANVIL_TIMEOUT");
}

async function stopAnvil(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveExit) => child.once("exit", resolveExit)),
    new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000)),
  ]);
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
}

function workflowChain(rpcUrl) {
  return defineChain({
    id: CHAIN_ID,
    name: "Mordant controlled FHE workflow",
    nativeCurrency: { name: "Synthetic Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
}

async function loadArtifact(path) {
  const artifact = asObject(await loadJson(path, "ARTIFACT_MISSING"), "ARTIFACT_INVALID");
  if (!Array.isArray(artifact.abi)) fail("ARTIFACT_INVALID");
  const bytecode = artifact.bytecode?.object;
  if (typeof bytecode !== "string" || !/^0x[0-9a-fA-F]+$/.test(bytecode)) {
    fail("ARTIFACT_INVALID");
  }
  return { abi: artifact.abi, bytecode };
}

function resultForChain(result, latestTimestamp) {
  if (BigInt(result.chainId) !== BigInt(CHAIN_ID)) {
    fail("INPUT_CHAIN_MISMATCH");
  }
  if (BigInt(result.validUntil) < latestTimestamp) fail("INPUT_RESULT_EXPIRED");
  return result;
}

function contractResult(result) {
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

async function signQuorum({ walletClient, validators, result, verifier, validatorSetId }) {
  const domain = {
    name: EIP712_NAME,
    version: EIP712_VERSION,
    chainId: CHAIN_ID,
    verifyingContract: verifier,
  };
  const resultDigest = computeResultDigest(result, verifier);
  const attestationDigest = computeAttestationDigest(
    result,
    verifier,
    validatorSetId,
    resultDigest,
  );
  const message = { validatorSetId, resultDigest };

  const signed = [];
  for (const validator of validators.slice(0, QUORUM)) {
    const signature = await walletClient.signTypedData({
      account: validator,
      domain,
      types: ATTESTATION_TYPES,
      primaryType: "ConfidentialPolicyAttestation",
      message,
    });
    const recovered = await recoverTypedDataAddress({
      domain,
      types: ATTESTATION_TYPES,
      primaryType: "ConfidentialPolicyAttestation",
      message,
      signature,
    });
    if (recovered.toLowerCase() !== validator.toLowerCase()) fail("ATTESTATION_SIGNER");
    signed.push({ validator: validator.toLowerCase(), signature });
  }
  signed.sort((left, right) => left.validator.localeCompare(right.validator));

  return {
    attestation: encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes[]" }],
      [validatorSetId, signed.map(({ signature }) => signature)],
    ),
    attestationDigest,
    resultDigest,
  };
}

function assertAcceptance({ logs, verifier, result, replayConsumed, decisionConsumed, viewVerified }) {
  const accepted = parseEventLogs({
    abi: verifier.abi,
    logs,
    eventName: "ConfidentialPolicyResultAccepted",
    strict: true,
  });
  if (accepted.length !== 1) fail("ACCEPT_EVENT");
  const event = accepted[0].args;
  if (
    event.resultCommitment !== result.resultCommitment ||
    event.providerProofCommitment !== result.providerProofCommitment ||
    event.policyId !== result.policyId ||
    event.vault.toLowerCase() !== result.vault ||
    event.policyVersion !== Number(result.policyVersion) ||
    event.nonce !== BigInt(result.nonce) ||
    event.conflictConfirmed !== result.conflictConfirmed
  ) {
    fail("ACCEPT_EVENT");
  }
  if (!viewVerified || !replayConsumed || !decisionConsumed) fail("ACCEPT_STATE");
}

export async function runWorkflow({
  input,
  fixture = false,
  artifactPath = DEFAULT_ARTIFACT_PATH,
} = {}) {
  if (fixture && input !== undefined) fail("INPUT_SOURCE_CONFLICT");
  if (!fixture && input === undefined) fail("INPUT_REQUIRED");
  const providerOutput = fixture ? await loadFixtureProviderOutput() : input;
  const normalizedInput = normalizeProviderOutput(providerOutput);
  const artifact = await loadArtifact(artifactPath);
  const { child, rpcUrl } = await startAnvil();

  try {
    const chain = workflowChain(rpcUrl);
    const transport = http(rpcUrl);
    const publicClient = createPublicClient({ chain, transport });
    const walletClient = createWalletClient({ chain, transport });
    const accounts = await walletClient.getAddresses();
    if (accounts.length < VALIDATOR_COUNT + 1) fail("SYNTHETIC_ACCOUNTS");
    const owner = accounts[0];
    const validators = accounts.slice(1, VALIDATOR_COUNT + 1);

    const deployHash = await walletClient.deployContract({
      account: owner,
      abi: artifact.abi,
      bytecode: artifact.bytecode,
      args: [owner, validators, BigInt(QUORUM)],
    });
    const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
    if (deployReceipt.status !== "success" || deployReceipt.contractAddress === null) {
      fail("DEPLOYMENT_FAILED");
    }
    const verifierAddress = deployReceipt.contractAddress;

    const policyHash = await walletClient.writeContract({
      account: owner,
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "setPolicyVersion",
      args: [
        normalizedInput.result.vault,
        normalizedInput.result.policyId,
        Number(normalizedInput.result.policyVersion),
      ],
    });
    const policyReceipt = await publicClient.waitForTransactionReceipt({ hash: policyHash });
    if (policyReceipt.status !== "success") fail("POLICY_CONFIGURATION_FAILED");

    const latestBlock = await publicClient.getBlock();
    const result = resultForChain(normalizedInput.result, latestBlock.timestamp);
    const resultReadyAt = performance.now();
    const resultArgument = contractResult(result);

    const validatorSetId = await publicClient.readContract({
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "validatorSetId",
    });
    const signed = await signQuorum({
      walletClient,
      validators,
      result,
      verifier: verifierAddress,
      validatorSetId,
    });

    const onchainResultDigest = await publicClient.readContract({
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "resultDigest",
      args: [resultArgument],
    });
    const onchainAttestationDigest = await publicClient.readContract({
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "attestationDigest",
      args: [validatorSetId, signed.resultDigest],
    });
    if (
      onchainResultDigest !== signed.resultDigest ||
      onchainAttestationDigest !== signed.attestationDigest
    ) {
      fail("CANONICAL_DIGEST_MISMATCH");
    }

    const verifyStartedAt = performance.now();
    const viewVerified = await publicClient.readContract({
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "verifyResult",
      args: [resultArgument, signed.attestation],
    });
    const verifyViewMs = performance.now() - verifyStartedAt;

    const acceptCalldata = encodeFunctionData({
      abi: artifact.abi,
      functionName: "acceptResult",
      args: [resultArgument, signed.attestation],
    });
    const transactionStartedAt = performance.now();
    const acceptHash = await walletClient.writeContract({
      account: owner,
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "acceptResult",
      args: [resultArgument, signed.attestation],
    });
    const acceptReceipt = await publicClient.waitForTransactionReceipt({ hash: acceptHash });
    const acceptedAt = performance.now();
    if (acceptReceipt.status !== "success") fail("ACCEPT_TRANSACTION_FAILED");

    const replayKey = await publicClient.readContract({
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "replayKey",
      args: [resultArgument],
    });
    const decisionKey = await publicClient.readContract({
      address: verifierAddress,
      abi: artifact.abi,
      functionName: "decisionKey",
      args: [resultArgument],
    });
    const [replayConsumed, decisionConsumed] = await Promise.all([
      publicClient.readContract({
        address: verifierAddress,
        abi: artifact.abi,
        functionName: "consumedReplayKeys",
        args: [replayKey],
      }),
      publicClient.readContract({
        address: verifierAddress,
        abi: artifact.abi,
        functionName: "consumedDecisionKeys",
        args: [decisionKey],
      }),
    ]);

    assertAcceptance({
      logs: acceptReceipt.logs,
      verifier: { abi: artifact.abi },
      result,
      replayConsumed,
      decisionConsumed,
      viewVerified,
    });

    const replayAttemptHash = await walletClient.sendTransaction({
      account: owner,
      to: verifierAddress,
      data: acceptCalldata,
      gas: 500_000n,
    });
    const replayAttemptReceipt = await publicClient.waitForTransactionReceipt({
      hash: replayAttemptHash,
    });
    if (replayAttemptReceipt.status !== "reverted") fail("REPLAY_ACCEPTED");

    return {
      schemaVersion: WORKFLOW_METRICS_SCHEMA_VERSION,
      ok: true,
      environment: "controlled-local-anvil",
      chainId: String(CHAIN_ID),
      result: {
        conflictConfirmed: result.conflictConfirmed,
        providerProofCommitment: result.providerProofCommitment,
        resultCommitment: result.resultCommitment,
      },
      receipt: {
        verifier: verifierAddress,
        transactionHash: acceptHash,
        blockNumber: acceptReceipt.blockNumber.toString(),
        replayKey,
        decisionKey,
        attestationDigest: signed.attestationDigest,
        validatorSetId,
      },
      quorum: {
        validatorCount: VALIDATOR_COUNT,
        required: QUORUM,
        signatures: QUORUM,
        syntheticTestKeys: true,
      },
      verification: {
        canonicalDigestsMatch: true,
        viewVerified: true,
        acceptanceEventObserved: true,
        replayStateConsumed: true,
        decisionStateConsumed: true,
        secondAcceptanceRejected: true,
        providerProofRequired: true,
        providerProofSupplied: true,
        providerProofBoundToAttestation: true,
        providerProofProvesCorrectComputation: false,
      },
      metrics: {
        calldataBytes: calldataBytes(acceptCalldata),
        gasUsed: {
          deployment: deployReceipt.gasUsed.toString(),
          policyConfiguration: policyReceipt.gasUsed.toString(),
          resultAcceptance: acceptReceipt.gasUsed.toString(),
        },
        latencyMs: {
          verifyView: roundMs(verifyViewMs),
          acceptTransaction: roundMs(acceptedAt - transactionStartedAt),
          resultToAccept: roundMs(acceptedAt - resultReadyAt),
        },
      },
    };
  } finally {
    await stopAnvil(child);
  }
}
