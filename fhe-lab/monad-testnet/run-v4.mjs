#!/usr/bin/env node

// M-PRIV5C product runner: one atomic non-economic recourse record opened
// against a real, deployed, Outstanding MordantInvoiceVault on Monad testnet,
// driven by a dealerless confidential evaluation and signed by three separate
// validator processes.
//
// This process never holds a validator key. Each signer generates its own key in
// its own directory and this runner asks two of them for a signature over the
// exact V3 result; each signer recomputes the digest itself before signing.
//
// Crash safety is preserved from the V3 runner: every transaction hash is
// journalled with atomic temp-and-rename before its receipt is awaited, and a
// persisted hash is reconciled rather than resubmitted.

import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient, createWalletClient, defineChain, http, getAddress, keccak256,
  stringToHex, parseEventLogs, encodeFunctionData, encodeAbiParameters,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../..");

export const CHAIN_ID = 10_143;
export const POLICY_LABEL = "mordant.anchored-recourse.policy/v4";
export const POLICY_ID = keccak256(stringToHex(POLICY_LABEL));
export const POLICY_VERSION = 1;
export const QUORUM = 2n;
export const CURE_PERIOD = 3_600n;
export const RESPONSIBLE_ROLE = keccak256(stringToHex("mordant.role.facility.v1"));
export const CONSEQUENCE_ID = keccak256(stringToHex("mordant.consequence.review-required.v1"));
export const RESULT_TTL_SECONDS = 1_800;
export const MIN_EXPIRY_MARGIN_SECONDS = 300;
export const MAX_TRANSACTION_GAS = 30_000_000n;
export const MAX_GAS_PRICE_WEI = 500_000_000_000n;
export const JOURNAL_SCHEMA = "mordant.anchored-recourse-journal/1";
export const REPORT_SCHEMA = "mordant.anchored-recourse/1";
export const STATES = Object.freeze([
  "PREFLIGHT", "SIGNERS_READY", "SETUP_CONFIRMED", "CEREMONY_PROVEN",
  "ATOMIC_PREPARED", "ATOMIC_HASH_PERSISTED", "ATOMIC_CONFIRMED",
  "READBACKS_CONFIRMED", "REPLAY_REJECTED", "PRODUCT_CLAIM_READY",
]);

// Field names that must never reach a public artifact.
const RESTRICTED = /plaintext|private.?key|threshold.?share|shamir|credential|secret.?key/i;

export class RunError extends Error {
  constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.code = code; }
}
const fail = (code, detail) => { throw new RunError(code, detail); };

/* ------------------------------------------------------------------ journal */

// The guard targets field NAMES, not free text. An error string such as
// "insufficient threshold shares" is a refusal message, not a secret, and
// matching it would make the gate fire on its own evidence of safety.
export function assertPublicOnly(value) {
  const walk = (node) => {
    if (Array.isArray(node)) { node.forEach(walk); return; }
    if (node === null || typeof node !== "object") return;
    for (const [key, child] of Object.entries(node)) {
      if (RESTRICTED.test(key)) fail("ARTIFACT_RESTRICTED_FIELD", key);
      walk(child);
    }
  };
  walk(value);
  return value;
}

export async function writeAtomic(path, value) {
  assertPublicOnly(value);
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`);
  await rename(temporary, path);
}

export function emptyJournal() {
  return {
    schemaVersion: JOURNAL_SCHEMA, chainId: CHAIN_ID, testAssetsOnly: true,
    state: "PREFLIGHT", history: [], signers: null, setup: null, ceremony: null,
    session: null, atomic: null, readbacks: null, replay: null, failure: null,
  };
}

export async function readJournal(path) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    return parsed?.schemaVersion === JOURNAL_SCHEMA ? parsed : null;
  } catch { return null; }
}

export async function advance(journal, path, state, patch = {}) {
  if (!STATES.includes(state)) fail("JOURNAL_UNKNOWN_STATE", state);
  Object.assign(journal, patch);
  journal.state = state;
  journal.history.push({ state, at: new Date().toISOString() });
  await writeAtomic(path, journal);
  return journal;
}

// A fresh submission is refused whenever a hash is already recorded, so a
// crashed run is reconciled instead of rebroadcast.
export async function reconcileAtomic({ journal, client }) {
  const atomic = journal?.atomic;
  if (!atomic?.hash) return { action: "SUBMIT", receipt: null };
  const receipt = await client.getTransactionReceipt({ hash: atomic.hash }).catch(() => null);
  if (!receipt) {
    const pending = await client.getTransaction({ hash: atomic.hash }).catch(() => null);
    fail(pending ? "ATOMIC_PENDING_UNKNOWN" : "ATOMIC_UNKNOWN_TRANSACTION", atomic.hash);
  }
  if (receipt.status !== "success") fail("ATOMIC_REVERTED", atomic.hash);
  return { action: "RESUME_CONFIRMED", receipt };
}

/* ------------------------------------------------------------------- config */

export function monadChain(rpc) {
  return defineChain({
    id: CHAIN_ID, name: "Monad testnet",
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
  });
}

export async function artifact(directory, name) {
  const raw = await readFile(resolve(REPO, `${directory}/${name}.json`), "utf8");
  const parsed = JSON.parse(raw);
  if (!parsed?.abi || typeof parsed?.bytecode?.object !== "string") fail("ARTIFACT_INVALID", name);
  return { abi: parsed.abi, bytecode: parsed.bytecode.object };
}

export function config(env = process.env) {
  const key = env.FHE_MONAD_DEPLOYER_PRIVATE_KEY;
  if (typeof key !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(key)) fail("CONFIG_DEPLOYER_KEY");
  const rpc = env.FHE_MONAD_RPC_URL;
  if (!rpc) fail("CONFIG_RPC_URL");
  return { rpc, deployer: privateKeyToAccount(key) };
}

/* -------------------------------------------------------------- signer pool */

// Each signer is a separate OS process that generated its own key. This runner
// holds none of them and can only ask for signatures.
export class SignerPool {
  constructor(root) { this.root = root; this.signers = []; }

  async provision(count, scope) {
    for (let index = 1; index <= count; index += 1) {
      const storage = resolve(this.root, `signer-${index}`);
      const address = (await runNode(["--mode", "identity", "--storage", storage])).trim();
      this.signers.push({ index, storage, address: getAddress(address), scope });
    }
    return this.signers.map((signer) => signer.address);
  }

  async start(scope) {
    for (const signer of this.signers) {
      const child = spawn(process.execPath, [
        resolve(HERE, "validator-signer.mjs"),
        "--mode", "serve", "--storage", signer.storage, "--port", "0",
        "--chain-id", String(CHAIN_ID), "--verifier", scope.verifier,
        "--policy-id", scope.policyId, "--consumer", scope.consumer, "--vault", scope.vault,
      ], { stdio: ["ignore", "pipe", "pipe"] });
      signer.pid = child.pid;
      signer.process = child;
      const ready = await new Promise((done, reject) => {
        let buffer = "";
        child.stdout.on("data", (chunk) => {
          buffer += chunk.toString();
          const line = buffer.split("\n").find((entry) => entry.includes("\"ready\""));
          if (line) { try { done(JSON.parse(line)); } catch { /* keep reading */ } }
        });
        child.once("exit", (code) => reject(new RunError("SIGNER_EXITED", `${signer.index}:${code}`)));
        setTimeout(() => reject(new RunError("SIGNER_TIMEOUT", String(signer.index))), 20_000);
      });
      signer.port = ready.port;
      signer.token = (await readFile(resolve(signer.storage, "runner.token"), "utf8")).trim();
      if (getAddress(ready.address) !== signer.address) fail("SIGNER_ADDRESS_MISMATCH", `start:${signer.index}:${ready.address}!=${signer.address}`);
    }
  }

  async sign(signer, payload) {
    const body = JSON.stringify(payload);
    const response = await fetch(`http://127.0.0.1:${signer.port}/v1/sign`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signer-auth": createHmac("sha256", signer.token).update(body).digest("hex"),
      },
      body,
    });
    const parsed = await response.json();
    if (response.status !== 200) fail("SIGNER_REFUSED", `${signer.index}:${parsed.error}`);
    if (getAddress(parsed.address) !== signer.address) fail("SIGNER_ADDRESS_MISMATCH", `sign:${signer.index}:${parsed.address}!=${signer.address}`);
    return parsed;
  }

  async status(signer) {
    const response = await fetch(`http://127.0.0.1:${signer.port}/v1/status`);
    return response.json();
  }

  stop() {
    for (const signer of this.signers) {
      if (signer.process && !signer.process.killed) signer.process.kill("SIGTERM");
    }
  }
}

function runNode(args) {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, [resolve(HERE, "validator-signer.mjs"), ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.stderr.on("data", (chunk) => { err += chunk; });
    child.once("exit", (code) => (code === 0 ? done(out) : reject(new RunError("SIGNER_IDENTITY_FAILED", err.trim()))));
  });
}

/* ------------------------------------------------------------------- helper */

export function resultTuple(result) {
  return {
    chainId: BigInt(result.chainId), consumer: getAddress(result.consumer), vault: getAddress(result.vault),
    policyId: result.policyId, policyVersion: Number(result.policyVersion),
    inputCommitmentA: result.inputCommitmentA, inputCommitmentB: result.inputCommitmentB,
    conflictConfirmed: Boolean(result.conflictConfirmed), nonce: BigInt(result.nonce),
    validUntil: BigInt(result.validUntil), providerProofCommitment: result.providerProofCommitment,
    resultCommitment: result.resultCommitment,
  };
}

export function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value, (_key, entry) => (typeof entry === "bigint" ? entry.toString() : entry)));
}

export { RESTRICTED };

/* --------------------------------------------------------------------- run */

export async function run(options = parseArgs(process.argv.slice(2))) {
  const settings = config();
  const chain = monadChain(settings.rpc);
  const client = createPublicClient({ chain, transport: http(settings.rpc) });
  const wallet = createWalletClient({ account: settings.deployer, chain, transport: http(settings.rpc) });
  const pool = new SignerPool(options.signerRoot);

  const pause = (ms) => new Promise((done) => setTimeout(done, ms));
  const read = async (address, abi, functionName, args = []) => {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const value = await client.readContract({ address, abi, functionName, args });
        await pause(110);
        return value;
      } catch (error) {
        if (attempt >= 5 || !/limited|rate|429/i.test(String(error?.message ?? ""))) throw error;
        await pause(1_000 * (attempt + 1));
      }
    }
  };
  const fees = async () => {
    const block = await client.getBlock();
    const priority = 2_000_000_000n;
    const base = block.baseFeePerGas ?? (await client.getGasPrice());
    if (base > MAX_GAS_PRICE_WEI) fail("GAS_PRICE_TOO_HIGH", String(base));
    return { maxPriorityFeePerGas: priority, maxFeePerGas: base * 2n + priority };
  };

  const anchorReport = JSON.parse(await readFile(options.anchor, "utf8"));
  const anchor = getAddress(anchorReport.anchor.vault);
  const anchorRoot = anchorReport.anchor.invoiceRoot;

  const verifierArt = await artifact("fhe-lab/monad-adapter/out/ECDSAQuorumConfidentialPolicyVerifierV3.sol", "ECDSAQuorumConfidentialPolicyVerifierV3");
  const consumerArt = await artifact("fhe-lab/monad-adapter/out/ReceivableAnchoredRecourseConsumer.sol", "ReceivableAnchoredRecourseConsumer");
  const vaultArt = await artifact("contracts/out/MordantInvoiceVault.sol", "MordantInvoiceVault");

  const chainId = await client.getChainId();
  if (chainId !== CHAIN_ID) fail("CHAIN_ID_MISMATCH", String(chainId));
  const balance = await client.getBalance({ address: settings.deployer.address });
  if (balance < 2_000_000_000_000_000_000n) fail("DEPLOYER_BALANCE_LOW", String(balance));

  // The anchor must be a deployed, Outstanding receivable before anything else.
  const anchorCode = await client.getCode({ address: anchor });
  if (!anchorCode || anchorCode.length <= 2) fail("ANCHOR_NOT_DEPLOYED", anchor);
  const anchorState = {
    invoiceRoot: await read(anchor, vaultArt.abi, "invoiceRoot"),
    currency: await read(anchor, vaultArt.abi, "currency"),
    receivableState: Number(await read(anchor, vaultArt.abi, "receivableState")),
    protectionState: Number(await read(anchor, vaultArt.abi, "protectionState")),
    totalSupply: (await read(anchor, vaultArt.abi, "totalSupply")).toString(),
    buyer: await read(anchor, vaultArt.abi, "buyer"),
    originatorTreasury: await read(anchor, vaultArt.abi, "originatorTreasury"),
    codeBytes: (anchorCode.length - 2) / 2,
  };
  if (anchorState.invoiceRoot.toLowerCase() !== anchorRoot.toLowerCase()) fail("ANCHOR_ROOT_MISMATCH");
  if (anchorState.receivableState !== 1) fail("ANCHOR_NOT_OUTSTANDING", String(anchorState.receivableState));
  if (anchorState.protectionState !== 1) fail("ANCHOR_PROTECTION_INACTIVE");

  if (options.mode === "check") {
    pool.stop();
    return { classification: "PRODUCT_PREFLIGHT", chainId, deployer: settings.deployer.address, balance: balance.toString(), anchor, anchorState };
  }

  const journal = (await readJournal(options.journal)) ?? emptyJournal();

  try {
    // 1. Three signer processes, each generating and holding only its own key.
    let signerAddresses;
    if (journal.signers?.addresses) {
      signerAddresses = journal.signers.addresses.map((address) => getAddress(address));
      for (let index = 1; index <= 3; index += 1) {
        pool.signers.push({ index, storage: resolve(options.signerRoot, `signer-${index}`), address: signerAddresses[index - 1] });
      }
    } else {
      signerAddresses = await pool.provision(3, null);
      const distinct = new Set(signerAddresses.map((address) => address.toLowerCase()));
      if (distinct.size !== 3 || distinct.has(settings.deployer.address.toLowerCase())) fail("SIGNER_IDENTITIES_INVALID");
      await advance(journal, options.journal, "SIGNERS_READY", { signers: { addresses: signerAddresses, storageRoot: options.signerRoot } });
    }

    // 2. Verifier bound to those three addresses, then the anchored consumer.
    const deploy = async (name, art, args) => {
      if (journal.setup?.[name]) return getAddress(journal.setup[name]);
      const data = encodeFunctionData ? undefined : undefined;
      const gasEstimate = await client.estimateGas({
        account: settings.deployer,
        data: (await import("viem")).encodeDeployData({ abi: art.abi, bytecode: art.bytecode, args }),
      });
      const gas = (gasEstimate * 130n) / 100n;
      if (gas > MAX_TRANSACTION_GAS) fail("SETUP_GAS_LIMIT", String(gas));
      const hash = await wallet.deployContract({ abi: art.abi, bytecode: art.bytecode, args, gas, ...(await fees()) });
      journal.setup = { ...(journal.setup ?? {}), [`${name}Hash`]: hash };
      await writeAtomic(options.journal, journal);
      const receipt = await client.waitForTransactionReceipt({ hash, pollingInterval: 1_000 });
      if (receipt.status !== "success") fail("SETUP_REVERTED", name);
      journal.setup = { ...journal.setup, [name]: getAddress(receipt.contractAddress) };
      await writeAtomic(options.journal, journal);
      return getAddress(receipt.contractAddress);
    };

    const verifier = await deploy("verifier", verifierArt, [settings.deployer.address, signerAddresses, QUORUM]);
    const consumer = await deploy("consumer", consumerArt, [
      verifier, anchor, POLICY_ID, POLICY_VERSION, RESPONSIBLE_ROLE, CURE_PERIOD, CONSEQUENCE_ID,
    ]);

    if (!journal.setup?.policyHash) {
      const hash = await wallet.writeContract({
        address: verifier, abi: verifierArt.abi, functionName: "setPolicyVersion",
        args: [anchor, POLICY_ID, POLICY_VERSION], gas: 200_000n, ...(await fees()),
      });
      journal.setup = { ...journal.setup, policyHash: hash };
      await writeAtomic(options.journal, journal);
      const receipt = await client.waitForTransactionReceipt({ hash, pollingInterval: 1_000 });
      if (receipt.status !== "success") fail("POLICY_CONFIG_REVERTED");
    }

    const validatorSetId = await read(verifier, verifierArt.abi, "validatorSetId");
    const quorum = await read(verifier, verifierArt.abi, "quorum");
    const configuredVersion = await read(verifier, verifierArt.abi, "currentPolicyVersion", [anchor, POLICY_ID]);
    if (Number(quorum) !== 2) fail("QUORUM_MISMATCH");
    if (Number(configuredVersion) !== POLICY_VERSION) fail("POLICY_NOT_CONFIGURED");
    const boundAnchor = await read(consumer, consumerArt.abi, "receivableAnchor");
    if (getAddress(boundAnchor) !== anchor) fail("CONSUMER_ANCHOR_MISMATCH");
    if (!(await read(consumer, consumerArt.abi, "anchorLive"))) fail("CONSUMER_ANCHOR_NOT_LIVE");

    await advance(journal, options.journal, "SETUP_CONFIRMED", {
      setup: { ...journal.setup, verifier, consumer, validatorSetId, policyVersion: POLICY_VERSION },
    });

    // 3. Dealerless confidential evaluation bound to the anchor and consumer.
    if (!journal.ceremony) {
      // A ceremony is one-shot: operators refuse to reuse storage, so each
      // attempt gets a fresh working directory. The evidence output path stays
      // stable so the retained bundle always names the same location.
      const attemptRoot = resolve(options.ceremonyRoot, `attempt-${Date.now()}`);
      await runCeremony({ repo: REPO, root: attemptRoot, out: options.ceremonyOut, vault: anchor, anchorRoot, consumer });
      const evaluator = JSON.parse(await readFile(resolve(options.ceremonyOut, "evaluator-result.json"), "utf8"));
      if (!evaluator.ok || !evaluator.conflictConfirmed) fail("CEREMONY_NO_CONFLICT");
      await advance(journal, options.journal, "CEREMONY_PROVEN", {
        ceremony: {
          out: options.ceremonyOut,
          inputCommitmentA: evaluator.inputCommitmentA,
          inputCommitmentB: evaluator.inputCommitmentB,
          providerProofCommitment: evaluator.providerProofCommitment,
          thresholdTranscript: evaluator.thresholdTranscriptCommitment,
          coalition: evaluator.coalition,
          custodyModel: evaluator.custodyModel,
          evaluatorCapabilities: evaluator.evaluatorCapabilities,
        },
      });
    }

    // 4. The fresh V3 result, bound to this consumer and this receivable.
    const plan = await reconcileAtomic({ journal, client });
    let openData = journal.session?.calldata ?? null;
    let result = journal.session?.result ? resultTuple(journal.session.result) : null;

    if (plan.action === "SUBMIT" && !openData) {
      const latest = await client.getBlock();
      const validUntil = BigInt(latest.timestamp) + BigInt(RESULT_TTL_SECONDS);
      const nonce = BigInt(`0x${Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex")}`);
      const core = {
        chainId: BigInt(CHAIN_ID), consumer, vault: anchor, policyId: POLICY_ID,
        policyVersion: POLICY_VERSION,
        inputCommitmentA: journal.ceremony.inputCommitmentA,
        inputCommitmentB: journal.ceremony.inputCommitmentB,
        conflictConfirmed: true, nonce, validUntil,
        providerProofCommitment: journal.ceremony.providerProofCommitment,
        resultCommitment: `0x${"00".repeat(32)}`,
      };
      core.resultCommitment = await read(verifier, verifierArt.abi, "resultCoreCommitment", [core]);
      result = core;

      // Freshness: none of the three one-time identities may be consumed.
      const replayKey = await read(verifier, verifierArt.abi, "replayKey", [core]);
      const decisionKey = await read(verifier, verifierArt.abi, "decisionKey", [core]);
      const consumed = {
        nonce: await read(verifier, verifierArt.abi, "consumedReplayKeys", [replayKey]),
        decision: await read(verifier, verifierArt.abi, "consumedDecisionKeys", [decisionKey]),
        providerProof: await read(verifier, verifierArt.abi, "consumedProviderProofCommitments", [core.providerProofCommitment]),
      };
      if (consumed.nonce || consumed.decision || consumed.providerProof) fail("RESULT_IDENTITY_CONSUMED", JSON.stringify(consumed));
      const record = await read(consumer, consumerArt.abi, "recourses", [core.resultCommitment]);
      if (Number(record[11]) !== 0) fail("RECOURSE_ALREADY_OPEN");
      const margin = Number(validUntil - BigInt(latest.timestamp));
      if (margin < MIN_EXPIRY_MARGIN_SECONDS) fail("RESULT_EXPIRY_MARGIN", String(margin));

      // 5. Two of three separate signer processes attest. This runner holds no key.
      await pool.start({ verifier, policyId: POLICY_ID, consumer, vault: anchor });
      const statuses = [];
      for (const signer of pool.signers) statuses.push(await pool.status(signer));
      const signed = [];
      for (const signer of pool.signers.slice(0, 2)) {
        const attestation = await pool.sign(signer, {
          chainId: CHAIN_ID, verifier, validatorSetId, result: jsonSafe(core),
        });
        signed.push({ address: signer.address, signature: attestation.signature, resultDigest: attestation.resultDigest });
      }
      signed.sort((left, right) => left.address.toLowerCase().localeCompare(right.address.toLowerCase()));
      const attestation = encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes[]" }],
        [validatorSetId, signed.map((entry) => entry.signature)],
      );
      openData = encodeFunctionData({ abi: consumerArt.abi, functionName: "openRecourse", args: [core, attestation] });

      await advance(journal, options.journal, "ATOMIC_PREPARED", {
        session: jsonSafe({
          verifier, consumer, anchor, validatorSetId, replayKey, decisionKey,
          attestingValidators: signed.map((entry) => entry.address),
          unselectedValidator: pool.signers[2].address,
          signerStatuses: statuses, result: core, calldata: openData,
          calldataBytes: (openData.length - 2) / 2, expirySecondsRemaining: margin,
        }),
      });
    }

    // 6. One atomic transaction. The hash is journalled before the receipt wait.
    let receipt = plan.receipt;
    if (plan.action === "SUBMIT") {
      const gasEstimate = await client.estimateGas({ account: settings.deployer, to: consumer, data: openData });
      const gas = (gasEstimate * 130n) / 100n;
      if (gas > MAX_TRANSACTION_GAS) fail("ATOMIC_GAS_LIMIT", String(gas));
      const submittedAt = Date.now();
      const hash = await wallet.sendTransaction({ to: consumer, data: openData, gas, ...(await fees()) });
      await advance(journal, options.journal, "ATOMIC_HASH_PERSISTED", {
        atomic: { hash, status: null, gasEstimate: gasEstimate.toString(), submittedAt: new Date(submittedAt).toISOString() },
      });
      receipt = await client.waitForTransactionReceipt({ hash, pollingInterval: 1_000 });
      if (receipt.status !== "success") fail("ATOMIC_REVERTED", hash);
      journal.atomic.latencyMs = Date.now() - submittedAt;
    }

    await advance(journal, options.journal, "ATOMIC_CONFIRMED", {
      atomic: {
        ...(journal.atomic ?? {}), hash: receipt.transactionHash, status: receipt.status,
        block: String(receipt.blockNumber), blockHash: receipt.blockHash,
        gasUsed: String(receipt.gasUsed), effectiveGasPrice: String(receipt.effectiveGasPrice ?? 0n),
      },
    });

    // 7. Events and readbacks.
    const verifierEvents = parseEventLogs({ abi: verifierArt.abi, logs: receipt.logs, eventName: "ConfidentialPolicyResultV3Accepted", strict: true });
    const recourseEvents = parseEventLogs({ abi: consumerArt.abi, logs: receipt.logs, eventName: "AnchoredRecourseOpened", strict: true });
    if (verifierEvents.length !== 1 || recourseEvents.length !== 1) fail("ATOMIC_EVENT_MISSING");

    result = result ?? resultTuple(journal.session.result);
    const replayKey = await read(verifier, verifierArt.abi, "replayKey", [result]);
    const decisionKey = await read(verifier, verifierArt.abi, "decisionKey", [result]);
    const record = await read(consumer, consumerArt.abi, "recourses", [result.resultCommitment]);
    const readbacks = {
      receivableAnchor: getAddress(await read(consumer, consumerArt.abi, "receivableAnchor")),
      anchorInvoiceRoot: await read(consumer, consumerArt.abi, "invoiceRoot"),
      anchorCurrency: await read(consumer, consumerArt.abi, "currency"),
      anchorLive: await read(consumer, consumerArt.abi, "anchorLive"),
      anchorReceivableState: Number(await read(anchor, vaultArt.abi, "receivableState")),
      anchorTotalSupply: (await read(anchor, vaultArt.abi, "totalSupply")).toString(),
      anchorBuyer: await read(anchor, vaultArt.abi, "buyer"),
      anchorOriginator: await read(anchor, vaultArt.abi, "originatorTreasury"),
      verifier, consumer, validatorSetId,
      policyId: await read(consumer, consumerArt.abi, "policyId"),
      policyVersion: Number(await read(consumer, consumerArt.abi, "policyVersion")),
      intendedConsumer: verifierEvents[0].args.consumer,
      resultCommitment: result.resultCommitment,
      providerProofCommitment: result.providerProofCommitment,
      nonceConsumed: await read(verifier, verifierArt.abi, "consumedReplayKeys", [replayKey]),
      decisionConsumed: await read(verifier, verifierArt.abi, "consumedDecisionKeys", [decisionKey]),
      providerProofConsumed: await read(verifier, verifierArt.abi, "consumedProviderProofCommitments", [result.providerProofCommitment]),
      recourseRecord: {
        resultCommitment: record[0], providerProofCommitment: record[1],
        inputCommitmentA: record[2], inputCommitmentB: record[3],
        policyId: record[4], policyVersion: Number(record[5]),
        responsibleRole: record[6], consequenceId: record[7], invoiceRoot: record[8],
        acceptedAt: String(record[9]), cureDeadline: String(record[10]), status: Number(record[11]),
      },
      events: {
        verifier: jsonSafe(verifierEvents[0].args),
        recourse: jsonSafe(recourseEvents[0].args),
      },
    };
    const checks = {
      anchorIsBoundReceivable: readbacks.receivableAnchor === anchor,
      anchorRootMatchesRecord: readbacks.recourseRecord.invoiceRoot.toLowerCase() === anchorRoot.toLowerCase(),
      intendedConsumerBound: getAddress(readbacks.intendedConsumer) === consumer,
      responsibilityDerived: readbacks.recourseRecord.responsibleRole === RESPONSIBLE_ROLE,
      consequenceDerived: readbacks.recourseRecord.consequenceId === CONSEQUENCE_ID,
      cureDeadlineDerived: BigInt(readbacks.recourseRecord.cureDeadline) === BigInt(readbacks.recourseRecord.acceptedAt) + CURE_PERIOD,
      statusOpen: readbacks.recourseRecord.status === 1,
      allIdentitiesConsumed: readbacks.nonceConsumed && readbacks.decisionConsumed && readbacks.providerProofConsumed,
      zeroValue: true,
      noAssetMovement: receipt.logs.length === 2,
    };
    if (Object.values(checks).some((value) => value !== true)) fail("READBACK_FAILED", JSON.stringify(checks));
    await advance(journal, options.journal, "READBACKS_CONFIRMED", { readbacks: jsonSafe({ ...readbacks, checks }) });

    // 8. Replay refused, proven by eth_call only.
    let replayRefused = false, replayError = null;
    try {
      await client.call({ to: consumer, data: openData, account: settings.deployer.address });
    } catch (error) { replayRefused = true; replayError = String(error?.shortMessage ?? error?.message ?? "").slice(0, 200); }
    if (!replayRefused) fail("REPLAY_ACCEPTED");
    await advance(journal, options.journal, "REPLAY_REJECTED", { replay: { refused: true, viaEthCallOnly: true, detail: replayError } });

    const report = {
      schemaVersion: REPORT_SCHEMA,
      classification: "ANCHORED CONFIDENTIAL RECOURSE: PROVEN (TEST ASSETS ONLY)",
      testAssetsOnly: true,
      network: { chainId, deployer: settings.deployer.address },
      receivableAnchor: { address: anchor, ...anchorState },
      setup: journal.setup,
      signers: {
        addresses: journal.signers.addresses,
        statuses: journal.session?.signerStatuses ?? null,
        attesting: journal.session?.attestingValidators ?? null,
        unselected: journal.session?.unselectedValidator ?? null,
        runnerHoldsNoValidatorKey: true,
      },
      ceremony: journal.ceremony,
      result: journal.session?.result ?? null,
      atomic: journal.atomic,
      readbacks: journal.readbacks,
      replay: journal.replay,
      generatedAt: new Date().toISOString(),
    };
    await advance(journal, options.journal, "PRODUCT_CLAIM_READY", {});
    await writeAtomic(options.out, report);
    return report;
  } finally {
    pool.stop();
  }
}

async function runCeremony({ repo, root, out, vault, anchorRoot, consumer }) {
  await mkdir(dirname(root), { recursive: true });
  const binary = resolve(root, "..", "ceremony-lab-bin");
  await new Promise((done, reject) => {
    const build = spawn("go", ["build", "-o", binary, "./cmd/ceremony-lab"], { cwd: resolve(repo, "fhe-lab/lattigo"), stdio: "inherit" });
    build.once("exit", (code) => (code === 0 ? done() : reject(new RunError("CEREMONY_BUILD_FAILED"))));
  });
  await new Promise((done, reject) => {
    const child = spawn(binary, [
      "-out", out, "-repo", resolve(repo, "fhe-lab/lattigo"), "-root", root,
      "-vault", vault, "-anchor-root", anchorRoot, "-policy-label", POLICY_LABEL,
    ], { stdio: "inherit" });
    child.once("exit", (code) => (code === 0 ? done() : reject(new RunError("CEREMONY_FAILED", String(code)))));
  });
  return { consumer };
}

export function parseArgs(argv) {
  let mode = null;
  const options = {
    out: resolve(HERE, "artifacts/anchored-recourse-latest.json"),
    journal: resolve(HERE, "artifacts/anchored-recourse-journal.json"),
    anchor: resolve(HERE, "artifacts/receivable-anchor.json"),
    signerRoot: resolve(HERE, "artifacts/.signers"),
    ceremonyRoot: resolve(HERE, "artifacts/.ceremony"),
    ceremonyOut: resolve(HERE, "artifacts/anchored-ceremony-evidence"),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--check") { mode = "check"; continue; }
    if (flag === "--run") { mode = "run"; continue; }
    for (const key of ["out", "journal", "anchor", "signerRoot", "ceremonyRoot", "ceremonyOut"]) {
      const dashed = `--${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`;
      if (flag === dashed && argv[index + 1]) { options[key] = resolve(process.cwd(), argv[++index]); }
    }
  }
  if (!mode) fail("MODE_REQUIRED");
  return { mode, ...options };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    const report = await run();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, code: error.code ?? error.message, detail: error.message })}\n`);
    process.exitCode = 1;
  }
}
