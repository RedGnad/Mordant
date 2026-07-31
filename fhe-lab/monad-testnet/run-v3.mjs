#!/usr/bin/env node

// Bounded V3 laboratory runner. It is intentionally isolated from V2 and drives
// only the V3 verifier plus the non-economic LaboratoryRecourseConsumer.
//
// The runner is crash-safe: a public journal is written with atomic
// temp-and-rename semantics before and after every network side effect, and a
// transaction hash is persisted before the receipt is awaited. A restart never
// resubmits an operation whose outcome is unknown; it reconciles the persisted
// hash against receipt, events and contract state, or stops with a specific
// recovery classification.
//
// The journal holds public evidence only: addresses, hashes, commitments,
// block metadata and gate results. No ciphertext, no pledge field, no key
// material and no environment value is ever written to it.

import { readFile, mkdir, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import {
  createPublicClient, createWalletClient, defineChain, encodeAbiParameters,
  encodeDeployData, encodeFunctionData, getAddress, getContractAddress, http,
  isAddress, keccak256, parseEventLogs, stringToHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { V3_ATTESTATION_TYPES, V3_EIP712_NAME, V3_EIP712_VERSION } from "../shared/scripts/canonical-v3.mjs";
import { lastProcessRunRoot, runProcessSeparatedV3 } from "../privacy-v3/process-run.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const LAB = resolve(HERE, "..");

export const CHAIN_ID = 10_143;
export const POLICY_ID = "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540";
export const POLICY_VERSION = 1;
export const QUORUM = 2;
export const CURE_PERIOD_SECONDS = 3_600n;
export const RESULT_TTL_SECONDS = 1_800;
export const MIN_EXPIRY_MARGIN_SECONDS = 300;
export const MAX_CREATION_BYTES = 131_072;
export const MAX_TRANSACTION_GAS = 30_000_000n;
export const MAX_GAS_PRICE_WEI = 200_000_000_000n;
export const REPORT_SCHEMA = "mordant.fhe-monad-v3-recourse/1";
export const JOURNAL_SCHEMA = "mordant.fhe-monad-v3-journal/1";
export const JOURNAL_PATH = resolve(HERE, "artifacts/privacy-v3-journal.json");

export const RESPONSIBLE_ROLE = keccak256(stringToHex("mordant.role.facility.v1"));
export const CONSEQUENCE_ID = keccak256(stringToHex("mordant.consequence.review-required.v1"));

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// Confirmed existing laboratory infrastructure. These are public transaction
// hashes, treated as an input to reconciliation, never as proof of a later run.
export const KNOWN_SETUP = Object.freeze({
  verifier: "0xeab86cb49731deca61b36517e6e3389a3c654b2753face718a2af58a0a4d0b0e",
  consumer: "0x5e1efb1b625267a69b0a42f33794e32c56d16b808c435c6ee91af0ab9d65b113",
  policy: "0xcf1b8d8fad00d7c96312ff85ee3b0895cb31494848728f7ca0a060ab0c585093",
});

export const STATES = Object.freeze([
  "PREFLIGHT", "SETUP_RECONCILED", "PROCESS_WORKFLOW_STARTED", "PROCESS_WORKFLOW_PROVEN",
  "ATOMIC_PREPARED", "ATOMIC_HASH_PERSISTED", "ATOMIC_CONFIRMED", "READBACKS_CONFIRMED",
  "REPLAY_REJECTED", "PRIVACY_CLAIM_READY",
]);

// Field names that must never appear in a public artifact. Mirrors the
// recursive leak scanner so the runner fails before writing, not after.
const RESTRICTED_FIELD_NAMES = /plaintext|private.?key|threshold.?share|credential|certificate.*private|secret/i;

export class V3RunnerError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "V3RunnerError";
    this.code = code;
    this.detail = detail ?? null;
  }
}

function fail(code, detail) { throw new V3RunnerError(code, detail); }
function required(value, code) { if (typeof value !== "string" || !value.trim()) fail(code); return value.trim(); }
function privateKeyField(value, code) {
  const key = required(value, code);
  if (!/^0x[\da-fA-F]{64}$/.test(key)) fail(code);
  return key;
}
function addressField(value, code) {
  const value_ = required(value, code);
  if (!isAddress(value_) || value_.toLowerCase() === ZERO_ADDRESS) fail(code);
  return getAddress(value_);
}
function same(left, right) {
  const normalize = (value) => (typeof value === "string" ? value.toLowerCase() : String(value));
  return normalize(left) === normalize(right);
}
function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value, (_key, item) => (typeof item === "bigint" ? item.toString() : item)));
}

export function parseArgs(argv) {
  let mode = null;
  let out = null;
  let journal = JOURNAL_PATH;
  let newSession = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if ((flag === "--check" || flag === "--run") && !mode) { mode = flag.slice(2); continue; }
    if (flag === "--out" && !out && argv[index + 1]) { out = resolve(process.cwd(), argv[++index]); continue; }
    if (flag === "--journal" && argv[index + 1]) { journal = resolve(process.cwd(), argv[++index]); continue; }
    if (flag === "--new-session" && !newSession) { newSession = true; continue; }
    fail("CLI_ARGUMENT", flag);
  }
  if (!mode) fail("CLI_MODE_REQUIRED");
  if ((mode === "run") !== Boolean(out)) fail("CLI_OUT_REQUIRED");
  return { mode, out, journal, newSession };
}

// A new confidential session is allowed only from a settled journal. A pending,
// unknown or reverted atomic operation must be reconciled first; it is never
// discarded to make room for a retry.
export async function archiveSettledJournal(path, journal, rename_ = rename) {
  if (!journal?.atomic?.hash) return { archived: false, reason: "no-atomic-operation" };
  if (journal.state !== "PRIVACY_CLAIM_READY") fail("NEW_SESSION_REFUSED_UNSETTLED", journal.state);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const target = `${path.replace(/\.json$/, "")}.${stamp}.json`;
  await rename_(path, target);
  return { archived: true, target };
}

export function config(env = process.env) {
  const deployer = privateKeyToAccount(privateKeyField(env.FHE_MONAD_DEPLOYER_PRIVATE_KEY, "CONFIG_DEPLOYER_KEY"));
  const declared = addressField(env.FHE_MONAD_DEPLOYER_ADDRESS, "CONFIG_DEPLOYER_ADDRESS");
  if (!same(deployer.address, declared)) fail("DEPLOYER_ADDRESS_MISMATCH");
  const validators = [1, 2, 3].map((index) =>
    privateKeyToAccount(privateKeyField(env[`FHE_MONAD_VALIDATOR_${index}_PRIVATE_KEY`], `CONFIG_VALIDATOR_${index}_KEY`)));
  const distinct = new Set(validators.map((validator) => validator.address.toLowerCase()));
  if (distinct.size !== 3 || distinct.has(deployer.address.toLowerCase())) fail("VALIDATOR_IDENTITIES_INVALID");
  return {
    rpc: required(env.FHE_MONAD_RPC_URL, "CONFIG_RPC_URL"),
    deployer,
    validators,
    vault: addressField(env.FHE_MONAD_TEST_VAULT, "CONFIG_TEST_VAULT"),
  };
}

function monadChain(rpc) {
  return defineChain({
    id: CHAIN_ID,
    name: "Monad testnet",
    nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
  });
}

export async function artifact(name) {
  let raw;
  try {
    raw = await readFile(resolve(LAB, `monad-adapter/out/${name}.sol/${name}.json`), "utf8");
  } catch { fail("V3_ARTIFACT_MISSING", name); }
  const parsed = JSON.parse(raw);
  if (!parsed.abi || !/^0x[\da-fA-F]+$/.test(parsed.bytecode?.object ?? "")) fail("V3_ARTIFACT_INVALID", name);
  if (!/^0x[\da-fA-F]+$/.test(parsed.deployedBytecode?.object ?? "")) fail("V3_ARTIFACT_INVALID", name);
  return {
    abi: parsed.abi,
    bytecode: parsed.bytecode.object,
    deployedBytecode: parsed.deployedBytecode.object,
    immutableReferences: parsed.deployedBytecode.immutableReferences ?? {},
  };
}

function byteLength(hex) { return (hex.length - 2) / 2; }

// Deployed runtime bytecode carries constructor immutables inline, so a raw
// comparison against the compiler artifact always differs. Masking the
// immutable ranges compares contract identity rather than configuration; the
// configuration itself is verified separately through public getters.
export function maskImmutables(code, immutableReferences) {
  if (typeof code !== "string" || !code.startsWith("0x")) return null;
  const bytes = Buffer.from(code.slice(2), "hex");
  for (const ranges of Object.values(immutableReferences ?? {})) {
    for (const { start, length } of ranges) bytes.fill(0, start, start + length);
  }
  return keccak256(`0x${bytes.toString("hex")}`);
}

/* ------------------------------------------------------------------ journal */

export function assertPublicOnly(value, code = "ARTIFACT_RESTRICTED_FIELD") {
  const serialized = JSON.stringify(value);
  if (serialized !== undefined && RESTRICTED_FIELD_NAMES.test(serialized)) fail(code);
  return value;
}

export async function writeAtomic(path, value) {
  assertPublicOnly(value);
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`);
  await rename(temporary, path);
}

export async function readJournal(path) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    if (parsed?.schemaVersion !== JOURNAL_SCHEMA) return null;
    return parsed;
  } catch { return null; }
}

export function emptyJournal() {
  return {
    schemaVersion: JOURNAL_SCHEMA,
    chainId: CHAIN_ID,
    testAssetsOnly: true,
    state: "PREFLIGHT",
    history: [],
    setup: null,
    session: null,
    atomic: null,
    readbacks: null,
    replay: null,
    processEvidence: null,
    failure: null,
  };
}

// Every advance is persisted before the side effect it authorises and again
// after that side effect resolves.
export async function advance(journal, path, state, patch = {}) {
  if (!STATES.includes(state)) fail("JOURNAL_UNKNOWN_STATE", state);
  Object.assign(journal, patch);
  journal.state = state;
  journal.history.push({ state, at: new Date().toISOString() });
  await writeAtomic(path, journal);
  return journal;
}

// A failure classification never deletes previously confirmed evidence.
export async function recordFailure(journal, path, code, detail) {
  journal.failure = { code, detail: detail ?? null, state: journal.state, at: new Date().toISOString() };
  try { await writeAtomic(path, journal); } catch { /* the thrown gate stays authoritative */ }
  return journal;
}

/* ------------------------------------------------------- throttled RPC layer */

// The public Monad testnet endpoint rejects bursts above a documented
// per-second budget. Every read and write is serialised through one queue with
// backoff, so a confirmed transaction is never lost to a transport rejection
// during its own readback.
export function createThrottle({ minIntervalMs = 150, attempts = 6, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  let last = 0;
  let chain = Promise.resolve();
  return function throttled(action, label) {
    const run = async () => {
      for (let attempt = 0; ; attempt += 1) {
        const wait = Math.max(0, minIntervalMs - (Date.now() - last));
        if (wait > 0) await sleep(wait);
        last = Date.now();
        try { return await action(); } catch (error) {
          const message = `${error?.details ?? ""}${error?.shortMessage ?? ""}${error?.message ?? ""}`;
          if (attempt + 1 < attempts && /limited|rate|429|timeout|socket|ECONNRESET|fetch failed/i.test(message)) {
            await sleep(1_000 * (attempt + 1));
            continue;
          }
          throw Object.assign(error, { rpcLabel: label });
        }
      }
    };
    chain = chain.then(run, run);
    return chain;
  };
}

export function createChainAdapter(client, artifacts, throttle) {
  return {
    async receipt(hash) {
      try { return await throttle(() => client.getTransactionReceipt({ hash }), `receipt:${hash}`); }
      catch { return null; }
    },
    async transaction(hash) {
      try { return await throttle(() => client.getTransaction({ hash }), `tx:${hash}`); }
      catch { return null; }
    },
    code(address) { return throttle(() => client.getCode({ address }), `code:${address}`); },
    read(address, which, functionName, args = []) {
      return throttle(
        () => client.readContract({ address, abi: artifacts[which].abi, functionName, args }),
        `${which}.${functionName}`,
      );
    },
  };
}

/* --------------------------------------------------- setup reconciliation */

// Pure invariant comparison. Every public value that binds the laboratory to
// this policy must match before the setup may be reused.
export function classifySetup(observed, expected) {
  if (!observed?.verifier?.address || !observed?.consumer?.address) {
    return { classification: "SETUP_INCOMPLETE", mismatches: [{ field: "addresses", observed: null, expected: "verifier and consumer" }] };
  }
  if (!observed.verifier.codeHash || !observed.consumer.codeHash) {
    return { classification: "SETUP_INCOMPLETE", mismatches: [{ field: "runtimeBytecode", observed: null, expected: "deployed code" }] };
  }
  const mismatches = [];
  const check = (field, actual, want) => {
    if (!same(actual, want)) mismatches.push({ field, observed: actual === undefined ? null : String(actual), expected: String(want) });
  };

  check("verifier.identityHash", observed.verifier.codeHash, expected.verifierCodeHash);
  check("consumer.identityHash", observed.consumer.codeHash, expected.consumerCodeHash);
  check("verifier.owner", observed.verifier.owner, expected.owner);
  check("verifier.quorum", observed.verifier.quorum, expected.quorum);
  check("verifier.domainName", observed.verifier.domainName, expected.domainName);
  check("verifier.domainVersion", observed.verifier.domainVersion, expected.domainVersion);
  check("verifier.policyVersionForVault", observed.verifier.policyVersionForVault, expected.policyVersion);
  for (const validator of expected.validators) {
    if (observed.verifier.validatorsActive?.[validator.toLowerCase()] !== true) {
      mismatches.push({ field: `verifier.validator.${validator}`, observed: "inactive", expected: "active" });
    }
  }
  if (observed.verifier.deployerIsValidator !== false) {
    mismatches.push({ field: "verifier.deployerIsValidator", observed: "true", expected: "false" });
  }
  check("consumer.verifier", observed.consumer.verifier, observed.verifier.address);
  check("consumer.vault", observed.consumer.vault, expected.vault);
  check("consumer.policyId", observed.consumer.policyId, expected.policyId);
  check("consumer.policyVersion", observed.consumer.policyVersion, expected.policyVersion);
  check("consumer.responsibleRole", observed.consumer.responsibleRole, expected.responsibleRole);
  check("consumer.curePeriod", observed.consumer.curePeriod, expected.curePeriod);
  check("consumer.consequenceId", observed.consumer.consequenceId, expected.consequenceId);

  return { classification: mismatches.length === 0 ? "SETUP_REUSABLE" : "SETUP_MISMATCH", mismatches };
}

// Resolves persisted setup transaction hashes into confirmed addresses without
// ever resubmitting. An unknown or still-pending hash is terminal.
export async function resolveSetupTransactions(hashes, chain) {
  const resolved = {};
  for (const [label, hash] of Object.entries(hashes)) {
    if (!hash) return { classification: "SETUP_INCOMPLETE", reason: `${label}:absent`, resolved };
    const receipt = await chain.receipt(hash);
    if (!receipt) {
      const pending = await chain.transaction(hash);
      return {
        classification: pending ? "SETUP_INCOMPLETE" : "SETUP_UNRECOVERABLE",
        reason: pending ? `${label}:pending` : `${label}:unknown-transaction`,
        resolved,
      };
    }
    if (receipt.status !== "success") {
      return { classification: "SETUP_UNRECOVERABLE", reason: `${label}:reverted`, resolved };
    }
    resolved[label] = {
      hash,
      status: receipt.status,
      block: String(receipt.blockNumber),
      blockHash: receipt.blockHash,
      address: receipt.contractAddress ? getAddress(receipt.contractAddress) : null,
      to: receipt.to ? getAddress(receipt.to) : null,
    };
  }
  return { classification: "RESOLVED", reason: null, resolved };
}

export async function observeSetup(resolved, chain, expected, artifacts) {
  const verifierAddress = resolved.verifier?.address;
  const consumerAddress = resolved.consumer?.address;
  if (!verifierAddress || !consumerAddress) return { verifier: {}, consumer: {} };
  const verifierCode = await chain.code(verifierAddress);
  const consumerCode = await chain.code(consumerAddress);
  const verifier = {
    address: verifierAddress,
    codeSize: verifierCode ? byteLength(verifierCode) : 0,
    codeHash: verifierCode ? maskImmutables(verifierCode, artifacts.verifier.immutableReferences) : null,
    owner: await chain.read(verifierAddress, "verifier", "owner"),
    quorum: String(await chain.read(verifierAddress, "verifier", "quorum")),
    validatorSetId: await chain.read(verifierAddress, "verifier", "validatorSetId"),
    domainName: await chain.read(verifierAddress, "verifier", "DOMAIN_NAME"),
    domainVersion: await chain.read(verifierAddress, "verifier", "DOMAIN_VERSION"),
    validatorsActive: {},
    deployerIsValidator: await chain.read(verifierAddress, "verifier", "validators", [expected.owner]),
    policyVersionForVault: String(await chain.read(verifierAddress, "verifier", "currentPolicyVersion", [expected.vault, expected.policyId])),
  };
  for (const validator of expected.validators) {
    verifier.validatorsActive[validator.toLowerCase()] =
      await chain.read(verifierAddress, "verifier", "validators", [validator]);
  }
  const consumer = {
    address: consumerAddress,
    codeSize: consumerCode ? byteLength(consumerCode) : 0,
    codeHash: consumerCode ? maskImmutables(consumerCode, artifacts.consumer.immutableReferences) : null,
    verifier: await chain.read(consumerAddress, "consumer", "verifier"),
    vault: await chain.read(consumerAddress, "consumer", "vault"),
    policyId: await chain.read(consumerAddress, "consumer", "policyId"),
    policyVersion: String(await chain.read(consumerAddress, "consumer", "policyVersion")),
    responsibleRole: await chain.read(consumerAddress, "consumer", "responsibleRole"),
    curePeriod: String(await chain.read(consumerAddress, "consumer", "curePeriod")),
    consequenceId: await chain.read(consumerAddress, "consumer", "consequenceId"),
  };
  return { verifier, consumer };
}

export async function reconcileSetup({ journal, chain, expected, artifacts, hashes }) {
  const candidate = journal?.setup?.hashes ?? hashes ?? KNOWN_SETUP;
  const resolution = await resolveSetupTransactions(candidate, chain);
  if (resolution.classification !== "RESOLVED") {
    return { classification: resolution.classification, reason: resolution.reason, hashes: candidate, resolved: resolution.resolved, observed: null, mismatches: [] };
  }
  if (!same(resolution.resolved.policy.to, resolution.resolved.verifier.address)) {
    return {
      classification: "SETUP_MISMATCH", reason: "policy-transaction-target", hashes: candidate,
      resolved: resolution.resolved, observed: null,
      mismatches: [{ field: "policy.to", observed: resolution.resolved.policy.to, expected: resolution.resolved.verifier.address }],
    };
  }
  const observed = await observeSetup(resolution.resolved, chain, expected, artifacts);
  const verdict = classifySetup(observed, expected);
  return {
    classification: verdict.classification, reason: null, hashes: candidate,
    resolved: resolution.resolved, observed, mismatches: verdict.mismatches,
  };
}

/* -------------------------------------------------- atomic reconciliation */

// Decides whether a fresh atomic submission is allowed. It never authorises a
// resubmission of a logical operation whose transaction hash is already known.
export async function reconcileAtomic({ journal, chain }) {
  const atomic = journal?.atomic;
  if (!atomic?.hash) return { action: "SUBMIT", code: null, receipt: null };
  const receipt = await chain.receipt(atomic.hash);
  if (!receipt) {
    const pending = await chain.transaction(atomic.hash);
    return {
      action: "STOP",
      code: pending ? "ATOMIC_PENDING_UNKNOWN" : "ATOMIC_UNKNOWN_TRANSACTION",
      receipt: null,
    };
  }
  if (receipt.status !== "success") return { action: "STOP", code: "ATOMIC_REVERTED", receipt };
  return { action: "RESUME_CONFIRMED", code: null, receipt };
}

// A fresh submission is refused whenever the chain already consumed any of the
// three one-time identities carried by this result.
export async function assertResultIdentityUnconsumed({ chain, verifier, consumer, result, replayKey, decisionKey }) {
  const consumed = {
    nonce: await chain.read(verifier, "verifier", "consumedReplayKeys", [replayKey]),
    decision: await chain.read(verifier, "verifier", "consumedDecisionKeys", [decisionKey]),
    providerProof: await chain.read(verifier, "verifier", "consumedProviderProofCommitments", [result.providerProofCommitment]),
  };
  const record = await chain.read(consumer, "consumer", "recourses", [result.resultCommitment]);
  const opened = Array.isArray(record) ? Number(record[10]) !== 0 : Number(record?.status ?? 0) !== 0;
  if (consumed.nonce || consumed.decision || consumed.providerProof || opened) {
    fail("RESULT_IDENTITY_CONSUMED", JSON.stringify({ ...consumed, recourseOpened: opened }));
  }
  return consumed;
}

/* ------------------------------------------------------------- transactions */

async function estimateAndSend({ wallet, client, throttle, request, label }) {
  let gas;
  try {
    gas = await throttle(() => client.estimateGas({ ...request, account: wallet.account.address }), `estimate:${label}`);
  } catch (error) { fail(`${label}_GAS_UNAVAILABLE`, error?.shortMessage ?? error?.message); }
  if (gas === 0n || gas > MAX_TRANSACTION_GAS) fail(`${label}_GAS_LIMIT`, String(gas));
  const limit = (gas * 125n) / 100n;
  if (limit > MAX_TRANSACTION_GAS) fail(`${label}_GAS_LIMIT`, String(limit));
  const hash = await throttle(() => wallet.sendTransaction({ ...request, gas: limit }), `send:${label}`);
  return { hash, gasEstimate: gas.toString(), gasLimit: limit.toString() };
}

async function awaitReceipt({ client, throttle, hash, label }) {
  const receipt = await throttle(
    () => client.waitForTransactionReceipt({ hash, pollingInterval: 1_000, retryDelay: 1_000 }),
    `wait:${label}`,
  );
  if (receipt.status !== "success") fail(`${label}_REVERTED`, hash);
  return receipt;
}

/* -------------------------------------------------------------------- run */

export async function run(options = parseArgs(process.argv.slice(2)), deps = {}) {
  // The six-process capture holds the two client-private canary manifests until
  // the runner has produced its own public artifacts. Whatever happens after
  // that capture, the manifests must be swept and removed before returning.
  let pendingSeal = null;
  try {
    return await runGuarded(options, deps, (seal) => { pendingSeal = seal; });
  } finally {
    if (pendingSeal) { try { await pendingSeal(); } catch { /* the original outcome stays authoritative */ } }
  }
}

async function runGuarded(options, deps, registerSeal) {
  const settings = config(deps.env ?? process.env);
  const artifacts = {
    verifier: await artifact("ECDSAQuorumConfidentialPolicyVerifierV3"),
    consumer: await artifact("LaboratoryRecourseConsumer"),
  };
  const expected = {
    owner: settings.deployer.address,
    quorum: String(QUORUM),
    validators: settings.validators.map((validator) => validator.address),
    vault: settings.vault,
    policyId: POLICY_ID,
    policyVersion: String(POLICY_VERSION),
    responsibleRole: RESPONSIBLE_ROLE,
    consequenceId: CONSEQUENCE_ID,
    curePeriod: String(CURE_PERIOD_SECONDS),
    domainName: "Mordant Confidential Policy",
    domainVersion: "3",
    verifierCodeHash: maskImmutables(artifacts.verifier.deployedBytecode, artifacts.verifier.immutableReferences),
    consumerCodeHash: maskImmutables(artifacts.consumer.deployedBytecode, artifacts.consumer.immutableReferences),
  };

  const chainDefinition = monadChain(settings.rpc);
  const client = deps.client ?? createPublicClient({ chain: chainDefinition, transport: http(settings.rpc), pollingInterval: 1_000 });
  const throttle = deps.throttle ?? createThrottle();
  const chain = deps.chain ?? createChainAdapter(client, artifacts, throttle);

  const report = {
    schemaVersion: REPORT_SCHEMA,
    testAssetsOnly: true,
    classification: "MONAD V3 ATOMIC RECOURSE: NOT PROVEN",
    mode: options.mode,
    network: null,
    setup: null,
    processEvidence: null,
    transactions: { setupVerifier: null, setupConsumer: null, setupPolicy: null, openRecourse: null },
    result: null,
    readbacks: null,
    events: null,
    replay: null,
    leakScan: null,
    performance: null,
  };

  /* ---- PREFLIGHT: read-only ---- */
  const chainId = await throttle(() => client.getChainId(), "chainId");
  if (chainId !== CHAIN_ID) fail("CHAIN_ID_MISMATCH", String(chainId));
  const balance = await throttle(() => client.getBalance({ address: settings.deployer.address }), "balance");
  const accountNonce = await throttle(() => client.getTransactionCount({ address: settings.deployer.address }), "nonce");
  const gasPrice = await throttle(() => client.getGasPrice(), "gasPrice");
  if (balance === 0n) fail("DEPLOYER_MON_INSUFFICIENT");
  if (gasPrice > MAX_GAS_PRICE_WEI) fail("GAS_PRICE_ABOVE_BOUND", gasPrice.toString());
  const verifierInit = encodeDeployData({
    abi: artifacts.verifier.abi, bytecode: artifacts.verifier.bytecode,
    args: [settings.deployer.address, expected.validators, BigInt(QUORUM)],
  });
  if (byteLength(verifierInit) > MAX_CREATION_BYTES || byteLength(artifacts.consumer.bytecode) > MAX_CREATION_BYTES) {
    fail("MONAD_CODE_SIZE_LIMIT");
  }
  report.network = {
    chainId, balance: balance.toString(), nonce: String(accountNonce), gasPrice: gasPrice.toString(),
    deployer: settings.deployer.address, validators: expected.validators, vault: settings.vault,
  };

  const setupState = await reconcileSetup({ journal: await readJournal(options.journal), chain, expected, artifacts });
  report.setup = {
    classification: setupState.classification,
    reason: setupState.reason,
    mismatches: setupState.mismatches,
    hashes: setupState.hashes,
    verifier: setupState.observed?.verifier?.address ?? null,
    consumer: setupState.observed?.consumer?.address ?? null,
    validatorSetId: setupState.observed?.verifier?.validatorSetId ?? null,
    policyId: POLICY_ID,
    policyVersion: POLICY_VERSION,
  };

  if (options.mode === "check") {
    report.classification = setupState.classification === "SETUP_REUSABLE"
      ? "MONAD V3 PREFLIGHT: READY"
      : "MONAD V3 PREFLIGHT: BLOCKED";
    assertPublicOnly(report);
    return report;
  }

  /* ---- write path ---- */
  if (setupState.classification !== "SETUP_REUSABLE") {
    fail(`SETUP_NOT_REUSABLE_${setupState.classification}`, setupState.reason ?? JSON.stringify(setupState.mismatches));
  }

  let existing = await readJournal(options.journal);
  if (options.newSession && existing) {
    const archived = await archiveSettledJournal(options.journal, existing);
    if (archived.archived) existing = null;
  }
  const journal = existing ?? emptyJournal();
  journal.failure = null;
  const verifier = setupState.observed.verifier.address;
  const consumer = setupState.observed.consumer.address;
  await advance(journal, options.journal, "SETUP_RECONCILED", {
    setup: {
      source: journal.setup?.source ?? "confirmed-existing-infrastructure",
      hashes: setupState.hashes,
      resolved: setupState.resolved,
      verifier,
      consumer,
      classification: setupState.classification,
      validatorSetId: setupState.observed.verifier.validatorSetId,
      observed: setupState.observed,
    },
  });
  report.transactions.setupVerifier = setupState.resolved.verifier;
  report.transactions.setupConsumer = setupState.resolved.consumer;
  report.transactions.setupPolicy = setupState.resolved.policy;

  const atomicPlan = await reconcileAtomic({ journal, chain });
  if (atomicPlan.action === "STOP") {
    await recordFailure(journal, options.journal, atomicPlan.code, journal.atomic?.hash ?? null);
    fail(atomicPlan.code, journal.atomic?.hash ?? null);
  }

  const started = performance.now();
  const wallet = deps.wallet ?? createWalletClient({ account: settings.deployer, chain: chainDefinition, transport: http(settings.rpc) });

  let openData = journal.session?.calldata ?? null;
  let result = journal.session?.result ?? null;
  let processRun = null;
  let processMilliseconds = null;
  let seal = null;

  if (atomicPlan.action === "SUBMIT") {
    /* ---- fresh six-process confidential workflow ---- */
    await advance(journal, options.journal, "PROCESS_WORKFLOW_STARTED", { session: null, atomic: null, readbacks: null, replay: null });
    const processStarted = performance.now();
    const validUntil = String(Math.floor(Date.now() / 1000) + RESULT_TTL_SECONDS);
    try {
      processRun = await runProcessSeparatedV3({
        root: null, chainId: String(CHAIN_ID), vault: settings.vault,
        policyId: POLICY_ID, consumer, nonce: null, validUntil,
      });
    } catch (error) {
      await recordFailure(journal, options.journal, error.code ?? "PROCESS_RUN_FAILED", lastProcessRunRoot());
      throw error;
    }
    processMilliseconds = Number((performance.now() - processStarted).toFixed(2));
    // Seal exactly once, whether the run succeeds or aborts below.
    let sealed = null;
    seal = async (extraRoots = []) => {
      if (sealed === null) sealed = await processRun.sealEvidence(extraRoots);
      return sealed;
    };
    registerSeal(seal);
    result = processRun.result.result;
    if (!result.conflictConfirmed) {
      await recordFailure(journal, options.journal, "FHE_CONFLICT_NOT_CONFIRMED", null);
      fail("FHE_CONFLICT_NOT_CONFIRMED");
    }
    if (!processRun.leakScan.ok) {
      await recordFailure(journal, options.journal, "PROCESS_RUN_LEAK_SCAN", null);
      fail("PROCESS_RUN_LEAK_SCAN");
    }
    if (!same(result.consumer, consumer)) {
      await recordFailure(journal, options.journal, "RESULT_CONSUMER_MISMATCH", result.consumer);
      fail("RESULT_CONSUMER_MISMATCH", result.consumer);
    }

    const evidence = {
      root: processRun.root,
      publicRoot: processRun.publicRoot,
      lifecycle: processRun.lifecycle,
      nodes: processRun.result.nodes ?? null,
      leakScan: { ok: processRun.leakScan.ok, scannedFiles: processRun.leakScan.generic.scannedFiles, canaries: processRun.leakScan.canaries.canaries, leaks: processRun.leakScan.canaries.leaks },
      providerProof: processRun.result.providerProof ?? null,
    };
    await advance(journal, options.journal, "PROCESS_WORKFLOW_PROVEN", { processEvidence: jsonSafe(evidence) });

    /* ---- prepare the atomic transaction ---- */
    const validatorSetId = await chain.read(verifier, "verifier", "validatorSetId");
    const digest = await chain.read(verifier, "verifier", "resultDigest", [result]);
    const replayKey = await chain.read(verifier, "verifier", "replayKey", [result]);
    const decisionKey = await chain.read(verifier, "verifier", "decisionKey", [result]);
    await assertResultIdentityUnconsumed({ chain, verifier, consumer, result, replayKey, decisionKey });

    const margin = Number(result.validUntil) - Math.floor(Date.now() / 1000);
    if (margin < MIN_EXPIRY_MARGIN_SECONDS) fail("RESULT_EXPIRY_MARGIN", String(margin));

    const domain = { name: V3_EIP712_NAME, version: V3_EIP712_VERSION, chainId: CHAIN_ID, verifyingContract: verifier };
    const signed = await Promise.all(settings.validators.slice(0, QUORUM).map(async (validator) => ({
      address: validator.address.toLowerCase(),
      signature: await validator.signTypedData({
        domain, types: V3_ATTESTATION_TYPES, primaryType: "ConfidentialPolicyAttestation",
        message: { validatorSetId, resultDigest: digest },
      }),
    })));
    signed.sort((left, right) => left.address.localeCompare(right.address));
    const attestation = encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes[]" }],
      [validatorSetId, signed.map((entry) => entry.signature)],
    );
    openData = encodeFunctionData({ abi: artifacts.consumer.abi, functionName: "openRecourse", args: [result, attestation] });

    await advance(journal, options.journal, "ATOMIC_PREPARED", {
      session: jsonSafe({
        verifier, consumer, validatorSetId, resultDigest: digest, replayKey, decisionKey,
        attestingValidators: signed.map((entry) => getAddress(entry.address)),
        result, calldata: openData, calldataBytes: byteLength(openData),
        expirySecondsRemaining: margin,
      }),
    });
  } else {
    // Resuming a confirmed transaction: the calldata and result identity were
    // persisted before the hash, so they are authoritative here.
    if (!openData || !result) fail("RESUME_SESSION_INCOMPLETE", journal.state);
  }

  /* ---- ATOMIC: hash persisted before the receipt is awaited ---- */
  let receipt = atomicPlan.receipt;
  if (atomicPlan.action === "SUBMIT") {
    const sent = await estimateAndSend({ wallet, client, throttle, request: { to: consumer, data: openData }, label: "ATOMIC_RECOURSE" });
    await advance(journal, options.journal, "ATOMIC_HASH_PERSISTED", {
      atomic: { hash: sent.hash, status: null, gasEstimate: sent.gasEstimate, gasLimit: sent.gasLimit, submittedAt: new Date().toISOString() },
    });
    receipt = await awaitReceipt({ client, throttle, hash: sent.hash, label: "ATOMIC_RECOURSE" });
  }

  await advance(journal, options.journal, "ATOMIC_CONFIRMED", {
    atomic: {
      ...(journal.atomic ?? {}),
      hash: receipt.transactionHash,
      status: receipt.status,
      block: String(receipt.blockNumber),
      blockHash: receipt.blockHash,
      gasUsed: String(receipt.gasUsed),
      calldataBytes: byteLength(openData),
    },
  });

  /* ---- events and readbacks ---- */
  const verifierEvents = parseEventLogs({ abi: artifacts.verifier.abi, logs: receipt.logs, eventName: "ConfidentialPolicyResultV3Accepted", strict: true });
  const recourseEvents = parseEventLogs({ abi: artifacts.consumer.abi, logs: receipt.logs, eventName: "LaboratoryRecourseOpened", strict: true });
  if (verifierEvents.length !== 1 || recourseEvents.length !== 1) {
    await recordFailure(journal, options.journal, "ATOMIC_EVENT_MISSING", `${verifierEvents.length}/${recourseEvents.length}`);
    fail("ATOMIC_EVENT_MISSING");
  }

  const replayKey = journal.session?.replayKey ?? await chain.read(verifier, "verifier", "replayKey", [result]);
  const decisionKey = journal.session?.decisionKey ?? await chain.read(verifier, "verifier", "decisionKey", [result]);
  const record = await chain.read(consumer, "consumer", "recourses", [result.resultCommitment]);
  const readbacks = jsonSafe({
    verifier, consumer,
    validatorSetId: journal.setup.validatorSetId,
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    intendedConsumer: result.consumer,
    resultCommitment: result.resultCommitment,
    providerProofCommitment: result.providerProofCommitment,
    inputCommitmentA: result.inputCommitmentA,
    inputCommitmentB: result.inputCommitmentB,
    replayKey, decisionKey,
    nonceConsumed: await chain.read(verifier, "verifier", "consumedReplayKeys", [replayKey]),
    decisionConsumed: await chain.read(verifier, "verifier", "consumedDecisionKeys", [decisionKey]),
    providerProofConsumed: await chain.read(verifier, "verifier", "consumedProviderProofCommitments", [result.providerProofCommitment]),
    recourseRecord: {
      resultCommitment: record[0], providerProofCommitment: record[1],
      inputCommitmentA: record[2], inputCommitmentB: record[3],
      policyId: record[4], policyVersion: record[5],
      responsibleRole: record[6], consequenceId: record[7],
      acceptedAt: String(record[8]), cureDeadline: String(record[9]), status: Number(record[10]),
    },
  });

  const derived = readbacks.recourseRecord;
  const acceptedAt = BigInt(derived.acceptedAt);
  const checks = {
    statusOpen: derived.status === 1,
    responsibleRoleMatchesPolicy: same(derived.responsibleRole, RESPONSIBLE_ROLE),
    consequenceMatchesPolicy: same(derived.consequenceId, CONSEQUENCE_ID),
    cureDeadlineDerivedOnChain: BigInt(derived.cureDeadline) === acceptedAt + CURE_PERIOD_SECONDS,
    acceptanceTimestampDerivedOnChain: acceptedAt > 0n,
    intendedConsumerEnforced: same(readbacks.intendedConsumer, consumer),
    identitiesConsumed: readbacks.nonceConsumed === true && readbacks.decisionConsumed === true && readbacks.providerProofConsumed === true,
  };
  const failedCheck = Object.entries(checks).find(([, ok]) => !ok);
  if (failedCheck) {
    await recordFailure(journal, options.journal, "READBACK_INVARIANT", failedCheck[0]);
    fail("READBACK_INVARIANT", failedCheck[0]);
  }
  await advance(journal, options.journal, "READBACKS_CONFIRMED", {
    readbacks: { ...readbacks, checks },
    events: jsonSafe({
      verifierAcceptance: verifierEvents.map((log) => ({ name: log.eventName, args: log.args })),
      recourseOpened: recourseEvents.map((log) => ({ name: log.eventName, args: log.args })),
    }),
  });

  /* ---- replay must be rejected, by simulation only ---- */
  let replay;
  try {
    await throttle(() => client.call({ to: consumer, data: openData, account: settings.deployer.address }), "replay");
    replay = { mode: "eth_call", rejected: false, secondTransactionBroadcast: false, revert: null };
  } catch (error) {
    const detail = error?.details ?? error?.shortMessage ?? error?.message ?? "";
    replay = {
      mode: "eth_call",
      rejected: true,
      secondTransactionBroadcast: false,
      revert: String(detail).slice(0, 200),
      customErrorDataExposed: /0x[0-9a-fA-F]{8}/.test(String(error?.data ?? "")),
      corroboratedByConsumedState: checks.identitiesConsumed,
    };
  }
  if (!replay.rejected) {
    await recordFailure(journal, options.journal, "REPLAY_NOT_REJECTED", null);
    fail("REPLAY_NOT_REJECTED");
  }
  await advance(journal, options.journal, "REPLAY_REJECTED", { replay });

  /* ---- assemble, persist, then seal the leak audit over every artifact ---- */
  report.classification = "MONAD V3 ATOMIC RECOURSE: PROVEN";
  report.processEvidence = journal.processEvidence;
  report.result = jsonSafe(result);
  report.transactions.openRecourse = journal.atomic;
  report.readbacks = journal.readbacks;
  report.events = journal.events;
  report.replay = replay;
  report.session = journal.session ? { ...journal.session, calldata: undefined, calldataBytes: journal.session.calldataBytes } : null;
  report.performance = {
    fheMilliseconds: processMilliseconds,
    calldataBytes: byteLength(openData),
    gasUsed: journal.atomic.gasUsed,
    totalMilliseconds: Number((performance.now() - started).toFixed(2)),
  };
  assertPublicOnly(report);
  await writeAtomic(options.out, report);

  if (seal) {
    // One final canary and field-name sweep that now also covers the journal,
    // the report, the persisted calldata, the decoded events and the readbacks.
    const extraRoots = [...new Set([dirname(options.out), dirname(options.journal)])];
    const sealed = await seal(extraRoots);
    report.leakScan = {
      sealed: true, ok: sealed.ok, scannedRoots: sealed.canaries.scannedRoots,
      scannedFiles: sealed.generic.scannedFiles, violations: sealed.generic.violations,
      leaks: sealed.canaries.leaks, canaries: sealed.canaries.canaries,
    };
    if (!sealed.ok) {
      report.classification = "MONAD V3 ATOMIC RECOURSE: NOT PROVEN";
      await writeAtomic(options.out, report);
      await recordFailure(journal, options.journal, "FINAL_LEAK_SCAN", null);
      fail("FINAL_LEAK_SCAN");
    }
    assertPublicOnly(report);
    await writeAtomic(options.out, report);
  } else {
    // Resumed run: the six-process capture belongs to the earlier invocation
    // that persisted it. Its scan result is retained evidence; this invocation
    // did not re-seal it and does not claim to have done so.
    report.leakScan = { sealed: false, resumedFromJournal: true, ...(journal.processEvidence?.leakScan ?? { ok: false }) };
    assertPublicOnly(report);
    await writeAtomic(options.out, report);
  }

  await advance(journal, options.journal, "PRIVACY_CLAIM_READY", { leakScan: report.leakScan });
  return report;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  try {
    process.stdout.write(`${JSON.stringify(await run(options), null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({
      ok: false,
      classification: "MONAD V3 ATOMIC RECOURSE: NOT PROVEN",
      failedGate: error.code ?? "V3_RUNNER_FAILED",
      detail: error.detail ?? null,
      journal: options.journal,
    }, null, 2)}\n`);
    process.exitCode = 1;
  }
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) await main();
