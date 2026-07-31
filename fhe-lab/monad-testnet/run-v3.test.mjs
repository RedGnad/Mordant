import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm, writeFile, chmod, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import {
  CHAIN_ID,
  CURE_PERIOD_SECONDS,
  JOURNAL_SCHEMA,
  KNOWN_SETUP,
  POLICY_ID,
  POLICY_VERSION,
  QUORUM,
  RESPONSIBLE_ROLE,
  CONSEQUENCE_ID,
  STATES,
  V3RunnerError,
  advance,
  archiveSettledJournal,
  assertPublicOnly,
  assertResultIdentityUnconsumed,
  classifySetup,
  createThrottle,
  emptyJournal,
  maskImmutables,
  parseArgs,
  readJournal,
  reconcileAtomic,
  reconcileSetup,
  recordFailure,
  resolveSetupTransactions,
  writeAtomic,
} from "./run-v3.mjs";

/* ------------------------------------------------------------------ fixtures */

const VERIFIER = "0x7F1271D43B0E41e2eeDDD5290f459fDc6196a19a";
const CONSUMER = "0xB23A3C3492B9BA83D80C8abc9A5484d2885f058A";
const VAULT = "0x7531d467F19d1055AcCF6B0D22286184f87adBd8";
const OWNER = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";
const VALIDATORS = [
  "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45",
  "0xEe3260bA47D097DE5a8601107e1b83454593617c",
  "0x5eFD0B652BC49F0a6B568daA3d1e86D635Fd07aa",
];
const VERIFIER_CODE_HASH = `0x${"11".repeat(32)}`;
const CONSUMER_CODE_HASH = `0x${"22".repeat(32)}`;

const EXPECTED = Object.freeze({
  owner: OWNER,
  quorum: String(QUORUM),
  validators: VALIDATORS,
  vault: VAULT,
  policyId: POLICY_ID,
  policyVersion: String(POLICY_VERSION),
  responsibleRole: RESPONSIBLE_ROLE,
  consequenceId: CONSEQUENCE_ID,
  curePeriod: String(CURE_PERIOD_SECONDS),
  domainName: "Mordant Confidential Policy",
  domainVersion: "3",
  verifierCodeHash: VERIFIER_CODE_HASH,
  consumerCodeHash: CONSUMER_CODE_HASH,
});

function observedSetup(overrides = {}) {
  const base = {
    verifier: {
      address: VERIFIER,
      codeSize: 7545,
      codeHash: VERIFIER_CODE_HASH,
      owner: OWNER,
      quorum: String(QUORUM),
      validatorSetId: `0x${"ab".repeat(32)}`,
      domainName: "Mordant Confidential Policy",
      domainVersion: "3",
      validatorsActive: Object.fromEntries(VALIDATORS.map((v) => [v.toLowerCase(), true])),
      deployerIsValidator: false,
      policyVersionForVault: String(POLICY_VERSION),
    },
    consumer: {
      address: CONSUMER,
      codeSize: 3349,
      codeHash: CONSUMER_CODE_HASH,
      verifier: VERIFIER,
      vault: VAULT,
      policyId: POLICY_ID,
      policyVersion: String(POLICY_VERSION),
      responsibleRole: RESPONSIBLE_ROLE,
      curePeriod: String(CURE_PERIOD_SECONDS),
      consequenceId: CONSEQUENCE_ID,
    },
  };
  return {
    verifier: { ...base.verifier, ...(overrides.verifier ?? {}) },
    consumer: { ...base.consumer, ...(overrides.consumer ?? {}) },
  };
}

// Minimal fake of the injectable chain adapter used by the reconcilers.
function fakeChain({ receipts = {}, transactions = {}, reads = {}, codes = {} } = {}) {
  return {
    async receipt(hash) { return receipts[hash] ?? null; },
    async transaction(hash) { return transactions[hash] ?? null; },
    async code(address) { return codes[address] ?? "0x00"; },
    async read(address, which, functionName, args = []) {
      const key = `${which}.${functionName}`;
      const entry = reads[key];
      if (typeof entry === "function") return entry(address, args);
      if (entry === undefined) throw new Error(`unexpected read ${key}`);
      return entry;
    },
  };
}

function successReceipt({ contractAddress = null, to = null, block = 49_704_137n } = {}) {
  return {
    status: "success",
    blockNumber: block,
    blockHash: `0x${"cd".repeat(32)}`,
    contractAddress,
    to,
    transactionHash: `0x${"ef".repeat(32)}`,
    gasUsed: 100_000n,
    logs: [],
  };
}

async function journalDir() {
  const root = await mkdtemp(resolve(tmpdir(), "mordant-v3-journal-"));
  return { root, path: resolve(root, "journal.json") };
}

/* --------------------------------------------------------------- CLI + gates */

test("requires an explicit read-only check or a recorded run", () => {
  assert.throws(() => parseArgs([]), (e) => e instanceof V3RunnerError && e.code === "CLI_MODE_REQUIRED");
  assert.throws(() => parseArgs(["--run"]), (e) => e instanceof V3RunnerError && e.code === "CLI_OUT_REQUIRED");
  assert.throws(() => parseArgs(["--check", "--out", "x.json"]), (e) => e.code === "CLI_OUT_REQUIRED");
  assert.equal(parseArgs(["--check"]).mode, "check");
  assert.equal(parseArgs(["--run", "--out", "r.json"]).mode, "run");
  assert.equal(parseArgs(["--run", "--out", "r.json", "--new-session"]).newSession, true);
  assert.equal(parseArgs(["--check"]).newSession, false);
});

test("pins Monad testnet, the existing policy and the derived consequences", () => {
  assert.equal(CHAIN_ID, 10_143);
  assert.equal(POLICY_VERSION, 1);
  assert.equal(QUORUM, 2);
  assert.equal(CURE_PERIOD_SECONDS, 3_600n);
  assert.match(POLICY_ID, /^0x[0-9a-f]{64}$/);
  assert.match(RESPONSIBLE_ROLE, /^0x[0-9a-f]{64}$/);
  assert.match(CONSEQUENCE_ID, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(STATES[0], "PREFLIGHT");
  assert.deepEqual(STATES.at(-1), "PRIVACY_CLAIM_READY");
});

test("refuses to write an artifact carrying a restricted field name", () => {
  assert.throws(() => assertPublicOnly({ note: "a private key" }), (e) => e.code === "ARTIFACT_RESTRICTED_FIELD");
  assert.throws(() => assertPublicOnly({ thresholdShare: "x" }), (e) => e.code === "ARTIFACT_RESTRICTED_FIELD");
  assert.throws(() => assertPublicOnly({ plaintextAmount: 1 }), (e) => e.code === "ARTIFACT_RESTRICTED_FIELD");
  assert.deepEqual(assertPublicOnly({ resultCommitment: "0x01" }), { resultCommitment: "0x01" });
});

test("masks constructor immutables so identity is compared, not configuration", () => {
  const refs = { "1": [{ start: 1, length: 2 }] };
  const left = maskImmutables("0xaabbccdd", refs);
  const right = maskImmutables("0xaa1122dd", refs);
  assert.equal(left, right);
  assert.notEqual(maskImmutables("0xaabbccdd", {}), maskImmutables("0xaa1122dd", {}));
  assert.equal(maskImmutables(undefined, refs), null);
});

/* ------------------------------------------------------- journal durability */

test("journal writes are atomic and leave no partial file behind", async () => {
  const { root, path } = await journalDir();
  try {
    const journal = emptyJournal();
    await writeAtomic(path, journal);
    const round = await readJournal(path);
    assert.equal(round.schemaVersion, JOURNAL_SCHEMA);
    assert.equal(round.state, "PREFLIGHT");
    const raw = await readFile(path, "utf8");
    assert.equal(raw.endsWith("\n"), true);
    assert.deepEqual(JSON.parse(raw), journal);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("a journal with an unknown schema version is not resumed", async () => {
  const { root, path } = await journalDir();
  try {
    await writeFile(path, JSON.stringify({ schemaVersion: "something-else", state: "ATOMIC_CONFIRMED" }));
    assert.equal(await readJournal(path), null);
    await writeFile(path, "{ not json");
    assert.equal(await readJournal(path), null);
    assert.equal(await readJournal(resolve(root, "absent.json")), null);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("advance rejects an unknown lifecycle state and records history in order", async () => {
  const { root, path } = await journalDir();
  try {
    const journal = emptyJournal();
    await advance(journal, path, "SETUP_RECONCILED", { setup: { verifier: VERIFIER } });
    await advance(journal, path, "PROCESS_WORKFLOW_STARTED");
    await assert.rejects(advance(journal, path, "NOT_A_STATE"), (e) => e.code === "JOURNAL_UNKNOWN_STATE");
    const persisted = await readJournal(path);
    assert.deepEqual(persisted.history.map((h) => h.state), ["SETUP_RECONCILED", "PROCESS_WORKFLOW_STARTED"]);
    assert.equal(persisted.state, "PROCESS_WORKFLOW_STARTED");
    assert.equal(persisted.setup.verifier, VERIFIER);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("report write failure preserves prior confirmed evidence in the journal", async () => {
  const { root, path } = await journalDir();
  try {
    const journal = emptyJournal();
    await advance(journal, path, "ATOMIC_CONFIRMED", {
      atomic: { hash: `0x${"aa".repeat(32)}`, status: "success", block: "49704668" },
      readbacks: { resultCommitment: `0x${"bb".repeat(32)}` },
    });

    // A read-only artifacts directory makes the report write fail.
    const locked = resolve(root, "locked");
    await mkdir(locked);
    await chmod(locked, 0o500);
    await assert.rejects(writeAtomic(resolve(locked, "report.json"), { ok: true }));

    await recordFailure(journal, path, "REPORT_WRITE_FAILED", "read-only artifacts directory");
    const persisted = await readJournal(path);
    assert.equal(persisted.atomic.hash, `0x${"aa".repeat(32)}`);
    assert.equal(persisted.atomic.status, "success");
    assert.equal(persisted.readbacks.resultCommitment, `0x${"bb".repeat(32)}`);
    assert.equal(persisted.failure.code, "REPORT_WRITE_FAILED");
    assert.equal(persisted.failure.state, "ATOMIC_CONFIRMED");
    await chmod(locked, 0o700);
  } finally { await rm(root, { recursive: true, force: true }); }
});

/* -------------------------------------------------- setup reconciliation */

test("a fully matching deployed setup is reusable", () => {
  const verdict = classifySetup(observedSetup(), EXPECTED);
  assert.equal(verdict.classification, "SETUP_REUSABLE");
  assert.deepEqual(verdict.mismatches, []);
});

test("mismatched deployed bytecode is rejected, never silently replaced", () => {
  const verdict = classifySetup(observedSetup({ verifier: { codeHash: `0x${"99".repeat(32)}` } }), EXPECTED);
  assert.equal(verdict.classification, "SETUP_MISMATCH");
  assert.deepEqual(verdict.mismatches.map((m) => m.field), ["verifier.identityHash"]);
});

test("mismatched policy configuration is rejected", () => {
  const unconfigured = classifySetup(observedSetup({ verifier: { policyVersionForVault: "0" } }), EXPECTED);
  assert.equal(unconfigured.classification, "SETUP_MISMATCH");
  assert.ok(unconfigured.mismatches.some((m) => m.field === "verifier.policyVersionForVault"));

  const wrongVersion = classifySetup(observedSetup({ consumer: { policyVersion: "2" } }), EXPECTED);
  assert.equal(wrongVersion.classification, "SETUP_MISMATCH");
  assert.ok(wrongVersion.mismatches.some((m) => m.field === "consumer.policyVersion"));

  const wrongPolicy = classifySetup(observedSetup({ consumer: { policyId: `0x${"01".repeat(32)}` } }), EXPECTED);
  assert.equal(wrongPolicy.classification, "SETUP_MISMATCH");
  assert.ok(wrongPolicy.mismatches.some((m) => m.field === "consumer.policyId"));
});

test("a consumer bound to a different verifier, vault or consequence is rejected", () => {
  for (const [field, overrides] of [
    ["consumer.verifier", { consumer: { verifier: OWNER } }],
    ["consumer.vault", { consumer: { vault: OWNER } }],
    ["consumer.responsibleRole", { consumer: { responsibleRole: `0x${"05".repeat(32)}` } }],
    ["consumer.consequenceId", { consumer: { consequenceId: `0x${"06".repeat(32)}` } }],
    ["consumer.curePeriod", { consumer: { curePeriod: "1" } }],
    ["verifier.quorum", { verifier: { quorum: "1" } }],
    ["verifier.owner", { verifier: { owner: VAULT } }],
  ]) {
    const verdict = classifySetup(observedSetup(overrides), EXPECTED);
    assert.equal(verdict.classification, "SETUP_MISMATCH", field);
    assert.ok(verdict.mismatches.some((m) => m.field === field), `${field} not reported`);
  }
});

test("an inactive validator or a validating deployer is rejected", () => {
  const inactive = observedSetup();
  inactive.verifier.validatorsActive[VALIDATORS[2].toLowerCase()] = false;
  assert.equal(classifySetup(inactive, EXPECTED).classification, "SETUP_MISMATCH");

  const selfValidating = classifySetup(observedSetup({ verifier: { deployerIsValidator: true } }), EXPECTED);
  assert.equal(selfValidating.classification, "SETUP_MISMATCH");
  assert.ok(selfValidating.mismatches.some((m) => m.field === "verifier.deployerIsValidator"));
});

test("an address with no deployed code is incomplete, not mismatched", () => {
  assert.equal(classifySetup(observedSetup({ verifier: { codeHash: null } }), EXPECTED).classification, "SETUP_INCOMPLETE");
  assert.equal(classifySetup({ verifier: {}, consumer: {} }, EXPECTED).classification, "SETUP_INCOMPLETE");
});

test("crash after setup hash persistence resolves the hash instead of redeploying", async () => {
  const chain = fakeChain({
    receipts: {
      [KNOWN_SETUP.verifier]: successReceipt({ contractAddress: VERIFIER }),
      [KNOWN_SETUP.consumer]: successReceipt({ contractAddress: CONSUMER }),
      [KNOWN_SETUP.policy]: successReceipt({ to: VERIFIER }),
    },
  });
  const resolution = await resolveSetupTransactions(KNOWN_SETUP, chain);
  assert.equal(resolution.classification, "RESOLVED");
  assert.equal(resolution.resolved.verifier.address, VERIFIER);
  assert.equal(resolution.resolved.consumer.address, CONSUMER);
  assert.equal(resolution.resolved.policy.to, VERIFIER);
});

test("a persisted setup hash that is still pending stops as incomplete", async () => {
  const chain = fakeChain({ transactions: { [KNOWN_SETUP.verifier]: { hash: KNOWN_SETUP.verifier } } });
  const resolution = await resolveSetupTransactions(KNOWN_SETUP, chain);
  assert.equal(resolution.classification, "SETUP_INCOMPLETE");
  assert.equal(resolution.reason, "verifier:pending");
});

test("a persisted setup hash the chain has never seen is unrecoverable", async () => {
  const resolution = await resolveSetupTransactions(KNOWN_SETUP, fakeChain({}));
  assert.equal(resolution.classification, "SETUP_UNRECOVERABLE");
  assert.equal(resolution.reason, "verifier:unknown-transaction");
});

test("a reverted setup transaction is unrecoverable", async () => {
  const chain = fakeChain({
    receipts: {
      [KNOWN_SETUP.verifier]: successReceipt({ contractAddress: VERIFIER }),
      [KNOWN_SETUP.consumer]: { ...successReceipt({ contractAddress: CONSUMER }), status: "reverted" },
    },
  });
  const resolution = await resolveSetupTransactions(KNOWN_SETUP, chain);
  assert.equal(resolution.classification, "SETUP_UNRECOVERABLE");
  assert.equal(resolution.reason, "consumer:reverted");
});

test("a policy transaction aimed at another contract is a mismatch", async () => {
  const chain = fakeChain({
    receipts: {
      [KNOWN_SETUP.verifier]: successReceipt({ contractAddress: VERIFIER }),
      [KNOWN_SETUP.consumer]: successReceipt({ contractAddress: CONSUMER }),
      [KNOWN_SETUP.policy]: successReceipt({ to: CONSUMER }),
    },
  });
  const state = await reconcileSetup({ journal: null, chain, expected: EXPECTED, artifacts: {}, hashes: KNOWN_SETUP });
  assert.equal(state.classification, "SETUP_MISMATCH");
  assert.equal(state.reason, "policy-transaction-target");
});

/* ------------------------------------------------- atomic reconciliation */

test("an empty journal authorises exactly one fresh submission", async () => {
  const plan = await reconcileAtomic({ journal: emptyJournal(), chain: fakeChain({}) });
  assert.equal(plan.action, "SUBMIT");
});

test("restart with a confirmed atomic receipt resumes instead of resubmitting", async () => {
  const hash = `0x${"3f".repeat(32)}`;
  const receipt = successReceipt({ to: CONSUMER, block: 49_704_668n });
  const journal = { ...emptyJournal(), state: "ATOMIC_CONFIRMED", atomic: { hash, status: "success" } };
  const plan = await reconcileAtomic({ journal, chain: fakeChain({ receipts: { [hash]: receipt } }) });
  assert.equal(plan.action, "RESUME_CONFIRMED");
  assert.equal(plan.receipt.blockNumber, 49_704_668n);
});

test("crash after atomic hash persistence resumes from the confirmed receipt", async () => {
  const hash = `0x${"7c".repeat(32)}`;
  const journal = { ...emptyJournal(), state: "ATOMIC_HASH_PERSISTED", atomic: { hash, status: null } };
  const plan = await reconcileAtomic({ journal, chain: fakeChain({ receipts: { [hash]: successReceipt({ to: CONSUMER }) } }) });
  assert.equal(plan.action, "RESUME_CONFIRMED");
});

test("restart with a still-pending atomic hash stops and never resubmits", async () => {
  const hash = `0x${"8d".repeat(32)}`;
  const journal = { ...emptyJournal(), state: "ATOMIC_HASH_PERSISTED", atomic: { hash, status: null } };
  const plan = await reconcileAtomic({ journal, chain: fakeChain({ transactions: { [hash]: { hash } } }) });
  assert.equal(plan.action, "STOP");
  assert.equal(plan.code, "ATOMIC_PENDING_UNKNOWN");
});

test("restart with an atomic hash of unknown state stops and never resubmits", async () => {
  const hash = `0x${"9e".repeat(32)}`;
  const journal = { ...emptyJournal(), state: "ATOMIC_HASH_PERSISTED", atomic: { hash, status: null } };
  const plan = await reconcileAtomic({ journal, chain: fakeChain({}) });
  assert.equal(plan.action, "STOP");
  assert.equal(plan.code, "ATOMIC_UNKNOWN_TRANSACTION");
});

test("a reverted atomic transaction stops rather than retrying the same result", async () => {
  const hash = `0x${"af".repeat(32)}`;
  const journal = { ...emptyJournal(), state: "ATOMIC_HASH_PERSISTED", atomic: { hash, status: null } };
  const receipts = { [hash]: { ...successReceipt({ to: CONSUMER }), status: "reverted" } };
  const plan = await reconcileAtomic({ journal, chain: fakeChain({ receipts }) });
  assert.equal(plan.action, "STOP");
  assert.equal(plan.code, "ATOMIC_REVERTED");
});

/* ------------------------------------------------ consumed result identity */

const RESULT = Object.freeze({
  resultCommitment: `0x${"37".repeat(32)}`,
  providerProofCommitment: `0x${"63".repeat(32)}`,
});
const REPLAY_KEY = `0x${"bb".repeat(32)}`;
const DECISION_KEY = `0x${"34".repeat(32)}`;
const OPEN_RECORD = [
  RESULT.resultCommitment, RESULT.providerProofCommitment, `0x${"0e".repeat(32)}`, `0x${"f2".repeat(32)}`,
  POLICY_ID, 1, RESPONSIBLE_ROLE, CONSEQUENCE_ID, 1_785_510_974n, 1_785_514_574n, 1,
];
const EMPTY_RECORD = [
  `0x${"00".repeat(32)}`, `0x${"00".repeat(32)}`, `0x${"00".repeat(32)}`, `0x${"00".repeat(32)}`,
  `0x${"00".repeat(32)}`, 0, `0x${"00".repeat(32)}`, `0x${"00".repeat(32)}`, 0n, 0n, 0,
];

function identityChain({ nonce = false, decision = false, proof = false, record = EMPTY_RECORD } = {}) {
  return fakeChain({
    reads: {
      "verifier.consumedReplayKeys": nonce,
      "verifier.consumedDecisionKeys": decision,
      "verifier.consumedProviderProofCommitments": proof,
      "consumer.recourses": record,
    },
  });
}

test("a fresh, unconsumed result identity passes the submission gate", async () => {
  const consumed = await assertResultIdentityUnconsumed({
    chain: identityChain(), verifier: VERIFIER, consumer: CONSUMER,
    result: RESULT, replayKey: REPLAY_KEY, decisionKey: DECISION_KEY,
  });
  assert.deepEqual(consumed, { nonce: false, decision: false, providerProof: false });
});

test("an already consumed result identity blocks a fresh submission", async () => {
  const cases = [
    ["replay nonce", { nonce: true }],
    ["decision", { decision: true }],
    ["provider proof", { proof: true }],
    ["recourse already open", { record: OPEN_RECORD }],
  ];
  for (const [label, consumedField] of cases) {
    await assert.rejects(
      assertResultIdentityUnconsumed({
        chain: identityChain(consumedField), verifier: VERIFIER, consumer: CONSUMER,
        result: RESULT, replayKey: REPLAY_KEY, decisionKey: DECISION_KEY,
      }),
      (e) => e.code === "RESULT_IDENTITY_CONSUMED",
      label,
    );
  }
});

/* ------------------------------------------------------------ new sessions */

test("a new session is refused while an atomic operation is unsettled", async () => {
  const { root, path } = await journalDir();
  try {
    const journal = { ...emptyJournal(), state: "ATOMIC_HASH_PERSISTED", atomic: { hash: `0x${"11".repeat(32)}`, status: null } };
    await writeAtomic(path, journal);
    await assert.rejects(
      archiveSettledJournal(path, journal),
      (e) => e.code === "NEW_SESSION_REFUSED_UNSETTLED",
    );
    assert.notEqual(await readJournal(path), null);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("a settled journal is archived, never deleted, before a new session", async () => {
  const { root, path } = await journalDir();
  try {
    const journal = { ...emptyJournal(), state: "PRIVACY_CLAIM_READY", atomic: { hash: `0x${"12".repeat(32)}`, status: "success" } };
    await writeAtomic(path, journal);
    const archived = await archiveSettledJournal(path, journal);
    assert.equal(archived.archived, true);
    const retained = JSON.parse(await readFile(archived.target, "utf8"));
    assert.equal(retained.atomic.hash, `0x${"12".repeat(32)}`);
    assert.equal(await readJournal(path), null);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("a journal with no atomic operation needs no archiving", async () => {
  const result = await archiveSettledJournal("/unused", emptyJournal());
  assert.deepEqual(result, { archived: false, reason: "no-atomic-operation" });
});

/* ---------------------------------------------------------------- throttle */

test("the throttle serialises calls and retries a rate-limited endpoint", async () => {
  const sleeps = [];
  const throttle = createThrottle({ minIntervalMs: 0, attempts: 4, sleep: async (ms) => { sleeps.push(ms); } });
  let attempts = 0;
  const value = await throttle(async () => {
    attempts += 1;
    if (attempts < 3) throw new Error("requests limited to 15/sec");
    return "ok";
  }, "read");
  assert.equal(value, "ok");
  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [1_000, 2_000]);
});

test("the throttle surfaces a non-transport error without retrying", async () => {
  const throttle = createThrottle({ minIntervalMs: 0, attempts: 4, sleep: async () => {} });
  let attempts = 0;
  await assert.rejects(throttle(async () => { attempts += 1; throw new Error("execution reverted"); }, "call"));
  assert.equal(attempts, 1);
});

test("throttled work runs one call at a time", async () => {
  const throttle = createThrottle({ minIntervalMs: 0, attempts: 1, sleep: async () => {} });
  let active = 0;
  let peak = 0;
  const jobs = Array.from({ length: 8 }, () => throttle(async () => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 5));
    active -= 1;
  }, "job"));
  await Promise.all(jobs);
  assert.equal(peak, 1);
});
