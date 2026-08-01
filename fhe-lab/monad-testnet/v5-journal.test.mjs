// Recovery tests for the V5 durable stage machine.
//
// Every test here simulates a crash by DISCARDING the in-memory Journal and
// reopening it from disk, which is exactly what a new session does. Nothing is
// carried across in a variable, because in a real interruption nothing is.
//
// The properties being proved are the ones that cost money or evidence when
// they fail: never duplicate a confirmed transaction, never resubmit an
// ambiguous nonce, never repeat a threshold release, never regenerate a session
// nullifier, never change canonical calldata after preparation.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Journal, JournalError, STAGES, STATES } from "./v5-journal.mjs";

const COMMIT = "99dae19";
const CHAIN = 10_143;

async function freshPath() {
  return join(await mkdtemp(join(tmpdir(), "v5-journal-")), "journal.json");
}

const open = (path) => Journal.open(path, { sourceCommit: COMMIT, chainId: CHAIN });

/// Drives the journal to CONFIRMED for every stage up to but excluding `target`.
async function advanceTo(path, target) {
  const journal = await open(path);
  for (const name of STAGES) {
    if (name === target) break;
    await journal.recordOffChain(name, { synthetic: name });
  }
  return journal;
}

/* ------------------------------------------------------------- basics */

test("a fresh journal starts at INITIALIZED with everything NOT_STARTED", async () => {
  const journal = await open(await freshPath());
  assert.equal(journal.nextStage(), "INITIALIZED");
  for (const name of STAGES) assert.equal(journal.state(name), STATES.NOT_STARTED);
});

test("a journal from a different source commit is refused, not migrated", async () => {
  const path = await freshPath();
  await open(path);
  await assert.rejects(
    () => Journal.open(path, { sourceCommit: "deadbee", chainId: CHAIN }),
    (error) => error instanceof JournalError && error.code === "JOURNAL_SOURCE_COMMIT_MISMATCH",
  );
});

test("a journal from a different chain is refused", async () => {
  const path = await freshPath();
  await open(path);
  await assert.rejects(
    () => Journal.open(path, { sourceCommit: COMMIT, chainId: 1 }),
    (error) => error instanceof JournalError && error.code === "JOURNAL_CHAIN_MISMATCH",
  );
});

test("stages cannot be skipped", async () => {
  const journal = await open(await freshPath());
  await assert.rejects(
    () => journal.prepare("VAULT_CREATED", { calldata: "0x00" }),
    (error) => error instanceof JournalError && error.code === "STAGE_OUT_OF_ORDER",
  );
});

/* ------------------------------ interruption: before broadcast */

test("crash BEFORE broadcast resumes at the same stage with the same calldata", async () => {
  const path = await freshPath();
  await advanceTo(path, "FINAL_STACK_DEPLOYED");

  let journal = await open(path);
  await journal.prepare("FINAL_STACK_DEPLOYED", {
    sender: "0xabc", nonce: 128, calldata: "0xdeadbeef", expected: "stack deployed",
  });

  // crash
  journal = await open(path);
  assert.equal(journal.state("FINAL_STACK_DEPLOYED"), STATES.PREPARED);
  assert.equal(journal.nextStage(), "FINAL_STACK_DEPLOYED");
  assert.equal(journal.stage("FINAL_STACK_DEPLOYED").calldata, "0xdeadbeef");
  assert.equal(journal.stage("FINAL_STACK_DEPLOYED").nonce, 128);
});

// The prepared bytes are what a human reviewed. A resumed run that rebuilt them
// could differ through a timestamp or a fresh salt and would then broadcast
// something nobody approved.
test("canonical calldata cannot change after preparation", async () => {
  const path = await freshPath();
  await advanceTo(path, "BINDING_PREPARED");
  let journal = await open(path);
  await journal.prepare("BINDING_PREPARED", { sender: "0xabc", nonce: 5, calldata: "0xaaaa" });

  journal = await open(path);
  await assert.rejects(
    () => journal.prepare("BINDING_PREPARED", { sender: "0xabc", nonce: 5, calldata: "0xbbbb" }),
    (error) => error instanceof JournalError && error.code === "PREPARED_INPUT_DRIFT",
  );
  // Re-preparing with the identical record is idempotent, so an ordinary resume
  // is not an error.
  const same = await journal.prepare("BINDING_PREPARED", { sender: "0xabc", nonce: 5, calldata: "0xaaaa" });
  assert.equal(same.calldata, "0xaaaa");
});

/* ------------------------------ interruption: after hash persistence */

test("crash AFTER hash persistence never rebroadcasts", async () => {
  const path = await freshPath();
  await advanceTo(path, "SESSION_COMMITTED");
  let journal = await open(path);
  await journal.prepare("SESSION_COMMITTED", { sender: "0xrelayer", nonce: 0, calldata: "0xc0" });
  await journal.markBroadcast("SESSION_COMMITTED", "0xhash1");

  // crash between broadcast and receipt
  journal = await open(path);
  assert.equal(journal.state("SESSION_COMMITTED"), STATES.BROADCAST);
  assert.equal(journal.stage("SESSION_COMMITTED").transactionHash, "0xhash1");

  // A resumed run that tried to broadcast a different transaction is refused.
  await assert.rejects(
    () => journal.markBroadcast("SESSION_COMMITTED", "0xhash2"),
    (error) => error instanceof JournalError && error.code === "DOUBLE_BROADCAST",
  );
  // Re-reporting the same hash is idempotent.
  const again = await journal.markBroadcast("SESSION_COMMITTED", "0xhash1");
  assert.equal(again.transactionHash, "0xhash1");
});

/* ------------------------------ interruption: while receipt pending */

test("reconcile CONFIRMS a broadcast stage whose receipt succeeded", async () => {
  const path = await freshPath();
  await advanceTo(path, "SESSION_COMMITTED");
  let journal = await open(path);
  await journal.prepare("SESSION_COMMITTED", { sender: "0xrelayer", nonce: 0, calldata: "0xc0" });
  await journal.markBroadcast("SESSION_COMMITTED", "0xhash1");

  journal = await open(path);
  const findings = await journal.reconcile({
    getTransactionReceipt: async () => ({ status: "success", blockNumber: 42n, blockHash: "0xblk", gasUsed: 1000n }),
    getTransactionCount: async () => 1,
  });
  assert.deepEqual(findings, [{ stage: "SESSION_COMMITTED", resolved: STATES.CONFIRMED }]);
  assert.equal(journal.state("SESSION_COMMITTED"), STATES.CONFIRMED);
  assert.equal(journal.stage("SESSION_COMMITTED").receipt.blockHash, "0xblk");
});

test("reconcile FAILS a broadcast stage whose receipt reverted", async () => {
  const path = await freshPath();
  await advanceTo(path, "SESSION_COMMITTED");
  let journal = await open(path);
  await journal.prepare("SESSION_COMMITTED", { sender: "0xrelayer", nonce: 0, calldata: "0xc0" });
  await journal.markBroadcast("SESSION_COMMITTED", "0xhash1");

  journal = await open(path);
  await journal.reconcile({
    getTransactionReceipt: async () => ({ status: "reverted", blockNumber: 42n }),
    getTransactionCount: async () => 1,
  });
  assert.equal(journal.state("SESSION_COMMITTED"), STATES.FAILED);
});

// The dangerous case: no receipt, but the nonce moved. Something consumed that
// nonce and we cannot prove it was ours. Resubmitting could double-spend the
// action; treating it as failed could skip a confirmed one.
test("no receipt with an advanced nonce is AMBIGUOUS and stops the run", async () => {
  const path = await freshPath();
  await advanceTo(path, "SESSION_COMMITTED");
  let journal = await open(path);
  await journal.prepare("SESSION_COMMITTED", { sender: "0xrelayer", nonce: 0, calldata: "0xc0" });
  await journal.markBroadcast("SESSION_COMMITTED", "0xlost");

  journal = await open(path);
  const findings = await journal.reconcile({
    getTransactionReceipt: async () => { throw new Error("not found"); },
    getTransactionCount: async () => 1, // advanced past nonce 0
  });
  assert.deepEqual(findings, [{ stage: "SESSION_COMMITTED", resolved: STATES.AMBIGUOUS }]);
  assert.equal(journal.state("SESSION_COMMITTED"), STATES.AMBIGUOUS);
  assert.throws(() => journal.nextStage(), (error) => error.code === "AMBIGUOUS_STAGE");
});

test("no receipt with an unchanged nonce stays pending rather than being retried", async () => {
  const path = await freshPath();
  await advanceTo(path, "SESSION_COMMITTED");
  let journal = await open(path);
  await journal.prepare("SESSION_COMMITTED", { sender: "0xrelayer", nonce: 0, calldata: "0xc0" });
  await journal.markBroadcast("SESSION_COMMITTED", "0xpending");

  journal = await open(path);
  const findings = await journal.reconcile({
    getTransactionReceipt: async () => { throw new Error("not found"); },
    getTransactionCount: async () => 0,
  });
  assert.deepEqual(findings, [{ stage: "SESSION_COMMITTED", resolved: "STILL_PENDING" }]);
  assert.equal(journal.state("SESSION_COMMITTED"), STATES.BROADCAST);
});

/* -------------------- interruption: after receipt, before readback */

test("crash AFTER receipt but before readback resumes at the readback stage", async () => {
  const path = await freshPath();
  await advanceTo(path, "BINDING_CONFIRMED");
  let journal = await open(path);
  await journal.prepare("BINDING_CONFIRMED", { sender: "0xabc", nonce: 9, calldata: "0xbind" });
  await journal.markBroadcast("BINDING_CONFIRMED", "0xbindhash");
  await journal.markConfirmed("BINDING_CONFIRMED", { blockNumber: 100, blockHash: "0xblk" });

  journal = await open(path);
  assert.equal(journal.state("BINDING_CONFIRMED"), STATES.CONFIRMED);
  assert.equal(journal.nextStage(), "READBACKS_COMPLETED");
});

/* ------------- interruption: off-chain stages must not be repeated */

// A repeated ceremony would produce different keys, silently invalidating every
// enrollment already admitted against the first one.
test("a completed ceremony is never re-run", async () => {
  const path = await freshPath();
  await advanceTo(path, "CEREMONY_COMPLETED");
  let journal = await open(path);
  await journal.recordOffChain("CEREMONY_COMPLETED", { keyId: "0xkey", evaluationKeyDigest: "0xekd" });

  journal = await open(path);
  assert.equal(journal.state("CEREMONY_COMPLETED"), STATES.CONFIRMED);
  assert.equal(journal.nextStage(), "ENROLLMENTS_ADMITTED");
  // Attempting to record different material is ignored, not applied.
  const again = await journal.recordOffChain("CEREMONY_COMPLETED", { keyId: "0xDIFFERENT" });
  assert.equal(again.keyId, "0xkey");
});

// A repeated release is a second decryption under the same authorization, which
// is exactly the probing surface the one-shot design exists to close.
test("a completed threshold release is never repeated", async () => {
  const path = await freshPath();
  await advanceTo(path, "THRESHOLD_RELEASE_COMPLETED");
  let journal = await open(path);
  await journal.recordOffChain("THRESHOLD_RELEASE_COMPLETED", {
    sameEconomicAsset: true, policyConflict: true, outputCommitment: "0xout",
  });

  journal = await open(path);
  assert.equal(journal.nextStage(), "VALIDATOR_ATTESTATIONS_COMPLETED");
  const again = await journal.recordOffChain("THRESHOLD_RELEASE_COMPLETED", { outputCommitment: "0xOTHER" });
  assert.equal(again.outputCommitment, "0xout");
});

// Regenerating the nullifier would admit a second session under one signed
// intent, which is finding M-02 reintroduced through the runner.
test("a session nullifier is never regenerated", async () => {
  const path = await freshPath();
  await advanceTo(path, "SESSION_PREPARED");
  let journal = await open(path);
  await journal.prepare("SESSION_PREPARED", {
    sessionNullifier: "0xnull", sessionCommitment: "0xcommit", sessionNonce: 7,
  });

  journal = await open(path);
  await assert.rejects(
    () => journal.prepare("SESSION_PREPARED", {
      sessionNullifier: "0xDIFFERENT", sessionCommitment: "0xcommit", sessionNonce: 7,
    }),
    (error) => error instanceof JournalError && error.code === "PREPARED_INPUT_DRIFT",
  );
  assert.equal(journal.stage("SESSION_PREPARED").sessionNullifier, "0xnull");
});

/* ------------------------------ full-sequence resumption */

test("interrupting at every stage boundary resumes at exactly that stage", async () => {
  for (const [index, target] of STAGES.entries()) {
    const path = await freshPath();
    const journal = await open(path);
    for (const name of STAGES.slice(0, index)) {
      await journal.recordOffChain(name, { synthetic: name });
    }
    // crash
    const resumed = await open(path);
    assert.equal(resumed.nextStage(), target, `interrupted before ${target}`);
    for (const done of STAGES.slice(0, index)) {
      assert.equal(resumed.state(done), STATES.CONFIRMED);
    }
  }
});

test("a fully confirmed journal reports no next stage", async () => {
  const path = await freshPath();
  const journal = await open(path);
  for (const name of STAGES) await journal.recordOffChain(name, { synthetic: name });
  assert.equal(journal.nextStage(), null);
});

/* ------------------------------ durability of the write itself */

// A torn write would leave unparseable JSON and lose the whole run. The atomic
// replace means a crash mid-write leaves the previous complete journal.
test("a partially written temporary file never becomes the journal", async () => {
  const path = await freshPath();
  const journal = await open(path);
  await journal.recordOffChain("INITIALIZED", { synthetic: "x" });
  await writeFile(`${path}.tmp`, "{ this is not json");

  const resumed = await open(path);
  assert.equal(resumed.state("INITIALIZED"), STATES.CONFIRMED);
  const raw = JSON.parse(await readFile(path, "utf8"));
  assert.equal(raw.sourceCommit, COMMIT);
});
