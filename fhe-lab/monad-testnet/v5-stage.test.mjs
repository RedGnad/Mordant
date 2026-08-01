// The stage framework's job is to make certain mistakes impossible rather than
// discouraged. These tests assert the impossibility, not the convention.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Journal, STATES } from "./v5-journal.mjs";
import { LIVE_GATE, TARGETS } from "./v5-live-guard.mjs";
import { defineStage, runStage, runPipeline, StageError } from "./v5-stage.mjs";

const COMMIT = "b84e043";
const CHAIN = 10_143;

async function context(overrides = {}) {
  const path = join(await mkdtemp(join(tmpdir(), "v5-stage-")), "journal.json");
  const journal = await Journal.open(path, { sourceCommit: COMMIT, chainId: CHAIN });
  return {
    journal,
    path,
    env: {},
    client: {
      waitForTransactionReceipt: async () => ({
        status: "success", blockNumber: 7n, blockHash: "0xblk", gasUsed: 21000n,
      }),
    },
    ...overrides,
  };
}

const trivial = (name, extra = {}) =>
  defineStage({ name, verify: async () => ({ ok: true }), ...extra });

test("a stage without a verify handler cannot be defined", () => {
  assert.throws(
    () => defineStage({ name: "INITIALIZED" }),
    (error) => error instanceof StageError && error.code === "STAGE_UNVERIFIABLE",
  );
});

test("a confirmed stage is skipped, not re-run", async () => {
  const ctx = await context();
  let ran = 0;
  const stage = trivial("INITIALIZED", { execute: async () => { ran += 1; return {}; } });
  await runStage(stage, ctx);
  const second = await runStage(stage, ctx);
  assert.equal(second.skipped, true);
  assert.equal(ran, 1);
});

// The central structural guarantee: execute cannot reach the live world, so it
// cannot re-derive a nonce, a salt or a calldata blob that preparation fixed.
test("execute receives only the prepared record, never the context", async () => {
  const ctx = await context();
  let seen = null;
  const stage = trivial("INITIALIZED", {
    prepare: async () => ({ calldata: "0xaaaa", sessionNonce: 7 }),
    execute: async (args) => { seen = args; return { outputs: {} }; },
  });
  await runStage(stage, ctx);

  assert.deepEqual(Object.keys(seen).sort(), ["broadcast", "journal", "prepared", "stage"]);
  assert.equal(seen.prepared.calldata, "0xaaaa");
  assert.equal(seen.client, undefined, "execute must not see the chain client");
  assert.equal(seen.context, undefined);
  assert.equal(seen.accounts, undefined);
});

test("the prepared record handed to execute is deeply frozen", async () => {
  const ctx = await context();
  let mutated = null;
  const stage = trivial("INITIALIZED", {
    prepare: async () => ({ calldata: "0xaaaa", nested: { nonce: 1 } }),
    execute: async ({ prepared }) => {
      try {
        prepared.nested.nonce = 999;
        mutated = prepared.nested.nonce;
      } catch {
        mutated = "threw";
      }
      return { outputs: {} };
    },
  });
  await runStage(stage, ctx);
  assert.notEqual(mutated, 999, "execute must not be able to mutate prepared inputs");
});

// A preparation handler that is not deterministic must be DETECTED, not
// tolerated. This is what stops a resumed run broadcasting bytes nobody
// reviewed because a salt or timestamp moved.
test("a non-deterministic prepare handler is caught as drift on resume", async () => {
  const ctx = await context();
  let value = "0xaaaa";
  const stage = trivial("INITIALIZED", {
    prepare: async () => ({ calldata: value }),
    execute: async () => ({ outputs: {} }),
  });
  await ctx.journal.prepare("INITIALIZED", { calldata: value });
  value = "0xbbbb";
  await assert.rejects(
    () => runStage(stage, ctx),
    (error) => error.code === "PREPARED_INPUT_DRIFT",
  );
});

// The supported way to freeze randomness: prepare receives the frozen record
// and reuses it, so the second call agrees with the first.
test("a prepare handler reuses frozen randomness through `existing`", async () => {
  const ctx = await context();
  let generated = 0;
  const stage = trivial("INITIALIZED", {
    prepare: async ({ existing }) => ({
      salt: existing?.salt ?? `0xsalt${++generated}`,
    }),
    execute: async () => ({ outputs: {} }),
  });
  await runStage(stage, ctx);
  const frozen = ctx.journal.stage("INITIALIZED").salt;
  assert.equal(frozen, "0xsalt1");

  // A resumed run must not generate a second salt.
  const resumed = await Journal.open(ctx.path, { sourceCommit: COMMIT, chainId: CHAIN });
  await runStage(stage, { ...ctx, journal: resumed });
  assert.equal(resumed.stage("INITIALIZED").salt, "0xsalt1");
  assert.equal(generated, 1, "randomness must be generated exactly once");
});

test("a broadcasting stage persists its hash before awaiting the receipt", async () => {
  const ctx = await context({
    client: {
      waitForTransactionReceipt: async () => {
        // At this instant the journal must already know the hash.
        assert.equal(ctx.journal.state("INITIALIZED"), STATES.BROADCAST);
        assert.equal(ctx.journal.stage("INITIALIZED").transactionHash, "0xhash");
        return { status: "success", blockNumber: 7n, blockHash: "0xblk", gasUsed: 21000n };
      },
    },
  });
  const stage = trivial("INITIALIZED", {
    target: TARGETS.LOCAL,
    prepare: async () => ({ calldata: "0xaa" }),
    execute: async ({ broadcast }) => ({
      transactionHash: await broadcast("test", async () => "0xhash"),
    }),
  });
  await runStage(stage, ctx);
  assert.equal(ctx.journal.state("INITIALIZED"), STATES.CONFIRMED);
});

test("a reverted transaction marks the stage FAILED and throws", async () => {
  const ctx = await context({
    client: {
      waitForTransactionReceipt: async () => ({ status: "reverted", blockNumber: 9n }),
    },
  });
  const stage = trivial("INITIALIZED", {
    prepare: async () => ({ calldata: "0xaa" }),
    execute: async ({ broadcast }) => ({
      transactionHash: await broadcast("test", async () => "0xhash"),
    }),
  });
  await assert.rejects(() => runStage(stage, ctx), (error) => error.code === "STAGE_REVERTED");
  assert.equal(ctx.journal.state("INITIALIZED"), STATES.FAILED);
});

// A Monad-targeted stage must be unreachable without the gate, even through the
// framework.
test("a Monad stage cannot broadcast without the live gate", async () => {
  const ctx = await context({ env: {} });
  const stage = trivial("INITIALIZED", {
    target: TARGETS.MONAD,
    prepare: async () => ({ calldata: "0xaa" }),
    execute: async ({ broadcast }) => ({
      transactionHash: await broadcast("live", async () => "0xhash"),
    }),
  });
  await assert.rejects(() => runStage(stage, ctx), (error) => error.code === "LIVE_EXECUTION_BLOCKED");
});

test("a Monad stage broadcasts with the exact gate", async () => {
  const ctx = await context({ env: { [LIVE_GATE]: "1" } });
  const stage = trivial("INITIALIZED", {
    target: TARGETS.MONAD,
    prepare: async () => ({ calldata: "0xaa" }),
    execute: async ({ broadcast }) => ({
      transactionHash: await broadcast("live", async () => "0xhash"),
    }),
  });
  await runStage(stage, ctx);
  assert.equal(ctx.journal.state("INITIALIZED"), STATES.CONFIRMED);
});

// Verification runs against the world, so a stage whose execute "succeeded" but
// whose resulting state is wrong must not be confirmed.
test("a stage that executes but fails verification is FAILED, not CONFIRMED", async () => {
  const ctx = await context();
  const stage = defineStage({
    name: "INITIALIZED",
    prepare: async () => ({ calldata: "0xaa" }),
    execute: async () => ({ outputs: {} }),
    verify: async () => ({ ok: false, reason: "readback did not match" }),
  });
  await assert.rejects(
    () => runStage(stage, ctx),
    (error) => error.code === "STAGE_VERIFICATION_FAILED",
  );
  assert.equal(ctx.journal.state("INITIALIZED"), STATES.FAILED);
});

// Reconciliation is how a resumed run discovers that work already happened on
// chain without the journal knowing.
test("reconcile can short-circuit a stage that already happened on chain", async () => {
  const ctx = await context();
  let executed = false;
  const stage = trivial("INITIALIZED", {
    reconcile: async () => ({ alreadyDone: true, outputs: { discoveredOnChain: true } }),
    execute: async () => { executed = true; return {}; },
  });
  const result = await runStage(stage, ctx);
  assert.equal(result.reconciled, true);
  assert.equal(executed, false);
  assert.equal(ctx.journal.stage("INITIALIZED").discoveredOnChain, true);
});

test("reconcile can declare a stage AMBIGUOUS and halt the pipeline", async () => {
  const ctx = await context();
  const stage = trivial("INITIALIZED", {
    reconcile: async () => ({ ambiguous: true, reason: "nonce advanced without a receipt" }),
  });
  await assert.rejects(() => runStage(stage, ctx), (error) => error.code === "STAGE_AMBIGUOUS");
  assert.equal(ctx.journal.state("INITIALIZED"), STATES.AMBIGUOUS);
  // A later run must refuse to continue rather than re-deciding.
  await assert.rejects(() => runStage(stage, ctx), (error) => error.code === "STAGE_AMBIGUOUS");
});

test("a pipeline resumes from the first unconfirmed stage", async () => {
  const ctx = await context();
  const order = [];
  const stages = ["INITIALIZED", "FINAL_STACK_PLANNED", "FINAL_STACK_DEPLOYED"].map((name) =>
    trivial(name, { execute: async () => { order.push(name); return { outputs: {} }; } }),
  );
  await runStage(stages[0], ctx);
  order.length = 0;
  await runPipeline(stages, ctx);
  assert.deepEqual(order, ["FINAL_STACK_PLANNED", "FINAL_STACK_DEPLOYED"]);
});

test("a pipeline can stop at a named stage without touching later ones", async () => {
  const ctx = await context({ stopAfter: "FINAL_STACK_PLANNED" });
  const stages = ["INITIALIZED", "FINAL_STACK_PLANNED", "FINAL_STACK_DEPLOYED"].map((name) => trivial(name));
  await runPipeline(stages, ctx);
  assert.equal(ctx.journal.state("FINAL_STACK_PLANNED"), STATES.CONFIRMED);
  assert.equal(ctx.journal.state("FINAL_STACK_DEPLOYED"), STATES.NOT_STARTED);
});

test("an external checkpoint persists its bounded request and resumes only by reconciliation", async () => {
  const ctx = await context();
  let issued = false;
  const request = {
    chainId: CHAIN,
    vaultAddress: "0x1111111111111111111111111111111111111111",
    requiredIdentityStatus: "valid A-Pass",
    minimumValidity: "isValidAPass(vault) === true",
  };
  const stage = defineStage({
    name: "INITIALIZED",
    prepare: async () => ({ externalActionRequest: request }),
    execute: async ({ prepared }) => ({ awaitingExternal: true, request: prepared.externalActionRequest }),
    reconcile: async () => issued ? { alreadyDone: true, outputs: { reconciledFromChain: true } } : null,
    verify: async () => ({ ok: issued }),
  });
  const first = await runStage(stage, ctx);
  assert.equal(first.awaitingExternal, true);
  assert.equal(ctx.journal.state("INITIALIZED"), STATES.AWAITING_EXTERNAL);
  assert.deepEqual(ctx.journal.stage("INITIALIZED").externalActionRequest, request);

  issued = true; // separate authority acts while the runner is down
  const resumed = await Journal.open(ctx.path, { sourceCommit: COMMIT, chainId: CHAIN });
  const result = await runStage(stage, { ...ctx, journal: resumed });
  assert.equal(result.reconciled, true);
  assert.equal(resumed.state("INITIALIZED"), STATES.CONFIRMED);
});
