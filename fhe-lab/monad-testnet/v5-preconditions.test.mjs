// Tests for the dynamic Phase B preconditions.
//
// The property that matters: the requirement must FALL as stages confirm, and
// must RISE when the network gets more expensive. A precondition that returns
// the same number regardless of progress or fees is decoration.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Journal, STAGES, STATES } from "./v5-journal.mjs";
import {
  assertPreconditions, PreconditionError, remainingGas, remainingDiskPeak,
  requiredBalance, requiredFreeDisk, ABSOLUTE_MINIMUM_FREE_BYTES, STAGE_GAS,
} from "./v5-preconditions.mjs";

const COMMIT = "ee62f91";
const CHAIN = 10_143;
const GWEI = 1_000_000_000n;

async function freshJournal() {
  const path = join(await mkdtemp(join(tmpdir(), "v5-pre-")), "journal.json");
  return Journal.open(path, { sourceCommit: COMMIT, chainId: CHAIN });
}

const client = ({ baseFee = 100n * GWEI, balance = 100n * 10n ** 18n }) => ({
  getBlock: async () => ({ baseFeePerGas: baseFee }),
  getGasPrice: async () => baseFee,
  getBalance: async () => balance,
});

test("remaining gas falls as stages confirm", async () => {
  const journal = await freshJournal();
  const atStart = remainingGas(journal);
  assert.ok(atStart > 30_000_000n, "the full run should cost tens of millions of gas");

  await journal.recordOffChain("INITIALIZED", {});
  await journal.recordOffChain("FINAL_STACK_PLANNED", {});
  await journal.recordOffChain("FINAL_STACK_DEPLOYED", {});
  const afterDeploy = remainingGas(journal);

  assert.ok(afterDeploy < atStart, "confirming the stack must reduce the requirement");
  assert.equal(atStart - afterDeploy, STAGE_GAS.FINAL_STACK_DEPLOYED);
});

test("the balance requirement rises with the network fee", async () => {
  const journal = await freshJournal();
  const gas = remainingGas(journal);
  const cheap = requiredBalance(gas, 50n * GWEI);
  const dear = requiredBalance(gas, 400n * GWEI);
  assert.ok(dear > cheap * 7n, "an 8x fee must move the requirement roughly 8x");
});

// Monad charges against gas_limit, not gas_used, so the requirement must exceed
// the naive product or the run reverts with "insufficient balance" despite
// appearing affordable.
test("the requirement exceeds naive gas times fee", async () => {
  const naive = 1_000_000n * 100n * GWEI;
  const actual = requiredBalance(1_000_000n, 100n * GWEI);
  assert.ok(actual > naive, "must account for the 1.3x gas limit, safety and reserve");
  // 1.3 limit x 1.2 safety x 1.25 reserve = 1.95
  assert.equal(actual, (naive * 130n * 120n * 125n) / 1_000_000n);
});

test("disk requirement never drops below the absolute floor", () => {
  assert.equal(requiredFreeDisk(0n), ABSOLUTE_MINIMUM_FREE_BYTES);
  assert.equal(requiredFreeDisk(1n), ABSOLUTE_MINIMUM_FREE_BYTES);
  const large = 10n * 1024n * 1024n * 1024n;
  assert.equal(requiredFreeDisk(large), large * 2n);
});

test("remaining disk peak falls as the heavy stages confirm", async () => {
  const journal = await freshJournal();
  const atStart = remainingDiskPeak(journal);
  for (const name of STAGES) {
    await journal.recordOffChain(name, {});
    if (name === "OPERATOR_RECOMPUTATION_COMPLETED") break;
  }
  assert.ok(remainingDiskPeak(journal) < atStart);
});

test("preconditions pass with ample balance and disk", async () => {
  const journal = await freshJournal();
  const facts = await assertPreconditions({
    journal,
    client: client({ balance: 1_000n * 10n ** 18n }),
    deployer: "0xdeployer",
    path: tmpdir(),
  });
  assert.equal(facts.passed, true);
  assert.equal(facts.nextStage, "INITIALIZED");
  assert.equal(facts.maxFeePerGasGwei, 202);
});

test("an underfunded deployer stops the run before any broadcast", async () => {
  const journal = await freshJournal();
  await assert.rejects(
    () => assertPreconditions({
      journal,
      client: client({ balance: 1n * 10n ** 18n }),
      deployer: "0xdeployer",
      path: tmpdir(),
    }),
    (error) => {
      assert.ok(error instanceof PreconditionError);
      assert.equal(error.code, "INSUFFICIENT_BALANCE");
      // The error must carry the numbers, or the operator cannot act on it.
      assert.ok(Number(error.facts.requiredBalanceMon) > 1);
      assert.equal(error.facts.actualBalanceMon, "1.0000");
      return true;
    },
  );
});

// A fee spike between sessions can make a previously affordable run
// unaffordable. The check must catch that rather than trusting the earlier pass.
test("a fee spike alone can fail a previously passing balance", async () => {
  const journal = await freshJournal();
  const balance = 20n * 10n ** 18n;
  await assertPreconditions({
    journal, client: client({ baseFee: 20n * GWEI, balance }),
    deployer: "0xd", path: tmpdir(),
  });
  await assert.rejects(
    () => assertPreconditions({
      journal, client: client({ baseFee: 400n * GWEI, balance }),
      deployer: "0xd", path: tmpdir(),
    }),
    (error) => error.code === "INSUFFICIENT_BALANCE",
  );
});

// Once the expensive stages are behind, the same balance should suffice, so a
// partially completed run is not blocked by the cost of work already paid for.
test("a partially completed run needs less than a fresh one", async () => {
  const journal = await freshJournal();
  const balance = 6n * 10n ** 18n;
  const fees = { baseFee: 100n * GWEI, balance };

  await assert.rejects(
    () => assertPreconditions({ journal, client: client(fees), deployer: "0xd", path: tmpdir() }),
    (error) => error.code === "INSUFFICIENT_BALANCE",
  );

  for (const name of ["INITIALIZED", "FINAL_STACK_PLANNED", "FINAL_STACK_DEPLOYED", "BYTECODE_VERIFIED", "VAULT_CREATED"]) {
    await journal.recordOffChain(name, {});
  }
  const facts = await assertPreconditions({ journal, client: client(fees), deployer: "0xd", path: tmpdir() });
  assert.equal(facts.passed, true);
});

test("preconditions refuse to run past an AMBIGUOUS stage", async () => {
  const journal = await freshJournal();
  await journal.recordOffChain("INITIALIZED", {});
  await journal.markAmbiguous("FINAL_STACK_PLANNED", "nonce advanced without a receipt");
  await assert.rejects(
    () => assertPreconditions({
      journal, client: client({ balance: 1_000n * 10n ** 18n }),
      deployer: "0xd", path: tmpdir(),
    }),
    (error) => error.code === "AMBIGUOUS_STAGE",
  );
});
