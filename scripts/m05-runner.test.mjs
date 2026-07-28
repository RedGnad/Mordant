import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  BROADCAST_CEREMONY, BUDGET, DEFAULT_MAX_GAS_PRICE_WEI, MONAD_CHAIN_ID, RunnerError,
  assertBroadcastAuthorized, assertChainId, assertFunded, assertGasPriceUnderCap, loadAccounts,
  scrubReport, waitForCureDeadline, writeCheckpoint,
} from "./m05-runner-lib.mjs";

/**
 * Gate tests for the M-05 runner. Every case here is a way the run must refuse to proceed, plus the
 * artifact guarantees that make an interrupted broadcast auditable.
 */

const address = (n) => `0x${String(n).repeat(40).slice(0, 40)}`;
const KEY = `0x${"11".repeat(32)}`;
const fakeAccount = (key) => ({ address: `0x${key.slice(4, 44)}`, source: "test" });

function fullEnv(extra = {}) {
  return {
    MORDANT_KEY_DEPLOYER: `0x${"a1".repeat(32)}`,
    MORDANT_KEY_BUYER: `0x${"a2".repeat(32)}`,
    MORDANT_KEY_FACILITY_A: `0x${"a3".repeat(32)}`,
    MORDANT_KEY_FACILITY_B: `0x${"a4".repeat(32)}`,
    MORDANT_KEY_HOLDER_A: `0x${"a5".repeat(32)}`,
    MORDANT_KEY_HOLDER_B: `0x${"a6".repeat(32)}`,
    MORDANT_KEY_ORIGINATOR: `0x${"a7".repeat(32)}`,
    ...extra,
  };
}

// --- 1. wrong chain id ---

test("a wrong chain id stops the run before anything else", async () => {
  const client = { getChainId: async () => 84_532 };
  await assert.rejects(assertChainId(client), (error) => {
    assert.ok(error instanceof RunnerError);
    assert.match(error.message, /BLOCKED — WRONG NETWORK/);
    assert.match(error.message, /84532/);
    return true;
  });
  assert.equal(await assertChainId({ getChainId: async () => MONAD_CHAIN_ID }), MONAD_CHAIN_ID);
});

// --- 2. missing authorization ---

test("broadcast without the ceremony string is refused", () => {
  assert.throws(() => assertBroadcastAuthorized("broadcast", {}), /Broadcasting is not authorized/);
  assert.throws(
    () => assertBroadcastAuthorized("broadcast", { MORDANT_BROADCAST_AUTHORIZED: "yes" }),
    /Broadcasting is not authorized/,
  );
  // Check and fork never consult it.
  assert.doesNotThrow(() => assertBroadcastAuthorized("check", {}));
  assert.doesNotThrow(() => assertBroadcastAuthorized("fork", {}));
  assert.doesNotThrow(
    () => assertBroadcastAuthorized("broadcast", { MORDANT_BROADCAST_AUTHORIZED: BROADCAST_CEREMONY }),
  );
});

// --- 3. missing key ---

test("a missing spending key stops a broadcast run", () => {
  const env = fullEnv();
  delete env.MORDANT_KEY_HOLDER_B;
  assert.throws(() => loadAccounts("broadcast", env, fakeAccount), (error) => {
    assert.match(error.message, /MORDANT_KEY_HOLDER_B is not set/);
    return true;
  });
});

test("the originator key is required and cannot be replaced by a pre-computed signature", () => {
  const env = fullEnv();
  delete env.MORDANT_KEY_ORIGINATOR;
  env.MORDANT_ADDRESS_ORIGINATOR = address(7);
  env.MORDANT_PLEDGE_SIGNATURE_1 = `0x${"cd".repeat(65)}`;
  assert.throws(() => loadAccounts("broadcast", env, fakeAccount), (error) => {
    assert.match(error.message, /MORDANT_KEY_ORIGINATOR is required/);
    // The reason matters: the pledge depends on values that do not exist before the run.
    assert.match(error.message, /vault address, invoice root and on-chain timestamps/);
    return true;
  });
});

test("check mode needs addresses but no key", () => {
  const addresses = {
    MORDANT_ADDRESS_DEPLOYER: address(1), MORDANT_ADDRESS_BUYER: address(2),
    MORDANT_ADDRESS_FACILITY_A: address(3), MORDANT_ADDRESS_FACILITY_B: address(4),
    MORDANT_ADDRESS_HOLDER_A: address(5), MORDANT_ADDRESS_HOLDER_B: address(6),
    MORDANT_ADDRESS_ORIGINATOR: address(7),
  };
  const loaded = loadAccounts("check", addresses, fakeAccount);
  assert.equal(loaded.accounts.deployer.address, address(1));
  assert.equal(loaded.secrets.length, 0, "check mode holds no secret");

  const partial = { ...addresses };
  delete partial.MORDANT_ADDRESS_HOLDER_A;
  assert.throws(() => loadAccounts("check", partial, fakeAccount), /holderA is not configured/);
});

// --- 4. underfunded wallet ---

test("an underfunded wallet stops the run before Phase 1", async () => {
  const accounts = Object.fromEntries(
    Object.keys(BUDGET).map((role, index) => [role, { address: address(index + 1) }]),
  );
  const balances = { ...BUDGET, holderB: BUDGET.holderB - 1n };
  const client = {
    getBalance: async ({ address: target }) => {
      const role = Object.keys(accounts).find((key) => accounts[key].address === target);
      return balances[role];
    },
  };
  await assert.rejects(assertFunded(client, accounts), (error) => {
    assert.match(error.message, /underfunded or unconfigured wallet\(s\): holderB/);
    return true;
  });

  const funded = await assertFunded(
    { getBalance: async () => 10n ** 19n }, accounts,
  );
  assert.equal(funded.length, 6);
  assert.ok(funded.every((entry) => entry.ok));
});

test("an unconfigured wallet is treated as underfunded", async () => {
  const accounts = { ...Object.fromEntries(Object.keys(BUDGET).map((r, i) => [r, { address: address(i + 1) }])) };
  accounts.buyer = {};
  await assert.rejects(
    assertFunded({ getBalance: async () => 10n ** 19n }, accounts),
    /buyer/,
  );
});

// --- 5. forced estimate failure, and the gas-price cap ---

test("a gas price above the cap stops the run", async () => {
  await assert.rejects(
    assertGasPriceUnderCap({ getGasPrice: async () => DEFAULT_MAX_GAS_PRICE_WEI + 1n }),
    (error) => {
      assert.match(error.message, /BLOCKED — GAS PRICE/);
      return true;
    },
  );
  assert.equal(
    await assertGasPriceUnderCap({ getGasPrice: async () => 102_000_000_000n }),
    102_000_000_000n,
  );
});

// --- 6. divergent readback and cure-window polling ---

test("cure polling waits for chain time to pass the recorded deadline", async () => {
  let timestamp = 100n;
  const client = {
    getBlock: async () => {
      timestamp += 40n;
      return { number: timestamp, timestamp };
    },
  };
  const polls = [];
  const result = await waitForCureDeadline(client, async () => 200n, {
    intervalMs: 1, onPoll: (block, time, deadline) => polls.push({ time, deadline }),
  });
  assert.ok(result.observedTimestamp > result.deadline, "returns only once chain time passed");
  assert.ok(polls.length >= 2, "polled more than once instead of sleeping blindly");
  assert.equal(result.deadline, 200n);
});

test("a zero cure deadline means the conflict was never revealed", async () => {
  await assert.rejects(
    waitForCureDeadline({ getBlock: async () => ({ number: 1n, timestamp: 1n }) }, async () => 0n),
    /never revealed/,
  );
});

test("cure polling gives up rather than waiting forever", async () => {
  await assert.rejects(
    waitForCureDeadline(
      { getBlock: async () => ({ number: 1n, timestamp: 1n }) },
      async () => 10n ** 12n,
      { intervalMs: 1, maxWaitMs: 20 },
    ),
    /did not elapse/,
  );
});

// --- 7. artifacts: interruption, atomicity, no secret ---

test("an interrupted run still leaves the hashes already broadcast", () => {
  const directory = mkdtempSync(join(tmpdir(), "m05-"));
  const prefix = join(directory, "run");
  const report = {
    status: "STOPPED",
    transactions: [
      { label: "MockEligibility", hash: `0x${"ab".repeat(32)}`, block: "10", gas: "363115" },
      { label: "settlement double", hash: `0x${"cd".repeat(32)}`, block: "11", gas: "736949" },
    ],
    steps: [{ phase: "stop", label: "run stopped", detail: "createInvoiceVault reverted" }],
  };
  const written = writeCheckpoint(prefix, report, []);
  const parsed = JSON.parse(readFileSync(written, "utf8"));

  assert.equal(parsed.status, "STOPPED");
  assert.equal(parsed.transactions.length, 2, "both broadcast hashes survive the failure");
  assert.equal(parsed.transactions[0].hash, `0x${"ab".repeat(32)}`, "hashes are kept, not redacted");
  assert.match(parsed.steps[0].detail, /reverted/, "the last readback failure is recorded");
  // Atomic: no temporary file is left behind.
  assert.deepEqual(readdirSync(directory), ["run.json"]);
});

test("a secret never reaches an artifact, even mid-failure", () => {
  const directory = mkdtempSync(join(tmpdir(), "m05-"));
  const prefix = join(directory, "run");
  const report = {
    status: "STOPPED",
    leaked: KEY,
    nested: { alsoLeaked: KEY, blockHash: `0x${"ef".repeat(32)}` },
    transactions: [{ label: "x", hash: `0x${"ab".repeat(32)}` }],
  };
  const written = writeCheckpoint(prefix, report, [KEY]);
  const serialized = readFileSync(written, "utf8");

  assert.doesNotMatch(serialized, new RegExp(KEY.slice(2), "i"), "the key is gone");
  assert.match(serialized, /\[REDACTED\]/);
  assert.match(serialized, new RegExp("ab".repeat(32)), "transaction hashes are still recorded");
  assert.match(serialized, new RegExp("ef".repeat(32)), "an allow-listed hash field survives");

  // Anything key-shaped outside the allow-list goes, even when it is not a known secret.
  const parsed = JSON.parse(serialized);
  assert.equal(parsed.leaked, "[REDACTED]");
  assert.equal(parsed.nested.alsoLeaked, "[REDACTED]");
});

test("key-shaped material in an unexpected field is redacted", () => {
  const { scrubbed, redactedKeys } = scrubReport({
    hash: `0x${"11".repeat(32)}`,
    surprise: `0x${"22".repeat(32)}`,
  }, []);
  assert.equal(scrubbed.hash, `0x${"11".repeat(32)}`, "an allowed field keeps its value");
  assert.equal(scrubbed.surprise, "[REDACTED]");
  assert.deepEqual(redactedKeys, ["surprise"]);
});

test("writing refuses outright if a known secret survives scrubbing", () => {
  const directory = mkdtempSync(join(tmpdir(), "m05-"));
  // A secret embedded inside a longer string is not an exact match, so scrubbing misses it and the
  // final guard must stop the write.
  assert.throws(
    () => writeCheckpoint(join(directory, "run"), { note: `prefix-${KEY}-suffix` }, [KEY]),
    /refusing to write an artifact containing secret material/,
  );
});
