import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  ControlError, assertChainId, assertFundedFor, assertGasUsable, assertKeyMatchesAddress,
  assertWriteAllowed, checkpointPending, scrub, writeArtifact,
} from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);
const stopsAsync = (fn) => assert.rejects(fn, ControlError);

// --- control 2: chain ---

test("the expected chain passes and is returned", async () => {
  assert.equal(await assertChainId({ getChainId: async () => 10_143 }), 10_143);
});

test("any other chain stops the run, mainnet included", async () => {
  await stopsAsync(() => assertChainId({ getChainId: async () => 143 }));
  await stopsAsync(() => assertChainId({ getChainId: async () => 1 }));
});

// --- controls 1 and 3: explicit flag, mandatory artifact ---

test("a non-writing mode needs no output prefix and reports it will not write", () => {
  assert.equal(assertWriteAllowed("check", "broadcast", null), false);
  assert.equal(assertWriteAllowed("check", "run", null), false);
});

test("a writing mode without an output prefix is refused", () => {
  stops(() => assertWriteAllowed("broadcast", "broadcast", null));
  stops(() => assertWriteAllowed("run", "run", ""));
  stops(() => assertWriteAllowed("run", "run", undefined));
});

test("a writing mode with an output prefix is allowed", () => {
  assert.equal(assertWriteAllowed("broadcast", "broadcast", "docs/evidence/x"), true);
});

test("no environment variable is consulted, so the flag alone decides", () => {
  // The removed MORDANT_*_BROADCAST_AUTHORIZED variables must not resurface as a hidden dependency.
  assert.equal(assertWriteAllowed("broadcast", "broadcast", "out"), true);
  assert.equal(assertWriteAllowed("check", "broadcast", "out"), false);
});

// --- control 4: key derives the configured address ---

const ADDRESS = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const OTHER = "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6";
const deriver = (address) => () => ({ address });

test("a key deriving the configured address passes", () => {
  assert.equal(assertKeyMatchesAddress("HOLDER_A", "0xkey", ADDRESS, deriver(ADDRESS)), ADDRESS);
});

test("casing does not matter to the comparison", () => {
  assert.equal(
    assertKeyMatchesAddress("HOLDER_A", "0xkey", ADDRESS.toLowerCase(), deriver(ADDRESS.toUpperCase())),
    ADDRESS.toUpperCase());
});

test("a missing key stops the run", () => {
  stops(() => assertKeyMatchesAddress("HOLDER_A", undefined, ADDRESS, deriver(ADDRESS)));
  stops(() => assertKeyMatchesAddress("HOLDER_A", "", ADDRESS, deriver(ADDRESS)));
});

test("a key deriving a different address stops the run", () => {
  // This is the swapped-keys case that actually occurred.
  stops(() => assertKeyMatchesAddress("HOLDER_A", "0xkey", ADDRESS, deriver(OTHER)));
});

test("an unusable key stops the run with a usable hint", () => {
  assert.throws(
    () => assertKeyMatchesAddress("HOLDER_A", "nothex", ADDRESS, () => { throw new Error("invalid private key"); }),
    /0x prefix/);
});

// --- control 6: fail-closed gas ---

const CEILING = 400_000n;

test("a measured cost within the ceilings returns the budget", () => {
  assert.equal(assertGasUsable(319_513n, 102_000_000_000n, CEILING), 319_513n * 102_000_000_000n);
});

test("an absent, zero or non-bigint gas value stops the run", () => {
  for (const gas of [undefined, null, 0n, -1n, 319_513, "319513"]) {
    stops(() => assertGasUsable(gas, 102_000_000_000n, CEILING));
  }
});

test("an absent, zero or non-bigint price stops the run", () => {
  for (const price of [undefined, null, 0n, 102_000_000_000]) {
    stops(() => assertGasUsable(319_513n, price, CEILING));
  }
});

test("a cost beyond either ceiling stops the run", () => {
  stops(() => assertGasUsable(CEILING + 1n, 1n, CEILING));
  stops(() => assertGasUsable(21_000n, 200_000_000_001n, CEILING));
});

test("a caller may tighten the price ceiling", () => {
  stops(() => assertGasUsable(21_000n, 2n, CEILING, 1n));
});

// --- funding ---

test("a wallet covering the budget passes, exactly at the boundary too", () => {
  assert.equal(assertFundedFor(ADDRESS, 100n, 100n), 100n);
});

test("a wallet short of the budget, or with an unreadable balance, stops the run", () => {
  stops(() => assertFundedFor(ADDRESS, 99n, 100n));
  stops(() => assertFundedFor(ADDRESS, undefined, 100n));
});

// --- scrubbing ---

test("scrub redacts credentials, reaching nested and array-held values", () => {
  const scrubbed = scrub({ data: { magickLink: "https://x/abc", code: 4 }, list: [{ apiKey: "k" }] });
  assert.equal(scrubbed.data.magickLink, "[REDACTED]");
  assert.equal(scrubbed.data.code, 4);
  assert.equal(scrubbed.list[0].apiKey, "[REDACTED]");
});

test("scrub leaves an absent credential absent rather than inventing a placeholder", () => {
  assert.equal(scrub({ magickLink: null }).magickLink, null);
});

// --- control 7 and artifact integrity ---

const scratch = () => join(mkdtempSync(join(tmpdir(), "mordant-controls-")), "artifact");

test("an artifact is written atomically, leaving no temporary file behind", () => {
  const out = scratch();
  const path = writeArtifact(out, { hello: "world" }, {});
  assert.equal(JSON.parse(readFileSync(path, "utf8")).hello, "world");
  assert.deepEqual(readdirSync(join(out, "..")), ["artifact.json"]);
});

test("an artifact containing a configured secret is refused", () => {
  const secret = "0x1234567890abcdef1234567890abcdef";
  assert.throws(
    () => writeArtifact(scratch(), { note: `leaked ${secret}` }, { MORDANT_KEY_HOLDER_A: secret }),
    ControlError);
});

test("a block hash is not mistaken for a secret", () => {
  const out = scratch();
  const blockHash = `0x${"ab".repeat(32)}`;
  const path = writeArtifact(out, { blockHash }, { MORDANT_KEY_HOLDER_A: `0x${"cd".repeat(32)}` });
  assert.equal(JSON.parse(readFileSync(path, "utf8")).blockHash, blockHash);
});

test("a short environment value is not treated as a secret to match on", () => {
  // Matching on a two-character value would reject almost every artifact.
  const path = writeArtifact(scratch(), { note: "ab" }, { MORDANT_KEY_X: "ab" });
  assert.equal(JSON.parse(readFileSync(path, "utf8")).note, "ab");
});

test("a hash is checkpointed as PENDING with no receipt", () => {
  const out = scratch();
  const report = { status: "RUNNING" };
  checkpointPending(report, "0xdead", out, {});
  const written = JSON.parse(readFileSync(`${out}.json`, "utf8"));
  assert.equal(written.execution.hash, "0xdead");
  assert.equal(written.execution.status, "PENDING");
  assert.equal(written.execution.receipt, null);
  assert.ok(written.generatedAt);
});

test("checkpointing preserves execution fields already recorded", () => {
  const report = { execution: { intent: "transfer" } };
  checkpointPending(report, "0xdead", null, {});
  assert.equal(report.execution.intent, "transfer");
  assert.equal(report.execution.status, "PENDING");
});
