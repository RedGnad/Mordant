import assert from "node:assert/strict";
import { test } from "node:test";

import { assertAPassUsable, assertDistinct, assertUnchanged, reconcileTransfer } from "./m07-ausdc-transfer.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);

const SENDER = "0xAAAAaaAAaaAAaAaAAaaaAAAAAaaAaAAaAAAAaAaA";
const RECIPIENT = "0xBBbBbBBbBbbBbbBBBbbbbbBBbBbbBBBbBbbbBBbB";
const FEE = "0xCCCcCCCccCCcCCCCCCcCCcCcCCcCCCcCcccCCccC";
const ZERO = "0x0000000000000000000000000000000000000000";

test("an unchanged address passes regardless of checksum casing", () => {
  assertUnchanged("aUSDC", "0xAC0893567D43C3E7E6E35A72803DF05416C1F20D",
    "0xaC0893567D43C3E7e6e35a72803df05416C1f20D");
});

test("a changed implementation stops the run", () => {
  stops(() => assertUnchanged("implementation", "0x0000000000000000000000000000000000000001", "0xabc"));
});

test("a missing observation stops the run rather than passing as absent", () => {
  stops(() => assertUnchanged("implementation", null, "0xabc"));
  stops(() => assertUnchanged("implementation", undefined, "0xabc"));
});

test("a self-transfer is refused, including across casing", () => {
  stops(() => assertDistinct("0xabc", "0xabc"));
  stops(() => assertDistinct("0xAbC", "0xaBc"));
});

test("an unset participant stops the run", () => {
  stops(() => assertDistinct(undefined, "0xabc"));
  stops(() => assertDistinct("0xabc", ""));
});

test("two distinct wallets pass", () => {
  assertDistinct("0xaaa", "0xbbb");
});

// --- A-Pass gate ---

const goodApass = (overrides = {}) => ({
  code: "0000",
  data: { status: 1, tier: 20, subTier: 0, expirationTime: 2_000_000_000, ...overrides },
});

test("an active, unexpired, on-chain confirmed A-Pass passes", () => {
  const checked = assertAPassUsable("HOLDER_A", SENDER, goodApass(), true, 1_785_000_000n);
  assert.equal(checked.status, 1);
  assert.equal(checked.expirationTime, 2_000_000_000);
  assert.ok(checked.secondsRemaining > 0);
});

test("a failed query_apass envelope stops the run", () => {
  stops(() => assertAPassUsable("A", SENDER, { code: "9999", data: null }, true, 1n));
  stops(() => assertAPassUsable("A", SENDER, undefined, true, 1n));
});

test("a successful envelope with no record stops the run", () => {
  stops(() => assertAPassUsable("A", SENDER, { code: "0000", data: null }, true, 1n));
  stops(() => assertAPassUsable("A", SENDER, { code: "0000", data: "nope" }, true, 1n));
});

test("an inactive status stops the run", () => {
  for (const status of [0, 2, 3, null, undefined]) {
    stops(() => assertAPassUsable("A", SENDER, goodApass({ status }), true, 1n));
  }
});

test("an absent or zero expiration is not treated as unlimited", () => {
  for (const expirationTime of [0, null, undefined, "", "abc"]) {
    stops(() => assertAPassUsable("A", SENDER, goodApass({ expirationTime }), true, 1n));
  }
});

test("an expiration at or before the block timestamp stops the run", () => {
  stops(() => assertAPassUsable("A", SENDER, goodApass({ expirationTime: 1000 }), true, 1000n));
  stops(() => assertAPassUsable("A", SENDER, goodApass({ expirationTime: 999 }), true, 1000n));
});

test("a valid record still stops when the chain disagrees", () => {
  stops(() => assertAPassUsable("A", SENDER, goodApass(), false, 1n));
  stops(() => assertAPassUsable("A", SENDER, goodApass(), null, 1n));
  // A truthy non-boolean must not satisfy the on-chain check either.
  stops(() => assertAPassUsable("A", SENDER, goodApass(), "true", 1n));
});

// --- reconciliation ---

const reconcile = (events, measured) => reconcileTransfer({
  events, amount: 1n, sender: SENDER, recipient: RECIPIENT, measured });

test("a clean one-unit transfer reconciles", () => {
  const result = reconcile(
    [{ from: SENDER, to: RECIPIENT, value: "1" }],
    { [SENDER.toLowerCase()]: "-1", [RECIPIENT.toLowerCase()]: "1" });
  assert.equal(result.ok, true, result.reasons.join("; "));
  assert.equal(result.senderDebit, "1");
  assert.equal(result.recipientCredit, "1");
  assert.equal(result.feeCharged, false);
  assert.deepEqual(result.counterparties, []);
});

test("a fee split is discovered from the events, not assumed", () => {
  const result = reconcileTransfer({
    events: [{ from: SENDER, to: RECIPIENT, value: "7" }, { from: SENDER, to: FEE, value: "3" }],
    amount: 10n, sender: SENDER, recipient: RECIPIENT,
    measured: { [SENDER.toLowerCase()]: "-10", [RECIPIENT.toLowerCase()]: "7", [FEE.toLowerCase()]: "3" },
  });
  assert.equal(result.ok, true, result.reasons.join("; "));
  assert.equal(result.feeCharged, true);
  assert.equal(result.counterparties.length, 1);
  assert.equal(result.counterparties[0].address, FEE.toLowerCase());
  assert.equal(result.counterparties[0].net, "3");
});

test("a burn is read from the events and does not count as a fee", () => {
  const result = reconcileTransfer({
    events: [{ from: SENDER, to: RECIPIENT, value: "8" }, { from: SENDER, to: ZERO, value: "2" }],
    amount: 10n, sender: SENDER, recipient: RECIPIENT,
    measured: { [SENDER.toLowerCase()]: "-10", [RECIPIENT.toLowerCase()]: "8" },
  });
  assert.equal(result.ok, true, result.reasons.join("; "));
  assert.equal(result.burned, "2");
  assert.equal(result.feeCharged, false);
  assert.equal(result.counterparties[0].isBurn, true);
});

test("no Transfer event fails reconciliation", () => {
  const result = reconcile([], {});
  assert.equal(result.ok, false);
  assert.match(result.reasons.join("; "), /no aUSDC Transfer event/);
});

test("a sender debit other than the intended amount fails", () => {
  const result = reconcile(
    [{ from: SENDER, to: RECIPIENT, value: "5" }],
    { [SENDER.toLowerCase()]: "-5", [RECIPIENT.toLowerCase()]: "5" });
  assert.equal(result.ok, false);
  assert.match(result.reasons.join("; "), /debit the sender 5, expected exactly 1/);
});

test("a recipient credited nothing fails, even when the sender paid", () => {
  const result = reconcile(
    [{ from: SENDER, to: FEE, value: "1" }],
    { [SENDER.toLowerCase()]: "-1", [FEE.toLowerCase()]: "1" });
  assert.equal(result.ok, false);
  assert.match(result.reasons.join("; "), /credit the recipient 0/);
});

test("balances disagreeing with the logs fail reconciliation", () => {
  const result = reconcile(
    [{ from: SENDER, to: RECIPIENT, value: "1" }],
    { [SENDER.toLowerCase()]: "-1", [RECIPIENT.toLowerCase()]: "0" });
  assert.equal(result.ok, false);
  assert.equal(result.mismatches.length, 1);
  assert.match(result.reasons.join("; "), /disagree with the events/);
});

test("an unexpected mint during the transfer fails", () => {
  const result = reconcile(
    [{ from: ZERO, to: RECIPIENT, value: "1" }, { from: SENDER, to: RECIPIENT, value: "1" }],
    { [SENDER.toLowerCase()]: "-1", [RECIPIENT.toLowerCase()]: "2" });
  assert.equal(result.ok, false);
  assert.match(result.reasons.join("; "), /minted during the transfer/);
});

test("reconciliation is case-insensitive about addresses", () => {
  const result = reconcile(
    [{ from: SENDER.toLowerCase(), to: RECIPIENT.toUpperCase().replace("0X", "0x"), value: "1" }],
    { [SENDER.toLowerCase()]: "-1", [RECIPIENT.toLowerCase()]: "1" });
  assert.equal(result.ok, true, result.reasons.join("; "));
});

