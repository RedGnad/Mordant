import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertApassUsable, assertProbeCodeMatches, assertProbeOwnedBy, assertUnchanged, classifyRoundTrip,
} from "./m10-custody-roundtrip.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);

const OWNER = "0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45";
const OTHER = "0x344412229B3b581C19572f9BF1F5d08d4Ae897E6";

// --- the rail is the one we reviewed ---

test("an unchanged address passes regardless of checksum casing", () => {
  assertUnchanged("aUSDC", OWNER.toUpperCase(), OWNER.toLowerCase());
});

test("a changed or missing observation stops the run", () => {
  stops(() => assertUnchanged("policy", OTHER, OWNER));
  stops(() => assertUnchanged("policy", null, OWNER));
  stops(() => assertUnchanged("policy", undefined, OWNER));
});

// --- preflight 4: the probe is the contract we compiled ---

const CODE = `0x${"60".repeat(64)}`;

test("matching code passes and reports its size and hash", () => {
  const facts = assertProbeCodeMatches(CODE, CODE);
  assert.equal(facts.size, 64);
  assert.match(facts.hash, /^0x[0-9a-f]{64}$/);
});

test("code differing only in case still matches", () => {
  assert.ok(assertProbeCodeMatches(CODE.toUpperCase().replace("0X", "0x"), CODE));
});

test("an address with no code stops the run", () => {
  stops(() => assertProbeCodeMatches("0x", CODE));
  stops(() => assertProbeCodeMatches(undefined, CODE));
  stops(() => assertProbeCodeMatches(null, CODE));
});

test("code of a different size stops the run", () => {
  stops(() => assertProbeCodeMatches(`0x${"60".repeat(63)}`, CODE));
});

test("same-size but different code stops the run", () => {
  // A different contract at the reviewed address would take custody under unreviewed rules.
  stops(() => assertProbeCodeMatches(`0x${"61".repeat(64)}`, CODE));
});

// --- preflight 5: only the owner can sweep ---

test("a probe owned by the signer passes", () => {
  assert.equal(assertProbeOwnedBy(OWNER, OWNER), OWNER);
  assert.equal(assertProbeOwnedBy(OWNER.toLowerCase(), OWNER.toUpperCase()), OWNER.toLowerCase());
});

test("a probe owned by anyone else stops the run", () => {
  stops(() => assertProbeOwnedBy(OTHER, OWNER));
  stops(() => assertProbeOwnedBy(null, OWNER));
  stops(() => assertProbeOwnedBy(undefined, OWNER));
});

// --- preflight 6: both credentials usable ---

const apass = (overrides = {}) => ({
  code: "0000", data: { status: 1, tier: "50", subTier: 0, expirationTime: 2_000_000_000, ...overrides },
});

test("an active, unexpired, chain-confirmed A-Pass passes for either party", () => {
  const checked = assertApassUsable("probe", OWNER, apass(), true, 1_785_000_000n);
  assert.equal(checked.status, 1);
  assert.ok(checked.secondsRemaining > 0);
});

test("a failed envelope or missing record stops the run", () => {
  stops(() => assertApassUsable("probe", OWNER, { code: "0002" }, true, 1n));
  stops(() => assertApassUsable("probe", OWNER, { code: "0000", data: null }, true, 1n));
  stops(() => assertApassUsable("probe", OWNER, undefined, true, 1n));
});

test("an inactive status stops the run", () => {
  for (const status of [0, 2, null, undefined]) {
    stops(() => assertApassUsable("probe", OWNER, apass({ status }), true, 1n));
  }
});

test("an absent or zero expiration is not read as unlimited", () => {
  for (const expirationTime of [0, null, undefined, "abc"]) {
    stops(() => assertApassUsable("probe", OWNER, apass({ expirationTime }), true, 1n));
  }
});

test("an expiration at or before the block timestamp stops the run", () => {
  stops(() => assertApassUsable("probe", OWNER, apass({ expirationTime: 1000 }), true, 1000n));
});

test("a record the chain does not confirm stops the run", () => {
  stops(() => assertApassUsable("probe", OWNER, apass(), false, 1n));
  stops(() => assertApassUsable("probe", OWNER, apass(), "true", 1n));
});

// --- the verdict ---

const ok = { ok: true };
const bad = { ok: false };

test("a failed outbound leg is reported as such, not as partial", () => {
  assert.equal(classifyRoundTrip({ outbound: bad, inbound: null, probeFinalBalance: 0n }),
    "CONTRACT AUSDC CUSTODY ROUND-TRIP: OUTBOUND FAILED");
  assert.equal(classifyRoundTrip({ outbound: null, inbound: null, probeFinalBalance: 0n }),
    "CONTRACT AUSDC CUSTODY ROUND-TRIP: OUTBOUND FAILED");
});

test("an outbound that landed with no return is partial, with funds in the probe", () => {
  assert.equal(classifyRoundTrip({ outbound: ok, inbound: null, probeFinalBalance: 1n }),
    "CONTRACT AUSDC CUSTODY ROUND-TRIP: PARTIAL — FUNDS IN PROBE");
  assert.equal(classifyRoundTrip({ outbound: ok, inbound: bad, probeFinalBalance: 1n }),
    "CONTRACT AUSDC CUSTODY ROUND-TRIP: PARTIAL — FUNDS IN PROBE");
});

test("a return that reconciled but left a balance behind is still partial", () => {
  // Both legs reporting ok is not enough: what matters is that the probe ends empty.
  assert.equal(classifyRoundTrip({ outbound: ok, inbound: ok, probeFinalBalance: 1n }),
    "CONTRACT AUSDC CUSTODY ROUND-TRIP: PARTIAL — FUNDS IN PROBE");
});

test("only a completed round trip leaving the probe empty is proven", () => {
  assert.equal(classifyRoundTrip({ outbound: ok, inbound: ok, probeFinalBalance: 0n }),
    "CONTRACT AUSDC CUSTODY ROUND-TRIP: PROVEN");
});

test("no outcome is ever described as a Mordant settlement", () => {
  for (const probeFinalBalance of [0n, 1n]) {
    for (const inbound of [ok, bad, null]) {
      const verdict = classifyRoundTrip({ outbound: ok, inbound, probeFinalBalance });
      assert.equal(verdict.includes("MORDANT"), false, verdict);
      assert.match(verdict, /^CONTRACT AUSDC CUSTODY ROUND-TRIP: /);
    }
  }
});
