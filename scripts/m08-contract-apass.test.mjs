import assert from "node:assert/strict";
import { test } from "node:test";

import {
  StopError, assertGasUsable, assertRunAuthorized, classifyApassResponse, classifyOutcome, scrub,
} from "./m08-contract-apass.mjs";

const stops = (fn) => assert.throws(fn, StopError);

test("check mode needs neither authorization nor an output prefix", () => {
  assertRunAuthorized("check", {});
  assertRunAuthorized("check", {}, null);
});

test("the flag alone cannot deploy", () => {
  stops(() => assertRunAuthorized("run", {}, "out"));
});

test("a near-miss authorization value cannot deploy", () => {
  for (const value of ["", "no", "YES", "true", "1", " yes"]) {
    stops(() => assertRunAuthorized("run", { MORDANT_M08_BROADCAST_AUTHORIZED: value }, "out"));
  }
});

test("a run without --out is refused, so spending gas always leaves an artifact", () => {
  stops(() => assertRunAuthorized("run", { MORDANT_M08_BROADCAST_AUTHORIZED: "yes" }, null));
});

test("authorization plus an output prefix permits a run", () => {
  assertRunAuthorized("run", { MORDANT_M08_BROADCAST_AUTHORIZED: "yes" }, "docs/evidence/x");
});

test("a plausible deployment cost passes and returns the budget", () => {
  assert.equal(assertGasUsable(600_000n, 102_000_000_000n), 600_000n * 102_000_000_000n);
});

test("an absent, zero or non-bigint gas value stops the run", () => {
  stops(() => assertGasUsable(undefined, 1n));
  stops(() => assertGasUsable(0n, 1n));
  stops(() => assertGasUsable(600_000, 1n));
  stops(() => assertGasUsable(600_000n, undefined));
  stops(() => assertGasUsable(600_000n, 0n));
});

test("an abnormal deployment cost stops the run", () => {
  stops(() => assertGasUsable(2_000_001n, 1n));
  stops(() => assertGasUsable(600_000n, 200_000_000_001n));
});

// --- A-Pass classification: a negative answer is a result, not an error ---

const record = (overrides = {}) => ({
  code: "0000",
  data: { status: 1, tier: "50", subTier: 0, expirationTime: 2_000_000_000, ...overrides },
});

test("an absent A-Pass is reported, not thrown", () => {
  const result = classifyApassResponse({ code: "0002", message: "apass not found" }, false, 1n);
  assert.equal(result.present, false);
  assert.equal(result.envelopeCode, "0002");
  assert.match(result.detail, /not found/);
});

test("a successful envelope with no record is reported as absent", () => {
  const result = classifyApassResponse({ code: "0000", data: null }, false, 1n);
  assert.equal(result.present, false);
});

test("a malformed response with no code stops the run", () => {
  stops(() => classifyApassResponse({}, false, 1n));
  stops(() => classifyApassResponse(undefined, false, 1n));
});

test("an active, future, chain-confirmed A-Pass is usable", () => {
  const result = classifyApassResponse(record(), true, 1_785_000_000n);
  assert.equal(result.present, true);
  assert.equal(result.usable, true);
  assert.equal(result.expired, false);
});

test("a record the chain does not confirm is present but not usable", () => {
  assert.equal(classifyApassResponse(record(), false, 1_785_000_000n).usable, false);
});

test("an inactive status is present but not usable", () => {
  assert.equal(classifyApassResponse(record({ status: 0 }), true, 1_785_000_000n).usable, false);
});

test("an expired or absent expiration is present but not usable", () => {
  assert.equal(classifyApassResponse(record({ expirationTime: 100 }), true, 1_785_000_000n).usable, false);
  assert.equal(classifyApassResponse(record({ expirationTime: 0 }), true, 1n).usable, false);
  assert.equal(classifyApassResponse(record({ expirationTime: null }), true, 1n).usable, false);
});

// --- outcome ---

const usable = { usable: true };

test("a refused request is reported as refused", () => {
  assert.equal(classifyOutcome({ requestAccepted: false, apass: null, canReceive: null }),
    "CONTRACT APASS: REFUSED BY CLEANVERSE");
});

test("an accepted request whose record is unusable is not counted as proven", () => {
  assert.equal(classifyOutcome({ requestAccepted: true, apass: { usable: false }, canReceive: true }),
    "CONTRACT APASS: ACCEPTED BUT NOT USABLE");
  assert.equal(classifyOutcome({ requestAccepted: true, apass: null, canReceive: true }),
    "CONTRACT APASS: ACCEPTED BUT NOT USABLE");
});

test("a usable A-Pass the policy still refuses is not counted as proven", () => {
  assert.equal(classifyOutcome({ requestAccepted: true, apass: usable, canReceive: false }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
  // A reverting canTransfer must not be read as success either.
  assert.equal(classifyOutcome({ requestAccepted: true, apass: usable, canReceive: null }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
});

test("only a credential the policy honours counts as proven", () => {
  assert.equal(classifyOutcome({ requestAccepted: true, apass: usable, canReceive: true }),
    "CONTRACT APASS: PROVEN");
});

test("scrub removes credentials while keeping the fields the classifier reads", () => {
  const scrubbed = scrub({ code: "0000", data: { status: 1, expirationTime: 5, magickLink: "https://x" } });
  assert.equal(scrubbed.data.magickLink, "[REDACTED]");
  assert.equal(scrubbed.data.status, 1);
  assert.equal(scrubbed.data.expirationTime, 5);
});
