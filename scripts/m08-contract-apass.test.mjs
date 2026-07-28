import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyApassResponse, classifyOutcome } from "./m08-contract-apass.mjs";
import { ControlError } from "./runner-controls.mjs";

const stops = (fn) => assert.throws(fn, ControlError);

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
/** The one combination that counts as proven; each test below breaks exactly one condition. */
const proven = { requestAccepted: true, apass: usable, verifyCode: 4, canReceive: true, canSend: true };

test("a refused request is reported as refused", () => {
  assert.equal(classifyOutcome({ ...proven, requestAccepted: false }),
    "CONTRACT APASS: REFUSED BY CLEANVERSE");
});

test("an accepted request whose record is unusable is not counted as proven", () => {
  assert.equal(classifyOutcome({ ...proven, apass: { usable: false } }),
    "CONTRACT APASS: ACCEPTED BUT NOT USABLE");
  assert.equal(classifyOutcome({ ...proven, apass: null }),
    "CONTRACT APASS: ACCEPTED BUT NOT USABLE");
});

test("a verify_apass code other than 4 is not counted as proven", () => {
  for (const verifyCode of [1, 2, 3, 5, 0, -4, null, undefined, "", NaN]) {
    assert.equal(classifyOutcome({ ...proven, verifyCode }),
      "CONTRACT APASS: ACCEPTED BUT NOT USABLE", `verifyCode ${String(verifyCode)}`);
  }
});

test("a verify_apass code of 4 as a string still counts, since the API is loosely typed", () => {
  assert.equal(classifyOutcome({ ...proven, verifyCode: "4" }), "CONTRACT APASS: PROVEN");
});

test("a contract the policy will not let receive is not counted as proven", () => {
  assert.equal(classifyOutcome({ ...proven, canReceive: false }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
  // A reverting or unread canTransfer must never be read as permission.
  assert.equal(classifyOutcome({ ...proven, canReceive: null }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
});

test("a contract that can receive but cannot send is not counted as proven", () => {
  assert.equal(classifyOutcome({ ...proven, canSend: false }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
});

test("an unread send direction is not counted as proven", () => {
  assert.equal(classifyOutcome({ ...proven, canSend: null }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
  assert.equal(classifyOutcome({ ...proven, canSend: undefined }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
});

test("a truthy non-boolean does not satisfy either direction", () => {
  assert.equal(classifyOutcome({ ...proven, canSend: "true" }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
  assert.equal(classifyOutcome({ ...proven, canReceive: 1 }),
    "CONTRACT APASS: ISSUED BUT TRANSFER STILL REFUSED");
});

test("only all five conditions together count as proven", () => {
  assert.equal(classifyOutcome(proven), "CONTRACT APASS: PROVEN");
});

