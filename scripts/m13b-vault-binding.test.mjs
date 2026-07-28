import assert from "node:assert/strict";
import { test } from "node:test";

import {
  checkBindPreconditions, checkBurnPath, checkReleasePath,
} from "./m13b-vault-binding.mjs";

const ZERO = "0x0000000000000000000000000000000000000000";
const TOKEN = "0x66F706D1Dc820CF09EBA5359cE9acd0D290bC17b";
const APASS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const ADAPTER = "0xc0bf43a4ca27e0976195e6661b099742f10507e5";

const goodBind = (overrides = {}) => ({
  adapterApass: true, vaultApass: true,
  participantApass: { buyer: true, originator: true, holderA: true, holderB: true },
  policyTuples: [{ label: "t1", answer: true }, { label: "t2", answer: true }],
  totalSupply: 100_000n, adapterBalance: 100_000n, expectedUnits: 100_000n,
  adapterIsMinter: true, adapterToken: TOKEN, adapterApassRegistry: APASS,
  vaultAdapter: ADAPTER, vaultToken: TOKEN, vaultUnits: 100_000n, boundVault: ZERO,
  expected: { token: TOKEN, apass: APASS, adapter: ADAPTER },
  ...overrides,
});

test("a fully prepared binding passes", () => {
  assert.equal(checkBindPreconditions(goodBind()).ok, true);
});

test("a missing adapter or vault A-Pass blocks binding", () => {
  assert.equal(checkBindPreconditions(goodBind({ adapterApass: false })).ok, false);
  assert.equal(checkBindPreconditions(goodBind({ vaultApass: null })).ok, false);
});

test("a participant without an A-Pass is named", () => {
  const result = checkBindPreconditions(goodBind({
    participantApass: { buyer: true, originator: false, holderA: true, holderB: true } }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /originator/);
});

test("a refused policy tuple blocks binding and is named", () => {
  const result = checkBindPreconditions(goodBind({
    policyTuples: [{ label: "aUSDC advance in", answer: false }] }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /aUSDC advance in/);
});

test("a supply that is not exactly the intended units blocks binding", () => {
  // bindVault compares exactly; one unit either way is a refusal.
  assert.equal(checkBindPreconditions(goodBind({ totalSupply: 99_999n })).ok, false);
  assert.equal(checkBindPreconditions(goodBind({ totalSupply: 100_001n })).ok, false);
  assert.equal(checkBindPreconditions(goodBind({ adapterBalance: 99_999n })).ok, false);
});

test("units held somewhere other than the adapter block binding", () => {
  // Supply right, adapter short: the difference is sitting elsewhere.
  const result = checkBindPreconditions(goodBind({ totalSupply: 100_000n, adapterBalance: 90_000n }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /adapter holds 90000/);
});

test("an adapter without MINTER_ROLE blocks binding", () => {
  assert.equal(checkBindPreconditions(goodBind({ adapterIsMinter: false })).ok, false);
});

test("a cross-link mismatch blocks binding", () => {
  assert.equal(checkBindPreconditions(goodBind({ adapterToken: ZERO })).ok, false);
  assert.equal(checkBindPreconditions(goodBind({ vaultAdapter: ZERO })).ok, false);
  assert.equal(checkBindPreconditions(goodBind({ vaultToken: ZERO })).ok, false);
  assert.equal(checkBindPreconditions(goodBind({ vaultUnits: 1n })).ok, false);
});

test("an already bound adapter blocks binding, since bindVault is one-shot", () => {
  const result = checkBindPreconditions(goodBind({ boundVault: ADAPTER }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /already bound/);
});

test("cross-link comparison ignores checksum casing", () => {
  assert.equal(checkBindPreconditions(goodBind({ adapterToken: TOKEN.toLowerCase() })).ok, true);
});

// --- the two terminal paths differ, and the checks must not be interchangeable ---

test("a clean burn falls in both supply and adapter balance", () => {
  assert.equal(checkBurnPath({ supplyBefore: 100_000n, supplyAfter: 90_000n,
    adapterBefore: 100_000n, adapterAfter: 90_000n, units: 10_000n }).ok, true);
});

test("a burn that did not reduce supply fails", () => {
  // This is what a release looks like, and it must not pass as a burn.
  const result = checkBurnPath({ supplyBefore: 100_000n, supplyAfter: 100_000n,
    adapterBefore: 100_000n, adapterAfter: 90_000n, units: 10_000n });
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /supply fell by 0/);
});

test("a burn of the wrong size fails", () => {
  assert.equal(checkBurnPath({ supplyBefore: 100_000n, supplyAfter: 91_000n,
    adapterBefore: 100_000n, adapterAfter: 90_000n, units: 10_000n }).ok, false);
});

const goodRelease = (overrides = {}) => ({
  supplyBefore: 100_000n, supplyAfter: 100_000n,
  adapterBefore: 100_000n, adapterAfter: 90_000n,
  holderBefore: 0n, holderAfter: 10_000n,
  receiptBefore: 100_000n, receiptAfter: 90_000n,
  units: 10_000n, ...overrides,
});

test("a clean release transfers without burning the token", () => {
  assert.equal(checkReleasePath(goodRelease()).ok, true);
});

test("a release that reduced token supply fails", () => {
  // The token moves; only the vault receipt is burned. Confusing the two is the mistake.
  const result = checkReleasePath(goodRelease({ supplyAfter: 90_000n }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /transfers, it does not burn/);
});

test("a release where the holder received nothing fails", () => {
  assert.equal(checkReleasePath(goodRelease({ holderAfter: 0n })).ok, false);
});

test("a release that burned no receipt units fails", () => {
  const result = checkReleasePath(goodRelease({ receiptAfter: 100_000n }));
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /receipt units burned 0/);
});

test("the holder must receive exactly the units the adapter lost", () => {
  assert.equal(checkReleasePath(goodRelease({ holderAfter: 9_000n })).ok, false);
  assert.equal(checkReleasePath(goodRelease({ adapterAfter: 95_000n })).ok, false);
});
