import assert from "node:assert/strict";
import { test } from "node:test";

import { ControlError } from "./runner-controls.mjs";
import {
  HOLDER_A, HOLDER_B, NEGATIVE_CONTROL, PRIVILEGED, UNCONTROLLED_APASS_WALLET,
  PAYOUT_A_ATOMIC, PAYOUT_B_ATOMIC,
  evaluateGates, formatAtomic, normalizeAddress, planPayouts, sameAddress,
} from "./verify-recourse-v2-demo-config.mjs";

const stops = (fn) => assert.throws(fn, ControlError);

/** Every gate true, so each test below can turn exactly one of them off. */
function passing(overrides = {}) {
  return {
    holderAApass: true, holderBApass: true,
    holderARole: true, holderBRole: true,
    holdersDistinct: true,
    funderToAdapter: true, adapterToHolderA: true, adapterToHolderB: true,
    facilityApass: true, facilityRole: true, cureAuthorized: true,
    payoutsFit: true, solvent: true, minv01Untouched: true,
    negativeControlRefused: true,
    holdersNotPrivileged: true, holdersNotUncontrolled: true,
    ...overrides,
  };
}

// ------------------------------------------------------------------ normalization

test("a lowercase address normalizes to its checksummed form", () => {
  assert.equal(normalizeAddress(HOLDER_B.toLowerCase()), HOLDER_B);
  assert.equal(normalizeAddress(HOLDER_B.toUpperCase().replace("0X", "0x")), HOLDER_B);
});

test("surrounding whitespace is not an address change", () => {
  assert.equal(normalizeAddress(`  ${HOLDER_A}\n`), HOLDER_A);
});

test("comparison survives a case difference between a readback and a literal", () => {
  // A chain readback and a checksummed constant must not disagree on identity.
  assert.equal(sameAddress(HOLDER_A.toLowerCase(), HOLDER_A), true);
  assert.equal(sameAddress(HOLDER_A, HOLDER_B), false);
});

test("anything that is not a 20-byte address is refused", () => {
  stops(() => normalizeAddress("0x1234"));
  stops(() => normalizeAddress(`${HOLDER_A}00`));
  stops(() => normalizeAddress("not-an-address"));
  stops(() => normalizeAddress(undefined));
  stops(() => normalizeAddress(null));
  stops(() => normalizeAddress(12345));
});

test("the zero address is refused rather than normalized", () => {
  // A reverted or unset immutable reads as zero, and zero must never look like a party.
  stops(() => normalizeAddress(`0x${"0".repeat(40)}`, "facility"));
});

test("atomic units render without floating point", () => {
  assert.equal(formatAtomic(2400n, 6), "0.0024");
  assert.equal(formatAtomic(1600n, 6), "0.0016");
  assert.equal(formatAtomic(4000n, 6), "0.004");
  assert.equal(formatAtomic(1000000n, 6), "1");
  assert.equal(formatAtomic(0n, 6), "0");
});

// ------------------------------------------------------------------ payout plan

test("the canonical split fits the funded reserve and keeps the 60/40 allocation", () => {
  const plan = planPayouts(4000n);
  assert.equal(plan.total, 4000n);
  assert.equal(plan.fits, true);
  assert.deepEqual(plan.allocationBps, { a: 6000, b: 4000 });
});

test("a plan larger than the reserve does not fit", () => {
  // The adapter reverts InsufficientReserve, so an oversized plan is not a plan.
  assert.equal(planPayouts(3999n).fits, false);
  assert.equal(planPayouts(0n).fits, false);
});

test("the stale one-aUSDC fixture does not fit the funded reserve", () => {
  // 600000 + 400000 atomic units is 250 times the 4000 actually available.
  assert.equal(planPayouts(4000n, 600_000n, 400_000n).fits, false);
});

test("a zero or negative payout leg is refused", () => {
  stops(() => planPayouts(4000n, 0n, 1600n));
  stops(() => planPayouts(4000n, 2400n, 0n));
  stops(() => planPayouts(4000n, -1n, 1600n));
});

test("the exported payouts are the ones the plan is built from", () => {
  assert.equal(PAYOUT_A_ATOMIC + PAYOUT_B_ATOMIC, 4000n);
});

// ------------------------------------------------------------------ fail-closed

test("all gates true passes", () => {
  const result = evaluateGates(passing());
  assert.equal(result.ok, true);
  assert.deepEqual(result.failed, []);
});

test("any single false gate fails the whole verification", () => {
  for (const key of Object.keys(passing())) {
    const result = evaluateGates(passing({ [key]: false }));
    assert.equal(result.ok, false, `${key} false must fail`);
    assert.equal(result.failed.length, 1, `${key} must fail exactly one gate`);
  }
});

test("a missing observation is a failure, never a pass", () => {
  // An unanswered question is not a satisfied one.
  assert.equal(evaluateGates({}).ok, false);
  assert.equal(evaluateGates(undefined).ok, false);
  assert.equal(evaluateGates(null).ok, false);
  assert.equal(evaluateGates({}).failed.length, 17);
});

test("a truthy non-boolean does not satisfy a gate", () => {
  // A reverted call surfacing "true", 1 or {} must not be scored as a passing readback.
  for (const truthy of ["true", 1, {}, [], "yes"]) {
    assert.equal(evaluateGates(passing({ adapterToHolderB: truthy })).ok, false,
      `${JSON.stringify(truthy)} must not satisfy a gate`);
  }
});

test("adapter-to-holderB is a gate in its own right", () => {
  // The claim that was published without a readback behind it now has to be observed.
  const result = evaluateGates(passing({ adapterToHolderB: false }));
  assert.deepEqual(result.failed, ["adapter to holderB permitted"]);
});

test("a still-qualified negative control fails the run", () => {
  // If the control ever passes, the gates stopped discriminating and nothing they say counts.
  assert.equal(evaluateGates(passing({ negativeControlRefused: false })).ok, false);
});

test("cure authorization is not satisfied by the facility A-Pass alone", () => {
  assert.equal(evaluateGates(passing({ facilityRole: false, cureAuthorized: false })).ok, false);
});

test("the negative control is not one of the two holders", () => {
  assert.notEqual(normalizeAddress(NEGATIVE_CONTROL), normalizeAddress(HOLDER_A));
  assert.notEqual(normalizeAddress(NEGATIVE_CONTROL), normalizeAddress(HOLDER_B));
  assert.notEqual(normalizeAddress(HOLDER_A), normalizeAddress(HOLDER_B));
});

// ------------------------------------------------------------------ custody separation

test("neither holder is a privileged address", () => {
  // A beneficiary that is also the owner, the cure authority or the bridge signer
  // collapses two roles the adapter keeps apart.
  for (const privileged of Object.values(PRIVILEGED)) {
    assert.notEqual(normalizeAddress(privileged), normalizeAddress(HOLDER_A));
    assert.notEqual(normalizeAddress(privileged), normalizeAddress(HOLDER_B));
  }
});

test("the A-Passed but uncontrolled wallet is not a holder", () => {
  // It passes every policy gate and still cannot sign, so it must never be a participant.
  assert.notEqual(normalizeAddress(UNCONTROLLED_APASS_WALLET), normalizeAddress(HOLDER_A));
  assert.notEqual(normalizeAddress(UNCONTROLLED_APASS_WALLET), normalizeAddress(HOLDER_B));
});

test("a privileged or uncontrolled holder fails the run", () => {
  assert.equal(evaluateGates(passing({ holdersNotPrivileged: false })).ok, false);
  assert.equal(evaluateGates(passing({ holdersNotUncontrolled: false })).ok, false);
});
