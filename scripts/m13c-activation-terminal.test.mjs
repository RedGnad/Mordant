import assert from "node:assert/strict";
import { test } from "node:test";

import {
  classifyRehearsal, validateActivation, validateScenarioA, validateScenarioB,
} from "./m13c-activation-terminal.mjs";

const ACTIVATION_EXPECTED = { netProceeds: 90_000n, bond: 10_000n, allocation: 50_000n,
  units: 100_000n, protectionState: 1, receivableState: 1 };
const goodActivation = (overrides = {}) => ({
  netProceedsReceived: "90000", bondLocked: "10000", receiptHolderA: "50000",
  receiptHolderB: "50000", receiptSupply: "100000", cvaAccounted: "100000",
  adapterAvailable: "100000", protectionState: 1, receivableState: 1, assertAccounting: true,
  ...overrides,
});

test("a correct activation validates", () => {
  assert.equal(validateActivation(goodActivation(), ACTIVATION_EXPECTED).ok, true);
});

test("wrong net proceeds or bond fail activation", () => {
  // The whole advance reaching the originator would mean the bond was never retained.
  assert.equal(validateActivation(goodActivation({ netProceedsReceived: "100000" }), ACTIVATION_EXPECTED).ok, false);
  assert.equal(validateActivation(goodActivation({ bondLocked: "0" }), ACTIVATION_EXPECTED).ok, false);
});

test("a lopsided or short receipt allocation fails activation", () => {
  assert.equal(validateActivation(goodActivation({ receiptHolderA: "60000" }), ACTIVATION_EXPECTED).ok, false);
  assert.equal(validateActivation(goodActivation({ receiptSupply: "50000" }), ACTIVATION_EXPECTED).ok, false);
});

test("accounting the adapter does not back fails activation", () => {
  assert.equal(validateActivation(goodActivation({ cvaAccounted: "0" }), ACTIVATION_EXPECTED).ok, false);
  assert.equal(validateActivation(goodActivation({ adapterAvailable: "0" }), ACTIVATION_EXPECTED).ok, false);
});

test("a wrong vault state fails activation", () => {
  assert.equal(validateActivation(goodActivation({ protectionState: 0 }), ACTIVATION_EXPECTED).ok, false);
  assert.equal(validateActivation(goodActivation({ receivableState: 0 }), ACTIVATION_EXPECTED).ok, false);
});

test("a failed assertAccounting fails activation whatever else holds", () => {
  const result = validateActivation(goodActivation({ assertAccounting: false }), ACTIVATION_EXPECTED);
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /assertAccounting/);
});

// --- scenario A ---

const A_EXPECTED = { holderCash: 55_000n, units: 100_000n, faceValue: 110_000n };
const goodA = (overrides = {}) => ({
  redeemed: [{ label: "holderA", cashReceived: "55000", receiptsAfter: "0" },
    { label: "holderB", cashReceived: "55000", receiptsAfter: "0" }],
  supplyAfter: "0", adapterAfter: "0", receiptSupplyAfter: "0", cvaAccounted: "0",
  cvaBurned: "100000", redeemedFace: "110000", redemptionEscrow: "0",
  deltaShape: { ok: true }, assertAccounting: true, ...overrides,
});

test("a correct cash redemption validates", () => {
  assert.equal(validateScenarioA(goodA(), A_EXPECTED).ok, true);
});

test("a holder paid the wrong amount fails scenario A", () => {
  assert.equal(validateScenarioA(goodA({
    redeemed: [{ label: "holderA", cashReceived: "50000", receiptsAfter: "0" },
      { label: "holderB", cashReceived: "55000", receiptsAfter: "0" }] }), A_EXPECTED).ok, false);
});

test("only one redemption fails scenario A", () => {
  assert.equal(validateScenarioA(goodA({
    redeemed: [{ label: "holderA", cashReceived: "55000", receiptsAfter: "0" }] }), A_EXPECTED).ok, false);
});

test("units left anywhere fail scenario A", () => {
  for (const field of ["supplyAfter", "adapterAfter", "receiptSupplyAfter", "cvaAccounted"]) {
    assert.equal(validateScenarioA(goodA({ [field]: "1" }), A_EXPECTED).ok, false, field);
  }
});

test("escrow left behind fails scenario A", () => {
  // A vault that burned correctly but kept escrow would still be broken.
  const result = validateScenarioA(goodA({ redemptionEscrow: "5000" }), A_EXPECTED);
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /redemptionEscrow/);
});

test("wrong cvaBurned or redeemedFace fails scenario A", () => {
  assert.equal(validateScenarioA(goodA({ cvaBurned: "0" }), A_EXPECTED).ok, false);
  assert.equal(validateScenarioA(goodA({ redeemedFace: "100000" }), A_EXPECTED).ok, false);
});

test("a broken delta shape or accounting fails scenario A", () => {
  assert.equal(validateScenarioA(goodA({ deltaShape: { ok: false } }), A_EXPECTED).ok, false);
  assert.equal(validateScenarioA(goodA({ assertAccounting: false }), A_EXPECTED).ok, false);
});

// --- scenario B ---

const B_EXPECTED = { holderUnits: 50_000n, units: 100_000n, faceValue: 110_000n };
const goodB = (overrides = {}) => ({
  releases: [{ label: "holderA", tokenReceived: "50000", receiptsAfter: "0" },
    { label: "holderB", tokenReceived: "50000", receiptsAfter: "0" }],
  supplyBefore: "100000", supplyAfter: "100000", adapterAfter: "0", receiptSupplyAfter: "0",
  cvaAccounted: "0", cvaReleasedFace: "110000", defaultCvaReleaseStarted: true,
  deltaShape: { ok: true }, assertAccounting: true, ...overrides,
});

test("a correct default release validates", () => {
  assert.equal(validateScenarioB(goodB(), B_EXPECTED).ok, true);
});

test("a release that burned the token fails scenario B", () => {
  // This is the discriminator: a release transfers, so supply must not move.
  const result = validateScenarioB(goodB({ supplyAfter: "0" }), B_EXPECTED);
  assert.equal(result.ok, false);
  assert.match(result.reasons.join(), /transfers, it does not burn/);
});

test("a holder given the wrong units fails scenario B", () => {
  assert.equal(validateScenarioB(goodB({
    releases: [{ label: "holderA", tokenReceived: "40000", receiptsAfter: "0" },
      { label: "holderB", tokenReceived: "50000", receiptsAfter: "0" }] }), B_EXPECTED).ok, false);
});

test("receipts left unburned fail scenario B", () => {
  assert.equal(validateScenarioB(goodB({ receiptSupplyAfter: "1" }), B_EXPECTED).ok, false);
  assert.equal(validateScenarioB(goodB({
    releases: [{ label: "holderA", tokenReceived: "50000", receiptsAfter: "10" },
      { label: "holderB", tokenReceived: "50000", receiptsAfter: "0" }] }), B_EXPECTED).ok, false);
});

test("an adapter still holding units fails scenario B", () => {
  assert.equal(validateScenarioB(goodB({ adapterAfter: "1" }), B_EXPECTED).ok, false);
});

test("wrong cvaReleasedFace or an unset default flag fails scenario B", () => {
  assert.equal(validateScenarioB(goodB({ cvaReleasedFace: "0" }), B_EXPECTED).ok, false);
  assert.equal(validateScenarioB(goodB({ defaultCvaReleaseStarted: false }), B_EXPECTED).ok, false);
  assert.equal(validateScenarioB(goodB({ defaultCvaReleaseStarted: "true" }), B_EXPECTED).ok, false);
});

test("a broken delta shape or accounting fails scenario B", () => {
  assert.equal(validateScenarioB(goodB({ deltaShape: { ok: false } }), B_EXPECTED).ok, false);
  assert.equal(validateScenarioB(goodB({ assertAccounting: false }), B_EXPECTED).ok, false);
});

// --- the rehearsal verdict is fail-closed ---

const allStages = { controlA: true, forkPinned: true, binding: true, activation: true,
  scenarioA: true, scenarioB: true };

test("every stage passing proves the rehearsal", () => {
  const verdict = classifyRehearsal(allStages);
  assert.equal(verdict.classification, "M-13 PINNED MONAD FORK REHEARSAL: PROVEN");
  assert.deepEqual(verdict.missing, []);
});

test("any single missing stage leaves it NOT PROVEN, and names the gap", () => {
  for (const stage of Object.keys(allStages)) {
    const verdict = classifyRehearsal({ ...allStages, [stage]: false });
    assert.equal(verdict.classification, "M-13 PINNED MONAD FORK REHEARSAL: NOT PROVEN", stage);
    assert.equal(verdict.missing.length, 1, stage);
  }
});

test("the scenarios alone do not prove the rehearsal", () => {
  // Passing both branches on an unpinned fork, or without control A, proves nothing.
  assert.match(classifyRehearsal({ ...allStages, controlA: false }).classification, /NOT PROVEN/);
  assert.match(classifyRehearsal({ ...allStages, forkPinned: false }).classification, /NOT PROVEN/);
});

test("a truthy non-boolean does not satisfy a stage", () => {
  assert.match(classifyRehearsal({ ...allStages, binding: "yes" }).classification, /NOT PROVEN/);
});
