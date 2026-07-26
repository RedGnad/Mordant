import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DEMO,
  holderEntitlement,
  holderRedemption,
  requiredBond,
} from "./scenario";

test("demo economics preserve both the 6/4 bond and 66/44 invoice split", () => {
  const [holderA, holderB] = DEMO.holders;
  assert.equal(holderEntitlement(holderA.units, DEMO.initialUnits, DEMO.initialBond), 6);
  assert.equal(holderEntitlement(holderB.units, DEMO.initialUnits, DEMO.initialBond), 4);
  assert.equal(holderRedemption(holderA.units), 66);
  assert.equal(holderRedemption(holderB.units), 44);
});

test("demo reserve amortizes with outstanding units", () => {
  assert.equal(requiredBond(100), 10);
  assert.equal(requiredBond(50), 5);
  assert.equal(requiredBond(0), 0);
  assert.throws(() => requiredBond(101), RangeError);
});
