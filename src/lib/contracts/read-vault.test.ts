import assert from "node:assert/strict";
import { test } from "node:test";

import {
  MordantVaultReadError,
  formatSixDecimalAmount,
  toHumanMordantInvoiceVaultSnapshot,
  type RawMordantInvoiceVaultSnapshot,
} from "./read-vault";

const RAW_SNAPSHOT: RawMordantInvoiceVaultSnapshot = Object.freeze({
  chainId: 10_143,
  blockNumber: 42n,
  vaultAddress: "0x1111111111111111111111111111111111111111",
  invoiceRoot: `0x${"22".repeat(32)}`,
  decimals: 6,
  protectionState: Object.freeze({ code: 4, label: "Entitled" }),
  receivableState: Object.freeze({ code: 1, label: "Outstanding" }),
  sequence: 9,
  totalSupply: 40_000_000n,
  initialUnits: 100_000_000n,
  cvaAccounted: 40_000_000n,
  cvaBurned: 60_000_000n,
  faceValue: 110_000_000n,
  initialBond: 10_000_000n,
  bondLocked: 0n,
  bondReturned: 0n,
  entitlementAllocated: 10_000_000n,
  entitlementClaimed: 6_000_000n,
  entitlementClaimedUnits: 60_000_000n,
  entitlementSnapshotSequence: 2,
  entitlementSnapshotSupply: 100_000_000n,
  redemptionEscrow: 44_000_000n,
  redeemedFace: 66_000_000n,
  cvaReleasedFace: 0n,
  settlementCreditTotal: 0n,
  defaultCvaReleaseStarted: false,
  accountedSettlementBalance: 48_000_000n,
  pendingConflict: null,
});

test("six-decimal formatter never loses atomic precision", () => {
  assert.deepEqual(formatSixDecimalAmount(10_000_001n), {
    atomics: "10000001",
    formatted: "10.000001",
    decimals: 6,
  });
  assert.throws(() => formatSixDecimalAmount(-1n), MordantVaultReadError);
});

test("human vault snapshot derives conservation and remaining liabilities", () => {
  const snapshot = toHumanMordantInvoiceVaultSnapshot(RAW_SNAPSHOT);
  assert.equal(snapshot.accounting.bondMatchesInitial, true);
  assert.equal(snapshot.accounting.supplyMatchesCva, true);
  assert.equal(snapshot.accounting.settlementAccountedMatchesComponents, true);
  assert.equal(snapshot.entitlement.unclaimed.formatted, "4.000000");
  assert.equal(snapshot.redemption.remainingFace.formatted, "44.000000");
  assert.equal(snapshot.supply.cvaBurned.formatted, "60.000000");
});

// Face value is discharged through two independent paths. The contract nets both in
// `_refundExcessRedemptionEscrow`; the reader has to net both as well or it overstates the
// buyer's remaining cash obligation after any CVA release.
test("cash-only settlement leaves the uncovered face value", () => {
  const snapshot = toHumanMordantInvoiceVaultSnapshot({
    ...RAW_SNAPSHOT,
    redeemedFace: 66_000_000n,
    cvaReleasedFace: 0n,
  });
  assert.equal(snapshot.redemption.redeemed.formatted, "66.000000");
  assert.equal(snapshot.redemption.cvaReleased.formatted, "0.000000");
  assert.equal(snapshot.redemption.remainingFace.formatted, "44.000000");
});

test("CVA-only settlement discharges face value exactly like cash", () => {
  const snapshot = toHumanMordantInvoiceVaultSnapshot({
    ...RAW_SNAPSHOT,
    redeemedFace: 0n,
    cvaReleasedFace: 66_000_000n,
    defaultCvaReleaseStarted: true,
  });
  assert.equal(snapshot.redemption.cvaReleased.formatted, "66.000000");
  assert.equal(snapshot.redemption.remainingFace.formatted, "44.000000");
  assert.equal(snapshot.redemption.defaultCvaReleaseStarted, true);
});

test("completed mixed cash/CVA settlement leaves no remaining face value", () => {
  const snapshot = toHumanMordantInvoiceVaultSnapshot({
    ...RAW_SNAPSHOT,
    redeemedFace: 44_000_000n,
    cvaReleasedFace: 66_000_000n,
    redemptionEscrow: 0n,
    accountedSettlementBalance: 4_000_000n,
  });
  assert.equal(snapshot.redemption.remainingFace.formatted, "0.000000");
  assert.equal(snapshot.redemption.unfundedLiability.formatted, "0.000000");
  assert.equal(snapshot.accounting.settlementAccountedMatchesComponents, true);
});

test("human snapshot refuses a face value discharged twice", () => {
  assert.throws(
    () => toHumanMordantInvoiceVaultSnapshot({
      ...RAW_SNAPSHOT,
      redeemedFace: 66_000_000n,
      cvaReleasedFace: 44_000_001n,
    }),
    MordantVaultReadError,
  );
});

test("human snapshot refuses escrow above the remaining cash liability", () => {
  assert.throws(
    () => toHumanMordantInvoiceVaultSnapshot({
      ...RAW_SNAPSHOT,
      cvaReleasedFace: 10_000_000n,
    }),
    MordantVaultReadError,
  );
});

test("human snapshot refuses impossible accounting", () => {
  assert.throws(
    () => toHumanMordantInvoiceVaultSnapshot({
      ...RAW_SNAPSHOT,
      entitlementClaimed: 10_000_001n,
    }),
    MordantVaultReadError,
  );
});

// `settlementCreditTotal` is part of the contract's own accounting assertion. If the reader drops
// it, `accountedSettlementBalance` looks unexplained the moment a pull-payment credit accrues.
test("settlement credit is read, formatted and reconciles the accounted balance", () => {
  const snapshot = toHumanMordantInvoiceVaultSnapshot({
    ...RAW_SNAPSHOT,
    settlementCreditTotal: 3_000_000n,
    accountedSettlementBalance: 51_000_000n,
  });
  assert.equal(snapshot.accounting.settlementCreditTotal.formatted, "3.000000");
  assert.equal(snapshot.accounting.settlementCreditTotal.atomics, "3000000");
  assert.equal(snapshot.accounting.settlementAccounted.formatted, "51.000000");
  assert.equal(snapshot.accounting.settlementAccountedMatchesComponents, true);
});

test("an unexplained accounted settlement balance is reported, not hidden", () => {
  const snapshot = toHumanMordantInvoiceVaultSnapshot({
    ...RAW_SNAPSHOT,
    settlementCreditTotal: 3_000_000n,
  });
  assert.equal(snapshot.accounting.settlementAccountedMatchesComponents, false);
});
