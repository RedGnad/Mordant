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
  assert.equal(snapshot.entitlement.unclaimed.formatted, "4.000000");
  assert.equal(snapshot.redemption.remainingFace.formatted, "44.000000");
  assert.equal(snapshot.supply.cvaBurned.formatted, "60.000000");
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
