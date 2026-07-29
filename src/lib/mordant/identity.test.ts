import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ROOTLINE_SPACINGS,
  ROOTLINE_USAGE_NOTICE,
  ROOTLINE_WIDTHS,
  rootlineSegments,
  syntheticFolioForScenario,
  syntheticInvoiceRootForScenario,
} from "./identity";
import { SYNTHETIC_DEALS } from "./product-model";

test("assigns every synthetic scenario a stable unique immutable root", () => {
  const roots = SYNTHETIC_DEALS.map((deal) => deal.machines.receivable.immutableInvoiceRoot);

  assert.equal(new Set(roots).size, SYNTHETIC_DEALS.length);
  for (const deal of SYNTHETIC_DEALS) {
    assert.equal(
      deal.machines.receivable.immutableInvoiceRoot,
      syntheticInvoiceRootForScenario(deal.scenario),
    );
  }
});

test("assigns stable unique folios to all fourteen scenarios", () => {
  const folios = SYNTHETIC_DEALS.map((deal) => syntheticFolioForScenario(deal.scenario));

  assert.equal(folios.length, 14);
  assert.equal(new Set(folios).size, folios.length);
  assert.equal(syntheticFolioForScenario("cure-expiring"), "MRD-S02481");
  assert.equal(syntheticFolioForScenario("cure-expiring"), syntheticFolioForScenario("cure-expiring"));
});

test("derives stable rootlines using all six widths and all three spacings", () => {
  const root = syntheticInvoiceRootForScenario("cure-expiring");
  const first = rootlineSegments(root);
  const second = rootlineSegments(root);

  assert.deepEqual(first, second);
  assert.equal(first.length, 8);
  assert.deepEqual(new Set(first.map((segment) => segment.width)), new Set(ROOTLINE_WIDTHS));
  assert.deepEqual(new Set(first.map((segment) => segment.spacing)), new Set(ROOTLINE_SPACINGS));
});

test("keeps each fixture rootline distinct and explicitly non-probatory", () => {
  const signatures = SYNTHETIC_DEALS.map((deal) =>
    JSON.stringify(rootlineSegments(deal.machines.receivable.immutableInvoiceRoot)),
  );

  assert.equal(new Set(signatures).size, SYNTHETIC_DEALS.length);
  assert.match(ROOTLINE_USAGE_NOTICE, /navigation aid only/i);
  assert.match(ROOTLINE_USAGE_NOTICE, /not cryptographic proof/i);
});

test("rejects missing roots and unregistered scenario folios", () => {
  assert.throws(() => rootlineSegments(""), /immutable invoice root/i);
  assert.throws(() => syntheticFolioForScenario("not-a-fixture"), /no synthetic folio/i);
  assert.throws(() => syntheticInvoiceRootForScenario("Not a slug"), /invalid synthetic scenario/i);
});
