import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import {
  assetId, assetCommitment, deriveSalt, normalizeAlphanumeric, normalizeNamespace,
  currencyCode, daysSinceEpoch, SCHEME_VERSION,
} from "./asset-identity.mjs";

// These values are emitted by contracts/test/IdentityVectors.t.sol. If this file
// and the Solidity library ever disagree, two platforms holding the same invoice
// derive different identities and a real conflict goes undetected. That is the
// dangerous failure direction for a matching product, so the agreement is
// pinned rather than assumed.
const VECTORS = {
  baseline: {
    input: {
      debtorNamespace: "lei", debtorId: "529900T8BM49AURSDO55",
      sellerNamespace: "lei", sellerId: "213800WAVVOPS85N2205",
      invoiceNumber: "INV-2026-0042", currency: "USD",
      amountMinor: 110_000_000n, amountExponent: 2,
      issueDate: 20_500, dueDate: 20_590,
    },
    assetId: "0x4116fe1fadbf98f677977e80518500ca631242d26da85c0a5327cbba2a9761d8",
  },
  normalizationEquivalent: {
    input: {
      debtorNamespace: "LEI", debtorId: "529900t8bm49aursdo55",
      sellerNamespace: "Lei", sellerId: "213800-wavvops85n2205",
      invoiceNumber: "inv 2026 0042", currency: "USD",
      amountMinor: 110_000_000n, amountExponent: 2,
      issueDate: 20_500, dueDate: 20_590,
    },
    assetId: "0x4116fe1fadbf98f677977e80518500ca631242d26da85c0a5327cbba2a9761d8",
  },
  noDueDate: {
    input: {
      debtorNamespace: "duns", debtorId: "150483782",
      sellerNamespace: "vat", sellerId: "FR40303265045",
      invoiceNumber: "2026/Q1/8891", currency: "EUR",
      amountMinor: 425_000n, amountExponent: 2,
      issueDate: 20_610, dueDate: 0,
    },
    assetId: "0xb819eda4dd7f0bd8f23e5519461ee31aeb987634a891d3dff56d8d6f1b121e0f",
  },
  zeroDecimalCurrency: {
    input: {
      debtorNamespace: "lei", debtorId: "353800A3D5UNTV6H2Y19",
      sellerNamespace: "gln", sellerId: "4012345000009",
      invoiceNumber: "A-77", currency: "JPY",
      amountMinor: 1_250_000n, amountExponent: 0,
      issueDate: 20_701, dueDate: 20_731,
    },
    assetId: "0xcc6ddd8fbf3e06e6bf3beb27b4a0f568848d407e4a50e1e0bdf986c7ae42191b",
  },
};

test("every canonical vector matches the Solidity implementation", () => {
  for (const [name, vector] of Object.entries(VECTORS)) {
    assert.equal(assetId(vector.input), vector.assetId, `vector ${name} diverged`);
  }
});

test("normalization converges: the same invoice written differently is the same asset", () => {
  assert.equal(
    assetId(VECTORS.baseline.input),
    assetId(VECTORS.normalizationEquivalent.input),
  );
});

test("genuinely different invoices stay distinct", () => {
  const ids = new Set(Object.values(VECTORS).map((vector) => assetId(vector.input)));
  // baseline and normalizationEquivalent collapse to one, leaving three.
  assert.equal(ids.size, 3);
});

test("commitment and salt vectors match Solidity", () => {
  const canonicalAssetId = VECTORS.baseline.assetId;
  const issuerMasterSecret = keccak256(stringToBytes("mordant.test.issuer-master-secret"));
  const salt = deriveSalt({ issuerMasterSecret, canonicalAssetId, identityEpoch: 1, anchorNonce: 1 });
  assert.equal(salt, "0xfddf47d5eed3490c5c98ebf5b986bfe4b2b604e8e384e3c23aca48cc2064cc35");
  const commitment = assetCommitment({ canonicalAssetId, identityEpoch: 1, salt });
  assert.equal(commitment, "0x4d7c1f4128b244638593d73d2eb1284952e869e4f8f0c2c516b4ab53f0467b40");
  assert.notEqual(commitment, canonicalAssetId);
});

test("two issuers commit the same asset to unlinkable values", () => {
  const canonicalAssetId = VECTORS.baseline.assetId;
  const first = assetCommitment({
    canonicalAssetId, identityEpoch: 1,
    salt: deriveSalt({
      issuerMasterSecret: keccak256(stringToBytes("platform-one")),
      canonicalAssetId, identityEpoch: 1, anchorNonce: 1,
    }),
  });
  const second = assetCommitment({
    canonicalAssetId, identityEpoch: 1,
    salt: deriveSalt({
      issuerMasterSecret: keccak256(stringToBytes("platform-two")),
      canonicalAssetId, identityEpoch: 1, anchorNonce: 9,
    }),
  });
  assert.notEqual(first, second);
});

test("salt is deterministic and therefore recoverable from the master secret", () => {
  const args = {
    issuerMasterSecret: keccak256(stringToBytes("recoverable")),
    canonicalAssetId: VECTORS.baseline.assetId,
    identityEpoch: 3,
    anchorNonce: 42,
  };
  assert.equal(deriveSalt(args), deriveSalt(args));
});

test("epoch rotation changes the commitment for the same asset and salt", () => {
  const canonicalAssetId = VECTORS.baseline.assetId;
  const salt = deriveSalt({
    issuerMasterSecret: keccak256(stringToBytes("rotate")),
    canonicalAssetId, identityEpoch: 1, anchorNonce: 1,
  });
  assert.notEqual(
    assetCommitment({ canonicalAssetId, identityEpoch: 1, salt }),
    assetCommitment({ canonicalAssetId, identityEpoch: 2, salt }),
  );
});

test("normalization primitives behave as specified", () => {
  assert.equal(normalizeAlphanumeric("INV-2026/0042"), normalizeAlphanumeric("inv 2026 0042"));
  assert.equal(normalizeNamespace("LEI"), normalizeNamespace("lei"));
  assert.notEqual(normalizeAlphanumeric("INV-0042"), normalizeAlphanumeric("INV-0043"));
  assert.equal(currencyCode("usd"), "0x555344");
  assert.throws(() => currencyCode("US"), /INVALID_CURRENCY_CODE/);
  assert.throws(() => normalizeAlphanumeric("---"), /IDENTITY_FIELD_EMPTY/);
});

test("dates encode as days since the unix epoch and null is permitted only for due date", () => {
  assert.equal(daysSinceEpoch("2026-02-06"), 20_490);
  assert.equal(daysSinceEpoch(null), 0);
  assert.equal(daysSinceEpoch(undefined), 0);
  assert.throws(
    () => assetId({ ...VECTORS.baseline.input, issueDate: 0 }),
    /ISSUE_DATE_REQUIRED/,
  );
  assert.throws(
    () => assetId({ ...VECTORS.baseline.input, dueDate: 20_000 }),
    /DUE_BEFORE_ISSUE/,
  );
});

test("an amended invoice is a different economic asset", () => {
  // Amount is part of the identity, so an amendment supersedes rather than
  // mutates: the amended invoice has its own identity and its own anchor.
  const amended = { ...VECTORS.baseline.input, amountMinor: 120_000_000n };
  assert.notEqual(assetId(amended), VECTORS.baseline.assetId);
});

test("unsupported scheme version is refused", () => {
  assert.throws(
    () => assetCommitment({
      canonicalAssetId: VECTORS.baseline.assetId,
      schemeVersion: SCHEME_VERSION + 1,
      identityEpoch: 1,
      salt: `0x${"11".repeat(32)}`,
    }),
    /UNSUPPORTED_SCHEME_VERSION/,
  );
});
