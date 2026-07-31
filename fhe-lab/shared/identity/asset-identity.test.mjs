import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import {
  stableAssetId, assetCommitment, termsCommitment, deriveSalt, normalize, namespace,
  canonicalBytes, currencyCode, daysSinceEpoch, validateTerms,
  Profile, Relation, IDENTITY_SCHEME_VERSION,
} from "./asset-identity.mjs";

// Emitted by contracts/test/IdentityVectors.t.sol. Two platforms that never
// communicate must derive the same stable identity, so the agreement between
// this file and the Solidity library is pinned rather than assumed.
const SELLER = normalize(Profile.ALNUM_UPPER_FIXED, "213800WAVVOPS85N2205", 20);
const DEBTOR = normalize(Profile.ALNUM_UPPER_FIXED, "529900T8BM49AURSDO55", 20);

function identity(invoiceNumber, issueDateDays) {
  return {
    sellerNamespace: namespace("lei"),
    sellerId: SELLER,
    debtorNamespace: namespace("lei"),
    debtorId: DEBTOR,
    invoiceNamespace: namespace("seller"),
    invoiceId: normalize(Profile.INVOICE_CASE_INSENSITIVE, invoiceNumber, 0),
    issueDateDays,
  };
}

function original(faceValueMinor, dueDateDays) {
  return {
    currencyCode: currencyCode("USD"),
    faceValueMinor,
    amountExponent: 2,
    dueDateDays,
    paymentScheduleDigest: `0x${"00".repeat(32)}`,
    termsVersion: 1,
    amendmentId: `0x${"00".repeat(32)}`,
    supersedesTermsCommitment: `0x${"00".repeat(32)}`,
    relation: Relation.Original,
    relatedStableAssetId: `0x${"00".repeat(32)}`,
    effectiveFrom: 1_760_000_000n,
  };
}

const BASELINE = "0x060778b5d9ddb677b48068aee8a3ca13bb64683cc37ff44b012407a2c8fcde53";
const FACE = 110_000_000n;

test("stable identity vectors match the Solidity implementation", () => {
  assert.equal(stableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
  assert.equal(
    stableAssetId(identity("inv 2026 0042", 20_500)),
    BASELINE,
    "formatting must not change identity",
  );
  assert.equal(
    stableAssetId(identity("INV-2026-0043", 20_500)),
    "0x215e176b4eddbf78bcaeb3a1d08a5892a39fa633799d242e6bda19fec045674a",
  );
  assert.equal(
    stableAssetId(identity("INV-2026-0042", 20_501)),
    "0x38224eebfcaa6c04c89ab68fd85ee23f6fd5665f13397b1492b7e16d5e2e5823",
  );
});

test("terms vectors match, and terms never move the stable identity", () => {
  assert.equal(
    termsCommitment(BASELINE, original(FACE, 20_590)),
    "0xd833732a67d31774e45d85e39d5fe1149143e032a091bfeb4b0fefa09bdfec1c",
  );
  assert.equal(
    termsCommitment(BASELINE, original(120_000_000n, 20_590)),
    "0xa50db32ab31c3e20c925a0169553be2dc020e00e383c272e4049aa33ad1cb595",
  );
  assert.equal(
    termsCommitment(BASELINE, original(FACE, 20_620)),
    "0x2411f484a4271c989dd07eb461b28ab63d9fdab95d2a78404c8cd532242bf2ca",
  );
  // The identity is untouched by every one of those.
  assert.equal(stableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
});

test("commitment and salt vectors match", () => {
  const issuerMasterSecret = keccak256(stringToBytes("mordant.test.issuer-master-secret"));
  const salt = deriveSalt({ issuerMasterSecret, stableId: BASELINE, identityEpoch: 1, anchorNonce: 1 });
  assert.equal(salt, "0x7b7a1004e942194ee50f3ae1e53251b239cd7952bea8e13fec02f38ac2534699");
  assert.equal(
    assetCommitment({ stableId: BASELINE, identityEpoch: 1, salt }),
    "0xdbe34193bdc60e205060888f9bc66457b8bceaa92cc2e2eb16f7ad273ec51bc6",
  );
});

test("same asset with different due dates keeps one identity", () => {
  const a = termsCommitment(BASELINE, original(FACE, 20_590));
  const b = termsCommitment(BASELINE, original(FACE, 20_620));
  assert.notEqual(a, b);
  assert.equal(stableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
});

test("an amended amount is the same asset, a different invoice is not", () => {
  const originalTerms = termsCommitment(BASELINE, original(FACE, 20_590));
  const amended = {
    ...original(120_000_000n, 20_590),
    termsVersion: 2,
    relation: Relation.Amendment,
    amendmentId: keccak256(stringToBytes("amendment-1")),
    supersedesTermsCommitment: originalTerms,
  };
  assert.notEqual(termsCommitment(BASELINE, amended), originalTerms);
  assert.equal(stableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
  assert.notEqual(stableAssetId(identity("INV-2026-0043", 20_500)), BASELINE);
});

test("identical terms under two assets are different commitments", () => {
  const other = stableAssetId(identity("INV-2026-0043", 20_500));
  assert.notEqual(
    termsCommitment(BASELINE, original(FACE, 20_590)),
    termsCommitment(other, original(FACE, 20_590)),
  );
});

test("relation rules fail closed", () => {
  assert.throws(
    () => termsCommitment(BASELINE, { ...original(FACE, 20_590), supersedesTermsCommitment: keccak256(stringToBytes("x")) }),
    /INVALID_RELATION/,
  );
  assert.throws(
    () => termsCommitment(BASELINE, { ...original(FACE, 20_590), relation: Relation.Amendment, termsVersion: 2, amendmentId: keccak256(stringToBytes("a")) }),
    /INVALID_RELATION/,
  );
  assert.throws(
    () => termsCommitment(BASELINE, { ...original(FACE, 20_590), relation: Relation.CreditNote, relatedStableAssetId: BASELINE }),
    /INVALID_RELATION/,
  );
  // A credit note pointing at a different asset is well formed.
  const other = stableAssetId(identity("INV-2026-0043", 20_500));
  assert.doesNotThrow(() => validateTerms(other, { ...original(10_000_000n, 20_600), relation: Relation.CreditNote, relatedStableAssetId: BASELINE }));
});

test("intended formatting equivalence", () => {
  assert.equal(
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "INV-2026/0042"),
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "inv 2026 0042"),
  );
  assert.equal(normalize(Profile.VAT, "FR 40.303-265045"), normalize(Profile.VAT, "fr40303265045"));
});

test("the lenient invoice profile is lossy and the strict one is not", () => {
  // Documented collision: this is the cost of tolerating formatting.
  assert.equal(
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "INV-001"),
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "IN-V001"),
  );
  assert.notEqual(
    normalize(Profile.INVOICE_CASE_SENSITIVE, "INV-001"),
    normalize(Profile.INVOICE_CASE_SENSITIVE, "IN-V001"),
  );
  // Case matters only where the profile says it does.
  assert.notEqual(
    normalize(Profile.INVOICE_CASE_SENSITIVE, "inv-001"),
    normalize(Profile.INVOICE_CASE_SENSITIVE, "INV-001"),
  );
  assert.equal(
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "inv-001"),
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "INV-001"),
  );
  // The profile id is inside the digest, so profiles never collide.
  assert.notEqual(
    normalize(Profile.INVOICE_CASE_SENSITIVE, "INV001"),
    normalize(Profile.INVOICE_CASE_INSENSITIVE, "INV001"),
  );
});

test("leading zeros are significant and lengths are enforced", () => {
  assert.notEqual(
    normalize(Profile.DIGITS_FIXED, "000000001", 9),
    normalize(Profile.DIGITS_FIXED, "100000000", 9),
  );
  assert.equal(canonicalBytes(Profile.DIGITS_FIXED, "000000001", 9), "000000001");
  assert.throws(() => normalize(Profile.DIGITS_FIXED, "00000001", 9), /WRONG_LENGTH/);
  assert.throws(() => normalize(Profile.DIGITS_FIXED, "000-00001", 9), /UNSUPPORTED_CHARACTER/);
  assert.throws(() => normalize(Profile.ALNUM_UPPER_FIXED, "213800-WAVVOPS85N220", 20), /UNSUPPORTED_CHARACTER/);
});

test("non-ASCII fails closed rather than folding", () => {
  assert.throws(() => normalize(Profile.INVOICE_CASE_INSENSITIVE, "Ｉ NV001"), /UNSUPPORTED_CHARACTER/);
  assert.throws(() => normalize(99, "anything"), /UNKNOWN_PROFILE/);
  assert.throws(() => currencyCode("US"), /INVALID_CURRENCY_CODE/);
});

test("the same characters in different namespaces are different parties", () => {
  const viaVat = { ...identity("INV-2026-0042", 20_500), debtorNamespace: namespace("vat"), debtorId: normalize(Profile.VAT, "FR40303265045") };
  const viaDuns = { ...identity("INV-2026-0042", 20_500), debtorNamespace: namespace("duns"), debtorId: normalize(Profile.DIGITS_FIXED, "150483782", 9) };
  assert.notEqual(stableAssetId(viaVat), stableAssetId(viaDuns));
  assert.notEqual(stableAssetId(viaVat), BASELINE);
});

test("dates encode as days since the unix epoch", () => {
  assert.equal(daysSinceEpoch("2026-02-06"), 20_490);
  assert.equal(daysSinceEpoch(null), 0);
  assert.throws(() => stableAssetId(identity("INV-2026-0042", 0)), /ISSUE_DATE_REQUIRED/);
});

test("unsupported scheme version is refused", () => {
  assert.throws(
    () => assetCommitment({ stableId: BASELINE, schemeVersion: IDENTITY_SCHEME_VERSION + 1, identityEpoch: 1, salt: `0x${"11".repeat(32)}` }),
    /UNSUPPORTED_SCHEME_VERSION/,
  );
});
