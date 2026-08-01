import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import {
  strictStableAssetId, candidateAliasId, candidateAliasCommitment, checkProfileCompatibility,
  assetCommitment, termsCommitment, deriveSalt, normalize, namespace,
  canonicalBytes, currencyCode, daysSinceEpoch, validateTerms, isLossless,
  Profile, Relation, IdentityTier, IDENTITY_SCHEME_VERSION,
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
    sellerProfile: Profile.ALNUM_UPPER_FIXED,
    debtorNamespace: namespace("lei"),
    debtorId: DEBTOR,
    debtorProfile: Profile.ALNUM_UPPER_FIXED,
    invoiceNamespace: namespace("seller"),
    invoiceId: normalize(Profile.INVOICE_CASE_SENSITIVE, invoiceNumber, 0),
    invoiceProfile: Profile.INVOICE_CASE_SENSITIVE,
    tier: IdentityTier.StrictSellerIssued,
    issueDateDays,
  };
}

function candidate(invoiceNumber, issueDateDays = 20_500) {
  return {
    ...identity(invoiceNumber, issueDateDays),
    invoiceId: normalize(Profile.INVOICE_CASE_INSENSITIVE, invoiceNumber, 0),
    invoiceProfile: Profile.INVOICE_CASE_INSENSITIVE,
    tier: IdentityTier.TolerantCandidate,
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

const BASELINE = "0x1a0691ee37d52a8a76723b23e44b4b3f74de8e954b039ee3543c7e4ba66310c2";
const FACE = 110_000_000n;

test("strict identity vectors match the Solidity implementation", () => {
  assert.equal(strictStableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
  // The strict path is non-lossy, so reformatting yields a DIFFERENT identity.
  assert.equal(
    strictStableAssetId(identity("inv 2026 0042", 20_500)),
    "0xf3fb4c2f820ccad3623c54a5df35f8dc416362c48e0d23b238915dc839c82562",
  );
  assert.equal(
    strictStableAssetId(identity("INV-2026-0043", 20_500)),
    "0xe71f6d5522e5dec0ff1fe9bc22600ad202714fd7a15a0a49212a36e2b2babdd1",
  );
  assert.equal(
    strictStableAssetId(identity("INV-2026-0042", 20_501)),
    "0x33534a47d1724360ab690dada2c7b5e7dc0e55020fca414312199ae7e9642290",
  );
});

test("candidate alias vectors match and live in a separate domain", () => {
  const aliasBaseline = candidateAliasId(candidate("INV-2026-0042"));
  assert.equal(aliasBaseline, "0xac93f8e37b46e45c70aea83ebba116049d2e20efd913ef0f8ba8d2f414c156f3");
  // The tolerant path merges formatting differences; that is its whole purpose.
  assert.equal(candidateAliasId(candidate("inv 2026 0042")), aliasBaseline);
  // And it can never be mistaken for a strict identity.
  assert.notEqual(aliasBaseline, BASELINE);
});

test("INV-001 versus IN-V001: candidate may match, exact must not", () => {
  assert.equal(
    candidateAliasId(candidate("INV-001")),
    candidateAliasId(candidate("IN-V001")),
    "tolerant path may suggest reconciliation",
  );
  assert.notEqual(
    strictStableAssetId(identity("INV-001", 20_500)),
    strictStableAssetId(identity("IN-V001", 20_500)),
    "strict path must keep them distinct",
  );
});

test("a lossy profile or tolerant tier cannot produce a binding identity", () => {
  assert.throws(
    () => strictStableAssetId({ ...candidate("INV-001"), tier: IdentityTier.StrictSellerIssued }),
    /LOSSY_PROFILE_NOT_PERMITTED/,
  );
  assert.throws(() => strictStableAssetId(candidate("INV-001")), /CANDIDATE_TIER_CANNOT_BIND/);
  assert.throws(() => candidateAliasId(identity("INV-001", 20_500)), /LOSSLESS_PROFILE_REQUIRED_FOR_TIER/);
  assert.equal(isLossless(Profile.INVOICE_CASE_INSENSITIVE), false);
  assert.equal(isLossless(Profile.INVOICE_CASE_SENSITIVE), true);
});

test("profile mismatch is an explicit protocol error, not an asset mismatch", () => {
  const a = identity("INV-2026-0042", 20_500);
  const b = candidate("INV-2026-0042");
  // Returning false here would say "different receivable" when the truth is
  // "we disagree about how to name receivables". That is a silent false
  // negative, so the gate throws instead.
  assert.throws(() => checkProfileCompatibility(a, b), /IDENTITY_PROFILE_MISMATCH/);
  assert.equal(checkProfileCompatibility(a, identity("INV-9999", 20_500)), true);

  const otherNamespace = { ...a, debtorNamespace: namespace("duns"), debtorProfile: Profile.DIGITS_FIXED };
  assert.throws(() => checkProfileCompatibility(a, otherNamespace), /IDENTITY_PROFILE_MISMATCH:debtorNamespace/);
});

test("terms vectors match, and terms never move the stable identity", () => {
  assert.equal(
    termsCommitment(BASELINE, original(FACE, 20_590)),
    "0x7120e8664e43417df27c828ff6faad7198761b2bbdaab1db68bb9ac2d6634d68",
  );
  assert.equal(
    termsCommitment(BASELINE, original(120_000_000n, 20_590)),
    "0x94276cec10dc6b727f27a5bb7a2ceab6c3001d2bb32a65187b4e8c094ea3b7c5",
  );
  assert.equal(
    termsCommitment(BASELINE, original(FACE, 20_620)),
    "0xe55ddef7cdd2a95115833d9d36d991681bf85cec7036393a5cf3141569f9011b",
  );
  // The identity is untouched by every one of those.
  assert.equal(strictStableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
});

test("commitment and salt vectors match, and commitment domains are separate", () => {
  const issuerMasterSecret = keccak256(stringToBytes("mordant.test.issuer-master-secret"));
  const salt = deriveSalt({ issuerMasterSecret, stableId: BASELINE, identityEpoch: 1, anchorNonce: 1 });
  assert.equal(salt, "0xcc01b11ef4b768954fe117f33bf6da76092282cee3ceee23a24429a4ab97f26d");
  const commitment = assetCommitment({ stableId: BASELINE, identityEpoch: 1, salt });
  assert.equal(commitment, "0x72d8e3b0549a898f4a686e0ec9bc2250a833979f0c27a92890f6166433c70754");
  const alias = candidateAliasCommitment({
    aliasId: candidateAliasId(candidate("INV-2026-0042")), identityEpoch: 1, salt,
  });
  assert.equal(alias, "0x6caa451a9003d46b3b9f61e369f03fa7eb233ab13ffb6b5e9fbd319dfc33b0ec");
  // A candidate commitment can never satisfy a binder expecting an asset one.
  assert.notEqual(commitment, alias);
});

test("same asset with different due dates keeps one identity", () => {
  const a = termsCommitment(BASELINE, original(FACE, 20_590));
  const b = termsCommitment(BASELINE, original(FACE, 20_620));
  assert.notEqual(a, b);
  assert.equal(strictStableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
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
  assert.equal(strictStableAssetId(identity("INV-2026-0042", 20_500)), BASELINE);
  assert.notEqual(strictStableAssetId(identity("INV-2026-0043", 20_500)), BASELINE);
});

test("identical terms under two assets are different commitments", () => {
  const other = strictStableAssetId(identity("INV-2026-0043", 20_500));
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
  const other = strictStableAssetId(identity("INV-2026-0043", 20_500));
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
  const viaVat = { ...identity("INV-2026-0042", 20_500), debtorNamespace: namespace("vat"), debtorId: normalize(Profile.VAT, "FR40303265045"), debtorProfile: Profile.VAT };
  const viaDuns = { ...identity("INV-2026-0042", 20_500), debtorNamespace: namespace("duns"), debtorId: normalize(Profile.DIGITS_FIXED, "150483782", 9), debtorProfile: Profile.DIGITS_FIXED };
  assert.notEqual(strictStableAssetId(viaVat), strictStableAssetId(viaDuns));
  assert.notEqual(strictStableAssetId(viaVat), BASELINE);
});

test("dates encode as days since the unix epoch", () => {
  assert.equal(daysSinceEpoch("2026-02-06"), 20_490);
  assert.equal(daysSinceEpoch(null), 0);
  assert.throws(() => strictStableAssetId(identity("INV-2026-0042", 0)), /ISSUE_DATE_REQUIRED/);
});

test("unsupported scheme version is refused", () => {
  assert.throws(
    () => assetCommitment({ stableId: BASELINE, schemeVersion: IDENTITY_SCHEME_VERSION + 1, identityEpoch: 1, salt: `0x${"11".repeat(32)}` }),
    /UNSUPPORTED_SCHEME_VERSION/,
  );
});
