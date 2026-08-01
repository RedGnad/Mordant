// Canonical economic-asset identity, scheme version 2.
//
// Reference implementation for clients and off-chain platforms. It must agree
// byte-for-byte with contracts/src/identity/, because two platforms that never
// communicate derive the same identity independently. Disagreement produces a
// false negative, which for a matching product is the dangerous direction: a
// real double-financing silently goes undetected.
//
// Scheme 2 splits what scheme 1 conflated:
//
//   StableAssetIdentity  what the receivable IS, and never changes
//   AssetTermsVersion    what it currently SAYS, and may be amended
//
// Putting currency, amount and due date inside the identity made an amended
// invoice a different asset, which hid exactly the conflicts this product
// exists to find.

import { encodeAbiParameters, keccak256, stringToBytes, toHex } from "viem";

export const IDENTITY_SCHEME_VERSION = 3;
export const TERMS_SCHEME_VERSION = 1;

export const STRICT_IDENTITY_DOMAIN = keccak256(stringToBytes("mordant.strict-stable-asset-identity/3"));
export const CANDIDATE_ALIAS_DOMAIN = keccak256(stringToBytes("mordant.candidate-alias-identity/1"));
export const COMMITMENT_DOMAIN = keccak256(stringToBytes("mordant.asset-commitment/3"));
export const CANDIDATE_COMMITMENT_DOMAIN = keccak256(stringToBytes("mordant.candidate-alias-commitment/1"));
export const TERMS_DOMAIN = keccak256(stringToBytes("mordant.asset-terms/1"));
export const SALT_DOMAIN = keccak256(stringToBytes("mordant.asset-salt/3"));

/** Authority ranking. Binding requires RegistryDocument or StrictSellerIssued. */
export const IdentityTier = Object.freeze({
  None: 0,
  RegistryDocument: 1,
  StrictSellerIssued: 2,
  TolerantCandidate: 3,
});

/** Only these profiles are injective, and only they may produce a binding identity. */
export const LOSSLESS_PROFILES = Object.freeze([1, 2, 3, 4, 5]);
export const isLossless = (profile) => LOSSLESS_PROFILES.includes(Number(profile));
const FIELD_DOMAIN = keccak256(stringToBytes("mordant.normalized-field/2"));
const NAMESPACE_DOMAIN = keccak256(stringToBytes("mordant.namespace/2"));

/** Relation of one terms version to what came before. */
export const Relation = Object.freeze({
  Original: 0,
  Amendment: 1,
  Cancellation: 2,
  CreditNote: 3,
  Replacement: 4,
  Novation: 5,
});

/* ------------------------------------------------------ normalization profiles */

export const Profile = Object.freeze({
  ALNUM_UPPER_FIXED: 1, // LEI: strict, no separators, fixed length
  DIGITS_FIXED: 2, // DUNS, GLN: digits only, leading zeros significant
  VAT: 3, // uppercase, strips only space, dot and hyphen
  HEX_ADDRESS: 4, // 0x + 40 hex, lowercased
  INVOICE_CASE_SENSITIVE: 5, // preserved exactly, no collisions
  INVOICE_CASE_INSENSITIVE: 6, // uppercased, non-alphanumerics dropped: lossy
});

function requirePrintableAscii(value) {
  if (value.length === 0) throw new Error("EMPTY_IDENTIFIER");
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    // No Unicode folding: it maps distinct characters together and would
    // manufacture collisions between genuinely different identifiers.
    if (code < 0x20 || code > 0x7e) throw new Error(`UNSUPPORTED_CHARACTER:${index}`);
  }
}

export function canonicalBytes(profile, value, fixedLength = 0) {
  const raw = String(value);
  requirePrintableAscii(raw);

  switch (profile) {
    case Profile.ALNUM_UPPER_FIXED: {
      if (!/^[0-9A-Za-z]+$/.test(raw)) throw new Error("UNSUPPORTED_CHARACTER");
      if (fixedLength && raw.length !== fixedLength) throw new Error("WRONG_LENGTH");
      return raw.toUpperCase();
    }
    case Profile.DIGITS_FIXED: {
      if (!/^[0-9]+$/.test(raw)) throw new Error("UNSUPPORTED_CHARACTER");
      if (fixedLength && raw.length !== fixedLength) throw new Error("WRONG_LENGTH");
      return raw; // leading zeros are significant and never trimmed
    }
    case Profile.VAT: {
      const stripped = raw.replace(/[ .-]/g, "").toUpperCase();
      if (!/^[A-Z]{2}[A-Z0-9]+$/.test(stripped) || stripped.length < 3) {
        throw new Error("MALFORMED_IDENTIFIER");
      }
      return stripped;
    }
    case Profile.HEX_ADDRESS: {
      if (!/^0[xX][0-9a-fA-F]{40}$/.test(raw)) throw new Error("MALFORMED_IDENTIFIER");
      return `0x${raw.slice(2).toLowerCase()}`;
    }
    case Profile.INVOICE_CASE_SENSITIVE:
      return raw;
    case Profile.INVOICE_CASE_INSENSITIVE: {
      const filtered = raw.replace(/[^0-9A-Za-z]/g, "").toUpperCase();
      if (filtered.length === 0) throw new Error("EMPTY_IDENTIFIER");
      return filtered;
    }
    default:
      throw new Error(`UNKNOWN_PROFILE:${profile}`);
  }
}

/** Domain-separated digest carrying the profile id, so profiles never collide. */
export function normalize(profile, value, fixedLength = 0) {
  const canonical = canonicalBytes(profile, value, fixedLength);
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint8" }, { type: "bytes" }],
      [FIELD_DOMAIN, profile, toHex(stringToBytes(canonical))],
    ),
  );
}

export function namespace(value) {
  const raw = String(value);
  requirePrintableAscii(raw);
  if (!/^[0-9A-Za-z]+$/.test(raw)) throw new Error("UNSUPPORTED_CHARACTER");
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes" }],
      [NAMESPACE_DOMAIN, toHex(stringToBytes(raw.toLowerCase()))],
    ),
  );
}

/* ------------------------------------------------------------ stable identity */

/**
 * The enduring receivable. Every field is identity-defining.
 *
 * Jurisdiction is deliberately absent: every supported namespace is either
 * globally unique (LEI, DUNS, GLN, PEPPOL) or self-scoping (a VAT identifier
 * carries its country prefix), so a separate field would give two ways to
 * express one fact and become a divergence source.
 */
function encodeIdentity(domain, identity) {
  const {
    sellerNamespace, sellerId, sellerProfile,
    debtorNamespace, debtorId, debtorProfile,
    invoiceNamespace, invoiceId, invoiceProfile,
    tier, issueDateDays,
  } = identity;
  if (!issueDateDays) throw new Error("ISSUE_DATE_REQUIRED");
  const parties = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }],
      [sellerNamespace, sellerId, Number(sellerProfile), debtorNamespace, debtorId, Number(debtorProfile)],
    ),
  );
  const document = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }, { type: "uint8" }, { type: "uint32" }],
      [invoiceNamespace, invoiceId, Number(invoiceProfile), Number(tier), Number(issueDateDays)],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "bytes32" }, { type: "bytes32" }],
      [domain, IDENTITY_SCHEME_VERSION, parties, document],
    ),
  );
}

/**
 * The binding identity. Non-lossy by construction: a lossy profile or a tolerant
 * tier cannot produce one at all, which is the structural reason a profile-6
 * equality can never reach a binder.
 */
export function strictStableAssetId(identity) {
  if (identity.tier !== IdentityTier.RegistryDocument && identity.tier !== IdentityTier.StrictSellerIssued) {
    throw new Error("CANDIDATE_TIER_CANNOT_BIND");
  }
  for (const profile of [identity.sellerProfile, identity.debtorProfile, identity.invoiceProfile]) {
    if (!isLossless(profile)) throw new Error(`LOSSY_PROFILE_NOT_PERMITTED:${profile}`);
  }
  return encodeIdentity(STRICT_IDENTITY_DOMAIN, identity);
}

/**
 * The tolerant alias. Separately domain-separated, may be lossy, and only ever
 * signals that private reconciliation may be appropriate.
 */
export function candidateAliasId(identity) {
  if (identity.tier !== IdentityTier.TolerantCandidate) {
    throw new Error("LOSSLESS_PROFILE_REQUIRED_FOR_TIER");
  }
  return encodeIdentity(CANDIDATE_ALIAS_DOMAIN, identity);
}

export function candidateAliasCommitment({ aliasId, identityEpoch, salt }) {
  if (!identityEpoch) throw new Error("IDENTITY_EPOCH_REQUIRED");
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "uint32" }, { type: "bytes32" }, { type: "bytes32" }],
      [CANDIDATE_COMMITMENT_DOMAIN, IDENTITY_SCHEME_VERSION, Number(identityEpoch), aliasId, salt],
    ),
  );
}

/**
 * Pre-evaluation compatibility gate.
 *
 * Two parties must agree on namespace and profile before any FHE work starts.
 * A mismatch is an explicit protocol error, never an asset-mismatch Boolean:
 * returning `false` would tell both sides "different receivable" when the truth
 * is "we disagree about how to name receivables", which is a silent false
 * negative and exactly the failure this product cannot afford.
 */
export function checkProfileCompatibility(a, b) {
  const fields = [
    ["sellerNamespace", "sellerProfile"],
    ["debtorNamespace", "debtorProfile"],
    ["invoiceNamespace", "invoiceProfile"],
  ];
  for (const [namespaceField, profileField] of fields) {
    if (a[namespaceField] !== b[namespaceField]) {
      throw new Error(`IDENTITY_PROFILE_MISMATCH:${namespaceField}`);
    }
    if (Number(a[profileField]) !== Number(b[profileField])) {
      throw new Error(`IDENTITY_PROFILE_MISMATCH:${profileField}`);
    }
  }
  if (Number(a.tier) !== Number(b.tier)) throw new Error("IDENTITY_PROFILE_MISMATCH:tier");
  return true;
}

export function assetCommitment({ stableId, schemeVersion = IDENTITY_SCHEME_VERSION, identityEpoch, salt }) {
  if (schemeVersion !== IDENTITY_SCHEME_VERSION) throw new Error("UNSUPPORTED_SCHEME_VERSION");
  if (!identityEpoch) throw new Error("IDENTITY_EPOCH_REQUIRED");
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "uint32" }, { type: "bytes32" }, { type: "bytes32" }],
      [COMMITMENT_DOMAIN, schemeVersion, Number(identityEpoch), stableId, salt],
    ),
  );
}

export function deriveSalt({ issuerMasterSecret, stableId, identityEpoch, anchorNonce }) {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint32" }, { type: "uint256" }],
      [SALT_DOMAIN, issuerMasterSecret, stableId, Number(identityEpoch), BigInt(anchorNonce)],
    ),
  );
}

/* --------------------------------------------------------------- terms version */

/** Mirrors the Solidity relation rules so a client fails before it signs. */
export function validateTerms(stableId, terms) {
  if (!stableId) throw new Error("STABLE_ASSET_ID_REQUIRED");
  if (!terms.currencyCode || !terms.faceValueMinor || !terms.termsVersion || !terms.effectiveFrom) {
    throw new Error("INVALID_TERMS_FIELD");
  }
  const relation = terms.relation ?? Relation.Original;
  const related = terms.relatedStableAssetId ?? `0x${"00".repeat(32)}`;
  const supersedes = terms.supersedesTermsCommitment ?? `0x${"00".repeat(32)}`;
  const amendmentId = terms.amendmentId ?? `0x${"00".repeat(32)}`;
  const zero = `0x${"00".repeat(32)}`;

  if (relation === Relation.Original) {
    if (Number(terms.termsVersion) !== 1 || supersedes !== zero || amendmentId !== zero || related !== zero) {
      throw new Error("INVALID_RELATION");
    }
  } else if (relation === Relation.Amendment || relation === Relation.Cancellation) {
    if (Number(terms.termsVersion) < 2 || supersedes === zero || related !== zero) {
      throw new Error("INVALID_RELATION");
    }
    if (relation === Relation.Amendment && amendmentId === zero) throw new Error("INVALID_RELATION");
  } else if (related === zero || related.toLowerCase() === stableId.toLowerCase()) {
    // CreditNote, Replacement and Novation describe a DIFFERENT asset that
    // points at this one.
    throw new Error("INVALID_RELATION");
  }
}

export function termsCommitment(stableId, terms, termsSchemeVersion = TERMS_SCHEME_VERSION) {
  if (termsSchemeVersion !== TERMS_SCHEME_VERSION) throw new Error("UNSUPPORTED_SCHEME_VERSION");
  validateTerms(stableId, terms);
  const zero = `0x${"00".repeat(32)}`;
  const economics = keccak256(
    encodeAbiParameters(
      [{ type: "bytes3" }, { type: "uint256" }, { type: "uint8" }, { type: "uint32" }, { type: "bytes32" }],
      [
        terms.currencyCode, BigInt(terms.faceValueMinor), Number(terms.amountExponent),
        Number(terms.dueDateDays ?? 0), terms.paymentScheduleDigest ?? zero,
      ],
    ),
  );
  const lineage = keccak256(
    encodeAbiParameters(
      [{ type: "uint32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint8" }, { type: "bytes32" }, { type: "uint64" }],
      [
        Number(terms.termsVersion), terms.amendmentId ?? zero,
        terms.supersedesTermsCommitment ?? zero, terms.relation ?? Relation.Original,
        terms.relatedStableAssetId ?? zero, BigInt(terms.effectiveFrom),
      ],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "bytes32" }, { type: "uint32" }, { type: "bytes32" }, { type: "bytes32" }],
      [TERMS_DOMAIN, termsSchemeVersion, stableId, Number(terms.termsVersion), economics, lineage],
    ),
  );
}

/** Days since 1970-01-01 UTC. Accepts an ISO string, a Date, or a day count. */
export function daysSinceEpoch(value) {
  if (value === null || value === undefined || value === "") return 0;
  if (typeof value === "number" || typeof value === "bigint") {
    const days = Number(value);
    if (!Number.isInteger(days) || days < 0 || days > 0xffffffff) throw new Error("INVALID_DATE");
    return days;
  }
  const date = value instanceof Date ? value : new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) throw new Error("INVALID_DATE");
  return Math.floor(date.getTime() / 86_400_000);
}

export function currencyCode(value) {
  const code = String(value).toUpperCase();
  if (!/^[A-Z]{3}$/.test(code)) throw new Error("INVALID_CURRENCY_CODE");
  return toHex(stringToBytes(code), { size: 3 });
}
