// Canonical economic-asset identity, scheme version 1.
//
// Reference implementation for clients and off-chain platforms. It must agree
// byte-for-byte with contracts/src/identity/MordantAssetIdentity.sol, because
// two platforms that never communicate derive the same identity independently.
// Disagreement produces a false negative, which for a matching product is the
// dangerous failure direction: the conflict silently goes undetected.

import { encodeAbiParameters, keccak256, stringToBytes, toHex } from "viem";

export const SCHEME_VERSION = 1;

export const IDENTITY_DOMAIN = keccak256(stringToBytes("mordant.canonical-asset-identity/1"));
export const COMMITMENT_DOMAIN = keccak256(stringToBytes("mordant.asset-commitment/1"));
export const SALT_DOMAIN = keccak256(stringToBytes("mordant.asset-salt/1"));

/** Uppercase alphanumeric ASCII only. Everything else is dropped. */
export function normalizeAlphanumeric(value) {
  const filtered = String(value).replace(/[^0-9A-Za-z]/g, "").toUpperCase();
  if (filtered.length === 0) throw new Error("IDENTITY_FIELD_EMPTY");
  return keccak256(stringToBytes(filtered));
}

/** Lowercase ASCII letters only. */
export function normalizeNamespace(value) {
  const filtered = String(value).replace(/[^A-Za-z]/g, "").toLowerCase();
  if (filtered.length === 0) throw new Error("IDENTITY_NAMESPACE_EMPTY");
  return keccak256(stringToBytes(filtered));
}

/** ISO 4217 alpha-3, uppercase, encoded as bytes3. */
export function currencyCode(value) {
  const code = String(value).toUpperCase();
  if (!/^[A-Z]{3}$/.test(code)) throw new Error("INVALID_CURRENCY_CODE");
  return toHex(stringToBytes(code), { size: 3 });
}

/**
 * Days since 1970-01-01 UTC.
 *
 * Accepts an ISO date string, a Date, or an already-encoded day count, so a
 * caller that stores the canonical integer never has to round-trip through a
 * calendar representation. `null`, `undefined` and `0` encode the permitted
 * null, which only the due date may use.
 */
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

/**
 * Canonical 256-bit economic-asset identity.
 *
 * Dynamic fields are pre-hashed and the tuple is abi.encoded, so no field
 * boundary is ambiguous and two distinct identities cannot share an encoding.
 */
export function assetId(identity) {
  const {
    debtorNamespace, debtorId, sellerNamespace, sellerId, invoiceNumber,
    currency, amountMinor, amountExponent, issueDate, dueDate,
  } = identity;

  const encodedIssue = daysSinceEpoch(issueDate);
  const encodedDue = daysSinceEpoch(dueDate);
  if (encodedIssue === 0) throw new Error("ISSUE_DATE_REQUIRED");
  if (encodedDue !== 0 && encodedDue < encodedIssue) throw new Error("DUE_BEFORE_ISSUE");
  const minor = BigInt(amountMinor);
  if (minor === 0n) throw new Error("AMOUNT_REQUIRED");

  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" }, { type: "uint16" },
        { type: "bytes32" }, { type: "bytes32" },
        { type: "bytes32" }, { type: "bytes32" },
        { type: "bytes32" }, { type: "bytes3" },
        { type: "uint256" }, { type: "uint8" },
        { type: "uint32" }, { type: "uint32" },
      ],
      [
        IDENTITY_DOMAIN, SCHEME_VERSION,
        normalizeNamespace(debtorNamespace), normalizeAlphanumeric(debtorId),
        normalizeNamespace(sellerNamespace), normalizeAlphanumeric(sellerId),
        normalizeAlphanumeric(invoiceNumber), currencyCode(currency),
        minor, Number(amountExponent),
        encodedIssue, encodedDue,
      ],
    ),
  );
}

/** Salted commitment. The salt is what makes two anchors unlinkable. */
export function assetCommitment({ canonicalAssetId, schemeVersion = SCHEME_VERSION, identityEpoch, salt }) {
  if (schemeVersion !== SCHEME_VERSION) throw new Error("UNSUPPORTED_SCHEME_VERSION");
  if (!identityEpoch) throw new Error("IDENTITY_EPOCH_REQUIRED");
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "uint32" }, { type: "bytes32" }, { type: "bytes32" }],
      [COMMITMENT_DOMAIN, schemeVersion, Number(identityEpoch), canonicalAssetId, salt],
    ),
  );
}

/**
 * Deterministic per-anchor salt.
 *
 * The issuer keeps one master secret and recovers any anchor's salt from public
 * data. There is no per-anchor backup to lose; losing the master secret is the
 * single failure mode, and it is recoverable only by the issuer.
 */
export function deriveSalt({ issuerMasterSecret, canonicalAssetId, identityEpoch, anchorNonce }) {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint32" }, { type: "uint256" }],
      [SALT_DOMAIN, issuerMasterSecret, canonicalAssetId, Number(identityEpoch), BigInt(anchorNonce)],
    ),
  );
}
