// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Canonical economic-asset identity, scheme version 1.
/// @dev Two platforms financing the same invoice must derive the same 256-bit
/// `assetId` from facts they each already hold, without ever exchanging it. This
/// library is the normative on-chain encoder; `contracts/src/identity/README.md`
/// is the normative specification and carries the cross-language test vectors.
///
/// The public `invoiceRoot` of a vault and the private `assetId` are separate
/// concepts and must never be equal: if they were, the identity would be
/// publicly computable and private matching would collapse.
library MordantAssetIdentity {
    /// @dev Bumped only when the encoding or normalization rules change. A
    /// commitment is only comparable with another of the same scheme version.
    uint16 internal constant SCHEME_VERSION = 1;

    bytes32 internal constant IDENTITY_DOMAIN =
        keccak256("mordant.canonical-asset-identity/1");
    bytes32 internal constant COMMITMENT_DOMAIN =
        keccak256("mordant.asset-commitment/1");
    bytes32 internal constant SALT_DOMAIN = keccak256("mordant.asset-salt/1");

    error InvalidIdentityField();
    error UnsupportedSchemeVersion(uint16 supplied);

    /// @notice Normalized economic-asset identity fields.
    /// @dev All string fields arrive already normalized per the specification.
    /// `normalizeAlphanumeric` and `normalizeNamespace` are provided so a caller
    /// can normalize on-chain when it does not trust its own client.
    struct AssetIdentity {
        bytes32 debtorNamespace; // keccak of the normalized namespace label
        bytes32 debtorId; // keccak of the normalized debtor identifier
        bytes32 sellerNamespace;
        bytes32 sellerId;
        bytes32 invoiceNumber; // keccak of the normalized invoice number
        bytes3 currencyCode; // ISO 4217, uppercase, e.g. "USD"
        uint256 amountMinor; // face amount in minor units
        uint8 amountExponent; // minor units per major unit, e.g. 2 for cents
        uint32 issueDateDays; // days since 1970-01-01 UTC
        uint32 dueDateDays; // days since 1970-01-01 UTC, 0 when absent
    }

    /// @notice Computes the canonical 256-bit economic-asset identity.
    /// @dev Dynamic fields are pre-hashed and the whole tuple is `abi.encode`d,
    /// so no field boundary is ambiguous and no two distinct identities can
    /// share an encoding by concatenation.
    function assetId(AssetIdentity memory identity) internal pure returns (bytes32) {
        if (
            identity.debtorNamespace == bytes32(0) || identity.debtorId == bytes32(0)
                || identity.sellerNamespace == bytes32(0) || identity.sellerId == bytes32(0)
                || identity.invoiceNumber == bytes32(0) || identity.currencyCode == bytes3(0)
                || identity.amountMinor == 0 || identity.issueDateDays == 0
        ) revert InvalidIdentityField();
        // dueDateDays == 0 is a permitted null. Any other zero field is not.
        if (identity.dueDateDays != 0 && identity.dueDateDays < identity.issueDateDays) {
            revert InvalidIdentityField();
        }
        return keccak256(
            abi.encode(
                IDENTITY_DOMAIN,
                SCHEME_VERSION,
                identity.debtorNamespace,
                identity.debtorId,
                identity.sellerNamespace,
                identity.sellerId,
                identity.invoiceNumber,
                identity.currencyCode,
                identity.amountMinor,
                identity.amountExponent,
                identity.issueDateDays,
                identity.dueDateDays
            )
        );
    }

    /// @notice Commits an asset identity under a high-entropy per-anchor salt.
    /// @dev The salt is what makes two anchors of the same economic asset carry
    /// unlinkable public commitments. It is never published.
    function assetCommitment(
        bytes32 canonicalAssetId,
        uint16 schemeVersion,
        uint32 identityEpoch,
        bytes32 salt
    ) internal pure returns (bytes32) {
        if (schemeVersion != SCHEME_VERSION) revert UnsupportedSchemeVersion(schemeVersion);
        if (canonicalAssetId == bytes32(0) || salt == bytes32(0) || identityEpoch == 0) {
            revert InvalidIdentityField();
        }
        return keccak256(
            abi.encode(COMMITMENT_DOMAIN, schemeVersion, identityEpoch, canonicalAssetId, salt)
        );
    }

    /// @notice Deterministic per-anchor salt derivation.
    /// @dev The issuer holds one master secret and recovers any anchor's salt
    /// from public data plus that secret. There is therefore no per-anchor
    /// backup to lose; losing the master secret is the single failure mode.
    function deriveSalt(
        bytes32 issuerMasterSecret,
        bytes32 canonicalAssetId,
        uint32 identityEpoch,
        uint256 anchorNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(SALT_DOMAIN, issuerMasterSecret, canonicalAssetId, identityEpoch, anchorNonce)
        );
    }

    /// @notice Normalizes an identifier to uppercase alphanumeric ASCII.
    /// @dev Drops every byte outside [0-9A-Za-z], uppercases the rest. This is
    /// the rule for debtor ids, seller ids and invoice numbers, and it makes
    /// "INV-2026/0042" and "inv 2026 0042" the same identifier.
    function normalizeAlphanumeric(string memory value) internal pure returns (bytes32) {
        bytes memory raw = bytes(value);
        bytes memory out = new bytes(raw.length);
        uint256 length;
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            if (character >= 0x30 && character <= 0x39) {
                out[length++] = bytes1(character); // 0-9
            } else if (character >= 0x41 && character <= 0x5A) {
                out[length++] = bytes1(character); // A-Z
            } else if (character >= 0x61 && character <= 0x7A) {
                out[length++] = bytes1(character - 32); // a-z -> A-Z
            }
        }
        if (length == 0) revert InvalidIdentityField();
        assembly {
            mstore(out, length)
        }
        return keccak256(out);
    }

    /// @notice Normalizes a namespace label to lowercase ASCII letters.
    function normalizeNamespace(string memory value) internal pure returns (bytes32) {
        bytes memory raw = bytes(value);
        bytes memory out = new bytes(raw.length);
        uint256 length;
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            if (character >= 0x61 && character <= 0x7A) {
                out[length++] = bytes1(character); // a-z
            } else if (character >= 0x41 && character <= 0x5A) {
                out[length++] = bytes1(character + 32); // A-Z -> a-z
            }
        }
        if (length == 0) revert InvalidIdentityField();
        assembly {
            mstore(out, length)
        }
        return keccak256(out);
    }
}
