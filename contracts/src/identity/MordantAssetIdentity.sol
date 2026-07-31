// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MordantNormalization} from "./MordantNormalization.sol";

/// @notice Canonical economic-asset identity, scheme version 2.
/// @dev Scheme 1 put currency, amount and due date inside the identity, so an
/// amended invoice became a different asset. That is exactly backwards for this
/// product: Mode B exists to find "same receivable, conflicting terms", and a
/// terms-bearing identity makes that case invisible. Scheme 2 splits the two.
///
///   StableAssetIdentity  what the receivable IS, and never changes
///   AssetTermsVersion    what the receivable currently SAYS, and may be amended
///
/// The FHE equality runs over the stable identity. The confidential policy runs
/// over the terms. Neither is ever compared in the clear.
library MordantAssetIdentity {
    uint16 internal constant IDENTITY_SCHEME_VERSION = 3;
    uint16 internal constant TERMS_SCHEME_VERSION = 1;

    /// @dev Strict and candidate identities live under separate domains, so a
    /// value produced on one path can never be presented as the other.
    bytes32 internal constant STRICT_IDENTITY_DOMAIN =
        keccak256("mordant.strict-stable-asset-identity/3");
    bytes32 internal constant CANDIDATE_ALIAS_DOMAIN =
        keccak256("mordant.candidate-alias-identity/1");
    bytes32 internal constant COMMITMENT_DOMAIN = keccak256("mordant.asset-commitment/3");
    bytes32 internal constant CANDIDATE_COMMITMENT_DOMAIN =
        keccak256("mordant.candidate-alias-commitment/1");
    bytes32 internal constant TERMS_DOMAIN = keccak256("mordant.asset-terms/1");
    bytes32 internal constant SALT_DOMAIN = keccak256("mordant.asset-salt/3");

    /// @notice Authority ranking of an identifier. Binding requires tier 1 or 2.
    enum IdentityTier {
        None,
        RegistryDocument, // an authoritative registry assigned this document id
        StrictSellerIssued, // the seller's own number under a lossless profile
        TolerantCandidate // a lossy alias: reconciliation only, never binding
    }

    error InvalidIdentityField();
    error InvalidTermsField();
    error UnsupportedSchemeVersion(uint16 supplied);
    error InvalidRelation();
    error LossyProfileNotPermitted(uint8 profile);
    error LosslessProfileRequiredForTier(IdentityTier tier);
    error CandidateTierCannotBind(IdentityTier tier);

    /// @notice How one terms version relates to what came before.
    /// @dev Relations are explicit because "this invoice was corrected" and
    /// "this is a different invoice" have opposite consequences for matching.
    enum Relation {
        Original, // first terms for this asset
        Amendment, // same asset, terms corrected
        Cancellation, // same asset, withdrawn
        CreditNote, // a DIFFERENT asset that credits this one
        Replacement, // a DIFFERENT asset that replaces this one
        Novation // a DIFFERENT asset: a party changed
    }

    /// @notice The enduring receivable. Every field here is identity-defining:
    /// changing it means a different receivable, not an amended one.
    /// @dev Profiles are carried alongside the hashed fields so the library can
    /// enforce losslessness rather than trust the caller to have chosen well.
    struct StableAssetIdentity {
        bytes32 sellerNamespace;
        bytes32 sellerId;
        uint8 sellerProfile;
        bytes32 debtorNamespace;
        bytes32 debtorId;
        uint8 debtorProfile;
        bytes32 invoiceNamespace; // registry namespace when one exists, else the seller's
        bytes32 invoiceId;
        uint8 invoiceProfile;
        IdentityTier tier;
        uint32 issueDateDays; // the date stated on the document, UTC days
    }

    /// @notice One version of the receivable's commercial terms.
    struct AssetTermsVersion {
        bytes3 currencyCode;
        uint256 faceValueMinor;
        uint8 amountExponent;
        uint32 dueDateDays; // 0 when the document states none
        bytes32 paymentScheduleDigest; // 0 for a single bullet payment
        uint32 termsVersion; // strictly increasing per asset, 1-based
        bytes32 amendmentId; // the amendment's own reference, 0 for the original
        bytes32 supersedesTermsCommitment; // 0 for the original
        Relation relation;
        bytes32 relatedStableAssetId; // set only for CreditNote/Replacement/Novation
        uint64 effectiveFrom; // unix seconds the terms take effect
    }

    /// @notice The binding identity. Non-lossy by construction.
    /// @dev Reverts if any field used a lossy profile or if the tier is
    /// TolerantCandidate. This is the structural reason a profile-6 equality can
    /// never reach a binder: it cannot produce a strict identity at all.
    ///
    /// Jurisdiction is deliberately absent: every supported namespace is either
    /// globally unique (LEI, DUNS, GLN, PEPPOL) or self-scoping (a VAT
    /// identifier carries its country prefix), so a separate field would give
    /// two ways to express one fact and become a divergence source.
    function strictStableAssetId(StableAssetIdentity memory identity)
        internal
        pure
        returns (bytes32)
    {
        if (identity.tier != IdentityTier.RegistryDocument && identity.tier != IdentityTier.StrictSellerIssued)
        {
            revert CandidateTierCannotBind(identity.tier);
        }
        _requireLossless(identity.sellerProfile);
        _requireLossless(identity.debtorProfile);
        _requireLossless(identity.invoiceProfile);
        return _encode(STRICT_IDENTITY_DOMAIN, identity);
    }

    /// @notice The tolerant alias. May be lossy, and is separately domain
    /// separated so it can never be mistaken for a strict identity.
    /// @dev A candidate equality only ever signals that private reconciliation
    /// may be appropriate. It is never released publicly and never consumed by a
    /// binder.
    function candidateAliasId(StableAssetIdentity memory identity)
        internal
        pure
        returns (bytes32)
    {
        if (identity.tier != IdentityTier.TolerantCandidate) {
            revert LosslessProfileRequiredForTier(identity.tier);
        }
        return _encode(CANDIDATE_ALIAS_DOMAIN, identity);
    }

    function _requireLossless(uint8 profile) private pure {
        if (!MordantNormalization.isLossless(profile)) revert LossyProfileNotPermitted(profile);
    }

    function _encode(bytes32 domain, StableAssetIdentity memory identity)
        private
        pure
        returns (bytes32)
    {
        if (
            identity.sellerNamespace == bytes32(0) || identity.sellerId == bytes32(0)
                || identity.debtorNamespace == bytes32(0) || identity.debtorId == bytes32(0)
                || identity.invoiceNamespace == bytes32(0) || identity.invoiceId == bytes32(0)
                || identity.issueDateDays == 0
        ) revert InvalidIdentityField();
        bytes32 parties = keccak256(
            abi.encode(
                identity.sellerNamespace,
                identity.sellerId,
                identity.sellerProfile,
                identity.debtorNamespace,
                identity.debtorId,
                identity.debtorProfile
            )
        );
        bytes32 document = keccak256(
            abi.encode(
                identity.invoiceNamespace,
                identity.invoiceId,
                identity.invoiceProfile,
                uint8(identity.tier),
                identity.issueDateDays
            )
        );
        return keccak256(abi.encode(domain, IDENTITY_SCHEME_VERSION, parties, document));
    }

    /// @notice Commits the stable identity under a high-entropy per-anchor salt.
    function assetCommitment(
        bytes32 canonicalStableAssetId,
        uint16 schemeVersion,
        uint32 identityEpoch,
        bytes32 salt
    ) internal pure returns (bytes32) {
        if (schemeVersion != IDENTITY_SCHEME_VERSION) {
            revert UnsupportedSchemeVersion(schemeVersion);
        }
        if (canonicalStableAssetId == bytes32(0) || salt == bytes32(0) || identityEpoch == 0) {
            revert InvalidIdentityField();
        }
        return keccak256(
            abi.encode(
                COMMITMENT_DOMAIN, schemeVersion, identityEpoch, canonicalStableAssetId, salt
            )
        );
    }

    /// @notice Commits one terms version, bound to the asset it belongs to.
    /// @dev `stableAssetId` is inside the commitment, so a terms version cannot
    /// be detached and re-attached to a different receivable.
    function termsCommitment(
        bytes32 canonicalStableAssetId,
        uint16 termsSchemeVersion,
        AssetTermsVersion memory terms
    ) internal pure returns (bytes32) {
        if (termsSchemeVersion != TERMS_SCHEME_VERSION) {
            revert UnsupportedSchemeVersion(termsSchemeVersion);
        }
        _validateTerms(canonicalStableAssetId, terms);
        bytes32 economics = keccak256(
            abi.encode(
                terms.currencyCode,
                terms.faceValueMinor,
                terms.amountExponent,
                terms.dueDateDays,
                terms.paymentScheduleDigest
            )
        );
        bytes32 lineage = keccak256(
            abi.encode(
                terms.termsVersion,
                terms.amendmentId,
                terms.supersedesTermsCommitment,
                uint8(terms.relation),
                terms.relatedStableAssetId,
                terms.effectiveFrom
            )
        );
        return keccak256(
            abi.encode(
                TERMS_DOMAIN,
                termsSchemeVersion,
                canonicalStableAssetId,
                terms.termsVersion,
                economics,
                lineage
            )
        );
    }

    function _validateTerms(bytes32 canonicalStableAssetId, AssetTermsVersion memory terms)
        private
        pure
    {
        if (canonicalStableAssetId == bytes32(0)) revert InvalidIdentityField();
        if (
            terms.currencyCode == bytes3(0) || terms.faceValueMinor == 0 || terms.termsVersion == 0
                || terms.effectiveFrom == 0
        ) revert InvalidTermsField();
        if (terms.dueDateDays != 0 && terms.dueDateDays < 1) revert InvalidTermsField();

        if (terms.relation == Relation.Original) {
            // The first terms version supersedes nothing and relates to nothing.
            if (
                terms.termsVersion != 1 || terms.supersedesTermsCommitment != bytes32(0)
                    || terms.amendmentId != bytes32(0) || terms.relatedStableAssetId != bytes32(0)
            ) revert InvalidRelation();
        } else if (terms.relation == Relation.Amendment || terms.relation == Relation.Cancellation) {
            // Same asset: there must be a predecessor and no related asset.
            if (
                terms.termsVersion < 2 || terms.supersedesTermsCommitment == bytes32(0)
                    || terms.relatedStableAssetId != bytes32(0)
            ) revert InvalidRelation();
            if (terms.relation == Relation.Amendment && terms.amendmentId == bytes32(0)) {
                revert InvalidRelation();
            }
        } else {
            // CreditNote, Replacement and Novation describe a DIFFERENT asset
            // that points at this one, so a related asset is mandatory and it
            // must not be this asset.
            if (
                terms.relatedStableAssetId == bytes32(0)
                    || terms.relatedStableAssetId == canonicalStableAssetId
            ) revert InvalidRelation();
        }
    }

    /// @notice Deterministic per-anchor salt derivation.
    function deriveSalt(
        bytes32 issuerMasterSecret,
        bytes32 canonicalStableAssetId,
        uint32 identityEpoch,
        uint256 anchorNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SALT_DOMAIN,
                issuerMasterSecret,
                canonicalStableAssetId,
                identityEpoch,
                anchorNonce
            )
        );
    }

    /// @notice Commits a tolerant alias. Separate domain from the binding
    /// commitment, so a candidate commitment presented to a binder cannot match.
    function candidateAliasCommitment(
        bytes32 aliasId,
        uint32 identityEpoch,
        bytes32 salt
    ) internal pure returns (bytes32) {
        if (aliasId == bytes32(0) || salt == bytes32(0) || identityEpoch == 0) {
            revert InvalidIdentityField();
        }
        return keccak256(
            abi.encode(CANDIDATE_COMMITMENT_DOMAIN, IDENTITY_SCHEME_VERSION, identityEpoch, aliasId, salt)
        );
    }

    /// @notice Convenience wrapper over the normalization profiles.
    function field(uint8 profile, string memory value, uint256 fixedLength)
        internal
        pure
        returns (bytes32)
    {
        return MordantNormalization.normalize(profile, value, fixedLength);
    }

    function namespaceOf(string memory value) internal pure returns (bytes32) {
        return MordantNormalization.namespace(value);
    }
}
