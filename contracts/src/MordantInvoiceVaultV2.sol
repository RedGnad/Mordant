// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {MordantInvoiceVault} from "./MordantInvoiceVault.sol";
import {IIdentityAnchor} from "./identity/IIdentityAnchor.sol";

/// @notice V1 receivable economics plus an immutable, pre-committed economic
/// asset identity.
/// @dev V2 extends V1 by inheritance rather than by copying it, so V1's
/// bytecode, tests and deployed instances are untouched and Mode A keeps
/// running exactly as proven.
///
/// Everything added here is opaque. `assetCommitment` is salted per anchor and
/// the salt never appears on-chain, so two anchors of the same economic asset
/// carry unlinkable commitments. There is no setter: the identity is fixed at
/// construction from an attestation the issuer signed before this contract
/// existed, which is what makes post-match remapping impossible rather than
/// merely discouraged.
contract MordantInvoiceVaultV2 is MordantInvoiceVault, IIdentityAnchor {
    error InvalidIdentity();

    struct IdentityInit {
        bytes32 assetCommitment;
        bytes32 initialTermsCommitment;
        uint16 identitySchemeVersion;
        uint16 termsSchemeVersion;
        uint32 identityEpoch;
        bytes32 issuerKeyId;
        bytes32 sourceAttestationDigest;
    }

    bytes32 private immutable _assetCommitment;
    bytes32 private immutable _initialTermsCommitment;
    uint16 private immutable _identitySchemeVersion;
    uint16 private immutable _termsSchemeVersion;
    uint32 private immutable _identityEpoch;
    bytes32 private immutable _issuerKeyId;
    bytes32 private immutable _sourceAttestationDigest;

    constructor(Init memory init, IdentityInit memory identity) MordantInvoiceVault(init) {
        if (
            identity.assetCommitment == bytes32(0) || identity.identitySchemeVersion == 0
                || identity.initialTermsCommitment == bytes32(0) || identity.termsSchemeVersion == 0
                || identity.identityEpoch == 0 || identity.issuerKeyId == bytes32(0)
                || identity.sourceAttestationDigest == bytes32(0)
        ) revert InvalidIdentity();
        // The asset identity and its terms are separate objects and must never
        // be the same value: conflating them is the scheme-1 defect.
        if (identity.assetCommitment == identity.initialTermsCommitment) revert InvalidIdentity();
        // The public root and the private commitment are separate concepts. If
        // they ever coincided the identity would be publicly computable from
        // chain data and private matching would be pointless.
        if (identity.assetCommitment == init.invoiceRoot) revert InvalidIdentity();

        _assetCommitment = identity.assetCommitment;
        _initialTermsCommitment = identity.initialTermsCommitment;
        _identitySchemeVersion = identity.identitySchemeVersion;
        _termsSchemeVersion = identity.termsSchemeVersion;
        _identityEpoch = identity.identityEpoch;
        _issuerKeyId = identity.issuerKeyId;
        _sourceAttestationDigest = identity.sourceAttestationDigest;
    }

    function assetCommitment() external view returns (bytes32) {
        return _assetCommitment;
    }

    function identitySchemeVersion() external view returns (uint16) {
        return _identitySchemeVersion;
    }

    /// @notice Terms as of creation. Amendments are appended in the terms
    /// registry and never rewrite this value.
    function initialTermsCommitment() external view returns (bytes32) {
        return _initialTermsCommitment;
    }

    function termsSchemeVersion() external view returns (uint16) {
        return _termsSchemeVersion;
    }

    function identityEpoch() external view returns (uint32) {
        return _identityEpoch;
    }

    function issuerKeyId() external view returns (bytes32) {
        return _issuerKeyId;
    }

    function sourceAttestationDigest() external view returns (bytes32) {
        return _sourceAttestationDigest;
    }
}
