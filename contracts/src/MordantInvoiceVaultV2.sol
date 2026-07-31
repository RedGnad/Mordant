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
        uint16 identitySchemeVersion;
        uint32 identityEpoch;
        bytes32 issuerKeyId;
        bytes32 sourceAttestationDigest;
    }

    bytes32 private immutable _assetCommitment;
    uint16 private immutable _identitySchemeVersion;
    uint32 private immutable _identityEpoch;
    bytes32 private immutable _issuerKeyId;
    bytes32 private immutable _sourceAttestationDigest;

    constructor(Init memory init, IdentityInit memory identity) MordantInvoiceVault(init) {
        if (
            identity.assetCommitment == bytes32(0) || identity.identitySchemeVersion == 0
                || identity.identityEpoch == 0 || identity.issuerKeyId == bytes32(0)
                || identity.sourceAttestationDigest == bytes32(0)
        ) revert InvalidIdentity();
        // The public root and the private commitment are separate concepts. If
        // they ever coincided the identity would be publicly computable from
        // chain data and private matching would be pointless.
        if (identity.assetCommitment == init.invoiceRoot) revert InvalidIdentity();

        _assetCommitment = identity.assetCommitment;
        _identitySchemeVersion = identity.identitySchemeVersion;
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
