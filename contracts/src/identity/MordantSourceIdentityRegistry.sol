// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IIdentityAnchor} from "./IIdentityAnchor.sol";
import {MordantAssetIdentity} from "./MordantAssetIdentity.sol";
import {MordantIssuerRegistry} from "./MordantIssuerRegistry.sol";
import {MordantSourceAttestation} from "./MordantSourceAttestation.sol";

/// @notice Identity anchors for receivables that are not tokenized here.
/// @dev Decision 11. Candidate A's counterparty is a traditional factor or bank
/// facility with no on-chain vault, and it must still commit to the same
/// canonical economic identity before any matching session. This registry gives
/// it an anchor that carries only the five opaque identity fields and nothing
/// economic.
///
/// A registry entry publishes strictly less than a vault: no debtor, no face
/// value, no currency, no dates. An observer learns that some issuer registered
/// some receivable at some time, which is the minimum required to satisfy
/// "committed before any session" and is deliberately not enough to correlate.
contract MordantSourceIdentityRegistry {
    error InvalidRegistration();
    error AttestationReplayed(bytes32 issuerKeyId, uint256 nonce);
    error SchemeMismatch(uint16 supplied, uint16 expected);
    error UnknownAnchor(bytes32 anchorId);

    event SourceIdentityRegistered(
        bytes32 indexed anchorId,
        bytes32 indexed issuerKeyId,
        bytes32 assetCommitment,
        uint16 identitySchemeVersion,
        uint32 identityEpoch,
        bytes32 sourceAttestationDigest
    );

    struct SourceAnchor {
        bytes32 assetCommitment;
        bytes32 initialTermsCommitment;
        uint16 identitySchemeVersion;
        uint32 identityEpoch;
        bytes32 issuerKeyId;
        bytes32 sourceAttestationDigest;
        uint64 registeredAt;
        bool registered;
    }

    MordantIssuerRegistry public immutable issuerRegistry;
    mapping(bytes32 anchorId => SourceAnchor anchor) private _anchors;
    mapping(bytes32 issuerKeyId => mapping(uint256 nonce => bool used)) public consumedNonce;

    constructor(MordantIssuerRegistry registry) {
        if (address(registry) == address(0)) revert InvalidRegistration();
        issuerRegistry = registry;
    }

    /// @notice The anchor identity of a non-vault source is the attestation
    /// digest itself: there is no address to name, and the digest is already a
    /// unique, pre-committed handle.
    function register(
        MordantSourceAttestation.SourceAssetAttestation calldata attestation,
        bytes calldata signature
    ) external returns (bytes32 anchorId) {
        (address signer, bytes32 attestationDigest) =
            MordantSourceAttestation.recover(attestation, signature, address(this));
        issuerRegistry.requireAuthorized(attestation.issuerKeyId, signer, attestation.identityEpoch);
        if (attestation.identitySchemeVersion != MordantAssetIdentity.IDENTITY_SCHEME_VERSION) {
            revert SchemeMismatch(
                attestation.identitySchemeVersion, MordantAssetIdentity.IDENTITY_SCHEME_VERSION
            );
        }
        if (consumedNonce[attestation.issuerKeyId][attestation.nonce]) {
            revert AttestationReplayed(attestation.issuerKeyId, attestation.nonce);
        }
        // A non-vault source has no creation parameters, so the attestation must
        // bind its own digest as the creation identity. This keeps one signed
        // struct for both anchor kinds.
        if (_anchors[attestationDigest].registered) revert InvalidRegistration();

        consumedNonce[attestation.issuerKeyId][attestation.nonce] = true;
        anchorId = attestationDigest;
        _anchors[anchorId] = SourceAnchor({
            assetCommitment: attestation.assetCommitment,
            initialTermsCommitment: attestation.initialTermsCommitment,
            identitySchemeVersion: attestation.identitySchemeVersion,
            identityEpoch: attestation.identityEpoch,
            issuerKeyId: attestation.issuerKeyId,
            sourceAttestationDigest: attestationDigest,
            registeredAt: uint64(block.timestamp),
            registered: true
        });

        emit SourceIdentityRegistered(
            anchorId,
            attestation.issuerKeyId,
            attestation.assetCommitment,
            attestation.identitySchemeVersion,
            attestation.identityEpoch,
            attestationDigest
        );
    }

    function anchor(bytes32 anchorId) external view returns (SourceAnchor memory) {
        SourceAnchor memory record = _anchors[anchorId];
        if (!record.registered) revert UnknownAnchor(anchorId);
        return record;
    }

    function assetCommitmentOf(bytes32 anchorId) external view returns (bytes32) {
        SourceAnchor memory record = _anchors[anchorId];
        if (!record.registered) revert UnknownAnchor(anchorId);
        return record.assetCommitment;
    }

    /// @notice A registered source anchor is immutable. There is no update, no
    /// re-point and no delete, so an issuer cannot remap it after observing a
    /// match.
    function isRegistered(bytes32 anchorId) external view returns (bool) {
        return _anchors[anchorId].registered;
    }
}
