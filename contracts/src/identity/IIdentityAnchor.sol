// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice The opaque identity surface every anchor exposes, whether or not it
/// is a tokenized vault.
/// @dev Decision 11: the abstraction is deliberately not vault-only. Candidate
/// A's non-vault source (a traditional factor with no on-chain footprint)
/// registers the same five fields through the source identity registry, so both
/// sides of a private match speak the same canonical identity architecture.
///
/// Nothing here reveals the economic asset: `assetCommitment` is salted per
/// anchor, and the salt is never published.
interface IIdentityAnchor {
    /// @notice Salted commitment to the canonical economic-asset identity.
    function assetCommitment() external view returns (bytes32);

    /// @notice Canonical identity scheme version this commitment was built under.
    function identitySchemeVersion() external view returns (uint16);

    /// @notice Commitment to the terms in force when the anchor was created.
    function initialTermsCommitment() external view returns (bytes32);

    /// @notice Terms scheme version.
    function termsSchemeVersion() external view returns (uint16);

    /// @notice Identity epoch, for salt and scheme rotation.
    function identityEpoch() external view returns (uint32);

    /// @notice The issuer that attested this anchor's identity.
    function issuerKeyId() external view returns (bytes32);

    /// @notice Digest of the original pre-deployment source attestation.
    function sourceAttestationDigest() external view returns (bytes32);
}
