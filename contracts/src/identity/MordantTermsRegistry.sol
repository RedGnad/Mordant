// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { MordantIssuerRegistry } from "./MordantIssuerRegistry.sol";

/// @notice Append-only history of terms versions for an anchor.
/// @dev Terms change; identity does not. Amendments are appended here and never
/// rewrite the anchor's immutable `initialTermsCommitment` or its
/// `assetCommitment`. The registry enforces the lineage rules that make an
/// amendment distinguishable from a relabelled new asset:
///
///   - versions are strictly increasing, so a rollback is impossible;
///   - each version names the commitment it supersedes, so history is a chain;
///   - a version is bound to one anchor, so it cannot be re-attached elsewhere;
///   - a version is one-shot, so an amendment cannot be replayed.
contract MordantTermsRegistry {
    error UnknownAnchor(bytes32 anchorId);
    error NotMonotonic(uint32 supplied, uint32 current);
    error SupersedesMismatch(bytes32 supplied, bytes32 expected);
    error AlreadyRecorded(bytes32 termsCommitment);
    error InvalidTermsRecord();
    error MalformedSignature();
    error WrongIssuer();

    event TermsVersionAppended(
        bytes32 indexed anchorId,
        bytes32 indexed issuerKeyId,
        uint32 indexed termsVersion,
        bytes32 termsCommitment,
        bytes32 supersedesTermsCommitment
    );

    string internal constant DOMAIN_NAME = "Mordant Terms Amendment";
    string internal constant DOMAIN_VERSION = "1";

    bytes32 public constant AMENDMENT_TYPEHASH = keccak256(
        "TermsAmendment(uint256 chainId,address registry,bytes32 anchorId,bytes32 assetCommitment,bytes32 termsCommitment,bytes32 supersedesTermsCommitment,uint32 termsVersion,uint16 termsSchemeVersion,bytes32 issuerKeyId,uint64 validUntil,uint256 nonce)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct TermsAmendment {
        uint256 chainId;
        address registry;
        bytes32 anchorId; // the anchor these terms belong to
        bytes32 assetCommitment; // must equal the anchor's, binding terms to identity
        bytes32 termsCommitment;
        bytes32 supersedesTermsCommitment;
        uint32 termsVersion;
        uint16 termsSchemeVersion;
        bytes32 issuerKeyId;
        uint64 validUntil;
        uint256 nonce;
    }

    struct AnchorTerms {
        bytes32 assetCommitment;
        bytes32 currentTermsCommitment;
        uint32 currentVersion;
        bytes32 issuerKeyId;
        bool initialised;
    }

    MordantIssuerRegistry public immutable issuerRegistry;

    mapping(bytes32 anchorId => AnchorTerms terms) public anchorTerms;
    mapping(bytes32 termsCommitment => bool recorded) public recordedTerms;
    mapping(bytes32 issuerKeyId => mapping(uint256 nonce => bool used)) public consumedNonce;

    constructor(MordantIssuerRegistry registry) {
        if (address(registry) == address(0)) revert InvalidTermsRecord();
        issuerRegistry = registry;
    }

    /// @notice Records the anchor's creation terms as version 1.
    /// @dev Callable once per anchor, by anyone, because it only mirrors values
    /// the anchor already carries immutably.
    function initialise(
        bytes32 anchorId,
        bytes32 assetCommitment,
        bytes32 initialTermsCommitment,
        bytes32 issuerKeyId
    ) external {
        AnchorTerms storage record = anchorTerms[anchorId];
        if (record.initialised) revert AlreadyRecorded(initialTermsCommitment);
        if (
            anchorId == bytes32(0) || assetCommitment == bytes32(0)
                || initialTermsCommitment == bytes32(0) || issuerKeyId == bytes32(0)
                || assetCommitment == initialTermsCommitment
        ) revert InvalidTermsRecord();
        if (recordedTerms[initialTermsCommitment]) revert AlreadyRecorded(initialTermsCommitment);

        anchorTerms[anchorId] = AnchorTerms({
            assetCommitment: assetCommitment,
            currentTermsCommitment: initialTermsCommitment,
            currentVersion: 1,
            issuerKeyId: issuerKeyId,
            initialised: true
        });
        recordedTerms[initialTermsCommitment] = true;
        emit TermsVersionAppended(anchorId, issuerKeyId, 1, initialTermsCommitment, bytes32(0));
    }

    /// @notice Appends an amended terms version, signed by the anchor's issuer.
    function appendAmendment(TermsAmendment calldata amendment, bytes calldata signature) external {
        AnchorTerms storage record = anchorTerms[amendment.anchorId];
        if (!record.initialised) revert UnknownAnchor(amendment.anchorId);

        if (amendment.chainId != block.chainid || amendment.registry != address(this)) {
            revert InvalidTermsRecord();
        }
        if (block.timestamp > amendment.validUntil) revert InvalidTermsRecord();
        // The amendment must belong to this anchor's asset, which is what stops
        // a terms version being attached to a different receivable.
        if (amendment.assetCommitment != record.assetCommitment) revert InvalidTermsRecord();
        // Only the issuer that anchored the asset may amend its terms.
        if (amendment.issuerKeyId != record.issuerKeyId) revert WrongIssuer();
        // Strictly increasing: a rollback to an earlier version is impossible.
        if (amendment.termsVersion <= record.currentVersion) {
            revert NotMonotonic(amendment.termsVersion, record.currentVersion);
        }
        // History is a chain, not a set.
        if (amendment.supersedesTermsCommitment != record.currentTermsCommitment) {
            revert SupersedesMismatch(
                amendment.supersedesTermsCommitment, record.currentTermsCommitment
            );
        }
        if (amendment.termsCommitment == bytes32(0) || amendment.nonce == 0) {
            revert InvalidTermsRecord();
        }
        // One-shot: an amendment cannot be replayed.
        if (recordedTerms[amendment.termsCommitment]) {
            revert AlreadyRecorded(amendment.termsCommitment);
        }
        if (consumedNonce[amendment.issuerKeyId][amendment.nonce]) revert InvalidTermsRecord();

        address signer = _recover(_digest(amendment), signature);
        issuerRegistry.requireAuthorized(amendment.issuerKeyId, signer, 1);

        consumedNonce[amendment.issuerKeyId][amendment.nonce] = true;
        recordedTerms[amendment.termsCommitment] = true;
        record.currentTermsCommitment = amendment.termsCommitment;
        record.currentVersion = amendment.termsVersion;

        emit TermsVersionAppended(
            amendment.anchorId,
            amendment.issuerKeyId,
            amendment.termsVersion,
            amendment.termsCommitment,
            amendment.supersedesTermsCommitment
        );
    }

    function currentTerms(bytes32 anchorId) external view returns (bytes32, uint32) {
        AnchorTerms memory record = anchorTerms[anchorId];
        if (!record.initialised) revert UnknownAnchor(anchorId);
        return (record.currentTermsCommitment, record.currentVersion);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(DOMAIN_NAME)),
                keccak256(bytes(DOMAIN_VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice The EIP-712 digest an issuer signs. Exposed so a signer never has
    /// to re-derive the encoding and risk diverging from the verifier.
    function digestOf(TermsAmendment calldata amendment) external view returns (bytes32) {
        return _digest(amendment);
    }

    function _digest(TermsAmendment calldata amendment) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encodePacked(
                abi.encode(
                    AMENDMENT_TYPEHASH,
                    amendment.chainId,
                    amendment.registry,
                    amendment.anchorId,
                    amendment.assetCommitment,
                    amendment.termsCommitment,
                    amendment.supersedesTermsCommitment
                ),
                abi.encode(
                    amendment.termsVersion,
                    amendment.termsSchemeVersion,
                    amendment.issuerKeyId,
                    amendment.validUntil,
                    amendment.nonce
                )
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _recover(bytes32 hash, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        address signer = ECDSA.recover(hash, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
        return signer;
    }
}
