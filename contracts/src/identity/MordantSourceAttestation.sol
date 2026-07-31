// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice EIP-712 source attestation binding an anchor to a committed economic
/// asset, signed before the anchor exists.
/// @dev This is the construct that closes the post-match remapping hole. The
/// issuer signs the commitment and the exact creation parameters *before*
/// deployment, so it cannot observe a match and then decide which anchor the
/// result attaches to. There is no discretionary mapping step after deployment
/// anywhere in this architecture.
library MordantSourceAttestation {
    error InvalidAttestation();
    error AttestationExpired(uint64 validUntil, uint256 nowTimestamp);
    error WrongChain(uint256 supplied, uint256 current);
    error WrongFactory(address supplied, address current);
    error MalformedSignature();

    /// @dev secp256k1 half order; rejects malleable signatures.
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    string internal constant DOMAIN_NAME = "Mordant Source Attestation";
    string internal constant DOMAIN_VERSION = "1";

    bytes32 internal constant ATTESTATION_TYPEHASH = keccak256(
        "SourceAssetAttestation(uint256 chainId,address factory,bytes32 creationDigest,bytes32 assetCommitment,uint16 identitySchemeVersion,uint32 identityEpoch,bytes32 issuerKeyId,bytes32 invoiceRoot,address controller,uint64 validUntil,uint256 nonce)"
    );

    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    /// @notice What an accountable issuer asserts before an anchor is created.
    struct SourceAssetAttestation {
        uint256 chainId;
        address factory; // the only admission contract that may consume it
        bytes32 creationDigest; // deterministic identity of the anchor to be created
        bytes32 assetCommitment; // salted commitment to the canonical economic asset
        uint16 identitySchemeVersion;
        uint32 identityEpoch;
        bytes32 issuerKeyId;
        bytes32 invoiceRoot; // the PUBLIC root; deliberately not the asset id
        address controller; // originator / controller of the receivable
        uint64 validUntil;
        uint256 nonce; // one-shot per issuer
    }

    function domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(DOMAIN_NAME)),
                keccak256(bytes(DOMAIN_VERSION)),
                block.chainid,
                verifyingContract
            )
        );
    }

    function structHash(SourceAssetAttestation memory attestation) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                attestation.chainId,
                attestation.factory,
                attestation.creationDigest,
                attestation.assetCommitment,
                attestation.identitySchemeVersion,
                attestation.identityEpoch,
                attestation.issuerKeyId,
                attestation.invoiceRoot,
                attestation.controller,
                attestation.validUntil,
                attestation.nonce
            )
        );
    }

    function digest(SourceAssetAttestation memory attestation, address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(verifyingContract), structHash(attestation))
        );
    }

    /// @notice Recovers the signer after enforcing scope and freshness.
    /// @dev Chain and factory are inside the signed struct *and* checked against
    /// the live environment, so an attestation cannot be lifted onto another
    /// chain or another admission contract.
    function recover(
        SourceAssetAttestation memory attestation,
        bytes memory signature,
        address verifyingContract
    ) internal view returns (address signer, bytes32 attestationDigest) {
        if (
            attestation.assetCommitment == bytes32(0) || attestation.creationDigest == bytes32(0)
                || attestation.issuerKeyId == bytes32(0) || attestation.invoiceRoot == bytes32(0)
                || attestation.controller == address(0) || attestation.identityEpoch == 0
                || attestation.nonce == 0
        ) revert InvalidAttestation();
        if (attestation.chainId != block.chainid) {
            revert WrongChain(attestation.chainId, block.chainid);
        }
        if (attestation.factory != verifyingContract) {
            revert WrongFactory(attestation.factory, verifyingContract);
        }
        if (block.timestamp > attestation.validUntil) {
            revert AttestationExpired(attestation.validUntil, block.timestamp);
        }
        // The public invoice root and the private asset commitment are separate
        // concepts and must never coincide; equality would make the identity
        // publicly computable.
        if (attestation.invoiceRoot == attestation.assetCommitment) revert InvalidAttestation();

        attestationDigest = digest(attestation, verifyingContract);
        signer = _recover(attestationDigest, signature);
    }

    function _recover(bytes32 hash, bytes memory signature) private pure returns (address) {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        address signer = ECDSA.recover(hash, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
        return signer;
    }
}
