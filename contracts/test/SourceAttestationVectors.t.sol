// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { MordantSourceAttestation } from "../src/identity/MordantSourceAttestation.sol";

/// @notice Pinned vectors for the source-attestation EIP-712 digest.
///
/// @dev `MordantSourceAttestation` is a library with `internal` functions and
/// `MordantFactoryV2` exposes no `attestationDigest` view, so the digest an
/// issuer signs before a vault exists cannot be read from any deployed
/// contract. A runner must derive it off chain.
///
/// That derivation is only safe if it is pinned. This contract is the
/// authority: it computes the digest with the frozen library itself, and
/// `source-attestation-digest.test.mjs` asserts the JavaScript mirrors
/// reproduce exactly these numbers. A change to the type string, the field
/// order or the domain fails here first.
///
/// The vector is deliberately computed for two different verifying contracts,
/// because the same attestation is signed once for the factory (anchor
/// creation) and once for the source-commitment registry (opaque admission),
/// and confusing the two is a realistic mistake.
contract SourceAttestationVectorsTest is Test {
    uint256 private constant CHAIN_ID = 10_143;
    address private constant FACTORY = address(0x1111111111111111111111111111111111111111);
    address private constant SOURCE_REGISTRY = address(0x2222222222222222222222222222222222222222);

    /// Pinned. Regenerate only as a deliberate, versioned schema change.
    bytes32 private constant EXPECTED_TYPEHASH =
        0x5c84efcfafc8e9d8293daaf7fbc1b3023887538bb27651c6c46e8af3551b3397;
    bytes32 private constant EXPECTED_STRUCT_HASH =
        0xce83de9e69a87c459c4770633f5d47f240404196deae25bf492c9ca695bae497;
    bytes32 private constant EXPECTED_DIGEST_FACTORY =
        0x49b44a18bf3a9641c23c074ce802b681777f472ddbdf4e7bb38d1d39ff880824;
    bytes32 private constant EXPECTED_DIGEST_SOURCE_REGISTRY =
        0x1d5598ee5e3236baff60335fc551898c0a2cf25f3c06994dddd5c2c4ee3e2ede;

    function setUp() public {
        vm.chainId(CHAIN_ID);
    }

    /// @dev Every field is a distinct, non-zero, non-repeating value, so a
    /// transposition of two fields changes the digest.
    function vector() public pure returns (MordantSourceAttestation.SourceAssetAttestation memory) {
        return MordantSourceAttestation.SourceAssetAttestation({
            chainId: CHAIN_ID,
            factory: FACTORY,
            creationDigest: keccak256("vector.creationDigest"),
            assetCommitment: keccak256("vector.assetCommitment"),
            initialTermsCommitment: keccak256("vector.initialTermsCommitment"),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
            identityEpoch: 7,
            issuerKeyId: keccak256("vector.issuerKeyId"),
            invoiceRoot: keccak256("vector.invoiceRoot"),
            controller: address(0x3333333333333333333333333333333333333333),
            validUntil: 1_800_000_000,
            nonce: 42
        });
    }

    function testEmitVectors() public view {
        MordantSourceAttestation.SourceAssetAttestation memory attestation = vector();
        console.log("TYPEHASH");
        console.logBytes32(MordantSourceAttestation.ATTESTATION_TYPEHASH);
        console.log("STRUCT_HASH");
        console.logBytes32(MordantSourceAttestation.structHash(attestation));
        console.log("DIGEST_FACTORY");
        console.logBytes32(MordantSourceAttestation.digest(attestation, FACTORY));
        console.log("DIGEST_SOURCE_REGISTRY");
        console.logBytes32(MordantSourceAttestation.digest(attestation, SOURCE_REGISTRY));
        console.log("DOMAIN_SEPARATOR_FACTORY");
        console.logBytes32(MordantSourceAttestation.domainSeparator(FACTORY));
    }

    function testPinnedTypehash() public pure {
        assertEq(MordantSourceAttestation.ATTESTATION_TYPEHASH, EXPECTED_TYPEHASH, "typehash");
    }

    function testPinnedStructHash() public view {
        assertEq(MordantSourceAttestation.structHash(vector()), EXPECTED_STRUCT_HASH, "structHash");
    }

    function testPinnedDigests() public view {
        assertEq(
            MordantSourceAttestation.digest(vector(), FACTORY),
            EXPECTED_DIGEST_FACTORY,
            "factory digest"
        );
        assertEq(
            MordantSourceAttestation.digest(vector(), SOURCE_REGISTRY),
            EXPECTED_DIGEST_SOURCE_REGISTRY,
            "source registry digest"
        );
    }

    /// The same attestation signed for two different verifying contracts must
    /// produce two different digests, or a signature for the factory would be
    /// replayable at the source registry.
    function testTheVerifyingContractSeparatesTheTwoDigests() public view {
        assertTrue(
            MordantSourceAttestation.digest(vector(), FACTORY)
                != MordantSourceAttestation.digest(vector(), SOURCE_REGISTRY),
            "verifying contract must separate the domains"
        );
    }
}
