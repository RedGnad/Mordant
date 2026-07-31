// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {MordantFactory} from "../src/MordantFactory.sol";
import {MordantFactoryV2} from "../src/MordantFactoryV2.sol";
import {MordantInvoiceVault} from "../src/MordantInvoiceVault.sol";
import {MordantInvoiceVaultV2} from "../src/MordantInvoiceVaultV2.sol";
import {MordantAssetIdentity} from "../src/identity/MordantAssetIdentity.sol";
import {MordantIssuerRegistry} from "../src/identity/MordantIssuerRegistry.sol";
import {MordantSourceAttestation} from "../src/identity/MordantSourceAttestation.sol";
import {MordantSourceIdentityRegistry} from "../src/identity/MordantSourceIdentityRegistry.sol";
import {MockCvaAdapter} from "../src/mocks/MockCvaAdapter.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockEligibility} from "../src/mocks/MockEligibility.sol";

/// @dev External boundary so `expectRevert` can observe reverts raised inside
/// the internal identity library.
contract IdentityHarness {
    function commitment(bytes32 assetId, uint16 schemeVersion, uint32 epoch, bytes32 salt)
        external
        pure
        returns (bytes32)
    {
        return MordantAssetIdentity.assetCommitment(assetId, schemeVersion, epoch, salt);
    }
}

contract MordantIdentityV2Test is Test {
    uint256 private constant ISSUER_KEY = 0x1551E4;
    uint256 private constant OTHER_ISSUER_KEY = 0x0FF1CE;
    uint256 private constant ONE = 1e6;
    uint256 private constant UNITS = 100 * ONE;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint64 private constant REVEAL_PERIOD = 1 hours;
    uint64 private constant CURE_PERIOD = 1 hours;
    uint32 private constant EPOCH = 1;

    address private issuer;
    address private otherIssuer;
    address private buyer = address(0xB0);
    address private originator = address(0x04);
    address private originatorSigner = address(0x05);
    address private facility = address(0xFAC);

    MockEligibility private eligibility;
    MockERC20 private settlement;
    MockERC20 private cva;
    MockCvaAdapter private adapter;
    MordantIssuerRegistry private registry;
    MordantFactoryV2 private factory;
    MordantSourceIdentityRegistry private sources;

    bytes32 private assetId;
    uint64 private protectionEnd;

    function setUp() public {
        vm.warp(1_000_000);
        issuer = vm.addr(ISSUER_KEY);
        otherIssuer = vm.addr(OTHER_ISSUER_KEY);

        eligibility = new MockEligibility();
        eligibility.setEligible(buyer, 1, true);
        eligibility.setEligible(originator, 2, true);
        eligibility.setEligible(originatorSigner, 2, true);
        eligibility.setEligible(facility, 3, true);

        settlement = new MockERC20("Settlement", "aUSD", 6);
        cva = new MockERC20("Invoice A-Token", "aINV", 6);
        adapter = new MockCvaAdapter(cva);

        registry = new MordantIssuerRegistry(address(this));
        registry.registerIssuer(issuer, EPOCH);
        registry.registerIssuer(otherIssuer, EPOCH);

        factory = new MordantFactoryV2(address(this), eligibility, registry);
        factory.setCvaAdapter(address(adapter), true);
        factory.setSettlementToken(address(settlement), true);
        factory.setFacility(facility, true);

        sources = new MordantSourceIdentityRegistry(registry);

        assetId = _canonicalAssetId("ACME-2026-0042");
        protectionEnd = uint64(block.timestamp + 30 days);
    }

    /* ------------------------------------------------------------- identity */

    function _canonicalAssetId(string memory invoiceNumber) private pure returns (bytes32) {
        MordantAssetIdentity.AssetIdentity memory identity = MordantAssetIdentity.AssetIdentity({
            debtorNamespace: MordantAssetIdentity.normalizeNamespace("LEI"),
            debtorId: MordantAssetIdentity.normalizeAlphanumeric("529900T8BM49AURSDO55"),
            sellerNamespace: MordantAssetIdentity.normalizeNamespace("lei"),
            sellerId: MordantAssetIdentity.normalizeAlphanumeric("213800WAVVOPS85N2205"),
            invoiceNumber: MordantAssetIdentity.normalizeAlphanumeric(invoiceNumber),
            currencyCode: bytes3("USD"),
            amountMinor: 110_000_000,
            amountExponent: 2,
            issueDateDays: 20_500,
            dueDateDays: 20_590
        });
        return MordantAssetIdentity.assetId(identity);
    }

    function testNormalizationMakesFormattingIrrelevant() public pure {
        // The same invoice written three ways is the same economic asset.
        assertEq(
            MordantAssetIdentity.normalizeAlphanumeric("INV-2026/0042"),
            MordantAssetIdentity.normalizeAlphanumeric("inv 2026 0042")
        );
        assertEq(
            MordantAssetIdentity.normalizeAlphanumeric("  Acme-42  "),
            MordantAssetIdentity.normalizeAlphanumeric("ACME42")
        );
        assertEq(
            MordantAssetIdentity.normalizeNamespace("LEI"),
            MordantAssetIdentity.normalizeNamespace("lei")
        );
        // But a genuinely different invoice number stays different.
        assertTrue(
            MordantAssetIdentity.normalizeAlphanumeric("INV-0042")
                != MordantAssetIdentity.normalizeAlphanumeric("INV-0043")
        );
    }

    function testDeterministicCommitmentAndSaltUnlinkability() public view {
        bytes32 salt1 = MordantAssetIdentity.deriveSalt(keccak256("master-1"), assetId, EPOCH, 1);
        bytes32 salt2 = MordantAssetIdentity.deriveSalt(keccak256("master-2"), assetId, EPOCH, 1);

        bytes32 c1 = MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, salt1);
        bytes32 c2 = MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, salt2);
        // Same canonical asset, different salts -> unlinkable public commitments.
        assertTrue(c1 != c2, "commitments must be unlinkable");
        // Identical inputs -> deterministic commitment.
        assertEq(c1, MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, salt1));
        // The salt itself is recoverable from the master secret alone.
        assertEq(salt1, MordantAssetIdentity.deriveSalt(keccak256("master-1"), assetId, EPOCH, 1));
        // A different epoch rotates the commitment.
        assertTrue(
            MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH + 1, salt1) != c1,
            "epoch must rotate the commitment"
        );
    }

    function testUnsupportedSchemeVersionIsRejected() public {
        IdentityHarness harness = new IdentityHarness();
        bytes32 salt = MordantAssetIdentity.deriveSalt(keccak256("m"), assetId, EPOCH, 1);
        vm.expectRevert(
            abi.encodeWithSelector(MordantAssetIdentity.UnsupportedSchemeVersion.selector, uint16(2))
        );
        harness.commitment(assetId, 2, EPOCH, salt);
    }

    /* ---------------------------------------------------------- attestation */

    function _config(bytes32 invoiceRoot) private view returns (MordantFactoryV2.InvoiceConfig memory) {
        return MordantFactoryV2.InvoiceConfig({
            cvaAdapter: address(adapter),
            settlementToken: address(settlement),
            invoiceRoot: invoiceRoot,
            currency: bytes32("USD"),
            buyer: buyer,
            originatorTreasury: originator,
            initialOriginatorSigner: originatorSigner,
            initialUnits: UNITS,
            advanceAmount: ADVANCE,
            faceValue: FACE,
            bondBps: 1_000,
            protectionEnd: protectionEnd,
            revealPeriod: REVEAL_PERIOD,
            curePeriod: CURE_PERIOD
        });
    }

    function _attestation(
        MordantFactoryV2.InvoiceConfig memory config,
        bytes32 commitment,
        uint256 nonce,
        address verifyingContract
    ) private view returns (MordantSourceAttestation.SourceAssetAttestation memory) {
        return MordantSourceAttestation.SourceAssetAttestation({
            chainId: block.chainid,
            factory: verifyingContract,
            creationDigest: factory.creationDigest(config),
            assetCommitment: commitment,
            identitySchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            invoiceRoot: config.invoiceRoot,
            controller: config.originatorTreasury,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: nonce
        });
    }

    function _sign(
        MordantSourceAttestation.SourceAssetAttestation memory attestation,
        uint256 key,
        address verifyingContract
    ) private view returns (bytes memory) {
        bytes32 digest = MordantSourceAttestation.digest(attestation, verifyingContract);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _commitment(uint256 anchorNonce) private view returns (bytes32) {
        bytes32 salt = MordantAssetIdentity.deriveSalt(keccak256("issuer-master"), assetId, EPOCH, anchorNonce);
        return MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, salt);
    }

    function _create(bytes32 invoiceRoot, uint256 nonce)
        private
        returns (MordantInvoiceVaultV2 vault, bytes32 commitment)
    {
        MordantFactoryV2.InvoiceConfig memory config = _config(invoiceRoot);
        commitment = _commitment(nonce);
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, commitment, nonce, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.prank(buyer);
        vault = factory.createIdentityAnchoredVault(config, attestation, signature);
    }

    /* ------------------------------------------------------------ happy path */

    function testIdentityAnchoredVaultCarriesImmutableOpaqueIdentity() public {
        (MordantInvoiceVaultV2 vault, bytes32 commitment) = _create(keccak256("root-1"), 1);

        assertEq(vault.assetCommitment(), commitment);
        assertEq(vault.identitySchemeVersion(), 1);
        assertEq(vault.identityEpoch(), EPOCH);
        assertEq(vault.issuerKeyId(), registry.issuerKeyIdFor(issuer));
        assertTrue(vault.sourceAttestationDigest() != bytes32(0));
        // The public root and the private commitment are distinct concepts.
        assertTrue(vault.assetCommitment() != vault.invoiceRoot());
        // V1 economics still work through inheritance.
        assertEq(vault.faceValue(), FACE);
        assertEq(uint256(vault.receivableState()), 0);
        // The vault landed at the CREATE2 address derived from the attestation.
        assertEq(factory.vaultForAttestation(vault.sourceAttestationDigest()), address(vault));
    }

    function testTwoAnchorsOfTheSameAssetAreUnlinkableByCommitment() public {
        (MordantInvoiceVaultV2 first,) = _create(keccak256("root-A"), 1);
        // A second platform anchors the SAME canonical asset under its own salt.
        bytes32 otherSalt =
            MordantAssetIdentity.deriveSalt(keccak256("other-issuer-master"), assetId, EPOCH, 7);
        bytes32 otherCommitment = MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, otherSalt);

        assertTrue(
            first.assetCommitment() != otherCommitment,
            "same asset must not produce equal public commitments"
        );
        // And neither commitment equals the canonical identity itself.
        assertTrue(first.assetCommitment() != assetId);
        assertTrue(otherCommitment != assetId);
    }

    /* -------------------------------------------------------------- negatives */

    function testWrongIssuerKeyIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-wrong-issuer"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(2), 2, address(factory));
        // Signed by a different key than the one the attestation names.
        bytes memory signature = _sign(attestation, OTHER_ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(MordantIssuerRegistry.InvalidIssuer.selector);
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testRevokedIssuerIsRejected() public {
        registry.revokeIssuer(registry.issuerKeyIdFor(issuer));
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-revoked"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(3), 3, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantIssuerRegistry.IssuerRevoked.selector, registry.issuerKeyIdFor(issuer)
            )
        );
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testExpiredAttestationIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-expired"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(4), 4, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.warp(attestation.validUntil + 1);
        vm.startPrank(buyer);
        vm.expectRevert();
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testWrongChainIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-chain"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(5), 5, address(factory));
        attestation.chainId = block.chainid + 1;
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert();
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testWrongFactoryIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-factory"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(6), 6, address(factory));
        attestation.factory = address(0xBEEF);
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert();
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testWrongIdentitySchemeVersionIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-scheme"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(7), 7, address(factory));
        attestation.identitySchemeVersion = 2;
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(
            abi.encodeWithSelector(MordantFactoryV2.SchemeMismatch.selector, uint16(2), uint16(1))
        );
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testEpochBelowIssuerMinimumIsRejected() public {
        registry.advanceEpoch(registry.issuerKeyIdFor(issuer), EPOCH + 5);
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-epoch"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(8), 8, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(MordantIssuerRegistry.InvalidIssuer.selector);
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testAttestationReplayIsRejected() public {
        _create(keccak256("root-replay-1"), 9);
        // Same issuer, same nonce, different root: the nonce alone stops it.
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-replay-2"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(9), 9, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantFactoryV2.AttestationReplayed.selector, registry.issuerKeyIdFor(issuer), uint256(9)
            )
        );
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testChangedCreationParameterAfterSigningIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-mutate"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(10), 10, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        // The buyer tries to deploy on better economics than were attested.
        config.faceValue = FACE + 1;
        vm.startPrank(buyer);
        vm.expectRevert();
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testChangedCommitmentAfterSigningIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-commit"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitment(11), 11, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        // Swapping the commitment invalidates the signature: this is the
        // post-hoc remapping attack, refused at admission.
        attestation.assetCommitment = _commitment(12);
        vm.startPrank(buyer);
        vm.expectRevert(MordantIssuerRegistry.InvalidIssuer.selector);
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testInvoiceRootEqualToCommitmentIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-equal"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, config.invoiceRoot, 13, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(MordantSourceAttestation.InvalidAttestation.selector);
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    /// The whole point of pre-commitment: there is no function that can change
    /// an identity after deployment, so no remapping path exists to test
    /// positively. This asserts the absence.
    function testNoPostDeploymentRemappingPathExists() public {
        (MordantInvoiceVaultV2 vault, bytes32 commitment) = _create(keccak256("root-immutable"), 14);
        // Every identity accessor is view-only and backed by an immutable.
        assertEq(vault.assetCommitment(), commitment);
        bytes32 attestationDigest = vault.sourceAttestationDigest();

        // No setter exists on the vault or the factory.
        (bool ok,) = address(vault).call(abi.encodeWithSignature("setAssetCommitment(bytes32)", bytes32(uint256(1))));
        assertFalse(ok, "vault must expose no identity setter");
        (ok,) = address(factory).call(
            abi.encodeWithSignature("remapAnchor(address,bytes32)", address(vault), bytes32(uint256(1)))
        );
        assertFalse(ok, "factory must expose no remapping entry point");

        assertEq(vault.assetCommitment(), commitment);
        assertEq(vault.sourceAttestationDigest(), attestationDigest);
    }

    /* ------------------------------------------------- non-vault source anchor */

    function testNonVaultSourceUsesTheSameCanonicalIdentity() public {
        bytes32 salt = MordantAssetIdentity.deriveSalt(keccak256("factor-master"), assetId, EPOCH, 100);
        bytes32 commitment = MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, salt);
        MordantSourceAttestation.SourceAssetAttestation memory attestation = MordantSourceAttestation
            .SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(sources),
            creationDigest: keccak256("off-chain-facility-record-1"),
            assetCommitment: commitment,
            identitySchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(otherIssuer),
            invoiceRoot: keccak256("factor-internal-reference"),
            controller: originator,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: 100
        });
        bytes memory signature = _sign(attestation, OTHER_ISSUER_KEY, address(sources));
        bytes32 anchorId = sources.register(attestation, signature);

        assertEq(sources.assetCommitmentOf(anchorId), commitment);
        assertTrue(sources.isRegistered(anchorId));
        // A second registration of the same attestation is refused.
        vm.expectRevert();
        sources.register(attestation, signature);
    }

    function testSourceRegistryRejectsUnauthorizedIssuer() public {
        registry.revokeIssuer(registry.issuerKeyIdFor(otherIssuer));
        MordantSourceAttestation.SourceAssetAttestation memory attestation = MordantSourceAttestation
            .SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(sources),
            creationDigest: keccak256("off-chain-record-2"),
            assetCommitment: _commitment(200),
            identitySchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(otherIssuer),
            invoiceRoot: keccak256("factor-reference-2"),
            controller: originator,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: 200
        });
        bytes memory signature = _sign(attestation, OTHER_ISSUER_KEY, address(sources));
        vm.expectRevert();
        sources.register(attestation, signature);
    }

    /* ------------------------------------------- public correlation surface */

    /// Two V2 anchors of the same asset must not be correlatable through the
    /// identity fields. This asserts the identity surface only; the economics
    /// V1 already publishes are analysed in the accompanying specification.
    function testIdentitySurfaceDoesNotCorrelateTwoAnchors() public {
        (MordantInvoiceVaultV2 first,) = _create(keccak256("root-corr-1"), 300);

        bytes32 salt = MordantAssetIdentity.deriveSalt(keccak256("second-master"), assetId, EPOCH, 301);
        bytes32 secondCommitment = MordantAssetIdentity.assetCommitment(assetId, 1, EPOCH, salt);

        assertTrue(first.assetCommitment() != secondCommitment);
        assertTrue(first.invoiceRoot() != secondCommitment);
        // The issuer key id is public and equal only if the same issuer anchored
        // both, which is exactly the case the two-anchor scenario excludes.
        assertTrue(first.issuerKeyId() != registry.issuerKeyIdFor(otherIssuer));
    }

    /* --------------------------------------------------------- V1 untouched */

    function testV1FactoryAndVaultRemainUsableAndUnchanged() public {
        MordantFactory legacy = new MordantFactory(address(this), eligibility);
        legacy.setCvaAdapter(address(adapter), true);
        legacy.setSettlementToken(address(settlement), true);
        MordantFactory.InvoiceConfig memory config = MordantFactory.InvoiceConfig({
            cvaAdapter: address(adapter),
            settlementToken: address(settlement),
            invoiceRoot: keccak256("v1-root"),
            currency: bytes32("USD"),
            buyer: buyer,
            originatorTreasury: originator,
            initialOriginatorSigner: originatorSigner,
            initialUnits: UNITS,
            advanceAmount: ADVANCE,
            faceValue: FACE,
            bondBps: 1_000,
            protectionEnd: protectionEnd,
            revealPeriod: REVEAL_PERIOD,
            curePeriod: CURE_PERIOD
        });
        vm.prank(buyer);
        MordantInvoiceVault legacyVault = legacy.createInvoiceVault(config);
        assertEq(legacyVault.invoiceRoot(), keccak256("v1-root"));
        // A V1 vault has no identity surface at all: it can serve Mode A and
        // cannot participate in Mode B, which is the intended migration boundary.
        (bool ok,) = address(legacyVault).call(abi.encodeWithSignature("assetCommitment()"));
        assertFalse(ok, "V1 must expose no identity surface");
    }
}
