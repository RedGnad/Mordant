// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {MordantFactory} from "../src/MordantFactory.sol";
import {MordantFactoryV2} from "../src/MordantFactoryV2.sol";
import {MordantInvoiceVault} from "../src/MordantInvoiceVault.sol";
import {MordantInvoiceVaultV2} from "../src/MordantInvoiceVaultV2.sol";
import {MordantAssetIdentity as Id} from "../src/identity/MordantAssetIdentity.sol";
import {MordantIssuerRegistry} from "../src/identity/MordantIssuerRegistry.sol";
import {MordantNormalization as N} from "../src/identity/MordantNormalization.sol";
import {MordantSourceAttestation} from "../src/identity/MordantSourceAttestation.sol";
import {MordantSourceIdentityRegistry} from "../src/identity/MordantSourceIdentityRegistry.sol";
import {MordantTermsRegistry} from "../src/identity/MordantTermsRegistry.sol";
import {MordantMatchResult as Match} from "../src/identity/MordantMatchResult.sol";
import {MordantSessionPrecommitRegistry} from "../src/identity/MordantSessionPrecommitRegistry.sol";
import {MockCvaAdapter} from "../src/mocks/MockCvaAdapter.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockEligibility} from "../src/mocks/MockEligibility.sol";

/// @dev External boundary so `expectRevert` can observe library reverts.
contract IdentityHarness {
    function commitment(bytes32 stableId, uint16 schemeVersion, uint32 epoch, bytes32 salt)
        external
        pure
        returns (bytes32)
    {
        return Id.assetCommitment(stableId, schemeVersion, epoch, salt);
    }

    function terms(bytes32 stableId, uint16 schemeVersion, Id.AssetTermsVersion calldata version)
        external
        pure
        returns (bytes32)
    {
        return Id.termsCommitment(stableId, schemeVersion, version);
    }

    function normalize(uint8 profile, string calldata value, uint256 fixedLength)
        external
        pure
        returns (bytes32)
    {
        return N.normalize(profile, value, fixedLength);
    }

    function strictId(Id.StableAssetIdentity calldata identity) external pure returns (bytes32) {
        return Id.strictStableAssetId(identity);
    }

    function aliasId(Id.StableAssetIdentity calldata identity) external pure returns (bytes32) {
        return Id.candidateAliasId(identity);
    }

    function bindable(Match.ConfidentialMatchResultV4 calldata result, bool precommitted)
        external
        pure
    {
        Match.requireBindable(result, precommitted);
    }
}

contract MordantIdentityV2Test is Test {
    uint256 private constant ISSUER_KEY = 0x1551E4;
    uint256 private constant OTHER_ISSUER_KEY = 0x0FF1CE;
    uint256 private constant ONE = 1e6;
    uint256 private constant UNITS = 100 * ONE;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint32 private constant EPOCH = 1;

    address private issuer;
    address private otherIssuer;
    address private buyer = address(0xB0);
    address private originator = address(0x04);
    address private originatorSigner = address(0x05);

    MockEligibility private eligibility;
    MockERC20 private settlement;
    MockERC20 private cva;
    MockCvaAdapter private adapter;
    MordantIssuerRegistry private registry;
    MordantFactoryV2 private factory;
    MordantSourceIdentityRegistry private sources;
    MordantTermsRegistry private termsRegistry;
    MordantSessionPrecommitRegistry private precommits;
    IdentityHarness private harness;

    bytes32 private stableId;
    uint64 private protectionEnd;

    function setUp() public {
        vm.warp(1_000_000);
        issuer = vm.addr(ISSUER_KEY);
        otherIssuer = vm.addr(OTHER_ISSUER_KEY);

        eligibility = new MockEligibility();
        eligibility.setEligible(buyer, 1, true);
        eligibility.setEligible(originator, 2, true);
        eligibility.setEligible(originatorSigner, 2, true);

        settlement = new MockERC20("Settlement", "aUSD", 6);
        cva = new MockERC20("Invoice A-Token", "aINV", 6);
        adapter = new MockCvaAdapter(cva);

        registry = new MordantIssuerRegistry(address(this));
        registry.registerIssuer(issuer, EPOCH);
        registry.registerIssuer(otherIssuer, EPOCH);

        factory = new MordantFactoryV2(address(this), eligibility, registry);
        factory.setCvaAdapter(address(adapter), true);
        factory.setSettlementToken(address(settlement), true);
        sources = new MordantSourceIdentityRegistry(registry);
        termsRegistry = new MordantTermsRegistry(registry);
        precommits = new MordantSessionPrecommitRegistry(registry);
        harness = new IdentityHarness();

        stableId = _stableId("INV-2026-0042", 20_500);
        protectionEnd = uint64(block.timestamp + 30 days);
    }

    /* ------------------------------------------------------ stable identity */

    function _identity(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (Id.StableAssetIdentity memory)
    {
        return Id.StableAssetIdentity({
            sellerNamespace: N.namespace("lei"),
            sellerId: N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "213800WAVVOPS85N2205", 20),
            sellerProfile: N.PROFILE_ALNUM_UPPER_FIXED,
            debtorNamespace: N.namespace("lei"),
            debtorId: N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "529900T8BM49AURSDO55", 20),
            debtorProfile: N.PROFILE_ALNUM_UPPER_FIXED,
            invoiceNamespace: N.namespace("seller"),
            invoiceId: N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, invoiceNumber, 0),
            invoiceProfile: N.PROFILE_INVOICE_CASE_SENSITIVE,
            tier: Id.IdentityTier.StrictSellerIssued,
            issueDateDays: issueDateDays
        });
    }

    function _stableId(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (bytes32)
    {
        return Id.strictStableAssetId(_identity(invoiceNumber, issueDateDays));
    }

    function _original(uint256 faceValueMinor, uint32 dueDateDays)
        private
        pure
        returns (Id.AssetTermsVersion memory)
    {
        return Id.AssetTermsVersion({
            currencyCode: bytes3("USD"),
            faceValueMinor: faceValueMinor,
            amountExponent: 2,
            dueDateDays: dueDateDays,
            paymentScheduleDigest: bytes32(0),
            termsVersion: 1,
            amendmentId: bytes32(0),
            supersedesTermsCommitment: bytes32(0),
            relation: Id.Relation.Original,
            relatedStableAssetId: bytes32(0),
            effectiveFrom: 1_760_000_000
        });
    }

    /* ----------------------------------- terms must not move stable identity */

    function testSameAssetDifferentDueDates() public view {
        bytes32 a = Id.termsCommitment(stableId, 1, _original(FACE, 20_590));
        bytes32 b = Id.termsCommitment(stableId, 1, _original(FACE, 20_620));
        assertTrue(a != b, "due date must move the terms commitment");
        // The identity is the same asset in both cases: this is the scheme-1 fix.
        assertEq(stableId, _stableId("INV-2026-0042", 20_500));
    }

    function testSameAssetAmendedAmountIsNotANewAsset() public view {
        bytes32 original = Id.termsCommitment(stableId, 1, _original(FACE, 20_590));
        Id.AssetTermsVersion memory amended = _original(FACE + 10 * ONE, 20_590);
        amended.termsVersion = 2;
        amended.relation = Id.Relation.Amendment;
        amended.amendmentId = keccak256("amendment-1");
        amended.supersedesTermsCommitment = original;
        bytes32 amendedCommitment = Id.termsCommitment(stableId, 1, amended);

        assertTrue(amendedCommitment != original);
        // An amount correction stays the same receivable, which is exactly what
        // scheme 1 got wrong.
        assertEq(stableId, _stableId("INV-2026-0042", 20_500));
    }

    function testSameAssetDifferentTermsVersionsDiffer() public view {
        bytes32 v1 = Id.termsCommitment(stableId, 1, _original(FACE, 20_590));
        Id.AssetTermsVersion memory second = _original(FACE, 20_590);
        second.termsVersion = 2;
        second.relation = Id.Relation.Amendment;
        second.amendmentId = keccak256("a");
        second.supersedesTermsCommitment = v1;
        assertTrue(Id.termsCommitment(stableId, 1, second) != v1);
    }

    function testSameTermsDifferentInvoiceIdentityDoNotMatch() public view {
        bytes32 otherAsset = _stableId("INV-2026-0043", 20_500);
        assertTrue(otherAsset != stableId, "different invoice is a different asset");
        // Identical terms bound to two different assets are different objects,
        // because the terms commitment binds the asset it belongs to.
        assertTrue(
            Id.termsCommitment(stableId, 1, _original(FACE, 20_590))
                != Id.termsCommitment(otherAsset, 1, _original(FACE, 20_590))
        );
    }

    /* -------------------------------------------------- relation semantics */

    function testCancellationStaysOnTheSameAsset() public view {
        bytes32 v1 = Id.termsCommitment(stableId, 1, _original(FACE, 20_590));
        Id.AssetTermsVersion memory cancelled = _original(FACE, 20_590);
        cancelled.termsVersion = 2;
        cancelled.relation = Id.Relation.Cancellation;
        cancelled.supersedesTermsCommitment = v1;
        // A cancellation is a terms event on the same receivable, not a new one.
        assertTrue(Id.termsCommitment(stableId, 1, cancelled) != v1);
    }

    function testCreditNoteIsADistinctAssetReferencingTheInvoice() public view {
        bytes32 creditNoteAsset = _stableId("CN-2026-0007", 20_600);
        assertTrue(creditNoteAsset != stableId, "a credit note is its own document");
        Id.AssetTermsVersion memory note = _original(10 * ONE, 20_600);
        note.relation = Id.Relation.CreditNote;
        note.relatedStableAssetId = stableId;
        // It commits under its own asset while naming the invoice it credits.
        assertTrue(Id.termsCommitment(creditNoteAsset, 1, note) != bytes32(0));
    }

    function testReplacementAndNovationAreDistinctAssets() public view {
        bytes32 replacement = _stableId("INV-2026-0042R", 20_610);
        Id.AssetTermsVersion memory terms = _original(FACE, 20_690);
        terms.relation = Id.Relation.Replacement;
        terms.relatedStableAssetId = stableId;
        assertTrue(Id.termsCommitment(replacement, 1, terms) != bytes32(0));
        assertTrue(replacement != stableId);

        // Novation changes a party, so the stable identity necessarily differs.
        Id.StableAssetIdentity memory novated = _identity("INV-2026-0042", 20_500);
        novated.debtorId = N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "353800A3D5UNTV6H2Y19", 20);
        assertTrue(Id.strictStableAssetId(novated) != stableId, "a party change is a different asset");
    }

    function testRelationRulesFailClosed() public {
        // An "original" that claims to supersede something is malformed.
        Id.AssetTermsVersion memory bogus = _original(FACE, 20_590);
        bogus.supersedesTermsCommitment = keccak256("x");
        vm.expectRevert(Id.InvalidRelation.selector);
        harness.terms(stableId, 1, bogus);

        // An amendment with no predecessor is malformed.
        Id.AssetTermsVersion memory orphan = _original(FACE, 20_590);
        orphan.relation = Id.Relation.Amendment;
        orphan.termsVersion = 2;
        orphan.amendmentId = keccak256("a");
        vm.expectRevert(Id.InvalidRelation.selector);
        harness.terms(stableId, 1, orphan);

        // A credit note that points at itself is malformed.
        Id.AssetTermsVersion memory selfRef = _original(FACE, 20_590);
        selfRef.relation = Id.Relation.CreditNote;
        selfRef.relatedStableAssetId = stableId;
        vm.expectRevert(Id.InvalidRelation.selector);
        harness.terms(stableId, 1, selfRef);
    }

    /* ------------------------------------------------ normalization profiles */

    function testIntendedFormattingEquivalence() public view {
        assertEq(
            N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "INV-2026/0042", 0),
            N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "inv 2026 0042", 0)
        );
        assertEq(
            N.normalize(N.PROFILE_VAT, "FR 40.303-265045", 0),
            N.normalize(N.PROFILE_VAT, "fr40303265045", 0)
        );
    }

    /// The lenient invoice profile is lossy and admits collisions between
    /// genuinely different strings. That is a deliberate trade and it is pinned
    /// here so nobody can claim the profile is injective.
    function testAdversarialCollisionsInTheLenientProfile() public view {
        assertEq(
            N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "INV-001", 0),
            N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "IN-V001", 0),
            "documented lossy collision"
        );
        // The case-sensitive profile has no such collision.
        assertTrue(
            N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, "INV-001", 0)
                != N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, "IN-V001", 0)
        );
    }

    function testCaseSensitiveAndInsensitiveProfilesDiffer() public view {
        assertTrue(
            N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, "inv-001", 0)
                != N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, "INV-001", 0),
            "case must matter in the case-sensitive profile"
        );
        assertEq(
            N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "inv-001", 0),
            N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "INV-001", 0)
        );
        // The same characters under two profiles never collide, because the
        // profile id is inside the digest.
        assertTrue(
            N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, "INV001", 0)
                != N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, "INV001", 0)
        );
    }

    function testLeadingZerosAreSignificantForFixedDigitRegistries() public view {
        assertTrue(
            N.normalize(N.PROFILE_DIGITS_FIXED, "000000001", 9)
                != N.normalize(N.PROFILE_DIGITS_FIXED, "100000000", 9),
            "leading zeros must not be trimmed"
        );
    }

    function testFixedLengthAndCharacterRulesFailClosed() public {
        vm.expectRevert(abi.encodeWithSelector(N.WrongLength.selector, uint256(8), uint256(9)));
        harness.normalize(N.PROFILE_DIGITS_FIXED, "00000001", 9);

        vm.expectRevert(abi.encodeWithSelector(N.UnsupportedCharacter.selector, uint8(3)));
        harness.normalize(N.PROFILE_DIGITS_FIXED, "000-00001", 9);

        // Strict registries reject separators outright rather than stripping.
        vm.expectRevert(abi.encodeWithSelector(N.UnsupportedCharacter.selector, uint8(6)));
        harness.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "213800-WAVVOPS85N220", 20);

        // Non-ASCII fails closed: no Unicode folding, which would manufacture
        // collisions between distinct characters.
        vm.expectRevert(abi.encodeWithSelector(N.UnsupportedCharacter.selector, uint8(0)));
        harness.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, unicode"Ｉ NV001", 0);

        vm.expectRevert(abi.encodeWithSelector(N.UnknownProfile.selector, uint8(99)));
        harness.normalize(99, "anything", 0);
    }

    function testSameCharactersInDifferentNamespacesAreDifferentParties() public view {
        Id.StableAssetIdentity memory viaVat = _identity("INV-2026-0042", 20_500);
        viaVat.debtorNamespace = N.namespace("vat");
        viaVat.debtorId = N.normalize(N.PROFILE_VAT, "FR40303265045", 0);

        Id.StableAssetIdentity memory viaSeller = _identity("INV-2026-0042", 20_500);
        viaSeller.debtorNamespace = N.namespace("duns");
        viaSeller.debtorId = N.normalize(N.PROFILE_DIGITS_FIXED, "150483782", 9);

        assertTrue(Id.strictStableAssetId(viaVat) != Id.strictStableAssetId(viaSeller));
        assertTrue(Id.strictStableAssetId(viaVat) != stableId);
    }

    /* --------------------------------------------------------- admission */

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
            revealPeriod: 1 hours,
            curePeriod: 1 hours
        });
    }

    function _commitmentFor(uint256 anchorNonce) private view returns (bytes32) {
        return Id.assetCommitment(
            stableId, 3, EPOCH, Id.deriveSalt(keccak256("issuer-master"), stableId, EPOCH, anchorNonce)
        );
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
            initialTermsCommitment: Id.termsCommitment(stableId, 1, _original(FACE, 20_590)),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
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
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, MordantSourceAttestation.digest(attestation, verifyingContract));
        return abi.encodePacked(r, s, v);
    }

    function _create(bytes32 invoiceRoot, uint256 nonce)
        private
        returns (MordantInvoiceVaultV2 vault, bytes32 commitment)
    {
        MordantFactoryV2.InvoiceConfig memory config = _config(invoiceRoot);
        commitment = _commitmentFor(nonce);
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, commitment, nonce, address(factory));
        vm.prank(buyer);
        vault = factory.createIdentityAnchoredVault(
            config, attestation, _sign(attestation, ISSUER_KEY, address(factory))
        );
    }

    function testAnchorCarriesSeparateIdentityAndTermsCommitments() public {
        (MordantInvoiceVaultV2 vault, bytes32 commitment) = _create(keccak256("root-1"), 1);
        assertEq(vault.assetCommitment(), commitment);
        assertEq(vault.initialTermsCommitment(), Id.termsCommitment(stableId, 1, _original(FACE, 20_590)));
        assertEq(vault.identitySchemeVersion(), 3);
        assertEq(vault.termsSchemeVersion(), 1);
        // Identity and terms are different objects on the anchor.
        assertTrue(vault.assetCommitment() != vault.initialTermsCommitment());
        assertTrue(vault.assetCommitment() != vault.invoiceRoot());
    }

    /* ----------------------------------------------------- terms registry */

    function _amendment(bytes32 anchorId, bytes32 assetCommitment, bytes32 supersedes, uint32 version, uint256 nonce)
        private
        view
        returns (MordantTermsRegistry.TermsAmendment memory)
    {
        Id.AssetTermsVersion memory amended = _original(FACE + 10 * ONE, 20_620);
        amended.termsVersion = version;
        amended.relation = Id.Relation.Amendment;
        amended.amendmentId = keccak256(abi.encode("amendment", version));
        amended.supersedesTermsCommitment = supersedes;
        return MordantTermsRegistry.TermsAmendment({
            chainId: block.chainid,
            registry: address(termsRegistry),
            anchorId: anchorId,
            assetCommitment: assetCommitment,
            termsCommitment: Id.termsCommitment(stableId, 1, amended),
            supersedesTermsCommitment: supersedes,
            termsVersion: version,
            termsSchemeVersion: 1,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            validUntil: uint64(block.timestamp + 1 days),
            nonce: nonce
        });
    }

    function _signAmendment(MordantTermsRegistry.TermsAmendment memory amendment, uint256 key)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, termsRegistry.digestOf(amendment));
        return abi.encodePacked(r, s, v);
    }

    function _initialisedAnchor() private returns (bytes32 anchorId, bytes32 commitment, bytes32 initialTerms) {
        MordantInvoiceVaultV2 vault;
        (vault, commitment) = _create(keccak256("root-terms"), 40);
        anchorId = bytes32(uint256(uint160(address(vault))));
        initialTerms = vault.initialTermsCommitment();
        termsRegistry.initialise(anchorId, commitment, initialTerms, vault.issuerKeyId());
    }

    function testAmendmentAppendsWithoutRewritingIdentity() public {
        (bytes32 anchorId, bytes32 commitment, bytes32 initialTerms) = _initialisedAnchor();
        MordantTermsRegistry.TermsAmendment memory amendment =
            _amendment(anchorId, commitment, initialTerms, 2, 1);
        termsRegistry.appendAmendment(amendment, _signAmendment(amendment, ISSUER_KEY));

        (bytes32 current, uint32 version) = termsRegistry.currentTerms(anchorId);
        assertEq(current, amendment.termsCommitment);
        assertEq(version, 2);
        // The anchor's own immutable values are untouched.
        (bytes32 storedAsset,,, ,) = termsRegistry.anchorTerms(anchorId);
        assertEq(storedAsset, commitment);
    }

    function testAmendmentReplayIsRejected() public {
        (bytes32 anchorId, bytes32 commitment, bytes32 initialTerms) = _initialisedAnchor();
        MordantTermsRegistry.TermsAmendment memory amendment =
            _amendment(anchorId, commitment, initialTerms, 2, 1);
        bytes memory signature = _signAmendment(amendment, ISSUER_KEY);
        termsRegistry.appendAmendment(amendment, signature);
        vm.expectRevert();
        termsRegistry.appendAmendment(amendment, signature);
    }

    function testTermsVersionRollbackIsRejected() public {
        (bytes32 anchorId, bytes32 commitment, bytes32 initialTerms) = _initialisedAnchor();
        MordantTermsRegistry.TermsAmendment memory second =
            _amendment(anchorId, commitment, initialTerms, 3, 1);
        termsRegistry.appendAmendment(second, _signAmendment(second, ISSUER_KEY));

        MordantTermsRegistry.TermsAmendment memory rollback =
            _amendment(anchorId, commitment, second.termsCommitment, 2, 2);
        bytes memory rollbackSignature = _signAmendment(rollback, ISSUER_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(MordantTermsRegistry.NotMonotonic.selector, uint32(2), uint32(3))
        );
        termsRegistry.appendAmendment(rollback, rollbackSignature);
    }

    /// An issuer must not be able to detach a terms version and re-attach it to
    /// a different receivable.
    function testIssuerCannotAttachTermsToAnotherAsset() public {
        (bytes32 anchorId, bytes32 commitment, bytes32 initialTerms) = _initialisedAnchor();
        MordantTermsRegistry.TermsAmendment memory amendment =
            _amendment(anchorId, commitment, initialTerms, 2, 1);
        amendment.assetCommitment = _commitmentFor(999); // a different asset
        bytes memory signature = _signAmendment(amendment, ISSUER_KEY);
        vm.expectRevert(MordantTermsRegistry.InvalidTermsRecord.selector);
        termsRegistry.appendAmendment(amendment, signature);
    }

    /// An issuer must not be able to relabel an amendment as a fresh original.
    function testIssuerCannotRelabelAnAmendmentAsANewOriginal() public {
        (bytes32 anchorId, bytes32 commitment,) = _initialisedAnchor();

        // First defence: the library refuses an amendment dressed as version 1.
        Id.AssetTermsVersion memory dressed = _original(FACE + 10 * ONE, 20_620);
        dressed.relation = Id.Relation.Amendment;
        dressed.amendmentId = keccak256("hidden");
        vm.expectRevert(Id.InvalidRelation.selector);
        harness.terms(stableId, 1, dressed);

        // Second defence: even a well formed "original" cannot be appended as
        // version 1 again, so amended economics cannot be presented as the
        // asset's first and only terms.
        Id.AssetTermsVersion memory freshOriginal = _original(FACE + 10 * ONE, 20_620);
        MordantTermsRegistry.TermsAmendment memory relabelled = MordantTermsRegistry.TermsAmendment({
            chainId: block.chainid,
            registry: address(termsRegistry),
            anchorId: anchorId,
            assetCommitment: commitment,
            termsCommitment: Id.termsCommitment(stableId, 1, freshOriginal),
            supersedesTermsCommitment: bytes32(0),
            termsVersion: 1,
            termsSchemeVersion: 1,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            validUntil: uint64(block.timestamp + 1 days),
            nonce: 5
        });
        bytes memory signature = _signAmendment(relabelled, ISSUER_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(MordantTermsRegistry.NotMonotonic.selector, uint32(1), uint32(1))
        );
        termsRegistry.appendAmendment(relabelled, signature);
    }

    function testForeignIssuerCannotAmend() public {
        (bytes32 anchorId, bytes32 commitment, bytes32 initialTerms) = _initialisedAnchor();
        MordantTermsRegistry.TermsAmendment memory amendment =
            _amendment(anchorId, commitment, initialTerms, 2, 1);
        amendment.issuerKeyId = registry.issuerKeyIdFor(otherIssuer);
        bytes memory signature = _signAmendment(amendment, OTHER_ISSUER_KEY);
        vm.expectRevert(MordantTermsRegistry.WrongIssuer.selector);
        termsRegistry.appendAmendment(amendment, signature);
    }

    function testBrokenSupersessionChainIsRejected() public {
        (bytes32 anchorId, bytes32 commitment,) = _initialisedAnchor();
        MordantTermsRegistry.TermsAmendment memory amendment =
            _amendment(anchorId, commitment, keccak256("not-the-current-terms"), 2, 1);
        bytes memory signature = _signAmendment(amendment, ISSUER_KEY);
        vm.expectRevert();
        termsRegistry.appendAmendment(amendment, signature);
    }

    /* ------------------------------------------------------ admission negatives */

    function testWrongSchemeVersionsAreRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-scheme"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitmentFor(7), 7, address(factory));
        attestation.identitySchemeVersion = 1; // the retired scheme
        vm.startPrank(buyer);
        vm.expectRevert(
            abi.encodeWithSelector(MordantFactoryV2.SchemeMismatch.selector, uint16(1), uint16(3))
        );
        factory.createIdentityAnchoredVault(config, attestation, _sign(attestation, ISSUER_KEY, address(factory)));
        vm.stopPrank();
    }

    function testAssetCommitmentEqualToTermsCommitmentIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-conflate"));
        bytes32 shared = _commitmentFor(8);
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, shared, 8, address(factory));
        attestation.initialTermsCommitment = shared;
        vm.startPrank(buyer);
        vm.expectRevert(MordantSourceAttestation.InvalidAttestation.selector);
        factory.createIdentityAnchoredVault(config, attestation, _sign(attestation, ISSUER_KEY, address(factory)));
        vm.stopPrank();
    }

    function testRevokedIssuerIsRejected() public {
        registry.revokeIssuer(registry.issuerKeyIdFor(issuer));
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-revoked"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitmentFor(3), 3, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantIssuerRegistry.IssuerRevoked.selector, registry.issuerKeyIdFor(issuer)
            )
        );
        factory.createIdentityAnchoredVault(config, attestation, _sign(attestation, ISSUER_KEY, address(factory)));
        vm.stopPrank();
    }

    function testAttestationReplayIsRejected() public {
        _create(keccak256("root-replay-1"), 9);
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-replay-2"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitmentFor(9), 9, address(factory));
        vm.startPrank(buyer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantFactoryV2.AttestationReplayed.selector, registry.issuerKeyIdFor(issuer), uint256(9)
            )
        );
        factory.createIdentityAnchoredVault(config, attestation, _sign(attestation, ISSUER_KEY, address(factory)));
        vm.stopPrank();
    }

    function testChangedCommitmentAfterSigningIsRejected() public {
        MordantFactoryV2.InvoiceConfig memory config = _config(keccak256("root-commit"));
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(config, _commitmentFor(11), 11, address(factory));
        bytes memory signature = _sign(attestation, ISSUER_KEY, address(factory));
        attestation.assetCommitment = _commitmentFor(12);
        vm.startPrank(buyer);
        vm.expectRevert(MordantIssuerRegistry.InvalidIssuer.selector);
        factory.createIdentityAnchoredVault(config, attestation, signature);
        vm.stopPrank();
    }

    function testNoPostDeploymentRemappingPathExists() public {
        (MordantInvoiceVaultV2 vault, bytes32 commitment) = _create(keccak256("root-immutable"), 14);
        (bool ok,) = address(vault).call(
            abi.encodeWithSignature("setAssetCommitment(bytes32)", bytes32(uint256(1)))
        );
        assertFalse(ok, "vault must expose no identity setter");
        (ok,) = address(vault).call(
            abi.encodeWithSignature("setInitialTermsCommitment(bytes32)", bytes32(uint256(1)))
        );
        assertFalse(ok, "vault must expose no terms setter");
        assertEq(vault.assetCommitment(), commitment);
    }

    /* -------------------------------------------- non-vault source parity */

    function testNonVaultSourceUsesTheSameIdentityAndTermsSpec() public {
        bytes32 salt = Id.deriveSalt(keccak256("factor-master"), stableId, EPOCH, 100);
        MordantSourceAttestation.SourceAssetAttestation memory attestation = MordantSourceAttestation
            .SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(sources),
            creationDigest: keccak256("off-chain-facility-record-1"),
            assetCommitment: Id.assetCommitment(stableId, 3, EPOCH, salt),
            initialTermsCommitment: Id.termsCommitment(stableId, 1, _original(FACE, 20_590)),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(otherIssuer),
            invoiceRoot: keccak256("factor-internal-reference"),
            controller: originator,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: 100
        });
        bytes32 anchorId =
            sources.register(attestation, _sign(attestation, OTHER_ISSUER_KEY, address(sources)));
        // The same stable asset, anchored by a non-vault source, under its own
        // salt, therefore unlinkable from the vault anchor.
        assertEq(sources.assetCommitmentOf(anchorId), Id.assetCommitment(stableId, 3, EPOCH, salt));
        assertTrue(sources.assetCommitmentOf(anchorId) != _commitmentFor(1));
    }

    /* ------------------------------ strict versus tolerant candidate paths */

    function _candidateIdentity(string memory invoiceNumber)
        private
        pure
        returns (Id.StableAssetIdentity memory identity)
    {
        identity = _identity(invoiceNumber, 20_500);
        identity.invoiceId = N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, invoiceNumber, 0);
        identity.invoiceProfile = N.PROFILE_INVOICE_CASE_INSENSITIVE;
        identity.tier = Id.IdentityTier.TolerantCandidate;
    }

    /// The decision case. `INV-001` and `IN-V001` are different invoices that
    /// the tolerant profile merges. A candidate match may fire; an exact match
    /// must not; and recourse must be impossible.
    function testInvOneVersusInVOneCandidateYesExactNo() public {
        assertEq(
            Id.candidateAliasId(_candidateIdentity("INV-001")),
            Id.candidateAliasId(_candidateIdentity("IN-V001")),
            "tolerant path may suggest these are the same"
        );
        assertTrue(
            _stableId("INV-001", 20_500) != _stableId("IN-V001", 20_500),
            "strict path must keep them distinct"
        );

        // And a result carrying only the candidate signal cannot bind.
        Match.ConfidentialMatchResultV4 memory candidate = _result(false, true, false);
        assertTrue(Match.opensReconciliation(candidate));
        vm.expectRevert(Match.CandidateResultNotBindable.selector);
        harness.bindable(candidate, true);
    }

    /// A lossy profile cannot produce a binding identity at all: the failure is
    /// structural, not a policy check that could be forgotten.
    function testLossyProfileCannotProduceStrictIdentity() public {
        Id.StableAssetIdentity memory tolerant = _candidateIdentity("INV-001");
        tolerant.tier = Id.IdentityTier.StrictSellerIssued; // claim a binding tier
        vm.expectRevert(
            abi.encodeWithSelector(
                Id.LossyProfileNotPermitted.selector, N.PROFILE_INVOICE_CASE_INSENSITIVE
            )
        );
        harness.strictId(tolerant);
    }

    function testCandidateTierCannotProduceStrictIdentity() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Id.CandidateTierCannotBind.selector, Id.IdentityTier.TolerantCandidate
            )
        );
        harness.strictId(_candidateIdentity("INV-001"));
    }

    function testStrictTierCannotProduceCandidateAlias() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Id.LosslessProfileRequiredForTier.selector, Id.IdentityTier.StrictSellerIssued
            )
        );
        harness.aliasId(_identity("INV-001", 20_500));
    }

    /// A registry document identifier outranks a seller-issued one, and the two
    /// are different identities even for the same invoice.
    function testRegistryDocumentTierIsDistinctFromSellerIssued() public view {
        Id.StableAssetIdentity memory registryDoc = _identity("IT00012026X", 20_500);
        registryDoc.invoiceNamespace = N.namespace("sdi");
        registryDoc.tier = Id.IdentityTier.RegistryDocument;
        assertTrue(Id.strictStableAssetId(registryDoc) != _stableId("IT00012026X", 20_500));
    }

    /* ---------------------------------------------------- result semantics */

    function _result(bool exact, bool candidate, bool conflict)
        private
        pure
        returns (Match.ConfidentialMatchResultV4 memory)
    {
        return Match.ConfidentialMatchResultV4({
            sessionId: keccak256("session-1"),
            scopeCommitmentA: keccak256("scope-a"),
            scopeCommitmentB: keccak256("scope-b"),
            inputCommitmentA: keccak256("input-a"),
            inputCommitmentB: keccak256("input-b"),
            exactMatchConfirmed: exact,
            candidateMatchSuggested: candidate,
            conflictConfirmed: conflict,
            matchCommitment: keccak256("match"),
            anchorCount: 1,
            providerProofCommitment: keccak256("proof")
        });
    }

    function testConflictRequiresExactMatch() public {
        vm.expectRevert(Match.ConflictWithoutExactMatch.selector);
        harness.bindable(_result(false, true, true), true);
    }

    function testCandidateResultReplayIntoBinderIsRejected() public {
        // Even a result that also claims an exact match is refused if it carries
        // the candidate signal: a session that ran the tolerant path is a
        // reconciliation signal by construction.
        Match.ConfidentialMatchResultV4 memory upgraded = _result(true, true, true);
        vm.expectRevert(
            abi.encodeWithSelector(
                Match.CandidateSessionCannotBind.selector, keccak256("session-1")
            )
        );
        harness.bindable(upgraded, true);
    }

    function testExactResultWithoutPrecommitmentIsRejected() public {
        vm.expectRevert(
            abi.encodeWithSelector(Match.MissingPrecommitment.selector, keccak256("session-1"))
        );
        harness.bindable(_result(true, false, true), false);
    }

    function testExactResultWithPrecommitmentIsAccepted() public view {
        harness.bindable(_result(true, false, true), true);
    }

    /* ------------------------------------------- reconciliation lifecycle */

    function _precommit(bytes32 sessionId, bytes32 candidateSession, uint256 nonce)
        private
        view
        returns (MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory)
    {
        return MordantSessionPrecommitRegistry.ExactSessionPrecommitment({
            chainId: block.chainid,
            registry: address(precommits),
            sessionId: sessionId,
            strictAssetCommitment: _commitmentFor(1),
            equivalenceOf: bytes32(0),
            supersedesCandidateSession: candidateSession,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            identityEpoch: EPOCH,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: nonce
        });
    }

    function _signPrecommit(
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory precommitment,
        uint256 key
    ) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, precommits.digestOf(precommitment));
        return abi.encodePacked(r, s, v);
    }

    function testReconciliationRequiresANewSessionAndPrecommitment() public {
        bytes32 candidateSession = keccak256("candidate-session");
        bytes32 exactSession = keccak256("exact-session");
        precommits.markCandidateSession(candidateSession);

        // The tolerant session can never be pre-committed as exact.
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory upgrade =
            _precommit(candidateSession, bytes32(0), 1);
        bytes memory upgradeSignature = _signPrecommit(upgrade, ISSUER_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantSessionPrecommitRegistry.CandidateSessionCannotBePrecommitted.selector,
                candidateSession
            )
        );
        precommits.precommitExactSession(upgrade, upgradeSignature);

        // Before reconciliation, the new session is not authorized.
        assertFalse(precommits.isSessionPrecommitted(exactSession, _commitmentFor(1)));

        // After an authorized pre-commitment, it is.
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory fresh =
            _precommit(exactSession, candidateSession, 2);
        precommits.precommitExactSession(fresh, _signPrecommit(fresh, ISSUER_KEY));
        assertTrue(precommits.isSessionPrecommitted(exactSession, _commitmentFor(1)));
        // And only for the committed asset.
        assertFalse(precommits.isSessionPrecommitted(exactSession, _commitmentFor(2)));
    }

    function testPrecommitmentIsOneShotAndIssuerAuthorized() public {
        bytes32 sessionId = keccak256("exact-session-2");
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory precommitment =
            _precommit(sessionId, bytes32(0), 3);
        precommits.precommitExactSession(precommitment, _signPrecommit(precommitment, ISSUER_KEY));

        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory repeat =
            _precommit(sessionId, bytes32(0), 4);
        bytes memory repeatSignature = _signPrecommit(repeat, ISSUER_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantSessionPrecommitRegistry.SessionAlreadyPrecommitted.selector, sessionId
            )
        );
        precommits.precommitExactSession(repeat, repeatSignature);

        // A revoked issuer cannot authorize a session.
        registry.revokeIssuer(registry.issuerKeyIdFor(issuer));
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory afterRevocation =
            _precommit(keccak256("exact-session-3"), bytes32(0), 5);
        bytes memory revokedSignature = _signPrecommit(afterRevocation, ISSUER_KEY);
        vm.expectRevert();
        precommits.precommitExactSession(afterRevocation, revokedSignature);
    }

    /* --------------------------------------------------------- V1 untouched */

    function testV1RemainsUsableAndHasNoIdentitySurface() public {
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
            revealPeriod: 1 hours,
            curePeriod: 1 hours
        });
        vm.prank(buyer);
        MordantInvoiceVault legacyVault = legacy.createInvoiceVault(config);
        assertEq(legacyVault.invoiceRoot(), keccak256("v1-root"));
        (bool ok,) = address(legacyVault).call(abi.encodeWithSignature("assetCommitment()"));
        assertFalse(ok, "V1 must expose no identity surface");
    }
}
