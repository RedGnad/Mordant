// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {MordantFactoryV2} from "../src/MordantFactoryV2.sol";
import {MordantInvoiceVault} from "../src/MordantInvoiceVault.sol";
import {MordantInvoiceVaultV2} from "../src/MordantInvoiceVaultV2.sol";
import {MockCvaAdapter} from "../src/mocks/MockCvaAdapter.sol";
import {MockEligibility} from "../src/mocks/MockEligibility.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MordantAssetIdentity as Id} from "../src/identity/MordantAssetIdentity.sol";
import {MordantIssuerRegistry} from "../src/identity/MordantIssuerRegistry.sol";
import {MordantMatchResult as Match} from "../src/identity/MordantMatchResult.sol";
import {MordantNormalization as N} from "../src/identity/MordantNormalization.sol";
import {MordantSessionPrecommitRegistry} from "../src/identity/MordantSessionPrecommitRegistry.sol";
import {MordantSourceAttestation} from "../src/identity/MordantSourceAttestation.sol";
import {MordantSourceIdentityRegistry} from "../src/identity/MordantSourceIdentityRegistry.sol";
import {ECDSAQuorumMatchVerifierV4} from "../src/v4/ECDSAQuorumMatchVerifierV4.sol";
import {IAnchoredReceivable} from "../src/v4/IAnchoredReceivable.sol";
import {PrivateMatchBinder} from "../src/v4/PrivateMatchBinder.sol";

/// @notice Settable identity anchor, for the anchor-state negatives a real vault
/// can only reach through its own economic lifecycle.
contract MockAnchor is IAnchoredReceivable {
    bytes32 public assetCommitment;
    uint16 public identitySchemeVersion = 3;
    bytes32 public initialTermsCommitment = keccak256("mock-terms");
    uint16 public termsSchemeVersion = 1;
    uint32 public identityEpoch = 1;
    bytes32 public issuerKeyId;
    bytes32 public sourceAttestationDigest = keccak256("mock-attestation");
    uint8 public receivableState = 1;
    uint8 public protectionState = 1;
    uint256 public totalSupply = 100e6;

    constructor(bytes32 commitment, bytes32 issuer) {
        assetCommitment = commitment;
        issuerKeyId = issuer;
    }

    function setScheme(uint16 value) external {
        identitySchemeVersion = value;
    }

    function setReceivableState(uint8 value) external {
        receivableState = value;
    }

    function setProtectionState(uint8 value) external {
        protectionState = value;
    }

    function setTotalSupply(uint256 value) external {
        totalSupply = value;
    }
}

/// @dev Every negative here builds its call arguments BEFORE arming
/// `vm.expectRevert`. The helpers make external and cheatcode calls, and one made
/// after the expectation would consume it instead of the call under test.
contract PrivateMatchBinderV4Test is Test {
    uint256 private constant ISSUER_KEY = 0x1551E4;
    uint256 private constant OTHER_ISSUER_KEY = 0x0FF1CE;
    uint256 private constant ONE = 1e6;
    uint256 private constant UNITS = 100 * ONE;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint32 private constant EPOCH = 1;
    bytes32 private constant CURRENCY = bytes32("USD");

    uint256 private constant BUYER_KEY = 0xB0B;
    uint256 private constant ORIGINATOR_KEY = 0xA11CE;
    uint256 private constant FACILITY_KEY = 0xFA11;
    uint256 private constant HOLDER_KEY = 0xAA01;
    uint256 private constant CONTROLLER_A_KEY = 0xC0A;
    uint256 private constant CONTROLLER_B_KEY = 0xC0B;
    uint256 private constant OUTSIDER_KEY = 0x0175;

    bytes32 private constant POLICY_ID = keccak256("mordant.double-financing/1");
    uint32 private constant POLICY_VERSION = 1;
    bytes32 private constant SCOPE_A = keccak256("scope-platform-a");
    bytes32 private constant SCOPE_B = keccak256("scope-platform-b");
    bytes32 private constant SESSION = keccak256("session-exact-1");
    uint64 private constant CURE_PERIOD = 7 days;

    address private issuer;
    address private otherIssuer;
    address private buyer;
    address private originator;
    address private facility;
    address private holder;
    address private controllerA;
    address private controllerB;

    uint256[3] private validatorKeys;
    address[] private validatorSet;

    MockEligibility private eligibility;
    MockERC20 private settlement;
    MordantIssuerRegistry private registry;
    MordantFactoryV2 private factory;
    MordantSourceIdentityRegistry private sources;
    MordantSessionPrecommitRegistry private precommits;
    ECDSAQuorumMatchVerifierV4 private verifier;
    PrivateMatchBinder private binder;

    MordantInvoiceVaultV2 private vault;
    bytes32 private anchorCommitment;
    bytes32 private counterpartyCommitment;
    bytes32 private counterpartyAnchorId;

    /// @dev One CVA token per vault: the factory binds a token to a single root.
    mapping(address anchor => MockCvaAdapter) private adapterOf;
    mapping(address anchor => MockERC20) private cvaOf;

    bytes32 private stableId;
    uint64 private protectionEnd;
    uint256 private precommitNonce = 1;

    function setUp() public {
        vm.warp(1_000_000);
        issuer = vm.addr(ISSUER_KEY);
        otherIssuer = vm.addr(OTHER_ISSUER_KEY);
        buyer = vm.addr(BUYER_KEY);
        originator = vm.addr(ORIGINATOR_KEY);
        facility = vm.addr(FACILITY_KEY);
        holder = vm.addr(HOLDER_KEY);
        controllerA = vm.addr(CONTROLLER_A_KEY);
        controllerB = vm.addr(CONTROLLER_B_KEY);

        eligibility = new MockEligibility();
        eligibility.setEligible(buyer, 1, true);
        eligibility.setEligible(originator, 2, true);
        eligibility.setEligible(facility, 3, true);
        eligibility.setEligible(holder, 4, true);

        settlement = new MockERC20("Settlement", "aUSD", 6);

        registry = new MordantIssuerRegistry(address(this));
        registry.registerIssuer(issuer, EPOCH);
        registry.registerIssuer(otherIssuer, EPOCH);

        factory = new MordantFactoryV2(address(this), eligibility, registry);
        factory.setFacility(facility, true);
        factory.setSettlementToken(address(settlement), true);
        sources = new MordantSourceIdentityRegistry(registry);
        precommits = new MordantSessionPrecommitRegistry(registry);

        stableId = _stableId("INV-2026-0042", 20_500);
        protectionEnd = uint64(block.timestamp + 30 days);

        // 2-of-3, the quorum shape the dealerless ceremony releases under.
        validatorKeys = [uint256(0xA11), uint256(0xB22), uint256(0xC33)];
        _sortValidators();
        verifier = new ECDSAQuorumMatchVerifierV4(address(this), validatorSet, 2);
        verifier.setPolicyVersion(POLICY_ID, POLICY_VERSION);
        verifier.setScopeAuthorized(SCOPE_A, true);
        verifier.setScopeAuthorized(SCOPE_B, true);

        binder = new PrivateMatchBinder(
            address(this),
            verifier,
            precommits,
            sources,
            POLICY_ID,
            POLICY_VERSION,
            keccak256("originator"),
            CURE_PERIOD,
            keccak256("recourse.notice/1")
        );
        binder.setScopeController(SCOPE_A, controllerA);
        binder.setScopeController(SCOPE_B, controllerB);

        // Local side: a real V2 vault, activated so the receivable is Outstanding
        // with funded protection.
        vault = _createVault(keccak256("root-local"), 1);
        anchorCommitment = vault.assetCommitment();
        _activate(vault);

        // Counterparty side: a traditional factor with no on-chain vault, which
        // still had to commit to its identity before any session could run.
        counterpartyCommitment = keccak256("counterparty-salted-commitment");
        counterpartyAnchorId = _registerSource(counterpartyCommitment, 900);
    }

    /* ------------------------------------------------------------ happy path */

    function testBindsConfirmedConflictToItsAnchor() public {
        _bind(SESSION, 1);

        PrivateMatchBinder.RecourseRecord memory record = binder.recourseOf(SESSION);
        assertEq(record.sessionId, SESSION);
        assertEq(record.matchCommitment, keccak256(abi.encode("match", SESSION)));
        assertEq(record.anchorCommitment, anchorCommitment);
        assertEq(record.counterpartyCommitment, counterpartyCommitment);
        assertEq(record.anchor, address(vault));
        assertEq(record.policyId, POLICY_ID);
        assertEq(record.policyVersion, POLICY_VERSION);
        assertTrue(record.conflictConfirmed);
        assertEq(record.cureDeadline, uint64(block.timestamp) + CURE_PERIOD);
        assertTrue(record.open);
        assertTrue(binder.anchorLive(SESSION));
    }

    function testBindingIsNonEconomicAndTouchesNothingOnTheAnchor() public {
        uint256 supplyBefore = vault.totalSupply();
        uint256 settlementBefore = settlement.balanceOf(address(vault));
        uint8 protectionBefore = uint8(vault.protectionState());

        _bind(SESSION, 1);

        // The binder holds nothing, moved nothing and changed no vault state.
        assertEq(vault.totalSupply(), supplyBefore);
        assertEq(settlement.balanceOf(address(vault)), settlementBefore);
        assertEq(uint8(vault.protectionState()), protectionBefore);
        assertEq(vault.balanceOf(address(binder)), 0);
        assertEq(settlement.balanceOf(address(binder)), 0);
    }

    function testNoAssetIdentifierIsWrittenToChain() public {
        _bind(SESSION, 1);
        PrivateMatchBinder.RecourseRecord memory record = binder.recourseOf(SESSION);
        // Everything recorded is a commitment. None of it is the canonical
        // identifier the session actually compared.
        assertTrue(record.anchorCommitment != stableId);
        assertTrue(record.counterpartyCommitment != stableId);
        assertTrue(record.matchCommitment != stableId);
        // The two sides are salted independently, so even a matching pair does
        // not publish a shared identifier.
        assertTrue(record.anchorCommitment != record.counterpartyCommitment);
    }

    /* --------------------------------------------------------- substitution */

    function testAResultCannotBeMovedToAnotherAnchor() public {
        MordantInvoiceVaultV2 other = _createVault(keccak256("root-other"), 2);
        _activate(other);
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);

        _expectRevert(
            _exactEnvelope(SESSION, 1),
            IAnchoredReceivable(address(other)),
            abi.encodeWithSelector(
                PrivateMatchBinder.AnchorCommitmentNotInSession.selector, other.assetCommitment()
            )
        );
    }

    function testASessionNotPrecommittedForTheAnchorCannotBind() public {
        // The anchor is genuinely a side of the session, but no issuer named this
        // session against it before the session ran.
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            abi.encodeWithSelector(
                PrivateMatchBinder.SessionNotPrecommittedForAnchor.selector, SESSION, anchorCommitment
            )
        );
    }

    function testAnotherIssuerCannotPrecommitAgainstThisAnchor() public {
        // The anchor's commitment is public, so any authorized issuer can copy it
        // into a pre-commitment. The binder requires the pre-committing issuer to
        // be the issuer that attested the anchor.
        _precommit(SESSION, anchorCommitment, OTHER_ISSUER_KEY, otherIssuer);
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            abi.encodeWithSelector(
                PrivateMatchBinder.PrecommitmentIssuerMismatch.selector,
                registry.issuerKeyIdFor(otherIssuer),
                vault.issuerKeyId()
            )
        );
    }

    function testAnAnchorCannotBeMatchedAgainstItself() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        envelope.result.inputCommitmentB = envelope.result.inputCommitmentA;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);

        _expectRevert(
            envelope, abi.encodeWithSelector(PrivateMatchBinder.SelfMatch.selector, anchorCommitment)
        );
    }

    function testCounterpartyMustBeAnchoredBeforeTheSession() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        PrivateMatchBinder.Counterparty memory unanchored;
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            IAnchoredReceivable(address(vault)),
            unanchored,
            abi.encodeWithSelector(PrivateMatchBinder.CounterpartyNotAnchored.selector)
        );
    }

    function testCounterpartyAnchorMustCarryTheCommitmentInTheSession() public {
        bytes32 unrelated = _registerSource(keccak256("unrelated-commitment"), 901);
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        PrivateMatchBinder.Counterparty memory wrong = PrivateMatchBinder.Counterparty({
            kind: PrivateMatchBinder.CounterpartyKind.RegisteredSource,
            anchorId: unrelated,
            vault: address(0)
        });
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            IAnchoredReceivable(address(vault)),
            wrong,
            abi.encodeWithSelector(
                PrivateMatchBinder.CounterpartyCommitmentMismatch.selector,
                keccak256("unrelated-commitment"),
                counterpartyCommitment
            )
        );
    }

    /* --------------------------------------------------------------- replay */

    function testTheSameSessionCannotBindTwice() public {
        _bind(SESSION, 1);
        // The session is already pre-committed and already bound. A second
        // envelope for it, however well formed, has nothing left to bind.
        _expectRevert(
            _exactEnvelope(SESSION, 2),
            abi.encodeWithSelector(PrivateMatchBinder.SessionAlreadyBound.selector, SESSION)
        );
    }

    function testTheSameNonceCannotBeReplayed() public {
        _bind(SESSION, 1);
        bytes32 second = keccak256("session-exact-2");
        _precommit(second, anchorCommitment, ISSUER_KEY, issuer);
        // A new session, but the same envelope nonce.
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(second, 1);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.ReplayAlreadyConsumed.selector, verifier.replayKey(envelope)
            )
        );
    }

    function testOnePositiveMatchBindsOnce() public {
        _bind(SESSION, 1);
        // A different anchor pair, so this is a fresh decision, but it carries
        // the match commitment that has already been bound. One confirmed match
        // binds once, which is what stops a match being spread over anchors.
        MordantInvoiceVaultV2 other = _createVault(keccak256("root-second"), 4);
        _activate(other);
        bytes32 otherCounterparty = keccak256("second-counterparty-commitment");
        bytes32 otherAnchorId = _registerSource(otherCounterparty, 902);

        bytes32 second = keccak256("session-exact-3");
        _precommit(second, other.assetCommitment(), ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope =
            _exactEnvelope(second, 2, other.assetCommitment());
        envelope.result.inputCommitmentB = otherCounterparty;
        envelope.result.matchCommitment = keccak256(abi.encode("match", SESSION));
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);

        _expectRevert(
            envelope,
            IAnchoredReceivable(address(other)),
            PrivateMatchBinder.Counterparty({
                kind: PrivateMatchBinder.CounterpartyKind.RegisteredSource,
                anchorId: otherAnchorId,
                vault: address(0)
            }),
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.MatchAlreadyConsumed.selector,
                keccak256(abi.encode("match", SESSION))
            )
        );
    }

    function testTheSameInputPairIsDecidedOnce() public {
        _bind(SESSION, 1);
        bytes32 second = keccak256("session-exact-4");
        _precommit(second, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(second, 3);
        // Same two anchors, reversed: still the same decision.
        envelope.result.inputCommitmentA = counterpartyCommitment;
        envelope.result.inputCommitmentB = anchorCommitment;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.DecisionAlreadyConsumed.selector,
                verifier.decisionKey(envelope)
            )
        );
    }

    /* ---------------------------------------------------- candidate results */

    function testACandidateResultCannotBind() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        _expectRevert(
            _candidateEnvelope(SESSION, 1),
            abi.encodeWithSelector(Match.CandidateSessionCannotBind.selector, SESSION)
        );
    }

    function testANoMatchResultCannotBind() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        envelope.result.outcome = Match.Outcome.NoMatchForSubmittedIdentities;
        envelope.result.exactMatchConfirmed = false;
        envelope.result.conflictConfirmed = false;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);

        _expectRevert(envelope, abi.encodeWithSelector(Match.CandidateResultNotBindable.selector));
    }

    function testANotComparableResultCannotBind() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        envelope.result.outcome = Match.Outcome.NotComparable;
        envelope.result.exactMatchConfirmed = false;
        envelope.result.conflictConfirmed = false;
        // No FHE ran, so there is no provider proof to carry.
        envelope.result.providerProofCommitment = bytes32(0);
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);

        _expectRevert(envelope, abi.encodeWithSelector(Match.CandidateResultNotBindable.selector));
    }

    function testTheVerifierRefusesACandidateResultEvenWithAValidQuorum() public {
        // The result invariants run before any signature check, so a tolerant
        // result cannot reach the chain by way of a well-formed quorum.
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _candidateEnvelope(SESSION, 1);
        envelope.binder = address(this);
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        bytes memory attestation = _attest(envelope);

        vm.expectRevert(abi.encodeWithSelector(Match.CandidateSessionCannotBind.selector, SESSION));
        verifier.acceptMatch(envelope, attestation);
    }

    /* ----------------------------------------------------- anchor negatives */

    function testAnUnactivatedReceivableCannotCarryRecourse() public {
        MordantInvoiceVaultV2 idle = _createVault(keccak256("root-idle"), 3);
        _precommit(SESSION, idle.assetCommitment(), ISSUER_KEY, issuer);
        _expectRevert(
            _exactEnvelope(SESSION, 1, idle.assetCommitment()),
            IAnchoredReceivable(address(idle)),
            abi.encodeWithSelector(PrivateMatchBinder.AnchorNotOutstanding.selector, 0)
        );
    }

    function testInactiveProtectionBlocksBinding() public {
        MockAnchor mock = new MockAnchor(keccak256("mock-commitment"), vault.issuerKeyId());
        mock.setProtectionState(0);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorProtectionInactive.selector, 0)
        );
    }

    function testARedeemedReceivableBlocksBinding() public {
        MockAnchor mock = new MockAnchor(keccak256("mock-commitment"), vault.issuerKeyId());
        mock.setReceivableState(2);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorNotOutstanding.selector, 2)
        );
    }

    function testAnAnchorWithNoUnitsBlocksBinding() public {
        MockAnchor mock = new MockAnchor(keccak256("mock-commitment"), vault.issuerKeyId());
        mock.setTotalSupply(0);
        _expectMockRevert(mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorHasNoUnits.selector));
    }

    function testAnotherIdentitySchemeBlocksBinding() public {
        MockAnchor mock = new MockAnchor(keccak256("mock-commitment"), vault.issuerKeyId());
        mock.setScheme(2);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorSchemeMismatch.selector, 2, 3)
        );
    }

    function testACodelessAddressCannotBeAnAnchor() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            IAnchoredReceivable(address(0xDEAD)),
            abi.encodeWithSelector(PrivateMatchBinder.AnchorNotDeployed.selector, address(0xDEAD))
        );
    }

    /* -------------------------------------------------------------- consent */

    function testOneSidedConsentCannotPublishAConflict() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        // Platform A signs for both scopes. The counterparty never agreed to
        // disclosure, which is the whole point of the private mode.
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _source(),
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY),
            _consent(envelope, SCOPE_B, CONTROLLER_A_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
    }

    function testConsentsCannotBeSuppliedForTheWrongScopes() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        // Both consents are individually valid, but swapped: each is matched to
        // its scope by content, not by argument position.
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _source(),
            _consent(envelope, SCOPE_B, CONTROLLER_B_KEY),
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
    }

    function testConsentIsBoundToTheResultItAuthorizes() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        // A consent signed over a different result does not carry to this one.
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory decoy = _exactEnvelope(SESSION, 2);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _source(),
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY),
            _consent(decoy, SCOPE_B, CONTROLLER_B_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
    }

    function testExpiredConsentIsRefused() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(envelope, SCOPE_B, CONTROLLER_B_KEY);
        uint64 expiry = consentB.validUntil;
        vm.warp(expiry + 1);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _source(),
            consentA,
            consentB,
            abi.encodeWithSelector(
                PrivateMatchBinder.DisclosureConsentExpired.selector, SCOPE_A, expiry
            )
        );
    }

    function testAnUnknownScopeControllerCannotConsent() public {
        binder.setScopeController(SCOPE_B, address(0));
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            abi.encodeWithSelector(PrivateMatchBinder.ScopeControllerUnknown.selector, SCOPE_B)
        );
    }

    function testOnlyTheOwnerSetsScopeControllers() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(
            abi.encodeWithSelector(PrivateMatchBinder.Unauthorized.selector, address(0xBAD))
        );
        binder.setScopeController(SCOPE_A, address(0xBAD));
    }

    /* --------------------------------------------------------------- quorum */

    function testOneValidatorIsNotAQuorum() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        _expectRevertWithAttestation(
            envelope,
            _attestWith(envelope, 1),
            abi.encodeWithSelector(ECDSAQuorumMatchVerifierV4.InsufficientSignatures.selector, 1, 2)
        );
    }

    function testAnOutsiderSignatureIsNotAValidator() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        bytes32 digest =
            verifier.attestationDigest(verifier.validatorSetId(), verifier.resultDigest(envelope));
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(validatorKeys[0], digest);
        signatures[1] = _sign(OUTSIDER_KEY, digest);
        // Sorted, so the ordering rule is not what rejects it.
        if (vm.addr(OUTSIDER_KEY) < validatorSet[0]) {
            (signatures[0], signatures[1]) = (signatures[1], signatures[0]);
        }
        _expectRevertWithAttestation(
            envelope,
            abi.encode(verifier.validatorSetId(), signatures),
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.ValidatorNotActive.selector, vm.addr(OUTSIDER_KEY)
            )
        );
    }

    function testOneValidatorCannotSignTwice() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        bytes32 digest =
            verifier.attestationDigest(verifier.validatorSetId(), verifier.resultDigest(envelope));
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(validatorKeys[0], digest);
        signatures[1] = _sign(validatorKeys[0], digest);
        _expectRevertWithAttestation(
            envelope,
            abi.encode(verifier.validatorSetId(), signatures),
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.SignersNotStrictlyIncreasing.selector,
                validatorSet[0],
                validatorSet[0]
            )
        );
    }

    function testATamperedResultCommitmentIsRejected() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        bytes32 expected = envelope.resultCommitment;
        bytes memory attestation = _attest(envelope);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(envelope, SCOPE_B, CONTROLLER_B_KEY);
        PrivateMatchBinder.Counterparty memory counterparty = _source();
        envelope.resultCommitment = keccak256("something-else");

        // Consent is signed over the result commitment, so tampering breaks the
        // consent before it ever reaches the verifier.
        vm.expectRevert(
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_A)
        );
        binder.bindRecourse(
            envelope,
            attestation,
            IAnchoredReceivable(address(vault)),
            counterparty,
            consentA,
            consentB
        );
        assertTrue(expected != envelope.resultCommitment);
    }

    function testTheVerifierRecomputesTheResultCommitment() public {
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        bytes32 expected = envelope.resultCommitment;
        envelope.binder = address(this);
        envelope.resultCommitment = keccak256("something-else");
        bytes memory attestation = _attest(envelope);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.InvalidResultCommitment.selector,
                keccak256("something-else"),
                verifier.resultCoreCommitment(envelope)
            )
        );
        verifier.acceptMatch(envelope, attestation);
        assertTrue(expected != envelope.resultCommitment);
    }

    function testAnExpiredResultIsRejected() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        bytes memory attestation = _attest(envelope);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(envelope, SCOPE_B, CONTROLLER_B_KEY);
        PrivateMatchBinder.Counterparty memory counterparty = _source();
        // Past the result's validity but inside the consents' validity.
        uint256 later = uint256(envelope.validUntil) + 1;
        vm.warp(later);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.ResultExpired.selector, envelope.validUntil, later
            )
        );
        binder.bindRecourse(
            envelope,
            attestation,
            IAnchoredReceivable(address(vault)),
            counterparty,
            consentA,
            consentB
        );
    }

    function testAnUnauthorizedScopeIsRejected() public {
        verifier.setScopeAuthorized(SCOPE_B, false);
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        _expectRevert(
            _exactEnvelope(SESSION, 1),
            abi.encodeWithSelector(ECDSAQuorumMatchVerifierV4.ScopeNotAuthorized.selector, SCOPE_B)
        );
    }

    function testOnlyTheNamedBinderCanConsumeAResult() public {
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        bytes memory attestation = _attest(envelope);
        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.InvalidBinder.selector, address(this), address(binder)
            )
        );
        verifier.acceptMatch(envelope, attestation);
    }

    function testAnEnvelopeForAnotherBinderIsRefused() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        envelope.binder = address(0xB1);
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                PrivateMatchBinder.EnvelopeNotForThisBinder.selector, address(0xB1)
            )
        );
    }

    function testAnotherPolicyIsRefused() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        envelope.policyId = keccak256("other-policy");
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                PrivateMatchBinder.UnexpectedPolicy.selector,
                keccak256("other-policy"),
                POLICY_VERSION
            )
        );
    }

    /// @dev The quorum is checked last, so a valid result survives a failed
    /// binding attempt. Otherwise anyone could burn one by calling with a bad
    /// consent.
    function testAFailedBindingDoesNotBurnTheResult() public {
        _precommit(SESSION, anchorCommitment, ISSUER_KEY, issuer);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(SESSION, 1);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _source(),
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY),
            _consent(envelope, SCOPE_B, OUTSIDER_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
        assertFalse(verifier.consumedReplayKeys(verifier.replayKey(envelope)));
        assertFalse(verifier.consumedMatchCommitments(envelope.result.matchCommitment));

        // The same result then binds normally.
        _bindWith(envelope);
        assertTrue(binder.recourseOf(SESSION).open);
    }

    /* -------------------------------------------------------------- helpers */

    function _bind(bytes32 sessionId, uint256 nonce) private {
        _precommit(sessionId, anchorCommitment, ISSUER_KEY, issuer);
        _bindWith(_exactEnvelope(sessionId, nonce));
    }

    function _bindWith(ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope) private {
        binder.bindRecourse(
            envelope,
            _attest(envelope),
            IAnchoredReceivable(address(vault)),
            _source(),
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY),
            _consent(envelope, SCOPE_B, CONTROLLER_B_KEY)
        );
    }

    function _expectRevert(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        bytes memory expected
    ) private {
        _expectRevert(envelope, IAnchoredReceivable(address(vault)), expected);
    }

    function _expectRevert(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        IAnchoredReceivable anchor,
        bytes memory expected
    ) private {
        _expectRevert(envelope, anchor, _source(), expected);
    }

    function _expectRevert(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        IAnchoredReceivable anchor,
        PrivateMatchBinder.Counterparty memory counterparty,
        bytes memory expected
    ) private {
        _expectRevert(
            envelope,
            anchor,
            counterparty,
            _consent(envelope, address(anchor), SCOPE_A, CONTROLLER_A_KEY),
            _consent(envelope, address(anchor), SCOPE_B, CONTROLLER_B_KEY),
            expected
        );
    }

    function _expectRevert(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        IAnchoredReceivable anchor,
        PrivateMatchBinder.Counterparty memory counterparty,
        PrivateMatchBinder.DisclosureConsent memory consentA,
        PrivateMatchBinder.DisclosureConsent memory consentB,
        bytes memory expected
    ) private {
        bytes memory attestation = _attest(envelope);
        vm.expectRevert(expected);
        binder.bindRecourse(envelope, attestation, anchor, counterparty, consentA, consentB);
    }

    function _expectRevertWithAttestation(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        bytes memory attestation,
        bytes memory expected
    ) private {
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(envelope, SCOPE_A, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(envelope, SCOPE_B, CONTROLLER_B_KEY);
        PrivateMatchBinder.Counterparty memory counterparty = _source();
        vm.expectRevert(expected);
        binder.bindRecourse(
            envelope,
            attestation,
            IAnchoredReceivable(address(vault)),
            counterparty,
            consentA,
            consentB
        );
    }

    function _expectMockRevert(MockAnchor mock, bytes memory expected) private {
        bytes32 commitment = mock.assetCommitment();
        _precommit(SESSION, commitment, ISSUER_KEY, issuer);
        _expectRevert(
            _exactEnvelope(SESSION, 1, commitment), IAnchoredReceivable(address(mock)), expected
        );
    }

    function _source() private view returns (PrivateMatchBinder.Counterparty memory) {
        return PrivateMatchBinder.Counterparty({
            kind: PrivateMatchBinder.CounterpartyKind.RegisteredSource,
            anchorId: counterpartyAnchorId,
            vault: address(0)
        });
    }

    function _exactEnvelope(bytes32 sessionId, uint256 nonce)
        private
        view
        returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory)
    {
        return _exactEnvelope(sessionId, nonce, anchorCommitment);
    }

    function _exactEnvelope(bytes32 sessionId, uint256 nonce, bytes32 localCommitment)
        private
        view
        returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope)
    {
        envelope = ECDSAQuorumMatchVerifierV4.MatchEnvelope({
            chainId: block.chainid,
            binder: address(binder),
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            nonce: nonce,
            validUntil: uint64(block.timestamp + 1 days),
            resultCommitment: bytes32(0),
            result: Match.ConfidentialMatchResultV4({
                sessionId: sessionId,
                scopeCommitmentA: SCOPE_A,
                scopeCommitmentB: SCOPE_B,
                inputCommitmentA: localCommitment,
                inputCommitmentB: counterpartyCommitment,
                outcome: Match.Outcome.ExactMatch,
                exactMatchConfirmed: true,
                candidateMatchSuggested: false,
                candidateFallbackAuthorized: false,
                conflictConfirmed: true,
                matchCommitment: keccak256(abi.encode("match", sessionId)),
                boundCandidateAliasCommitment: bytes32(0),
                anchorCount: 2,
                providerProofCommitment: keccak256(abi.encode("provider-proof", sessionId, nonce))
            })
        });
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
    }

    function _candidateEnvelope(bytes32 sessionId, uint256 nonce)
        private
        view
        returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope)
    {
        envelope = _exactEnvelope(sessionId, nonce);
        envelope.result.outcome = Match.Outcome.ReconciliationRequired;
        envelope.result.exactMatchConfirmed = false;
        envelope.result.candidateMatchSuggested = true;
        envelope.result.candidateFallbackAuthorized = true;
        envelope.result.conflictConfirmed = false;
        envelope.result.boundCandidateAliasCommitment = keccak256("bound-alias");
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
    }

    function _attest(ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope)
        private
        view
        returns (bytes memory)
    {
        return _attestWith(envelope, 2);
    }

    function _attestWith(ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope, uint256 count)
        private
        view
        returns (bytes memory)
    {
        bytes32 setId = verifier.validatorSetId();
        bytes32 digest = verifier.attestationDigest(setId, verifier.resultDigest(envelope));
        bytes[] memory signatures = new bytes[](count);
        for (uint256 i; i < count; ++i) {
            signatures[i] = _sign(validatorKeys[i], digest);
        }
        return abi.encode(setId, signatures);
    }

    function _consent(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        bytes32 scopeCommitment,
        uint256 key
    ) private view returns (PrivateMatchBinder.DisclosureConsent memory) {
        return _consent(envelope, address(vault), scopeCommitment, key);
    }

    /// @dev Consents outlive the result envelope on purpose, so a test about an
    /// expired result is not silently answered by an expired consent.
    function _consent(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        address anchor,
        bytes32 scopeCommitment,
        uint256 key
    ) private view returns (PrivateMatchBinder.DisclosureConsent memory) {
        uint64 validUntil = uint64(block.timestamp + 5 days);
        bytes32 digest = binder.consentDigest(
            envelope.result.sessionId,
            envelope.resultCommitment,
            scopeCommitment,
            anchor,
            validUntil
        );
        return PrivateMatchBinder.DisclosureConsent({
            scopeCommitment: scopeCommitment,
            validUntil: validUntil,
            signature: _sign(key, digest)
        });
    }

    function _sign(uint256 key, bytes32 digest) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sortValidators() private {
        uint256[3] memory keys = validatorKeys;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) {
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
        validatorKeys = keys;
        for (uint256 i; i < 3; ++i) {
            validatorSet.push(vm.addr(keys[i]));
        }
    }

    function _precommit(bytes32 sessionId, bytes32 commitment, uint256 key, address signer) private {
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment memory precommitment =
        MordantSessionPrecommitRegistry.ExactSessionPrecommitment({
            chainId: block.chainid,
            registry: address(precommits),
            sessionId: sessionId,
            strictAssetCommitment: commitment,
            equivalenceOf: bytes32(0),
            supersedesCandidateSession: bytes32(0),
            issuerKeyId: registry.issuerKeyIdFor(signer),
            identityEpoch: EPOCH,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: precommitNonce++
        });
        precommits.precommitExactSession(
            precommitment, _sign(key, precommits.digestOf(precommitment))
        );
    }

    function _registerSource(bytes32 commitment, uint256 nonce) private returns (bytes32) {
        MordantSourceAttestation.SourceAssetAttestation memory attestation = MordantSourceAttestation
            .SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(sources),
            creationDigest: keccak256(abi.encode("source-creation", nonce)),
            assetCommitment: commitment,
            initialTermsCommitment: keccak256(abi.encode("source-terms", nonce)),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(otherIssuer),
            invoiceRoot: keccak256(abi.encode("source-root", nonce)),
            controller: otherIssuer,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: nonce
        });
        return sources.register(
            attestation,
            _sign(OTHER_ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(sources)))
        );
    }

    /* --------------------------------------------------------- vault set-up */

    function _stableId(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (bytes32)
    {
        return Id.strictStableAssetId(_identity(invoiceNumber, issueDateDays));
    }

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

    function _config(bytes32 root, address cvaAdapter)
        private
        view
        returns (MordantFactoryV2.InvoiceConfig memory)
    {
        return MordantFactoryV2.InvoiceConfig({
            cvaAdapter: cvaAdapter,
            settlementToken: address(settlement),
            invoiceRoot: root,
            currency: CURRENCY,
            buyer: buyer,
            originatorTreasury: originator,
            initialOriginatorSigner: originator,
            initialUnits: UNITS,
            advanceAmount: ADVANCE,
            faceValue: FACE,
            bondBps: 1_000,
            protectionEnd: protectionEnd,
            revealPeriod: 1 hours,
            curePeriod: 1 hours
        });
    }

    function _createVault(bytes32 root, uint256 nonce) private returns (MordantInvoiceVaultV2) {
        // The factory binds one CVA token to one root, so each anchor gets its own.
        MockERC20 token = new MockERC20("Invoice A-Token", "aINV", 6);
        MockCvaAdapter adapter = new MockCvaAdapter(token);
        factory.setCvaAdapter(address(adapter), true);

        MordantFactoryV2.InvoiceConfig memory config = _config(root, address(adapter));
        bytes32 commitment = Id.assetCommitment(
            stableId, 3, EPOCH, Id.deriveSalt(keccak256("issuer-master"), stableId, EPOCH, nonce)
        );
        MordantSourceAttestation.SourceAssetAttestation memory attestation = MordantSourceAttestation
            .SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(factory),
            creationDigest: factory.creationDigest(config),
            assetCommitment: commitment,
            initialTermsCommitment: keccak256(abi.encode("terms", root)),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            invoiceRoot: root,
            controller: originator,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: nonce
        });
        bytes memory signature =
            _sign(ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(factory)));
        vm.prank(buyer);
        MordantInvoiceVaultV2 created =
            factory.createIdentityAnchoredVault(config, attestation, signature);
        eligibility.setIdentityValid(address(created), true);
        adapterOf[address(created)] = adapter;
        cvaOf[address(created)] = token;
        return created;
    }

    /// @dev Brings a vault to Outstanding with funded protection through its own
    /// activation path. Nothing here is a shortcut around the vault's rules.
    function _activate(MordantInvoiceVaultV2 target) private {
        MockCvaAdapter adapter = adapterOf[address(target)];
        MockERC20 token = cvaOf[address(target)];
        token.mint(address(this), UNITS);
        token.approve(address(adapter), UNITS);
        adapter.creditVault(address(target), UNITS);

        settlement.mint(holder, ADVANCE);
        vm.prank(holder);
        settlement.approve(address(target), type(uint256).max);

        MordantInvoiceVault.Pledge memory pledge = MordantInvoiceVault.Pledge({
            invoiceRoot: target.invoiceRoot(),
            originatorSigner: originator,
            facility: facility,
            obligationId: keccak256(abi.encode("obligation", address(target))),
            amount: FACE,
            currency: CURRENCY,
            activeFrom: uint64(block.timestamp - 1),
            activeUntil: protectionEnd + 1,
            nonce: uint256(uint160(address(target))),
            deadline: uint64(block.timestamp + 2 days),
            exclusive: true
        });
        address[] memory holders = new address[](1);
        holders[0] = holder;
        uint256[] memory allocations = new uint256[](1);
        allocations[0] = UNITS;
        // Hoisted: `hashPledge` is an external call, and a prank set before it
        // would be consumed by that call instead of by `activate`.
        bytes memory pledgeSignature = _sign(ORIGINATOR_KEY, target.hashPledge(pledge));
        vm.prank(facility);
        target.activate(pledge, pledgeSignature, holder, holders, allocations);
    }
}
