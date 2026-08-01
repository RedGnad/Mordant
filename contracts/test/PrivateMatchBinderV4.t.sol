// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, Vm } from "forge-std/Test.sol";

import { MordantFactoryV2 } from "../src/MordantFactoryV2.sol";
import { MordantInvoiceVault } from "../src/MordantInvoiceVault.sol";
import { MordantInvoiceVaultV2 } from "../src/MordantInvoiceVaultV2.sol";
import { MockCvaAdapter } from "../src/mocks/MockCvaAdapter.sol";
import { MockEligibility } from "../src/mocks/MockEligibility.sol";
import { MockERC20 } from "../src/mocks/MockERC20.sol";
import { MordantAssetIdentity as Id } from "../src/identity/MordantAssetIdentity.sol";
import { MordantIssuerRegistry } from "../src/identity/MordantIssuerRegistry.sol";
import { MordantMatchResult as Match } from "../src/identity/MordantMatchResult.sol";
import { MordantNormalization as N } from "../src/identity/MordantNormalization.sol";
import { MordantSourceAttestation } from "../src/identity/MordantSourceAttestation.sol";
import { MordantSourceIdentityRegistry } from "../src/identity/MordantSourceIdentityRegistry.sol";
import { ECDSAQuorumMatchVerifierV4 } from "../src/v4/ECDSAQuorumMatchVerifierV4.sol";
import { IAnchoredReceivable } from "../src/v4/IAnchoredReceivable.sol";
import {
    MordantScopeGovernanceRegistry as Governance
} from "../src/v4/MordantScopeGovernanceRegistry.sol";
import { PrivateMatchBinder } from "../src/v4/PrivateMatchBinder.sol";

/// @notice Settable identity anchor, for the anchor-state negatives a real vault
/// can only reach through its own economic lifecycle.
contract MockAnchor is IAnchoredReceivable {
    bytes32 public assetCommitment;
    uint16 public identitySchemeVersion = 3;
    bytes32 public initialTermsCommitment = keccak256("mock-terms");
    uint16 public termsSchemeVersion = 1;
    uint32 public identityEpoch = 1;
    bytes32 public issuerKeyId;
    bytes32 public sourceAttestationDigest;
    uint8 public receivableState = 1;
    uint8 public protectionState = 1;
    uint256 public totalSupply = 100e6;

    constructor(bytes32 commitment, bytes32 issuer, bytes32 attestation) {
        assetCommitment = commitment;
        issuerKeyId = issuer;
        sourceAttestationDigest = attestation;
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
    uint256 private constant NEW_CONTROLLER_A_KEY = 0xC0A2;
    uint256 private constant OUTSIDER_KEY = 0x0175;

    bytes32 private constant POLICY_ID = keccak256("mordant.double-financing/1");
    uint32 private constant POLICY_VERSION = 1;
    bytes32 private constant SCOPE_A = keccak256("scope-platform-a");
    bytes32 private constant SCOPE_B = keccak256("scope-platform-b");
    bytes32 private constant ORG_A = keccak256("org-platform-a");
    bytes32 private constant ORG_B = keccak256("org-platform-b");
    bytes32 private constant KEY_A = keccak256("controller-key-a");
    bytes32 private constant KEY_B = keccak256("controller-key-b");
    uint64 private constant CURE_PERIOD = 7 days;

    address private issuer;
    address private otherIssuer;
    address private buyer;
    address private originator;
    address private facility;
    address private holder;
    address private controllerA;
    address private controllerB;
    address private newControllerA;
    address private relayer = address(0xBEEF);

    uint256[3] private validatorKeys;
    address[] private validatorSet;

    MockEligibility private eligibility;
    MockERC20 private settlement;
    MordantIssuerRegistry private registry;
    MordantFactoryV2 private factory;
    MordantSourceIdentityRegistry private sources;
    Governance private governance;
    ECDSAQuorumMatchVerifierV4 private verifier;
    PrivateMatchBinder private binder;

    MordantInvoiceVaultV2 private vault;
    bytes32 private anchorCommitment;
    bytes32 private anchorSourceRecord;
    bytes32 private counterpartyCommitment;
    bytes32 private counterpartyAnchorId;

    bytes32 private recordA;
    bytes32 private recordB;
    uint32 private versionA = 1;
    uint32 private versionB = 1;
    uint256 private governanceNonce = 1;

    /// @dev The session under construction. Kept in storage so a test can mutate
    /// one field of a 24-field intent without drowning in stack slots.
    Governance.BilateralSessionIntent private intent;
    bytes32 private salt;
    bytes32 private commitmentKey;

    mapping(address anchor => MockCvaAdapter) private adapterOf;
    mapping(address anchor => MockERC20) private cvaOf;

    bytes32 private stableId;
    uint64 private protectionEnd;

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
        newControllerA = vm.addr(NEW_CONTROLLER_A_KEY);

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

        stableId = _stableId("INV-2026-0042", 20_500);
        protectionEnd = uint64(block.timestamp + 30 days);

        governance = new Governance(address(this));
        governance.setAuthorizedRelayer(relayer, true);
        recordA = _authorize(SCOPE_A, controllerA, KEY_A, ORG_A, 1, versionA);
        recordB = _authorize(SCOPE_B, controllerB, KEY_B, ORG_B, 1, versionB);

        validatorKeys = [uint256(0xA11), uint256(0xB22), uint256(0xC33)];
        _sortValidators();
        verifier = new ECDSAQuorumMatchVerifierV4(address(this), governance, validatorSet, 2);
        verifier.setPolicyVersion(POLICY_ID, POLICY_VERSION);

        binder = _deployBinder();

        vault = _createVault(keccak256("root-local"), 1);
        anchorCommitment = vault.assetCommitment();
        anchorSourceRecord = vault.sourceAttestationDigest();
        _activate(vault);

        counterpartyCommitment = keccak256("counterparty-salted-commitment");
        counterpartyAnchorId = _registerSource(counterpartyCommitment, 900);
    }

    /* ------------------------------------------------------------ happy path */

    function testBindsConfirmedConflictToItsAnchor() public {
        bytes32 key = _bind(1);

        PrivateMatchBinder.RecourseRecord memory record = binder.recourseOf(key);
        assertEq(record.sessionCommitment, key);
        assertEq(record.matchCommitment, keccak256(abi.encode("match", key)));
        assertEq(record.anchorCommitment, anchorCommitment);
        assertEq(record.counterpartyCommitment, counterpartyCommitment);
        assertEq(record.anchor, address(vault));
        assertEq(record.policyId, POLICY_ID);
        assertTrue(record.conflictConfirmed);
        assertEq(record.cureDeadline, uint64(block.timestamp) + CURE_PERIOD);
        assertTrue(record.open);
        assertTrue(binder.anchorLive(key));
    }

    function testBindingIsNonEconomicAndTouchesNothingOnTheAnchor() public {
        uint256 supplyBefore = vault.totalSupply();
        uint256 settlementBefore = settlement.balanceOf(address(vault));
        uint8 protectionBefore = uint8(vault.protectionState());

        _bind(1);

        assertEq(vault.totalSupply(), supplyBefore);
        assertEq(settlement.balanceOf(address(vault)), settlementBefore);
        assertEq(uint8(vault.protectionState()), protectionBefore);
        assertEq(vault.balanceOf(address(binder)), 0);
        assertEq(settlement.balanceOf(address(binder)), 0);
    }

    function testNoAssetIdentifierIsWrittenToChain() public {
        bytes32 key = _bind(1);
        PrivateMatchBinder.RecourseRecord memory record = binder.recourseOf(key);
        assertTrue(record.anchorCommitment != stableId);
        assertTrue(record.counterpartyCommitment != stableId);
        assertTrue(record.matchCommitment != stableId);
        assertTrue(record.anchorCommitment != record.counterpartyCommitment);
    }

    /* -------------------------------------------------- pre-binding privacy */

    /// @dev The central privacy property: committing a session must publish one
    /// opaque hash and nothing that identifies either side.
    function testCommittingASessionPublishesNothingIdentifying() public {
        _prepareIntent(1);
        bytes32 key = governance.sessionCommitmentOf(intent, _signatures(), salt);

        vm.recordLogs();
        vm.prank(relayer);
        governance.commitSession(key);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1, "a commitment is exactly one event");
        assertEq(logs[0].topics.length, 2);
        assertEq(logs[0].topics[1], key);

        bytes32[] memory forbidden = _forbiddenValues();
        for (uint256 i; i < logs.length; ++i) {
            for (uint256 t; t < logs[i].topics.length; ++t) {
                _assertNotForbidden(logs[i].topics[t], forbidden);
            }
            bytes memory data = logs[i].data;
            for (uint256 offset; offset + 32 <= data.length; offset += 32) {
                bytes32 word;
                assembly {
                    word := mload(add(add(data, 0x20), offset))
                }
                _assertNotForbidden(word, forbidden);
            }
        }
    }

    /// @dev A session that is committed and never bound must stay unlinkable.
    /// The only residue is the hash itself and the fact that some comparison
    /// happened, which does not distinguish a negative result from a declined
    /// disclosure.
    function testAnUnboundSessionLeavesNoResolvablePairing() public {
        _prepareIntent(1);
        bytes32 key = _commit();

        // Nothing on-chain maps the commitment to a party, a scope or an anchor.
        Governance.SessionCommitment memory stored = governance.commitment(key);
        assertTrue(stored.exists);
        assertEq(stored.submitter, relayer);
        assertFalse(stored.consumed);
        assertEq(governance.committedAt(key), uint64(block.timestamp));
        // No recourse record, so no anchor, no commitments, no pairing.
        assertFalse(binder.recourseOf(key).open);
        assertEq(binder.recourseOf(key).anchor, address(0));
        assertEq(binder.recourseOf(key).anchorCommitment, bytes32(0));
        // And the whole storage slot set of the commitment holds no record digest.
        assertTrue(bytes32(uint256(uint160(stored.submitter))) != recordA);
        assertTrue(bytes32(uint256(uint160(stored.submitter))) != recordB);
    }

    function testAParticipantCannotPostTheCommitment() public {
        _prepareIntent(1);
        bytes32 key = governance.sessionCommitmentOf(intent, _signatures(), salt);
        vm.prank(controllerA);
        vm.expectRevert(
            abi.encodeWithSelector(Governance.RelayerNotAuthorized.selector, controllerA)
        );
        governance.commitSession(key);
    }

    function testAnAllowlistedSubmitterThatIsAParticipantIsCaughtAtReveal() public {
        // The allowlist is not proof of neutrality. If the relayer turns out to
        // be one of the two controllers, the session cannot be opened.
        governance.setAuthorizedRelayer(controllerB, true);
        _prepareIntent(1);
        bytes32 key = governance.sessionCommitmentOf(intent, _signatures(), salt);
        vm.prank(controllerB);
        governance.commitSession(key);
        commitmentKey = key;

        _expectRevert(
            _exactEnvelope(key, 1),
            abi.encodeWithSelector(Governance.RelayerIsController.selector, controllerB)
        );
    }

    /* ---------------------------------------------------- mutual initiation */

    function testAUnilateralIntentCannotBeOpened() public {
        // Side A signs twice and commits that bundle. B never agreed to the
        // comparison at all, so the session cannot be opened even though the
        // commitment is internally consistent.
        _prepareIntent(1);
        Governance.InitiationSignatures memory unilateral =
            _signaturesWith(CONTROLLER_A_KEY, CONTROLLER_A_KEY, ISSUER_KEY);
        bytes32 key = _commitWith(unilateral);
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(unilateral),
            abi.encodeWithSelector(Governance.IntentNotBilateral.selector, controllerB, controllerA)
        );
    }

    function testAnOutsiderSignatureIsNotInitiation() public {
        _prepareIntent(1);
        Governance.InitiationSignatures memory forged =
            _signaturesWith(CONTROLLER_A_KEY, OUTSIDER_KEY, ISSUER_KEY);
        bytes32 key = _commitWith(forged);
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(forged),
            abi.encodeWithSelector(
                Governance.IntentNotBilateral.selector, controllerB, vm.addr(OUTSIDER_KEY)
            )
        );
    }

    /* ---------------------------------------------- signature bundle binding */

    /// @dev The commitment must prove that authorization existed when it was
    /// published, not merely that the intent fields did.
    function testACommitmentMadeWithoutSignaturesCannotBeOpenedLater() public {
        _prepareIntent(1);
        Governance.InitiationSignatures memory none =
            Governance.InitiationSignatures({ controllerA: "", controllerB: "", issuer: "" });
        bytes32 key = _commitWith(none);
        // Collecting the three signatures afterwards does not open it: they are
        // part of the preimage, so a different bundle is a different session.
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _reveal(),
            abi.encodeWithSelector(
                Governance.UnknownCommitment.selector,
                governance.sessionCommitmentOf(intent, _signatures(), salt)
            )
        );
    }

    function testAlternateSignatureBytesCannotOpenTheCommitment() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        // Same intent, same signer, different bytes.
        Governance.InitiationSignatures memory altered = _signatures();
        altered.controllerA = _flipV(altered.controllerA);
        assertTrue(key != governance.sessionCommitmentOf(intent, altered, salt));
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(altered),
            abi.encodeWithSelector(
                Governance.UnknownCommitment.selector,
                governance.sessionCommitmentOf(intent, altered, salt)
            )
        );
    }

    function testSwappedControllerSignaturesAreRejected() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        Governance.InitiationSignatures memory swapped = _signatures();
        (swapped.controllerA, swapped.controllerB) = (swapped.controllerB, swapped.controllerA);
        // Swapping changes the bundle, so it is not this session at all.
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(swapped),
            abi.encodeWithSelector(
                Governance.UnknownCommitment.selector,
                governance.sessionCommitmentOf(intent, swapped, salt)
            )
        );

        // And committing the swapped bundle does not help: each slot must be
        // signed by the controller that occupies it.
        _prepareIntent(2);
        Governance.InitiationSignatures memory committedSwapped = _signatures();
        (committedSwapped.controllerA, committedSwapped.controllerB) =
        (committedSwapped.controllerB, committedSwapped.controllerA);
        bytes32 second = _commitWith(committedSwapped);
        _expectRevertWithReveal(
            _exactEnvelope(second, 2),
            _revealWithSignatures(committedSwapped),
            abi.encodeWithSelector(Governance.IntentNotBilateral.selector, controllerA, controllerB)
        );
    }

    function testASuccessorControllerSignatureCannotOpenASession() public {
        // The intent names the historical record, but the bundle carries the
        // successor's signature. Authority does not transfer to a key the frozen
        // record never named.
        vm.warp(block.timestamp + 1 hours);
        _prepareIntent(1);
        Governance.InitiationSignatures memory successor =
            _signaturesWith(NEW_CONTROLLER_A_KEY, CONTROLLER_B_KEY, ISSUER_KEY);
        bytes32 key = _commitWith(successor);
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(successor),
            abi.encodeWithSelector(
                Governance.IntentNotBilateral.selector, controllerA, newControllerA
            )
        );
    }

    function testAnIssuerSignatureForAnotherIntentIsRejected() public {
        _prepareIntent(2);
        bytes32 foreignDigest = governance.intentDigest(intent);
        _prepareIntent(1);
        Governance.InitiationSignatures memory mismatched = _signatures();
        mismatched.issuer = _sign(ISSUER_KEY, foreignDigest);
        bytes32 key = _commitWith(mismatched);
        // The bundle is committed, both controllers are genuine, but the issuer
        // authorized a different session, so it recovers to an unknown key.
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(mismatched),
            abi.encodeWithSelector(MordantIssuerRegistry.InvalidIssuer.selector)
        );
    }

    function testANonCanonicalSignatureIsRejected() public {
        _prepareIntent(1);
        Governance.InitiationSignatures memory malleable = _signatures();
        malleable.controllerA = _malleate(malleable.controllerA);
        bytes32 key = _commitWith(malleable);
        // The malleated signature recovers the same address, so only the
        // canonical-encoding rule stops it.
        _expectRevertWithReveal(
            _exactEnvelope(key, 1),
            _revealWithSignatures(malleable),
            abi.encodeWithSelector(Governance.MalformedSignature.selector)
        );
    }

    function testEachSignatureIsBoundIntoTheCommitment() public {
        _prepareIntent(1);
        bytes32 base = governance.sessionCommitmentOf(intent, _signatures(), salt);
        Governance.InitiationSignatures memory changedA = _signatures();
        changedA.controllerA = _sign(NEW_CONTROLLER_A_KEY, governance.intentDigest(intent));
        Governance.InitiationSignatures memory changedB = _signatures();
        changedB.controllerB = _sign(OUTSIDER_KEY, governance.intentDigest(intent));
        Governance.InitiationSignatures memory changedIssuer = _signatures();
        changedIssuer.issuer = _sign(OTHER_ISSUER_KEY, governance.intentDigest(intent));

        assertTrue(governance.sessionCommitmentOf(intent, changedA, salt) != base);
        assertTrue(governance.sessionCommitmentOf(intent, changedB, salt) != base);
        assertTrue(governance.sessionCommitmentOf(intent, changedIssuer, salt) != base);
        // And the salt still separates two sessions with identical authorization.
        salt = keccak256("another-salt");
        assertTrue(governance.sessionCommitmentOf(intent, _signatures(), salt) != base);
    }

    function testAllThreeHistoricalSignaturesRevealSuccessfully() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        bytes32 frozen = recordA;
        // The controllers are replaced after commitment. The bundle that opened
        // this session is the historical one, and it still opens it.
        vm.warp(block.timestamp + 1 hours);
        _rotateScopeA(newControllerA);

        _bindWith(envelope, frozen, recordB, CONTROLLER_A_KEY, CONTROLLER_B_KEY);
        assertTrue(binder.recourseOf(key).open);
        assertTrue(governance.commitment(key).consumed);
    }

    function testAnUncommittedIntentIsUnusable() public {
        // A perfectly signed intent that was never committed is not a session.
        _prepareIntent(1);
        bytes32 key = governance.sessionCommitmentOf(intent, _signatures(), salt);
        _expectRevert(
            _exactEnvelope(key, 1),
            abi.encodeWithSelector(Governance.UnknownCommitment.selector, key)
        );
    }

    /* ------------------------------------------------- commitment integrity */

    function testAChangedParticipantPairDoesNotOpenTheCommitment() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        // Swap in a third party after the fact.
        bytes32 replacement = _authorize(
            keccak256("scope-platform-c"), newControllerA, KEY_A, keccak256("org-c"), 1, 1
        );
        intent.governanceRecordB = replacement;
        _expectMutatedIntentRejected(key);
    }

    function testAChangedGovernanceRecordDoesNotOpenTheCommitment() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        _rotateScopeA(controllerA);
        intent.governanceRecordA = recordA;
        intent.scopeAuthorizationVersionA = versionA;
        intent.controllerEpochA = versionA;
        _expectMutatedIntentRejected(key);
    }

    function testAChangedCandidateAuthorizationDoesNotOpenTheCommitment() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        // The parties agreed to an exact-only session. Claiming otherwise at
        // reveal produces a different commitment.
        intent.candidateAuthorized = true;
        _expectMutatedIntentRejected(key);
    }

    function testAChangedBudgetDoesNotOpenTheCommitment() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        intent.exactBudget = 99;
        _expectMutatedIntentRejected(key);
    }

    function testAnIntentRecordFieldMustMatchItsRecord() public {
        // The intent asserts the controller epoch and authorization version. If
        // they disagree with the record they name, the session is incoherent even
        // though the commitment recomputes.
        _prepareIntent(1);
        intent.controllerEpochA = 7;
        bytes32 key = _commit();
        _expectRevert(
            _exactEnvelope(key, 1),
            abi.encodeWithSelector(Governance.IntentRecordMismatch.selector, recordA)
        );
    }

    function testACommitmentIsSingleUseAcrossResults() public {
        bytes32 key = _bind(1);
        // A second, independent binder cannot reopen the same commitment: the
        // one-time rule lives in the registry, not in one binder's bookkeeping.
        PrivateMatchBinder second = _deployBinder();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 2);
        envelope.binder = address(second);
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);

        PrivateMatchBinder.SessionReveal memory reveal = _reveal();
        bytes memory attestation = _attest(envelope);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(second, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(second, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY);
        vm.expectRevert(abi.encodeWithSelector(Governance.CommitmentConsumed.selector, key));
        second.bindRecourse(
            envelope, attestation, reveal, IAnchoredReceivable(address(vault)), consentA, consentB
        );
    }

    function testAResultBoundToAnotherCommitmentIsRefused() public {
        _prepareIntent(1);
        bytes32 first = _commit();
        // A second, genuine session.
        _prepareIntent(2);
        bytes32 second = _commit();

        // The envelope names the second commitment; the reveal opens the first.
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(second, 1);
        _prepareIntent(1);
        PrivateMatchBinder.SessionReveal memory reveal = _reveal();
        _expectRevertWithReveal(
            envelope,
            reveal,
            abi.encodeWithSelector(PrivateMatchBinder.RevealNotForEnvelope.selector, first, second)
        );
    }

    function testAResultMustNameItsOwnCommitmentAsItsSession() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        envelope.result.sessionId = keccak256("some-other-session");
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.ResultNotBoundToCommitment.selector,
                keccak256("some-other-session"),
                key
            )
        );
    }

    function testTheVerifierRefusesAResultWithNoCommitment() public {
        _prepareIntent(1);
        bytes32 key = governance.sessionCommitmentOf(intent, _signatures(), salt);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        envelope.binder = address(this);
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        bytes memory attestation = _attest(envelope);
        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.UnknownSessionCommitment.selector, key
            )
        );
        verifier.acceptMatch(envelope, attestation);
    }

    function testOnlyAnAuthorizedBinderMayReveal() public {
        _prepareIntent(1);
        _commit();
        PrivateMatchBinder.SessionReveal memory reveal = _reveal();
        vm.expectRevert(abi.encodeWithSelector(Governance.Unauthorized.selector, address(this)));
        governance.resolveSession(reveal.intent, reveal.salt, reveal.signatures);
    }

    /* ------------------------------------------- rotation and revocation */

    function testNormalRotationDuringAPendingSessionDoesNotBreakIt() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        bytes32 frozen = recordA;
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);

        // An orderly handover happens while the comparison is in flight.
        vm.warp(block.timestamp + 1 hours);
        _rotateScopeA(newControllerA);
        assertTrue(recordA != frozen);

        // The session still binds under the authority it was committed with.
        _bindWith(envelope, frozen, recordB, CONTROLLER_A_KEY, CONTROLLER_B_KEY);
        assertTrue(binder.recourseOf(key).open);
    }

    function testTheNewControllerCannotConsentForAPendingSession() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        bytes32 frozen = recordA;
        vm.warp(block.timestamp + 1 hours);
        _rotateScopeA(newControllerA);

        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, NEW_CONTROLLER_A_KEY),
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY),
            abi.encodeWithSelector(
                PrivateMatchBinder.ConsentRecordNotFrozenForSession.selector, SCOPE_A, recordA
            )
        );
        assertTrue(frozen != recordA);
    }

    function testEmergencyRevocationBeforeConsentBlocksBinding() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        bytes32 frozen = recordA;
        governance.emergencyRevoke(frozen);

        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                Governance.ControllerEmergencyRevoked.selector,
                frozen,
                governance.record(frozen).hardRevokedAt
            )
        );
    }

    function testEmergencyRevocationAfterConsentButBeforeBindingBlocksBinding() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        bytes32 frozen = recordA;
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);

        // The consents are signed while the key is still good.
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(binder, envelope, address(vault), SCOPE_A, frozen, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY);

        // The compromise is discovered before anyone binds.
        vm.warp(block.timestamp + 1 hours);
        governance.emergencyRevoke(frozen);

        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            consentA,
            consentB,
            abi.encodeWithSelector(
                Governance.ControllerEmergencyRevoked.selector,
                frozen,
                governance.record(frozen).hardRevokedAt
            )
        );
    }

    function testANewSessionUnderReplacementControllersBinds() public {
        // The pending session is killed by the compromise.
        _prepareIntent(1);
        bytes32 dead = _commit();
        governance.emergencyRevoke(recordA);
        _expectRevert(
            _exactEnvelope(dead, 1),
            abi.encodeWithSelector(
                Governance.ControllerEmergencyRevoked.selector,
                recordA,
                governance.record(recordA).hardRevokedAt
            )
        );

        // The parties appoint a replacement and run a fresh session under it.
        vm.warp(block.timestamp + 1 hours);
        versionA += 1;
        recordA = _authorize(SCOPE_A, newControllerA, KEY_A, ORG_A, versionA, versionA);
        _prepareIntent(2);
        bytes32 fresh =
            _commitWith(_signaturesWith(NEW_CONTROLLER_A_KEY, CONTROLLER_B_KEY, ISSUER_KEY));
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(fresh, 2);
        _bindWith(envelope, recordA, recordB, NEW_CONTROLLER_A_KEY, CONTROLLER_B_KEY);
        assertTrue(binder.recourseOf(fresh).open);
    }

    function testEmergencyRevocationIsTerminalAndDistinctFromRetirement() public {
        bytes32 target = recordA;
        governance.emergencyRevoke(target);
        Governance.ScopeAuthorization memory record = governance.record(target);
        assertEq(record.hardRevokedAt, uint64(block.timestamp));
        // Revocation also closes the normal window, so it cannot be used to open
        // a new session either.
        assertEq(record.retiredAt, uint64(block.timestamp));
        vm.expectRevert(abi.encodeWithSelector(Governance.AlreadyHardRevoked.selector, target));
        governance.emergencyRevoke(target);
    }

    function testRetirementAloneDoesNotHardRevoke() public {
        bytes32 target = recordA;
        governance.retire(target);
        assertEq(governance.record(target).hardRevokedAt, 0);
        assertEq(governance.record(target).retiredAt, uint64(block.timestamp));
    }

    /* ------------------------------------------------------- authorization */

    function testAuthorizationCannotBeBackDated() public {
        uint64 before = uint64(block.timestamp);
        vm.warp(before + 1 days);
        bytes32 fresh =
            _authorize(keccak256("scope-late"), controllerA, KEY_A, keccak256("org-late"), 1, 1);
        Governance.ScopeAuthorization memory record = governance.record(fresh);
        assertEq(record.validFrom, uint64(block.timestamp));
        assertTrue(record.validFrom > before);
        assertFalse(governance.isLiveAt(fresh, before));
    }

    function testAnAuthorizationCreatedAfterTheCommitmentCannotGovernIt() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        // A record authorized after the commitment, then named in a new intent.
        vm.warp(block.timestamp + 1 hours);
        versionA += 1;
        recordA = _authorize(SCOPE_A, controllerA, KEY_A, ORG_A, versionA, versionA);
        _prepareIntent(1);
        bytes32 later = governance.sessionCommitmentOf(intent, _signatures(), salt);
        assertTrue(later != key);
        // It is simply a different, uncommitted session.
        _expectRevert(
            _exactEnvelope(later, 1),
            abi.encodeWithSelector(Governance.UnknownCommitment.selector, later)
        );
    }

    function testAuthorizationVersionsMustBeSequential() public {
        Governance.AuthorizationRequest memory request = Governance.AuthorizationRequest({
            scopeCommitment: SCOPE_A,
            controller: newControllerA,
            controllerKeyId: KEY_A,
            organizationId: ORG_A,
            controllerEpoch: 9,
            authorizationVersion: 7,
            nonce: governanceNonce++
        });
        vm.expectRevert(abi.encodeWithSelector(Governance.VersionNotSequential.selector, 7, 2));
        governance.authorize(request);
    }

    function testRotationIsAppendOnlyAndNonRetroactive() public {
        bytes32 first = recordA;
        uint64 at = uint64(block.timestamp);
        vm.warp(block.timestamp + 1 days);
        _rotateScopeA(newControllerA);

        Governance.ScopeAuthorization memory historical = governance.record(first);
        assertEq(historical.controller, controllerA);
        assertEq(historical.authorizationVersion, 1);
        assertTrue(governance.isLiveAt(first, at));
        assertEq(governance.record(recordA).authorizationVersion, 2);
        assertEq(governance.latestVersion(SCOPE_A), 2);
        assertEq(governance.versionRecord(SCOPE_A, 1), first);
    }

    function testTwoScopesOfOneOrganizationCannotFormASession() public {
        bytes32 sibling = _authorize(keccak256("scope-sibling"), controllerB, KEY_A, ORG_A, 1, 1);
        _prepareIntent(1);
        intent.governanceRecordB = sibling;
        intent.controllerKeyIdB = KEY_A;
        bytes32 key = _commit();
        _expectRevert(
            _exactEnvelope(key, 1),
            abi.encodeWithSelector(Governance.SameOrganization.selector, ORG_A)
        );
    }

    function testOnlyTheGovernorAuthorizes() public {
        Governance.AuthorizationRequest memory request = Governance.AuthorizationRequest({
            scopeCommitment: keccak256("scope-x"),
            controller: controllerA,
            controllerKeyId: KEY_A,
            organizationId: keccak256("org-x"),
            controllerEpoch: 1,
            authorizationVersion: 1,
            nonce: governanceNonce++
        });
        vm.prank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(Governance.Unauthorized.selector, address(0xBAD)));
        governance.authorize(request);
    }

    /* -------------------------------------------------- pre-session anchoring */

    function testACounterpartyRegisteredAfterTheCommitmentIsRefused() public {
        // A source-identity anchor id is its attestation digest, which is
        // computable before the anchor is registered. So the interesting attack
        // is to name a counterparty in the intent, commit, and only then bring
        // the counterparty into existence.
        bytes32 lateCommitment = keccak256("late-counterparty-commitment");
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _sourceAttestation(lateCommitment, 950);
        bytes32 lateAnchorId = MordantSourceAttestation.digest(attestation, address(sources));

        _prepareIntent(2);
        intent.sourceRecordB = lateAnchorId;
        bytes32 key = _commit();
        uint64 at = governance.committedAt(key);

        vm.warp(block.timestamp + 1 hours);
        assertEq(_registerAttestation(attestation), lateAnchorId);
        uint64 registeredAt = sources.anchor(lateAnchorId).registeredAt;
        assertTrue(registeredAt > at);

        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 2);
        envelope.result.inputCommitmentB = lateCommitment;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);

        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                PrivateMatchBinder.CounterpartyRegisteredAfterCommitment.selector, registeredAt, at
            )
        );
    }

    function testAnAnchorNotPreAuthorizedByTheIssuerIsRefused() public {
        MordantInvoiceVaultV2 other = _createVault(keccak256("root-other"), 2);
        _activate(other);
        _prepareIntent(1);
        bytes32 key = _commit();
        // The issuer signed for this session's anchor, not that one.
        _expectRevert(
            _exactEnvelope(key, 1),
            IAnchoredReceivable(address(other)),
            abi.encodeWithSelector(
                PrivateMatchBinder.AnchorNotPreAuthorized.selector,
                other.assetCommitment(),
                anchorCommitment
            )
        );
    }

    function testAnUnauthorizedIssuerCannotPreAuthorizeAnAnchor() public {
        _prepareIntent(1);
        intent.issuerKeyId = registry.issuerKeyIdFor(otherIssuer);
        bytes32 key = _commit();
        // The intent claims one issuer key; the signature is the real issuer's.
        _expectRevert(
            _exactEnvelope(key, 1),
            abi.encodeWithSelector(MordantIssuerRegistry.InvalidIssuer.selector)
        );
    }

    function testCounterpartyAnchorMustCarryTheCommitmentInTheSession() public {
        bytes32 unrelated = _registerSource(keccak256("unrelated-commitment"), 901);
        _prepareIntent(1);
        intent.sourceRecordB = unrelated;
        bytes32 key = _commit();
        _expectRevert(
            _exactEnvelope(key, 1),
            abi.encodeWithSelector(
                PrivateMatchBinder.CounterpartyCommitmentMismatch.selector,
                keccak256("unrelated-commitment"),
                counterpartyCommitment
            )
        );
    }

    /* --------------------------------------------------------- substitution */

    function testAnAnchorCannotBeMatchedAgainstItself() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        envelope.result.inputCommitmentB = envelope.result.inputCommitmentA;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(PrivateMatchBinder.SelfMatch.selector, anchorCommitment)
        );
    }

    /* --------------------------------------------------------------- replay */

    function testTheSameSessionCannotBindTwice() public {
        bytes32 key = _bind(1);
        _expectRevert(
            _exactEnvelope(key, 2),
            abi.encodeWithSelector(PrivateMatchBinder.SessionAlreadyBound.selector, key)
        );
    }

    function testTheSameNonceCannotBeReplayed() public {
        _bind(1);
        _prepareIntent(2);
        bytes32 second = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(second, 1);
        _expectRevert(
            envelope,
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.ReplayAlreadyConsumed.selector,
                verifier.replayKey(envelope)
            )
        );
    }

    function testTheSameInputPairIsDecidedOnce() public {
        bytes32 first = _bind(1);
        _prepareIntent(2);
        bytes32 second = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(second, 3);
        envelope.result.inputCommitmentA = counterpartyCommitment;
        envelope.result.inputCommitmentB = anchorCommitment;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        assertTrue(first != second);
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
        _prepareIntent(1);
        bytes32 key = _commit();
        _expectRevert(
            _candidateEnvelope(key, 1),
            abi.encodeWithSelector(Match.CandidateSessionCannotBind.selector, key)
        );
    }

    function testANoMatchResultCannotBind() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        envelope.result.outcome = Match.Outcome.NoMatchForSubmittedIdentities;
        envelope.result.exactMatchConfirmed = false;
        envelope.result.conflictConfirmed = false;
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(envelope, abi.encodeWithSelector(Match.CandidateResultNotBindable.selector));
    }

    function testANotComparableResultCannotBind() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        envelope.result.outcome = Match.Outcome.NotComparable;
        envelope.result.exactMatchConfirmed = false;
        envelope.result.conflictConfirmed = false;
        envelope.result.providerProofCommitment = bytes32(0);
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
        _expectRevert(envelope, abi.encodeWithSelector(Match.CandidateResultNotBindable.selector));
    }

    /* ----------------------------------------------------- anchor negatives */

    function testAnUnactivatedReceivableCannotCarryRecourse() public {
        MordantInvoiceVaultV2 idle = _createVault(keccak256("root-idle"), 3);
        _prepareIntent(1);
        intent.strictAssetCommitmentA = idle.assetCommitment();
        intent.sourceRecordA = idle.sourceAttestationDigest();
        bytes32 key = _commit();
        _expectRevert(
            _exactEnvelope(key, 1, idle.assetCommitment()),
            IAnchoredReceivable(address(idle)),
            abi.encodeWithSelector(PrivateMatchBinder.AnchorNotOutstanding.selector, 0)
        );
    }

    function testInactiveProtectionBlocksBinding() public {
        MockAnchor mock = _mock();
        mock.setProtectionState(0);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorProtectionInactive.selector, 0)
        );
    }

    function testARedeemedReceivableBlocksBinding() public {
        MockAnchor mock = _mock();
        mock.setReceivableState(2);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorNotOutstanding.selector, 2)
        );
    }

    function testAnAnchorWithNoUnitsBlocksBinding() public {
        MockAnchor mock = _mock();
        mock.setTotalSupply(0);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorHasNoUnits.selector)
        );
    }

    function testAnotherIdentitySchemeBlocksBinding() public {
        MockAnchor mock = _mock();
        mock.setScheme(2);
        _expectMockRevert(
            mock, abi.encodeWithSelector(PrivateMatchBinder.AnchorSchemeMismatch.selector, 2, 3)
        );
    }

    function testACodelessAddressCannotBeAnAnchor() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        _expectRevert(
            _exactEnvelope(key, 1),
            IAnchoredReceivable(address(0xDEAD)),
            abi.encodeWithSelector(PrivateMatchBinder.AnchorNotDeployed.selector, address(0xDEAD))
        );
    }

    /* -------------------------------------------------------------- consent */

    function testOneSidedConsentCannotPublishAConflict() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY),
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_A_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
    }

    function testConsentsCannotBeSuppliedForTheWrongScopes() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY),
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY),
            abi.encodeWithSelector(
                PrivateMatchBinder.ConsentScopeMismatch.selector, SCOPE_B, SCOPE_A
            )
        );
    }

    function testConsentIsBoundToTheResultItAuthorizes() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory decoy = _exactEnvelope(key, 2);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY),
            _consent(binder, decoy, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
    }

    function testExpiredConsentIsRefused() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY);
        uint64 expiry = consentA.validUntil;
        vm.warp(expiry + 1);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            consentA,
            consentB,
            abi.encodeWithSelector(
                PrivateMatchBinder.DisclosureConsentExpired.selector, SCOPE_A, expiry
            )
        );
    }

    function testAConsentNonceIsOneShot() public {
        bytes32 key = _bind(1);
        uint256 spent = _consentNonce(key, SCOPE_A);
        assertTrue(binder.consumedConsentNonce(SCOPE_A, spent));

        _prepareIntent(2);
        bytes32 second = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(second, 2);
        PrivateMatchBinder.DisclosureConsent memory replayed = _consentWithNonce(
            binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY, spent
        );
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            replayed,
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.ConsentNonceConsumed.selector, SCOPE_A, spent)
        );
    }

    function testAnotherDisclosureVersionIsRefused() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY);
        consentA.disclosureVersion = 2;
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            consentA,
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureVersionMismatch.selector, 2, 1)
        );
    }

    /* --------------------------------------------------------------- quorum */

    function testOneValidatorIsNotAQuorum() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        _expectRevertWithAttestation(
            envelope,
            _attestWith(envelope, 1),
            abi.encodeWithSelector(ECDSAQuorumMatchVerifierV4.InsufficientSignatures.selector, 1, 2)
        );
    }

    function testAnOutsiderIsNotAValidator() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        bytes32 digest =
            verifier.attestationDigest(verifier.validatorSetId(), verifier.resultDigest(envelope));
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sign(validatorKeys[0], digest);
        signatures[1] = _sign(OUTSIDER_KEY, digest);
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
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
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

    function testAnExpiredResultIsRejected() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        PrivateMatchBinder.SessionReveal memory reveal = _reveal();
        bytes memory attestation = _attest(envelope);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY);
        uint256 later = uint256(envelope.validUntil) + 1;
        vm.warp(later);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumMatchVerifierV4.ResultExpired.selector, envelope.validUntil, later
            )
        );
        binder.bindRecourse(
            envelope, attestation, reveal, IAnchoredReceivable(address(vault)), consentA, consentB
        );
    }

    function testAnEnvelopeForAnotherBinderIsRefused() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
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
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
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
    /// binding attempt without burning the commitment either.
    function testAFailedBindingBurnsNothing() public {
        _prepareIntent(1);
        bytes32 key = _commit();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _exactEnvelope(key, 1);
        _expectRevert(
            envelope,
            IAnchoredReceivable(address(vault)),
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY),
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, OUTSIDER_KEY),
            abi.encodeWithSelector(PrivateMatchBinder.DisclosureConsentMissing.selector, SCOPE_B)
        );
        assertFalse(verifier.consumedReplayKeys(verifier.replayKey(envelope)));
        assertFalse(verifier.consumedMatchCommitments(envelope.result.matchCommitment));
        assertFalse(governance.commitment(key).consumed);

        _bindWith(envelope, recordA, recordB, CONTROLLER_A_KEY, CONTROLLER_B_KEY);
        assertTrue(binder.recourseOf(key).open);
    }

    /* -------------------------------------------------------------- helpers */

    function _deployBinder() private returns (PrivateMatchBinder deployed) {
        deployed = new PrivateMatchBinder(
            verifier,
            governance,
            registry,
            sources,
            POLICY_ID,
            POLICY_VERSION,
            keccak256("originator"),
            CURE_PERIOD,
            keccak256("recourse.notice/1")
        );
        governance.setAuthorizedBinder(address(deployed), true);
    }

    function _mock() private returns (MockAnchor) {
        return new MockAnchor(anchorCommitment, vault.issuerKeyId(), anchorSourceRecord);
    }

    /// @dev Fills the pending intent from current state. Tests mutate one field
    /// of it before committing or before revealing, depending on what they probe.
    function _prepareIntent(uint256 sessionNonce) private {
        salt = keccak256(abi.encode("session-salt", sessionNonce));
        intent = Governance.BilateralSessionIntent({
            chainId: block.chainid,
            governanceRegistry: address(governance),
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            governanceRecordA: recordA,
            governanceRecordB: recordB,
            controllerKeyIdA: KEY_A,
            controllerKeyIdB: KEY_B,
            controllerEpochA: versionA,
            controllerEpochB: versionB,
            scopeAuthorizationVersionA: versionA,
            scopeAuthorizationVersionB: versionB,
            sourceRecordA: anchorSourceRecord,
            sourceRecordB: counterpartyAnchorId,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            identityEpoch: EPOCH,
            strictAssetCommitmentA: anchorCommitment,
            supersedesCandidateSession: bytes32(0),
            candidateAuthorized: false,
            exactBudget: 1,
            candidateBudget: 0,
            sessionNonce: sessionNonce,
            expiry: uint64(block.timestamp + 10 days),
            disclosureVersion: 1
        });
    }

    /// @dev Signatures exist before the commitment does, because they are part
    /// of its preimage. The relayer is handed only the resulting 32 bytes.
    function _commit() private returns (bytes32 key) {
        key = governance.sessionCommitmentOf(intent, _signatures(), salt);
        vm.prank(relayer);
        governance.commitSession(key);
        commitmentKey = key;
    }

    function _commitWith(Governance.InitiationSignatures memory signatures)
        private
        returns (bytes32 key)
    {
        key = governance.sessionCommitmentOf(intent, signatures, salt);
        vm.prank(relayer);
        governance.commitSession(key);
        commitmentKey = key;
    }

    function _signatures() private view returns (Governance.InitiationSignatures memory) {
        return _signaturesWith(CONTROLLER_A_KEY, CONTROLLER_B_KEY, ISSUER_KEY);
    }

    function _signaturesWith(uint256 keyA, uint256 keyB, uint256 keyIssuer)
        private
        view
        returns (Governance.InitiationSignatures memory)
    {
        bytes32 digest = governance.intentDigest(intent);
        return Governance.InitiationSignatures({
            controllerA: _sign(keyA, digest),
            controllerB: _sign(keyB, digest),
            issuer: _sign(keyIssuer, digest)
        });
    }

    function _reveal() private view returns (PrivateMatchBinder.SessionReveal memory) {
        return _revealWithSignatures(_signatures());
    }

    function _revealWithSignatures(Governance.InitiationSignatures memory signatures)
        private
        view
        returns (PrivateMatchBinder.SessionReveal memory)
    {
        return PrivateMatchBinder.SessionReveal({
            intent: intent, salt: salt, signatures: signatures
        });
    }

    function _revealWith(uint256 keyA, uint256 keyB)
        private
        view
        returns (PrivateMatchBinder.SessionReveal memory)
    {
        return _revealWithSignatures(_signaturesWith(keyA, keyB, ISSUER_KEY));
    }

    function _bind(uint256 sessionNonce) private returns (bytes32 key) {
        _prepareIntent(sessionNonce);
        key = _commit();
        _bindWith(
            _exactEnvelope(key, sessionNonce), recordA, recordB, CONTROLLER_A_KEY, CONTROLLER_B_KEY
        );
    }

    function _bindWith(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        bytes32 consentRecordA,
        bytes32 consentRecordB,
        uint256 keyA,
        uint256 keyB
    ) private {
        binder.bindRecourse(
            envelope,
            _attest(envelope),
            _revealWith(keyA, keyB),
            IAnchoredReceivable(address(vault)),
            _consent(binder, envelope, address(vault), SCOPE_A, consentRecordA, keyA),
            _consent(binder, envelope, address(vault), SCOPE_B, consentRecordB, keyB)
        );
    }

    function _expectMutatedIntentRejected(bytes32 committed) private {
        bytes32 recomputed = governance.sessionCommitmentOf(intent, _signatures(), salt);
        assertTrue(recomputed != committed, "mutation must change the commitment");
        _expectRevert(
            _exactEnvelope(committed, 1),
            abi.encodeWithSelector(Governance.UnknownCommitment.selector, recomputed)
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
        _expectRevert(
            envelope,
            anchor,
            _consent(binder, envelope, address(anchor), SCOPE_A, recordA, CONTROLLER_A_KEY),
            _consent(binder, envelope, address(anchor), SCOPE_B, recordB, CONTROLLER_B_KEY),
            expected
        );
    }

    function _expectRevert(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        IAnchoredReceivable anchor,
        PrivateMatchBinder.DisclosureConsent memory consentA,
        PrivateMatchBinder.DisclosureConsent memory consentB,
        bytes memory expected
    ) private {
        bytes memory attestation = _attest(envelope);
        PrivateMatchBinder.SessionReveal memory reveal = _reveal();
        vm.expectRevert(expected);
        binder.bindRecourse(envelope, attestation, reveal, anchor, consentA, consentB);
    }

    function _expectRevertWithReveal(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        PrivateMatchBinder.SessionReveal memory reveal,
        bytes memory expected
    ) private {
        bytes memory attestation = _attest(envelope);
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY);
        vm.expectRevert(expected);
        binder.bindRecourse(
            envelope, attestation, reveal, IAnchoredReceivable(address(vault)), consentA, consentB
        );
    }

    function _expectRevertWithAttestation(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        bytes memory attestation,
        bytes memory expected
    ) private {
        PrivateMatchBinder.SessionReveal memory reveal = _reveal();
        PrivateMatchBinder.DisclosureConsent memory consentA =
            _consent(binder, envelope, address(vault), SCOPE_A, recordA, CONTROLLER_A_KEY);
        PrivateMatchBinder.DisclosureConsent memory consentB =
            _consent(binder, envelope, address(vault), SCOPE_B, recordB, CONTROLLER_B_KEY);
        vm.expectRevert(expected);
        binder.bindRecourse(
            envelope, attestation, reveal, IAnchoredReceivable(address(vault)), consentA, consentB
        );
    }

    function _expectMockRevert(MockAnchor mock, bytes memory expected) private {
        _prepareIntent(1);
        bytes32 key = _commit();
        _expectRevert(
            _exactEnvelope(key, 1, mock.assetCommitment()),
            IAnchoredReceivable(address(mock)),
            expected
        );
    }

    function _forbiddenValues() private view returns (bytes32[] memory forbidden) {
        forbidden = new bytes32[](12);
        forbidden[0] = recordA;
        forbidden[1] = recordB;
        forbidden[2] = SCOPE_A;
        forbidden[3] = SCOPE_B;
        forbidden[4] = ORG_A;
        forbidden[5] = ORG_B;
        forbidden[6] = anchorCommitment;
        forbidden[7] = counterpartyCommitment;
        forbidden[8] = bytes32(uint256(uint160(controllerA)));
        forbidden[9] = bytes32(uint256(uint160(controllerB)));
        forbidden[10] = bytes32(uint256(uint160(address(vault))));
        forbidden[11] = counterpartyAnchorId;
    }

    function _assertNotForbidden(bytes32 word, bytes32[] memory forbidden) private pure {
        for (uint256 i; i < forbidden.length; ++i) {
            require(word != forbidden[i], "pre-binding leak");
        }
    }

    /* ----------------------------------------------------------- governance */

    function _authorize(
        bytes32 scope,
        address controller,
        bytes32 controllerKeyId,
        bytes32 organizationId,
        uint32 controllerEpoch,
        uint32 version
    ) private returns (bytes32) {
        return governance.authorize(
            Governance.AuthorizationRequest({
                scopeCommitment: scope,
                controller: controller,
                controllerKeyId: controllerKeyId,
                organizationId: organizationId,
                controllerEpoch: controllerEpoch,
                authorizationVersion: version,
                nonce: governanceNonce++
            })
        );
    }

    function _rotateScopeA(address controller) private {
        bytes32 previous = recordA;
        versionA += 1;
        recordA = _authorize(SCOPE_A, controller, KEY_A, ORG_A, versionA, versionA);
        governance.retire(previous);
    }

    /* ------------------------------------------------------------- envelope */

    function _exactEnvelope(bytes32 sessionCommitment, uint256 nonce)
        private
        view
        returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory)
    {
        return _exactEnvelope(sessionCommitment, nonce, anchorCommitment);
    }

    function _exactEnvelope(bytes32 sessionCommitment, uint256 nonce, bytes32 localCommitment)
        private
        view
        returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope)
    {
        envelope = ECDSAQuorumMatchVerifierV4.MatchEnvelope({
            chainId: block.chainid,
            binder: address(binder),
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            sessionCommitment: sessionCommitment,
            nonce: nonce,
            validUntil: uint64(block.timestamp + 1 days),
            resultCommitment: bytes32(0),
            result: Match.ConfidentialMatchResultV4({
                sessionId: sessionCommitment,
                scopeCommitmentA: SCOPE_A,
                scopeCommitmentB: SCOPE_B,
                inputCommitmentA: localCommitment,
                inputCommitmentB: counterpartyCommitment,
                outcome: Match.Outcome.ExactMatch,
                exactMatchConfirmed: true,
                candidateMatchSuggested: false,
                candidateFallbackAuthorized: false,
                conflictConfirmed: true,
                matchCommitment: keccak256(abi.encode("match", sessionCommitment)),
                boundCandidateAliasCommitment: bytes32(0),
                anchorCount: 2,
                providerProofCommitment: keccak256(
                    abi.encode("provider-proof", sessionCommitment, nonce)
                )
            })
        });
        envelope.resultCommitment = verifier.resultCoreCommitment(envelope);
    }

    function _candidateEnvelope(bytes32 sessionCommitment, uint256 nonce)
        private
        view
        returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope)
    {
        envelope = _exactEnvelope(sessionCommitment, nonce);
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

    function _consentNonce(bytes32 sessionCommitment, bytes32 scope)
        private
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encode("consent-nonce", sessionCommitment, scope)));
    }

    function _consent(
        PrivateMatchBinder target,
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        address anchor,
        bytes32 scopeCommitment,
        bytes32 governanceRecord,
        uint256 key
    ) private view returns (PrivateMatchBinder.DisclosureConsent memory) {
        return _consentWithNonce(
            target,
            envelope,
            anchor,
            scopeCommitment,
            governanceRecord,
            key,
            _consentNonce(envelope.sessionCommitment, scopeCommitment)
        );
    }

    /// @dev Consents outlive the result envelope on purpose, so a test about an
    /// expired result is not silently answered by an expired consent.
    function _consentWithNonce(
        PrivateMatchBinder target,
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope,
        address anchor,
        bytes32 scopeCommitment,
        bytes32 governanceRecord,
        uint256 key,
        uint256 nonce
    ) private view returns (PrivateMatchBinder.DisclosureConsent memory consent) {
        consent = PrivateMatchBinder.DisclosureConsent({
                scopeCommitment: scopeCommitment,
                governanceRecord: governanceRecord,
                disclosureVersion: target.DISCLOSURE_VERSION(),
                validUntil: uint64(block.timestamp + 5 days),
                nonce: nonce,
                signature: ""
            });
        bytes32 digest = target.consentDigest(
            envelope.sessionCommitment,
            envelope.resultCommitment,
            envelope.result.matchCommitment,
            anchor,
            consent
        );
        consent.signature = _sign(key, digest);
    }

    /// @dev secp256k1 group order, for constructing the malleable counterpart of
    /// a canonical signature.
    uint256 private constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _malleate(bytes memory signature) private pure returns (bytes memory) {
        (bytes32 r, bytes32 s_, uint8 v) = _split(signature);
        return
            abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s_)), v == 27 ? uint8(28) : uint8(27));
    }

    function _flipV(bytes memory signature) private pure returns (bytes memory) {
        (bytes32 r, bytes32 s_, uint8 v) = _split(signature);
        return abi.encodePacked(r, s_, v == 27 ? uint8(28) : uint8(27));
    }

    function _split(bytes memory signature) private pure returns (bytes32 r, bytes32 s_, uint8 v) {
        assembly {
            r := mload(add(signature, 0x20))
            s_ := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
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

    function _registerSource(bytes32 commitment, uint256 nonce) private returns (bytes32) {
        return _registerAttestation(_sourceAttestation(commitment, nonce));
    }

    function _registerAttestation(
        MordantSourceAttestation.SourceAssetAttestation memory attestation
    ) private returns (bytes32) {
        return sources.register(
            attestation,
            _sign(OTHER_ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(sources)))
        );
    }

    function _sourceAttestation(bytes32 commitment, uint256 nonce)
        private
        view
        returns (MordantSourceAttestation.SourceAssetAttestation memory)
    {
        return MordantSourceAttestation.SourceAssetAttestation({
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
        MockERC20 token = new MockERC20("Invoice A-Token", "aINV", 6);
        MockCvaAdapter adapter = new MockCvaAdapter(token);
        factory.setCvaAdapter(address(adapter), true);

        MordantFactoryV2.InvoiceConfig memory config = _config(root, address(adapter));
        bytes32 commitment = Id.assetCommitment(
            stableId, 3, EPOCH, Id.deriveSalt(keccak256("issuer-master"), stableId, EPOCH, nonce)
        );
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            MordantSourceAttestation.SourceAssetAttestation({
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
