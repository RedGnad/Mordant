// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { MordantFactoryV2 } from "../src/MordantFactoryV2.sol";
import { MordantInvoiceVault } from "../src/MordantInvoiceVault.sol";
import { MordantInvoiceVaultV2 } from "../src/MordantInvoiceVaultV2.sol";
import { MockCvaAdapter } from "../src/mocks/MockCvaAdapter.sol";
import { MockEligibility } from "../src/mocks/MockEligibility.sol";
import { MockERC20 } from "../src/mocks/MockERC20.sol";
import { MordantAssetIdentity as Id } from "../src/identity/MordantAssetIdentity.sol";
import { MordantIssuerRegistry } from "../src/identity/MordantIssuerRegistry.sol";
import { MordantNormalization as N } from "../src/identity/MordantNormalization.sol";
import { MordantMatchResultV5 as Outcomes } from "../src/identity/MordantMatchResultV5.sol";
import { MordantSourceAttestation as Attest } from "../src/identity/MordantSourceAttestation.sol";
import { IAnchoredReceivable } from "../src/v4/IAnchoredReceivable.sol";
import { MordantMatchVerifierV5 as Verifier } from "../src/v5/MordantMatchVerifierV5.sol";
import { MordantResultCoreV5 as Core } from "../src/v5/MordantResultCoreV5.sol";
import {
    MordantScopeGovernanceRegistryV5 as Governance
} from "../src/v5/MordantScopeGovernanceRegistryV5.sol";
import {
    MordantSourceCommitmentRegistry as Sources
} from "../src/v5/MordantSourceCommitmentRegistry.sol";
import {
    IFactoryAdmission,
    PrivateMatchBinderV5 as Binder
} from "../src/v5/PrivateMatchBinderV5.sol";

/// @notice A contract that implements the anchor interface perfectly and is not
/// an anchor. Findings M-06 and L-01: V4 could not tell the difference.
contract ImpostorAnchor is IAnchoredReceivable {
    bytes32 public assetCommitment;
    uint16 public identitySchemeVersion = 3;
    bytes32 public initialTermsCommitment = keccak256("impostor-terms");
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
}

contract V5VerifierBinderTest is Test {
    uint256 private constant ISSUER_KEY = 0x1551E4;
    uint256 private constant BUYER_KEY = 0xB111;
    uint256 private constant ORIGINATOR_KEY = 0x0121;
    uint256 private constant FACILITY_KEY = 0xFAC1;
    uint256 private constant HOLDER_KEY = 0x40D3;
    uint256 private constant CONTROLLER_A_KEY = 0xC0A;
    uint256 private constant CONTROLLER_B_KEY = 0xC0B;

    uint32 private constant EPOCH = 1;
    uint32 private constant POLICY_VERSION = 1;
    bytes32 private constant POLICY_ID = keccak256("mordant.policy.v5");
    bytes32 private constant CURRENCY = keccak256("USD");
    bytes32 private constant SCOPE_A = keccak256("scope-a");
    bytes32 private constant SCOPE_B = keccak256("scope-b");
    uint256 private constant FACE = 1_000_000e6;
    uint256 private constant UNITS = 1_000e6;
    uint256 private constant ADVANCE = 900_000e6;

    address private issuer;
    address private buyer;
    address private originator;
    address private facility;
    address private holder;
    address private controllerA;
    address private controllerB;
    address private relayer = address(0xBEEF);
    address private submitter = address(0x5B);

    MockEligibility private eligibility;
    MockERC20 private settlement;
    MordantIssuerRegistry private registry;
    MordantFactoryV2 private factory;
    Governance private governance;
    Sources private sources;
    Verifier private verifier;
    Binder private binder;

    MordantInvoiceVaultV2 private vault;
    mapping(address => MockCvaAdapter) private adapterOf;
    mapping(address => MockERC20) private cvaOf;

    uint256[3] private validatorKeys;
    address[] private validatorSet;

    bytes32 private stableId;
    uint64 private protectionEnd;
    bytes32 private recordA;
    bytes32 private recordB;
    bytes32 private anchoredSourceCommitment;
    bytes32 private counterpartySourceCommitment;
    Core.ResultCore private pendingCore;
    bytes32 private pendingResult;
    address private pendingAnchor;
    Binder.SourceReveal private anchoredReveal;
    Binder.SourceReveal private counterpartyReveal;

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(1000);
        issuer = vm.addr(ISSUER_KEY);
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

        factory = new MordantFactoryV2(address(this), eligibility, registry);
        factory.setFacility(facility, true);
        factory.setSettlementToken(address(settlement), true);

        stableId = _stableId("INV-2026-0042", 20_500);
        protectionEnd = uint64(block.timestamp + 30 days);

        governance = new Governance(address(this));
        governance.setAuthorizedRelayer(relayer, true);
        sources = new Sources(address(this), registry);
        sources.setAuthorizedSubmitter(submitter, true);

        validatorKeys = [uint256(0xA11), uint256(0xB22), uint256(0xC33)];
        _sortValidators();
        verifier = new Verifier(address(this), governance, validatorSet, 2, 2);
        verifier.setPolicyVersion(POLICY_ID, POLICY_VERSION);

        binder = new Binder(
            verifier,
            governance,
            sources,
            IFactoryAdmission(address(factory)),
            POLICY_ID,
            POLICY_VERSION,
            7 days,
            keccak256("consequence")
        );
        governance.setAuthorizedBinder(address(binder), true);
        sources.setAuthorizedRevealer(address(binder), true);

        vault = _createVault(keccak256("root-v5"), 1);
        _activate(vault);

        recordA = _authorize(SCOPE_A, controllerA, keccak256("key-a"), keccak256("org-a"), 1);
        recordB = _authorize(SCOPE_B, controllerB, keccak256("key-b"), keccak256("org-b"), 2);

        // Both sources are published as opaque commitments before any session.
        (anchoredSourceCommitment, anchoredReveal) =
            _commitSource(vault.assetCommitment(), keccak256("root-v5"), originator, 11);
        (counterpartySourceCommitment, counterpartyReveal) = _commitSource(
            keccak256("counterparty-salted-commitment"),
            keccak256("root-counterparty"),
            address(0xC0FFEE),
            12
        );

        // Records and sources must be strictly earlier than the session block.
        vm.roll(block.number + 1);
    }

    /* ---------------------------------------------------------- happy path */

    function testBindsAConfirmedPolicyConflict() public {
        bytes32 session = _bind(1);
        Binder.RecourseRecord memory record = binder.recourseOf(session);
        assertTrue(record.open);
        assertEq(record.anchor, address(vault));
        assertEq(record.anchorCommitment, vault.assetCommitment());
        assertEq(record.counterpartyCommitment, keccak256("counterparty-salted-commitment"));
        assertEq(record.policyId, POLICY_ID);
    }

    /* ------------------------------- verifier: outcome and result core ---- */

    function testTheImpossibleStateIsRejectedAtTheResultCore() public {
        // 01: a policy conflict without an asset match. The policy conjunction
        // has identity equality as a factor, so this state cannot be produced.
        Core.ResultCore memory core = _core(1);
        core.sameEconomicAsset = false;
        core.policyConflict = true;
        core.outcome = Outcomes.Outcome.SameAssetPolicyConflict;
        vm.expectRevert(Outcomes.PolicyConflictWithoutAssetMatch.selector);
        this.externalWellFormed(core);
    }

    function externalWellFormed(Core.ResultCore memory core) external view {
        Core.requireWellFormed(core, address(verifier), block.timestamp);
    }

    function testADeclaredOutcomeMustMatchTheTwoBits() public {
        Core.ResultCore memory core = _core(1);
        core.outcome = Outcomes.Outcome.DifferentAsset; // bits say conflict
        vm.expectRevert(Outcomes.ReleasedBitsDisagreeWithOutcome.selector);
        this.externalWellFormed(core);
    }

    function testAMutatedCoreFailsItsResultCommitment() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        // The runtime fingerprint was entirely outside the V4 signature.
        envelope.core.evaluation.runtimeFingerprint = keccak256("a-different-build");
        vm.prank(address(binder));
        vm.expectRevert();
        verifier.acceptMatch(envelope, attestation);
    }

    function testAProtocolVersionBelowV5IsRejected() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        envelope.core.schemaVersion = 4;
        envelope.resultCommitment = Core.commitmentOf(envelope.core);
        vm.prank(address(binder));
        vm.expectRevert(abi.encodeWithSelector(Verifier.ProtocolVersionRetired.selector, uint16(4)));
        verifier.acceptMatch(envelope, attestation);
    }

    function testOnlyTheNamedBinderMayPresentAResult() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        vm.expectRevert(
            abi.encodeWithSelector(Verifier.InvalidBinder.selector, address(this), address(binder))
        );
        verifier.acceptMatch(envelope, attestation);
    }

    /* ------------------------------- verifier: session and nullifier ------ */

    function testAResultForAnUnadmittedSessionIsRejected() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        envelope.core.session.sessionCommitment = keccak256("never-committed");
        envelope.resultCommitment = Core.commitmentOf(envelope.core);
        attestation = _attest(envelope);
        vm.prank(address(binder));
        vm.expectRevert(
            abi.encodeWithSelector(
                Verifier.UnknownSessionCommitment.selector, keccak256("never-committed")
            )
        );
        verifier.acceptMatch(envelope, attestation);
    }

    /// The nullifier is read from the registry's admission record, never taken
    /// from the envelope, so a result cannot be detached from the admitted intent.
    function testANullifierThatDisagreesWithTheAdmissionRecordIsRejected() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        bytes32 admitted = envelope.core.session.sessionNullifier;
        envelope.core.session.sessionNullifier = keccak256("another-nullifier");
        envelope.resultCommitment = Core.commitmentOf(envelope.core);
        attestation = _attest(envelope);
        vm.prank(address(binder));
        vm.expectRevert(
            abi.encodeWithSelector(
                Verifier.SessionNullifierMismatch.selector, keccak256("another-nullifier"), admitted
            )
        );
        verifier.acceptMatch(envelope, attestation);
    }

    /* ------------------------------- verifier: recomputation transcript --- */

    function testATranscriptBelowTheRecomputationQuorumIsRejected() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        envelope.transcript.recomputationQuorum = 1; // one operator is self-agreement
        vm.prank(address(binder));
        vm.expectRevert(
            abi.encodeWithSelector(
                Verifier.RecomputationQuorumTooSmall.selector, uint16(1), uint16(2)
            )
        );
        verifier.acceptMatch(envelope, attestation);
    }

    /// The context is recomputed from the result core, never read, so a
    /// transcript cannot describe one runtime while the result claims another.
    function testATranscriptForADifferentRuntimeIsRejected() public {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(1);
        envelope.transcript.contextDigest = keccak256("some-other-runtime");
        vm.prank(address(binder));
        vm.expectRevert();
        verifier.acceptMatch(envelope, attestation);
    }

    /* ------------------------------- verifier: one-time identities -------- */

    function testEachIdentityIsConsumedExactlyOnce() public {
        bytes32 session = _bind(1);
        assertTrue(binder.recourseOf(session).open);

        // A second, fully valid envelope for the same session must fail: the
        // session, its nullifier, the output and the provider proof are spent.
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) = _envelope(2);
        vm.prank(address(binder));
        vm.expectRevert();
        verifier.acceptMatch(envelope, attestation);
    }

    /* ------------------------------- verifier: quorum --------------------- */

    function testASingleValidatorCannotFillTheQuorum() public {
        (Verifier.MatchEnvelopeV5 memory envelope,) = _envelope(1);
        bytes32 digest = verifier.attestationDigest(
            verifier.resultDigest(envelope.core), envelope.transcript.contextDigest
        );
        bytes memory doubled =
            bytes.concat(_sig(validatorKeys[0], digest), _sig(validatorKeys[0], digest));
        vm.prank(address(binder));
        vm.expectRevert();
        verifier.acceptMatch(envelope, doubled);
    }

    function testAnUnknownSignerIsRejected() public {
        (Verifier.MatchEnvelopeV5 memory envelope,) = _envelope(1);
        bytes32 digest = verifier.attestationDigest(
            verifier.resultDigest(envelope.core), envelope.transcript.contextDigest
        );
        uint256[] memory keys = new uint256[](2);
        keys[0] = validatorKeys[0];
        keys[1] = 0xDEAD;
        bytes memory attestation = _sortedSigs(keys, digest);
        vm.prank(address(binder));
        vm.expectRevert();
        verifier.acceptMatch(envelope, attestation);
    }

    /* ------------------------------- binder: anchor provenance ------------ */

    /// The headline M-06 / L-01 test. A contract that implements the anchor
    /// interface perfectly, reports Outstanding, protected and funded, and even
    /// carries the right asset commitment, must still be refused: it was never
    /// created by the authorized factory.
    function testAnInterfaceCompatibleMockIsRefused() public {
        ImpostorAnchor impostor = new ImpostorAnchor(
            vault.assetCommitment(),
            registry.issuerKeyIdFor(issuer),
            vault.sourceAttestationDigest()
        );
        // Sanity: the impostor satisfies every behavioural check V4 performed.
        assertEq(impostor.assetCommitment(), vault.assetCommitment());
        assertEq(impostor.receivableState(), 1);
        assertEq(impostor.protectionState(), 1);
        assertTrue(impostor.totalSupply() > 0);

        _stage(_core(1), address(impostor));
        vm.expectRevert(
            abi.encodeWithSelector(
                Binder.AnchorNotFromAuthorizedFactory.selector, address(impostor), address(vault)
            )
        );
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    /// An anchor whose attestation digest resolves nowhere in the factory.
    function testAForeignAnchorIsRefused() public {
        ImpostorAnchor foreign = new ImpostorAnchor(
            vault.assetCommitment(),
            registry.issuerKeyIdFor(issuer),
            keccak256("foreign-attestation")
        );
        _stage(_core(1), address(foreign));
        vm.expectRevert(
            abi.encodeWithSelector(
                Binder.AnchorNotFromAuthorizedFactory.selector, address(foreign), address(0)
            )
        );
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    function testAnEmptyAddressIsRefused() public {
        _stage(_core(1), address(0xD15C));
        vm.expectRevert(abi.encodeWithSelector(Binder.AnchorNotDeployed.selector, address(0xD15C)));
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    /* ------------------------------- binder: outcome gate ----------------- */

    function testANonConflictResultCannotOpenARecourse() public {
        Core.ResultCore memory core = _core(1);
        core.policyConflict = false;
        core.outcome = Outcomes.Outcome.SameAssetNoPolicyConflict;
        _stage(core, address(vault));
        vm.expectRevert(
            abi.encodeWithSelector(
                Binder.ResultNotBindable.selector, Outcomes.Outcome.SameAssetNoPolicyConflict
            )
        );
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    function testADifferentAssetResultCannotOpenARecourse() public {
        Core.ResultCore memory core = _core(1);
        core.sameEconomicAsset = false;
        core.policyConflict = false;
        core.outcome = Outcomes.Outcome.DifferentAsset;
        _stage(core, address(vault));
        vm.expectRevert(
            abi.encodeWithSelector(
                Binder.ResultNotBindable.selector, Outcomes.Outcome.DifferentAsset
            )
        );
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    /* ------------------------------- binder: consents --------------------- */

    function testBothControllersMustConsent() public {
        // Side B's consent signed by side A's controller.
        _stage(_core(1), address(vault));
        vm.expectRevert();
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_A_KEY, uint64(block.timestamp + 1 days));
    }

    function testAnExpiredConsentIsRefused() public {
        _stage(_core(1), address(vault));
        vm.expectRevert();
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp - 1));
    }

    /* ------------------------------- binder: source records --------------- */

    function testASourceRecordThatIsNotTheOneInTheResultIsRefused() public {
        Core.ResultCore memory core = _core(1);
        core.session.sourceRecordCommitmentB = keccak256("some-other-source");
        _stage(core, address(vault));
        vm.expectRevert();
        this.submitBind(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    /* ------------------------------------------------------------ helpers */

    function _bind(uint256 nonce) private returns (bytes32) {
        Core.ResultCore memory core = _core(nonce);
        _bindCore(core, address(vault));
        return core.session.sessionCommitment;
    }

    function _bindWithAnchor(uint256 nonce, IAnchoredReceivable anchor) private {
        _bindCore(_core(nonce), address(anchor));
    }

    /// @dev External on purpose: `vm.expectRevert` applies to the next EXTERNAL
    /// call, and every helper below makes view calls before reaching the binder.
    function submitBind(uint256 keyA, uint256 keyB, uint64 validUntil) external {
        _submit(keyA, keyB, validUntil);
    }

    function _bindCore(Core.ResultCore memory core, address anchor) private {
        _stage(core, anchor);
        _submit(CONTROLLER_A_KEY, CONTROLLER_B_KEY, uint64(block.timestamp + 1 days));
    }

    function _bindWithConsentSigners(uint256 nonce, uint256 keyA, uint256 keyB) private {
        _stage(_core(nonce), address(vault));
        _submit(keyA, keyB, uint64(block.timestamp + 1 days));
    }

    function _bindWithConsentExpiry(uint256 nonce, uint64 validUntil) private {
        _stage(_core(nonce), address(vault));
        _submit(CONTROLLER_A_KEY, CONTROLLER_B_KEY, validUntil);
    }

    function _stage(Core.ResultCore memory core, address anchor) private {
        pendingCore = core;
        pendingResult = Core.commitmentOf(core);
        pendingAnchor = anchor;
    }

    function _submit(uint256 keyA, uint256 keyB, uint64 validUntil) private {
        (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation) =
            _envelopeFor(pendingCore);
        binder.bindRecourse(
            envelope,
            attestation,
            _reveal(),
            anchoredReveal,
            counterpartyReveal,
            IAnchoredReceivable(pendingAnchor),
            _consent(SCOPE_A, recordA, keyA, validUntil, 1),
            _consent(SCOPE_B, recordB, keyB, validUntil, 2)
        );
    }

    function _intent() private view returns (Governance.BilateralSessionIntentV5 memory) {
        return Governance.BilateralSessionIntentV5({
            chainId: block.chainid,
            governanceRegistry: address(governance),
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            governanceRecordA: recordA,
            governanceRecordB: recordB,
            controllerKeyIdA: keccak256("key-a"),
            controllerKeyIdB: keccak256("key-b"),
            controllerEpochA: 1,
            controllerEpochB: 1,
            scopeAuthorizationVersionA: 1,
            scopeAuthorizationVersionB: 1,
            sourceRecordCommitmentA: anchoredSourceCommitment,
            sourceRecordCommitmentB: counterpartySourceCommitment,
            scopeCommitmentA: SCOPE_A,
            scopeCommitmentB: SCOPE_B,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            identityEpoch: EPOCH,
            strictAssetCommitmentA: vault.assetCommitment(),
            candidateAuthorized: false,
            exactBudget: 1,
            candidateBudget: 0,
            sessionNonce: 7,
            expiry: uint64(block.timestamp + 7 days),
            disclosureVersion: POLICY_VERSION
        });
    }

    function _signatures() private view returns (Governance.InitiationSignatures memory) {
        bytes32 digest = governance.intentDigest(_intent());
        return Governance.InitiationSignatures({
            controllerA: _sig(CONTROLLER_A_KEY, digest),
            controllerB: _sig(CONTROLLER_B_KEY, digest),
            issuer: _sig(ISSUER_KEY, digest)
        });
    }

    function _reveal() private view returns (Binder.SessionReveal memory) {
        return Binder.SessionReveal({
            intent: _intent(), salt: keccak256("session-salt"), signatures: _signatures()
        });
    }

    /// @dev Publishes the session commitment once, lazily, then returns it.
    function _session() private returns (bytes32 commitment, bytes32 nullifier) {
        Governance.BilateralSessionIntentV5 memory intent = _intent();
        commitment =
            governance.sessionCommitmentOf(intent, _signatures(), keccak256("session-salt"));
        nullifier = governance.sessionNullifierOf(intent);
        if (!governance.commitment(commitment).exists) {
            vm.prank(relayer);
            governance.commitSession(commitment, nullifier);
            vm.roll(block.number + 1);
        }
    }

    function _core(uint256 nonce) private returns (Core.ResultCore memory core) {
        (bytes32 sessionCommitment, bytes32 nullifier) = _session();
        core.schemaVersion = Core.RESULT_SCHEMA_VERSION;
        core.chainId = block.chainid;
        core.verifier = address(verifier);
        core.binder = address(binder);
        core.policyId = POLICY_ID;
        core.policyVersion = POLICY_VERSION;
        core.session = Core.SessionBinding({
            sessionCommitment: sessionCommitment,
            sessionNullifier: nullifier,
            governanceContext: keccak256(abi.encode(address(governance), recordA, recordB)),
            sourceRecordCommitmentA: anchoredSourceCommitment,
            sourceRecordCommitmentB: counterpartySourceCommitment,
            enrollmentDigestA: keccak256("enrollment-a"),
            enrollmentDigestB: keccak256("enrollment-b")
        });
        core.evaluation = Core.EvaluationBinding({
            ciphertextDigestA: keccak256("ciphertext-a"),
            ciphertextDigestB: keccak256("ciphertext-b"),
            inputCommitmentA: keccak256("input-a"),
            inputCommitmentB: keccak256("input-b"),
            outputCiphertextCommitment: keccak256(abi.encode("output", nonce)),
            circuitHash: keccak256("circuit-v5"),
            circuitVersion: Core.CIRCUIT_VERSION,
            releaseLayoutVersion: Core.RELEASE_LAYOUT_VERSION,
            parameterFingerprint: keccak256("bgv-logn15"),
            evaluationKeyEpoch: 1,
            evaluationKeyDigest: keccak256("evaluation-keys"),
            runtimeFingerprint: keccak256("lattigo-6.2.0/go1.24.0"),
            providerProofCommitment: keccak256(abi.encode("provider-proof", nonce))
        });
        core.sameEconomicAsset = true;
        core.policyConflict = true;
        core.outcome = Outcomes.Outcome.SameAssetPolicyConflict;
        core.nonce = nonce;
        core.expiry = uint64(block.timestamp + 1 days);
    }

    function _envelope(uint256 nonce)
        private
        returns (Verifier.MatchEnvelopeV5 memory, bytes memory)
    {
        return _envelopeFor(_core(nonce));
    }

    function _envelopeFor(Core.ResultCore memory core)
        private
        view
        returns (Verifier.MatchEnvelopeV5 memory envelope, bytes memory attestation)
    {
        envelope.core = core;
        envelope.resultCommitment = Core.commitmentOf(core);
        envelope.transcript = Verifier.RecomputationTranscript({
            transcriptCommitment: keccak256("release-transcript"),
            operatorSetDigest: keccak256("operators-1-2"),
            recomputationQuorum: 2,
            contextDigest: verifier.recomputationContext(core)
        });
        attestation = _attest(envelope);
    }

    function _attest(Verifier.MatchEnvelopeV5 memory envelope) private view returns (bytes memory) {
        bytes32 digest = verifier.attestationDigest(
            verifier.resultDigest(envelope.core), envelope.transcript.contextDigest
        );
        uint256[] memory keys = new uint256[](2);
        keys[0] = validatorKeys[0];
        keys[1] = validatorKeys[1];
        return _sortedSigs(keys, digest);
    }

    function _sortedSigs(uint256[] memory keys, bytes32 digest)
        private
        pure
        returns (bytes memory)
    {
        // Signers must be strictly increasing by address.
        for (uint256 i; i < keys.length; ++i) {
            for (uint256 j = i + 1; j < keys.length; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) {
                    (keys[i], keys[j]) = (keys[j], keys[i]);
                }
            }
        }
        bytes memory out;
        for (uint256 i; i < keys.length; ++i) {
            out = bytes.concat(out, _sig(keys[i], digest));
        }
        return out;
    }

    function _consent(bytes32 scope, bytes32 record, uint256 key, uint64 validUntil, uint256 nonce)
        private
        view
        returns (Binder.DisclosureConsent memory consent)
    {
        consent = Binder.DisclosureConsent({
            scopeCommitment: scope,
            governanceRecord: record,
            disclosureVersion: POLICY_VERSION,
            validUntil: validUntil,
            nonce: nonce,
            signature: ""
        });
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(
                    binder.CONSENT_TYPEHASH(),
                    block.chainid,
                    address(binder),
                    POLICY_ID,
                    POLICY_VERSION,
                    pendingCore.session.sessionCommitment,
                    pendingCore.session.sessionNullifier,
                    pendingResult
                ),
                abi.encode(
                    scope,
                    record,
                    pendingCore.session.sourceRecordCommitmentA,
                    pendingAnchor,
                    POLICY_VERSION,
                    validUntil,
                    nonce
                )
            )
        );
        consent.signature = _sig(
            key, keccak256(abi.encodePacked("\x19\x01", binder.domainSeparator(), structHash))
        );
    }

    function _commitSource(
        bytes32 assetCommitment,
        bytes32 invoiceRoot,
        address controller,
        uint256 nonce
    ) private returns (bytes32 key, Binder.SourceReveal memory reveal) {
        Attest.SourceAssetAttestation memory attestation = Attest.SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(sources),
            creationDigest: keccak256(abi.encode("creation", nonce)),
            assetCommitment: assetCommitment,
            initialTermsCommitment: keccak256(abi.encode("terms", nonce)),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: registry.issuerKeyIdFor(issuer),
            invoiceRoot: invoiceRoot,
            controller: controller,
            validUntil: uint64(block.timestamp + 30 days),
            nonce: nonce
        });
        bytes memory signature = _sig(ISSUER_KEY, Attest.digest(attestation, address(sources)));
        bytes32 salt = keccak256(abi.encode("source-salt", nonce));
        key = sources.sourceCommitmentOf(attestation, signature, salt);
        vm.prank(submitter);
        sources.commitSource(key);
        reveal = Binder.SourceReveal({
            attestation: attestation, issuerSignature: signature, salt: salt
        });
    }

    function _authorize(
        bytes32 scope,
        address controller,
        bytes32 keyId,
        bytes32 org,
        uint256 nonce
    ) private returns (bytes32) {
        return governance.authorize(
            Governance.AuthorizationRequest({
                scopeCommitment: scope,
                controller: controller,
                controllerKeyId: keyId,
                organizationId: org,
                controllerEpoch: 1,
                authorizationVersion: 1,
                nonce: nonce
            })
        );
    }

    function _sortValidators() private {
        uint256[3] memory keys = validatorKeys;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (vm.addr(keys[j]) < vm.addr(keys[i])) (keys[i], keys[j]) = (keys[j], keys[i]);
            }
        }
        validatorKeys = keys;
        delete validatorSet;
        for (uint256 i; i < 3; ++i) {
            validatorSet.push(vm.addr(keys[i]));
        }
    }

    function _sig(uint256 key, bytes32 digest) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _stableId(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (bytes32)
    {
        return Id.strictStableAssetId(
            Id.StableAssetIdentity({
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
            })
        );
    }

    function _config(bytes32 root, address adapter)
        private
        view
        returns (MordantFactoryV2.InvoiceConfig memory)
    {
        return MordantFactoryV2.InvoiceConfig({
            cvaAdapter: adapter,
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
        Attest.SourceAssetAttestation memory attestation = Attest.SourceAssetAttestation({
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
        bytes memory signature = _sig(ISSUER_KEY, Attest.digest(attestation, address(factory)));
        vm.prank(buyer);
        MordantInvoiceVaultV2 created =
            factory.createIdentityAnchoredVault(config, attestation, signature);
        eligibility.setIdentityValid(address(created), true);
        adapterOf[address(created)] = adapter;
        cvaOf[address(created)] = token;
        return created;
    }

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
        bytes memory pledgeSignature = _sig(ORIGINATOR_KEY, target.hashPledge(pledge));
        vm.prank(facility);
        target.activate(pledge, pledgeSignature, holder, holders, allocations);
    }
}
