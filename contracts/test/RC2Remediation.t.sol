// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {MordantIssuerRegistry} from "../src/identity/MordantIssuerRegistry.sol";
import {MordantMatchResultV5 as R} from "../src/identity/MordantMatchResultV5.sol";
import {MordantSourceAttestation} from "../src/identity/MordantSourceAttestation.sol";
import {MordantSourceCommitmentRegistry} from "../src/v5/MordantSourceCommitmentRegistry.sol";
import {MordantScopeGovernanceRegistryV5 as G} from "../src/v5/MordantScopeGovernanceRegistryV5.sol";

/// @dev Library reverts are same-depth, so `expectRevert` needs an external call.
contract ResultHarness {
    function coherent(R.ConfidentialMatchResultV5 memory result) external pure {
        R.requireCoherent(result);
    }

    function bindable(R.ConfidentialMatchResultV5 memory result, bool precommitted) external pure {
        R.requireBindable(result, precommitted);
    }

    function outcomeOf(bool sameAsset, bool policyConflict) external pure returns (R.Outcome) {
        return R.outcomeOf(sameAsset, policyConflict);
    }
}

/// @notice Tests for the RC2 corrections to external audit findings
/// C-01, H-02, M-02, M-03, M-04 and L-03.
///
/// Every negative here is a defect the auditor actually found in RC1, expressed
/// as the behaviour that must now be impossible.
contract RC2RemediationTest is Test {
    uint256 private constant ISSUER_KEY = 0x1551E4;
    uint256 private constant CONTROLLER_A_KEY = 0xC0A;
    uint256 private constant CONTROLLER_B_KEY = 0xC0B;
    uint32 private constant EPOCH = 1;

    address private issuer;
    address private controllerA;
    address private controllerB;
    address private relayer = address(0xBEEF);
    address private submitter = address(0x5B);

    MordantIssuerRegistry private issuers;
    MordantSourceCommitmentRegistry private sources;
    G private governance;
    ResultHarness private harness;

    function setUp() public {
        issuer = vm.addr(ISSUER_KEY);
        controllerA = vm.addr(CONTROLLER_A_KEY);
        controllerB = vm.addr(CONTROLLER_B_KEY);
        issuers = new MordantIssuerRegistry(address(this));
        issuers.registerIssuer(issuer, EPOCH);
        sources = new MordantSourceCommitmentRegistry(address(this), issuers);
        governance = new G(address(this));
        governance.setAuthorizedRelayer(relayer, true);
        governance.setAuthorizedBinder(address(this), true);
        sources.setAuthorizedSubmitter(submitter, true);
        sources.setAuthorizedRevealer(address(this), true);
        harness = new ResultHarness();
        vm.roll(1000);
    }

    /* ============================ H-02: separate outputs ==================== */

    function testTheTwoReleasedBitsDetermineTheOutcome() public view {
        assertEq(uint256(harness.outcomeOf(false, false)), uint256(R.Outcome.DifferentAsset));
        assertEq(uint256(harness.outcomeOf(true, false)), uint256(R.Outcome.SameAssetNoPolicyConflict));
        assertEq(uint256(harness.outcomeOf(true, true)), uint256(R.Outcome.SameAssetPolicyConflict));
    }

    function testAPolicyConflictWithoutAnAssetMatchIsStructurallyImpossible() public {
        // State 01. The policy conjunction has identity equality as a factor, so
        // this is not a weaker signal, it is an impossible one.
        vm.expectRevert(R.PolicyConflictWithoutAssetMatch.selector);
        harness.outcomeOf(false, true);
    }

    function testDifferentAssetAndNoConflictAreDistinguishable() public view {
        // The RC1 defect: one conjunction bit could not tell these apart.
        R.ConfidentialMatchResultV5 memory different = _result(false, false, R.Outcome.DifferentAsset);
        R.ConfidentialMatchResultV5 memory noConflict =
            _result(true, false, R.Outcome.SameAssetNoPolicyConflict);
        harness.coherent(different);
        harness.coherent(noConflict);
        assertTrue(different.outcome != noConflict.outcome);
    }

    function testADeclaredOutcomeMustMatchTheReleasedBits() public {
        // A coordinator claiming a conflict on bits that do not imply one.
        R.ConfidentialMatchResultV5 memory forged =
            _result(true, false, R.Outcome.SameAssetPolicyConflict);
        vm.expectRevert(R.ReleasedBitsDisagreeWithOutcome.selector);
        harness.coherent(forged);
    }

    function testOnlyAPolicyConflictIsBindable() public {
        vm.expectRevert(
            abi.encodeWithSelector(R.ResultNotBindable.selector, R.Outcome.DifferentAsset)
        );
        harness.bindable(_result(false, false, R.Outcome.DifferentAsset), true);

        vm.expectRevert(
            abi.encodeWithSelector(R.ResultNotBindable.selector, R.Outcome.SameAssetNoPolicyConflict)
        );
        harness.bindable(_result(true, false, R.Outcome.SameAssetNoPolicyConflict), true);

        // The only bindable state.
        harness.bindable(_result(true, true, R.Outcome.SameAssetPolicyConflict), true);
    }

    function testABindableResultStillNeedsItsPrecommitment() public {
        R.ConfidentialMatchResultV5 memory result =
            _result(true, true, R.Outcome.SameAssetPolicyConflict);
        vm.expectRevert(
            abi.encodeWithSelector(R.MissingPrecommitment.selector, result.sessionCommitment)
        );
        harness.bindable(result, false);
    }

    function testAnEvaluatedResultMustCarryTwoDistinctEnrollmentDigests() public {
        R.ConfidentialMatchResultV5 memory result =
            _result(true, true, R.Outcome.SameAssetPolicyConflict);
        result.enrollmentDigestB = result.enrollmentDigestA;
        vm.expectRevert(R.EmptyResult.selector);
        harness.coherent(result);
    }

    function testNotComparablePerformsNoEvaluation() public {
        R.ConfidentialMatchResultV5 memory result =
            _result(false, false, R.Outcome.NotComparable);
        result.providerProofCommitment = bytes32(0);
        result.thresholdTranscriptCommitment = bytes32(0);
        harness.coherent(result);

        result.providerProofCommitment = keccak256("proof");
        vm.expectRevert(R.NotComparableMustNotEvaluate.selector);
        harness.coherent(result);
    }

    /* ============================ C-01: opaque source ====================== */

    function _attestation(address controller, uint256 nonce)
        private
        view
        returns (MordantSourceAttestation.SourceAssetAttestation memory)
    {
        return MordantSourceAttestation.SourceAssetAttestation({
            chainId: block.chainid,
            factory: address(sources),
            creationDigest: keccak256("creation"),
            assetCommitment: keccak256("asset"),
            initialTermsCommitment: keccak256("terms"),
            identitySchemeVersion: 3,
            termsSchemeVersion: 1,
            identityEpoch: EPOCH,
            issuerKeyId: issuers.issuerKeyIdFor(issuer),
            invoiceRoot: keccak256("root"),
            controller: controller,
            validUntil: uint64(block.timestamp + 1 days),
            nonce: nonce
        });
    }

    function _sign(uint256 key, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _commitSource(address controller, uint256 nonce, bytes32 salt)
        private
        returns (
            MordantSourceAttestation.SourceAssetAttestation memory attestation,
            bytes memory signature,
            bytes32 key
        )
    {
        attestation = _attestation(controller, nonce);
        signature = _sign(ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(sources)));
        key = sources.sourceCommitmentOf(attestation, signature, salt);
        vm.prank(submitter);
        sources.commitSource(key);
    }

    function testCommittingASourcePublishesNoCorrelatableField() public {
        (
            MordantSourceAttestation.SourceAssetAttestation memory attestation,
            bytes memory signature,
            bytes32 key
        ) = _commitSource(address(0xC0117), 1, keccak256("salt"));

        // The RC1 defect was that the whole attestation was an ABI argument, so
        // the controller sat in permanent public calldata. Here the only public
        // value is the commitment itself.
        MordantSourceCommitmentRegistry.SourceCommitment memory stored = sources.commitment(key);
        assertTrue(stored.exists);
        assertEq(stored.submitter, submitter);
        assertEq(stored.committedInBlock, uint64(block.number));
        assertFalse(stored.revealed);

        // Nothing about the source is derivable from the commitment.
        assertTrue(key != bytes32(uint256(uint160(attestation.controller))));
        assertTrue(key != attestation.assetCommitment);
        assertTrue(key != attestation.invoiceRoot);
        assertTrue(signature.length == 65);
    }

    function testTheSameAttestationUnderADifferentSaltIsADifferentCommitment() public {
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(address(0xC0117), 1);
        bytes memory signature =
            _sign(ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(sources)));
        assertTrue(
            sources.sourceCommitmentOf(attestation, signature, keccak256("a"))
                != sources.sourceCommitmentOf(attestation, signature, keccak256("b"))
        );
    }

    function testOnlyAnAuthorizedSubmitterMayCommitASource() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantSourceCommitmentRegistry.SubmitterNotAuthorized.selector, address(0xBAD)
            )
        );
        sources.commitSource(keccak256("anything"));
    }

    function testOnlyAnAuthorizedRevealerMayOpenASource() public {
        (
            MordantSourceAttestation.SourceAssetAttestation memory attestation,
            bytes memory signature,
        ) = _commitSource(address(0xC0117), 1, keccak256("salt"));
        vm.prank(address(0xBAD));
        vm.expectRevert(
            abi.encodeWithSelector(MordantSourceCommitmentRegistry.Unauthorized.selector, address(0xBAD))
        );
        sources.revealSource(attestation, signature, keccak256("salt"));
    }

    function testRevealingOpensTheSourceExactlyOnce() public {
        (
            MordantSourceAttestation.SourceAssetAttestation memory attestation,
            bytes memory signature,
            bytes32 key
        ) = _commitSource(address(0xC0117), 1, keccak256("salt"));

        MordantSourceCommitmentRegistry.RevealedSource memory revealed =
            sources.revealSource(attestation, signature, keccak256("salt"));
        assertEq(revealed.sourceRecordCommitment, key);
        assertEq(revealed.controller, address(0xC0117));
        assertEq(revealed.assetCommitment, attestation.assetCommitment);
        assertEq(revealed.issuerSigner, issuer);
        assertEq(revealed.termsSchemeVersion, 1);

        vm.expectRevert(
            abi.encodeWithSelector(MordantSourceCommitmentRegistry.CommitmentAlreadyRevealed.selector, key)
        );
        sources.revealSource(attestation, signature, keccak256("salt"));
    }

    function testAnUncommittedSourceCannotBeRevealed() public {
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(address(0xC0117), 1);
        bytes memory signature =
            _sign(ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(sources)));
        bytes32 key = sources.sourceCommitmentOf(attestation, signature, keccak256("salt"));
        vm.expectRevert(
            abi.encodeWithSelector(MordantSourceCommitmentRegistry.UnknownCommitment.selector, key)
        );
        sources.revealSource(attestation, signature, keccak256("salt"));
    }

    function testASubmitterThatIsTheSourceControllerIsRefusedAtReveal() public {
        // The allowlist is policy, not proof. A submitter that turns out to be
        // the principal it published was never a non-principal relayer.
        sources.setAuthorizedSubmitter(submitter, true);
        (
            MordantSourceAttestation.SourceAssetAttestation memory attestation,
            bytes memory signature,
        ) = _commitSource(submitter, 1, keccak256("salt"));
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantSourceCommitmentRegistry.SubmitterIsTheSourceController.selector, submitter
            )
        );
        sources.revealSource(attestation, signature, keccak256("salt"));
    }

    function testAnIncompatibleTermsSchemeIsRefused() public {
        // Finding L-03: RC1 signed termsSchemeVersion but never checked it.
        MordantSourceAttestation.SourceAssetAttestation memory attestation =
            _attestation(address(0xC0117), 1);
        attestation.termsSchemeVersion = 2;
        bytes memory signature =
            _sign(ISSUER_KEY, MordantSourceAttestation.digest(attestation, address(sources)));
        bytes32 key = sources.sourceCommitmentOf(attestation, signature, keccak256("salt"));
        vm.prank(submitter);
        sources.commitSource(key);
        vm.expectRevert(
            abi.encodeWithSelector(MordantSourceCommitmentRegistry.SchemeMismatch.selector, 2, 1)
        );
        sources.revealSource(attestation, signature, keccak256("salt"));
    }

    function testAnIssuerNonceIsOneShotAcrossSources() public {
        (
            MordantSourceAttestation.SourceAssetAttestation memory first,
            bytes memory firstSignature,
        ) = _commitSource(address(0xC0117), 7, keccak256("salt-1"));
        sources.revealSource(first, firstSignature, keccak256("salt-1"));

        (
            MordantSourceAttestation.SourceAssetAttestation memory second,
            bytes memory secondSignature,
        ) = _commitSource(address(0xC0118), 7, keccak256("salt-2"));
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantSourceCommitmentRegistry.NonceConsumed.selector, second.issuerKeyId, 7
            )
        );
        sources.revealSource(second, secondSignature, keccak256("salt-2"));
    }

    /* ================== M-02: session one-shot nullifier =================== */

    function _authorize(bytes32 scope, address controller, bytes32 org, uint32 version, uint256 nonce)
        private
        returns (bytes32)
    {
        return governance.authorize(
            G.AuthorizationRequest({
                scopeCommitment: scope,
                controller: controller,
                controllerKeyId: keccak256(abi.encode("key", scope)),
                organizationId: org,
                controllerEpoch: version,
                authorizationVersion: version,
                nonce: nonce
            })
        );
    }

    function _intent(bytes32 recordA, bytes32 recordB, uint256 sessionNonce)
        private
        view
        returns (G.BilateralSessionIntentV5 memory)
    {
        return G.BilateralSessionIntentV5({
            chainId: block.chainid,
            governanceRegistry: address(governance),
            policyId: keccak256("policy"),
            policyVersion: 1,
            governanceRecordA: recordA,
            governanceRecordB: recordB,
            controllerKeyIdA: keccak256(abi.encode("key", keccak256("scope-a"))),
            controllerKeyIdB: keccak256(abi.encode("key", keccak256("scope-b"))),
            controllerEpochA: 1,
            controllerEpochB: 1,
            scopeAuthorizationVersionA: 1,
            scopeAuthorizationVersionB: 1,
            sourceRecordCommitmentA: keccak256("src-a"),
            sourceRecordCommitmentB: keccak256("src-b"),
            scopeCommitmentA: keccak256("scope-a"),
            scopeCommitmentB: keccak256("scope-b"),
            issuerKeyId: issuers.issuerKeyIdFor(issuer),
            identityEpoch: EPOCH,
            strictAssetCommitmentA: keccak256("asset-a"),
            candidateAuthorized: false,
            exactBudget: 1,
            candidateBudget: 0,
            sessionNonce: sessionNonce,
            expiry: uint64(block.timestamp + 1 days),
            disclosureVersion: 1
        });
    }

    function _signatures(G.BilateralSessionIntentV5 memory intent)
        private
        returns (G.InitiationSignatures memory)
    {
        bytes32 digest = governance.intentDigest(intent);
        return G.InitiationSignatures({
            controllerA: _sign(CONTROLLER_A_KEY, digest),
            controllerB: _sign(CONTROLLER_B_KEY, digest),
            issuer: _sign(ISSUER_KEY, digest)
        });
    }

    function _twoRecords() private returns (bytes32 recordA, bytes32 recordB) {
        recordA = _authorize(keccak256("scope-a"), controllerA, keccak256("org-a"), 1, 1);
        recordB = _authorize(keccak256("scope-b"), controllerB, keccak256("org-b"), 1, 2);
        // Records must be strictly earlier than the commitment block.
        vm.roll(block.number + 1);
    }

    function testOneSignedIntentAdmitsExactlyOneSession() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 nullifier = governance.sessionNullifierOf(intent);

        bytes32 first = governance.sessionCommitmentOf(intent, signatures, keccak256("salt-1"));
        vm.prank(relayer);
        governance.commitSession(first, nullifier);

        // The RC1 defect: the same signatures under a new salt produced another
        // accepted session, without limit.
        bytes32 second = governance.sessionCommitmentOf(intent, signatures, keccak256("salt-2"));
        assertTrue(second != first);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(G.NullifierConsumed.selector, nullifier));
        governance.commitSession(second, nullifier);
    }

    function testTheNullifierIsIndependentOfTheSalt() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        // Salt changes the commitment and must NOT change the nullifier.
        assertTrue(
            governance.sessionCommitmentOf(intent, signatures, keccak256("a"))
                != governance.sessionCommitmentOf(intent, signatures, keccak256("b"))
        );
        assertEq(governance.sessionNullifierOf(intent), governance.sessionNullifierOf(intent));
    }

    function testADifferentSessionNonceIsADifferentSession() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        assertTrue(
            governance.sessionNullifierOf(_intent(recordA, recordB, 1))
                != governance.sessionNullifierOf(_intent(recordA, recordB, 2))
        );
    }

    function testAMismatchedNullifierCannotBeRevealed() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));

        // Admitted under an unrelated nullifier.
        vm.prank(relayer);
        governance.commitSession(key, keccak256("some-other-nullifier"));

        vm.expectRevert(
            abi.encodeWithSelector(
                G.NullifierMismatch.selector, governance.sessionNullifierOf(intent), keccak256("some-other-nullifier")
            )
        );
        governance.resolveSession(intent, keccak256("salt"), signatures);
    }

    /* ================ M-03 / M-04: strict block chronology ================= */

    function testARecordAuthorizedInTheCommitmentBlockIsRefused() public {
        bytes32 recordA = _authorize(keccak256("scope-a"), controllerA, keccak256("org-a"), 1, 1);
        bytes32 recordB = _authorize(keccak256("scope-b"), controllerB, keccak256("org-b"), 1, 2);
        // No vm.roll: authorization and commitment land in the same block, which
        // a timestamp comparison could not distinguish.
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));
        bytes32 nullifier = governance.sessionNullifierOf(intent);
        vm.prank(relayer);
        governance.commitSession(key, nullifier);

        vm.expectRevert(
            abi.encodeWithSelector(
                G.RecordNotStrictlyBeforeCommitment.selector, recordA, uint64(block.number), uint64(block.number)
            )
        );
        governance.resolveSession(intent, keccak256("salt"), signatures);
    }

    function testARecordRetiredInTheCommitmentBlockIsRefused() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));
        bytes32 nullifier = governance.sessionNullifierOf(intent);
        vm.prank(relayer);
        governance.commitSession(key, nullifier);
        // Retired in the very block the commitment landed in: ambiguous, so the
        // conservative answer is that it was not still live.
        governance.retire(recordA);

        vm.expectRevert(
            abi.encodeWithSelector(
                G.RecordNotStrictlyBeforeCommitment.selector, recordA, uint64(block.number - 1), uint64(block.number)
            )
        );
        governance.resolveSession(intent, keccak256("salt"), signatures);
    }

    function testARotationInALaterBlockDoesNotStrandACommittedSession() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));
        bytes32 nullifier = governance.sessionNullifierOf(intent);
        vm.prank(relayer);
        governance.commitSession(key, nullifier);

        // An orderly handover strictly after the commitment must not break it.
        vm.roll(block.number + 1);
        governance.retire(recordA);

        G.ResolvedSession memory resolved = governance.resolveSession(intent, keccak256("salt"), signatures);
        assertEq(resolved.sessionCommitment, key);
        assertEq(resolved.controllerA, controllerA);
        assertEq(resolved.scopeCommitmentA, keccak256("scope-a"));
    }

    function testEmergencyRevocationStillReachesACommittedSession() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));
        bytes32 nullifier = governance.sessionNullifierOf(intent);
        vm.prank(relayer);
        governance.commitSession(key, nullifier);

        vm.roll(block.number + 1);
        governance.emergencyRevoke(recordA);

        vm.expectRevert(
            abi.encodeWithSelector(
                G.ControllerEmergencyRevoked.selector, recordA, uint64(block.number)
            )
        );
        governance.resolveSession(intent, keccak256("salt"), signatures);
    }

    function testTheIntentMustNameTheScopeItsRecordAuthorizes() public {
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        intent.scopeCommitmentA = keccak256("some-other-scope");
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));
        bytes32 nullifier = governance.sessionNullifierOf(intent);
        vm.prank(relayer);
        governance.commitSession(key, nullifier);

        vm.expectRevert(abi.encodeWithSelector(G.IntentRecordMismatch.selector, recordA));
        governance.resolveSession(intent, keccak256("salt"), signatures);
    }

    function testARelayerThatIsAControllerCannotOpenTheSession() public {
        governance.setAuthorizedRelayer(controllerA, true);
        (bytes32 recordA, bytes32 recordB) = _twoRecords();
        G.BilateralSessionIntentV5 memory intent = _intent(recordA, recordB, 42);
        G.InitiationSignatures memory signatures = _signatures(intent);
        bytes32 key = governance.sessionCommitmentOf(intent, signatures, keccak256("salt"));
        bytes32 nullifier = governance.sessionNullifierOf(intent);
        vm.prank(controllerA);
        governance.commitSession(key, nullifier);

        vm.expectRevert(abi.encodeWithSelector(G.RelayerIsController.selector, controllerA));
        governance.resolveSession(intent, keccak256("salt"), signatures);
    }

    /* ---------------------------------------------------------------- helper */

    function _result(bool sameAsset, bool policyConflict, R.Outcome outcome)
        private
        pure
        returns (R.ConfidentialMatchResultV5 memory)
    {
        return R.ConfidentialMatchResultV5({
            schemaVersion: R.RESULT_SCHEMA_VERSION,
            sessionCommitment: keccak256("session"),
            scopeCommitmentA: keccak256("scope-a"),
            scopeCommitmentB: keccak256("scope-b"),
            inputCommitmentA: keccak256("in-a"),
            inputCommitmentB: keccak256("in-b"),
            enrollmentDigestA: keccak256("enroll-a"),
            enrollmentDigestB: keccak256("enroll-b"),
            outcome: outcome,
            sameEconomicAsset: sameAsset,
            policyConflict: policyConflict,
            candidateMatchSuggested: false,
            candidateFallbackAuthorized: false,
            matchCommitment: keccak256("match"),
            boundCandidateAliasCommitment: bytes32(0),
            anchorCount: 2,
            providerProofCommitment: keccak256("proof"),
            thresholdTranscriptCommitment: keccak256("transcript")
        });
    }
}
