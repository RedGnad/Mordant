// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {MordantIssuerRegistry} from "../src/identity/MordantIssuerRegistry.sol";
import {MordantMatchResult as Match} from "../src/identity/MordantMatchResult.sol";
import {MordantSourceAttestation} from "../src/identity/MordantSourceAttestation.sol";
import {MordantSourceIdentityRegistry} from "../src/identity/MordantSourceIdentityRegistry.sol";
import {ECDSAQuorumMatchVerifierV4} from "../src/v4/ECDSAQuorumMatchVerifierV4.sol";
import {MordantScopeGovernanceRegistry as Governance} from
    "../src/v4/MordantScopeGovernanceRegistry.sol";
import {PrivateMatchBinder} from "../src/v4/PrivateMatchBinder.sol";

/// @notice Emits the exact digests the frozen V4 contracts compute for one fixed
/// input, and asserts the pinned off-chain mirrors reproduce them.
///
/// @dev The frozen contracts hash in nested chunks to stay inside the stack
/// limit, so a generic EIP-712 encoder does NOT reproduce these values. The
/// constants below are the authority; `v4-digests.test.mjs` pins the JavaScript
/// mirrors against exactly these numbers, and the runner additionally checks
/// every digest against the deployed bytecode over `eth_call` before publishing
/// anything.
contract V4DigestVectorsTest is Test {
    uint256 private constant CHAIN_ID = 10_143;
    bytes32 private constant POLICY_ID = keccak256("mordant.private-match.policy/v4");
    uint32 private constant POLICY_VERSION = 1;
    bytes32 private constant SCOPE_A = keccak256("vector-scope-a");
    bytes32 private constant SCOPE_B = keccak256("vector-scope-b");

    Governance private governance;
    ECDSAQuorumMatchVerifierV4 private verifier;
    PrivateMatchBinder private binder;
    MordantIssuerRegistry private issuers;
    MordantSourceIdentityRegistry private sources;

    function setUp() public {
        vm.chainId(CHAIN_ID);
        governance = new Governance(address(this));
        issuers = new MordantIssuerRegistry(address(this));
        sources = new MordantSourceIdentityRegistry(issuers);
        address[] memory validators = new address[](3);
        validators[0] = address(0x1001);
        validators[1] = address(0x1002);
        validators[2] = address(0x1003);
        verifier = new ECDSAQuorumMatchVerifierV4(address(this), governance, validators, 2);
        binder = new PrivateMatchBinder(
            verifier,
            governance,
            issuers,
            sources,
            POLICY_ID,
            POLICY_VERSION,
            keccak256("mordant.role.facility.v1"),
            3_600,
            keccak256("mordant.consequence.review-required.v1")
        );
    }

    function _intent() private view returns (Governance.BilateralSessionIntent memory) {
        return Governance.BilateralSessionIntent({
            chainId: CHAIN_ID,
            governanceRegistry: address(governance),
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            governanceRecordA: keccak256("vector-record-a"),
            governanceRecordB: keccak256("vector-record-b"),
            controllerKeyIdA: keccak256("vector-key-a"),
            controllerKeyIdB: keccak256("vector-key-b"),
            controllerEpochA: 1,
            controllerEpochB: 2,
            scopeAuthorizationVersionA: 3,
            scopeAuthorizationVersionB: 4,
            sourceRecordA: keccak256("vector-source-a"),
            sourceRecordB: keccak256("vector-source-b"),
            issuerKeyId: keccak256("vector-issuer"),
            identityEpoch: 5,
            strictAssetCommitmentA: keccak256("vector-asset"),
            supersedesCandidateSession: keccak256("vector-supersedes"),
            candidateAuthorized: false,
            exactBudget: 1,
            candidateBudget: 0,
            sessionNonce: 42,
            expiry: 1_900_000_000,
            disclosureVersion: 1
        });
    }

    function _signatures() private pure returns (Governance.InitiationSignatures memory) {
        return Governance.InitiationSignatures({
            controllerA: hex"11",
            controllerB: hex"22",
            issuer: hex"33"
        });
    }

    function _envelope() private view returns (ECDSAQuorumMatchVerifierV4.MatchEnvelope memory) {
        bytes32 session = keccak256("vector-session-commitment");
        return ECDSAQuorumMatchVerifierV4.MatchEnvelope({
            chainId: CHAIN_ID,
            binder: address(binder),
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            sessionCommitment: session,
            nonce: 7,
            validUntil: 1_900_000_000,
            resultCommitment: bytes32(0),
            result: Match.ConfidentialMatchResultV4({
                sessionId: session,
                scopeCommitmentA: SCOPE_A,
                scopeCommitmentB: SCOPE_B,
                inputCommitmentA: keccak256("vector-input-a"),
                inputCommitmentB: keccak256("vector-input-b"),
                outcome: Match.Outcome.ExactMatch,
                exactMatchConfirmed: true,
                candidateMatchSuggested: false,
                candidateFallbackAuthorized: false,
                conflictConfirmed: true,
                matchCommitment: keccak256("vector-match"),
                boundCandidateAliasCommitment: bytes32(0),
                anchorCount: 2,
                providerProofCommitment: keccak256("vector-provider-proof")
            })
        });
    }

    function testEmitAndPinVectors() public {
        Governance.BilateralSessionIntent memory intent = _intent();
        Governance.InitiationSignatures memory signatures = _signatures();
        ECDSAQuorumMatchVerifierV4.MatchEnvelope memory envelope = _envelope();

        // Deterministic deployment order, so these addresses are stable and the
        // JavaScript mirrors can be pinned against the same instances.
        assertEq(address(governance), 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, "governance");
        assertEq(address(verifier), 0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9, "verifier");
        assertEq(address(binder), 0xc7183455a4C133Ae270771860664b6B7ec320bB1, "binder");

        // Pinned: exactly the values the JavaScript mirrors must reproduce.
        assertEq(
            governance.intentHash(intent),
            0xb35378f88ae1b291f8fd2ea35b9f87cf955522ff95d7c0110e81bcd0db8f5002,
            "intentHash"
        );
        assertEq(
            governance.intentDigest(intent),
            0x847cd0d66df47501eff97c349435d3502c1dc1c7fa9a9f71e31bbfa5f4a170dc,
            "intentDigest"
        );
        assertEq(
            governance.signatureBundleDigest(signatures),
            0xd4cc601182fc9fccd2f6c79bf2d4284e259da247f3ac18c3e400d01bf5c6abf1,
            "signatureBundleDigest"
        );
        assertEq(
            governance.sessionCommitmentOf(intent, signatures, keccak256("vector-salt")),
            0x6affcc5733259b6d158cd5aa6cba092059f368ccbbdd89654299a20891ecfd73,
            "sessionCommitment"
        );
        assertEq(
            verifier.resultCoreCommitment(envelope),
            0xb28adf706ab41a3f731ef437fd09b8cb89797058446cc2fd7095f57ce0e2dee3,
            "resultCoreCommitment"
        );
        assertEq(
            verifier.resultDigest(envelope),
            0x995a99e0aca02ca57d25c1bd631b6fd503b8286949528411636016d85d8084ee,
            "resultDigest"
        );
        assertEq(
            verifier.attestationDigest(verifier.validatorSetId(), verifier.resultDigest(envelope)),
            0x5f49fdaaaf68ba54c7ed011ddd870244d4b7a6106ca0e5cfcbf2816fbf4f89d8,
            "attestationDigest"
        );
        assertEq(
            verifier.validatorSetId(),
            0x1328a50ed3a905a5c5cbb7549ddbfad81c1947c788b348a4be1102acba4eab9e,
            "validatorSetId"
        );
    }

    function testConsentDigestVector() public {
        // The binder reads controller identity, epoch and version from the named
        // governance record, so the vector needs a real authorization.
        bytes32 recordDigest = governance.authorize(
            Governance.AuthorizationRequest({
                scopeCommitment: SCOPE_A,
                controller: address(0x2001),
                controllerKeyId: keccak256("vector-key-a"),
                organizationId: keccak256("vector-org-a"),
                controllerEpoch: 1,
                authorizationVersion: 1,
                nonce: 1
            })
        );
        PrivateMatchBinder.DisclosureConsent memory consent = PrivateMatchBinder.DisclosureConsent({
            scopeCommitment: SCOPE_A,
            governanceRecord: recordDigest,
            disclosureVersion: 1,
            validUntil: 1_900_000_000,
            nonce: 99,
            signature: ""
        });
        bytes32 digest = binder.consentDigest(
            keccak256("vector-session-commitment"),
            keccak256("vector-result-commitment"),
            keccak256("vector-match"),
            address(0xDEC0DE),
            consent
        );
        assertEq(
            recordDigest,
            0x800387f0d89db8ba1404de28f091006c75df34b46fcb58fedbdd0c3872d4d59b,
            "recordDigest"
        );
        assertEq(
            digest,
            0xa9250b85ccd7a63524ca5b11306f44256f999cb6e103f1e13c54df7a928bbc0f,
            "consentDigest"
        );
    }
}
