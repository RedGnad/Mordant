// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";

import { MordantMatchResultV5 as Outcomes } from "../src/identity/MordantMatchResultV5.sol";
import { MordantMatchVerifierV5 as Verifier } from "../src/v5/MordantMatchVerifierV5.sol";
import { MordantResultCoreV5 as Core } from "../src/v5/MordantResultCoreV5.sol";
import {
    MordantScopeGovernanceRegistryV5 as Governance
} from "../src/v5/MordantScopeGovernanceRegistryV5.sol";
import {
    MordantSourceCommitmentRegistry as Sources
} from "../src/v5/MordantSourceCommitmentRegistry.sol";
import { MordantIssuerRegistry } from "../src/identity/MordantIssuerRegistry.sol";
import {
    IFactoryAdmission,
    PrivateMatchBinderV5 as Binder
} from "../src/v5/PrivateMatchBinderV5.sol";

/// @notice Pinned vectors for the three digests a producer must reproduce
/// before it signs anything: the V5 result struct hash, the V5 result
/// commitment, and the disclosure-consent digest.
///
/// @dev The deployed contract is the canonical checker. A runner that derives
/// any of these itself and disagrees would sign a value the chain rejects, and
/// would learn that only after broadcast. These vectors let the disagreement be
/// caught in CI instead.
///
/// The consent vector is emitted for BOTH sides, with different source-record
/// commitments, because the corrected binder binds each side's own source and a
/// mirror that reused side A's for both would otherwise look correct.
contract V5DigestVectorsTest is Test {
    uint256 private constant CHAIN_ID = 10_143;
    bytes32 private constant POLICY_ID = keccak256("mordant.policy.v5");
    uint32 private constant POLICY_VERSION = 1;
    address private constant ANCHOR = address(0x4444444444444444444444444444444444444444);

    // Pinned. Regenerate only as a deliberate, versioned schema change.
    bytes32 private constant EXPECTED_STRUCT_HASH =
        0x0dcf27cfe4c90449bf1128ce4001004ba73f00dea8153a7bf53aac95bf9829da;
    bytes32 private constant EXPECTED_RESULT_COMMITMENT =
        0x990cec9a6605b88cfd03a2175321b1021a46b5452d2b66622032aab47f8bf2f2;
    bytes32 private constant EXPECTED_CONSENT_A =
        0x1e428406d6c02db320077c296a87ff49a95e8b54503b20ace9416507b390bd16;
    bytes32 private constant EXPECTED_CONSENT_B =
        0xf6ffa1b3cbe1602532566dd6b52e32eb67db96b46e0d39777288cdbc8146ecfc;

    Verifier private verifier;
    Binder private binder;

    function setUp() public {
        vm.chainId(CHAIN_ID);
        Governance governance = new Governance(address(this));
        MordantIssuerRegistry issuers = new MordantIssuerRegistry(address(this));
        Sources sources = new Sources(address(this), issuers);
        address[] memory validators = new address[](3);
        validators[0] = address(0xA1);
        validators[1] = address(0xB2);
        validators[2] = address(0xC3);
        verifier = new Verifier(address(this), governance, validators, 2, 2);
        binder = new Binder(
            verifier,
            governance,
            sources,
            IFactoryAdmission(address(0xF1)),
            POLICY_ID,
            POLICY_VERSION,
            7 days,
            keccak256("consequence")
        );
    }

    /// @dev Every field distinct and non-zero, so a transposition changes the
    /// digest. `binder` and `verifier` are the deployed addresses, which is why
    /// the vectors are asserted through the contracts rather than hard-coded
    /// against a fixed address.
    function core() public view returns (Core.ResultCore memory value) {
        value.schemaVersion = Core.RESULT_SCHEMA_VERSION;
        value.chainId = CHAIN_ID;
        value.verifier = address(verifier);
        value.binder = address(binder);
        value.policyId = POLICY_ID;
        value.policyVersion = POLICY_VERSION;
        value.session = Core.SessionBinding({
            sessionCommitment: keccak256("vector.sessionCommitment"),
            sessionNullifier: keccak256("vector.sessionNullifier"),
            governanceContext: keccak256("vector.governanceContext"),
            sourceRecordCommitmentA: keccak256("vector.sourceA"),
            sourceRecordCommitmentB: keccak256("vector.sourceB"),
            enrollmentDigestA: keccak256("vector.enrollmentA"),
            enrollmentDigestB: keccak256("vector.enrollmentB")
        });
        value.evaluation = Core.EvaluationBinding({
            ciphertextDigestA: keccak256("vector.ciphertextA"),
            ciphertextDigestB: keccak256("vector.ciphertextB"),
            inputCommitmentA: keccak256("vector.inputA"),
            inputCommitmentB: keccak256("vector.inputB"),
            outputCiphertextCommitment: keccak256("vector.output"),
            circuitHash: keccak256("vector.circuit"),
            circuitVersion: Core.CIRCUIT_VERSION,
            releaseLayoutVersion: Core.RELEASE_LAYOUT_VERSION,
            parameterFingerprint: keccak256("vector.parameters"),
            evaluationKeyEpoch: 1,
            evaluationKeyDigest: keccak256("vector.evaluationKeys"),
            runtimeFingerprint: keccak256("vector.runtime"),
            providerProofCommitment: keccak256("vector.providerProof")
        });
        value.sameEconomicAsset = true;
        value.policyConflict = true;
        value.outcome = Outcomes.Outcome.SameAssetPolicyConflict;
        value.nonce = 42;
        value.expiry = 1_900_000_000;
    }

    function consent(bytes32 scope, bytes32 record, uint256 nonce)
        public
        pure
        returns (Binder.DisclosureConsent memory)
    {
        return Binder.DisclosureConsent({
            scopeCommitment: scope,
            governanceRecord: record,
            disclosureVersion: POLICY_VERSION,
            validUntil: 1_900_000_000,
            nonce: nonce,
            signature: ""
        });
    }

    function testEmitVectors() public view {
        Core.ResultCore memory value = core();
        console.log("VERIFIER");
        console.log(address(verifier));
        console.log("BINDER");
        console.log(address(binder));
        console.log("STRUCT_HASH");
        console.logBytes32(verifier.resultStructHash(value));
        console.log("RESULT_COMMITMENT");
        console.logBytes32(verifier.resultCommitmentOf(value));
        console.log("CONSENT_A");
        console.logBytes32(
            binder.consentDigest(
                value.session.sessionCommitment,
                value.session.sessionNullifier,
                verifier.resultCommitmentOf(value),
                value.session.sourceRecordCommitmentA,
                ANCHOR,
                consent(keccak256("vector.scopeA"), keccak256("vector.recordA"), 1)
            )
        );
        console.log("CONSENT_B");
        console.logBytes32(
            binder.consentDigest(
                value.session.sessionCommitment,
                value.session.sessionNullifier,
                verifier.resultCommitmentOf(value),
                value.session.sourceRecordCommitmentB,
                ANCHOR,
                consent(keccak256("vector.scopeB"), keccak256("vector.recordB"), 2)
            )
        );
        console.log("BINDER_DOMAIN_SEPARATOR");
        console.logBytes32(binder.domainSeparator());
        console.log("VERIFIER_DOMAIN_SEPARATOR");
        console.logBytes32(verifier.domainSeparator());
        console.log("CONSENT_TYPEHASH");
        console.logBytes32(binder.CONSENT_TYPEHASH());
    }

    function testPinned() public view {
        Core.ResultCore memory value = core();
        assertEq(verifier.resultStructHash(value), EXPECTED_STRUCT_HASH, "structHash");
        assertEq(verifier.resultCommitmentOf(value), EXPECTED_RESULT_COMMITMENT, "resultCommitment");
        bytes32 commitment = verifier.resultCommitmentOf(value);
        assertEq(
            binder.consentDigest(
                value.session.sessionCommitment,
                value.session.sessionNullifier,
                commitment,
                value.session.sourceRecordCommitmentA,
                ANCHOR,
                consent(keccak256("vector.scopeA"), keccak256("vector.recordA"), 1)
            ),
            EXPECTED_CONSENT_A,
            "consent A"
        );
        assertEq(
            binder.consentDigest(
                value.session.sessionCommitment,
                value.session.sessionNullifier,
                commitment,
                value.session.sourceRecordCommitmentB,
                ANCHOR,
                consent(keccak256("vector.scopeB"), keccak256("vector.recordB"), 2)
            ),
            EXPECTED_CONSENT_B,
            "consent B"
        );
    }

    /// The commitment and the struct hash must be different preimages, or a
    /// signature over one could be replayed as the other.
    function testCommitmentIsNotTheStructHash() public view {
        Core.ResultCore memory value = core();
        assertTrue(verifier.resultCommitmentOf(value) != verifier.resultStructHash(value));
    }

    /// The corrected binder binds each side's OWN source record. A mirror that
    /// reused side A's for both sides would produce equal digests here.
    function testTheTwoConsentDigestsDiffer() public view {
        Core.ResultCore memory value = core();
        bytes32 commitment = verifier.resultCommitmentOf(value);
        bytes32 a = binder.consentDigest(
            value.session.sessionCommitment,
            value.session.sessionNullifier,
            commitment,
            value.session.sourceRecordCommitmentA,
            ANCHOR,
            consent(keccak256("vector.scopeA"), keccak256("vector.recordA"), 1)
        );
        bytes32 b = binder.consentDigest(
            value.session.sessionCommitment,
            value.session.sessionNullifier,
            commitment,
            value.session.sourceRecordCommitmentB,
            ANCHOR,
            consent(keccak256("vector.scopeB"), keccak256("vector.recordB"), 2)
        );
        assertTrue(a != b, "each side must bind its own source record");
    }

    /// The source record is genuinely inside the consent digest. Without this,
    /// swapping the two sides' sources would go unnoticed.
    function testTheSourceRecordIsCoveredByTheConsentDigest() public view {
        Core.ResultCore memory value = core();
        bytes32 commitment = verifier.resultCommitmentOf(value);
        Binder.DisclosureConsent memory one =
            consent(keccak256("vector.scopeA"), keccak256("vector.recordA"), 1);
        bytes32 withA = binder.consentDigest(
            value.session.sessionCommitment,
            value.session.sessionNullifier,
            commitment,
            value.session.sourceRecordCommitmentA,
            ANCHOR,
            one
        );
        bytes32 withB = binder.consentDigest(
            value.session.sessionCommitment,
            value.session.sessionNullifier,
            commitment,
            value.session.sourceRecordCommitmentB,
            ANCHOR,
            one
        );
        assertTrue(withA != withB, "source record must be covered");
    }
}
