// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ECDSAQuorumConfidentialPolicyVerifierV3
} from "../src/ECDSAQuorumConfidentialPolicyVerifierV3.sol";
import { LaboratoryRecourseConsumer } from "../src/LaboratoryRecourseConsumer.sol";
import {
    ConfidentialPolicyResultV3,
    IConfidentialPolicyVerifierV3
} from "../src/interfaces/IConfidentialPolicyVerifierV3.sol";

interface VmV3 {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function expectRevert() external;
}

contract V3LaboratoryRecourseTest {
    VmV3 private constant VM = VmV3(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY_A = 0xA11CE;
    uint256 private constant KEY_B = 0xB0B;
    uint256 private constant KEY_C = 0xCAFE;
    address private constant VAULT = address(0x1010);
    bytes32 private constant POLICY = keccak256("mordant.v3.conflict-policy");
    uint32 private constant VERSION = 7;
    bytes32 private constant ROLE = keccak256("mordant.role.facility.v1");
    bytes32 private constant CONSEQUENCE = keccak256("mordant.consequence.review-required.v1");

    ECDSAQuorumConfidentialPolicyVerifierV3 private verifier;
    LaboratoryRecourseConsumer private consumer;

    function setUp() public {
        address[] memory validators = new address[](3);
        validators[0] = VM.addr(KEY_A);
        validators[1] = VM.addr(KEY_B);
        validators[2] = VM.addr(KEY_C);
        verifier = new ECDSAQuorumConfidentialPolicyVerifierV3(address(this), validators, 2);
        verifier.setPolicyVersion(VAULT, POLICY, VERSION);
        consumer = new LaboratoryRecourseConsumer(
            IConfidentialPolicyVerifierV3(address(verifier)),
            VAULT,
            POLICY,
            VERSION,
            ROLE,
            3 days,
            CONSEQUENCE
        );
    }

    function testAtomicAcceptanceOpensDerivedNonEconomicRecourse() public {
        ConfidentialPolicyResultV3 memory result = _result(true);
        consumer.openRecourse(result, _attestation(result, 2));
        (
            bytes32 resultCommitment,
            bytes32 proof,
            bytes32 inputA,
            bytes32 inputB,
            bytes32 policy,
            uint32 version,
            bytes32 role,
            bytes32 consequence,
            uint64 acceptedAt,
            uint64 deadline,
            LaboratoryRecourseConsumer.RecourseStatus status
        ) = consumer.recourses(result.resultCommitment);
        _eq(resultCommitment, result.resultCommitment);
        _eq(proof, result.providerProofCommitment);
        _eq(inputA, result.inputCommitmentA);
        _eq(inputB, result.inputCommitmentB);
        _eq(policy, POLICY);
        require(
            version == VERSION && role == ROLE && consequence == CONSEQUENCE,
            "derived policy mismatch"
        );
        require(
            acceptedAt == block.timestamp && deadline == acceptedAt + 3 days, "deadline not derived"
        );
        require(status == LaboratoryRecourseConsumer.RecourseStatus.Open, "not open");
        require(verifier.consumedReplayKeys(verifier.replayKey(result)), "nonce not consumed");
        require(
            verifier.consumedProviderProofCommitments(result.providerProofCommitment),
            "proof not consumed"
        );
    }

    function testDirectVerifierBypassFailsAndDoesNotConsume() public {
        ConfidentialPolicyResultV3 memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert();
        verifier.acceptResult(result, attestation);
        require(
            !verifier.consumedReplayKeys(verifier.replayKey(result)),
            "consumed outside atomic transition"
        );
    }

    function testWrongConsumerFails() public {
        ConfidentialPolicyResultV3 memory result = _result(true);
        result.consumer = address(0xBEEF);
        result.resultCommitment = verifier.resultCoreCommitment(result);
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert();
        consumer.openRecourse(result, attestation);
    }

    function testWrongVaultPolicyAndVersionFailBeforeConsumption() public {
        ConfidentialPolicyResultV3 memory result = _result(true);
        result.vault = address(0x1011);
        result.resultCommitment = verifier.resultCoreCommitment(result);
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert(LaboratoryRecourseConsumer.UnexpectedPolicy.selector);
        consumer.openRecourse(result, attestation);

        result = _result(true);
        result.policyId = keccak256("wrong-policy");
        result.resultCommitment = verifier.resultCoreCommitment(result);
        attestation = _attestation(result, 2);
        VM.expectRevert(LaboratoryRecourseConsumer.UnexpectedPolicy.selector);
        consumer.openRecourse(result, attestation);

        result = _result(true);
        result.policyVersion = VERSION - 1;
        result.resultCommitment = verifier.resultCoreCommitment(result);
        attestation = _attestation(result, 2);
        VM.expectRevert(LaboratoryRecourseConsumer.UnexpectedPolicy.selector);
        consumer.openRecourse(result, attestation);
    }

    function testExpiredAndFalseConflictFailWithoutConsumption() public {
        ConfidentialPolicyResultV3 memory expired = _result(true);
        bytes memory expiredAttestation = _attestation(expired, 2);
        VM.warp(uint256(expired.validUntil) + 1);
        VM.expectRevert();
        consumer.openRecourse(expired, expiredAttestation);

        ConfidentialPolicyResultV3 memory negative = _result(false);
        bytes memory negativeAttestation = _attestation(negative, 2);
        VM.expectRevert(LaboratoryRecourseConsumer.ResultNotConflict.selector);
        consumer.openRecourse(negative, negativeAttestation);
        require(
            !verifier.consumedReplayKeys(verifier.replayKey(negative)), "negative result consumed"
        );
    }

    function testMutationOneValidatorAndDuplicateValidatorFail() public {
        ConfidentialPolicyResultV3 memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        result.conflictConfirmed = false;
        result.resultCommitment = verifier.resultCoreCommitment(result);
        VM.expectRevert();
        consumer.openRecourse(result, attestation);

        result = _result(true);
        result.providerProofCommitment = keccak256("mutated-proof");
        result.resultCommitment = verifier.resultCoreCommitment(result);
        bytes memory originalAttestation = _attestation(_result(true), 2);
        VM.expectRevert();
        consumer.openRecourse(result, originalAttestation);

        result = _result(true);
        bytes memory singleAttestation = _attestation(result, 1);
        VM.expectRevert();
        consumer.openRecourse(result, singleAttestation);

        bytes32 setId = verifier.validatorSetId();
        bytes32 digest = verifier.attestationDigest(setId, verifier.resultDigest(result));
        bytes memory signature = _signature(KEY_A, digest);
        bytes[] memory repeated = new bytes[](2);
        repeated[0] = signature;
        repeated[1] = signature;
        bytes memory duplicateAttestation = abi.encode(setId, repeated);
        VM.expectRevert();
        consumer.openRecourse(result, duplicateAttestation);
    }

    function testReplayNonceDecisionAndProviderProofCannotBeReused() public {
        ConfidentialPolicyResultV3 memory first = _result(true);
        consumer.openRecourse(first, _attestation(first, 2));

        ConfidentialPolicyResultV3 memory sameNonce = _result(true);
        sameNonce.inputCommitmentB = keccak256("same-nonce-new-input");
        sameNonce.resultCommitment = verifier.resultCoreCommitment(sameNonce);
        bytes memory sameNonceAttestation = _attestation(sameNonce, 2);
        VM.expectRevert();
        consumer.openRecourse(sameNonce, sameNonceAttestation);

        ConfidentialPolicyResultV3 memory sameDecision = _result(true);
        sameDecision.nonce += 1;
        sameDecision.resultCommitment = verifier.resultCoreCommitment(sameDecision);
        bytes memory sameDecisionAttestation = _attestation(sameDecision, 2);
        VM.expectRevert();
        consumer.openRecourse(sameDecision, sameDecisionAttestation);

        ConfidentialPolicyResultV3 memory sameProof = _result(true);
        sameProof.nonce += 2;
        sameProof.inputCommitmentA = keccak256("other-a");
        sameProof.inputCommitmentB = keccak256("other-b");
        sameProof.resultCommitment = verifier.resultCoreCommitment(sameProof);
        bytes memory sameProofAttestation = _attestation(sameProof, 2);
        VM.expectRevert();
        consumer.openRecourse(sameProof, sameProofAttestation);
    }

    function _result(bool conflict)
        private
        view
        returns (ConfidentialPolicyResultV3 memory result)
    {
        result = ConfidentialPolicyResultV3({
            chainId: block.chainid,
            consumer: address(consumer),
            vault: VAULT,
            policyId: POLICY,
            policyVersion: VERSION,
            inputCommitmentA: keccak256("public-input-a"),
            inputCommitmentB: keccak256("public-input-b"),
            conflictConfirmed: conflict,
            nonce: 91,
            validUntil: uint64(block.timestamp + 10 minutes),
            providerProofCommitment: keccak256("provider-proof-v3"),
            resultCommitment: bytes32(0)
        });
        result.resultCommitment = verifier.resultCoreCommitment(result);
    }

    function _attestation(ConfidentialPolicyResultV3 memory result, uint256 count)
        private
        returns (bytes memory)
    {
        uint256[] memory keys = new uint256[](count);
        keys[0] = KEY_A;
        if (count > 1) keys[1] = KEY_B;
        if (count > 2) keys[2] = KEY_C;
        bytes32 digest =
            verifier.attestationDigest(verifier.validatorSetId(), verifier.resultDigest(result));
        bytes[] memory signatures = new bytes[](count);
        address[] memory signers = new address[](count);
        for (uint256 i; i < count; ++i) {
            signers[i] = VM.addr(keys[i]);
            signatures[i] = _signature(keys[i], digest);
        }
        for (uint256 i; i < count; ++i) {
            for (uint256 j = i + 1; j < count; ++j) {
                if (signers[j] < signers[i]) {
                    (signers[i], signers[j]) = (signers[j], signers[i]);
                    (signatures[i], signatures[j]) = (signatures[j], signatures[i]);
                }
            }
        }
        return abi.encode(verifier.validatorSetId(), signatures);
    }

    function _signature(uint256 key, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _eq(bytes32 a, bytes32 b) private pure {
        require(a == b, "bytes32 mismatch");
    }
}
