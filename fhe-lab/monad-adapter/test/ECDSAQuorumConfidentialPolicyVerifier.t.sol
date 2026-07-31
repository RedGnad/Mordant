// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ECDSAQuorumConfidentialPolicyVerifier
} from "../src/ECDSAQuorumConfidentialPolicyVerifier.sol";
import {
    ConfidentialPolicyResult,
    IConfidentialPolicyVerifier
} from "../src/interfaces/IConfidentialPolicyVerifier.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function chainId(uint256 newChainId) external;
    function expectEmit(
        bool checkTopic1,
        bool checkTopic2,
        bool checkTopic3,
        bool checkData,
        address emitter
    ) external;
    function expectPartialRevert(bytes4 revertData) external;
    function expectRevert() external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 newTimestamp) external;
}

contract ExactInterfaceConsumer {
    function verify(
        IConfidentialPolicyVerifier verifier,
        ConfidentialPolicyResult calldata result,
        bytes calldata attestation
    ) external view returns (bool) {
        return verifier.verifyResult(result, attestation);
    }
}

contract ECDSAQuorumConfidentialPolicyVerifierTest {
    event ConfidentialPolicyResultAccepted(
        bytes32 indexed resultCommitment,
        bytes32 indexed policyId,
        address indexed vault,
        uint32 policyVersion,
        uint256 nonce,
        bool conflictConfirmed
    );

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant VALIDATOR_KEY_A = 0xA11CE;
    uint256 private constant VALIDATOR_KEY_B = 0xB0B;
    uint256 private constant VALIDATOR_KEY_C = 0xCAFE;
    uint32 private constant POLICY_VERSION = 3;

    address private constant VAULT_A = address(0x1001);
    address private constant VAULT_B = address(0x1002);
    bytes32 private constant POLICY_ID = keccak256("conflicting-pledge");

    ECDSAQuorumConfidentialPolicyVerifier private verifier;
    address private validatorA;
    address private validatorB;
    address private validatorC;

    function setUp() public {
        validatorA = vm.addr(VALIDATOR_KEY_A);
        validatorB = vm.addr(VALIDATOR_KEY_B);
        validatorC = vm.addr(VALIDATOR_KEY_C);

        address[] memory initialValidators = new address[](3);
        initialValidators[0] = validatorA;
        initialValidators[1] = validatorB;
        initialValidators[2] = validatorC;
        verifier = new ECDSAQuorumConfidentialPolicyVerifier(address(this), initialValidators, 2);
        verifier.setPolicyVersion(VAULT_A, POLICY_ID, POLICY_VERSION);
        verifier.setPolicyVersion(VAULT_B, POLICY_ID, POLICY_VERSION);
    }

    function testExactRequiredInterface() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        ExactInterfaceConsumer consumer = new ExactInterfaceConsumer();

        _assertTrue(
            consumer.verify(IConfidentialPolicyVerifier(address(verifier)), result, attestation)
        );
        _assertEqSelector(
            IConfidentialPolicyVerifier.verifyResult.selector,
            bytes4(
                keccak256(
                    "verifyResult((uint256,address,bytes32,uint32,bytes32,bytes32,bool,bytes32,uint64,uint256,uint64,bytes32),bytes)"
                )
            )
        );
    }

    function testVerifyResultIsViewAndDoesNotConsume() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        bytes32 key = verifier.replayKey(result);

        _assertTrue(verifier.verifyResult(result, attestation));
        _assertTrue(verifier.verifyResult(result, attestation));
        _assertFalse(verifier.consumedReplayKeys(key));
    }

    function testAcceptResultConsumesExactReplayKeyAndEmits() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes32 key =
            keccak256(abi.encode(result.chainId, result.vault, result.policyId, result.nonce));
        bytes memory attestation = _attestation(result, 2);

        vm.expectEmit(true, true, true, true, address(verifier));
        emit ConfidentialPolicyResultAccepted(
            result.resultCommitment,
            result.policyId,
            result.vault,
            result.policyVersion,
            result.nonce,
            result.conflictConfirmed
        );
        bytes32 acceptedKey = verifier.acceptResult(result, attestation);

        _assertEq(acceptedKey, key);
        _assertTrue(verifier.consumedReplayKeys(key));
    }

    function testReplayKeyRejectsDifferentResultWithSameChainVaultPolicyAndNonce() public {
        ConfidentialPolicyResult memory first = _result(true);
        verifier.acceptResult(first, _attestation(first, 2));

        ConfidentialPolicyResult memory second = _result(true);
        second.inputCommitmentB = keccak256("different-input");
        second.resultCommitment = verifier.resultCoreCommitment(second);
        bytes32 key = verifier.replayKey(second);
        bytes memory secondAttestation = _attestation(second, 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.ReplayAlreadyConsumed.selector, key
            )
        );
        verifier.acceptResult(second, secondAttestation);
    }

    function testDecisionKeyRejectsEquivocationWithAnotherNonceAndResult() public {
        ConfidentialPolicyResult memory first = _result(true);
        bytes32 firstDecisionKey = verifier.decisionKey(first);
        verifier.acceptResult(first, _attestation(first, 2));

        ConfidentialPolicyResult memory competing = _result(false);
        competing.inputCommitmentA = first.inputCommitmentB;
        competing.inputCommitmentB = first.inputCommitmentA;
        competing.nonce = first.nonce + 1;
        competing.resultCommitment = verifier.resultCoreCommitment(competing);
        bytes32 competingDecisionKey = verifier.decisionKey(competing);
        bytes memory competingAttestation = _attestation(competing, 2);

        _assertEq(competingDecisionKey, firstDecisionKey);
        _assertNotEq(verifier.replayKey(competing), verifier.replayKey(first));
        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.DecisionAlreadyConsumed.selector,
                firstDecisionKey
            )
        );
        verifier.acceptResult(competing, competingAttestation);
    }

    function testPolicyDisablePreservesLatestAndRejectsSignedResult() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        verifier.setPolicyVersion(VAULT_A, POLICY_ID, 0);

        _assertEq(uint256(verifier.currentPolicyVersion(VAULT_A, POLICY_ID)), 0);
        _assertEq(uint256(verifier.latestPolicyVersion(VAULT_A, POLICY_ID)), POLICY_VERSION);
        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.PolicyNotConfigured.selector,
                VAULT_A,
                POLICY_ID
            )
        );
        verifier.verifyResult(result, attestation);
    }

    function testStalePolicyCannotBeReenabledAfterDisable() public {
        ConfidentialPolicyResult memory staleResult = _result(true);
        bytes memory staleAttestation = _attestation(staleResult, 2);
        verifier.setPolicyVersion(VAULT_A, POLICY_ID, 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.PolicyVersionNotIncreasing.selector,
                POLICY_VERSION,
                POLICY_VERSION
            )
        );
        verifier.setPolicyVersion(VAULT_A, POLICY_ID, POLICY_VERSION);

        uint32 nextVersion = POLICY_VERSION + 1;
        verifier.setPolicyVersion(VAULT_A, POLICY_ID, nextVersion);
        _assertEq(uint256(verifier.currentPolicyVersion(VAULT_A, POLICY_ID)), nextVersion);
        _assertEq(uint256(verifier.latestPolicyVersion(VAULT_A, POLICY_ID)), nextVersion);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.PolicyVersionMismatch.selector,
                POLICY_VERSION,
                nextVersion
            )
        );
        verifier.verifyResult(staleResult, staleAttestation);

        ConfidentialPolicyResult memory currentResult = _result(true);
        currentResult.policyVersion = nextVersion;
        currentResult.resultCommitment = verifier.resultCoreCommitment(currentResult);
        _assertTrue(verifier.verifyResult(currentResult, _attestation(currentResult, 2)));
    }

    function testObsoleteValidatorSetIsRejectedAfterQuorumRotation() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes32 oldSetId = verifier.validatorSetId();
        bytes memory oldAttestation = _attestation(result, 2);
        verifier.setQuorum(3);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.ValidatorSetMismatch.selector,
                oldSetId,
                verifier.validatorSetId()
            )
        );
        verifier.verifyResult(result, oldAttestation);
    }

    function testValidatorMutationRotatesSet() public {
        bytes32 previousSet = verifier.validatorSetId();
        uint64 previousEpoch = verifier.validatorSetEpoch();
        verifier.setValidator(validatorC, false);

        _assertNotEq(verifier.validatorSetId(), previousSet);
        _assertEq(uint256(verifier.validatorSetEpoch()), uint256(previousEpoch) + 1);
    }

    function testInvalidResultCommitmentIsRejected() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        result.resultCommitment = keccak256("fabricated-commitment");

        vm.expectPartialRevert(
            ECDSAQuorumConfidentialPolicyVerifier.InvalidResultCommitment.selector
        );
        verifier.verifyResult(result, attestation);
    }

    function testFalseResultRequiresZeroRoleAndDeadline() public {
        ConfidentialPolicyResult memory validResult = _result(false);
        _assertTrue(verifier.verifyResult(validResult, _attestation(validResult, 2)));

        ConfidentialPolicyResult memory invalidResult = _result(false);
        invalidResult.responsibleRole = keccak256("FACILITY_B");
        invalidResult.cureDeadline = uint64(block.timestamp + 1 days);
        invalidResult.resultCommitment = verifier.resultCoreCommitment(invalidResult);
        bytes memory invalidAttestation = _attestation(invalidResult, 2);

        vm.expectPartialRevert(ECDSAQuorumConfidentialPolicyVerifier.InvalidNegativeResult.selector);
        verifier.verifyResult(invalidResult, invalidAttestation);
    }

    function testTrueResultRequiresNonzeroRoleAndDeadline() public {
        ConfidentialPolicyResult memory noRole = _result(true);
        noRole.responsibleRole = bytes32(0);
        noRole.resultCommitment = verifier.resultCoreCommitment(noRole);
        bytes memory noRoleAttestation = _attestation(noRole, 2);
        vm.expectPartialRevert(ECDSAQuorumConfidentialPolicyVerifier.InvalidPositiveResult.selector);
        verifier.verifyResult(noRole, noRoleAttestation);

        ConfidentialPolicyResult memory noDeadline = _result(true);
        noDeadline.cureDeadline = 0;
        noDeadline.resultCommitment = verifier.resultCoreCommitment(noDeadline);
        bytes memory noDeadlineAttestation = _attestation(noDeadline, 2);
        vm.expectPartialRevert(ECDSAQuorumConfidentialPolicyVerifier.InvalidPositiveResult.selector);
        verifier.verifyResult(noDeadline, noDeadlineAttestation);
    }

    function testExpiredResultIsRejected() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);
        vm.warp(uint256(result.validUntil) + 1);

        vm.expectPartialRevert(ECDSAQuorumConfidentialPolicyVerifier.ResultExpired.selector);
        verifier.verifyResult(result, attestation);
    }

    function testStalePolicyVersionIsRejected() public {
        ConfidentialPolicyResult memory result = _result(true);
        result.policyVersion = POLICY_VERSION - 1;
        result.resultCommitment = verifier.resultCoreCommitment(result);
        bytes memory attestation = _attestation(result, 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.PolicyVersionMismatch.selector,
                POLICY_VERSION - 1,
                POLICY_VERSION
            )
        );
        verifier.verifyResult(result, attestation);
    }

    function testAttestationCannotMoveToAnotherVault() public {
        ConfidentialPolicyResult memory signedResult = _result(true);
        bytes memory attestation = _attestation(signedResult, 2);

        ConfidentialPolicyResult memory transplanted = signedResult;
        transplanted.vault = VAULT_B;
        transplanted.resultCommitment = verifier.resultCoreCommitment(transplanted);

        vm.expectRevert();
        verifier.verifyResult(transplanted, attestation);
    }

    function testAttestationCannotMoveToAnotherChain() public {
        ConfidentialPolicyResult memory signedResult = _result(true);
        bytes memory attestation = _attestation(signedResult, 2);
        vm.chainId(block.chainid + 1);

        ConfidentialPolicyResult memory transplanted = signedResult;
        transplanted.chainId = block.chainid;
        transplanted.resultCommitment = verifier.resultCoreCommitment(transplanted);

        vm.expectRevert();
        verifier.verifyResult(transplanted, attestation);
    }

    function testInputsAndResultAreBoundByNestedAttestation() public {
        ConfidentialPolicyResult memory signedResult = _result(true);
        bytes memory attestation = _attestation(signedResult, 2);

        ConfidentialPolicyResult memory changedInput = signedResult;
        changedInput.inputCommitmentB = keccak256("tampered-input");
        changedInput.resultCommitment = verifier.resultCoreCommitment(changedInput);
        vm.expectRevert();
        verifier.verifyResult(changedInput, attestation);

        ConfidentialPolicyResult memory changedRole = signedResult;
        changedRole.responsibleRole = keccak256("DIFFERENT_ROLE");
        changedRole.resultCommitment = verifier.resultCoreCommitment(changedRole);
        vm.expectRevert();
        verifier.verifyResult(changedRole, attestation);
    }

    function testRevokedValidatorDoesNotCountInCurrentSet() public {
        verifier.setValidator(validatorA, false);
        ConfidentialPolicyResult memory result = _result(true);
        uint256[] memory keys = new uint256[](2);
        keys[0] = VALIDATOR_KEY_A;
        keys[1] = VALIDATOR_KEY_B;
        bytes memory attestation = _attestationWithKeys(result, keys);

        vm.expectPartialRevert(ECDSAQuorumConfidentialPolicyVerifier.ValidatorNotActive.selector);
        verifier.verifyResult(result, attestation);
    }

    function testQuorumIsConfigurable() public {
        verifier.setQuorum(3);
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory insufficientAttestation = _attestation(result, 2);

        vm.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifier.InsufficientSignatures.selector, 2, 3
            )
        );
        verifier.verifyResult(result, insufficientAttestation);

        _assertTrue(verifier.verifyResult(result, _attestation(result, 3)));
    }

    function testDuplicateValidatorSignatureIsRejected() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes32 resultHash = verifier.resultDigest(result);
        bytes32 signedDigest = verifier.attestationDigest(verifier.validatorSetId(), resultHash);
        bytes memory duplicate = _signature(VALIDATOR_KEY_A, signedDigest);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = duplicate;
        signatures[1] = duplicate;
        bytes memory attestation = abi.encode(verifier.validatorSetId(), signatures);

        vm.expectPartialRevert(
            ECDSAQuorumConfidentialPolicyVerifier.SignersNotStrictlyIncreasing.selector
        );
        verifier.verifyResult(result, attestation);
    }

    function testAttestationCannotMoveToAnotherVerifierContract() public {
        ConfidentialPolicyResult memory result = _result(true);
        bytes memory attestation = _attestation(result, 2);

        address[] memory initialValidators = new address[](3);
        initialValidators[0] = validatorA;
        initialValidators[1] = validatorB;
        initialValidators[2] = validatorC;
        ECDSAQuorumConfidentialPolicyVerifier secondVerifier =
            new ECDSAQuorumConfidentialPolicyVerifier(address(this), initialValidators, 2);
        secondVerifier.setPolicyVersion(VAULT_A, POLICY_ID, POLICY_VERSION);

        vm.expectRevert();
        secondVerifier.verifyResult(result, attestation);
    }

    function _result(bool conflict) private view returns (ConfidentialPolicyResult memory result) {
        result = ConfidentialPolicyResult({
            chainId: block.chainid,
            vault: VAULT_A,
            policyId: POLICY_ID,
            policyVersion: POLICY_VERSION,
            inputCommitmentA: keccak256("invoice-root-and-position"),
            inputCommitmentB: keccak256("conflicting-claim"),
            conflictConfirmed: conflict,
            responsibleRole: conflict ? keccak256("mordant.role.facility.v1") : bytes32(0),
            cureDeadline: conflict ? uint64(block.timestamp + 1 days) : 0,
            nonce: 41,
            validUntil: uint64(block.timestamp + 10 minutes),
            resultCommitment: bytes32(0)
        });
        result.resultCommitment = verifier.resultCoreCommitment(result);
    }

    function _attestation(ConfidentialPolicyResult memory result, uint256 count)
        private
        returns (bytes memory)
    {
        uint256[] memory keys = new uint256[](count);
        keys[0] = VALIDATOR_KEY_A;
        if (count > 1) keys[1] = VALIDATOR_KEY_B;
        if (count > 2) keys[2] = VALIDATOR_KEY_C;
        return _attestationWithKeys(result, keys);
    }

    function _attestationWithKeys(ConfidentialPolicyResult memory result, uint256[] memory keys)
        private
        returns (bytes memory)
    {
        bytes32 setId = verifier.validatorSetId();
        bytes32 signedDigest = verifier.attestationDigest(setId, verifier.resultDigest(result));
        bytes[] memory signatures = new bytes[](keys.length);
        address[] memory signers = new address[](keys.length);
        for (uint256 index; index < keys.length; ++index) {
            signers[index] = vm.addr(keys[index]);
            signatures[index] = _signature(keys[index], signedDigest);
        }

        for (uint256 outer; outer < keys.length; ++outer) {
            for (uint256 inner = outer + 1; inner < keys.length; ++inner) {
                if (signers[inner] < signers[outer]) {
                    (signers[outer], signers[inner]) = (signers[inner], signers[outer]);
                    (signatures[outer], signatures[inner]) = (signatures[inner], signatures[outer]);
                }
            }
        }
        return abi.encode(setId, signatures);
    }

    function _signature(uint256 privateKey, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _assertTrue(bool value) private pure {
        require(value, "assert true failed");
    }

    function _assertFalse(bool value) private pure {
        require(!value, "assert false failed");
    }

    function _assertEq(bytes32 actual, bytes32 expected) private pure {
        require(actual == expected, "bytes32 equality failed");
    }

    function _assertEqSelector(bytes4 actual, bytes4 expected) private pure {
        require(actual == expected, "bytes4 equality failed");
    }

    function _assertEq(uint256 actual, uint256 expected) private pure {
        require(actual == expected, "uint256 equality failed");
    }

    function _assertNotEq(bytes32 actual, bytes32 expected) private pure {
        require(actual != expected, "bytes32 inequality failed");
    }
}
