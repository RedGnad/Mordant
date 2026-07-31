// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ConfidentialPolicyResultV3,
    IConfidentialPolicyVerifierV3
} from "./interfaces/IConfidentialPolicyVerifierV3.sol";

/// @notice Isolated non-economic laboratory consumer for one confidential conflict policy.
/// @dev It cannot move assets, reserves, receivables, claims or settlement funds.
contract LaboratoryRecourseConsumer {
    error InvalidConfiguration();
    error AlreadyOpened(bytes32 resultCommitment);
    error ResultNotForConsumer(address supplied);
    error ResultNotConflict();
    error UnexpectedPolicy();

    enum RecourseStatus {
        None,
        Open
    }

    struct RecourseRecord {
        bytes32 resultCommitment;
        bytes32 providerProofCommitment;
        bytes32 inputCommitmentA;
        bytes32 inputCommitmentB;
        bytes32 policyId;
        uint32 policyVersion;
        bytes32 responsibleRole;
        bytes32 consequenceId;
        uint64 acceptedAt;
        uint64 cureDeadline;
        RecourseStatus status;
    }

    event LaboratoryRecourseOpened(
        bytes32 indexed resultCommitment,
        bytes32 indexed providerProofCommitment,
        address indexed vault,
        bytes32 policyId,
        uint32 policyVersion,
        bytes32 responsibleRole,
        uint64 cureDeadline,
        bytes32 consequenceId
    );

    IConfidentialPolicyVerifierV3 public immutable verifier;
    address public immutable vault;
    bytes32 public immutable policyId;
    uint32 public immutable policyVersion;
    bytes32 public immutable responsibleRole;
    uint64 public immutable curePeriod;
    bytes32 public immutable consequenceId;
    mapping(bytes32 resultCommitment => RecourseRecord record) public recourses;

    constructor(
        IConfidentialPolicyVerifierV3 verifier_,
        address vault_,
        bytes32 policyId_,
        uint32 policyVersion_,
        bytes32 responsibleRole_,
        uint64 curePeriod_,
        bytes32 consequenceId_
    ) {
        if (
            address(verifier_) == address(0) || vault_ == address(0) || policyId_ == bytes32(0)
                || policyVersion_ == 0 || responsibleRole_ == bytes32(0) || curePeriod_ == 0
                || consequenceId_ == bytes32(0)
        ) {
            revert InvalidConfiguration();
        }
        verifier = verifier_;
        vault = vault_;
        policyId = policyId_;
        policyVersion = policyVersion_;
        responsibleRole = responsibleRole_;
        curePeriod = curePeriod_;
        consequenceId = consequenceId_;
    }

    function openRecourse(ConfidentialPolicyResultV3 calldata result, bytes calldata attestation)
        external
    {
        if (result.consumer != address(this)) revert ResultNotForConsumer(result.consumer);
        if (!result.conflictConfirmed) revert ResultNotConflict();
        if (
            result.vault != vault || result.policyId != policyId
                || result.policyVersion != policyVersion
        ) {
            revert UnexpectedPolicy();
        }
        if (recourses[result.resultCommitment].status != RecourseStatus.None) {
            revert AlreadyOpened(result.resultCommitment);
        }

        verifier.acceptResult(result, attestation);
        uint64 acceptedAt = uint64(block.timestamp);
        uint64 cureDeadline = acceptedAt + curePeriod;
        recourses[result.resultCommitment] = RecourseRecord({
            resultCommitment: result.resultCommitment,
            providerProofCommitment: result.providerProofCommitment,
            inputCommitmentA: result.inputCommitmentA,
            inputCommitmentB: result.inputCommitmentB,
            policyId: result.policyId,
            policyVersion: result.policyVersion,
            responsibleRole: responsibleRole,
            consequenceId: consequenceId,
            acceptedAt: acceptedAt,
            cureDeadline: cureDeadline,
            status: RecourseStatus.Open
        });
        emit LaboratoryRecourseOpened(
            result.resultCommitment,
            result.providerProofCommitment,
            result.vault,
            result.policyId,
            result.policyVersion,
            responsibleRole,
            cureDeadline,
            consequenceId
        );
    }
}
