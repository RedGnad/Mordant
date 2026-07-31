// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Provider-neutral policy result. Commitments are opaque to this interface.
/// @dev Field order is part of the shared wire format and must not be changed in place.
struct ConfidentialPolicyResult {
    uint256 chainId;
    address vault;
    bytes32 policyId;
    uint32 policyVersion;
    bytes32 inputCommitmentA;
    bytes32 inputCommitmentB;
    bool conflictConfirmed;
    bytes32 responsibleRole;
    uint64 cureDeadline;
    uint256 nonce;
    uint64 validUntil;
    bytes32 resultCommitment;
}

interface IConfidentialPolicyVerifier {
    /// @notice Verify `abi.encode(bytes32 validatorSetId, bytes[] signatures)` without consuming it.
    function verifyResult(ConfidentialPolicyResult calldata result, bytes calldata attestation)
        external
        view
        returns (bool);
}
