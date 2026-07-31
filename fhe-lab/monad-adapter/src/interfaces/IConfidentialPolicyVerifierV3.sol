// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Provider-neutral confidential-policy result schema 3.
/// @dev V3 is intentionally separate from V2. It binds a result to one non-economic consumer and
/// leaves recourse consequences to that consumer's immutable/versioned on-chain policy.
struct ConfidentialPolicyResultV3 {
    uint256 chainId;
    address consumer;
    address vault;
    bytes32 policyId;
    uint32 policyVersion;
    bytes32 inputCommitmentA;
    bytes32 inputCommitmentB;
    bool conflictConfirmed;
    uint256 nonce;
    uint64 validUntil;
    bytes32 providerProofCommitment;
    bytes32 resultCommitment;
}

interface IConfidentialPolicyVerifierV3 {
    function acceptResult(ConfidentialPolicyResultV3 calldata result, bytes calldata attestation)
        external
        returns (bytes32 acceptedReplayKey);
}
