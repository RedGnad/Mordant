// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Provider-neutral policy result schema 2. Commitments are opaque to this interface.
/// @dev Field order is ABI-significant. Schema 2 appends providerProofCommitment before the final
///      resultCommitment and is intentionally incompatible with the schema-1 tuple selector.
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
    /// @notice Domain-separated commitment to the result ciphertext and threshold evidence.
    /// @dev A validator quorum endorses the commitment's preimage construction offchain.
    bytes32 providerProofCommitment;
    bytes32 resultCommitment;
}

interface IConfidentialPolicyVerifier {
    /// @notice Verify `abi.encode(bytes32 validatorSetId, bytes[] signatures)` without consuming it.
    function verifyResult(ConfidentialPolicyResult calldata result, bytes calldata attestation)
        external
        view
        returns (bool);
}
