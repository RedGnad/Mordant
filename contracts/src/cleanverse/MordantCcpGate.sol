// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Throwaway contract used to answer one question: can Mordant register a smart-contract
/// address with the Cleanverse APass Compliance Validator on Monad testnet, set a RuleV2 on it, and
/// read a compliance verdict back?
/// @dev Deliberately minimal, and deliberately not `Ownable` from OpenZeppelin. Cleanverse's signed
/// registration path is documented for contract addresses exposing `Ownable.owner()`, so the only
/// surface that matters here is that one getter. Keeping the contract to that getter means a failed
/// registration cannot be blamed on unrelated logic, a constructor side effect or an inherited
/// modifier. It is not part of the Mordant protocol and nothing depends on it.
///
/// Ownership is transferable so a spike deployment is never stranded with the wrong owner: whichever
/// key signed the registration message can hand the gate to another key without redeploying.
contract MordantCcpGate {
    /// @notice The address Cleanverse is expected to recover from the registration signature.
    address public owner;

    /// @notice Emitted on deployment so a gate is identifiable in logs without an ABI lookup.
    event GateDeployed(address indexed owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error OwnerIsZeroAddress();
    error CallerIsNotOwner(address caller);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert OwnerIsZeroAddress();
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
        emit GateDeployed(initialOwner);
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert CallerIsNotOwner(msg.sender);
        if (newOwner == address(0)) revert OwnerIsZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
