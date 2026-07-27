// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal transfer-policy surface exposed by Cleanverse A-Tokens.
interface ICleanversePolicy {
    function canTransfer(address token, address from, address to, uint256 amount)
        external
        view
        returns (bool);
}
