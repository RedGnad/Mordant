// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Minimal deployed A-Pass view used by Mordant.
/// @dev The selector was verified against the Cleanverse Monad testnet deployment.
interface ICleanverseAPass {
    function isValidAPass(address account) external view returns (bool);
}
