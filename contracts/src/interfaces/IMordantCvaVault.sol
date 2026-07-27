// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Immutable fields a CVA adapter verifies before accepting a one-time vault binding.
interface IMordantCvaVault {
    function cvaAdapter() external view returns (address);

    function cvaToken() external view returns (address);

    function initialUnits() external view returns (uint256);
}
