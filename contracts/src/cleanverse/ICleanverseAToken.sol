// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Minimal A-Token surface proven on the deployed Cleanverse aUSDC implementation.
/// @dev A dedicated invoice A-Token must be checked against this ABI before it is bound.
interface ICleanverseAToken is IERC20 {
    function decimals() external view returns (uint8);

    function policy() external view returns (address);

    function MINTER_ROLE() external view returns (bytes32);

    function hasRole(bytes32 role, address account) external view returns (bool);

    function burn(address account, uint256 amount) external;
}
