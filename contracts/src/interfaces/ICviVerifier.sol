// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Sponsor adapter boundary. It intentionally does not assume a Cleanverse ABI.
interface ICviVerifier {
    function isEligible(address account, uint8 role) external view returns (bool);
}
