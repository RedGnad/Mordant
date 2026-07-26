// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ICviVerifier } from "../interfaces/ICviVerifier.sol";

contract MockEligibility is ICviVerifier {
    mapping(address account => mapping(uint8 role => bool eligible)) public eligibility;

    function setEligible(address account, uint8 role, bool eligible) external {
        eligibility[account][role] = eligible;
    }

    function isEligible(address account, uint8 role) external view returns (bool) {
        return eligibility[account][role];
    }
}
