// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ICviVerifier } from "../interfaces/ICviVerifier.sol";

contract MockEligibility is ICviVerifier {
    mapping(address account => mapping(uint8 role => bool eligible)) public eligibility;
    mapping(address account => mapping(uint8 role => bool denied)) public assetIneligibility;
    mapping(address account => bool valid) public identityValidity;

    function setIdentityValid(address account, bool valid_) external {
        identityValidity[account] = valid_;
    }

    function setEligible(address account, uint8 role, bool eligible) external {
        eligibility[account][role] = eligible;
    }

    function setAssetEligible(address account, uint8 role, bool eligible) external {
        assetIneligibility[account][role] = !eligible;
    }

    function isEligible(address account, uint8 role) external view returns (bool) {
        return eligibility[account][role];
    }

    function hasValidIdentity(address account) external view returns (bool) {
        return identityValidity[account];
    }

    function isEligibleForAsset(address account, uint8 role, address, address, uint256)
        external
        view
        returns (bool)
    {
        return eligibility[account][role] && !assetIneligibility[account][role];
    }

    function isAssetTransferAllowed(address, address, address, uint256)
        external
        pure
        returns (bool)
    {
        return true;
    }
}
