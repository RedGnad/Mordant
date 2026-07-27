// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { ICleanverseAPass } from "./ICleanverseAPass.sol";
import { ICleanverseAToken } from "./ICleanverseAToken.sol";
import { ICleanversePolicy } from "./ICleanversePolicy.sol";
import { ICviVerifier } from "../interfaces/ICviVerifier.sol";

/// @notice Combines live Cleanverse A-Pass validity with Mordant-specific role authorization.
/// @dev Roles selected in `openRoleMask` need no additional grant. A-Pass failure always fails closed.
contract CleanverseAPassVerifier is ICviVerifier, Ownable {
    uint8 public constant ROLE_BUYER = 1;
    uint8 public constant ROLE_ORIGINATOR = 2;
    uint8 public constant ROLE_FACILITY = 3;
    uint8 public constant ROLE_HOLDER = 4;

    ICleanverseAPass public immutable apass;
    uint256 public immutable openRoleMask;

    mapping(address account => uint256 roleMask) public grantedRoleMask;

    error InvalidConfiguration();

    event RoleEligibilitySet(address indexed account, uint8 indexed role, bool eligible);

    constructor(address initialOwner, ICleanverseAPass apass_, uint256 openRoleMask_)
        Ownable(initialOwner)
    {
        uint256 holderOnlyOpenRoleMask = uint256(1) << ROLE_HOLDER;
        if (
            initialOwner == address(0) || address(apass_) == address(0)
                || address(apass_).code.length == 0
                || (openRoleMask_ & ~holderOnlyOpenRoleMask) != 0
        ) revert InvalidConfiguration();

        apass = apass_;
        openRoleMask = openRoleMask_;
    }

    function setRoleEligibility(address account, uint8 role, bool eligible) external onlyOwner {
        uint256 bit = _roleBit(role);
        if (account == address(0) || bit == 0) revert InvalidConfiguration();

        if (eligible) {
            grantedRoleMask[account] |= bit;
        } else {
            grantedRoleMask[account] &= ~bit;
        }
        emit RoleEligibilitySet(account, role, eligible);
    }

    function hasValidIdentity(address account) external view returns (bool) {
        return _hasValidIdentity(account);
    }

    function isEligible(address account, uint8 role) external view returns (bool) {
        return _isEligible(account, role);
    }

    function isEligibleForAsset(
        address account,
        uint8 role,
        address asset,
        address custodian,
        uint256 amount
    ) external view returns (bool) {
        if (!_isEligible(account, role)) return false;
        if (role != ROLE_HOLDER) return true;
        if (asset == address(0) || asset.code.length == 0 || custodian == address(0)) {
            return false;
        }

        return _isAssetTransferAllowed(asset, custodian, account, amount);
    }

    function isAssetTransferAllowed(address asset, address from, address to, uint256 amount)
        external
        view
        returns (bool)
    {
        return _isAssetTransferAllowed(asset, from, to, amount);
    }

    function _isEligible(address account, uint8 role) private view returns (bool) {
        uint256 bit = _roleBit(role);
        if (
            account == address(0) || bit == 0
                || ((openRoleMask & bit) == 0 && (grantedRoleMask[account] & bit) == 0)
        ) return false;

        return _hasValidIdentity(account);
    }

    function _hasValidIdentity(address account) private view returns (bool) {
        if (account == address(0)) return false;
        try apass.isValidAPass(account) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }

    function _isAssetTransferAllowed(address asset, address from, address to, uint256 amount)
        private
        view
        returns (bool)
    {
        if (asset == address(0) || asset.code.length == 0) return false;
        try ICleanverseAToken(asset).policy() returns (address policy) {
            if (policy == address(0) || policy.code.length == 0) return false;
            try ICleanversePolicy(policy).canTransfer(asset, from, to, amount) returns (
                bool allowed
            ) {
                return allowed;
            } catch {
                return false;
            }
        } catch {
            return false;
        }
    }

    function _roleBit(uint8 role) private pure returns (uint256) {
        if (role < ROLE_BUYER || role > ROLE_HOLDER) return 0;
        return uint256(1) << role;
    }
}
