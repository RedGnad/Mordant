// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import { ICleanverseAPass } from "./ICleanverseAPass.sol";
import { ICleanverseAToken } from "./ICleanverseAToken.sol";
import { ICleanversePolicy } from "./ICleanversePolicy.sol";
import { ICvaAdapter } from "../interfaces/ICvaAdapter.sol";
import { IMordantCvaVault } from "../interfaces/IMordantCvaVault.sol";

/// @notice Single-invoice custody adapter for a Cleanverse A-Token.
/// @dev The adapter needs its own A-Pass and the A-Token MINTER_ROLE before activation.
contract CleanverseCvaAdapter is ICvaAdapter, Ownable, ReentrancyGuard {
    using SafeERC20 for ICleanverseAToken;

    uint8 public constant EXPECTED_DECIMALS = 6;

    ICleanverseAToken public immutable token;
    ICleanverseAPass public immutable apass;
    address public boundVault;
    uint256 private custodyCredit;

    error InvalidConfiguration();
    error AlreadyBound();
    error UnauthorizedVault();
    error InsufficientCredit();
    error AccountingMismatch();
    error InvalidCustodyIdentity();
    error MissingMinterRole();
    error TransferPolicyDenied();
    error InvalidTokenDecimals(uint8 actual);

    event VaultBound(address indexed vault, uint256 units);
    event CreditConsumed(address indexed vault, uint256 units);
    event CreditReleased(address indexed vault, address indexed holder, uint256 units);

    constructor(address initialOwner, ICleanverseAToken token_, ICleanverseAPass apass_)
        Ownable(initialOwner)
    {
        if (
            initialOwner == address(0) || address(token_) == address(0)
                || address(token_).code.length == 0 || address(apass_) == address(0)
                || address(apass_).code.length == 0
        ) revert InvalidConfiguration();
        token = token_;
        apass = apass_;
    }

    /// @notice Irrevocably binds the complete dedicated token supply to one Mordant vault.
    function bindVault(address vault, uint256 units) external onlyOwner {
        if (boundVault != address(0)) revert AlreadyBound();
        if (vault == address(0) || vault.code.length == 0 || units == 0) {
            revert InvalidConfiguration();
        }
        _validateVaultBinding(vault, units);
        _requireExpectedDecimals();
        if (!_hasValidAPass()) revert InvalidCustodyIdentity();
        if (!_hasMinterRole()) revert MissingMinterRole();
        if (token.totalSupply() != units || token.balanceOf(address(this)) != units) {
            revert AccountingMismatch();
        }

        boundVault = vault;
        custodyCredit = units;
        emit VaultBound(vault, units);
    }

    function asset() external view returns (address) {
        return address(token);
    }

    function issuedSupply() external view returns (uint256) {
        _requireExpectedDecimals();
        return token.totalSupply();
    }

    function availableBalance(address vault) external view returns (uint256) {
        if (vault != boundVault) return 0;
        _requireExpectedDecimals();
        if (token.balanceOf(address(this)) < custodyCredit) revert AccountingMismatch();
        return custodyCredit;
    }

    function isActivationReady(address vault) external view returns (bool) {
        if (vault != boundVault || custodyCredit == 0 || !_hasValidAPass()) return false;
        if (!_hasExpectedDecimals() || !_hasMinterRole()) return false;
        if (!_hasPolicy()) return false;
        try token.balanceOf(address(this)) returns (uint256 balance) {
            if (balance < custodyCredit) return false;
        } catch {
            return false;
        }
        try token.totalSupply() returns (uint256 supply) {
            return supply == custodyCredit;
        } catch {
            return false;
        }
    }

    function isCashRedemptionReady(address vault) external view returns (bool) {
        if (vault != boundVault || custodyCredit == 0 || !_hasValidAPass()) return false;
        if (!_hasExpectedDecimals() || !_hasMinterRole() || !_hasPolicy()) return false;
        try token.balanceOf(address(this)) returns (uint256 balance) {
            return balance >= custodyCredit;
        } catch {
            return false;
        }
    }

    function isRedemptionReady(address vault, uint256 units) external view returns (bool) {
        return _isRedemptionReady(vault, units);
    }

    function _isRedemptionReady(address vault, uint256 units) private view returns (bool) {
        if (vault != boundVault || units == 0 || custodyCredit < units || !_hasValidAPass()) {
            return false;
        }
        if (!_hasExpectedDecimals() || !_hasMinterRole()) return false;
        if (!_isPolicyTransferAllowed(address(this), address(0), units)) return false;
        try token.balanceOf(address(this)) returns (uint256 balance) {
            return balance >= custodyCredit;
        } catch {
            return false;
        }
    }

    function consumeOnRedemption(address vault, uint256 units) external nonReentrant {
        _requireVault(vault, units);
        if (!_hasValidAPass()) revert InvalidCustodyIdentity();
        if (!_hasMinterRole()) revert MissingMinterRole();
        if (!_isPolicyTransferAllowed(address(this), address(0), units)) {
            revert TransferPolicyDenied();
        }
        uint256 balanceBefore = token.balanceOf(address(this));
        uint256 supplyBefore = token.totalSupply();

        custodyCredit -= units;
        token.burn(address(this), units);

        if (
            balanceBefore < token.balanceOf(address(this))
                || balanceBefore - token.balanceOf(address(this)) != units
                || supplyBefore < token.totalSupply() || supplyBefore - token.totalSupply() != units
        ) revert AccountingMismatch();
        emit CreditConsumed(vault, units);
    }

    function releaseOnDefault(address vault, address holder, uint256 units) external nonReentrant {
        _requireVault(vault, units);
        if (!_hasValidAPass()) revert InvalidCustodyIdentity();
        if (holder == address(0)) revert InvalidConfiguration();
        if (!_isPolicyTransferAllowed(address(this), holder, units)) {
            revert TransferPolicyDenied();
        }
        uint256 adapterBefore = token.balanceOf(address(this));
        uint256 holderBefore = token.balanceOf(holder);

        custodyCredit -= units;
        token.safeTransfer(holder, units);

        if (
            adapterBefore < token.balanceOf(address(this))
                || adapterBefore - token.balanceOf(address(this)) != units
                || token.balanceOf(holder) < holderBefore
                || token.balanceOf(holder) - holderBefore != units
        ) revert AccountingMismatch();
        emit CreditReleased(vault, holder, units);
    }

    function _requireVault(address vault, uint256 units) private view {
        if (msg.sender != boundVault || vault != boundVault) revert UnauthorizedVault();
        if (units == 0 || custodyCredit < units) revert InsufficientCredit();
        _requireExpectedDecimals();
        if (token.balanceOf(address(this)) < custodyCredit) revert AccountingMismatch();
    }

    function _hasValidAPass() private view returns (bool) {
        try apass.isValidAPass(address(this)) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }

    function _hasMinterRole() private view returns (bool) {
        try token.MINTER_ROLE() returns (bytes32 role) {
            try token.hasRole(role, address(this)) returns (bool granted) {
                return granted;
            } catch {
                return false;
            }
        } catch {
            return false;
        }
    }

    function _hasExpectedDecimals() private view returns (bool) {
        try token.decimals() returns (uint8 actual) {
            return actual == EXPECTED_DECIMALS;
        } catch {
            return false;
        }
    }

    function _isPolicyTransferAllowed(address from, address to, uint256 amount)
        private
        view
        returns (bool)
    {
        try token.policy() returns (address policy) {
            if (policy == address(0) || policy.code.length == 0) return false;
            try ICleanversePolicy(policy).canTransfer(address(token), from, to, amount) returns (
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

    function _hasPolicy() private view returns (bool) {
        try token.policy() returns (address policy) {
            return policy != address(0) && policy.code.length != 0;
        } catch {
            return false;
        }
    }

    function _validateVaultBinding(address vault, uint256 units) private view {
        IMordantCvaVault candidate = IMordantCvaVault(vault);
        try candidate.cvaAdapter() returns (address configuredAdapter) {
            if (configuredAdapter != address(this)) revert InvalidConfiguration();
        } catch {
            revert InvalidConfiguration();
        }
        try candidate.cvaToken() returns (address configuredToken) {
            if (configuredToken != address(token)) revert InvalidConfiguration();
        } catch {
            revert InvalidConfiguration();
        }
        try candidate.initialUnits() returns (uint256 configuredUnits) {
            if (configuredUnits != units) revert InvalidConfiguration();
        } catch {
            revert InvalidConfiguration();
        }
    }

    function _requireExpectedDecimals() private view {
        uint8 actual = token.decimals();
        if (actual != EXPECTED_DECIMALS) revert InvalidTokenDecimals(actual);
    }
}
