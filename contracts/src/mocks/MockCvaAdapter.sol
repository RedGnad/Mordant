// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import { ICvaAdapter } from "../interfaces/ICvaAdapter.sol";
import { MockERC20 } from "./MockERC20.sol";

/// @notice Unit-test adapter only. It is not a Cleanverse implementation.
contract MockCvaAdapter is ICvaAdapter {
    using SafeERC20 for IERC20;

    MockERC20 public immutable token;
    mapping(address vault => uint256 units) public custodyCredit;

    error UnauthorizedVault();
    error InsufficientCredit();
    error AccountingMismatch();

    constructor(MockERC20 token_) {
        token = token_;
    }

    function asset() external view returns (address) {
        return address(token);
    }

    function issuedSupply() external view returns (uint256) {
        return token.totalSupply();
    }

    function availableBalance(address vault) external view returns (uint256) {
        return custodyCredit[vault];
    }

    function isActivationReady(address vault) external view returns (bool) {
        return custodyCredit[vault] != 0;
    }

    function isCashRedemptionReady(address vault) external view returns (bool) {
        return custodyCredit[vault] != 0;
    }

    function isRedemptionReady(address vault, uint256 units) external view returns (bool) {
        return units != 0 && custodyCredit[vault] >= units;
    }

    /// @notice Test-only stand-in for sponsor-approved custody crediting a vault.
    function creditVault(address vault, uint256 units) external {
        uint256 beforeBalance = token.balanceOf(address(this));
        IERC20(address(token)).safeTransferFrom(msg.sender, address(this), units);
        if (token.balanceOf(address(this)) - beforeBalance != units) revert AccountingMismatch();
        custodyCredit[vault] += units;
    }

    function consumeOnRedemption(address vault, uint256 units) external {
        if (msg.sender != vault) revert UnauthorizedVault();
        if (custodyCredit[vault] < units) revert InsufficientCredit();
        custodyCredit[vault] -= units;
        token.burn(units);
    }

    function releaseOnDefault(address vault, address holder, uint256 units) external {
        if (msg.sender != vault) revert UnauthorizedVault();
        if (custodyCredit[vault] < units) revert InsufficientCredit();
        custodyCredit[vault] -= units;
        IERC20(address(token)).safeTransfer(holder, units);
    }
}
