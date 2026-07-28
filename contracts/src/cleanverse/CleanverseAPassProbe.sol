// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Throwaway contract used to answer one question: can a Cleanverse A-Pass be issued to a
/// contract address, and can that contract then hold and move an A-Token?
/// @dev Deliberately minimal. It is not part of the Mordant protocol and nothing depends on it. It
/// exists so the A-Pass question is settled against a disposable address rather than against a vault
/// or adapter, where a wrong answer would be expensive.
///
/// The only behaviour beyond holding a balance is `sweep`, so a probe deployment can never strand
/// tokens: whatever it receives, the owner can always recover.
contract CleanverseAPassProbe is Ownable {
    using SafeERC20 for IERC20;

    /// @notice Emitted on deployment so a probe is identifiable in logs without an ABI lookup.
    event ProbeDeployed(address indexed owner);

    constructor(address initialOwner) Ownable(initialOwner) {
        emit ProbeDeployed(initialOwner);
    }

    /// @notice Sends `amount` of `token` to `to`.
    /// @dev The A-Token policy checks both sides of a transfer, so this reverts unless this contract
    /// is itself permitted to send. That revert is a result, not a failure of the probe.
    function sweep(IERC20 token, address to, uint256 amount) external onlyOwner {
        token.safeTransfer(to, amount);
    }

    /// @notice Balance of `token` held by this probe.
    function balanceOf(IERC20 token) external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
