// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Participant-eligibility boundary for live CVI and application-specific role policy.
interface ICviVerifier {
    /// @notice Live identity validity without an application role decision.
    function hasValidIdentity(address account) external view returns (bool);

    function isEligible(address account, uint8 role) external view returns (bool);

    /// @notice Role eligibility plus the underlying asset policy for a future custody transfer.
    function isEligibleForAsset(
        address account,
        uint8 role,
        address asset,
        address custodian,
        uint256 amount
    ) external view returns (bool);

    /// @notice Mirrors the underlying asset policy for a receipt transfer between holders.
    function isAssetTransferAllowed(address asset, address from, address to, uint256 amount)
        external
        view
        returns (bool);
}
