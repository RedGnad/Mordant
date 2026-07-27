// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Sponsor adapter boundary for a custom invoice A-Token.
/// @dev A production implementation requires written approval from Cleanverse.
interface ICvaAdapter {
    function asset() external view returns (address);

    /// @notice Global issued supply for the invoice-specific A-Token.
    /// @dev Kept behind the adapter because the sponsor ABI is not yet confirmed.
    function issuedSupply() external view returns (uint256);

    /// @notice Sponsor-custody credit attributable to a Mordant vault.
    /// @dev The vault itself is not assumed to be eligible to custody the A-Token.
    function availableBalance(address vault) external view returns (uint256);

    /// @notice Base custody, identity, role, supply and policy configuration is live.
    /// @dev The vault separately checks every initial allocation through `isRedemptionReady`.
    function isActivationReady(address vault) external view returns (bool);

    /// @notice Base custody, identity, burn role and policy configuration can accept cash.
    /// @dev Exact holder lots are checked during redemption and default-path selection.
    function isCashRedemptionReady(address vault) external view returns (bool);

    /// @notice True when this exact receipt amount can currently be burned for cash redemption.
    function isRedemptionReady(address vault, uint256 units) external view returns (bool);

    function consumeOnRedemption(address vault, uint256 units) external;

    function releaseOnDefault(address vault, address holder, uint256 units) external;
}
