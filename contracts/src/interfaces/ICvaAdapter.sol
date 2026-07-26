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

    function consumeOnRedemption(address vault, uint256 units) external;

    function releaseOnDefault(address vault, address holder, uint256 units) external;
}
