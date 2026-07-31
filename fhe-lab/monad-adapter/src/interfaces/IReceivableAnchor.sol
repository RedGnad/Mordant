// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice The read-only surface of a tokenized receivable that a recourse
/// consumer binds to. It is satisfied by MordantInvoiceVault.
/// @dev Deliberately view-only: a non-economic recourse consumer must be unable
/// to move units, settlement funds, reserves or entitlements on the anchor.
interface IReceivableAnchor {
    /// @notice Unique identifier of the buyer-accepted receivable.
    function invoiceRoot() external view returns (bytes32);

    /// @notice Settlement currency code of the receivable.
    function currency() external view returns (bytes32);

    /// @notice Lifecycle state: 0 Unissued, 1 Outstanding, 2 Redeemed, 3 DefaultOutstanding.
    function receivableState() external view returns (uint8);

    /// @notice Exclusivity protection state: 1 Active while protection is funded.
    function protectionState() external view returns (uint8);

    /// @notice Tokenized units outstanding against the receivable.
    function totalSupply() external view returns (uint256);
}
