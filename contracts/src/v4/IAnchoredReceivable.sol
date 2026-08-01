// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IIdentityAnchor} from "../identity/IIdentityAnchor.sol";

/// @notice A tokenized receivable that also carries a canonical identity anchor.
/// @dev View-only by construction. The binder is non-economic and must be unable
/// to move units, settlement funds, reserves, entitlements or claims, so it is
/// given no mutating selector to call.
///
/// Satisfied by MordantInvoiceVaultV2. The lifecycle getters are declared
/// `uint8` rather than with the vault's enum types: the selectors are identical
/// and the ABI encoding of an enum is a uint8, so this reads the deployed vault
/// without importing its economics.
interface IAnchoredReceivable is IIdentityAnchor {
    /// @notice Lifecycle: 0 Unissued, 1 Outstanding, 2 Redeemed, 3 DefaultOutstanding.
    function receivableState() external view returns (uint8);

    /// @notice Exclusivity protection: 1 Active while protection is funded.
    function protectionState() external view returns (uint8);

    /// @notice Tokenized units outstanding against the receivable.
    function totalSupply() external view returns (uint256);
}
