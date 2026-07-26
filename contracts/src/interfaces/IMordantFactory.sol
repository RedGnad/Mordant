// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IMordantFactory {
    function isFacility(address account) external view returns (bool);
}
