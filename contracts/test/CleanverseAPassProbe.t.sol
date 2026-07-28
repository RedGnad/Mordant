// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { CleanverseAPassProbe } from "../src/cleanverse/CleanverseAPassProbe.sol";
import { MockERC20 } from "../src/mocks/MockERC20.sol";

contract CleanverseAPassProbeTest is Test {
    CleanverseAPassProbe private probe;
    MockERC20 private token;

    address private constant OWNER = address(0xA11CE);
    address private constant STRANGER = address(0xB0B);

    function setUp() public {
        probe = new CleanverseAPassProbe(OWNER);
        token = new MockERC20("Probe Token", "PT", 6);
    }

    function test_ownerIsSetAtDeployment() public view {
        assertEq(probe.owner(), OWNER);
    }

    function test_reportsItsOwnBalance() public {
        token.mint(address(probe), 1_000);
        assertEq(probe.balanceOf(IERC20(address(token))), 1_000);
    }

    function test_ownerCanSweepEverythingItReceives() public {
        token.mint(address(probe), 1_000);

        vm.prank(OWNER);
        probe.sweep(IERC20(address(token)), OWNER, 1_000);

        assertEq(token.balanceOf(OWNER), 1_000);
        assertEq(probe.balanceOf(IERC20(address(token))), 0);
    }

    function test_sweepIsOwnerOnly() public {
        token.mint(address(probe), 1_000);

        vm.prank(STRANGER);
        vm.expectRevert();
        probe.sweep(IERC20(address(token)), STRANGER, 1_000);

        assertEq(probe.balanceOf(IERC20(address(token))), 1_000);
    }

    /// @dev A probe must never trap what it is sent, whatever amount arrives.
    function testFuzz_ownerCanAlwaysRecoverTheFullBalance(uint128 amount) public {
        token.mint(address(probe), amount);

        vm.prank(OWNER);
        probe.sweep(IERC20(address(token)), OWNER, amount);

        assertEq(probe.balanceOf(IERC20(address(token))), 0);
        assertEq(token.balanceOf(OWNER), amount);
    }
}
