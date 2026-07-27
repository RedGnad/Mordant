// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script } from "forge-std/Script.sol";

import { CleanverseAPassVerifier } from "../src/cleanverse/CleanverseAPassVerifier.sol";
import { CleanverseCvaAdapter } from "../src/cleanverse/CleanverseCvaAdapter.sol";
import { ICleanverseAPass } from "../src/cleanverse/ICleanverseAPass.sol";
import { ICleanverseAToken } from "../src/cleanverse/ICleanverseAToken.sol";

/// @notice Deploys the two Cleanverse boundaries without hard-coded addresses or sponsor API calls.
contract DeployCleanverseBoundaries is Script {
    uint256 private constant MONAD_TESTNET_CHAIN_ID = 10_143;
    uint256 private constant ANVIL_CHAIN_ID = 31_337;
    uint256 private constant HOLDER_ONLY_OPEN_ROLE_MASK = uint256(1) << 4;

    error UnsupportedChain(uint256 chainId);
    error InvalidConfiguration();

    function run()
        external
        returns (CleanverseAPassVerifier verifier, CleanverseCvaAdapter adapter)
    {
        if (block.chainid != MONAD_TESTNET_CHAIN_ID && block.chainid != ANVIL_CHAIN_ID) {
            revert UnsupportedChain(block.chainid);
        }

        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address boundaryOwner = vm.envAddress("MORDANT_BOUNDARY_OWNER");
        address apass = vm.envAddress("CLEANVERSE_APASS_ADDRESS");
        address invoiceAToken = vm.envAddress("INVOICE_ATOKEN_ADDRESS");
        uint256 openRoleMask = vm.envUint("CVI_OPEN_ROLE_MASK");
        if (boundaryOwner == address(0) || openRoleMask != HOLDER_ONLY_OPEN_ROLE_MASK) {
            revert InvalidConfiguration();
        }

        vm.startBroadcast(deployerKey);
        verifier = new CleanverseAPassVerifier(boundaryOwner, ICleanverseAPass(apass), openRoleMask);
        adapter = new CleanverseCvaAdapter(
            boundaryOwner, ICleanverseAToken(invoiceAToken), ICleanverseAPass(apass)
        );
        vm.stopBroadcast();
    }
}
