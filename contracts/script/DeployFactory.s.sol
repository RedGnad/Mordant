// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script } from "forge-std/Script.sol";

import { MordantFactory } from "../src/MordantFactory.sol";
import { ICviVerifier } from "../src/interfaces/ICviVerifier.sol";

/// @notice Testnet/local deployment only. It never supplies default addresses or keys.
contract DeployFactory is Script {
    uint256 private constant MONAD_TESTNET_CHAIN_ID = 10_143;
    uint256 private constant ANVIL_CHAIN_ID = 31_337;

    error UnsupportedChain(uint256 chainId);
    error InvalidFinalOwner();

    function run() external returns (MordantFactory factory) {
        if (block.chainid != MONAD_TESTNET_CHAIN_ID && block.chainid != ANVIL_CHAIN_ID) {
            revert UnsupportedChain(block.chainid);
        }

        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address finalOwner = vm.envAddress("MORDANT_FACTORY_OWNER");
        address cviVerifier = vm.envAddress("CVI_VERIFIER_ADDRESS");
        address cvaAdapter = vm.envAddress("CVA_ADAPTER_ADDRESS");
        address settlementToken = vm.envAddress("SETTLEMENT_TOKEN_ADDRESS");
        if (finalOwner == address(0)) revert InvalidFinalOwner();

        address deployer = vm.addr(deployerKey);
        vm.startBroadcast(deployerKey);
        factory = new MordantFactory(deployer, ICviVerifier(cviVerifier));
        factory.setCvaAdapter(cvaAdapter, true);
        factory.setSettlementToken(settlementToken, true);
        factory.transferOwnership(finalOwner);
        vm.stopBroadcast();
    }
}
