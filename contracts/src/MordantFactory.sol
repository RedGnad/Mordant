// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import { MordantInvoiceVault } from "./MordantInvoiceVault.sol";
import { ICvaAdapter } from "./interfaces/ICvaAdapter.sol";
import { ICviVerifier } from "./interfaces/ICviVerifier.sol";
import { IMordantFactory } from "./interfaces/IMordantFactory.sol";

/// @notice Immutable root/CVA/vault bindings and the participating-facility allowlist.
contract MordantFactory is IMordantFactory, Ownable, ReentrancyGuard {
    uint8 private constant ROLE_BUYER = 1;
    uint8 private constant ROLE_ORIGINATOR = 2;
    uint8 private constant ROLE_FACILITY = 3;

    struct InvoiceConfig {
        address cvaAdapter;
        address settlementToken;
        bytes32 invoiceRoot;
        bytes32 currency;
        address buyer;
        address originatorTreasury;
        address initialOriginatorSigner;
        uint256 initialUnits;
        uint256 advanceAmount;
        uint256 faceValue;
        uint16 bondBps;
        uint64 protectionEnd;
        uint64 revealPeriod;
        uint64 curePeriod;
    }

    error InvalidConfiguration();
    error Unauthorized();
    error AlreadyBound();
    error NotApproved();
    error RoleOverlap();

    event FacilitySet(address indexed facility, bool enabled);
    event CvaAdapterSet(address indexed adapter, bool enabled);
    event SettlementTokenSet(address indexed token, bool enabled);
    event InvoiceVaultCreated(
        bytes32 indexed invoiceRoot,
        address indexed cvaToken,
        address indexed vault,
        address buyer,
        address originator
    );

    ICviVerifier public immutable cviVerifier;

    mapping(address facility => bool registered) public override isFacility;
    mapping(address adapter => bool approved) public approvedCvaAdapter;
    mapping(address token => bool approved) public approvedSettlementToken;
    mapping(bytes32 invoiceRoot => address vault) public vaultForRoot;
    mapping(address cvaToken => bytes32 invoiceRoot) public rootForCva;

    constructor(address initialOwner, ICviVerifier cviVerifier_) Ownable(initialOwner) {
        if (
            initialOwner == address(0) || address(cviVerifier_) == address(0)
                || address(cviVerifier_).code.length == 0
        ) {
            revert InvalidConfiguration();
        }
        cviVerifier = cviVerifier_;
    }

    function setFacility(address facility, bool enabled) external onlyOwner {
        if (facility == address(0)) revert InvalidConfiguration();
        if (enabled && !cviVerifier.isEligible(facility, ROLE_FACILITY)) revert Unauthorized();
        isFacility[facility] = enabled;
        emit FacilitySet(facility, enabled);
    }

    function setCvaAdapter(address adapter, bool enabled) external onlyOwner {
        if (adapter == address(0) || adapter.code.length == 0) revert InvalidConfiguration();
        if (enabled && ICvaAdapter(adapter).asset() == address(0)) {
            revert InvalidConfiguration();
        }
        approvedCvaAdapter[adapter] = enabled;
        emit CvaAdapterSet(adapter, enabled);
    }

    function setSettlementToken(address token, bool enabled) external onlyOwner {
        if (token == address(0) || token.code.length == 0) revert InvalidConfiguration();
        approvedSettlementToken[token] = enabled;
        emit SettlementTokenSet(token, enabled);
    }

    function createInvoiceVault(InvoiceConfig calldata config)
        external
        nonReentrant
        returns (MordantInvoiceVault vault)
    {
        if (msg.sender != config.buyer) revert Unauthorized();
        if (
            !approvedCvaAdapter[config.cvaAdapter]
                || !approvedSettlementToken[config.settlementToken]
        ) revert NotApproved();
        if (
            !cviVerifier.isEligible(config.buyer, ROLE_BUYER)
                || !cviVerifier.isEligible(config.initialOriginatorSigner, ROLE_ORIGINATOR)
                || !cviVerifier.isEligible(config.originatorTreasury, ROLE_ORIGINATOR)
        ) revert Unauthorized();
        if (
            config.buyer == config.originatorTreasury
                || config.buyer == config.initialOriginatorSigner || isFacility[config.buyer]
                || isFacility[config.originatorTreasury]
                || isFacility[config.initialOriginatorSigner]
        ) revert RoleOverlap();
        if (
            config.cvaAdapter == address(0) || config.settlementToken == address(0)
                || config.invoiceRoot == bytes32(0)
                || vaultForRoot[config.invoiceRoot] != address(0)
        ) revert InvalidConfiguration();

        address cvaToken = ICvaAdapter(config.cvaAdapter).asset();
        if (cvaToken == address(0)) revert InvalidConfiguration();
        if (rootForCva[cvaToken] != bytes32(0)) revert AlreadyBound();

        MordantInvoiceVault.Init memory init = MordantInvoiceVault.Init({
            factory: address(this),
            cviVerifier: address(cviVerifier),
            cvaAdapter: config.cvaAdapter,
            settlementToken: config.settlementToken,
            invoiceRoot: config.invoiceRoot,
            currency: config.currency,
            buyer: config.buyer,
            originatorTreasury: config.originatorTreasury,
            initialOriginatorSigner: config.initialOriginatorSigner,
            initialUnits: config.initialUnits,
            advanceAmount: config.advanceAmount,
            faceValue: config.faceValue,
            bondBps: config.bondBps,
            protectionEnd: config.protectionEnd,
            revealPeriod: config.revealPeriod,
            curePeriod: config.curePeriod
        });

        vault = new MordantInvoiceVault(init);
        vaultForRoot[config.invoiceRoot] = address(vault);
        rootForCva[cvaToken] = config.invoiceRoot;

        emit InvoiceVaultCreated(
            config.invoiceRoot, cvaToken, address(vault), config.buyer, config.originatorTreasury
        );
    }
}
