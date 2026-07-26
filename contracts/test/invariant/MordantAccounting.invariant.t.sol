// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { StdInvariant } from "forge-std/StdInvariant.sol";
import { Test } from "forge-std/Test.sol";

import { MordantFactory } from "../../src/MordantFactory.sol";
import { MordantInvoiceVault } from "../../src/MordantInvoiceVault.sol";
import { MockCvaAdapter } from "../../src/mocks/MockCvaAdapter.sol";
import { MockEligibility } from "../../src/mocks/MockEligibility.sol";
import { MockERC20 } from "../../src/mocks/MockERC20.sol";

contract MordantVaultHandler is Test {
    MordantInvoiceVault public immutable vault;
    address public immutable holderA;
    address public immutable holderB;

    constructor(MordantInvoiceVault vault_, address holderA_, address holderB_) {
        vault = vault_;
        holderA = holderA_;
        holderB = holderB_;
    }

    function transferAtoB(uint256 requested) external {
        _transfer(holderA, holderB, requested);
    }

    function transferBtoA(uint256 requested) external {
        _transfer(holderB, holderA, requested);
    }

    function redeemA(uint256 requested) external {
        _redeem(holderA, requested);
    }

    function redeemB(uint256 requested) external {
        _redeem(holderB, requested);
    }

    function _transfer(address from, address to, uint256 requested) private {
        uint256 balance = vault.balanceOf(from);
        if (balance == 0) return;
        uint256 amount = bound(requested, 1, balance);
        vm.prank(from);
        try vault.transfer(to, amount) { } catch { }
    }

    function _redeem(address holder, uint256 requested) private {
        uint256 balance = vault.balanceOf(holder);
        if (balance == 0) return;
        uint256 amount = bound(requested, 1, balance);
        vm.prank(holder);
        try vault.redeem(amount) { } catch { }
    }
}

contract MordantAccountingInvariant is StdInvariant, Test {
    uint256 private constant ONE = 1e6;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint256 private constant UNITS = 100 * ONE;

    uint256 private constant ORIGINATOR_KEY = 0xA11CE;
    uint256 private constant FACILITY_KEY = 0xFA11;

    MockERC20 private ausdc;
    MockERC20 private cva;
    MockCvaAdapter private adapter;
    MordantInvoiceVault private vault;
    address private buyer;
    address private originator;
    address private facility;
    address private holderA;
    address private holderB;

    function setUp() public {
        vm.warp(1_000_000);
        buyer = vm.addr(0xB0B);
        originator = vm.addr(ORIGINATOR_KEY);
        facility = vm.addr(FACILITY_KEY);
        holderA = vm.addr(0xAA01);
        holderB = vm.addr(0xBB02);

        MockEligibility eligibility = new MockEligibility();
        eligibility.setEligible(buyer, 1, true);
        eligibility.setEligible(originator, 2, true);
        eligibility.setEligible(facility, 3, true);
        eligibility.setEligible(holderA, 4, true);
        eligibility.setEligible(holderB, 4, true);

        ausdc = new MockERC20("Mock aUSDC", "aUSDC", 6);
        cva = new MockERC20("Synthetic Invoice A-Token", "aINV", 6);
        adapter = new MockCvaAdapter(cva);
        MordantFactory factory = new MordantFactory(address(this), eligibility);
        factory.setFacility(facility, true);
        factory.setCvaAdapter(address(adapter), true);
        factory.setSettlementToken(address(ausdc), true);
        vault = _deployVault(factory);
        _activateAndFund();

        MordantVaultHandler handler = new MordantVaultHandler(vault, holderA, holderB);
        targetContract(address(handler));
    }

    function _deployVault(MordantFactory factory) private returns (MordantInvoiceVault deployed) {
        MordantFactory.InvoiceConfig memory config = MordantFactory.InvoiceConfig({
            cvaAdapter: address(adapter),
            settlementToken: address(ausdc),
            invoiceRoot: keccak256("invariant-invoice"),
            currency: bytes32("USD"),
            buyer: buyer,
            originatorTreasury: originator,
            initialOriginatorSigner: originator,
            initialUnits: UNITS,
            advanceAmount: ADVANCE,
            faceValue: FACE,
            bondBps: 1_000,
            protectionEnd: uint64(block.timestamp + 30 days),
            revealPeriod: 1 hours,
            curePeriod: 1 hours
        });
        vm.prank(buyer);
        deployed = factory.createInvoiceVault(config);
    }

    function _activateAndFund() private {
        cva.mint(address(this), UNITS);
        cva.approve(address(adapter), UNITS);
        adapter.creditVault(address(vault), UNITS);

        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(vault), type(uint256).max);

        MordantInvoiceVault.Pledge memory pledge = MordantInvoiceVault.Pledge({
            invoiceRoot: vault.invoiceRoot(),
            originatorSigner: originator,
            facility: facility,
            obligationId: keccak256("first-facility-obligation"),
            amount: FACE,
            currency: bytes32("USD"),
            activeFrom: uint64(block.timestamp - 1),
            activeUntil: uint64(block.timestamp + 31 days),
            nonce: 1,
            deadline: uint64(block.timestamp + 2 days),
            exclusive: true
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ORIGINATOR_KEY, vault.hashPledge(pledge));
        bytes memory signature = abi.encodePacked(r, s, v);
        address[] memory holders = new address[](2);
        holders[0] = holderA;
        holders[1] = holderB;
        uint256[] memory allocations = new uint256[](2);
        allocations[0] = 60 * ONE;
        allocations[1] = 40 * ONE;
        vm.prank(facility);
        vault.activate(pledge, signature, holderA, holders, allocations);

        ausdc.mint(buyer, FACE);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), type(uint256).max);
        vault.fundRedemption(FACE);
        vm.stopPrank();
    }

    function invariant_receiptsRemainBackedOneToOne() public view {
        assertEq(vault.totalSupply(), vault.cvaAccounted());
        assertEq(adapter.availableBalance(address(vault)), vault.cvaAccounted());
        assertEq(adapter.issuedSupply(), vault.initialUnits() - vault.cvaBurned());
    }

    function invariant_bondIsConservedAcrossAmortization() public view {
        assertEq(
            vault.bondLocked() + vault.bondReturned() + vault.entitlementAllocated(),
            vault.initialBond()
        );
        assertLe(vault.entitlementClaimed(), vault.entitlementAllocated());
    }

    function invariant_settlementLiabilitiesRemainFunded() public view {
        assertGe(ausdc.balanceOf(address(vault)), vault.accountedSettlementBalance());
    }

    function invariant_contractLevelAccountingAssertionHolds() public view {
        vault.assertAccounting();
    }
}

contract MordantEntitledHandler is Test {
    MordantInvoiceVault public immutable vault;
    MockCvaAdapter public immutable adapter;
    address public immutable holderA;
    address public immutable holderB;

    bool public claimTouchedReceivableAccounting;
    uint256 public observedClaimA;
    uint256 public observedClaimB;

    constructor(
        MordantInvoiceVault vault_,
        MockCvaAdapter adapter_,
        address holderA_,
        address holderB_
    ) {
        vault = vault_;
        adapter = adapter_;
        holderA = holderA_;
        holderB = holderB_;
    }

    function transferAtoB(uint256 requested) external {
        _transfer(holderA, holderB, requested);
    }

    function transferBtoA(uint256 requested) external {
        _transfer(holderB, holderA, requested);
    }

    function redeemA(uint256 requested) external {
        _redeem(holderA, requested);
    }

    function redeemB(uint256 requested) external {
        _redeem(holderB, requested);
    }

    function claimA() external {
        _claim(holderA, true);
    }

    function claimB() external {
        _claim(holderB, false);
    }

    function observedClaims() external view returns (uint256) {
        return observedClaimA + observedClaimB;
    }

    function _transfer(address from, address to, uint256 requested) private {
        uint256 balance = vault.balanceOf(from);
        if (balance == 0) return;
        uint256 amount = bound(requested, 1, balance);
        vm.prank(from);
        try vault.transfer(to, amount) { } catch { }
    }

    function _redeem(address holder, uint256 requested) private {
        uint256 balance = vault.balanceOf(holder);
        if (balance == 0) return;
        uint256 amount = bound(requested, 1, balance);
        vm.prank(holder);
        try vault.redeem(amount) { } catch { }
    }

    function _claim(address holder, bool isHolderA) private {
        uint256 supplyBefore = vault.totalSupply();
        uint256 accountedBefore = vault.cvaAccounted();
        uint256 burnedBefore = vault.cvaBurned();
        uint256 creditBefore = adapter.availableBalance(address(vault));

        vm.prank(holder);
        try vault.claimBond() returns (uint256 amount) {
            if (isHolderA) observedClaimA += amount;
            else observedClaimB += amount;
        } catch { }

        if (
            vault.totalSupply() != supplyBefore || vault.cvaAccounted() != accountedBefore
                || vault.cvaBurned() != burnedBefore
                || adapter.availableBalance(address(vault)) != creditBefore
        ) claimTouchedReceivableAccounting = true;
    }
}

contract MordantEntitledInvariant is StdInvariant, Test {
    uint256 private constant ONE = 1e6;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint256 private constant UNITS = 100 * ONE;
    uint256 private constant ORIGINATOR_KEY = 0xA11CE;

    address private buyer;
    address private originator;
    address private facilityA;
    address private facilityB;
    address private holderA;
    address private holderB;
    uint64 private protectionEnd;

    MockERC20 private ausdc;
    MockERC20 private cva;
    MockCvaAdapter private adapter;
    MordantInvoiceVault private vault;
    MordantEntitledHandler private handler;

    function setUp() public {
        vm.warp(2_000_000);
        buyer = vm.addr(0xB0B);
        originator = vm.addr(ORIGINATOR_KEY);
        facilityA = vm.addr(0xFA11);
        facilityB = vm.addr(0xFB22);
        holderA = vm.addr(0xAA01);
        holderB = vm.addr(0xBB02);
        protectionEnd = uint64(block.timestamp + 30 days);

        MockEligibility eligibility = _eligibilityFixture();
        ausdc = new MockERC20("Mock aUSDC", "aUSDC", 6);
        cva = new MockERC20("Synthetic Invoice A-Token", "aINV", 6);
        adapter = new MockCvaAdapter(cva);
        MordantFactory factory = new MordantFactory(address(this), eligibility);
        factory.setFacility(facilityA, true);
        factory.setFacility(facilityB, true);
        factory.setCvaAdapter(address(adapter), true);
        factory.setSettlementToken(address(ausdc), true);
        vault = _deployVault(factory);
        _activateAndFinalizeConflict();
        _fundFaceValue();

        handler = new MordantEntitledHandler(vault, adapter, holderA, holderB);
        targetContract(address(handler));
    }

    function _eligibilityFixture() private returns (MockEligibility eligibility) {
        eligibility = new MockEligibility();
        eligibility.setEligible(buyer, 1, true);
        eligibility.setEligible(originator, 2, true);
        eligibility.setEligible(facilityA, 3, true);
        eligibility.setEligible(facilityB, 3, true);
        eligibility.setEligible(holderA, 4, true);
        eligibility.setEligible(holderB, 4, true);
    }

    function _deployVault(MordantFactory factory) private returns (MordantInvoiceVault deployed) {
        MordantFactory.InvoiceConfig memory config = MordantFactory.InvoiceConfig({
            cvaAdapter: address(adapter),
            settlementToken: address(ausdc),
            invoiceRoot: keccak256("entitled-invariant-invoice"),
            currency: bytes32("USD"),
            buyer: buyer,
            originatorTreasury: originator,
            initialOriginatorSigner: originator,
            initialUnits: UNITS,
            advanceAmount: ADVANCE,
            faceValue: FACE,
            bondBps: 1_000,
            protectionEnd: protectionEnd,
            revealPeriod: 1 hours,
            curePeriod: 1 hours
        });
        vm.prank(buyer);
        deployed = factory.createInvoiceVault(config);
    }

    function _activateAndFinalizeConflict() private {
        cva.mint(address(this), UNITS);
        cva.approve(address(adapter), UNITS);
        adapter.creditVault(address(vault), UNITS);
        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(vault), type(uint256).max);

        MordantInvoiceVault.Pledge memory first = _pledge(facilityA, 1);
        bytes memory firstSignature = _sign(vault.hashPledge(first));
        address[] memory holders = new address[](2);
        holders[0] = holderA;
        holders[1] = holderB;
        uint256[] memory allocations = new uint256[](2);
        allocations[0] = 60 * ONE;
        allocations[1] = 40 * ONE;
        vm.prank(facilityA);
        vault.activate(first, firstSignature, holderA, holders, allocations);

        MordantInvoiceVault.Pledge memory second = _pledge(facilityB, 2);
        bytes memory secondSignature = _sign(vault.hashPledge(second));
        bytes32 salt = keccak256("entitled-invariant-salt");
        bytes32 commitment = vault.conflictCommitment(
            vault.hashPledge(second), keccak256(secondSignature), facilityB, salt
        );
        vm.prank(facilityB);
        vault.commitConflict(commitment);
        vm.prank(facilityB);
        vault.revealConflict(second, secondSignature, salt);
        vm.warp(block.timestamp + 1 hours + 1);
        vault.finalizeConflict();
    }

    function _fundFaceValue() private {
        ausdc.mint(buyer, FACE);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();
    }

    function _pledge(address facility, uint256 nonce)
        private
        view
        returns (MordantInvoiceVault.Pledge memory)
    {
        return MordantInvoiceVault.Pledge({
            invoiceRoot: vault.invoiceRoot(),
            originatorSigner: originator,
            facility: facility,
            obligationId: keccak256(abi.encode("entitled-obligation", facility, nonce)),
            amount: FACE,
            currency: bytes32("USD"),
            activeFrom: uint64(block.timestamp - 1),
            activeUntil: protectionEnd + 1,
            nonce: nonce,
            deadline: uint64(block.timestamp + 2 days),
            exclusive: true
        });
    }

    function _sign(bytes32 digest) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ORIGINATOR_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function invariant_entitlementAndHistoricalPayoutAreBounded() public view {
        assertLe(vault.entitlementClaimed(), vault.entitlementAllocated());
        assertLe(vault.entitlementClaimedUnits(), vault.entitlementSnapshotSupply());
        assertLe(handler.observedClaims(), vault.entitlementAllocated());
        assertEq(handler.observedClaims(), vault.entitlementClaimed());
        assertLe(handler.observedClaimA(), 6 * ONE);
        assertLe(handler.observedClaimB(), 4 * ONE);
        if (vault.bondClaimedBy(holderA)) assertEq(handler.observedClaimA(), 6 * ONE);
        if (vault.bondClaimedBy(holderB)) assertEq(handler.observedClaimB(), 4 * ONE);
    }

    function invariant_claimNeverTouchesReceivableAccounting() public view {
        assertFalse(handler.claimTouchedReceivableAccounting());
        assertEq(vault.totalSupply(), vault.cvaAccounted());
        assertEq(adapter.availableBalance(address(vault)), vault.cvaAccounted());
        assertEq(adapter.issuedSupply(), vault.initialUnits() - vault.cvaBurned());
    }

    function invariant_snapshotRemainsSixtyForty() public view {
        uint48 snapshot = vault.entitlementSnapshotSequence();
        assertEq(vault.entitlementSnapshotSupply(), UNITS);
        assertEq(vault.balanceAt(holderA, snapshot), 60 * ONE);
        assertEq(vault.balanceAt(holderB, snapshot), 40 * ONE);
    }

    function invariant_entitledBondLifecycleAndSettlementStayFunded() public view {
        assertEq(
            vault.bondLocked() + vault.bondReturned() + vault.entitlementAllocated(),
            vault.initialBond()
        );
        assertGe(ausdc.balanceOf(address(vault)), vault.accountedSettlementBalance());
        vault.assertAccounting();
    }
}
