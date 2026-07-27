// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";

import { MordantFactory } from "../src/MordantFactory.sol";
import { MordantInvoiceVault } from "../src/MordantInvoiceVault.sol";
import { MockCvaAdapter } from "../src/mocks/MockCvaAdapter.sol";
import { MockEligibility } from "../src/mocks/MockEligibility.sol";
import { MockERC20 } from "../src/mocks/MockERC20.sol";

contract MordantInvoiceVaultTest is Test {
    uint256 private constant ONE = 1e6;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint256 private constant UNITS = 100 * ONE;
    uint64 private constant REVEAL_PERIOD = 1 hours;
    uint64 private constant CURE_PERIOD = 1 hours;

    uint256 private buyerKey = 0xB0B;
    uint256 private originatorKey = 0xA11CE;
    uint256 private facilityAKey = 0xFA11;
    uint256 private facilityBKey = 0xFB22;
    uint256 private holderAKey = 0xAA01;
    uint256 private holderBKey = 0xBB02;
    uint256 private holderCKey = 0xCC03;
    uint256 private debtorKey = 0xDD04;

    address private buyer;
    address private originator;
    address private facilityA;
    address private facilityB;
    address private holderA;
    address private holderB;
    address private holderC;
    address private debtor;

    bytes32 private constant ROOT = keccak256("buyer-accepted-invoice-0042");
    bytes32 private constant CURRENCY = bytes32("USD");
    bytes32 private constant SALT = keccak256("mordant-demo-salt");

    MockEligibility private eligibility;
    MockERC20 private ausdc;
    MockERC20 private cva;
    MockCvaAdapter private cvaAdapter;
    MordantFactory private factory;
    MordantInvoiceVault private vault;
    uint64 private protectionEnd;

    function setUp() public {
        vm.warp(1_000_000);
        buyer = vm.addr(buyerKey);
        originator = vm.addr(originatorKey);
        facilityA = vm.addr(facilityAKey);
        facilityB = vm.addr(facilityBKey);
        holderA = vm.addr(holderAKey);
        holderB = vm.addr(holderBKey);
        holderC = vm.addr(holderCKey);
        debtor = vm.addr(debtorKey);

        eligibility = new MockEligibility();
        eligibility.setEligible(buyer, 1, true);
        eligibility.setEligible(originator, 2, true);
        eligibility.setEligible(facilityA, 3, true);
        eligibility.setEligible(facilityB, 3, true);
        eligibility.setEligible(holderA, 4, true);
        eligibility.setEligible(holderB, 4, true);
        eligibility.setEligible(holderC, 4, true);

        ausdc = new MockERC20("Mock aUSDC", "aUSDC", 6);
        cva = new MockERC20("Synthetic Invoice A-Token", "aINV", 6);
        cvaAdapter = new MockCvaAdapter(cva);
        factory = new MordantFactory(address(this), eligibility);
        factory.setFacility(facilityA, true);
        factory.setFacility(facilityB, true);
        factory.setCvaAdapter(address(cvaAdapter), true);
        factory.setSettlementToken(address(ausdc), true);

        protectionEnd = uint64(block.timestamp + 30 days);
        vault = _createVault(ROOT, cvaAdapter, UNITS);
        _creditVault(cvaAdapter, cva, vault, UNITS);
        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(vault), type(uint256).max);
    }

    function testActivationAtomicallySplitsNinetyTenAndMintsSixtyForty() public {
        _activateSixtyForty(vault);

        assertEq(ausdc.balanceOf(originator), 90 * ONE);
        assertEq(ausdc.balanceOf(address(vault)), 10 * ONE);
        assertEq(vault.bondLocked(), 10 * ONE);
        assertEq(vault.balanceOf(holderA), 60 * ONE);
        assertEq(vault.balanceOf(holderB), 40 * ONE);
        assertEq(vault.totalSupply(), UNITS);
        assertEq(vault.cvaAccounted(), UNITS);
        assertEq(cva.balanceOf(address(vault)), 0);
        assertEq(cva.balanceOf(address(cvaAdapter)), UNITS);
        assertEq(cvaAdapter.availableBalance(address(vault)), UNITS);
        assertEq(uint256(vault.protectionState()), 1);
        assertEq(uint256(vault.receivableState()), 1);
        vault.assertAccounting();
    }

    function testActivationRevertsWhenCvaIsMissing() public {
        MockERC20 otherCva = new MockERC20("Other", "OTHER", 6);
        MockCvaAdapter otherAdapter = new MockCvaAdapter(otherCva);
        factory.setCvaAdapter(address(otherAdapter), true);
        MordantInvoiceVault otherVault = _createVault(keccak256("missing-cva"), otherAdapter, UNITS);
        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(otherVault), type(uint256).max);

        (MordantInvoiceVault.Pledge memory pledge, bytes memory signature) =
            _signedPledge(otherVault, facilityA, 1, originatorKey);
        (address[] memory holders, uint256[] memory allocations) = _sixtyForty();
        vm.prank(facilityA);
        vm.expectRevert(MordantInvoiceVault.InsufficientCva.selector);
        otherVault.activate(pledge, signature, holderA, holders, allocations);
        assertEq(ausdc.balanceOf(originator), 0);
    }

    function testConflictPaysSixFourWithoutConsumingInvoiceClaim() public {
        _activateSixtyForty(vault);
        _finalizeConflict(vault, 2);

        uint256 supplyBefore = vault.totalSupply();
        uint256 cvaBefore = cvaAdapter.availableBalance(address(vault));
        vm.prank(holderA);
        assertEq(vault.claimBond(), 6 * ONE);
        vm.prank(holderB);
        assertEq(vault.claimBond(), 4 * ONE);

        assertEq(vault.totalSupply(), supplyBefore);
        assertEq(cvaAdapter.availableBalance(address(vault)), cvaBefore);
        assertEq(vault.balanceOf(holderA), 60 * ONE);
        assertEq(vault.balanceOf(holderB), 40 * ONE);

        _fundRedemption(FACE);
        vm.prank(holderA);
        assertEq(vault.redeem(60 * ONE), 66 * ONE);
        vm.prank(holderB);
        assertEq(vault.redeem(40 * ONE), 44 * ONE);
        assertEq(ausdc.balanceOf(originator), 90 * ONE);
        assertEq(vault.totalSupply(), 0);
        assertEq(cvaAdapter.availableBalance(address(vault)), 0);
        vault.assertAccounting();
    }

    function testCashBondClaimDoesNotDependOnCvaDeliveryEligibility() public {
        _activateSixtyForty(vault);
        _finalizeConflict(vault, 2);
        eligibility.setAssetEligible(holderA, 4, false);

        vm.prank(holderA);
        assertEq(vault.claimBond(), 6 * ONE);
        assertEq(ausdc.balanceOf(holderA), 6 * ONE);
    }

    function testCleanRedemptionReturnsAmortizedBond() public {
        _activateSixtyForty(vault);
        _fundRedemption(FACE);

        vm.prank(holderA);
        vault.redeem(60 * ONE);
        assertEq(vault.bondLocked(), 4 * ONE);
        assertEq(vault.bondReturned(), 6 * ONE);

        vm.prank(holderB);
        vault.redeem(40 * ONE);
        assertEq(vault.bondLocked(), 0);
        assertEq(vault.bondReturned(), 10 * ONE);
        vm.prank(originator);
        assertEq(vault.claimSettlementCredit(), 10 * ONE);
        assertEq(ausdc.balanceOf(originator), ADVANCE);
        assertEq(uint256(vault.protectionState()), 5);
        assertEq(uint256(vault.receivableState()), 2);
        vault.assertAccounting();
    }

    function testPartialRedemptionAmortizesConflictBondToRemainingExposure() public {
        _activateSixtyForty(vault);
        _fundRedemption(55 * ONE);
        vm.prank(holderA);
        vault.redeem(50 * ONE);

        assertEq(vault.totalSupply(), 50 * ONE);
        assertEq(vault.bondLocked(), 5 * ONE);
        assertEq(vault.bondReturned(), 5 * ONE);

        _finalizeConflict(vault, 2);
        assertEq(vault.entitlementAllocated(), 5 * ONE);
        vm.prank(holderA);
        assertEq(vault.claimBond(), 1 * ONE);
        vm.prank(holderB);
        assertEq(vault.claimBond(), 4 * ONE);
        vault.assertAccounting();
    }

    function testTransferAfterCommitDoesNotMoveRecordDate() public {
        _activateSixtyForty(vault);
        (MordantInvoiceVault.Pledge memory second, bytes memory signature) =
            _signedPledge(vault, facilityB, 2, originatorKey);
        bytes32 commitment = vault.conflictCommitment(
            vault.hashPledge(second), keccak256(signature), facilityB, SALT
        );

        vm.prank(facilityB);
        vault.commitConflict(commitment);
        vm.prank(holderA);
        vault.transfer(holderB, 10 * ONE);
        assertEq(vault.balanceOf(holderA), 50 * ONE);
        assertEq(vault.balanceOf(holderB), 50 * ONE);

        vm.prank(facilityB);
        vault.revealConflict(second, signature, SALT);
        vm.warp(block.timestamp + CURE_PERIOD + 1);
        vault.finalizeConflict();

        vm.prank(holderA);
        assertEq(vault.claimBond(), 6 * ONE);
        vm.prank(holderB);
        assertEq(vault.claimBond(), 4 * ONE);
    }

    function testRedemptionAfterCommitCannotAmortizeSnapshotBond() public {
        _activateSixtyForty(vault);
        (MordantInvoiceVault.Pledge memory second, bytes memory signature) =
            _signedPledge(vault, facilityB, 2, originatorKey);
        bytes32 commitment = vault.conflictCommitment(
            vault.hashPledge(second), keccak256(signature), facilityB, SALT
        );
        vm.prank(facilityB);
        vault.commitConflict(commitment);

        _fundRedemption(55 * ONE);
        vm.prank(holderA);
        vault.redeem(50 * ONE);
        assertEq(vault.totalSupply(), 50 * ONE);
        assertEq(vault.bondLocked(), 10 * ONE);

        vm.warp(block.timestamp + REVEAL_PERIOD + 1);
        vault.expireCommit();
        assertEq(vault.bondLocked(), 5 * ONE);
        assertEq(vault.bondReturned(), 5 * ONE);
    }

    function testDualAuthenticatedCancellationCuresConflict() public {
        _activateSixtyForty(vault);
        (MordantInvoiceVault.Pledge memory second, bytes memory signature) =
            _revealConflict(vault, 2);
        bytes32 pledgeDigest = vault.hashPledge(second);
        MordantInvoiceVault.Cancellation memory cancellation = MordantInvoiceVault.Cancellation({
            invoiceRoot: ROOT,
            pledgeDigest: pledgeDigest,
            nonce: 77,
            deadline: uint64(block.timestamp + 1 hours)
        });
        bytes memory cancellationSignature =
            _signature(originatorKey, vault.hashCancellation(cancellation));

        vm.prank(facilityB);
        vault.cureConflict(cancellation, cancellationSignature);
        assertEq(uint256(vault.protectionState()), 1);
        assertEq(vault.entitlementAllocated(), 0);
        assertEq(vault.bondLocked(), 10 * ONE);

        bytes32 repeatedCommitment = vault.conflictCommitment(
            pledgeDigest, keccak256(signature), facilityB, bytes32("again")
        );
        vm.prank(facilityB);
        vault.commitConflict(repeatedCommitment);
        vm.prank(facilityB);
        vm.expectRevert(MordantInvoiceVault.AlreadyUsed.selector);
        vault.revealConflict(second, signature, bytes32("again"));
    }

    function testCannotFinalizeBeforeCureDeadlineOrCureAfterIt() public {
        _activateSixtyForty(vault);
        (MordantInvoiceVault.Pledge memory second,) = _revealConflict(vault, 2);

        vm.expectRevert(MordantInvoiceVault.WindowOpen.selector);
        vault.finalizeConflict();
        vm.warp(block.timestamp + CURE_PERIOD + 1);

        MordantInvoiceVault.Cancellation memory cancellation = MordantInvoiceVault.Cancellation({
            invoiceRoot: ROOT,
            pledgeDigest: vault.hashPledge(second),
            nonce: 9,
            deadline: uint64(block.timestamp + 1 hours)
        });
        bytes memory cancellationSignature =
            _signature(originatorKey, vault.hashCancellation(cancellation));
        vm.prank(facilityB);
        vm.expectRevert(MordantInvoiceVault.WindowClosed.selector);
        vault.cureConflict(cancellation, cancellationSignature);

        vault.finalizeConflict();
        vm.expectRevert(MordantInvoiceVault.InvalidState.selector);
        vault.finalizeConflict();
    }

    function testPendingCommitBlocksCleanCloseUntilExpiry() public {
        _activateSixtyForty(vault);
        vm.warp(protectionEnd);
        (MordantInvoiceVault.Pledge memory second, bytes memory signature) =
            _signedPledge(vault, facilityB, 2, originatorKey);
        bytes32 commitment = vault.conflictCommitment(
            vault.hashPledge(second), keccak256(signature), facilityB, SALT
        );
        vm.prank(facilityB);
        vault.commitConflict(commitment);

        vm.warp(block.timestamp + 1);
        vm.expectRevert(MordantInvoiceVault.InvalidState.selector);
        vault.closeProtection();

        vm.warp(block.timestamp + REVEAL_PERIOD + 1);
        vault.expireCommit();
        vault.closeProtection();
        vm.prank(originator);
        vault.claimSettlementCredit();
        assertEq(ausdc.balanceOf(originator), ADVANCE);
        assertEq(uint256(vault.receivableState()), 3);
    }

    function testDefaultReturnsExclusivityBondAndReleasesCvaClaim() public {
        _activateSixtyForty(vault);
        vm.warp(protectionEnd + 1);
        vault.closeProtection();

        vm.prank(originator);
        vault.claimSettlementCredit();
        assertEq(ausdc.balanceOf(originator), ADVANCE);
        assertEq(uint256(vault.receivableState()), 3);
        vm.prank(holderA);
        vault.releaseDefaultCva(20 * ONE);
        assertTrue(vault.defaultCvaReleaseStarted());

        ausdc.mint(buyer, FACE);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), FACE);
        vm.expectRevert(MordantInvoiceVault.InvalidAmount.selector);
        vault.fundRedemption(ONE);
        vm.stopPrank();
        vm.prank(holderB);
        vm.expectRevert(MordantInvoiceVault.InvalidAmount.selector);
        vault.redeem(ONE);

        vm.prank(holderA);
        vault.releaseDefaultCva(40 * ONE);
        vm.prank(holderB);
        vault.releaseDefaultCva(40 * ONE);
        assertEq(cva.balanceOf(holderA), 60 * ONE);
        assertEq(cva.balanceOf(holderB), 40 * ONE);
        assertEq(vault.totalSupply(), 0);
        assertEq(vault.cvaAccounted(), 0);

        vm.prank(buyer);
        vm.expectRevert(MordantInvoiceVault.InvalidState.selector);
        vault.fundRedemption(ONE);
    }

    function testLateCashRedemptionRemainsAvailableAfterDefaultUntilCvaReleaseStarts() public {
        _activateSixtyForty(vault);
        vm.warp(protectionEnd + 1);
        vault.closeProtection();
        _fundRedemption(FACE);

        vm.prank(holderA);
        assertEq(vault.redeem(60 * ONE), 66 * ONE);
        vm.prank(holderB);
        assertEq(vault.redeem(40 * ONE), 44 * ONE);
        assertFalse(vault.defaultCvaReleaseStarted());
        assertEq(uint256(vault.receivableState()), 2);
    }

    function testFullyFundedPostDefaultCashBlocksCvaAndAllowsRedemption() public {
        _activateSixtyForty(vault);
        vm.warp(protectionEnd + 1);
        vault.closeProtection();
        _fundRedemption(FACE);
        assertEq(vault.redemptionEscrow(), FACE);

        vm.prank(holderA);
        vm.expectRevert(MordantInvoiceVault.InvalidState.selector);
        vault.releaseDefaultCva(ONE);
        assertFalse(vault.defaultCvaReleaseStarted());

        vm.prank(holderA);
        vault.redeem(60 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);
    }

    function testBuyerCannotFundPostDefaultDustInsteadOfFullRemainingLiability() public {
        MockERC20 concentratedCva = new MockERC20("Concentrated invoice", "cINV", 6);
        MockCvaAdapter concentratedAdapter = new MockCvaAdapter(concentratedCva);
        factory.setCvaAdapter(address(concentratedAdapter), true);
        MordantInvoiceVault concentratedVault =
            _createVault(keccak256("concentrated-invoice"), concentratedAdapter, 10 * ONE);
        _creditVault(concentratedAdapter, concentratedCva, concentratedVault, 10 * ONE);
        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(concentratedVault), type(uint256).max);

        (MordantInvoiceVault.Pledge memory pledge, bytes memory signature) =
            _signedPledge(concentratedVault, facilityA, 1, originatorKey);
        address[] memory holders = new address[](2);
        holders[0] = holderA;
        holders[1] = holderB;
        uint256[] memory allocations = new uint256[](2);
        allocations[0] = 6 * ONE;
        allocations[1] = 4 * ONE;
        vm.prank(facilityA);
        concentratedVault.activate(pledge, signature, holderA, holders, allocations);

        vm.warp(protectionEnd + 1);
        concentratedVault.closeProtection();
        ausdc.mint(buyer, 1);
        vm.startPrank(buyer);
        ausdc.approve(address(concentratedVault), 1);
        vm.expectRevert(MordantInvoiceVault.InvalidAmount.selector);
        concentratedVault.fundRedemption(1);
        vm.stopPrank();

        assertEq(concentratedVault.redemptionEscrow(), 0);
        vm.prank(holderA);
        concentratedVault.releaseDefaultCva(ONE);
        assertTrue(concentratedVault.defaultCvaReleaseStarted());
    }

    function testPreDefaultPartialDustIsRefundedWhenCvaPathIsSelected() public {
        _activateSixtyForty(vault);
        ausdc.mint(buyer, 1);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), 1);
        vault.fundRedemption(1);
        vm.stopPrank();
        assertEq(ausdc.balanceOf(buyer), 0);

        vm.warp(protectionEnd + 1);
        vault.closeProtection();
        vm.prank(holderA);
        vault.releaseDefaultCva(ONE);
        vm.prank(holderA);
        vault.releaseDefaultCva(59 * ONE);
        vm.prank(holderB);
        vault.releaseDefaultCva(40 * ONE);

        assertEq(vault.redemptionEscrow(), 0);
        vm.prank(buyer);
        vault.claimSettlementCredit();
        assertEq(ausdc.balanceOf(buyer), 1);
        assertTrue(vault.defaultCvaReleaseStarted());
    }

    function testBuyerCanCompletePreDefaultPartialEscrowAfterDefault() public {
        _activateSixtyForty(vault);
        _fundRedemption(ONE);
        vm.warp(protectionEnd + 1);
        vault.closeProtection();

        ausdc.mint(buyer, FACE - ONE);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), FACE - ONE);
        vault.fundRedemption(FACE - ONE);
        vm.stopPrank();

        assertEq(vault.redemptionEscrow(), FACE);
        vm.prank(holderA);
        vm.expectRevert(MordantInvoiceVault.InvalidState.selector);
        vault.releaseDefaultCva(ONE);
        vm.prank(holderA);
        assertEq(vault.redeem(60 * ONE), 66 * ONE);
        vm.prank(holderB);
        assertEq(vault.redeem(40 * ONE), 44 * ONE);
    }

    function testPartiallyConsumedEscrowRemainderIsRefundedWhenCvaPathIsSelected() public {
        _activateSixtyForty(vault);
        _fundRedemption(60 * ONE);
        vm.warp(protectionEnd + 1);
        vault.closeProtection();

        vm.prank(holderA);
        assertEq(vault.redeem(50 * ONE), 55 * ONE);
        assertEq(vault.redemptionEscrow(), 5 * ONE);
        assertEq(ausdc.balanceOf(buyer), 0);

        vm.prank(holderB);
        vault.releaseDefaultCva(40 * ONE);
        vm.prank(holderA);
        vault.releaseDefaultCva(10 * ONE);
        assertEq(vault.redemptionEscrow(), 0);
        vm.prank(buyer);
        vault.claimSettlementCredit();
        assertEq(ausdc.balanceOf(buyer), 5 * ONE);
        assertTrue(vault.defaultCvaReleaseStarted());
    }

    function testUnauthorizedThirdPartyCannotFundDustToBlockDefaultCvaRelease() public {
        _activateSixtyForty(vault);
        vm.warp(protectionEnd + 1);
        vault.closeProtection();

        ausdc.mint(debtor, 1);
        vm.startPrank(debtor);
        ausdc.approve(address(vault), 1);
        vm.expectRevert(MordantInvoiceVault.Unauthorized.selector);
        vault.fundRedemption(1);
        vm.stopPrank();

        assertEq(vault.redemptionEscrow(), 0);
        vm.prank(holderA);
        vault.releaseDefaultCva(ONE);
        assertTrue(vault.defaultCvaReleaseStarted());
    }

    function testRedeemedUnitsDoNotBlockRemainingUnitsChoosingDefaultCvaWhenEscrowIsZero() public {
        _activateSixtyForty(vault);
        _fundRedemption(66 * ONE);
        vm.prank(holderA);
        vault.redeem(60 * ONE);
        assertEq(vault.redemptionEscrow(), 0);
        assertEq(vault.redeemedFace(), 66 * ONE);

        vm.warp(protectionEnd + 1);
        vault.closeProtection();
        vm.prank(holderB);
        vault.releaseDefaultCva(40 * ONE);
        assertTrue(vault.defaultCvaReleaseStarted());
        assertEq(cva.balanceOf(holderB), 40 * ONE);
        assertEq(vault.totalSupply(), 0);
    }

    function testFactoryRejectsUnapprovedAdapterAndSettlementToken() public {
        MockERC20 unapprovedCva = new MockERC20("Unapproved", "NOPE", 6);
        MockCvaAdapter unapprovedAdapter = new MockCvaAdapter(unapprovedCva);
        MordantFactory.InvoiceConfig memory config =
            _config(keccak256("unapproved-adapter"), unapprovedAdapter, UNITS);

        vm.prank(buyer);
        vm.expectRevert(MordantFactory.NotApproved.selector);
        factory.createInvoiceVault(config);

        factory.setCvaAdapter(address(unapprovedAdapter), true);
        MockERC20 unapprovedSettlement = new MockERC20("Unapproved cash", "NO-CASH", 6);
        config.settlementToken = address(unapprovedSettlement);
        vm.prank(buyer);
        vm.expectRevert(MordantFactory.NotApproved.selector);
        factory.createInvoiceVault(config);
    }

    function testFactoryRejectsMoreReceiptUnitsThanAtomicFaceValue() public {
        MockERC20 oversizedCva = new MockERC20("Oversized invoice", "OVERSIZED", 6);
        MockCvaAdapter oversizedAdapter = new MockCvaAdapter(oversizedCva);
        factory.setCvaAdapter(address(oversizedAdapter), true);
        MordantFactory.InvoiceConfig memory config =
            _config(keccak256("zero-value-atomic-lot"), oversizedAdapter, FACE + 1);

        vm.prank(buyer);
        vm.expectRevert(MordantInvoiceVault.InvalidConfiguration.selector);
        factory.createInvoiceVault(config);
    }

    function testRelatedPartyRoleOverlapIsRejected() public {
        eligibility.setEligible(buyer, 2, true);
        MordantFactory.InvoiceConfig memory config =
            _config(keccak256("buyer-is-originator"), cvaAdapter, UNITS);
        config.originatorTreasury = buyer;
        vm.prank(buyer);
        vm.expectRevert(MordantFactory.RoleOverlap.selector);
        factory.createInvoiceVault(config);

        _activateSixtyForty(vault);
        eligibility.setEligible(facilityB, 2, true);
        vm.prank(buyer);
        vm.expectRevert(MordantInvoiceVault.RoleOverlap.selector);
        vault.authorizeOriginatorWallet(facilityB);
    }

    function testSignatureHashMismatchCannotRevealCommittedConflict() public {
        _activateSixtyForty(vault);
        (MordantInvoiceVault.Pledge memory second, bytes memory signature) =
            _signedPledge(vault, facilityB, 2, originatorKey);
        bytes32 commitment = vault.conflictCommitment(
            vault.hashPledge(second), keccak256("different-signature"), facilityB, SALT
        );
        vm.prank(facilityB);
        vault.commitConflict(commitment);

        vm.prank(facilityB);
        vm.expectRevert(MordantInvoiceVault.InvalidCommitment.selector);
        vault.revealConflict(second, signature, SALT);
    }

    function testRedemptionFundingCannotExceedRemainingFaceValue() public {
        _activateSixtyForty(vault);
        ausdc.mint(buyer, FACE + 1);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), type(uint256).max);
        vm.expectRevert(MordantInvoiceVault.InvalidAmount.selector);
        vault.fundRedemption(FACE + 1);
        vault.fundRedemption(60 * ONE);
        vm.expectRevert(MordantInvoiceVault.InvalidAmount.selector);
        vault.fundRedemption(50 * ONE + 1);
        vm.stopPrank();
        assertEq(vault.redemptionEscrow(), 60 * ONE);
    }

    function testTransferToWalletWhoseEligibilityWasRevokedFails() public {
        _activateSixtyForty(vault);
        eligibility.setEligible(holderB, 4, false);
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderB, uint8(4))
        );
        vault.transfer(holderB, ONE);
        assertEq(vault.balanceOf(holderA), 60 * ONE);
        assertEq(vault.balanceOf(holderB), 40 * ONE);
    }

    function testRoundingDustGoesToHolderCompletingSnapshotSupply() public {
        MockERC20 tinyCva = new MockERC20("Tiny Invoice", "TINY", 6);
        MockCvaAdapter tinyAdapter = new MockCvaAdapter(tinyCva);
        factory.setCvaAdapter(address(tinyAdapter), true);
        MordantInvoiceVault tinyVault =
            _createVault(keccak256("three-unit-invoice"), tinyAdapter, 3);
        _creditVault(tinyAdapter, tinyCva, tinyVault, 3);
        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(tinyVault), type(uint256).max);

        (MordantInvoiceVault.Pledge memory first, bytes memory firstSignature) =
            _signedPledge(tinyVault, facilityA, 1, originatorKey);
        address[] memory holders = new address[](3);
        holders[0] = holderA;
        holders[1] = holderB;
        holders[2] = holderC;
        uint256[] memory allocations = new uint256[](3);
        allocations[0] = 1;
        allocations[1] = 1;
        allocations[2] = 1;
        vm.prank(facilityA);
        tinyVault.activate(first, firstSignature, holderA, holders, allocations);
        _finalizeConflict(tinyVault, 2);

        vm.prank(holderA);
        assertEq(tinyVault.claimBond(), 3_333_333);
        vm.prank(holderB);
        assertEq(tinyVault.claimBond(), 3_333_333);
        vm.prank(holderC);
        assertEq(tinyVault.claimBond(), 3_333_334);
        assertEq(tinyVault.entitlementClaimed(), 10 * ONE);
    }

    function testExternalCvaMintIsNotAcceptedSilently() public {
        _activateSixtyForty(vault);
        cva.mint(address(cvaAdapter), 50 * ONE);

        vm.expectRevert(MordantInvoiceVault.AccountingMismatch.selector);
        vault.assertAccounting();
        vm.prank(holderA);
        vm.expectRevert(MordantInvoiceVault.AccountingMismatch.selector);
        vault.transfer(holderB, ONE);
    }

    function testCrossContractSignatureReplayFails() public {
        _activateSixtyForty(vault);
        MockERC20 otherCva = new MockERC20("Other", "OTHER", 6);
        MockCvaAdapter otherAdapter = new MockCvaAdapter(otherCva);
        factory.setCvaAdapter(address(otherAdapter), true);
        MordantInvoiceVault otherVault = _createVault(keccak256("other-root"), otherAdapter, UNITS);
        _creditVault(otherAdapter, otherCva, otherVault, UNITS);
        ausdc.mint(holderA, ADVANCE);
        vm.prank(holderA);
        ausdc.approve(address(otherVault), type(uint256).max);

        MordantInvoiceVault.Pledge memory pledge = _pledge(otherVault, facilityA, 1);
        // Signed over the first vault's domain, not otherVault's.
        bytes memory wrongDomainSignature = _signature(originatorKey, vault.hashPledge(pledge));
        (address[] memory holders, uint256[] memory allocations) = _sixtyForty();
        vm.prank(facilityA);
        vm.expectRevert(MordantInvoiceVault.InvalidSignature.selector);
        otherVault.activate(pledge, wrongDomainSignature, holderA, holders, allocations);
    }

    function _createVault(bytes32 root, MockCvaAdapter adapter, uint256 units)
        private
        returns (MordantInvoiceVault created)
    {
        MordantFactory.InvoiceConfig memory config = _config(root, adapter, units);
        vm.prank(buyer);
        created = factory.createInvoiceVault(config);
        eligibility.setIdentityValid(address(created), true);
    }

    function _config(bytes32 root, MockCvaAdapter adapter, uint256 units)
        private
        view
        returns (MordantFactory.InvoiceConfig memory)
    {
        return MordantFactory.InvoiceConfig({
            cvaAdapter: address(adapter),
            settlementToken: address(ausdc),
            invoiceRoot: root,
            currency: CURRENCY,
            buyer: buyer,
            originatorTreasury: originator,
            initialOriginatorSigner: originator,
            initialUnits: units,
            advanceAmount: ADVANCE,
            faceValue: FACE,
            bondBps: 1_000,
            protectionEnd: protectionEnd,
            revealPeriod: REVEAL_PERIOD,
            curePeriod: CURE_PERIOD
        });
    }

    function _creditVault(
        MockCvaAdapter adapter,
        MockERC20 token,
        MordantInvoiceVault target,
        uint256 units
    ) private {
        token.mint(address(this), units);
        token.approve(address(adapter), units);
        adapter.creditVault(address(target), units);
    }

    function _activateSixtyForty(MordantInvoiceVault target) private {
        (MordantInvoiceVault.Pledge memory pledge, bytes memory signature) =
            _signedPledge(target, facilityA, 1, originatorKey);
        (address[] memory holders, uint256[] memory allocations) = _sixtyForty();
        vm.prank(facilityA);
        target.activate(pledge, signature, holderA, holders, allocations);
    }

    function _revealConflict(MordantInvoiceVault target, uint256 nonce)
        private
        returns (MordantInvoiceVault.Pledge memory second, bytes memory signature)
    {
        (second, signature) = _signedPledge(target, facilityB, nonce, originatorKey);
        bytes32 commitment = target.conflictCommitment(
            target.hashPledge(second), keccak256(signature), facilityB, SALT
        );
        vm.prank(facilityB);
        target.commitConflict(commitment);
        vm.prank(facilityB);
        target.revealConflict(second, signature, SALT);
    }

    function _finalizeConflict(MordantInvoiceVault target, uint256 nonce) private {
        _revealConflict(target, nonce);
        vm.warp(block.timestamp + CURE_PERIOD + 1);
        target.finalizeConflict();
    }

    function _fundRedemption(uint256 amount) private {
        ausdc.mint(buyer, amount);
        vm.startPrank(buyer);
        ausdc.approve(address(vault), type(uint256).max);
        vault.fundRedemption(amount);
        vm.stopPrank();
    }

    function _signedPledge(
        MordantInvoiceVault target,
        address facility,
        uint256 nonce,
        uint256 signerKey
    ) private view returns (MordantInvoiceVault.Pledge memory pledge, bytes memory signature) {
        pledge = _pledge(target, facility, nonce);
        signature = _signature(signerKey, target.hashPledge(pledge));
    }

    function _pledge(MordantInvoiceVault target, address facility, uint256 nonce)
        private
        view
        returns (MordantInvoiceVault.Pledge memory)
    {
        return MordantInvoiceVault.Pledge({
            invoiceRoot: target.invoiceRoot(),
            originatorSigner: originator,
            facility: facility,
            obligationId: keccak256(abi.encode("facility-obligation", facility, nonce)),
            amount: FACE,
            currency: CURRENCY,
            activeFrom: uint64(block.timestamp - 1),
            activeUntil: protectionEnd + 1,
            nonce: nonce,
            deadline: uint64(block.timestamp + 2 days),
            exclusive: true
        });
    }

    function _signature(uint256 signerKey, bytes32 digest) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sixtyForty()
        private
        view
        returns (address[] memory holders, uint256[] memory allocations)
    {
        holders = new address[](2);
        holders[0] = holderA;
        holders[1] = holderB;
        allocations = new uint256[](2);
        allocations[0] = 60 * ONE;
        allocations[1] = 40 * ONE;
    }
}
