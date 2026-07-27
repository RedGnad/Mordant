// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { Test } from "forge-std/Test.sol";

import { CleanverseAPassVerifier } from "../src/cleanverse/CleanverseAPassVerifier.sol";
import { CleanverseCvaAdapter } from "../src/cleanverse/CleanverseCvaAdapter.sol";
import { ICleanverseAPass } from "../src/cleanverse/ICleanverseAPass.sol";
import { ICleanverseAToken } from "../src/cleanverse/ICleanverseAToken.sol";
import { ICleanversePolicy } from "../src/cleanverse/ICleanversePolicy.sol";
import { MordantFactory } from "../src/MordantFactory.sol";
import { MordantInvoiceVault } from "../src/MordantInvoiceVault.sol";

contract MockAPass is ICleanverseAPass {
    mapping(address account => bool valid) public validity;
    bool public shouldRevert;

    function setValid(address account, bool valid) external {
        validity[account] = valid;
    }

    function setShouldRevert(bool enabled) external {
        shouldRevert = enabled;
    }

    function isValidAPass(address account) external view returns (bool) {
        if (shouldRevert) revert("APass unavailable");
        return validity[account];
    }
}

contract MockCleanversePolicy is ICleanversePolicy {
    ICleanverseAPass public immutable apass;
    mapping(address account => bool allowed) public policyEligibility;
    mapping(bytes32 transferKey => bool denied) public deniedTransfer;
    mapping(address token => mapping(address account => uint256 maximum)) public holdingCap;
    mapping(address token => mapping(address account => bool enabled)) public holdingCapEnabled;
    bool public shouldRevert;

    constructor(ICleanverseAPass apass_) {
        apass = apass_;
    }

    function setAllowed(address account, bool allowed) external {
        policyEligibility[account] = allowed;
    }

    function setShouldRevert(bool enabled) external {
        shouldRevert = enabled;
    }

    function setHoldingCap(address token, address account, uint256 maximum, bool enabled) external {
        holdingCap[token][account] = maximum;
        holdingCapEnabled[token][account] = enabled;
    }

    function setTransferDenied(address token, address from, address to, uint256 amount, bool denied)
        external
    {
        deniedTransfer[keccak256(abi.encode(token, from, to, amount))] = denied;
    }

    function canTransfer(address token, address from, address to, uint256 amount)
        external
        view
        returns (bool)
    {
        if (shouldRevert) revert("Policy unavailable");
        if (deniedTransfer[keccak256(abi.encode(token, from, to, amount))]) return false;
        if (to != address(0) && holdingCapEnabled[token][to]) {
            uint256 currentBalance = IERC20(token).balanceOf(to);
            uint256 maximum = holdingCap[token][to];
            if (currentBalance > maximum || amount > maximum - currentBalance) return false;
        }
        return _isAllowed(from) && _isAllowed(to);
    }

    function _isAllowed(address account) private view returns (bool) {
        if (account == address(0)) return true;
        if (!policyEligibility[account]) return false;
        try apass.isValidAPass(account) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }
}

contract MockCleanverseAToken is ERC20, ICleanverseAToken {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    mapping(address account => bool allowed) public minter;
    uint8 private immutable tokenDecimals;
    address public immutable policy;
    bool private bypassPolicy;

    error Unauthorized();
    error TransferNotAllowed();

    constructor(uint8 decimals_, address policy_) ERC20("Invoice A-Token", "aINV") {
        minter[msg.sender] = true;
        tokenDecimals = decimals_;
        policy = policy_;
    }

    function decimals() public view override(ERC20, ICleanverseAToken) returns (uint8) {
        return tokenDecimals;
    }

    function setMinter(address account, bool allowed) external {
        minter[account] = allowed;
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return role == MINTER_ROLE && minter[account];
    }

    function mint(address account, uint256 amount) external {
        if (!minter[msg.sender]) revert Unauthorized();
        _mint(account, amount);
    }

    function forceTransfer(address from, address to, uint256 amount) external {
        bypassPolicy = true;
        _transfer(from, to, amount);
        bypassPolicy = false;
    }

    function burn(address account, uint256 amount) external {
        if (!minter[msg.sender]) revert Unauthorized();
        _burn(account, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (!bypassPolicy && !ICleanversePolicy(policy).canTransfer(address(this), from, to, value))
        {
            revert TransferNotAllowed();
        }
        super._update(from, to, value);
    }
}

contract BoundVaultCaller {
    address public immutable cvaAdapter;
    address public immutable cvaToken;
    uint256 public immutable initialUnits;

    constructor(address adapter, address token, uint256 units) {
        cvaAdapter = adapter;
        cvaToken = token;
        initialUnits = units;
    }

    function consume(CleanverseCvaAdapter adapter, uint256 units) external {
        adapter.consumeOnRedemption(address(this), units);
    }

    function release(CleanverseCvaAdapter adapter, address holder, uint256 units) external {
        adapter.releaseOnDefault(address(this), holder, units);
    }

    function transferReceipt(MordantInvoiceVault receipt, address holder, uint256 units) external {
        receipt.transfer(holder, units);
    }
}

contract CleanverseAdaptersTest is Test {
    uint256 private constant UNITS = 100e6;
    uint8 private constant ROLE_BUYER = 1;
    uint8 private constant ROLE_HOLDER = 4;

    address private buyer = makeAddr("buyer");
    address private holder = makeAddr("holder");
    address private stranger = makeAddr("stranger");

    MockAPass private apass;
    MockCleanversePolicy private policy;
    CleanverseAPassVerifier private verifier;
    MockCleanverseAToken private token;
    CleanverseCvaAdapter private adapter;
    BoundVaultCaller private vault;

    function setUp() public {
        apass = new MockAPass();
        policy = new MockCleanversePolicy(apass);
        verifier = new CleanverseAPassVerifier(address(this), apass, uint256(1) << ROLE_HOLDER);
        token = new MockCleanverseAToken(6, address(policy));
        adapter = new CleanverseCvaAdapter(address(this), token, apass);
        vault = new BoundVaultCaller(address(adapter), address(token), UNITS);
        policy.setAllowed(address(adapter), true);
        policy.setAllowed(holder, true);
        apass.setValid(holder, true);
    }

    function testVerifierRequiresLiveAPassAndRoleAuthorization() public {
        apass.setValid(buyer, true);
        assertFalse(verifier.isEligible(buyer, ROLE_BUYER));

        verifier.setRoleEligibility(buyer, ROLE_BUYER, true);
        assertTrue(verifier.isEligible(buyer, ROLE_BUYER));

        apass.setValid(buyer, false);
        assertFalse(verifier.isEligible(buyer, ROLE_BUYER));
    }

    function testVerifierAllowsAnyValidAPassForOpenHolderRole() public {
        apass.setValid(holder, true);
        assertTrue(verifier.isEligible(holder, ROLE_HOLDER));
        assertFalse(verifier.isEligible(stranger, ROLE_HOLDER));
        assertFalse(verifier.isEligible(holder, 0));
        assertFalse(verifier.isEligible(holder, 5));
    }

    function testVerifierFailsClosedWhenAPassCallReverts() public {
        apass.setValid(holder, true);
        apass.setShouldRevert(true);
        assertFalse(verifier.isEligible(holder, ROLE_HOLDER));
    }

    function testVerifierMirrorsCvaPolicyForExactDeliveryAmount() public {
        apass.setValid(address(adapter), true);
        assertTrue(
            verifier.isEligibleForAsset(
                holder, ROLE_HOLDER, address(token), address(adapter), UNITS
            )
        );

        policy.setTransferDenied(address(token), address(adapter), holder, UNITS, true);
        assertFalse(
            verifier.isEligibleForAsset(
                holder, ROLE_HOLDER, address(token), address(adapter), UNITS
            )
        );
        assertTrue(
            verifier.isEligibleForAsset(holder, ROLE_HOLDER, address(token), address(adapter), 1)
        );

        policy.setShouldRevert(true);
        assertFalse(
            verifier.isEligibleForAsset(holder, ROLE_HOLDER, address(token), address(adapter), 1)
        );
    }

    function testVerifierMirrorsDirectHolderTransferPolicy() public {
        apass.setValid(address(adapter), true);
        apass.setValid(buyer, true);
        policy.setAllowed(buyer, true);
        assertTrue(verifier.isAssetTransferAllowed(address(token), holder, buyer, 7));

        policy.setTransferDenied(address(token), holder, buyer, 7, true);
        assertFalse(verifier.isAssetTransferAllowed(address(token), holder, buyer, 7));
        assertTrue(verifier.isAssetTransferAllowed(address(token), holder, buyer, 8));
    }

    function testOnlyOwnerCanGrantRestrictedRole() public {
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger)
        );
        verifier.setRoleEligibility(buyer, ROLE_BUYER, true);
    }

    function testVerifierCannotOpenInstitutionalRolesByConfiguration() public {
        vm.expectRevert(CleanverseAPassVerifier.InvalidConfiguration.selector);
        new CleanverseAPassVerifier(address(this), apass, uint256(1) << ROLE_BUYER);
    }

    function testAdapterBindsCompleteSupplyThenBurnsAndReleasesExactCredit() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        assertEq(adapter.asset(), address(token));
        assertEq(adapter.issuedSupply(), UNITS);
        assertEq(adapter.availableBalance(address(vault)), UNITS);

        vault.consume(adapter, 40e6);
        assertEq(adapter.issuedSupply(), 60e6);
        assertEq(adapter.availableBalance(address(vault)), 60e6);
        assertEq(token.balanceOf(address(adapter)), 60e6);

        vault.release(adapter, holder, 20e6);
        assertEq(adapter.issuedSupply(), 60e6);
        assertEq(adapter.availableBalance(address(vault)), 40e6);
        assertEq(token.balanceOf(address(adapter)), 40e6);
        assertEq(token.balanceOf(holder), 20e6);
    }

    function testAdapterRejectsPartialOrAmbiguousInitialCustody() public {
        apass.setValid(address(adapter), true);
        apass.setValid(stranger, true);
        policy.setAllowed(stranger, true);
        token.setMinter(address(adapter), true);
        token.mint(address(adapter), UNITS - 1);
        token.mint(stranger, 1);

        vm.expectRevert(CleanverseCvaAdapter.AccountingMismatch.selector);
        adapter.bindVault(address(vault), UNITS);
    }

    function testAdapterBindingIsIrrevocable() public {
        apass.setValid(address(adapter), true);
        token.setMinter(address(adapter), true);
        token.mint(address(adapter), UNITS);
        adapter.bindVault(address(vault), UNITS);

        vm.expectRevert(CleanverseCvaAdapter.AlreadyBound.selector);
        adapter.bindVault(address(vault), UNITS);
    }

    function testOnlyBoundVaultCanConsumeCredit() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        vm.expectRevert(CleanverseCvaAdapter.UnauthorizedVault.selector);
        adapter.consumeOnRedemption(address(vault), 1);
    }

    function testAdapterRejectsBindingWithoutLiveAPass() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        apass.setValid(address(adapter), false);

        vm.expectRevert(CleanverseCvaAdapter.InvalidCustodyIdentity.selector);
        adapter.bindVault(address(vault), UNITS);
    }

    function testAdapterRejectsBindingWithoutMinterRole() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);

        vm.expectRevert(CleanverseCvaAdapter.MissingMinterRole.selector);
        adapter.bindVault(address(vault), UNITS);
    }

    function testAdapterRejectsVaultWhoseImmutableBindingDoesNotMatch() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        BoundVaultCaller wrongVault =
            new BoundVaultCaller(address(adapter), address(token), UNITS + 1);

        vm.expectRevert(CleanverseCvaAdapter.InvalidConfiguration.selector);
        adapter.bindVault(address(wrongVault), UNITS);
    }

    function testAdapterRejectsATokenWithDifferentUnitScale() public {
        MockCleanverseAToken wrongScaleToken = new MockCleanverseAToken(18, address(policy));
        CleanverseCvaAdapter wrongScaleAdapter =
            new CleanverseCvaAdapter(address(this), wrongScaleToken, apass);
        BoundVaultCaller wrongScaleVault =
            new BoundVaultCaller(address(wrongScaleAdapter), address(wrongScaleToken), UNITS);
        apass.setValid(address(wrongScaleAdapter), true);
        policy.setAllowed(address(wrongScaleAdapter), true);
        wrongScaleToken.mint(address(wrongScaleAdapter), UNITS);
        wrongScaleToken.setMinter(address(wrongScaleAdapter), true);

        vm.expectRevert(
            abi.encodeWithSelector(CleanverseCvaAdapter.InvalidTokenDecimals.selector, uint8(18))
        );
        wrongScaleAdapter.bindVault(address(wrongScaleVault), UNITS);
    }

    function testReadinessTracksAPassAndBurnRole() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);
        assertTrue(adapter.isActivationReady(address(vault)));
        assertTrue(adapter.isCashRedemptionReady(address(vault)));

        apass.setValid(address(adapter), false);
        assertFalse(adapter.isActivationReady(address(vault)));
        assertFalse(adapter.isCashRedemptionReady(address(vault)));

        token.setMinter(address(adapter), false);
        assertFalse(adapter.isActivationReady(address(vault)));
        assertFalse(adapter.isCashRedemptionReady(address(vault)));
    }

    function testBaseReadinessAvoidsFullSupplyFalseNegativeButExactReadinessFailsClosed() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        policy.setTransferDenied(address(token), address(adapter), address(0), UNITS, true);
        assertTrue(adapter.isActivationReady(address(vault)));
        assertTrue(adapter.isCashRedemptionReady(address(vault)));
        assertFalse(adapter.isRedemptionReady(address(vault), UNITS));

        policy.setTransferDenied(address(token), address(adapter), address(0), UNITS, false);
        policy.setShouldRevert(true);
        assertTrue(adapter.isActivationReady(address(vault)));
        assertTrue(adapter.isCashRedemptionReady(address(vault)));
        assertFalse(adapter.isRedemptionReady(address(vault), UNITS));
    }

    function testAdapterRechecksExactPolicyOnBurnAndDefaultRelease() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        policy.setTransferDenied(address(token), address(adapter), address(0), 40e6, true);
        assertTrue(adapter.isCashRedemptionReady(address(vault)));
        assertFalse(adapter.isRedemptionReady(address(vault), 40e6));
        vm.expectRevert(CleanverseCvaAdapter.TransferPolicyDenied.selector);
        vault.consume(adapter, 40e6);
        assertEq(adapter.availableBalance(address(vault)), UNITS);

        policy.setTransferDenied(address(token), address(adapter), holder, 20e6, true);
        vm.expectRevert(CleanverseCvaAdapter.TransferPolicyDenied.selector);
        vault.release(adapter, holder, 20e6);
        assertEq(adapter.availableBalance(address(vault)), UNITS);
    }

    function testAdapterRequiresAPassForBothBurnAndTransfer() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        apass.setValid(address(adapter), false);
        vm.expectRevert(CleanverseCvaAdapter.InvalidCustodyIdentity.selector);
        vault.consume(adapter, 1);

        vm.expectRevert(CleanverseCvaAdapter.InvalidCustodyIdentity.selector);
        vault.release(adapter, holder, 1);

        apass.setValid(address(adapter), true);
        token.setMinter(address(adapter), false);
        vm.expectRevert(CleanverseCvaAdapter.MissingMinterRole.selector);
        vault.consume(adapter, 1);
    }

    function testMinterRevocationDoesNotBlockDefaultAssetRelease() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        token.setMinter(address(adapter), false);
        vault.release(adapter, holder, 1);
        assertEq(token.balanceOf(holder), 1);
        assertEq(adapter.availableBalance(address(vault)), UNITS - 1);
    }

    function testAvailableBalanceFailsClosedOnCustodyDeficit() public {
        apass.setValid(address(adapter), true);
        token.mint(address(adapter), UNITS);
        token.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);

        token.forceTransfer(address(adapter), stranger, 1);
        vm.expectRevert(CleanverseCvaAdapter.AccountingMismatch.selector);
        adapter.availableBalance(address(vault));
    }
}

contract CleanverseBoundaryIntegrationTest is Test {
    uint256 private constant ONE = 1e6;
    uint256 private constant ADVANCE = 100 * ONE;
    uint256 private constant FACE = 110 * ONE;
    uint256 private constant UNITS = 100 * ONE;
    uint8 private constant ROLE_BUYER = 1;
    uint8 private constant ROLE_ORIGINATOR = 2;
    uint8 private constant ROLE_FACILITY = 3;
    uint8 private constant ROLE_HOLDER = 4;
    bytes32 private constant ROOT = keccak256("cleanverse-boundary-invoice");
    bytes32 private constant CURRENCY = bytes32("USD");

    uint256 private buyerKey = 0xB0B;
    uint256 private originatorKey = 0xA11CE;
    uint256 private facilityKey = 0xFA11;
    uint256 private holderAKey = 0xAA01;

    address private buyer;
    address private originator;
    address private facility;
    address private holderA;
    address private holderB;

    MockCleanverseAToken private cva;
    MockCleanversePolicy private cvaPolicy;
    MockCleanversePolicy private settlementPolicy;
    MockAPass private apass;
    CleanverseCvaAdapter private adapter;
    MockCleanverseAToken private settlement;
    MordantInvoiceVault private vault;

    function setUp() public {
        vm.warp(1_000_000);
        buyer = vm.addr(buyerKey);
        originator = vm.addr(originatorKey);
        facility = vm.addr(facilityKey);
        holderA = vm.addr(holderAKey);
        holderB = vm.addr(0xBB02);

        apass = new MockAPass();
        apass.setValid(buyer, true);
        apass.setValid(originator, true);
        apass.setValid(facility, true);
        apass.setValid(holderA, true);
        apass.setValid(holderB, true);

        cvaPolicy = new MockCleanversePolicy(apass);
        settlementPolicy = new MockCleanversePolicy(apass);

        CleanverseAPassVerifier verifier =
            new CleanverseAPassVerifier(address(this), apass, uint256(1) << ROLE_HOLDER);
        verifier.setRoleEligibility(buyer, ROLE_BUYER, true);
        verifier.setRoleEligibility(originator, ROLE_ORIGINATOR, true);
        verifier.setRoleEligibility(facility, ROLE_FACILITY, true);

        cva = new MockCleanverseAToken(6, address(cvaPolicy));
        adapter = new CleanverseCvaAdapter(address(this), cva, apass);
        apass.setValid(address(adapter), true);
        cvaPolicy.setAllowed(address(adapter), true);
        cvaPolicy.setAllowed(holderA, true);
        cvaPolicy.setAllowed(holderB, true);
        settlement = new MockCleanverseAToken(6, address(settlementPolicy));
        settlementPolicy.setAllowed(buyer, true);
        settlementPolicy.setAllowed(originator, true);
        settlementPolicy.setAllowed(holderA, true);
        settlementPolicy.setAllowed(holderB, true);
        MordantFactory factory = new MordantFactory(address(this), verifier);
        factory.setFacility(facility, true);
        factory.setCvaAdapter(address(adapter), true);
        factory.setSettlementToken(address(settlement), true);

        MordantFactory.InvoiceConfig memory config = MordantFactory.InvoiceConfig({
            cvaAdapter: address(adapter),
            settlementToken: address(settlement),
            invoiceRoot: ROOT,
            currency: CURRENCY,
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
        vault = factory.createInvoiceVault(config);

        apass.setValid(address(vault), true);
        settlementPolicy.setAllowed(address(vault), true);

        cva.mint(address(adapter), UNITS);
        cva.setMinter(address(adapter), true);
        adapter.bindVault(address(vault), UNITS);
        settlement.mint(holderA, ADVANCE);
        vm.prank(holderA);
        settlement.approve(address(vault), ADVANCE);
    }

    function testConcreteBoundariesFinanceAndRedeemAgainstProtocolDoubles() public {
        _activate();
        assertEq(settlement.balanceOf(originator), 90 * ONE);
        assertEq(adapter.availableBalance(address(vault)), UNITS);

        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();
        vm.prank(holderA);
        vault.redeem(60 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);

        assertEq(adapter.availableBalance(address(vault)), 0);
        assertEq(cva.totalSupply(), 0);
        assertEq(vault.totalSupply(), 0);
        vault.assertAccounting();
    }

    function testConcreteBoundariesReleaseCvaAfterDefault() public {
        _activate();
        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();

        vm.prank(holderA);
        vault.releaseDefaultCva(60 * ONE);
        vm.prank(holderB);
        vault.releaseDefaultCva(40 * ONE);

        assertEq(cva.balanceOf(holderA), 60 * ONE);
        assertEq(cva.balanceOf(holderB), 40 * ONE);
        assertEq(adapter.availableBalance(address(vault)), 0);
        assertEq(cva.totalSupply(), UNITS);
        assertEq(vault.totalSupply(), 0);
        vault.assertAccounting();
    }

    function testActivationRejectsCvaCustodyDeficitBeforeFinancingMoves() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        cva.forceTransfer(address(adapter), buyer, 1);

        vm.startPrank(facility);
        vm.expectRevert(CleanverseCvaAdapter.AccountingMismatch.selector);
        vault.activate(pledge, signature, holderA, holders, allocations);
        vm.stopPrank();

        assertEq(settlement.balanceOf(originator), 0);
        assertEq(settlement.balanceOf(holderA), ADVANCE);
    }

    function testActivationRechecksAdapterAPassBeforeFinancingMoves() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        apass.setValid(address(adapter), false);

        vm.startPrank(facility);
        vm.expectRevert(MordantInvoiceVault.CvaNotReady.selector);
        vault.activate(pledge, signature, holderA, holders, allocations);
        vm.stopPrank();

        assertEq(settlement.balanceOf(originator), 0);
        assertEq(settlement.balanceOf(holderA), ADVANCE);
    }

    function testActivationRejectsVaultWithoutAPassBeforeFinancingMoves() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        apass.setValid(address(vault), false);

        vm.startPrank(facility);
        vm.expectRevert(MordantInvoiceVault.SettlementNotReady.selector);
        vault.activate(pledge, signature, holderA, holders, allocations);
        vm.stopPrank();

        assertEq(settlement.balanceOf(originator), 0);
        assertEq(settlement.balanceOf(holderA), ADVANCE);
        assertEq(vault.totalSupply(), 0);
    }

    function testActivationRejectsAPassedHolderDeniedByCvaPolicy() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        cvaPolicy.setAllowed(holderB, false);

        vm.startPrank(facility);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderB, ROLE_HOLDER)
        );
        vault.activate(pledge, signature, holderA, holders, allocations);
        vm.stopPrank();

        assertEq(settlement.balanceOf(originator), 0);
        assertEq(settlement.balanceOf(holderA), ADVANCE);
    }

    function testActivationChecksEachExactAllocationBurn() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        cvaPolicy.setTransferDenied(
            address(cva), address(adapter), address(0), allocations[0], true
        );

        vm.prank(facility);
        vm.expectRevert(MordantInvoiceVault.CvaNotReady.selector);
        vault.activate(pledge, signature, holderA, holders, allocations);
        assertEq(settlement.balanceOf(originator), 0);
        assertEq(settlement.balanceOf(holderA), ADVANCE);
    }

    function testActivationRejectsDuplicateHolderAllocations() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        holders[1] = holderA;

        vm.prank(facility);
        vm.expectRevert(MordantInvoiceVault.InvalidAllocation.selector);
        vault.activate(pledge, signature, holderA, holders, allocations);

        assertEq(settlement.balanceOf(originator), 0);
        assertEq(settlement.balanceOf(holderA), ADVANCE);
        assertEq(vault.totalSupply(), 0);
    }

    function testFullSupplyBurnLimitDoesNotRejectExecutableHolderLots() public {
        cvaPolicy.setTransferDenied(address(cva), address(adapter), address(0), UNITS, true);
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();

        vm.prank(holderA);
        vault.redeem(60 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);
        assertEq(vault.totalSupply(), 0);
        assertEq(cva.totalSupply(), 0);
    }

    function testNonAllocatedFunderNeedsIdentityButNotCvaDeliverability() public {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        address payer = makeAddr("payer");
        apass.setValid(payer, true);
        settlementPolicy.setAllowed(payer, true);
        settlement.mint(payer, ADVANCE);
        vm.prank(payer);
        settlement.approve(address(vault), ADVANCE);

        vm.prank(facility);
        vault.activate(pledge, signature, payer, holders, allocations);

        assertEq(cvaPolicy.policyEligibility(payer), false);
        assertEq(settlement.balanceOf(originator), 90 * ONE);
        assertEq(vault.balanceOf(payer), 0);
    }

    function testReceiptTransferMirrorsExactUnderlyingPolicyPair() public {
        _activate();
        uint256 units = 10 * ONE;
        cvaPolicy.setTransferDenied(address(cva), holderA, holderB, units, true);

        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderB, ROLE_HOLDER)
        );
        vault.transfer(holderB, units);
        assertEq(vault.balanceOf(holderA), 60 * ONE);
        assertEq(vault.balanceOf(holderB), 40 * ONE);

        cvaPolicy.setTransferDenied(address(cva), holderA, holderB, units, false);
        vm.prank(holderA);
        vault.transfer(holderB, units);
        assertEq(vault.balanceOf(holderA), 50 * ONE);
        assertEq(vault.balanceOf(holderB), 50 * ONE);
    }

    function testReceiptTransferChecksRecipientsCompleteFutureCvaBalance() public {
        cvaPolicy.setHoldingCap(address(cva), holderB, 45 * ONE, true);
        _activate();

        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderB, ROLE_HOLDER)
        );
        vault.transfer(holderB, 6 * ONE);

        vm.prank(holderA);
        vault.transfer(holderB, 5 * ONE);
        assertEq(vault.balanceOf(holderA), 55 * ONE);
        assertEq(vault.balanceOf(holderB), 45 * ONE);
    }

    function testPartialCvaReleaseReservesCapacityForResidualReceiptClaim() public {
        cvaPolicy.setHoldingCap(address(cva), holderA, 60 * ONE, true);
        _activate();
        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();

        vm.prank(holderA);
        vault.releaseDefaultCva(20 * ONE);
        assertEq(cva.balanceOf(holderA), 20 * ONE);
        assertEq(vault.balanceOf(holderA), 40 * ONE);

        vm.prank(holderB);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderA, ROLE_HOLDER)
        );
        vault.transfer(holderA, ONE);

        vm.prank(holderA);
        vault.releaseDefaultCva(40 * ONE);
        assertEq(cva.balanceOf(holderA), 60 * ONE);
        assertEq(vault.balanceOf(holderA), 0);
    }

    function testZeroReceiptTransferRemainsPolicyCheckedAndErc20Compatible() public {
        _activate();
        vm.prank(holderA);
        assertTrue(vault.transfer(holderB, 0));

        cvaPolicy.setTransferDenied(address(cva), holderA, holderB, 0, true);
        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderB, ROLE_HOLDER)
        );
        vault.transfer(holderB, 0);
    }

    function testDefaultReleaseChecksExactAdapterToHolderPolicy() public {
        _activate();
        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();
        uint256 units = 60 * ONE;
        cvaPolicy.setTransferDenied(address(cva), address(adapter), holderA, units, true);

        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(MordantInvoiceVault.Ineligible.selector, holderA, ROLE_HOLDER)
        );
        vault.releaseDefaultCva(units);
        assertEq(vault.balanceOf(holderA), units);
        assertEq(cva.balanceOf(holderA), 0);

        cvaPolicy.setTransferDenied(address(cva), address(adapter), holderA, units, false);
        vm.prank(holderA);
        vault.releaseDefaultCva(units);
        assertEq(vault.balanceOf(holderA), 0);
        assertEq(cva.balanceOf(holderA), units);
    }

    function testSystemContractsCannotBecomeReceiptHoldersButOtherContractsCan() public {
        _activate();
        cvaPolicy.setAllowed(address(vault), true);

        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantInvoiceVault.Ineligible.selector, address(adapter), ROLE_HOLDER
            )
        );
        vault.transfer(address(adapter), ONE);

        vm.prank(holderA);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantInvoiceVault.Ineligible.selector, address(vault), ROLE_HOLDER
            )
        );
        vault.transfer(address(vault), ONE);

        BoundVaultCaller smartWallet = new BoundVaultCaller(address(0x1), address(0x2), 1);
        apass.setValid(address(smartWallet), true);
        cvaPolicy.setAllowed(address(smartWallet), true);
        vm.prank(holderA);
        vault.transfer(address(smartWallet), ONE);
        assertEq(vault.balanceOf(address(smartWallet)), ONE);
        smartWallet.transferReceipt(vault, holderA, ONE);
        assertEq(vault.balanceOf(address(smartWallet)), 0);
    }

    function testCashFundingRejectsRevokedBurnRoleBeforeTakingBuyerFunds() public {
        _activate();
        cva.setMinter(address(adapter), false);
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vm.expectRevert(MordantInvoiceVault.CvaNotReady.selector);
        vault.fundRedemption(FACE);
        vm.stopPrank();

        assertEq(settlement.balanceOf(buyer), FACE);
        assertEq(vault.redemptionEscrow(), 0);
    }

    function testCashFundingRejectsExpiredAdapterAPassBeforeTakingBuyerFunds() public {
        _activate();
        apass.setValid(address(adapter), false);
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vm.expectRevert(MordantInvoiceVault.CvaNotReady.selector);
        vault.fundRedemption(FACE);
        vm.stopPrank();

        assertEq(settlement.balanceOf(buyer), FACE);
        assertEq(vault.redemptionEscrow(), 0);
    }

    function testVaultAPassRevocationKeepsFundingAndRedemptionAtomic() public {
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        apass.setValid(address(vault), false);
        vm.expectRevert(MordantInvoiceVault.SettlementNotReady.selector);
        vault.fundRedemption(FACE);
        vm.stopPrank();
        assertEq(settlement.balanceOf(buyer), FACE);
        assertEq(vault.redemptionEscrow(), 0);

        apass.setValid(address(vault), true);
        vm.prank(buyer);
        vault.fundRedemption(FACE);
        uint256 cvaSupplyBefore = cva.totalSupply();
        uint256 escrowBefore = vault.redemptionEscrow();
        apass.setValid(address(vault), false);

        vm.prank(holderA);
        vm.expectRevert(MordantInvoiceVault.SettlementNotReady.selector);
        vault.redeem(60 * ONE);
        assertEq(cva.totalSupply(), cvaSupplyBefore);
        assertEq(vault.redemptionEscrow(), escrowBefore);
        assertEq(vault.balanceOf(holderA), 60 * ONE);

        apass.setValid(address(vault), true);
        vm.prank(holderA);
        vault.redeem(60 * ONE);
        assertEq(vault.balanceOf(holderA), 0);
    }

    function testCashRedemptionDoesNotDependOnHolderCvaDeliveryPolicy() public {
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();

        cvaPolicy.setTransferDenied(address(cva), address(adapter), holderA, 60 * ONE, true);
        vm.prank(holderA);
        vault.redeem(60 * ONE);

        assertEq(vault.balanceOf(holderA), 0);
        assertEq(settlement.balanceOf(holderA), 66 * ONE);
        assertEq(cva.totalSupply(), 40 * ONE);
    }

    function testAmountSensitiveBurnCannotTrapFullyFundedCashAndCva() public {
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();
        cvaPolicy.setTransferDenied(address(cva), address(adapter), address(0), 1, true);

        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();
        vm.prank(holderA);
        vm.expectRevert(MordantInvoiceVault.InvalidState.selector);
        vault.releaseDefaultCva(1);

        cvaPolicy.setTransferDenied(address(cva), address(adapter), address(0), 1, false);
        cvaPolicy.setTransferDenied(address(cva), address(adapter), address(0), 60 * ONE, true);
        vm.prank(holderA);
        vault.releaseDefaultCva(60 * ONE);

        assertEq(vault.redemptionEscrow(), 44 * ONE);
        vm.prank(buyer);
        assertEq(vault.claimSettlementCredit(), 66 * ONE);
        assertEq(settlement.balanceOf(buyer), 66 * ONE);
        assertEq(cva.balanceOf(holderA), 60 * ONE);
        assertEq(vault.balanceOf(holderA), 0);

        vm.prank(holderB);
        vault.redeem(40 * ONE);
        assertEq(settlement.balanceOf(holderB), 44 * ONE);
        assertEq(cva.balanceOf(holderB), 0);
        assertEq(cva.totalSupply(), 60 * ONE);
        assertEq(vault.totalSupply(), 0);
        assertEq(adapter.availableBalance(address(vault)), 0);
    }

    function testDeniedExactCashTransferFallsBackPerHolderToCva() public {
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();
        settlementPolicy.setTransferDenied(
            address(settlement), address(vault), holderA, 66 * ONE, true
        );

        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();
        vm.prank(holderA);
        vm.expectRevert(MordantInvoiceVault.SettlementNotReady.selector);
        vault.redeem(60 * ONE);
        vm.prank(holderA);
        vault.releaseDefaultCva(60 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);

        assertEq(cva.balanceOf(holderA), 60 * ONE);
        assertEq(settlement.balanceOf(holderB), 44 * ONE);
        assertEq(vault.settlementCredit(buyer), 66 * ONE);
        assertEq(vault.totalSupply(), 0);
    }

    function testSplitNonBurnableWalletCannotForceOtherHoldersOffCash() public {
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();

        address splitHolder = makeAddr("split-holder");
        apass.setValid(splitHolder, true);
        cvaPolicy.setAllowed(splitHolder, true);
        vm.prank(holderA);
        vault.transfer(splitHolder, ONE);
        cvaPolicy.setTransferDenied(address(cva), address(adapter), address(0), ONE, true);

        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();
        vm.prank(splitHolder);
        vault.releaseDefaultCva(ONE);
        vm.prank(holderA);
        vault.redeem(59 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);

        assertEq(cva.balanceOf(splitHolder), ONE);
        assertEq(cva.totalSupply(), ONE);
        assertEq(vault.totalSupply(), 0);
        assertEq(vault.redemptionEscrow(), 0);
        assertEq(vault.settlementCredit(buyer), 11 * ONE / 10);
        assertEq(vault.cvaReleasedFace(), 11 * ONE / 10);
        assertEq(vault.cvaReleasedFace() + vault.redeemedFace(), FACE);
    }

    function testExpiredOriginatorCannotBlockHolderRedemption() public {
        _activate();
        settlement.mint(buyer, FACE);
        vm.startPrank(buyer);
        settlement.approve(address(vault), FACE);
        vault.fundRedemption(FACE);
        vm.stopPrank();
        apass.setValid(originator, false);

        vm.prank(holderA);
        vault.redeem(60 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);

        assertEq(vault.totalSupply(), 0);
        assertEq(vault.settlementCredit(originator), 10 * ONE);
        assertEq(settlement.balanceOf(originator), 90 * ONE);
        apass.setValid(originator, true);
        vm.prank(originator);
        vault.claimSettlementCredit();
        assertEq(settlement.balanceOf(originator), ADVANCE);
    }

    function testExpiredBuyerCannotBlockDefaultCvaRelease() public {
        _activate();
        uint256 partialCash = 5 * ONE;
        settlement.mint(buyer, partialCash);
        vm.startPrank(buyer);
        settlement.approve(address(vault), partialCash);
        vault.fundRedemption(partialCash);
        vm.stopPrank();
        apass.setValid(buyer, false);

        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();
        vm.prank(holderA);
        vault.releaseDefaultCva(60 * ONE);
        vm.prank(holderB);
        vault.releaseDefaultCva(40 * ONE);

        assertEq(cva.balanceOf(holderA), 60 * ONE);
        assertEq(vault.settlementCredit(buyer), partialCash);
        assertEq(settlement.balanceOf(buyer), 0);
        apass.setValid(buyer, true);
        vm.prank(buyer);
        vault.claimSettlementCredit();
        assertEq(settlement.balanceOf(buyer), partialCash);
    }

    function testBuyerCanFundRemainingHoldersAfterPartialCvaRelease() public {
        _activate();
        vm.warp(vault.protectionEnd() + 1);
        vault.closeProtection();
        vm.prank(holderA);
        vault.releaseDefaultCva(20 * ONE);

        uint256 remainingCash = 88 * ONE;
        settlement.mint(buyer, remainingCash);
        vm.startPrank(buyer);
        settlement.approve(address(vault), remainingCash);
        vault.fundRedemption(remainingCash);
        vm.stopPrank();

        vm.prank(holderA);
        vault.redeem(40 * ONE);
        vm.prank(holderB);
        vault.redeem(40 * ONE);

        assertEq(cva.balanceOf(holderA), 20 * ONE);
        assertEq(cva.totalSupply(), 20 * ONE);
        assertEq(vault.cvaReleasedFace(), 22 * ONE);
        assertEq(vault.redeemedFace(), remainingCash);
        assertEq(vault.cvaReleasedFace() + vault.redeemedFace(), FACE);
        assertEq(vault.totalSupply(), 0);
        assertEq(vault.redemptionEscrow(), 0);
    }

    function _activate() private {
        (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        ) = _activationData();
        vm.prank(facility);
        vault.activate(pledge, signature, holderA, holders, allocations);
    }

    function _activationData()
        private
        view
        returns (
            MordantInvoiceVault.Pledge memory pledge,
            bytes memory signature,
            address[] memory holders,
            uint256[] memory allocations
        )
    {
        pledge = MordantInvoiceVault.Pledge({
            invoiceRoot: ROOT,
            facility: facility,
            originatorSigner: originator,
            obligationId: keccak256("cleanverse-boundary-pledge"),
            amount: FACE,
            currency: CURRENCY,
            nonce: 1,
            activeFrom: uint64(block.timestamp),
            activeUntil: uint64(block.timestamp + 30 days),
            deadline: uint64(block.timestamp + 1 days),
            exclusive: true
        });
        bytes32 digest = vault.hashPledge(pledge);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(originatorKey, digest);
        signature = abi.encodePacked(r, s, v);
        holders = new address[](2);
        holders[0] = holderA;
        holders[1] = holderB;
        allocations = new uint256[](2);
        allocations[0] = 60 * ONE;
        allocations[1] = 40 * ONE;
    }
}
