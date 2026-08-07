// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { MordantRecourseAdapter } from "../src/recourse/MordantRecourseAdapter.sol";
import { ICviVerifier } from "../src/interfaces/ICviVerifier.sol";
import { MockERC20 } from "../src/mocks/MockERC20.sol";
import { MockEligibility } from "../src/mocks/MockEligibility.sol";

/// @dev Reverts on transfer so the adapter's failure handling can be observed.
contract HostileToken is MockERC20 {
    bool public failTransfers;

    constructor() MockERC20("Hostile", "HOS", 6) { }

    function setFailTransfers(bool value) external {
        failTransfers = value;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (failTransfers) return false;
        return super.transfer(to, amount);
    }
}

/// @dev Attempts to re-enter `claim` from the token transfer.
contract ReentrantToken is MockERC20 {
    MordantRecourseAdapter public adapter;
    bytes32 public runId;
    bool private entered;

    constructor() MockERC20("Reentrant", "REE", 6) { }

    function arm(MordantRecourseAdapter target, bytes32 id) external {
        adapter = target;
        runId = id;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (address(adapter) != address(0) && !entered) {
            entered = true;
            // Must revert inside the guard rather than pay twice.
            try adapter.claim(runId, false) { } catch { }
        }
        return super.transfer(to, amount);
    }
}

contract MordantRecourseAdapterTest is Test {
    MordantRecourseAdapter private adapter;
    MockERC20 private token;
    MockEligibility private eligibility;

    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    uint256 private constant OTHER_KEY = 0xB0B;
    address private attestor;
    address private facility = address(0xFAC);
    address private owner = address(0x0E1);
    address private holderA = address(0xA1);
    address private holderB = address(0xB1);
    address private funder = address(0xF1);
    address private stranger = address(0x517);

    bytes32 private constant ASSET = keccak256("MINV01");
    bytes32 private constant AUTHORITY = keccak256("release-authority");
    bytes32 private constant MODE = keccak256("governed-decryptor-v1");
    bytes32 private constant CIRCUIT = keccak256("circuit");
    bytes32 private constant PARAMS = keccak256("parameter-profile");
    uint64 private constant CURE_WINDOW = 1 days;
    uint256 private constant PAY_A = 600_000;
    uint256 private constant PAY_B = 400_000;
    uint256 private constant RESERVE = 5_000_000;

    function setUp() public {
        attestor = vm.addr(ATTESTOR_KEY);
        token = new MockERC20("aUSDC", "aUSDC", 6);
        eligibility = new MockEligibility();
        eligibility.setEligible(facility, adapterRoleFacility(), true);
        eligibility.setEligible(holderA, adapterRoleHolder(), true);
        eligibility.setEligible(holderB, adapterRoleHolder(), true);
        adapter = _deploy(IERC20(address(token)));
        token.mint(funder, RESERVE * 4);
        vm.prank(funder);
        token.approve(address(adapter), type(uint256).max);
    }

    function adapterRoleFacility() private pure returns (uint8) {
        return 3;
    }

    function adapterRoleHolder() private pure returns (uint8) {
        return 4;
    }

    function _deploy(IERC20 settlement) private returns (MordantRecourseAdapter) {
        return new MordantRecourseAdapter(
            settlement,
            ICviVerifier(address(eligibility)),
            attestor,
            facility,
            owner,
            ASSET,
            AUTHORITY,
            MODE,
            CIRCUIT,
            PARAMS,
            CURE_WINDOW
        );
    }

    function _release(bytes32 runId, bool conflict)
        private
        view
        returns (MordantRecourseAdapter.GovernedRelease memory r)
    {
        r.runId = runId;
        r.fheCaseId = keccak256(abi.encodePacked("case", runId));
        r.caseBindingDigest = keccak256(abi.encodePacked("binding", runId));
        r.assetIdentityDigest = ASSET;
        r.governedResultDigest = keccak256(abi.encodePacked("result", runId));
        r.resultCiphertextDigest = keccak256(abi.encodePacked("ciphertext", runId));
        r.participantArtifactDigestA = keccak256(abi.encodePacked("artifactA", runId));
        r.participantArtifactDigestB = keccak256(abi.encodePacked("artifactB", runId));
        r.holderA = holderA;
        r.holderB = holderB;
        r.payoutA = conflict ? PAY_A : 0;
        r.payoutB = conflict ? PAY_B : 0;
        r.conflict = conflict;
        r.releaseAuthorityId = AUTHORITY;
        r.releaseMode = MODE;
        r.circuitHash = CIRCUIT;
        r.parameterFingerprint = PARAMS;
        r.nonce = uint256(runId);
        r.issuedAt = uint64(block.timestamp);
        r.expiry = uint64(block.timestamp + 1 hours);
    }

    function _sign(MordantRecourseAdapter.GovernedRelease memory r, uint256 key)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(key, adapter.hashRelease(r));
        return abi.encodePacked(rr, ss, v);
    }

    function _fund(uint256 amount) private {
        vm.prank(funder);
        adapter.fundReserve(amount);
    }

    function _consume(MordantRecourseAdapter.GovernedRelease memory r) private {
        adapter.consumeGovernedRelease(r, _sign(r, ATTESTOR_KEY));
    }

    function _assertSolvent() private view {
        assertGe(
            token.balanceOf(address(adapter)),
            adapter.availableReserve() + adapter.openReserved() + adapter.entitledUnpaid(),
            "solvency invariant"
        );
    }

    // ------------------------------------------------------------------ positive

    function test_fundReserveCreditsAvailable() public {
        _fund(RESERVE);
        assertEq(adapter.availableReserve(), RESERVE);
        assertEq(token.balanceOf(address(adapter)), RESERVE);
        _assertSolvent();
    }

    function test_conflictReleaseOpensCureWindowAndReserves() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(1)), true);
        _consume(r);
        assertEq(adapter.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.CureOpen));
        assertEq(adapter.openReserved(), PAY_A + PAY_B);
        assertEq(adapter.availableReserve(), RESERVE - PAY_A - PAY_B);
        _assertSolvent();
    }

    function test_noConflictReleaseIsTerminalAndReservesNothing() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(2)), false);
        _consume(r);
        assertEq(adapter.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.Refused));
        assertEq(adapter.openReserved(), 0);
        assertEq(adapter.availableReserve(), RESERVE);
        _assertSolvent();
    }

    function test_cureReturnsReservedToAvailable() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(3)), true);
        _consume(r);
        vm.prank(facility);
        adapter.cure(r.runId);
        assertEq(adapter.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.Cured));
        assertEq(adapter.openReserved(), 0);
        assertEq(adapter.availableReserve(), RESERVE);
        _assertSolvent();
    }

    function test_finalizeIsPermissionlessAfterDeadline() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(4)), true);
        _consume(r);
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        vm.prank(stranger);
        adapter.finalize(r.runId);
        assertEq(adapter.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.Entitled));
        assertEq(adapter.entitledUnpaid(), PAY_A + PAY_B);
        _assertSolvent();
    }

    function test_claimAAndClaimBReachTerminalAccounting() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(5)), true);
        _consume(r);
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        adapter.finalize(r.runId);

        vm.prank(stranger);
        adapter.claim(r.runId, true);
        assertEq(token.balanceOf(holderA), PAY_A, "A paid the signed holder");
        assertEq(adapter.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.Entitled));

        adapter.claim(r.runId, false);
        assertEq(token.balanceOf(holderB), PAY_B);
        assertEq(adapter.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.Claimed));
        assertEq(adapter.entitledUnpaid(), 0);
        assertEq(adapter.openReserved(), 0);
        assertEq(adapter.availableReserve(), RESERVE - PAY_A - PAY_B);
        _assertSolvent();
    }

    function test_minv01IsNeverTouched() public {
        MockERC20 minv01 = new MockERC20("MINV01", "MINV01", 6);
        minv01.mint(address(adapter), 1_000);
        uint256 before = minv01.balanceOf(address(adapter));

        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(6)), true);
        _consume(r);
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        adapter.finalize(r.runId);
        adapter.claim(r.runId, true);
        adapter.claim(r.runId, false);

        assertEq(minv01.balanceOf(address(adapter)), before, "the receivable token never moves");
    }

    function test_ownerCanOnlyWithdrawUnreservedReserve() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(7)), true);
        _consume(r);
        uint256 free = adapter.availableReserve();
        vm.prank(owner);
        adapter.withdrawAvailable(owner, free);
        assertEq(adapter.availableReserve(), 0);
        _assertSolvent();
    }

    // ------------------------------------------------------------------ adversarial

    function test_wrongSignerIsRejected() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(10)), true);
        bytes memory wrongSignature = _sign(r, OTHER_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, wrongSignature);
    }

    function test_wrongDomainAndWrongContractAreRejected() public {
        _fund(RESERVE);
        MordantRecourseAdapter other = _deploy(IERC20(address(token)));
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(11)), true);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(ATTESTOR_KEY, other.hashRelease(r));
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, abi.encodePacked(rr, ss, v));

        // Same struct, a different chain id, therefore a different domain separator.
        bytes32 onThisChain = adapter.hashRelease(r);
        vm.chainId(block.chainid + 1);
        assertTrue(adapter.hashRelease(r) != onThisChain, "chain id must separate the domain");
    }

    function test_wrongAssetCaseCircuitAndAuthorityAreRejected() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(12)), true);
        bytes memory signature;

        r.assetIdentityDigest = keccak256("OTHER_ASSET");
        signature = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, signature);

        r = _release(bytes32(uint256(13)), true);
        r.circuitHash = keccak256("other-circuit");
        signature = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, signature);

        r = _release(bytes32(uint256(14)), true);
        r.parameterFingerprint = keccak256("other-parameters");
        signature = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, signature);

        r = _release(bytes32(uint256(15)), true);
        r.releaseAuthorityId = keccak256("other-authority");
        signature = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, signature);

        r = _release(bytes32(uint256(16)), true);
        r.releaseMode = keccak256("other-mode");
        signature = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, signature);
    }

    function test_holderOrPayoutSubstitutionInvalidatesTheSignature() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(17)), true);
        bytes memory signature = _sign(r, ATTESTOR_KEY);

        MordantRecourseAdapter.GovernedRelease memory swapped = r;
        swapped.holderA = stranger;
        vm.expectRevert();
        adapter.consumeGovernedRelease(swapped, signature);

        MordantRecourseAdapter.GovernedRelease memory inflated = r;
        inflated.payoutA = PAY_A * 2;
        vm.expectRevert();
        adapter.consumeGovernedRelease(inflated, signature);

        MordantRecourseAdapter.GovernedRelease memory flipped = r;
        flipped.conflict = false;
        vm.expectRevert();
        adapter.consumeGovernedRelease(flipped, signature);
    }

    function test_expiredOrNotYetIssuedReleaseIsRejected() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(18)), true);
        r.expiry = uint64(block.timestamp - 1);
        bytes memory sig_r = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, sig_r);

        MordantRecourseAdapter.GovernedRelease memory future = _release(bytes32(uint256(19)), true);
        future.issuedAt = uint64(block.timestamp + 1 hours);
        future.expiry = uint64(block.timestamp + 2 hours);
        bytes memory sig_future = _sign(future, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(future, sig_future);
    }

    function test_replayByRunResultAndNonceIsRefused() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(20)), true);
        _consume(r);

        // Identical attestation again.
        bytes memory sig_r = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, sig_r);

        // Fresh run, same governed result digest.
        MordantRecourseAdapter.GovernedRelease memory sameResult =
            _release(bytes32(uint256(21)), true);
        sameResult.governedResultDigest = r.governedResultDigest;
        bytes memory sig_sameResult = _sign(sameResult, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(sameResult, sig_sameResult);
    }

    function test_insufficientReserveRefusesTheRelease() public {
        _fund(PAY_A);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(22)), true);
        bytes memory sig_r = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, sig_r);
        assertEq(adapter.openReserved(), 0);
        _assertSolvent();
    }

    function test_unauthorizedOrLateCureIsRefused() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(23)), true);
        _consume(r);

        vm.prank(stranger);
        vm.expectRevert();
        adapter.cure(r.runId);

        vm.warp(block.timestamp + CURE_WINDOW + 1);
        vm.prank(facility);
        vm.expectRevert();
        adapter.cure(r.runId);
    }

    function test_finalizeTooEarlyAndClaimTooEarlyAreRefused() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(24)), true);
        _consume(r);

        vm.expectRevert();
        adapter.finalize(r.runId);

        vm.expectRevert();
        adapter.claim(r.runId, true);
    }

    function test_doubleClaimIsRefused() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(25)), true);
        _consume(r);
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        adapter.finalize(r.runId);
        adapter.claim(r.runId, true);
        vm.expectRevert();
        adapter.claim(r.runId, true);
        _assertSolvent();
    }

    function test_ineligibleHolderCannotBePaid() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(26)), true);
        _consume(r);
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        adapter.finalize(r.runId);
        eligibility.setEligible(holderA, adapterRoleHolder(), false);
        vm.expectRevert();
        adapter.claim(r.runId, true);
        _assertSolvent();
    }

    function test_ownerCannotWithdrawReservedOrEntitledLiability() public {
        _fund(PAY_A + PAY_B);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(27)), true);
        _consume(r);
        assertEq(adapter.availableReserve(), 0);

        vm.prank(owner);
        vm.expectRevert();
        adapter.withdrawAvailable(owner, 1);

        vm.warp(block.timestamp + CURE_WINDOW + 1);
        adapter.finalize(r.runId);
        vm.prank(owner);
        vm.expectRevert();
        adapter.withdrawAvailable(owner, 1);
        _assertSolvent();
    }

    function test_curedCaseCannotBeFinalizedAndRefusedCannotBecomeConflict() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(28)), true);
        _consume(r);
        vm.prank(facility);
        adapter.cure(r.runId);
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        vm.expectRevert();
        adapter.finalize(r.runId);

        MordantRecourseAdapter.GovernedRelease memory refused =
            _release(bytes32(uint256(29)), false);
        _consume(refused);
        MordantRecourseAdapter.GovernedRelease memory upgrade = _release(refused.runId, true);
        bytes memory sig_upgrade = _sign(upgrade, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(upgrade, sig_upgrade);
        assertEq(adapter.caseState(refused.runId), uint8(MordantRecourseAdapter.CaseState.Refused));
    }

    function test_noConflictCarryingAPayoutIsRefused() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(30)), false);
        r.payoutA = 1;
        bytes memory sig_r = _sign(r, ATTESTOR_KEY);
        vm.expectRevert();
        adapter.consumeGovernedRelease(r, sig_r);
    }

    function test_failingTokenTransferRevertsTheClaim() public {
        HostileToken hostile = new HostileToken();
        MordantRecourseAdapter hostileAdapter = _deploy(IERC20(address(hostile)));
        hostile.mint(funder, RESERVE);
        vm.prank(funder);
        hostile.approve(address(hostileAdapter), type(uint256).max);
        vm.prank(funder);
        hostileAdapter.fundReserve(RESERVE);

        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(31)), true);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(ATTESTOR_KEY, hostileAdapter.hashRelease(r));
        hostileAdapter.consumeGovernedRelease(r, abi.encodePacked(rr, ss, v));
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        hostileAdapter.finalize(r.runId);

        hostile.setFailTransfers(true);
        vm.expectRevert();
        hostileAdapter.claim(r.runId, true);
    }

    function test_reentrantTokenCannotDoubleSpend() public {
        ReentrantToken evil = new ReentrantToken();
        MordantRecourseAdapter evilAdapter = _deploy(IERC20(address(evil)));
        evil.mint(funder, RESERVE);
        vm.prank(funder);
        evil.approve(address(evilAdapter), type(uint256).max);
        vm.prank(funder);
        evilAdapter.fundReserve(RESERVE);

        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(32)), true);
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(ATTESTOR_KEY, evilAdapter.hashRelease(r));
        evilAdapter.consumeGovernedRelease(r, abi.encodePacked(rr, ss, v));
        vm.warp(block.timestamp + CURE_WINDOW + 1);
        evilAdapter.finalize(r.runId);
        evil.arm(evilAdapter, r.runId);

        evilAdapter.claim(r.runId, true);
        assertEq(evil.balanceOf(holderA), PAY_A);
        assertEq(evil.balanceOf(holderB), 0, "the re-entrant claim must not have paid B");
        assertEq(evilAdapter.entitledUnpaid(), PAY_B);
    }

    function test_solvencyHoldsAcrossAFullConflictAndCureMix() public {
        _fund(RESERVE);
        MordantRecourseAdapter.GovernedRelease memory paid = _release(bytes32(uint256(40)), true);
        _consume(paid);
        _assertSolvent();

        MordantRecourseAdapter.GovernedRelease memory cured = _release(bytes32(uint256(41)), true);
        _consume(cured);
        _assertSolvent();

        vm.prank(facility);
        adapter.cure(cured.runId);
        _assertSolvent();

        vm.warp(block.timestamp + CURE_WINDOW + 1);
        adapter.finalize(paid.runId);
        _assertSolvent();

        adapter.claim(paid.runId, true);
        adapter.claim(paid.runId, false);
        _assertSolvent();
        adapter.assertSolvency();
    }

    // ------------------------------------------------- governed authority separation

    /// @dev A plausible generic label. The former adapter pinned exactly this shape, which is
    /// precisely the confusion these tests exist to prevent.
    bytes32 private constant GENERIC_LABEL =
        keccak256("mordant.governed-decryptor-v1.release-authority");
    /// @dev Stands in for the sha256-derived identifier the real Ed25519 result carries.
    bytes32 private constant REAL_GOVERNED_AUTHORITY =
        0x9f1d4c2b6a8e07f35d94c1b0e2a76f38c5d0b419e83a7c26df5108b4a37e69c2;
    bytes32 private constant OTHER_GOVERNED_AUTHORITY = keccak256("some.other.release.authority");
    /// @dev Produced independently by viem's hashTypedData over the same struct, domain and
    /// verifying contract. Recorded here so a drift in either implementation fails loudly.
    bytes32 private constant VIEM_VECTOR_DIGEST =
        0x51bca185f3e8a0fc8d1788c882c62acf2e514c61e0d371c96aca27f2a48a593c;

    function _deployWithAuthority(bytes32 authority) private returns (MordantRecourseAdapter) {
        return new MordantRecourseAdapter(
            IERC20(address(token)),
            ICviVerifier(address(eligibility)),
            attestor,
            facility,
            owner,
            ASSET,
            authority,
            MODE,
            CIRCUIT,
            PARAMS,
            CURE_WINDOW
        );
    }

    function _signFor(
        MordantRecourseAdapter target,
        MordantRecourseAdapter.GovernedRelease memory r,
        uint256 key
    ) private view returns (bytes memory) {
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(key, target.hashRelease(r));
        return abi.encodePacked(rr, ss, v);
    }

    function test_theRealGovernedAuthorityIsAccepted() public {
        MordantRecourseAdapter pinned = _deployWithAuthority(REAL_GOVERNED_AUTHORITY);
        assertEq(pinned.expectedGovernedReleaseAuthorityId(), REAL_GOVERNED_AUTHORITY);
        token.mint(funder, RESERVE);
        vm.prank(funder);
        token.approve(address(pinned), type(uint256).max);
        vm.prank(funder);
        pinned.fundReserve(RESERVE);

        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(50)), true);
        r.releaseAuthorityId = REAL_GOVERNED_AUTHORITY;
        pinned.consumeGovernedRelease(r, _signFor(pinned, r, ATTESTOR_KEY));
        assertEq(pinned.caseState(r.runId), uint8(MordantRecourseAdapter.CaseState.CureOpen));
    }

    function test_theGenericLabelIsRejectedByAnAdapterPinnedToTheRealAuthority() public {
        MordantRecourseAdapter pinned = _deployWithAuthority(REAL_GOVERNED_AUTHORITY);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(51)), true);
        r.releaseAuthorityId = GENERIC_LABEL;
        bytes memory signature = _signFor(pinned, r, ATTESTOR_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantRecourseAdapter.GovernedAuthorityMismatch.selector,
                GENERIC_LABEL,
                REAL_GOVERNED_AUTHORITY
            )
        );
        pinned.consumeGovernedRelease(r, signature);
    }

    function test_anyOtherGovernedAuthorityIsRejected() public {
        MordantRecourseAdapter pinned = _deployWithAuthority(REAL_GOVERNED_AUTHORITY);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(52)), true);
        r.releaseAuthorityId = OTHER_GOVERNED_AUTHORITY;
        bytes memory signature = _signFor(pinned, r, ATTESTOR_KEY);
        vm.expectRevert();
        pinned.consumeGovernedRelease(r, signature);
    }

    /// @dev The bridge key is not the governed identity: a perfect bridge signature over the wrong
    /// governed authority must still fail.
    function test_correctBridgeSignerWithWrongGovernedAuthorityIsRejected() public {
        MordantRecourseAdapter pinned = _deployWithAuthority(REAL_GOVERNED_AUTHORITY);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(53)), true);
        r.releaseAuthorityId = GENERIC_LABEL;
        bytes memory signature = _signFor(pinned, r, ATTESTOR_KEY);
        assertEq(
            vm.addr(ATTESTOR_KEY), pinned.attestor(), "the bridge signature is genuinely correct"
        );
        vm.expectRevert();
        pinned.consumeGovernedRelease(r, signature);
    }

    /// @dev And the governed identity is not the bridge key: the right authority signed by the
    /// wrong key must fail too.
    function test_wrongBridgeSignerWithCorrectGovernedAuthorityIsRejected() public {
        MordantRecourseAdapter pinned = _deployWithAuthority(REAL_GOVERNED_AUTHORITY);
        token.mint(funder, RESERVE);
        vm.prank(funder);
        token.approve(address(pinned), type(uint256).max);
        vm.prank(funder);
        pinned.fundReserve(RESERVE);

        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(54)), true);
        r.releaseAuthorityId = REAL_GOVERNED_AUTHORITY;
        bytes memory signature = _signFor(pinned, r, OTHER_KEY);
        vm.expectRevert();
        pinned.consumeGovernedRelease(r, signature);
    }

    /// @dev One fixed struct, every field a distinct constant, so a field-ordering mistake in
    /// either implementation changes the digest.
    function _canonicalVector()
        private
        pure
        returns (MordantRecourseAdapter.GovernedRelease memory r)
    {
        r.runId = bytes32(uint256(0x01));
        r.fheCaseId = bytes32(uint256(0x02));
        r.caseBindingDigest = bytes32(uint256(0x03));
        r.assetIdentityDigest = bytes32(uint256(0x04));
        r.governedResultDigest = bytes32(uint256(0x05));
        r.resultCiphertextDigest = bytes32(uint256(0x06));
        r.participantArtifactDigestA = bytes32(uint256(0x07));
        r.participantArtifactDigestB = bytes32(uint256(0x08));
        r.holderA = address(0x00000000000000000000000000000000000000A1);
        r.holderB = address(0x00000000000000000000000000000000000000B1);
        r.payoutA = 600_000;
        r.payoutB = 400_000;
        r.conflict = true;
        r.releaseAuthorityId = bytes32(uint256(0x09));
        r.releaseMode = bytes32(uint256(0x0a));
        r.circuitHash = bytes32(uint256(0x0b));
        r.parameterFingerprint = bytes32(uint256(0x0c));
        r.nonce = 42;
        r.issuedAt = 1_785_000_000;
        r.expiry = 1_785_000_600;
    }

    /// @dev A viem-produced vector. If either implementation drifts, this stops being equal.
    function test_theSolidityDigestMatchesTheViemVector() public view {
        MordantRecourseAdapter.GovernedRelease memory r = _canonicalVector();
        assertEq(adapter.hashRelease(r), VIEM_VECTOR_DIGEST, "viem and Solidity must agree");
    }

    function test_allTwentySignedFieldsRemainMutationSensitive() public view {
        MordantRecourseAdapter.GovernedRelease memory base = _canonicalVector();
        bytes32 baseline = adapter.hashRelease(base);
        uint256 observed;

        MordantRecourseAdapter.GovernedRelease memory m = base;
        m.runId = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.fheCaseId = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.caseBindingDigest = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.assetIdentityDigest = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.governedResultDigest = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.resultCiphertextDigest = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.participantArtifactDigestA = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.participantArtifactDigestB = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.holderA = address(0xDEAD);
        observed += _differs(baseline, m);
        m = base;
        m.holderB = address(0xDEAD);
        observed += _differs(baseline, m);
        m = base;
        m.payoutA += 1;
        observed += _differs(baseline, m);
        m = base;
        m.payoutB += 1;
        observed += _differs(baseline, m);
        m = base;
        m.conflict = !base.conflict;
        observed += _differs(baseline, m);
        m = base;
        m.releaseAuthorityId = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.releaseMode = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.circuitHash = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.parameterFingerprint = keccak256("x");
        observed += _differs(baseline, m);
        m = base;
        m.nonce += 1;
        observed += _differs(baseline, m);
        m = base;
        m.issuedAt += 1;
        observed += _differs(baseline, m);
        m = base;
        m.expiry += 1;
        observed += _differs(baseline, m);

        assertEq(observed, 20, "every one of the twenty signed fields must move the digest");
    }

    function _differs(bytes32 baseline, MordantRecourseAdapter.GovernedRelease memory m)
        private
        view
        returns (uint256)
    {
        return adapter.hashRelease(m) == baseline ? 0 : 1;
    }

    // ------------------------------------------------- canonical runtime handoff

    /// @dev Read from the committed runtime fixture
    /// `src/lib/protection/governed-recourse-bridge.test.ts` on
    /// feat/live-participant-admission-v1-runtime-candidate. Not copied from a message.
    bytes32 private constant RUNTIME_RELEASE_TYPEHASH =
        0x5e5f1a6c601ddff4a7d452bf8cf5c106c0efb68a0d0e17832da59c95a6ac0a8d;
    bytes32 private constant RUNTIME_GOVERNED_AUTHORITY =
        0xc21276405a249b7c178914508d99e9f0286ce29e5e3bb085ad3697f0cc665c3d;
    bytes32 private constant RUNTIME_GOVERNED_CIRCUIT =
        0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e;
    bytes32 private constant RUNTIME_GOVERNED_PARAMETERS =
        0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6;
    bytes32 private constant RUNTIME_GOVERNED_ASSET =
        0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c;
    address private constant RUNTIME_BRIDGE_ATTESTOR = 0xEe3260bA47D097DE5a8601107e1b83454593617c;

    /// @dev The struct schema is what makes the runtime's viem vector reproducible here. If the
    /// typehash ever drifts, every digest on both sides drifts with it.
    function test_theStructSchemaMatchesTheRuntimeHandoff() public view {
        assertEq(
            adapter.RELEASE_TYPEHASH(),
            RUNTIME_RELEASE_TYPEHASH,
            "typehash must match the runtime fixture"
        );
    }

    /// @dev The three pins the runtime handoff found wrong on the former adapter.
    function test_anAdapterPinnedToTheGovernedValuesAcceptsThem() public {
        MordantRecourseAdapter pinned = new MordantRecourseAdapter(
            IERC20(address(token)),
            ICviVerifier(address(eligibility)),
            RUNTIME_BRIDGE_ATTESTOR,
            facility,
            owner,
            RUNTIME_GOVERNED_ASSET,
            RUNTIME_GOVERNED_AUTHORITY,
            MODE,
            RUNTIME_GOVERNED_CIRCUIT,
            RUNTIME_GOVERNED_PARAMETERS,
            CURE_WINDOW
        );
        assertEq(pinned.expectedGovernedReleaseAuthorityId(), RUNTIME_GOVERNED_AUTHORITY);
        assertEq(pinned.circuitHash(), RUNTIME_GOVERNED_CIRCUIT);
        assertEq(pinned.parameterFingerprint(), RUNTIME_GOVERNED_PARAMETERS);
        assertEq(pinned.assetIdentityDigest(), RUNTIME_GOVERNED_ASSET);
        assertEq(
            pinned.attestor(), RUNTIME_BRIDGE_ATTESTOR, "the bridge signer stays a separate address"
        );
        // The governed authority is data, the bridge signer is a key. They must never coincide.
        assertTrue(
            uint256(pinned.expectedGovernedReleaseAuthorityId())
                != uint256(uint160(pinned.attestor()))
        );
    }

    /// @dev The former adapter's label, refused by an adapter pinned to the real authority.
    function test_theFormerAdapterLabelIsRefusedByTheCorrectedPin() public {
        MordantRecourseAdapter pinned = _deployWithAuthority(RUNTIME_GOVERNED_AUTHORITY);
        MordantRecourseAdapter.GovernedRelease memory r = _release(bytes32(uint256(60)), true);
        r.releaseAuthorityId = 0x130d619731ab2a03a81de297e058ef57a6a85656d0ddf76d26e7a20cfa2d3651;
        bytes memory signature = _signFor(pinned, r, ATTESTOR_KEY);
        vm.expectRevert(
            abi.encodeWithSelector(
                MordantRecourseAdapter.GovernedAuthorityMismatch.selector,
                bytes32(0x130d619731ab2a03a81de297e058ef57a6a85656d0ddf76d26e7a20cfa2d3651),
                RUNTIME_GOVERNED_AUTHORITY
            )
        );
        pinned.consumeGovernedRelease(r, signature);
    }
}
