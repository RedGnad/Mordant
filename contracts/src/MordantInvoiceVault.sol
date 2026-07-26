// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import { ICvaAdapter } from "./interfaces/ICvaAdapter.sol";
import { ICviVerifier } from "./interfaces/ICviVerifier.sol";
import { IMordantFactory } from "./interfaces/IMordantFactory.sol";

/// @notice One synthetic, buyer-accepted invoice and its funded exclusivity reserve.
/// @dev Hackathon/testnet prototype. This contract does not establish legal assignment or priority.
contract MordantInvoiceVault is ERC20, EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint8 public constant ROLE_BUYER = 1;
    uint8 public constant ROLE_ORIGINATOR = 2;
    uint8 public constant ROLE_FACILITY = 3;
    uint8 public constant ROLE_HOLDER = 4;

    bytes32 public constant PLEDGE_TYPEHASH = keccak256(
        "Pledge(bytes32 invoiceRoot,address originatorSigner,address facility,bytes32 obligationId,uint256 amount,bytes32 currency,uint64 activeFrom,uint64 activeUntil,uint256 nonce,uint64 deadline,bool exclusive)"
    );
    bytes32 public constant CANCELLATION_TYPEHASH = keccak256(
        "Cancellation(bytes32 invoiceRoot,bytes32 pledgeDigest,uint256 nonce,uint64 deadline)"
    );

    enum ProtectionState {
        Unfunded,
        Active,
        CommitPending,
        ConflictConfirmed,
        Entitled,
        Released
    }

    enum ReceivableState {
        Unissued,
        Outstanding,
        Redeemed,
        DefaultOutstanding
    }

    struct Init {
        address factory;
        address cviVerifier;
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

    struct Pledge {
        bytes32 invoiceRoot;
        address originatorSigner;
        address facility;
        bytes32 obligationId;
        uint256 amount;
        bytes32 currency;
        uint64 activeFrom;
        uint64 activeUntil;
        uint256 nonce;
        uint64 deadline;
        bool exclusive;
    }

    struct Cancellation {
        bytes32 invoiceRoot;
        bytes32 pledgeDigest;
        uint256 nonce;
        uint64 deadline;
    }

    struct PendingConflict {
        bytes32 commitment;
        address facility;
        uint48 snapshotSequence;
        uint208 snapshotSupply;
        uint256 snapshotBond;
        uint64 committedAt;
        uint64 revealDeadline;
        uint64 cureDeadline;
        bytes32 conflictingPledgeDigest;
        address conflictSigner;
    }

    struct BalanceCheckpoint {
        uint48 sequence;
        uint208 balance;
    }

    error InvalidConfiguration();
    error RoleOverlap();
    error InvalidState();
    error Ineligible(address account, uint8 role);
    error Unauthorized();
    error InvalidPledge();
    error InvalidSignature();
    error AlreadyUsed();
    error InvalidCommitment();
    error WindowClosed();
    error WindowOpen();
    error InvalidAmount();
    error InvalidAllocation();
    error InsufficientCva();
    error AccountingMismatch();
    error NothingToClaim();

    event Activated(
        bytes32 indexed invoiceRoot,
        bytes32 indexed protectedPledgeDigest,
        address indexed facility,
        uint256 advance,
        uint256 originatorProceeds,
        uint256 bond
    );
    event OriginatorSignerAuthorized(address indexed signer);
    event ConflictCommitted(
        bytes32 indexed commitment,
        address indexed facility,
        uint48 snapshotSequence,
        uint256 snapshotSupply,
        uint256 snapshotBond,
        uint64 revealDeadline
    );
    event ConflictRevealed(
        bytes32 indexed pledgeDigest, address indexed facility, uint64 cureDeadline
    );
    event ConflictCommitExpired(bytes32 indexed commitment);
    event ConflictCured(bytes32 indexed pledgeDigest);
    event ConflictFinalized(
        bytes32 indexed pledgeDigest,
        uint48 snapshotSequence,
        uint256 snapshotSupply,
        uint256 entitlementBond
    );
    event BondClaimed(address indexed holder, uint256 units, uint256 amount);
    event BondReturned(address indexed originator, uint256 amount);
    event RedemptionFunded(address indexed payer, uint256 amount);
    event PartialRedemptionEscrowRefunded(address indexed buyer, uint256 amount);
    event Redeemed(address indexed holder, uint256 units, uint256 amount);
    event DefaultCvaReleasePathSelected();
    event DefaultCvaReleased(address indexed holder, uint256 units);
    event DefaultMarked();

    IMordantFactory public immutable factory;
    ICviVerifier public immutable cviVerifier;
    ICvaAdapter public immutable cvaAdapter;
    IERC20 public immutable settlementToken;
    address public immutable cvaToken;

    bytes32 public immutable invoiceRoot;
    bytes32 public immutable currency;
    address public immutable buyer;
    address public immutable originatorTreasury;

    uint256 public immutable initialUnits;
    uint256 public immutable advanceAmount;
    uint256 public immutable faceValue;
    uint256 public immutable initialBond;
    uint256 public immutable netProceeds;
    uint16 public immutable bondBps;
    uint64 public immutable protectionEnd;
    uint64 public immutable revealPeriod;
    uint64 public immutable curePeriod;

    ProtectionState public protectionState;
    ReceivableState public receivableState;

    mapping(address signer => bool authorized) public authorizedOriginator;
    mapping(address signer => mapping(uint256 nonce => bool used)) public usedPledgeNonce;
    mapping(address signer => mapping(uint256 nonce => bool used)) public usedCancellationNonce;
    mapping(bytes32 digest => bool used) public usedPledgeDigest;

    address public protectedFacility;
    bytes32 public protectedPledgeDigest;
    uint64 public protectedActiveFrom;
    uint64 public protectedActiveUntil;

    PendingConflict public pendingConflict;

    uint48 public sequence;
    mapping(address holder => BalanceCheckpoint[]) private _balanceCheckpoints;
    BalanceCheckpoint[] private _supplyCheckpoints;

    uint256 public cvaAccounted;
    uint256 public cvaBurned;
    uint256 public bondLocked;
    uint256 public bondReturned;
    uint256 public entitlementAllocated;
    uint256 public entitlementClaimed;
    uint256 public entitlementClaimedUnits;
    uint48 public entitlementSnapshotSequence;
    uint256 public entitlementSnapshotSupply;
    mapping(address holder => bool claimed) public bondClaimedBy;

    uint256 public redemptionEscrow;
    uint256 public redeemedFace;
    bool public defaultCvaReleaseStarted;

    constructor(Init memory init) ERC20("Mordant Invoice Units", "mINV") EIP712("Mordant", "1") {
        if (
            init.factory == address(0) || init.cviVerifier == address(0)
                || init.cvaAdapter == address(0) || init.settlementToken == address(0)
                || init.invoiceRoot == bytes32(0) || init.currency == bytes32(0)
                || init.buyer == address(0) || init.originatorTreasury == address(0)
                || init.initialOriginatorSigner == address(0) || init.initialUnits == 0
                || init.initialUnits > type(uint208).max || init.advanceAmount == 0
                || init.faceValue < init.advanceAmount || init.bondBps == 0
                || init.bondBps >= 10_000 || init.protectionEnd <= block.timestamp
                || init.revealPeriod == 0 || init.curePeriod == 0
        ) revert InvalidConfiguration();

        factory = IMordantFactory(init.factory);
        cviVerifier = ICviVerifier(init.cviVerifier);
        cvaAdapter = ICvaAdapter(init.cvaAdapter);
        settlementToken = IERC20(init.settlementToken);
        cvaToken = ICvaAdapter(init.cvaAdapter).asset();
        if (cvaToken == address(0)) revert InvalidConfiguration();

        invoiceRoot = init.invoiceRoot;
        currency = init.currency;
        buyer = init.buyer;
        originatorTreasury = init.originatorTreasury;
        if (
            init.buyer == init.originatorTreasury || init.buyer == init.initialOriginatorSigner
                || factory.isFacility(init.buyer) || factory.isFacility(init.originatorTreasury)
                || factory.isFacility(init.initialOriginatorSigner)
        ) revert RoleOverlap();
        initialUnits = init.initialUnits;
        advanceAmount = init.advanceAmount;
        faceValue = init.faceValue;
        bondBps = init.bondBps;
        initialBond = Math.mulDiv(init.advanceAmount, init.bondBps, 10_000);
        netProceeds = init.advanceAmount - initialBond;
        protectionEnd = init.protectionEnd;
        revealPeriod = init.revealPeriod;
        curePeriod = init.curePeriod;

        authorizedOriginator[init.initialOriginatorSigner] = true;
        if (initialBond == 0) revert InvalidConfiguration();
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function authorizeOriginatorWallet(address signer) external {
        if (msg.sender != buyer) revert Unauthorized();
        _requireEligible(buyer, ROLE_BUYER);
        _requireEligible(signer, ROLE_ORIGINATOR);
        if (signer == buyer || factory.isFacility(signer)) revert RoleOverlap();
        if (signer == address(0) || balanceOf(signer) != 0) revert InvalidConfiguration();
        if (protectionState != ProtectionState.Unfunded) _assertCvaIntegrity();
        authorizedOriginator[signer] = true;
        emit OriginatorSignerAuthorized(signer);
    }

    function hashPledge(Pledge calldata pledge) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    PLEDGE_TYPEHASH,
                    pledge.invoiceRoot,
                    pledge.originatorSigner,
                    pledge.facility,
                    pledge.obligationId,
                    pledge.amount,
                    pledge.currency,
                    pledge.activeFrom,
                    pledge.activeUntil,
                    pledge.nonce,
                    pledge.deadline,
                    pledge.exclusive
                )
            )
        );
    }

    function hashCancellation(Cancellation calldata cancellation) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    CANCELLATION_TYPEHASH,
                    cancellation.invoiceRoot,
                    cancellation.pledgeDigest,
                    cancellation.nonce,
                    cancellation.deadline
                )
            )
        );
    }

    function conflictCommitment(
        bytes32 pledgeDigest,
        bytes32 signatureHash,
        address facility,
        bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(abi.encode(pledgeDigest, signatureHash, facility, address(this), salt));
    }

    function activate(
        Pledge calldata pledge,
        bytes calldata signature,
        address funder,
        address[] calldata holders,
        uint256[] calldata allocations
    ) external nonReentrant {
        if (
            protectionState != ProtectionState.Unfunded
                || receivableState != ReceivableState.Unissued
        ) revert InvalidState();
        if (holders.length == 0 || holders.length != allocations.length) {
            revert InvalidAllocation();
        }

        bytes32 digest = _validatePledge(pledge, signature, msg.sender, uint64(block.timestamp));
        if (pledge.activeUntil < protectionEnd) revert InvalidPledge();
        if (usedPledgeDigest[digest] || usedPledgeNonce[pledge.originatorSigner][pledge.nonce]) {
            revert AlreadyUsed();
        }
        if (cvaAdapter.availableBalance(address(this)) != initialUnits) revert InsufficientCva();
        if (cvaAdapter.asset() != cvaToken || cvaAdapter.issuedSupply() != initialUnits) {
            revert AccountingMismatch();
        }
        _requireHolder(funder);

        uint256 allocated;
        for (uint256 i; i < holders.length; ++i) {
            _requireHolder(holders[i]);
            if (allocations[i] == 0) revert InvalidAllocation();
            allocated += allocations[i];
        }
        if (allocated != initialUnits) revert InvalidAllocation();

        uint256 beforeVault = settlementToken.balanceOf(address(this));
        settlementToken.safeTransferFrom(funder, address(this), advanceAmount);
        if (settlementToken.balanceOf(address(this)) - beforeVault != advanceAmount) {
            revert AccountingMismatch();
        }

        usedPledgeDigest[digest] = true;
        usedPledgeNonce[pledge.originatorSigner][pledge.nonce] = true;
        protectedPledgeDigest = digest;
        protectedFacility = msg.sender;
        protectedActiveFrom = pledge.activeFrom;
        protectedActiveUntil = pledge.activeUntil;
        cvaAccounted = initialUnits;
        bondLocked = initialBond;
        protectionState = ProtectionState.Active;
        receivableState = ReceivableState.Outstanding;

        for (uint256 i; i < holders.length; ++i) {
            _mint(holders[i], allocations[i]);
        }
        _transferExact(settlementToken, originatorTreasury, netProceeds);
        _assertAccounting();

        emit Activated(invoiceRoot, digest, msg.sender, advanceAmount, netProceeds, initialBond);
    }

    function commitConflict(bytes32 commitment) external {
        _assertCvaIntegrity();
        if (protectionState != ProtectionState.Active) revert InvalidState();
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (block.timestamp > protectionEnd) revert WindowClosed();
        if (
            msg.sender == protectedFacility || msg.sender == buyer
                || msg.sender == originatorTreasury || authorizedOriginator[msg.sender]
                || !factory.isFacility(msg.sender)
        ) {
            revert Unauthorized();
        }
        _requireEligible(msg.sender, ROLE_FACILITY);

        uint256 supply = totalSupply();
        if (supply == 0 || supply > type(uint208).max) revert InvalidState();
        uint256 exposedBond = requiredBond(supply);
        if (bondLocked < exposedBond) revert AccountingMismatch();

        pendingConflict = PendingConflict({
            commitment: commitment,
            facility: msg.sender,
            snapshotSequence: sequence,
            snapshotSupply: uint208(supply),
            snapshotBond: exposedBond,
            committedAt: uint64(block.timestamp),
            revealDeadline: uint64(block.timestamp) + revealPeriod,
            cureDeadline: 0,
            conflictingPledgeDigest: bytes32(0),
            conflictSigner: address(0)
        });
        protectionState = ProtectionState.CommitPending;

        emit ConflictCommitted(
            commitment, msg.sender, sequence, supply, exposedBond, pendingConflict.revealDeadline
        );
    }

    function revealConflict(Pledge calldata pledge, bytes calldata signature, bytes32 salt)
        external
    {
        _assertCvaIntegrity();
        if (protectionState != ProtectionState.CommitPending) revert InvalidState();
        PendingConflict storage pending = pendingConflict;
        if (msg.sender != pending.facility) revert Unauthorized();
        if (block.timestamp > pending.revealDeadline) revert WindowClosed();

        bytes32 digest = _validatePledge(pledge, signature, msg.sender, pending.committedAt);
        if (
            conflictCommitment(digest, keccak256(signature), msg.sender, salt) != pending.commitment
        ) {
            revert InvalidCommitment();
        }
        if (msg.sender == protectedFacility) revert InvalidPledge();
        if (pledge.activeFrom >= protectedActiveUntil || protectedActiveFrom >= pledge.activeUntil) revert InvalidPledge();
        if (usedPledgeDigest[digest] || usedPledgeNonce[pledge.originatorSigner][pledge.nonce]) {
            revert AlreadyUsed();
        }

        usedPledgeDigest[digest] = true;
        usedPledgeNonce[pledge.originatorSigner][pledge.nonce] = true;
        pending.conflictingPledgeDigest = digest;
        pending.conflictSigner = pledge.originatorSigner;
        pending.cureDeadline = uint64(block.timestamp) + curePeriod;
        protectionState = ProtectionState.ConflictConfirmed;

        emit ConflictRevealed(digest, msg.sender, pending.cureDeadline);
    }

    function expireCommit() external nonReentrant {
        if (protectionState != ProtectionState.CommitPending) revert InvalidState();
        if (block.timestamp <= pendingConflict.revealDeadline) revert WindowOpen();
        bytes32 commitment = pendingConflict.commitment;
        delete pendingConflict;
        protectionState = ProtectionState.Active;
        _releaseExcessBond();
        _assertAccounting();
        emit ConflictCommitExpired(commitment);
    }

    function cureConflict(Cancellation calldata cancellation, bytes calldata signature)
        external
        nonReentrant
    {
        if (protectionState != ProtectionState.ConflictConfirmed) revert InvalidState();
        PendingConflict memory pending = pendingConflict;
        if (msg.sender != pending.facility) revert Unauthorized();
        _requireEligible(msg.sender, ROLE_FACILITY);
        if (block.timestamp > pending.cureDeadline || block.timestamp > cancellation.deadline) {
            revert WindowClosed();
        }
        if (
            cancellation.invoiceRoot != invoiceRoot
                || cancellation.pledgeDigest != pending.conflictingPledgeDigest
        ) revert InvalidPledge();
        if (usedCancellationNonce[pending.conflictSigner][cancellation.nonce]) {
            revert AlreadyUsed();
        }
        bytes32 cancellationDigest = hashCancellation(cancellation);
        if (ECDSA.recover(cancellationDigest, signature) != pending.conflictSigner) {
            revert InvalidSignature();
        }

        usedCancellationNonce[pending.conflictSigner][cancellation.nonce] = true;
        bytes32 pledgeDigest = pending.conflictingPledgeDigest;
        delete pendingConflict;
        protectionState = ProtectionState.Active;
        _releaseExcessBond();
        _assertAccounting();
        emit ConflictCured(pledgeDigest);
    }

    function finalizeConflict() external {
        if (protectionState != ProtectionState.ConflictConfirmed) revert InvalidState();
        PendingConflict memory pending = pendingConflict;
        if (block.timestamp <= pending.cureDeadline) revert WindowOpen();
        if (pending.snapshotBond > bondLocked || entitlementAllocated != 0) {
            revert AccountingMismatch();
        }

        entitlementSnapshotSequence = pending.snapshotSequence;
        entitlementSnapshotSupply = pending.snapshotSupply;
        entitlementAllocated = pending.snapshotBond;
        bondLocked -= pending.snapshotBond;
        delete pendingConflict;
        protectionState = ProtectionState.Entitled;
        _assertAccounting();

        emit ConflictFinalized(
            pending.conflictingPledgeDigest,
            pending.snapshotSequence,
            pending.snapshotSupply,
            pending.snapshotBond
        );
    }

    function claimBond() external nonReentrant returns (uint256 amount) {
        if (protectionState != ProtectionState.Entitled || bondClaimedBy[msg.sender]) {
            revert NothingToClaim();
        }
        _requireEligible(msg.sender, ROLE_HOLDER);
        uint256 units = balanceAt(msg.sender, entitlementSnapshotSequence);
        if (units == 0) revert NothingToClaim();

        uint256 nextClaimedUnits = entitlementClaimedUnits + units;
        if (nextClaimedUnits > entitlementSnapshotSupply) revert AccountingMismatch();
        if (nextClaimedUnits == entitlementSnapshotSupply) {
            amount = entitlementAllocated - entitlementClaimed;
        } else {
            amount = Math.mulDiv(entitlementAllocated, units, entitlementSnapshotSupply);
        }

        bondClaimedBy[msg.sender] = true;
        entitlementClaimedUnits = nextClaimedUnits;
        entitlementClaimed += amount;
        if (amount != 0) _transferExact(settlementToken, msg.sender, amount);
        _assertAccounting();
        emit BondClaimed(msg.sender, units, amount);
    }

    function fundRedemption(uint256 amount) external nonReentrant {
        if (msg.sender != buyer) revert Unauthorized();
        _assertCvaIntegrity();
        if (defaultCvaReleaseStarted) revert InvalidState();
        if (
            receivableState != ReceivableState.Outstanding
                && receivableState != ReceivableState.DefaultOutstanding
        ) revert InvalidState();
        if (amount == 0) revert InvalidAmount();
        uint256 remainingUnfundedLiability = faceValue - redeemedFace - redemptionEscrow;
        if (
            receivableState == ReceivableState.DefaultOutstanding
                && amount != remainingUnfundedLiability
        ) revert InvalidAmount();
        if (amount > remainingUnfundedLiability) revert InvalidAmount();
        uint256 beforeVault = settlementToken.balanceOf(address(this));
        settlementToken.safeTransferFrom(msg.sender, address(this), amount);
        if (settlementToken.balanceOf(address(this)) - beforeVault != amount) {
            revert AccountingMismatch();
        }
        redemptionEscrow += amount;
        _assertAccounting();
        emit RedemptionFunded(msg.sender, amount);
    }

    function redeem(uint256 units) external nonReentrant returns (uint256 amount) {
        if (defaultCvaReleaseStarted) revert InvalidState();
        if (
            receivableState != ReceivableState.Outstanding
                && receivableState != ReceivableState.DefaultOutstanding
        ) revert InvalidState();
        _requireHolder(msg.sender);
        uint256 supplyBefore = totalSupply();
        if (units == 0 || balanceOf(msg.sender) < units) revert InvalidAmount();

        amount = units == supplyBefore
            ? faceValue - redeemedFace
            : Math.mulDiv(faceValue, units, initialUnits);
        if (redemptionEscrow < amount || cvaAccounted < units) revert InvalidAmount();

        uint256 cvaBefore = cvaAdapter.availableBalance(address(this));
        cvaAdapter.consumeOnRedemption(address(this), units);
        uint256 cvaAfter = cvaAdapter.availableBalance(address(this));
        if (cvaBefore < cvaAfter || cvaBefore - cvaAfter != units) revert AccountingMismatch();

        cvaAccounted -= units;
        cvaBurned += units;
        redemptionEscrow -= amount;
        redeemedFace += amount;
        _burn(msg.sender, units);
        _transferExact(settlementToken, msg.sender, amount);

        if (protectionState == ProtectionState.Active) {
            _releaseExcessBond();
            if (totalSupply() == 0) protectionState = ProtectionState.Released;
        }
        if (totalSupply() == 0) receivableState = ReceivableState.Redeemed;
        _assertAccounting();
        emit Redeemed(msg.sender, units, amount);
    }

    function closeProtection() external nonReentrant {
        _assertCvaIntegrity();
        if (protectionState != ProtectionState.Active) revert InvalidState();
        if (totalSupply() != 0 && block.timestamp <= protectionEnd) revert WindowOpen();
        if (totalSupply() != 0) {
            receivableState = ReceivableState.DefaultOutstanding;
            emit DefaultMarked();
        } else {
            receivableState = ReceivableState.Redeemed;
        }
        _returnAllLockedBond();
        protectionState = ProtectionState.Released;
        _assertAccounting();
    }

    function markDefault() external {
        _assertCvaIntegrity();
        if (protectionState != ProtectionState.Entitled) revert InvalidState();
        if (receivableState != ReceivableState.Outstanding) revert InvalidState();
        if (block.timestamp <= protectionEnd) revert WindowOpen();
        receivableState = ReceivableState.DefaultOutstanding;
        _assertAccounting();
        emit DefaultMarked();
    }

    function releaseDefaultCva(uint256 units) external nonReentrant {
        if (receivableState != ReceivableState.DefaultOutstanding) revert InvalidState();
        _requireHolder(msg.sender);
        if (units == 0 || balanceOf(msg.sender) < units || cvaAccounted < units) {
            revert InvalidAmount();
        }
        if (!defaultCvaReleaseStarted) {
            uint256 remainingCashLiability = faceValue - redeemedFace;
            uint256 partialEscrow = redemptionEscrow;
            if (partialEscrow == remainingCashLiability) revert InvalidState();

            redemptionEscrow = 0;
            defaultCvaReleaseStarted = true;
            if (partialEscrow != 0) {
                _transferExact(settlementToken, buyer, partialEscrow);
                emit PartialRedemptionEscrowRefunded(buyer, partialEscrow);
            }
            emit DefaultCvaReleasePathSelected();
        }

        uint256 cvaBefore = cvaAdapter.availableBalance(address(this));
        cvaAdapter.releaseOnDefault(address(this), msg.sender, units);
        uint256 cvaAfter = cvaAdapter.availableBalance(address(this));
        if (cvaBefore < cvaAfter || cvaBefore - cvaAfter != units) revert AccountingMismatch();

        cvaAccounted -= units;
        _burn(msg.sender, units);
        _assertAccounting();
        emit DefaultCvaReleased(msg.sender, units);
    }

    function requiredBond(uint256 supply) public view returns (uint256 result) {
        result = Math.mulDiv(initialBond, supply, initialUnits);
        if (mulmod(initialBond, supply, initialUnits) != 0) ++result;
    }

    function balanceAt(address holder, uint48 atSequence) public view returns (uint256) {
        if (atSequence > sequence) revert InvalidConfiguration();
        return _lookup(_balanceCheckpoints[holder], atSequence);
    }

    function totalSupplyAt(uint48 atSequence) public view returns (uint256) {
        if (atSequence > sequence) revert InvalidConfiguration();
        return _lookup(_supplyCheckpoints, atSequence);
    }

    function accountedSettlementBalance() public view returns (uint256) {
        return bondLocked + (entitlementAllocated - entitlementClaimed) + redemptionEscrow;
    }

    function assertAccounting() external view {
        _assertAccounting();
    }

    function _validatePledge(
        Pledge calldata pledge,
        bytes calldata signature,
        address facilityCaller,
        uint64 validAt
    ) private view returns (bytes32 digest) {
        if (
            pledge.invoiceRoot != invoiceRoot || pledge.facility != facilityCaller
                || pledge.amount != faceValue || pledge.currency != currency || !pledge.exclusive
                || pledge.activeFrom > validAt || validAt >= pledge.activeUntil
                || validAt > pledge.deadline || pledge.activeFrom >= pledge.activeUntil
                || !authorizedOriginator[pledge.originatorSigner]
                || !factory.isFacility(facilityCaller) || facilityCaller == buyer
                || facilityCaller == originatorTreasury || authorizedOriginator[facilityCaller]
        ) revert InvalidPledge();
        _requireEligible(pledge.originatorSigner, ROLE_ORIGINATOR);
        _requireEligible(facilityCaller, ROLE_FACILITY);
        digest = hashPledge(pledge);
        if (ECDSA.recover(digest, signature) != pledge.originatorSigner) {
            revert InvalidSignature();
        }
    }

    function _requireEligible(address account, uint8 role) private view {
        if (!cviVerifier.isEligible(account, role)) revert Ineligible(account, role);
    }

    function _requireHolder(address account) private view {
        _requireEligible(account, ROLE_HOLDER);
        if (
            account == address(0) || account == buyer || account == originatorTreasury
                || authorizedOriginator[account] || factory.isFacility(account)
        ) revert Ineligible(account, ROLE_HOLDER);
    }

    function _releaseExcessBond() private {
        if (protectionState != ProtectionState.Active) return;
        uint256 target = requiredBond(totalSupply());
        if (bondLocked <= target) return;
        uint256 amount = bondLocked - target;
        bondLocked = target;
        bondReturned += amount;
        _transferExact(settlementToken, originatorTreasury, amount);
        emit BondReturned(originatorTreasury, amount);
    }

    function _returnAllLockedBond() private {
        uint256 amount = bondLocked;
        bondLocked = 0;
        bondReturned += amount;
        if (amount != 0) _transferExact(settlementToken, originatorTreasury, amount);
        emit BondReturned(originatorTreasury, amount);
    }

    function _transferExact(IERC20 token, address recipient, uint256 amount) private {
        if (amount == 0) return;
        uint256 beforeRecipient = token.balanceOf(recipient);
        token.safeTransfer(recipient, amount);
        if (token.balanceOf(recipient) - beforeRecipient != amount) revert AccountingMismatch();
    }

    function _assertAccounting() private view {
        _assertCvaIntegrity();
        if (totalSupply() != cvaAccounted) revert AccountingMismatch();
        if (bondLocked + bondReturned + entitlementAllocated != initialBond) {
            revert AccountingMismatch();
        }
        if (
            entitlementClaimed > entitlementAllocated
                || entitlementClaimedUnits > entitlementSnapshotSupply
        ) revert AccountingMismatch();
        if (settlementToken.balanceOf(address(this)) < accountedSettlementBalance()) {
            revert AccountingMismatch();
        }
        if (defaultCvaReleaseStarted && redemptionEscrow != 0) revert AccountingMismatch();
    }

    function _assertCvaIntegrity() private view {
        if (
            cvaAdapter.asset() != cvaToken
                || cvaAdapter.availableBalance(address(this)) != cvaAccounted
                || cvaAdapter.issuedSupply() != initialUnits - cvaBurned
        ) revert AccountingMismatch();
    }

    function _update(address from, address to, uint256 value) internal override {
        if (protectionState != ProtectionState.Unfunded) _assertCvaIntegrity();
        if (from != address(0) && to != address(0)) {
            if (
                receivableState != ReceivableState.Outstanding
                    && receivableState != ReceivableState.DefaultOutstanding
            ) revert InvalidState();
            _requireHolder(from);
            _requireHolder(to);
        } else if (to != address(0)) {
            _requireHolder(to);
        } else if (from != address(0)) {
            _requireHolder(from);
        }

        if (sequence == type(uint48).max) revert InvalidState();
        ++sequence;
        super._update(from, to, value);
        if (from != address(0)) _writeCheckpoint(_balanceCheckpoints[from], balanceOf(from));
        if (to != address(0)) _writeCheckpoint(_balanceCheckpoints[to], balanceOf(to));
        _writeCheckpoint(_supplyCheckpoints, totalSupply());
    }

    function _writeCheckpoint(BalanceCheckpoint[] storage checkpoints, uint256 value) private {
        if (value > type(uint208).max) revert AccountingMismatch();
        uint256 length = checkpoints.length;
        if (length != 0 && checkpoints[length - 1].sequence == sequence) {
            checkpoints[length - 1].balance = uint208(value);
        } else {
            checkpoints.push(BalanceCheckpoint({ sequence: sequence, balance: uint208(value) }));
        }
    }

    function _lookup(BalanceCheckpoint[] storage checkpoints, uint48 atSequence)
        private
        view
        returns (uint256)
    {
        uint256 low;
        uint256 high = checkpoints.length;
        while (low < high) {
            uint256 mid = (low + high) / 2;
            if (checkpoints[mid].sequence > atSequence) high = mid;
            else low = mid + 1;
        }
        return high == 0 ? 0 : checkpoints[high - 1].balance;
    }
}
