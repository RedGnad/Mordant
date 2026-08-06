// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { ICviVerifier } from "../interfaces/ICviVerifier.sol";

/// @notice Consumes one governed FHE conflict decision and runs the settlement consequence.
///
/// @dev Two distinct identities meet here, and they are deliberately not conflated.
///
/// `expectedGovernedReleaseAuthorityId` is the identifier of the Ed25519 governed release
/// authority, derived from the FHE result itself. It is data: the contract compares it, it never
/// verifies an Ed25519 signature, because the EVM cannot.
///
/// `attestor` is a secp256k1 key that signs the EIP-712 bridge attestation after the Ed25519
/// release has been verified off-chain. It is a signer, not an identity claim.
///
/// They are different keys, on different curves, doing different jobs. A release is admitted only
/// when both hold: the bridge signature recovers to `attestor`, and the governed authority carried
/// in the attestation equals the pinned one. Neither alone is sufficient, and nothing here should
/// be read as asserting that the bridge key is the governed authority.
///
/// Every economic parameter is fixed at deployment. There is no upgrade path, no arbitrary call,
/// no settable settlement token and no settable recipient: a payout can only ever reach the holder
/// address that the attestor signed.
contract MordantRecourseAdapter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint8 public constant ROLE_FACILITY = 3;
    uint8 public constant ROLE_HOLDER = 4;

    enum CaseState {
        None,
        CureOpen,
        Cured,
        Entitled,
        Claimed,
        Refused
    }

    /// @dev Every field the attestor signs. Anything absent here could be substituted freely.
    struct GovernedRelease {
        bytes32 runId;
        bytes32 fheCaseId;
        bytes32 caseBindingDigest;
        bytes32 assetIdentityDigest;
        bytes32 governedResultDigest;
        bytes32 resultCiphertextDigest;
        bytes32 participantArtifactDigestA;
        bytes32 participantArtifactDigestB;
        address holderA;
        address holderB;
        uint256 payoutA;
        uint256 payoutB;
        bool conflict;
        /// @dev The Ed25519 governed release authority identifier, taken from the verified FHE
        /// result. Not the bridge signer.
        bytes32 releaseAuthorityId;
        bytes32 releaseMode;
        bytes32 circuitHash;
        bytes32 parameterFingerprint;
        uint256 nonce;
        uint64 issuedAt;
        uint64 expiry;
    }

    struct Case {
        CaseState state;
        bool paidA;
        bool paidB;
        uint64 cureDeadline;
        address holderA;
        address holderB;
        uint256 payoutA;
        uint256 payoutB;
    }

    bytes32 public constant RELEASE_TYPEHASH = keccak256(
        "GovernedRelease(bytes32 runId,bytes32 fheCaseId,bytes32 caseBindingDigest,bytes32 assetIdentityDigest,bytes32 governedResultDigest,bytes32 resultCiphertextDigest,bytes32 participantArtifactDigestA,bytes32 participantArtifactDigestB,address holderA,address holderB,uint256 payoutA,uint256 payoutB,bool conflict,bytes32 releaseAuthorityId,bytes32 releaseMode,bytes32 circuitHash,bytes32 parameterFingerprint,uint256 nonce,uint64 issuedAt,uint64 expiry)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    IERC20 public immutable settlementToken;
    ICviVerifier public immutable cviVerifier;
    /// @notice secp256k1 signer of the bridge attestation. Never the governed authority.
    address public immutable attestor;
    address public immutable facility;
    address public immutable owner;
    bytes32 public immutable assetIdentityDigest;
    /// @notice The one Ed25519 governed release authority whose results this adapter settles.
    bytes32 public immutable expectedGovernedReleaseAuthorityId;
    bytes32 public immutable releaseMode;
    bytes32 public immutable circuitHash;
    bytes32 public immutable parameterFingerprint;
    uint64 public immutable cureWindow;
    uint256 private immutable deployedChainId;
    bytes32 private immutable cachedDomainSeparator;

    /// @dev Explicit, not derived from the token balance: a donated transfer must never be
    /// mistaken for reserve, and reserved liabilities must never be spendable.
    uint256 public availableReserve;
    uint256 public openReserved;
    uint256 public entitledUnpaid;

    mapping(bytes32 => Case) private caseByRun;
    mapping(bytes32 => bool) public resultConsumed;
    mapping(bytes32 => bool) public attestationConsumed;

    event ReserveFunded(address indexed payer, uint256 amount, uint256 available);
    event ReserveWithdrawn(address indexed to, uint256 amount, uint256 available);
    event ReleaseConsumed(bytes32 indexed runId, bool conflict, bytes32 governedResultDigest);
    event CureWindowOpened(bytes32 indexed runId, uint64 cureDeadline, uint256 reserved);
    event ConflictCured(bytes32 indexed runId, uint256 released);
    event RecourseRefused(bytes32 indexed runId);
    event EntitlementOpened(bytes32 indexed runId, uint256 amount);
    event Claimed(bytes32 indexed runId, address indexed holder, uint256 amount);

    error ZeroAddress();
    error ZeroAmount();
    error NotOwner();
    error NotFacility();
    error WrongState(CaseState state);
    error RunConsumed(bytes32 runId);
    error ResultConsumed(bytes32 governedResultDigest);
    error AttestationConsumed(bytes32 attestationDigest);
    error BadAttestor(address recovered);
    error BadAsset(bytes32 supplied);
    /// @dev Kept separate from a bad signature so the two failures are never confused.
    error GovernedAuthorityMismatch(bytes32 supplied, bytes32 expected);
    error BadReleaseMode(bytes32 supplied);
    error BadCircuit();
    error Expired(uint64 expiry);
    error NotYetIssued(uint64 issuedAt);
    error InsufficientReserve(uint256 required, uint256 available);
    error WindowOpen();
    error WindowClosed();
    error AlreadyPaid();
    error NothingToPay();
    error Ineligible(address account, uint8 role);
    error PayoutOnNoConflict();
    error Insolvent();

    constructor(
        IERC20 initialSettlementToken,
        ICviVerifier initialCviVerifier,
        address initialAttestor,
        address initialFacility,
        address initialOwner,
        bytes32 initialAssetIdentityDigest,
        bytes32 initialExpectedGovernedReleaseAuthorityId,
        bytes32 initialReleaseMode,
        bytes32 initialCircuitHash,
        bytes32 initialParameterFingerprint,
        uint64 initialCureWindow
    ) {
        if (
            address(initialSettlementToken) == address(0) || address(initialCviVerifier) == address(0)
                || initialAttestor == address(0) || initialFacility == address(0) || initialOwner == address(0)
        ) revert ZeroAddress();
        if (
            initialAssetIdentityDigest == bytes32(0) || initialExpectedGovernedReleaseAuthorityId == bytes32(0)
                || initialReleaseMode == bytes32(0) || initialCircuitHash == bytes32(0)
                || initialParameterFingerprint == bytes32(0) || initialCureWindow == 0
        ) revert ZeroAmount();

        settlementToken = initialSettlementToken;
        cviVerifier = initialCviVerifier;
        attestor = initialAttestor;
        facility = initialFacility;
        owner = initialOwner;
        assetIdentityDigest = initialAssetIdentityDigest;
        expectedGovernedReleaseAuthorityId = initialExpectedGovernedReleaseAuthorityId;
        releaseMode = initialReleaseMode;
        circuitHash = initialCircuitHash;
        parameterFingerprint = initialParameterFingerprint;
        cureWindow = initialCureWindow;
        deployedChainId = block.chainid;
        cachedDomainSeparator = _buildDomainSeparator();
    }

    // ------------------------------------------------------------------ reserve

    function fundReserve(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        availableReserve += amount;
        settlementToken.safeTransferFrom(msg.sender, address(this), amount);
        emit ReserveFunded(msg.sender, amount, availableReserve);
    }

    /// @dev Bounded on purpose: only unreserved reserve can leave, so no administrative path can
    /// reach an open or entitled liability.
    function withdrawAvailable(address to, uint256 amount) external nonReentrant {
        if (msg.sender != owner) revert NotOwner();
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (amount > availableReserve) revert InsufficientReserve(amount, availableReserve);
        availableReserve -= amount;
        settlementToken.safeTransfer(to, amount);
        emit ReserveWithdrawn(to, amount, availableReserve);
    }

    // ------------------------------------------------------------------ release

    function consumeGovernedRelease(GovernedRelease calldata r, bytes calldata signature)
        external
        nonReentrant
    {
        if (caseByRun[r.runId].state != CaseState.None) revert RunConsumed(r.runId);
        if (resultConsumed[r.governedResultDigest]) revert ResultConsumed(r.governedResultDigest);
        if (r.assetIdentityDigest != assetIdentityDigest) revert BadAsset(r.assetIdentityDigest);
        if (r.releaseAuthorityId != expectedGovernedReleaseAuthorityId) {
            revert GovernedAuthorityMismatch(r.releaseAuthorityId, expectedGovernedReleaseAuthorityId);
        }
        if (r.releaseMode != releaseMode) revert BadReleaseMode(r.releaseMode);
        if (r.circuitHash != circuitHash || r.parameterFingerprint != parameterFingerprint) revert BadCircuit();
        if (block.timestamp > r.expiry) revert Expired(r.expiry);
        if (block.timestamp < r.issuedAt) revert NotYetIssued(r.issuedAt);
        if (r.runId == bytes32(0) || r.governedResultDigest == bytes32(0)) revert ZeroAmount();

        bytes32 attestationDigest = _hashRelease(r);
        if (attestationConsumed[attestationDigest]) revert AttestationConsumed(attestationDigest);
        address recovered = ECDSA.recover(attestationDigest, signature);
        if (recovered != attestor) revert BadAttestor(recovered);

        resultConsumed[r.governedResultDigest] = true;
        attestationConsumed[attestationDigest] = true;

        Case storage entry = caseByRun[r.runId];
        entry.holderA = r.holderA;
        entry.holderB = r.holderB;

        if (!r.conflict) {
            // A signed false Boolean is terminal for this case. Nothing is reserved, and no later
            // attestation can reopen it because the run is already consumed.
            if (r.payoutA != 0 || r.payoutB != 0) revert PayoutOnNoConflict();
            entry.state = CaseState.Refused;
            emit ReleaseConsumed(r.runId, false, r.governedResultDigest);
            emit RecourseRefused(r.runId);
            return;
        }

        if (r.holderA == address(0) || r.holderB == address(0)) revert ZeroAddress();
        uint256 total = r.payoutA + r.payoutB;
        if (total == 0) revert ZeroAmount();
        if (total > availableReserve) revert InsufficientReserve(total, availableReserve);

        availableReserve -= total;
        openReserved += total;
        entry.payoutA = r.payoutA;
        entry.payoutB = r.payoutB;
        entry.state = CaseState.CureOpen;
        entry.cureDeadline = uint64(block.timestamp) + cureWindow;

        emit ReleaseConsumed(r.runId, true, r.governedResultDigest);
        emit CureWindowOpened(r.runId, entry.cureDeadline, total);
    }

    // ------------------------------------------------------------------ lifecycle

    function cure(bytes32 runId) external nonReentrant {
        if (msg.sender != facility) revert NotFacility();
        _requireEligible(msg.sender, ROLE_FACILITY);
        Case storage entry = caseByRun[runId];
        if (entry.state != CaseState.CureOpen) revert WrongState(entry.state);
        if (block.timestamp > entry.cureDeadline) revert WindowClosed();

        uint256 released = entry.payoutA + entry.payoutB;
        openReserved -= released;
        availableReserve += released;
        entry.state = CaseState.Cured;
        emit ConflictCured(runId, released);
    }

    /// @dev Permissionless on purpose: an uncured conflict must not depend on any party acting.
    function finalize(bytes32 runId) external nonReentrant {
        Case storage entry = caseByRun[runId];
        if (entry.state != CaseState.CureOpen) revert WrongState(entry.state);
        if (block.timestamp <= entry.cureDeadline) revert WindowOpen();

        uint256 amount = entry.payoutA + entry.payoutB;
        openReserved -= amount;
        entitledUnpaid += amount;
        entry.state = CaseState.Entitled;
        emit EntitlementOpened(runId, amount);
    }

    /// @param holderIsA which fixed entitlement to settle. The recipient is never a parameter.
    function claim(bytes32 runId, bool holderIsA) external nonReentrant {
        Case storage entry = caseByRun[runId];
        if (entry.state != CaseState.Entitled) revert WrongState(entry.state);

        address holder = holderIsA ? entry.holderA : entry.holderB;
        uint256 amount = holderIsA ? entry.payoutA : entry.payoutB;
        if (holderIsA ? entry.paidA : entry.paidB) revert AlreadyPaid();
        if (amount == 0) revert NothingToPay();
        _requireEligible(holder, ROLE_HOLDER);

        if (holderIsA) entry.paidA = true;
        else entry.paidB = true;
        entitledUnpaid -= amount;
        if (entry.paidA && entry.paidB) entry.state = CaseState.Claimed;

        settlementToken.safeTransfer(holder, amount);
        emit Claimed(runId, holder, amount);
    }

    // ------------------------------------------------------------------ views

    function caseOf(bytes32 runId) external view returns (Case memory) {
        return caseByRun[runId];
    }

    function caseState(bytes32 runId) external view returns (uint8) {
        return uint8(caseByRun[runId].state);
    }

    function domainSeparator() public view returns (bytes32) {
        return block.chainid == deployedChainId ? cachedDomainSeparator : _buildDomainSeparator();
    }

    function hashRelease(GovernedRelease calldata r) external view returns (bytes32) {
        return _hashRelease(r);
    }

    /// @notice token balance >= available + open reserved + entitled unpaid.
    function solvent() public view returns (bool) {
        return settlementToken.balanceOf(address(this)) >= availableReserve + openReserved + entitledUnpaid;
    }

    function assertSolvency() external view {
        if (!solvent()) revert Insolvent();
    }

    // ------------------------------------------------------------------ internals

    function _requireEligible(address account, uint8 role) private view {
        if (!cviVerifier.isEligible(account, role)) revert Ineligible(account, role);
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("MordantRecourseAdapter"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev Encoded in two halves purely to keep the stack shallow. Every field is a value type,
    /// so the concatenation is byte-identical to encoding all twenty at once, and the EIP-712
    /// struct hash is unchanged.
    function _hashRelease(GovernedRelease calldata r) private view returns (bytes32) {
        bytes memory head = abi.encode(
            RELEASE_TYPEHASH,
            r.runId,
            r.fheCaseId,
            r.caseBindingDigest,
            r.assetIdentityDigest,
            r.governedResultDigest,
            r.resultCiphertextDigest,
            r.participantArtifactDigestA,
            r.participantArtifactDigestB,
            r.holderA,
            r.holderB
        );
        bytes memory tail = abi.encode(
            r.payoutA,
            r.payoutB,
            r.conflict,
            r.releaseAuthorityId,
            r.releaseMode,
            r.circuitHash,
            r.parameterFingerprint,
            r.nonce,
            r.issuedAt,
            r.expiry
        );
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), keccak256(bytes.concat(head, tail)))
        );
    }
}
