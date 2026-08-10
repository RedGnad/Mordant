// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { ICviVerifier } from "../interfaces/ICviVerifier.sol";

/// @notice Consumes one coalition-released FHE decision and runs the settlement consequence.
///
/// @dev This is Adapter V2 with one identity replaced and one Boolean split in two. Everything
/// else, including every economic control, is deliberately unchanged so the two can be diffed.
///
/// **The release identity is a coalition, not a key.** V2 pinned the identifier of a single Ed25519
/// governed release authority. Here `expectedCoalitionAuthorityId` is the digest of the threshold
/// manifest that publishes the operator set and its quorum. It is still data: the contract compares
/// it and verifies no signature, because the EVM cannot verify Ed25519. What changed is what the
/// off-chain verifier must establish before it will attest, which is a quorum of operator
/// signatures against that manifest rather than one signature from one key. Nothing here should be
/// read as the contract having verified that quorum.
///
/// `attestor` is unchanged: a secp256k1 key that signs the EIP-712 bridge attestation once the
/// coalition evidence has been verified off-chain. It is a signer, not an identity claim, and it is
/// never the release authority.
///
/// **Two facts, not one Boolean.** External audit finding H-02 is that a single conjunction cannot
/// distinguish "different receivable" from "same receivable, no policy conflict". V2's `conflict`
/// has exactly that shape. The two facts arrive separately here, and the contract refuses the one
/// combination the circuit cannot produce.
///
/// `sameEconomicAsset` is an integrity constraint, not an economic input. Only `policyConflict`
/// decides whether anything is reserved or paid; the asset bit exists so a vector that could not
/// have come from the circuit is rejected rather than settled.
///
/// Every economic parameter is fixed at deployment. There is no upgrade path, no arbitrary call,
/// no settable settlement token and no settable recipient: a payout can only ever reach the holder
/// address that the attestor signed.
contract MordantCoalitionAdapter is ReentrancyGuard {
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
    struct CoalitionRelease {
        bytes32 runId;
        bytes32 fheCaseId;
        bytes32 caseBindingDigest;
        bytes32 assetIdentityDigest;
        bytes32 coalitionResultDigest;
        /// @dev The transcript commitment over the whole coalition release. V2 carried a single
        /// result ciphertext digest; a coalition releases two bits and commits to both, to the
        /// operators that served and to what each recomputed.
        bytes32 releaseTranscript;
        bytes32 participantArtifactDigestA;
        bytes32 participantArtifactDigestB;
        address holderA;
        address holderB;
        uint256 payoutA;
        uint256 payoutB;
        /// @dev Integrity only. Never an economic input.
        bool sameEconomicAsset;
        /// @dev The decision. This alone opens or refuses the consequence.
        bool policyConflict;
        /// @dev The digest of the threshold manifest that published the coalition. Not the bridge
        /// signer, and not a key.
        bytes32 coalitionAuthorityId;
        /// @dev The quorum that served, as recorded in the verified evidence.
        uint16 servingQuorum;
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
        "CoalitionRelease(bytes32 runId,bytes32 fheCaseId,bytes32 caseBindingDigest,bytes32 assetIdentityDigest,bytes32 coalitionResultDigest,bytes32 releaseTranscript,bytes32 participantArtifactDigestA,bytes32 participantArtifactDigestB,address holderA,address holderB,uint256 payoutA,uint256 payoutB,bool sameEconomicAsset,bool policyConflict,bytes32 coalitionAuthorityId,uint16 servingQuorum,bytes32 releaseMode,bytes32 circuitHash,bytes32 parameterFingerprint,uint256 nonce,uint64 issuedAt,uint64 expiry)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    IERC20 public immutable settlementToken;
    ICviVerifier public immutable cviVerifier;
    /// @notice secp256k1 signer of the bridge attestation. Never the coalition authority.
    address public immutable attestor;
    address public immutable facility;
    address public immutable owner;
    bytes32 public immutable assetIdentityDigest;
    /// @notice The digest of the threshold manifest whose coalition this adapter settles for.
    bytes32 public immutable expectedCoalitionAuthorityId;
    /// @notice The quorum that manifest requires. A release attesting a smaller one is refused.
    uint16 public immutable requiredQuorum;
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
    event ReleaseConsumed(
        bytes32 indexed runId,
        bool sameEconomicAsset,
        bool policyConflict,
        bytes32 coalitionResultDigest
    );
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
    error ResultConsumed(bytes32 coalitionResultDigest);
    error AttestationConsumed(bytes32 attestationDigest);
    error BadAttestor(address recovered);
    error BadAsset(bytes32 supplied);
    /// @dev Kept separate from a bad signature so the two failures are never confused.
    error CoalitionAuthorityMismatch(bytes32 supplied, bytes32 expected);
    /// @dev A quorum smaller than the manifest requires is not the coalition this adapter settles.
    error QuorumTooSmall(uint16 supplied, uint16 required);
    /// @dev The circuit cannot produce a policy conflict without an asset match, because identity
    /// equality is a factor of the conjunction. A release claiming otherwise did not come from it.
    error NonCanonicalDecision(bool sameEconomicAsset, bool policyConflict);
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
    /// @dev Kept distinct from Ineligible: an identity that is still valid can
    /// still be refused by the asset's policy, and the two failures call for
    /// different responses.
    error TransferPolicyDenied(address holder, uint256 amount);
    error PayoutOnNoConflict();
    error Insolvent();

    constructor(
        IERC20 initialSettlementToken,
        ICviVerifier initialCviVerifier,
        address initialAttestor,
        address initialFacility,
        address initialOwner,
        bytes32 initialAssetIdentityDigest,
        bytes32 initialExpectedCoalitionAuthorityId,
        uint16 initialRequiredQuorum,
        bytes32 initialReleaseMode,
        bytes32 initialCircuitHash,
        bytes32 initialParameterFingerprint,
        uint64 initialCureWindow
    ) {
        if (
            address(initialSettlementToken) == address(0)
                || address(initialCviVerifier) == address(0) || initialAttestor == address(0)
                || initialFacility == address(0) || initialOwner == address(0)
        ) revert ZeroAddress();
        if (
            initialAssetIdentityDigest == bytes32(0)
                || initialExpectedCoalitionAuthorityId == bytes32(0)
                || initialReleaseMode == bytes32(0) || initialCircuitHash == bytes32(0)
                || initialParameterFingerprint == bytes32(0) || initialCureWindow == 0
        ) revert ZeroAmount();
        // A quorum of one is not a coalition, and this adapter exists so that a single operator
        // cannot settle. Refusing it at deployment removes the configuration that would undo the
        // property, rather than trusting nobody sets it.
        if (initialRequiredQuorum < 2) revert QuorumTooSmall(initialRequiredQuorum, 2);

        settlementToken = initialSettlementToken;
        cviVerifier = initialCviVerifier;
        attestor = initialAttestor;
        facility = initialFacility;
        owner = initialOwner;
        assetIdentityDigest = initialAssetIdentityDigest;
        expectedCoalitionAuthorityId = initialExpectedCoalitionAuthorityId;
        requiredQuorum = initialRequiredQuorum;
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

    function consumeCoalitionRelease(CoalitionRelease calldata r, bytes calldata signature)
        external
        nonReentrant
    {
        if (caseByRun[r.runId].state != CaseState.None) revert RunConsumed(r.runId);
        if (resultConsumed[r.coalitionResultDigest]) {
            revert ResultConsumed(r.coalitionResultDigest);
        }
        if (r.assetIdentityDigest != assetIdentityDigest) revert BadAsset(r.assetIdentityDigest);
        if (r.coalitionAuthorityId != expectedCoalitionAuthorityId) {
            revert CoalitionAuthorityMismatch(r.coalitionAuthorityId, expectedCoalitionAuthorityId);
        }
        if (r.servingQuorum < requiredQuorum) {
            revert QuorumTooSmall(r.servingQuorum, requiredQuorum);
        }
        // H-02 on chain. The circuit's policy conjunction has identity equality as a factor, so
        // this combination is unreachable. Refusing it keeps the two facts meaningful here rather
        // than letting the chain accept a vector the circuit cannot produce.
        if (r.policyConflict && !r.sameEconomicAsset) {
            revert NonCanonicalDecision(r.sameEconomicAsset, r.policyConflict);
        }
        if (r.releaseMode != releaseMode) revert BadReleaseMode(r.releaseMode);
        if (r.circuitHash != circuitHash || r.parameterFingerprint != parameterFingerprint) {
            revert BadCircuit();
        }
        if (block.timestamp > r.expiry) revert Expired(r.expiry);
        if (block.timestamp < r.issuedAt) revert NotYetIssued(r.issuedAt);
        if (
            r.runId == bytes32(0) || r.coalitionResultDigest == bytes32(0)
                || r.releaseTranscript == bytes32(0)
        ) {
            revert ZeroAmount();
        }

        bytes32 attestationDigest = _hashRelease(r);
        if (attestationConsumed[attestationDigest]) revert AttestationConsumed(attestationDigest);
        address recovered = ECDSA.recover(attestationDigest, signature);
        if (recovered != attestor) revert BadAttestor(recovered);

        resultConsumed[r.coalitionResultDigest] = true;
        attestationConsumed[attestationDigest] = true;

        Case storage entry = caseByRun[r.runId];
        entry.holderA = r.holderA;
        entry.holderB = r.holderB;

        if (!r.policyConflict) {
            // A signed absence of policy conflict is terminal for this case, whether or not the
            // two sides pledged the same asset. Nothing is reserved, and no later attestation can
            // reopen it because the run is already consumed.
            if (r.payoutA != 0 || r.payoutB != 0) revert PayoutOnNoConflict();
            entry.state = CaseState.Refused;
            emit ReleaseConsumed(r.runId, r.sameEconomicAsset, false, r.coalitionResultDigest);
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

        emit ReleaseConsumed(r.runId, r.sameEconomicAsset, true, r.coalitionResultDigest);
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
        // Two independent Cleanverse authorities are consulted at the only moment
        // value actually moves, and both are read live rather than remembered
        // from admission time.
        //
        // The first is the holder's identity: `isEligible` resolves the A-Pass
        // through the CVI verifier, so an entitlement opened months ago stops
        // being claimable the moment that identity ceases to be valid.
        //
        // The second is the asset's own policy, which the settlement token
        // resolves for itself and which can refuse a transfer the identity gate
        // would allow. MordantInvoiceVault consults it at its own release, and
        // this is the same boundary for the same reason: an entitlement is not a
        // permission to move the token.
        _requireEligible(holder, ROLE_HOLDER);
        if (!cviVerifier.isAssetTransferAllowed(
                address(settlementToken), address(this), holder, amount
            )) {
            revert TransferPolicyDenied(holder, amount);
        }

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

    function hashRelease(CoalitionRelease calldata r) external view returns (bytes32) {
        return _hashRelease(r);
    }

    /// @notice token balance >= available + open reserved + entitled unpaid.
    function solvent() public view returns (bool) {
        return settlementToken.balanceOf(address(this))
            >= availableReserve + openReserved + entitledUnpaid;
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
                keccak256("MordantCoalitionAdapter"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev Encoded in halves purely to keep the stack shallow. Every field is a value type, so the
    /// concatenation is byte-identical to encoding all of them at once, and the EIP-712 struct hash
    /// is unchanged.
    function _hashRelease(CoalitionRelease calldata r) private view returns (bytes32) {
        bytes memory head = abi.encode(
            RELEASE_TYPEHASH,
            r.runId,
            r.fheCaseId,
            r.caseBindingDigest,
            r.assetIdentityDigest,
            r.coalitionResultDigest,
            r.releaseTranscript,
            r.participantArtifactDigestA,
            r.participantArtifactDigestB,
            r.holderA,
            r.holderB
        );
        bytes memory tail = abi.encode(
            r.payoutA,
            r.payoutB,
            r.sameEconomicAsset,
            r.policyConflict,
            r.coalitionAuthorityId,
            r.servingQuorum,
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
