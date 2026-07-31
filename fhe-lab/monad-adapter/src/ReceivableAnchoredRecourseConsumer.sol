// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ConfidentialPolicyResultV3,
    IConfidentialPolicyVerifierV3
} from "./interfaces/IConfidentialPolicyVerifierV3.sol";
import {IReceivableAnchor} from "./interfaces/IReceivableAnchor.sol";

/// @notice Non-economic recourse consumer bound to a real tokenized receivable.
/// @dev This is the V4 consumer. It keeps the V3 result schema, the V3 verifier
/// and the provider-proof semantics untouched, and adds one thing the V3
/// laboratory consumer lacked: the vault named by the confidential result must
/// be a deployed tokenized receivable in the expected state, not an arbitrary
/// codeless address.
///
/// It remains strictly non-economic. It holds no balance, has no token
/// interface, and the anchor is reached only through a view-only interface, so
/// it cannot move units, settlement funds, reserves, entitlements or claims.
contract ReceivableAnchoredRecourseConsumer {
    error InvalidConfiguration();
    error AlreadyOpened(bytes32 resultCommitment);
    error ResultNotForConsumer(address supplied);
    error ResultNotConflict();
    error UnexpectedPolicy();
    error AnchorMismatch(address supplied, address expected);
    error AnchorNotDeployed(address anchor);
    error AnchorRootMismatch(bytes32 observed, bytes32 expected);
    error AnchorCurrencyMismatch(bytes32 observed, bytes32 expected);
    error AnchorNotOutstanding(uint8 receivableState);
    error AnchorProtectionInactive(uint8 protectionState);
    error AnchorHasNoUnits();

    enum RecourseStatus {
        None,
        Open
    }

    struct RecourseRecord {
        bytes32 resultCommitment;
        bytes32 providerProofCommitment;
        bytes32 inputCommitmentA;
        bytes32 inputCommitmentB;
        bytes32 policyId;
        uint32 policyVersion;
        bytes32 responsibleRole;
        bytes32 consequenceId;
        bytes32 invoiceRoot;
        uint64 acceptedAt;
        uint64 cureDeadline;
        RecourseStatus status;
    }

    event AnchoredRecourseOpened(
        bytes32 indexed resultCommitment,
        bytes32 indexed providerProofCommitment,
        address indexed receivableAnchor,
        bytes32 invoiceRoot,
        bytes32 policyId,
        uint32 policyVersion,
        bytes32 responsibleRole,
        uint64 cureDeadline,
        bytes32 consequenceId
    );

    /// @dev Receivable lifecycle states mirrored from MordantInvoiceVault.
    uint8 public constant RECEIVABLE_OUTSTANDING = 1;
    /// @dev Exclusivity protection is funded and running.
    uint8 public constant PROTECTION_ACTIVE = 1;

    IConfidentialPolicyVerifierV3 public immutable verifier;
    IReceivableAnchor public immutable receivableAnchor;
    bytes32 public immutable invoiceRoot;
    bytes32 public immutable currency;
    bytes32 public immutable policyId;
    uint32 public immutable policyVersion;
    bytes32 public immutable responsibleRole;
    uint64 public immutable curePeriod;
    bytes32 public immutable consequenceId;
    mapping(bytes32 resultCommitment => RecourseRecord record) public recourses;

    constructor(
        IConfidentialPolicyVerifierV3 verifier_,
        IReceivableAnchor receivableAnchor_,
        bytes32 policyId_,
        uint32 policyVersion_,
        bytes32 responsibleRole_,
        uint64 curePeriod_,
        bytes32 consequenceId_
    ) {
        if (
            address(verifier_) == address(0) || address(receivableAnchor_) == address(0)
                || policyId_ == bytes32(0) || policyVersion_ == 0 || responsibleRole_ == bytes32(0)
                || curePeriod_ == 0 || consequenceId_ == bytes32(0)
        ) {
            revert InvalidConfiguration();
        }
        // The anchor's identity is read once at construction and frozen. A
        // codeless address cannot answer these calls, so it cannot be bound.
        if (address(receivableAnchor_).code.length == 0) {
            revert AnchorNotDeployed(address(receivableAnchor_));
        }
        bytes32 root = receivableAnchor_.invoiceRoot();
        bytes32 anchorCurrency = receivableAnchor_.currency();
        if (root == bytes32(0) || anchorCurrency == bytes32(0)) revert InvalidConfiguration();
        if (receivableAnchor_.receivableState() != RECEIVABLE_OUTSTANDING) {
            revert AnchorNotOutstanding(receivableAnchor_.receivableState());
        }
        if (receivableAnchor_.totalSupply() == 0) revert AnchorHasNoUnits();

        verifier = verifier_;
        receivableAnchor = receivableAnchor_;
        invoiceRoot = root;
        currency = anchorCurrency;
        policyId = policyId_;
        policyVersion = policyVersion_;
        responsibleRole = responsibleRole_;
        curePeriod = curePeriod_;
        consequenceId = consequenceId_;
    }

    /// @notice Opens one non-economic recourse record for a confirmed conflict.
    /// @dev The confidential result's `vault` must be the bound receivable
    /// anchor, and the anchor must still be a live Outstanding receivable with
    /// the same invoice root and currency it was bound to.
    function openRecourse(ConfidentialPolicyResultV3 calldata result, bytes calldata attestation)
        external
    {
        if (result.consumer != address(this)) revert ResultNotForConsumer(result.consumer);
        if (!result.conflictConfirmed) revert ResultNotConflict();
        if (result.policyId != policyId || result.policyVersion != policyVersion) {
            revert UnexpectedPolicy();
        }
        // The result is scoped to the receivable itself, not to a placeholder.
        if (result.vault != address(receivableAnchor)) {
            revert AnchorMismatch(result.vault, address(receivableAnchor));
        }
        _assertAnchorLive();
        if (recourses[result.resultCommitment].status != RecourseStatus.None) {
            revert AlreadyOpened(result.resultCommitment);
        }

        verifier.acceptResult(result, attestation);
        uint64 acceptedAt = uint64(block.timestamp);
        uint64 cureDeadline = acceptedAt + curePeriod;
        recourses[result.resultCommitment] = RecourseRecord({
            resultCommitment: result.resultCommitment,
            providerProofCommitment: result.providerProofCommitment,
            inputCommitmentA: result.inputCommitmentA,
            inputCommitmentB: result.inputCommitmentB,
            policyId: result.policyId,
            policyVersion: result.policyVersion,
            responsibleRole: responsibleRole,
            consequenceId: consequenceId,
            invoiceRoot: invoiceRoot,
            acceptedAt: acceptedAt,
            cureDeadline: cureDeadline,
            status: RecourseStatus.Open
        });
        emit AnchoredRecourseOpened(
            result.resultCommitment,
            result.providerProofCommitment,
            address(receivableAnchor),
            invoiceRoot,
            result.policyId,
            result.policyVersion,
            responsibleRole,
            cureDeadline,
            consequenceId
        );
    }

    /// @notice Reports whether the bound receivable is still in the state that
    /// makes a recourse record meaningful.
    function anchorLive() external view returns (bool) {
        return address(receivableAnchor).code.length != 0
            && receivableAnchor.invoiceRoot() == invoiceRoot
            && receivableAnchor.currency() == currency
            && receivableAnchor.receivableState() == RECEIVABLE_OUTSTANDING
            && receivableAnchor.protectionState() == PROTECTION_ACTIVE;
    }

    function _assertAnchorLive() private view {
        if (address(receivableAnchor).code.length == 0) {
            revert AnchorNotDeployed(address(receivableAnchor));
        }
        bytes32 observedRoot = receivableAnchor.invoiceRoot();
        if (observedRoot != invoiceRoot) revert AnchorRootMismatch(observedRoot, invoiceRoot);
        bytes32 observedCurrency = receivableAnchor.currency();
        if (observedCurrency != currency) {
            revert AnchorCurrencyMismatch(observedCurrency, currency);
        }
        uint8 receivable = receivableAnchor.receivableState();
        if (receivable != RECEIVABLE_OUTSTANDING) revert AnchorNotOutstanding(receivable);
        uint8 protection = receivableAnchor.protectionState();
        if (protection != PROTECTION_ACTIVE) revert AnchorProtectionInactive(protection);
    }
}
