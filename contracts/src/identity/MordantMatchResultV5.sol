// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice RC2 match-result semantics.
///
/// @dev The V4 schema derived BOTH `exactMatchConfirmed` and `conflictConfirmed`
/// from a single released conjunction
///
///     identityEqual AND currencyEqual AND overlap AND exclusiveA AND exclusiveB
///
/// so a false bit could mean "different receivable" OR "same receivable, terms
/// do not conflict", and the two were indistinguishable. External audit finding
/// H-02: the system could not answer the question the product is named after.
///
/// RC2 releases TWO independent bits and derives a three-state outcome from
/// them. Nothing is inferred:
///
///     sameEconomicAsset  =  identityEqual
///     policyConflict     =  identityEqual AND currencyEqual AND overlap
///                           AND exclusiveA AND exclusiveB
///
/// | sameEconomicAsset | policyConflict | outcome                       |
/// |-------------------|----------------|-------------------------------|
/// | false             | false          | DifferentAsset                |
/// | true              | false          | SameAssetNoPolicyConflict     |
/// | true              | true           | SameAssetPolicyConflict       |
/// | false             | true           | incoherent, always rejected   |
///
/// Only `SameAssetPolicyConflict` may open a recourse record.
library MordantMatchResultV5 {
    error EmptyResult();
    error OutcomeInconsistent(Outcome outcome);
    error PolicyConflictWithoutAssetMatch();
    error ResultNotBindable(Outcome outcome);
    error MissingPrecommitment(bytes32 sessionCommitment);
    error CandidateResultNotBindable();
    error NotComparableMustNotEvaluate();
    error ReleasedBitsDisagreeWithOutcome();

    /// @dev The result schema version carried in every signed envelope. A
    /// consumer that does not understand it must refuse rather than guess.
    uint16 internal constant RESULT_SCHEMA_VERSION = 5;

    enum Outcome {
        None,
        /// The two submitted identities are not equal.
        DifferentAsset,
        /// Same receivable, but the submitted terms do not conflict.
        SameAssetNoPolicyConflict,
        /// Same receivable AND the terms conflict under the configured policy.
        SameAssetPolicyConflict,
        /// The tolerant path suggested an alias match. Never bindable.
        ReconciliationRequired,
        /// The submissions were not comparable. No FHE ran.
        NotComparable
    }

    /// @notice What the quorum attests for one session.
    struct ConfidentialMatchResultV5 {
        uint16 schemaVersion;
        bytes32 sessionCommitment;
        bytes32 scopeCommitmentA;
        bytes32 scopeCommitmentB;
        bytes32 inputCommitmentA;
        bytes32 inputCommitmentB;
        /// @dev Digest of each side's signed enrollment. Binds the evaluated
        /// pair to two authorizations of the SAME bilateral session.
        bytes32 enrollmentDigestA;
        bytes32 enrollmentDigestB;
        Outcome outcome;
        /// @dev Released bit 0. The encrypted strict-identity equality.
        bool sameEconomicAsset;
        /// @dev Released bit 1. The encrypted policy conjunction.
        bool policyConflict;
        /// @dev Tolerant path only. Never bindable.
        bool candidateMatchSuggested;
        bool candidateFallbackAuthorized;
        bytes32 matchCommitment;
        bytes32 boundCandidateAliasCommitment;
        uint8 anchorCount;
        /// @dev Commits to the circuit, its parameters, both input ciphertexts,
        /// both enrollments and the released output. Zero only for NotComparable.
        bytes32 providerProofCommitment;
        /// @dev Commits to the release transcript the operators recomputed.
        bytes32 thresholdTranscriptCommitment;
    }

    /// @notice The outcome implied by the two released bits, with no inference.
    function outcomeOf(bool sameEconomicAsset, bool policyConflict)
        internal
        pure
        returns (Outcome)
    {
        // A policy conflict on receivables that are not the same asset is not a
        // weaker signal, it is an impossible one: the policy conjunction has
        // identity equality as a factor.
        if (policyConflict && !sameEconomicAsset) revert PolicyConflictWithoutAssetMatch();
        if (!sameEconomicAsset) return Outcome.DifferentAsset;
        return policyConflict ? Outcome.SameAssetPolicyConflict : Outcome.SameAssetNoPolicyConflict;
    }

    /// @notice Structural coherence. Every consumer runs this first.
    function requireCoherent(ConfidentialMatchResultV5 memory result) internal pure {
        if (result.schemaVersion != RESULT_SCHEMA_VERSION) revert OutcomeInconsistent(result.outcome);
        if (
            result.sessionCommitment == bytes32(0) || result.inputCommitmentA == bytes32(0)
                || result.inputCommitmentB == bytes32(0) || result.scopeCommitmentA == bytes32(0)
                || result.scopeCommitmentB == bytes32(0)
        ) revert EmptyResult();
        if (result.scopeCommitmentA == result.scopeCommitmentB) revert EmptyResult();
        if (result.inputCommitmentA == result.inputCommitmentB) revert EmptyResult();

        if (result.outcome == Outcome.NotComparable) {
            // No FHE ran, so there is nothing to attest and nothing to release.
            if (result.sameEconomicAsset || result.policyConflict || result.candidateMatchSuggested) {
                revert OutcomeInconsistent(result.outcome);
            }
            if (
                result.providerProofCommitment != bytes32(0)
                    || result.thresholdTranscriptCommitment != bytes32(0)
            ) revert NotComparableMustNotEvaluate();
            return;
        }

        if (result.outcome == Outcome.ReconciliationRequired) {
            if (!result.candidateMatchSuggested || result.sameEconomicAsset || result.policyConflict) {
                revert OutcomeInconsistent(result.outcome);
            }
            if (!result.candidateFallbackAuthorized) revert OutcomeInconsistent(result.outcome);
            if (result.boundCandidateAliasCommitment == bytes32(0)) revert EmptyResult();
            if (result.providerProofCommitment == bytes32(0)) revert EmptyResult();
            return;
        }

        // Every remaining outcome came from a real evaluation of the strict path.
        if (result.candidateMatchSuggested) revert OutcomeInconsistent(result.outcome);
        if (result.providerProofCommitment == bytes32(0)) revert EmptyResult();
        if (result.thresholdTranscriptCommitment == bytes32(0)) revert EmptyResult();
        if (result.enrollmentDigestA == bytes32(0) || result.enrollmentDigestB == bytes32(0)) {
            revert EmptyResult();
        }
        if (result.enrollmentDigestA == result.enrollmentDigestB) revert EmptyResult();

        // The declared outcome must be exactly what the two released bits imply.
        // This is the check that makes the enum a consequence of the ciphertext
        // rather than a label the coordinator chose.
        if (outcomeOf(result.sameEconomicAsset, result.policyConflict) != result.outcome) {
            revert ReleasedBitsDisagreeWithOutcome();
        }
    }

    /// @notice The only gate through which a result may open a recourse record.
    /// @dev `precommitted` is the registry's answer, never a caller assertion.
    function requireBindable(ConfidentialMatchResultV5 memory result, bool precommitted)
        internal
        pure
    {
        requireCoherent(result);
        if (result.outcome == Outcome.ReconciliationRequired) revert CandidateResultNotBindable();
        // DifferentAsset and SameAssetNoPolicyConflict are both real answers.
        // Neither opens a recourse: one says it is not the same receivable, the
        // other says it is but the terms do not conflict.
        if (result.outcome != Outcome.SameAssetPolicyConflict) revert ResultNotBindable(result.outcome);
        if (!result.sameEconomicAsset || !result.policyConflict) {
            revert ReleasedBitsDisagreeWithOutcome();
        }
        if (result.matchCommitment == bytes32(0) || result.anchorCount == 0) revert EmptyResult();
        if (!precommitted) revert MissingPrecommitment(result.sessionCommitment);
    }

    /// @notice Whether a result may open a private reconciliation workflow.
    function opensReconciliation(ConfidentialMatchResultV5 memory result)
        internal
        pure
        returns (bool)
    {
        return result.outcome == Outcome.ReconciliationRequired;
    }

    /// @notice Only a confirmed policy conflict is publicly submittable.
    function isPubliclySubmittable(ConfidentialMatchResultV5 memory result)
        internal
        pure
        returns (bool)
    {
        return result.outcome == Outcome.SameAssetPolicyConflict;
    }

    /// @notice What a consumer may conclude. Kept as data so no caller has to
    /// remember the scoping rules.
    /// @dev `DifferentAsset` is scoped by its own name: it states that the two
    /// identifiers submitted in THIS session were not equal. It is never
    /// evidence of market completeness, of the absence of another pledge, or
    /// that the receivable is unencumbered anywhere else.
    function meaningOf(Outcome outcome) internal pure returns (string memory) {
        if (outcome == Outcome.DifferentAsset) {
            return "the two identifiers submitted in this session were not equal";
        }
        if (outcome == Outcome.SameAssetNoPolicyConflict) {
            return "the same receivable, and the submitted terms do not conflict";
        }
        if (outcome == Outcome.SameAssetPolicyConflict) {
            return "the same receivable, and the submitted terms conflict";
        }
        if (outcome == Outcome.ReconciliationRequired) {
            return "the identifiers may describe the same receivable; private reconciliation is required";
        }
        return "the submissions were not comparable; no evaluation was performed";
    }
}
