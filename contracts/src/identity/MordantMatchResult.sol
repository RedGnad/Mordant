// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Frozen V4 match-result semantics.
/// @dev Four private protocol outcomes, deliberately not collapsed into one
/// Boolean, because they mean different things and carry different authority:
///
///   EXACT_MATCH                      strict identity equality: the only bindable outcome
///   RECONCILIATION_REQUIRED          tolerant alias equality: opens a private workflow
///   NO_MATCH_FOR_SUBMITTED_IDENTITIES  exact equality ran and returned false
///   NOT_COMPARABLE                   no FHE ran; the submissions were incompatible
///
/// `NO_MATCH_FOR_SUBMITTED_IDENTITIES` is scoped by its own name. It states that
/// the two identifiers submitted in this session were not equal. It is never
/// evidence of market completeness, of the absence of another pledge, or that
/// the receivable is unencumbered anywhere else, and no consumer may present it
/// as such.
library MordantMatchResult {
    error CandidateResultNotBindable();
    error ConflictWithoutExactMatch();
    error EmptyResult();
    error MissingPrecommitment(bytes32 sessionId);
    error CandidateSessionCannotBind(bytes32 candidateSessionId);
    error OutcomeInconsistent(Outcome outcome);
    error CandidateFallbackNotAuthorized(bytes32 sessionId);
    error NotComparableMustNotEvaluate();
    error CandidateAliasNotBound();

    enum Outcome {
        None,
        ExactMatch,
        ReconciliationRequired,
        NoMatchForSubmittedIdentities,
        NotComparable
    }

    /// @notice What the quorum attests for one session.
    struct ConfidentialMatchResultV4 {
        bytes32 sessionId;
        bytes32 scopeCommitmentA;
        bytes32 scopeCommitmentB;
        bytes32 inputCommitmentA;
        bytes32 inputCommitmentB;
        Outcome outcome;
        /// @dev Set only on the strict path.
        bool exactMatchConfirmed;
        /// @dev Set only on the tolerant path, and only when both parties
        /// authorized candidate fallback when the session was initiated.
        bool candidateMatchSuggested;
        /// @dev Both parties authorized the tolerant path at session start. A
        /// candidate outcome without this is a protocol violation, not a signal.
        bool candidateFallbackAuthorized;
        /// @dev Terms conflict. Meaningless without an exact match.
        bool conflictConfirmed;
        /// @dev Salted per session; opens against the strict identity only.
        bytes32 matchCommitment;
        /// @dev Binds the tolerant alias to its issuer, profile, source record,
        /// session, scope and enrollment. Zero on the strict path.
        bytes32 boundCandidateAliasCommitment;
        uint8 anchorCount;
        /// @dev Zero for NOT_COMPARABLE, which performs no FHE evaluation.
        bytes32 providerProofCommitment;
    }

    /// @notice Structural coherence. Every consumer runs this first.
    function requireCoherent(ConfidentialMatchResultV4 memory result) internal pure {
        if (
            result.sessionId == bytes32(0) || result.inputCommitmentA == bytes32(0)
                || result.inputCommitmentB == bytes32(0) || result.scopeCommitmentA == bytes32(0)
                || result.scopeCommitmentB == bytes32(0)
        ) revert EmptyResult();
        if (result.conflictConfirmed && result.outcome != Outcome.ExactMatch) {
            revert ConflictWithoutExactMatch();
        }

        if (result.outcome == Outcome.ExactMatch) {
            // Exact means exact: a session that also ran the tolerant path is a
            // reconciliation signal, not a binding one.
            if (!result.exactMatchConfirmed || result.candidateMatchSuggested) {
                revert OutcomeInconsistent(result.outcome);
            }
            if (result.providerProofCommitment == bytes32(0)) revert EmptyResult();
        } else if (result.outcome == Outcome.ReconciliationRequired) {
            if (!result.candidateMatchSuggested || result.exactMatchConfirmed) {
                revert OutcomeInconsistent(result.outcome);
            }
            // The tolerant path may only run when both parties authorized it at
            // session initiation and paid for it from the session budget.
            if (!result.candidateFallbackAuthorized) {
                revert CandidateFallbackNotAuthorized(result.sessionId);
            }
            // The alias must be bound to its source, so a client cannot
            // manufacture a reconciliation signal or spend another party's budget.
            if (result.boundCandidateAliasCommitment == bytes32(0)) revert CandidateAliasNotBound();
            if (result.providerProofCommitment == bytes32(0)) revert EmptyResult();
        } else if (result.outcome == Outcome.NoMatchForSubmittedIdentities) {
            if (result.exactMatchConfirmed || result.candidateMatchSuggested) {
                revert OutcomeInconsistent(result.outcome);
            }
            if (result.providerProofCommitment == bytes32(0)) revert EmptyResult();
        } else if (result.outcome == Outcome.NotComparable) {
            // No FHE ran, so there is nothing to attest and nothing to release.
            if (
                result.exactMatchConfirmed || result.candidateMatchSuggested
                    || result.conflictConfirmed
            ) revert OutcomeInconsistent(result.outcome);
            if (result.providerProofCommitment != bytes32(0)) revert NotComparableMustNotEvaluate();
        } else {
            revert OutcomeInconsistent(result.outcome);
        }
    }

    /// @notice The only gate through which a result may reach a binder.
    /// @dev `precommitted` is the registry's answer, never a caller assertion.
    function requireBindable(ConfidentialMatchResultV4 memory result, bool precommitted)
        internal
        pure
    {
        requireCoherent(result);
        if (result.outcome != Outcome.ExactMatch) {
            if (result.outcome == Outcome.ReconciliationRequired) {
                revert CandidateSessionCannotBind(result.sessionId);
            }
            revert CandidateResultNotBindable();
        }
        if (result.matchCommitment == bytes32(0) || result.anchorCount == 0) revert EmptyResult();
        if (!precommitted) revert MissingPrecommitment(result.sessionId);
    }

    /// @notice Whether a result may open a private reconciliation workflow.
    function opensReconciliation(ConfidentialMatchResultV4 memory result)
        internal
        pure
        returns (bool)
    {
        return result.outcome == Outcome.ReconciliationRequired;
    }

    /// @notice A candidate outcome is terminal: it is never publicly submitted
    /// and never replayed into anything.
    function isPubliclySubmittable(ConfidentialMatchResultV4 memory result)
        internal
        pure
        returns (bool)
    {
        return result.outcome == Outcome.ExactMatch;
    }
}
