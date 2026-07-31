// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Frozen V4 match-result semantics.
/// @dev The binder is not implemented yet; these rules are what it will be built
/// against, and they are enforced here so the semantics cannot drift.
///
/// Three distinct outcomes, deliberately not collapsed into one Boolean:
///
///   exactMatchConfirmed      strict, non-lossy identity equality under FHE
///   candidateMatchSuggested  tolerant alias equality: reconciliation only
///   conflictConfirmed        a terms conflict, valid ONLY on an exact match
///
/// A tolerant equality is never sufficient for matchConfirmed, conflict,
/// binding, responsibility, cure deadline, recourse or disclosure. There is no
/// path in this library that upgrades a candidate result into a bindable one:
/// the only way to reach binding is a fresh exact session run after an
/// authorized pre-commitment.
library MordantMatchResult {
    error CandidateResultNotBindable();
    error ConflictWithoutExactMatch();
    error EmptyResult();
    error MissingPrecommitment(bytes32 sessionId);
    error CandidateSessionCannotBind(bytes32 candidateSessionId);

    /// @notice What the quorum attests for one session.
    struct ConfidentialMatchResultV4 {
        bytes32 sessionId;
        bytes32 scopeCommitmentA;
        bytes32 scopeCommitmentB;
        bytes32 inputCommitmentA;
        bytes32 inputCommitmentB;
        /// @dev Set only on the strict path. Never set from a tolerant alias.
        bool exactMatchConfirmed;
        /// @dev Set only on the tolerant path. Advisory, private, non-binding.
        bool candidateMatchSuggested;
        /// @dev Terms conflict. Meaningless without an exact match.
        bool conflictConfirmed;
        /// @dev Salted per session; opens against the strict identity only.
        bytes32 matchCommitment;
        uint8 anchorCount;
        bytes32 providerProofCommitment;
    }

    /// @notice Structural coherence, checked before anything consumes a result.
    /// @dev `conflictConfirmed` without `exactMatchConfirmed` is refused rather
    /// than tolerated: a terms conflict on an unproven identity would assign
    /// responsibility against the wrong receivable.
    function requireCoherent(ConfidentialMatchResultV4 memory result) internal pure {
        if (
            result.sessionId == bytes32(0) || result.inputCommitmentA == bytes32(0)
                || result.inputCommitmentB == bytes32(0) || result.providerProofCommitment == bytes32(0)
        ) revert EmptyResult();
        if (result.conflictConfirmed && !result.exactMatchConfirmed) {
            revert ConflictWithoutExactMatch();
        }
    }

    /// @notice The only gate through which a result may reach a binder.
    /// @dev `precommitted` must be the registry's answer for this session, not a
    /// caller assertion, so a candidate result cannot be re-labelled as exact by
    /// whoever submits it.
    function requireBindable(ConfidentialMatchResultV4 memory result, bool precommitted)
        internal
        pure
    {
        requireCoherent(result);
        // A tolerant equality can never bind, whatever else the result says.
        if (!result.exactMatchConfirmed) revert CandidateResultNotBindable();
        if (result.candidateMatchSuggested) {
            // A session that ran the tolerant path is a reconciliation signal by
            // construction. Binding requires a fresh strict session.
            revert CandidateSessionCannotBind(result.sessionId);
        }
        if (result.matchCommitment == bytes32(0) || result.anchorCount == 0) {
            revert EmptyResult();
        }
        if (!precommitted) revert MissingPrecommitment(result.sessionId);
    }

    /// @notice Whether a result may open a private reconciliation workflow.
    /// @dev This is the only thing a candidate result is good for.
    function opensReconciliation(ConfidentialMatchResultV4 memory result)
        internal
        pure
        returns (bool)
    {
        return result.candidateMatchSuggested && !result.exactMatchConfirmed;
    }
}
