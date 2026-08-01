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
///
/// External audit finding M-05: V4 carried a tolerant "candidate alias" path
/// whose suggestion nothing authenticated. It is not present here. The V5
/// circuit compares only the strict identifier, under encryption, and produces
/// exactly two bits, so there is no tolerant result for the schema to express.
/// Removing it rather than gating it is what makes the unauthenticated path
/// unreachable instead of merely discouraged.
library MordantMatchResultV5 {
    error OutcomeInconsistent(Outcome outcome);
    error PolicyConflictWithoutAssetMatch();
    error ResultNotBindable(Outcome outcome);
    error ReleasedBitsDisagreeWithOutcome();

    enum Outcome {
        None,
        /// The two submitted identities are not equal.
        DifferentAsset,
        /// Same receivable, but the submitted terms do not conflict.
        SameAssetNoPolicyConflict,
        /// Same receivable AND the terms conflict under the configured policy.
        SameAssetPolicyConflict,
        /// The submissions were not comparable. No FHE ran.
        NotComparable
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

    /// @notice The declared outcome must be exactly what the two bits imply.
    /// @dev This is the check that makes the enum a consequence of the released
    /// ciphertext rather than a label the coordinator chose. It also reverts on
    /// the 01 state, via `outcomeOf`, so an invalid result cannot pass any
    /// boundary that calls this.
    function requireOutcomeMatchesBits(Outcome outcome, bool sameEconomicAsset, bool policyConflict)
        internal
        pure
    {
        if (outcome == Outcome.NotComparable) {
            // No evaluation ran, so neither bit may be set.
            if (sameEconomicAsset || policyConflict) revert OutcomeInconsistent(outcome);
            return;
        }
        if (outcomeOf(sameEconomicAsset, policyConflict) != outcome) {
            revert ReleasedBitsDisagreeWithOutcome();
        }
    }

    /// @notice The only gate through which a result may open a recourse record.
    /// @dev `DifferentAsset` and `SameAssetNoPolicyConflict` are both real
    /// answers. Neither opens a recourse: one says it is not the same
    /// receivable, the other says it is but the terms do not conflict.
    function requireBindableOutcome(Outcome outcome, bool sameEconomicAsset, bool policyConflict)
        internal
        pure
    {
        requireOutcomeMatchesBits(outcome, sameEconomicAsset, policyConflict);
        if (outcome != Outcome.SameAssetPolicyConflict) revert ResultNotBindable(outcome);
        // Belt and braces: the enum and the bits must both say conflict.
        if (!sameEconomicAsset || !policyConflict) revert ReleasedBitsDisagreeWithOutcome();
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
        return "the submissions were not comparable; no evaluation was performed";
    }
}
