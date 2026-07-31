// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {MordantAssetIdentity as Id} from "../src/identity/MordantAssetIdentity.sol";
import {MordantNormalization as N} from "../src/identity/MordantNormalization.sol";

/// @notice Normative cross-language vectors for scheme 3.
/// @dev Two properties are pinned here and replayed by the JavaScript reference:
/// the strict path is non-lossy and therefore case- and punctuation-sensitive,
/// and the tolerant candidate path lives under a separate domain so its values
/// can never be presented as strict ones. Run with `-vv` to print.
contract IdentityVectorsTest is Test {
    function _strict(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (Id.StableAssetIdentity memory)
    {
        return Id.StableAssetIdentity({
            sellerNamespace: N.namespace("lei"),
            sellerId: N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "213800WAVVOPS85N2205", 20),
            sellerProfile: N.PROFILE_ALNUM_UPPER_FIXED,
            debtorNamespace: N.namespace("lei"),
            debtorId: N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "529900T8BM49AURSDO55", 20),
            debtorProfile: N.PROFILE_ALNUM_UPPER_FIXED,
            invoiceNamespace: N.namespace("seller"),
            invoiceId: N.normalize(N.PROFILE_INVOICE_CASE_SENSITIVE, invoiceNumber, 0),
            invoiceProfile: N.PROFILE_INVOICE_CASE_SENSITIVE,
            tier: Id.IdentityTier.StrictSellerIssued,
            issueDateDays: issueDateDays
        });
    }

    function _candidate(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (Id.StableAssetIdentity memory)
    {
        Id.StableAssetIdentity memory identity = _strict(invoiceNumber, issueDateDays);
        identity.invoiceId = N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, invoiceNumber, 0);
        identity.invoiceProfile = N.PROFILE_INVOICE_CASE_INSENSITIVE;
        identity.tier = Id.IdentityTier.TolerantCandidate;
        return identity;
    }

    function _terms(uint256 faceValueMinor, uint32 dueDateDays)
        private
        pure
        returns (Id.AssetTermsVersion memory)
    {
        return Id.AssetTermsVersion({
            currencyCode: bytes3("USD"),
            faceValueMinor: faceValueMinor,
            amountExponent: 2,
            dueDateDays: dueDateDays,
            paymentScheduleDigest: bytes32(0),
            termsVersion: 1,
            amendmentId: bytes32(0),
            supersedesTermsCommitment: bytes32(0),
            relation: Id.Relation.Original,
            relatedStableAssetId: bytes32(0),
            effectiveFrom: 1_760_000_000
        });
    }

    function testEmitStrictIdentityVectors() public view {
        bytes32 baseline = Id.strictStableAssetId(_strict("INV-2026-0042", 20_500));
        bytes32 reformatted = Id.strictStableAssetId(_strict("inv 2026 0042", 20_500));
        bytes32 otherInvoice = Id.strictStableAssetId(_strict("INV-2026-0043", 20_500));
        bytes32 otherDate = Id.strictStableAssetId(_strict("INV-2026-0042", 20_501));

        console.log("strict-baseline");
        console.logBytes32(baseline);
        console.log("strict-reformatted");
        console.logBytes32(reformatted);
        console.log("strict-other-invoice");
        console.logBytes32(otherInvoice);
        console.log("strict-other-issue-date");
        console.logBytes32(otherDate);

        // The strict path is non-lossy, so a formatting difference is a
        // different identifier. It never silently merges two invoice numbers.
        assertTrue(baseline != reformatted, "strict identity must be non-lossy");
        assertTrue(baseline != otherInvoice);
        assertTrue(baseline != otherDate);
    }

    function testEmitCandidateAliasVectors() public view {
        bytes32 aliasBaseline = Id.candidateAliasId(_candidate("INV-2026-0042", 20_500));
        bytes32 aliasReformatted = Id.candidateAliasId(_candidate("inv 2026 0042", 20_500));
        console.log("candidate-baseline");
        console.logBytes32(aliasBaseline);
        console.log("candidate-reformatted");
        console.logBytes32(aliasReformatted);

        // The tolerant path merges formatting differences. That is its purpose,
        // and it is exactly why it may only suggest reconciliation.
        assertEq(aliasBaseline, aliasReformatted, "candidate path is tolerant");
        // And it lives in a different domain, so it can never be mistaken for a
        // strict identity even when the underlying invoice is the same.
        assertTrue(aliasBaseline != Id.strictStableAssetId(_strict("INV-2026-0042", 20_500)));
    }

    function testTermsChangeDoesNotChangeIdentity() public view {
        Id.StableAssetIdentity memory identity = _strict("INV-2026-0042", 20_500);
        bytes32 stableId = Id.strictStableAssetId(identity);

        bytes32 originalTerms = Id.termsCommitment(stableId, 1, _terms(110_000_000, 20_590));
        bytes32 amendedAmount = Id.termsCommitment(stableId, 1, _terms(120_000_000, 20_590));
        bytes32 amendedDue = Id.termsCommitment(stableId, 1, _terms(110_000_000, 20_620));

        console.log("strictAssetId");
        console.logBytes32(stableId);
        console.log("terms-original");
        console.logBytes32(originalTerms);
        console.log("terms-amended-amount");
        console.logBytes32(amendedAmount);
        console.log("terms-amended-due-date");
        console.logBytes32(amendedDue);

        assertTrue(originalTerms != amendedAmount, "amount must move the terms commitment");
        assertTrue(originalTerms != amendedDue, "due date must move the terms commitment");
        assertEq(stableId, Id.strictStableAssetId(identity));
    }

    function testCommitmentAndSaltVectors() public view {
        bytes32 stableId = Id.strictStableAssetId(_strict("INV-2026-0042", 20_500));
        bytes32 master = keccak256("mordant.test.issuer-master-secret");
        bytes32 salt = Id.deriveSalt(master, stableId, 1, 1);
        bytes32 commitment = Id.assetCommitment(stableId, 3, 1, salt);
        bytes32 aliasCommitment =
            Id.candidateAliasCommitment(Id.candidateAliasId(_candidate("INV-2026-0042", 20_500)), 1, salt);
        console.log("salt");
        console.logBytes32(salt);
        console.log("assetCommitment");
        console.logBytes32(commitment);
        console.log("candidateAliasCommitment");
        console.logBytes32(aliasCommitment);

        assertTrue(commitment != stableId);
        // Separate commitment domains: a candidate commitment can never satisfy
        // a binder that expects an asset commitment.
        assertTrue(commitment != aliasCommitment);
    }
}
