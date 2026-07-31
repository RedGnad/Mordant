// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {MordantAssetIdentity} from "../src/identity/MordantAssetIdentity.sol";
import {MordantNormalization as N} from "../src/identity/MordantNormalization.sol";

/// @notice Normative cross-language vectors for scheme 2.
/// @dev Two platforms that never speak must derive the same stable identity from
/// the same invoice, and must derive DIFFERENT terms commitments when the terms
/// differ. Both properties are pinned here and replayed by the JavaScript
/// reference. Run with `-vv` to print.
contract IdentityVectorsTest is Test {
    function _identity(string memory invoiceNumber, uint32 issueDateDays)
        private
        pure
        returns (MordantAssetIdentity.StableAssetIdentity memory)
    {
        return MordantAssetIdentity.StableAssetIdentity({
            sellerNamespace: N.namespace("lei"),
            sellerId: N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "213800WAVVOPS85N2205", 20),
            debtorNamespace: N.namespace("lei"),
            debtorId: N.normalize(N.PROFILE_ALNUM_UPPER_FIXED, "529900T8BM49AURSDO55", 20),
            invoiceNamespace: N.namespace("seller"),
            invoiceId: N.normalize(N.PROFILE_INVOICE_CASE_INSENSITIVE, invoiceNumber, 0),
            issueDateDays: issueDateDays
        });
    }

    function _terms(uint256 faceValueMinor, uint32 dueDateDays)
        private
        pure
        returns (MordantAssetIdentity.AssetTermsVersion memory)
    {
        return MordantAssetIdentity.AssetTermsVersion({
            currencyCode: bytes3("USD"),
            faceValueMinor: faceValueMinor,
            amountExponent: 2,
            dueDateDays: dueDateDays,
            paymentScheduleDigest: bytes32(0),
            termsVersion: 1,
            amendmentId: bytes32(0),
            supersedesTermsCommitment: bytes32(0),
            relation: MordantAssetIdentity.Relation.Original,
            relatedStableAssetId: bytes32(0),
            effectiveFrom: 1_760_000_000
        });
    }

    function testEmitStableIdentityVectors() public view {
        bytes32 baseline = MordantAssetIdentity.stableAssetId(_identity("INV-2026-0042", 20_500));
        bytes32 equivalent = MordantAssetIdentity.stableAssetId(_identity("inv 2026 0042", 20_500));
        bytes32 otherInvoice = MordantAssetIdentity.stableAssetId(_identity("INV-2026-0043", 20_500));
        bytes32 otherDate = MordantAssetIdentity.stableAssetId(_identity("INV-2026-0042", 20_501));

        console.log("stable-baseline");
        console.logBytes32(baseline);
        console.log("stable-normalization-equivalent");
        console.logBytes32(equivalent);
        console.log("stable-other-invoice");
        console.logBytes32(otherInvoice);
        console.log("stable-other-issue-date");
        console.logBytes32(otherDate);

        assertEq(baseline, equivalent, "formatting must not change identity");
        assertTrue(baseline != otherInvoice);
        assertTrue(baseline != otherDate);
    }

    /// The property scheme 1 got wrong: amount and due date must move the terms
    /// commitment and leave the stable identity alone.
    function testTermsChangeDoesNotChangeIdentity() public view {
        MordantAssetIdentity.StableAssetIdentity memory identity = _identity("INV-2026-0042", 20_500);
        bytes32 stableId = MordantAssetIdentity.stableAssetId(identity);

        bytes32 originalTerms =
            MordantAssetIdentity.termsCommitment(stableId, 1, _terms(110_000_000, 20_590));
        bytes32 amendedAmount =
            MordantAssetIdentity.termsCommitment(stableId, 1, _terms(120_000_000, 20_590));
        bytes32 amendedDue =
            MordantAssetIdentity.termsCommitment(stableId, 1, _terms(110_000_000, 20_620));

        console.log("stableAssetId");
        console.logBytes32(stableId);
        console.log("terms-original");
        console.logBytes32(originalTerms);
        console.log("terms-amended-amount");
        console.logBytes32(amendedAmount);
        console.log("terms-amended-due-date");
        console.logBytes32(amendedDue);

        assertTrue(originalTerms != amendedAmount, "amount must move the terms commitment");
        assertTrue(originalTerms != amendedDue, "due date must move the terms commitment");
        // And the identity is untouched by both.
        assertEq(stableId, MordantAssetIdentity.stableAssetId(identity));
    }

    function testCommitmentAndSaltVectors() public view {
        bytes32 stableId = MordantAssetIdentity.stableAssetId(_identity("INV-2026-0042", 20_500));
        bytes32 master = keccak256("mordant.test.issuer-master-secret");
        bytes32 salt = MordantAssetIdentity.deriveSalt(master, stableId, 1, 1);
        bytes32 commitment = MordantAssetIdentity.assetCommitment(stableId, 2, 1, salt);
        console.log("salt");
        console.logBytes32(salt);
        console.log("assetCommitment");
        console.logBytes32(commitment);
        assertTrue(commitment != stableId);
    }
}
