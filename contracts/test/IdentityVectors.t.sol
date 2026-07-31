// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {MordantAssetIdentity} from "../src/identity/MordantAssetIdentity.sol";

/// @notice Emits the normative cross-language test vectors.
/// @dev Two platforms that never speak must derive the same 256-bit identity
/// from the same invoice. That only holds if every implementation agrees
/// byte-for-byte, so the vectors are generated here and replayed by the Go and
/// JavaScript implementations. Run with `-vv` to print them.
contract IdentityVectorsTest is Test {
    struct Vector {
        string label;
        string debtorNamespace;
        string debtorId;
        string sellerNamespace;
        string sellerId;
        string invoiceNumber;
        bytes3 currencyCode;
        uint256 amountMinor;
        uint8 amountExponent;
        uint32 issueDateDays;
        uint32 dueDateDays;
    }

    function _vectors() private pure returns (Vector[] memory vectors) {
        vectors = new Vector[](4);
        vectors[0] = Vector({
            label: "baseline",
            debtorNamespace: "lei",
            debtorId: "529900T8BM49AURSDO55",
            sellerNamespace: "lei",
            sellerId: "213800WAVVOPS85N2205",
            invoiceNumber: "INV-2026-0042",
            currencyCode: bytes3("USD"),
            amountMinor: 110_000_000,
            amountExponent: 2,
            issueDateDays: 20_500,
            dueDateDays: 20_590
        });
        // Same economic asset, written the way a different platform would.
        vectors[1] = Vector({
            label: "normalization-equivalent",
            debtorNamespace: "LEI",
            debtorId: "529900t8bm49aursdo55",
            sellerNamespace: "Lei",
            sellerId: "213800-wavvops85n2205",
            invoiceNumber: "inv 2026 0042",
            currencyCode: bytes3("USD"),
            amountMinor: 110_000_000,
            amountExponent: 2,
            issueDateDays: 20_500,
            dueDateDays: 20_590
        });
        // Null due date is a permitted absence.
        vectors[2] = Vector({
            label: "no-due-date",
            debtorNamespace: "duns",
            debtorId: "150483782",
            sellerNamespace: "vat",
            sellerId: "FR40303265045",
            invoiceNumber: "2026/Q1/8891",
            currencyCode: bytes3("EUR"),
            amountMinor: 4_250_00,
            amountExponent: 2,
            issueDateDays: 20_610,
            dueDateDays: 0
        });
        // Zero-decimal currency.
        vectors[3] = Vector({
            label: "zero-decimal-currency",
            debtorNamespace: "lei",
            debtorId: "353800A3D5UNTV6H2Y19",
            sellerNamespace: "gln",
            sellerId: "4012345000009",
            invoiceNumber: "A-77",
            currencyCode: bytes3("JPY"),
            amountMinor: 1_250_000,
            amountExponent: 0,
            issueDateDays: 20_701,
            dueDateDays: 20_731
        });
    }

    function _assetId(Vector memory vector) private pure returns (bytes32) {
        return MordantAssetIdentity.assetId(
            MordantAssetIdentity.AssetIdentity({
                debtorNamespace: MordantAssetIdentity.normalizeNamespace(vector.debtorNamespace),
                debtorId: MordantAssetIdentity.normalizeAlphanumeric(vector.debtorId),
                sellerNamespace: MordantAssetIdentity.normalizeNamespace(vector.sellerNamespace),
                sellerId: MordantAssetIdentity.normalizeAlphanumeric(vector.sellerId),
                invoiceNumber: MordantAssetIdentity.normalizeAlphanumeric(vector.invoiceNumber),
                currencyCode: vector.currencyCode,
                amountMinor: vector.amountMinor,
                amountExponent: vector.amountExponent,
                issueDateDays: vector.issueDateDays,
                dueDateDays: vector.dueDateDays
            })
        );
    }

    function testEmitCanonicalVectors() public view {
        Vector[] memory vectors = _vectors();
        for (uint256 i; i < vectors.length; ++i) {
            bytes32 id = _assetId(vectors[i]);
            console.log(vectors[i].label);
            console.logBytes32(id);
        }
        // Vectors 0 and 1 are the same economic asset expressed differently.
        assertEq(_assetId(vectors[0]), _assetId(vectors[1]), "normalization must converge");
        // Every other pair is distinct.
        assertTrue(_assetId(vectors[0]) != _assetId(vectors[2]));
        assertTrue(_assetId(vectors[0]) != _assetId(vectors[3]));
        assertTrue(_assetId(vectors[2]) != _assetId(vectors[3]));
    }

    function testCommitmentAndSaltVectors() public view {
        bytes32 id = _assetId(_vectors()[0]);
        bytes32 master = keccak256("mordant.test.issuer-master-secret");
        bytes32 salt = MordantAssetIdentity.deriveSalt(master, id, 1, 1);
        bytes32 commitment = MordantAssetIdentity.assetCommitment(id, 1, 1, salt);
        console.log("assetId");
        console.logBytes32(id);
        console.log("salt");
        console.logBytes32(salt);
        console.log("assetCommitment");
        console.logBytes32(commitment);
        assertTrue(commitment != id, "commitment must not equal the identity");
    }
}
