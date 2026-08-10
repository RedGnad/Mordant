// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Generated from a real 2-of-3 coalition release of the Go spine. Do not edit by hand.
///
/// Regenerate with:
///   MORDANT_COALITION_FIXTURE_OUT=<abs path to test/fixtures/coalition-settlement.json> ///     go test -run TestEmitCoalitionSettlementFixture ./governedfhe/
library CoalitionSettlementFixture {
    bytes32 internal constant FHE_CASE_ID = 0xb11cd43ae71072e2e03bdc6eaf63afc34dfd39e5cfd3e4463af86c3f1a240f62;
    bytes32 internal constant CASE_BINDING_DIGEST = 0x3d2c9860bf6f67408b79bbe95d59d0c7a75eb1da2d9c048863b3c5974d9695ce;
    bytes32 internal constant ASSET_IDENTITY_DIGEST = 0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c;
    bytes32 internal constant COALITION_RESULT_DIGEST = 0x4a66528c51feb72331bb1a9599c43a3476623995f7c542f5a3ba476116da1e02;
    bytes32 internal constant RELEASE_TRANSCRIPT = 0x55a7307d80d98276b02211a28f4eb099a075b9b6987aa55b6f2d10234d558c79;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_A = 0x5eb150540e2d21d42748075e18a1f104a075a0a4b83f002348eccac7a62c6429;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_B = 0xfa956064d8e15ce5ffbeb1299a9c2c0ea311fc4c61eef0c20ab1486e1b3ec789;
    bytes32 internal constant COALITION_AUTHORITY_ID = 0x0316321eb90f06f557b8d0326f309c5ab3aeedad3844fbc7e1965d22a8dbb8b3;
    bytes32 internal constant RELEASE_MODE = 0x3e9aa502ff816920edf9c2ccd76b26b04c99aa481ff8977d681068163943ff11;
    bytes32 internal constant CIRCUIT_DIGEST = 0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e;
    bytes32 internal constant PARAMETER_FINGERPRINT = 0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6;
    uint16 internal constant SERVING_QUORUM = 2;
    bool internal constant SAME_ECONOMIC_ASSET = true;
    bool internal constant POLICY_CONFLICT = true;
}
