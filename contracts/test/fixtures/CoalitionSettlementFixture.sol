// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Generated from a real 2-of-3 coalition release of the Go spine. Do not edit by hand.
///
/// Regenerate with:
///   MORDANT_COALITION_FIXTURE_OUT=<abs path to test/fixtures/coalition-settlement.json> ///     go test -run TestEmitCoalitionSettlementFixture ./governedfhe/
library CoalitionSettlementFixture {
    bytes32 internal constant FHE_CASE_ID = 0xb11cd43ae71072e2e03bdc6eaf63afc34dfd39e5cfd3e4463af86c3f1a240f62;
    bytes32 internal constant CASE_BINDING_DIGEST = 0xa264f827a9056d9a34c3d1cc240a907f018fa8d4e6f91f88f2b33052d3162e04;
    bytes32 internal constant ASSET_IDENTITY_DIGEST = 0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c;
    bytes32 internal constant COALITION_RESULT_DIGEST = 0x292c7c49077f76d7fb832da5845cf19bb1c57f766f77183e9485f80500c36fec;
    bytes32 internal constant RELEASE_TRANSCRIPT = 0x01538576ae35ab26d9ba0a1d364167952df0b9577033e465476956c0bc97b6c5;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_A = 0xd8101b1261b686db17e14c3885ffee002a18dea944a5c16ecef4be4c98d45df4;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_B = 0x1a9f8f7f3a5fe3956257432f6c9309ee157294a10336f4f070dfc18e61d08dd9;
    bytes32 internal constant COALITION_AUTHORITY_ID = 0xc2fc334829cbd5f8c15b45b93548cc628e32cc8bdc433ea718baa70fa3a40a65;
    bytes32 internal constant RELEASE_MODE = 0x3e9aa502ff816920edf9c2ccd76b26b04c99aa481ff8977d681068163943ff11;
    bytes32 internal constant CIRCUIT_DIGEST = 0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e;
    bytes32 internal constant PARAMETER_FINGERPRINT = 0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6;
    uint16 internal constant SERVING_QUORUM = 2;
    bool internal constant SAME_ECONOMIC_ASSET = true;
    bool internal constant POLICY_CONFLICT = true;
}
