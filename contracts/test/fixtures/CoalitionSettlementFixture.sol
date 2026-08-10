// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Generated from a real 2-of-3 coalition release of the Go spine. Do not edit by hand.
///
/// Regenerate with:
///   MORDANT_COALITION_FIXTURE_OUT=<abs path to test/fixtures/coalition-settlement.json> ///     go test -run TestEmitCoalitionSettlementFixture ./governedfhe/
library CoalitionSettlementFixture {
    bytes32 internal constant FHE_CASE_ID =
        0xb11cd43ae71072e2e03bdc6eaf63afc34dfd39e5cfd3e4463af86c3f1a240f62;
    bytes32 internal constant CASE_BINDING_DIGEST =
        0x52ce837ddc12b06579f49cad1ec68498aa99d8e8b6b2aaa07183b36626fb0e15;
    bytes32 internal constant ASSET_IDENTITY_DIGEST =
        0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c;
    bytes32 internal constant COALITION_RESULT_DIGEST =
        0xd23fd3887e93ffd73801d8c7caddb851a135591647a48d663f768bd91ef0b126;
    bytes32 internal constant RELEASE_TRANSCRIPT =
        0xee83158d1fa65993ca7cfca9271ff695c24c2183bba66331eb995ccfb6891cb4;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_A =
        0x0803f02de1385d7e14a04a2f5dcf364bb20fe19d1c6f3d24272ce912d88d49cf;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_B =
        0x6bf16e3acef1e25812abe241ba77864b34796924289c4103b3bf2916408dc673;
    bytes32 internal constant COALITION_AUTHORITY_ID =
        0xebebb8eeca335ab615de36bfcd90ffe8e8abd7821e10198ff30836f9f67e87ec;
    bytes32 internal constant RELEASE_MODE =
        0x3e9aa502ff816920edf9c2ccd76b26b04c99aa481ff8977d681068163943ff11;
    bytes32 internal constant CIRCUIT_DIGEST =
        0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e;
    bytes32 internal constant PARAMETER_FINGERPRINT =
        0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6;
    uint16 internal constant SERVING_QUORUM = 2;
    bool internal constant SAME_ECONOMIC_ASSET = true;
    bool internal constant POLICY_CONFLICT = true;
}
