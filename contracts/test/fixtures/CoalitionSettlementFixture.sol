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
        0xafd0da308701c48d674ec91008b078ec96158d64b69e2da5e5f8a68aeb861f00;
    bytes32 internal constant ASSET_IDENTITY_DIGEST =
        0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c;
    bytes32 internal constant COALITION_RESULT_DIGEST =
        0xa966c86106d165b65ce2c967b8ea529731bbd0424ceb1817d0898b1c32f8203a;
    bytes32 internal constant RELEASE_TRANSCRIPT =
        0x068ac5752f10bcc7d4c1b4155ca837a603a7cc5ed82aa272681d863d5d520d84;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_A =
        0x0631043b143864a7efaafe5dda0daedd725d9459a752bb7ace07322e68b7f489;
    bytes32 internal constant PARTICIPANT_ARTIFACT_DIGEST_B =
        0x7dd15145ef8f5387d471b09176f1745271f8cfa3ccfa5b55698a32dc7eeba4ca;
    bytes32 internal constant COALITION_AUTHORITY_ID =
        0x836c3f867326538e22e17f69563091b97159f7c15023055390da6d4629c65cfc;
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
