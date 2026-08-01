import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import {
  intentHash, intentDigest, signatureBundleDigest, sessionCommitment,
  consentDigest, resultCoreCommitment, resultDigest, attestationDigest,
  assertCanonicalSignature,
} from "./v4-digests.mjs";

// Every expected value below is emitted by contracts/test/V4DigestVectors.t.sol
// from the frozen V4 contracts. If a mirror drifts from the Solidity byte
// layout, one of these fails before any gas is spent.
const CHAIN_ID = 10_143;
const GOVERNANCE = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f";
const VERIFIER = "0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9";
const BINDER = "0xc7183455a4C133Ae270771860664b6B7ec320bB1";
const POLICY_ID = keccak256(stringToBytes("mordant.private-match.policy/v4"));
const SCOPE_A = keccak256(stringToBytes("vector-scope-a"));
const SCOPE_B = keccak256(stringToBytes("vector-scope-b"));
const SESSION = keccak256(stringToBytes("vector-session-commitment"));
const k = (label) => keccak256(stringToBytes(label));

const INTENT = {
  chainId: CHAIN_ID,
  governanceRegistry: GOVERNANCE,
  policyId: POLICY_ID,
  policyVersion: 1,
  governanceRecordA: k("vector-record-a"),
  governanceRecordB: k("vector-record-b"),
  controllerKeyIdA: k("vector-key-a"),
  controllerKeyIdB: k("vector-key-b"),
  controllerEpochA: 1,
  controllerEpochB: 2,
  scopeAuthorizationVersionA: 3,
  scopeAuthorizationVersionB: 4,
  sourceRecordA: k("vector-source-a"),
  sourceRecordB: k("vector-source-b"),
  issuerKeyId: k("vector-issuer"),
  identityEpoch: 5,
  strictAssetCommitmentA: k("vector-asset"),
  supersedesCandidateSession: k("vector-supersedes"),
  candidateAuthorized: false,
  exactBudget: 1,
  candidateBudget: 0,
  sessionNonce: 42,
  expiry: 1_900_000_000,
  disclosureVersion: 1,
};

const SIGNATURES = { controllerA: "0x11", controllerB: "0x22", issuer: "0x33" };

const ENVELOPE = {
  chainId: CHAIN_ID,
  binder: BINDER,
  policyId: POLICY_ID,
  policyVersion: 1,
  sessionCommitment: SESSION,
  nonce: 7,
  validUntil: 1_900_000_000,
  result: {
    sessionId: SESSION,
    scopeCommitmentA: SCOPE_A,
    scopeCommitmentB: SCOPE_B,
    inputCommitmentA: k("vector-input-a"),
    inputCommitmentB: k("vector-input-b"),
    outcome: 1,
    conflictConfirmed: true,
    matchCommitment: k("vector-match"),
    anchorCount: 2,
    providerProofCommitment: k("vector-provider-proof"),
  },
};

const VALIDATOR_SET_ID = "0x1328a50ed3a905a5c5cbb7549ddbfad81c1947c788b348a4be1102acba4eab9e";

test("the intent hash mirrors the frozen registry", () => {
  assert.equal(
    intentHash(INTENT),
    "0xb35378f88ae1b291f8fd2ea35b9f87cf955522ff95d7c0110e81bcd0db8f5002",
  );
  assert.equal(
    intentDigest(INTENT, CHAIN_ID, GOVERNANCE),
    "0x847cd0d66df47501eff97c349435d3502c1dc1c7fa9a9f71e31bbfa5f4a170dc",
  );
});

test("the signature bundle and session commitment mirror the frozen registry", () => {
  assert.equal(
    signatureBundleDigest(SIGNATURES),
    "0xd4cc601182fc9fccd2f6c79bf2d4284e259da247f3ac18c3e400d01bf5c6abf1",
  );
  assert.equal(
    sessionCommitment({
      intent: INTENT,
      signatures: SIGNATURES,
      salt: k("vector-salt"),
      chainId: CHAIN_ID,
      governance: GOVERNANCE,
    }),
    "0x6affcc5733259b6d158cd5aa6cba092059f368ccbbdd89654299a20891ecfd73",
  );
});

test("one changed signature changes the commitment", () => {
  const base = sessionCommitment({
    intent: INTENT, signatures: SIGNATURES, salt: k("vector-salt"),
    chainId: CHAIN_ID, governance: GOVERNANCE,
  });
  for (const field of ["controllerA", "controllerB", "issuer"]) {
    assert.notEqual(
      sessionCommitment({
        intent: INTENT,
        signatures: { ...SIGNATURES, [field]: "0x44" },
        salt: k("vector-salt"),
        chainId: CHAIN_ID,
        governance: GOVERNANCE,
      }),
      base,
      `${field} must be bound into the commitment`,
    );
  }
  // Swapping two signatures is a different session, not the same one reordered.
  assert.notEqual(
    sessionCommitment({
      intent: INTENT,
      signatures: { controllerA: SIGNATURES.controllerB, controllerB: SIGNATURES.controllerA, issuer: SIGNATURES.issuer },
      salt: k("vector-salt"), chainId: CHAIN_ID, governance: GOVERNANCE,
    }),
    base,
  );
});

test("the V4 result digests mirror the frozen verifier", () => {
  assert.equal(
    resultCoreCommitment(ENVELOPE),
    "0xb28adf706ab41a3f731ef437fd09b8cb89797058446cc2fd7095f57ce0e2dee3",
  );
  const digest = resultDigest(ENVELOPE, CHAIN_ID, VERIFIER);
  assert.equal(digest, "0x995a99e0aca02ca57d25c1bd631b6fd503b8286949528411636016d85d8084ee");
  assert.equal(
    attestationDigest({
      validatorSetId: VALIDATOR_SET_ID, resultHash: digest, chainId: CHAIN_ID, verifier: VERIFIER,
    }),
    "0x5f49fdaaaf68ba54c7ed011ddd870244d4b7a6106ca0e5cfcbf2816fbf4f89d8",
  );
});

test("the consent digest mirrors the frozen binder", () => {
  assert.equal(
    consentDigest({
      chainId: CHAIN_ID,
      binder: BINDER,
      policyId: POLICY_ID,
      policyVersion: 1,
      sessionCommitment: SESSION,
      resultCommitment: k("vector-result-commitment"),
      matchCommitment: k("vector-match"),
      anchor: "0x0000000000000000000000000000000000DEc0DE",
      consent: {
        scopeCommitment: SCOPE_A,
        governanceRecord: "0x800387f0d89db8ba1404de28f091006c75df34b46fcb58fedbdd0c3872d4d59b",
        disclosureVersion: 1,
        validUntil: 1_900_000_000,
        nonce: 99,
      },
      authorization: {
        controllerKeyId: k("vector-key-a"),
        controllerEpoch: 1,
        authorizationVersion: 1,
      },
    }),
    "0xa9250b85ccd7a63524ca5b11306f44256f999cb6e103f1e13c54df7a928bbc0f",
  );
});

test("non-canonical signatures are refused before they can be committed", () => {
  const low = `0x${"11".repeat(32)}${"22".repeat(32)}1b`;
  assert.equal(assertCanonicalSignature(low, "ok"), true);
  // s above the half order is the malleable counterpart of a valid signature.
  const highS = `0x${"11".repeat(32)}${"ff".repeat(32)}1b`;
  assert.throws(() => assertCanonicalSignature(highS, "a"), /SIGNATURE_NOT_LOW_S:a/);
  assert.throws(() => assertCanonicalSignature(`0x${"11".repeat(32)}${"22".repeat(32)}00`, "b"), /SIGNATURE_BAD_V:b/);
  assert.throws(() => assertCanonicalSignature("0x1234", "c"), /SIGNATURE_MALFORMED:c/);
  assert.throws(() => assertCanonicalSignature(`0x${"00".repeat(64)}1b`, "d"), /SIGNATURE_NOT_LOW_S:d/);
});
