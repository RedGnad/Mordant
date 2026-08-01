import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import { reviewIntent, reviewConsent, reviewSourceAttestation, ROLES } from "./party-signer.mjs";
import { review as reviewResult } from "./match-validator-signer.mjs";

const CHAIN_ID = 10_143;
const GOVERNANCE = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f";
const BINDER = "0xc7183455a4C133Ae270771860664b6B7ec320bB1";
const VERIFIER = "0x5991A2dF15A8F6A256D3Ec51E99254Cd3fb576A9";
const POLICY_ID = keccak256(stringToBytes("policy"));
const RECORD_A = keccak256(stringToBytes("record-a"));
const RECORD_B = keccak256(stringToBytes("record-b"));
const SCOPE_A = keccak256(stringToBytes("scope-a"));
const KEY_A = keccak256(stringToBytes("key-a"));
const SESSION = keccak256(stringToBytes("session"));
const future = () => Math.floor(Date.now() / 1000) + 3_600;

const controllerOptions = {
  role: "controller-a", chainId: CHAIN_ID, governance: GOVERNANCE, binder: BINDER,
  policyId: POLICY_ID, scope: SCOPE_A, governanceRecord: RECORD_A, controllerKeyId: KEY_A,
};

function intent(overrides = {}) {
  return {
    chainId: CHAIN_ID, governanceRegistry: GOVERNANCE, policyId: POLICY_ID, policyVersion: 1,
    governanceRecordA: RECORD_A, governanceRecordB: RECORD_B,
    controllerKeyIdA: KEY_A, controllerKeyIdB: keccak256(stringToBytes("key-b")),
    controllerEpochA: 1, controllerEpochB: 1,
    scopeAuthorizationVersionA: 1, scopeAuthorizationVersionB: 1,
    sourceRecordA: keccak256(stringToBytes("src-a")), sourceRecordB: keccak256(stringToBytes("src-b")),
    issuerKeyId: keccak256(stringToBytes("issuer")), identityEpoch: 1,
    strictAssetCommitmentA: keccak256(stringToBytes("asset")),
    supersedesCandidateSession: `0x${"00".repeat(32)}`,
    candidateAuthorized: false, exactBudget: 1, candidateBudget: 0,
    sessionNonce: 1, expiry: future(), disclosureVersion: 1,
    ...overrides,
  };
}

const intentPayload = (overrides = {}) => ({
  chainId: CHAIN_ID, governance: GOVERNANCE, intent: intent(overrides),
});

test("the four roles are separate processes", () => {
  assert.deepEqual(ROLES, ["controller-a", "controller-b", "issuer", "relayer"]);
});

test("a controller signs an intent only inside its own scope", () => {
  assert.equal(reviewIntent(intentPayload(), controllerOptions), null);
  assert.match(
    reviewIntent({ ...intentPayload(), chainId: 1 }, controllerOptions),
    /chain out of scope/,
  );
  assert.match(
    reviewIntent(intentPayload({ policyId: keccak256(stringToBytes("other")) }), controllerOptions),
    /policy out of scope/,
  );
});

test("a controller refuses an intent naming a governance record it does not hold", () => {
  // This is the swap the runner must not be able to perform silently.
  assert.match(
    reviewIntent(intentPayload({ governanceRecordA: RECORD_B }), controllerOptions),
    /another governance record/,
  );
  // Side B checks its own slot.
  assert.match(
    reviewIntent(intentPayload(), { ...controllerOptions, role: "controller-b", governanceRecord: RECORD_A }),
    /another governance record/,
  );
});

test("a controller refuses to authorize the tolerant candidate path", () => {
  assert.match(
    reviewIntent(intentPayload({ candidateAuthorized: true }), controllerOptions),
    /tolerant candidate path/,
  );
});

test("an expired intent is refused before signing", () => {
  assert.match(
    reviewIntent(intentPayload({ expiry: 1 }), controllerOptions),
    /already expired/,
  );
});

function consentPayload(overrides = {}) {
  return {
    chainId: CHAIN_ID, binder: BINDER, policyId: POLICY_ID, policyVersion: 1,
    sessionCommitment: SESSION, resultCommitment: keccak256(stringToBytes("result")),
    matchCommitment: keccak256(stringToBytes("match")), anchor: BINDER,
    outcome: 1, exactMatchConfirmed: true, candidateMatchSuggested: false,
    consent: {
      scopeCommitment: SCOPE_A, governanceRecord: RECORD_A, disclosureVersion: 1,
      validUntil: future(), nonce: 7,
    },
    authorization: { controllerKeyId: KEY_A, controllerEpoch: 1, authorizationVersion: 1 },
    ...overrides,
  };
}

test("a controller consents only to a confirmed exact match", () => {
  assert.equal(reviewConsent(consentPayload(), controllerOptions), null);
  assert.match(
    reviewConsent(consentPayload({ outcome: 2 }), controllerOptions),
    /non exact-match result/,
  );
  assert.match(
    reviewConsent(consentPayload({ exactMatchConfirmed: false }), controllerOptions),
    /non exact-match result/,
  );
  assert.match(
    reviewConsent(consentPayload({ candidateMatchSuggested: true }), controllerOptions),
    /candidate result/,
  );
});

test("a consent cannot be made under a substituted authority", () => {
  assert.match(
    reviewConsent(
      consentPayload({ consent: { ...consentPayload().consent, governanceRecord: RECORD_B } }),
      controllerOptions,
    ),
    /another governance record/,
  );
  assert.match(
    reviewConsent(
      consentPayload({ authorization: { controllerKeyId: keccak256(stringToBytes("other")), controllerEpoch: 1, authorizationVersion: 1 } }),
      controllerOptions,
    ),
    /another controller key/,
  );
});

test("a consent needs a live one-shot nonce and the right binder", () => {
  assert.match(
    reviewConsent(consentPayload({ consent: { ...consentPayload().consent, nonce: 0 } }), controllerOptions),
    /nonce required/,
  );
  assert.match(
    reviewConsent(consentPayload({ binder: VERIFIER }), controllerOptions),
    /binder out of scope/,
  );
});

test("the issuer attests only its own key and the frozen schemes", () => {
  const issuerOptions = { role: "issuer", chainId: CHAIN_ID, issuerKeyId: KEY_A };
  const payload = (overrides = {}) => ({
    chainId: CHAIN_ID, verifyingContract: GOVERNANCE,
    attestation: {
      chainId: CHAIN_ID, factory: GOVERNANCE, issuerKeyId: KEY_A,
      identitySchemeVersion: 3, termsSchemeVersion: 1, validUntil: future(), ...overrides,
    },
  });
  assert.equal(reviewSourceAttestation(payload(), issuerOptions), null);
  assert.match(
    reviewSourceAttestation(payload({ issuerKeyId: RECORD_B }), issuerOptions),
    /another issuer key/,
  );
  assert.match(
    reviewSourceAttestation(payload({ identitySchemeVersion: 2 }), issuerOptions),
    /unsupported identity or terms scheme/,
  );
});

/* ------------------------------------------------------------ V4 validators */

const validatorOptions = {
  chainId: CHAIN_ID, verifier: VERIFIER, binder: BINDER, policyId: POLICY_ID, governance: GOVERNANCE,
};

function envelopePayload(resultOverrides = {}, envelopeOverrides = {}) {
  return {
    chainId: CHAIN_ID, verifier: VERIFIER, validatorSetId: keccak256(stringToBytes("set")),
    envelope: {
      chainId: CHAIN_ID, binder: BINDER, policyId: POLICY_ID, policyVersion: 1,
      sessionCommitment: SESSION, nonce: 1, validUntil: future(),
      resultCommitment: keccak256(stringToBytes("core")),
      result: {
        sessionId: SESSION, scopeCommitmentA: SCOPE_A, scopeCommitmentB: RECORD_B,
        inputCommitmentA: keccak256(stringToBytes("in-a")),
        inputCommitmentB: keccak256(stringToBytes("in-b")),
        outcome: 1, exactMatchConfirmed: true, candidateMatchSuggested: false,
        conflictConfirmed: true, matchCommitment: keccak256(stringToBytes("match")),
        anchorCount: 2, providerProofCommitment: keccak256(stringToBytes("proof")),
        ...resultOverrides,
      },
      ...envelopeOverrides,
    },
  };
}

test("a validator attests only a coherent exact match", () => {
  assert.equal(reviewResult(envelopePayload(), validatorOptions), null);
  assert.match(reviewResult(envelopePayload({ outcome: 2 }), validatorOptions), /non exact-match/);
  assert.match(reviewResult(envelopePayload({ exactMatchConfirmed: false }), validatorOptions), /unconfirmed match/);
  assert.match(reviewResult(envelopePayload({ candidateMatchSuggested: true }), validatorOptions), /candidate result/);
  assert.match(reviewResult(envelopePayload({ conflictConfirmed: false }), validatorOptions), /non-conflict/);
  assert.match(reviewResult(envelopePayload({ anchorCount: 1 }), validatorOptions), /anchor count/);
});

test("a validator refuses a result detached from its session commitment", () => {
  assert.match(
    reviewResult(envelopePayload({ sessionId: keccak256(stringToBytes("other")) }), validatorOptions),
    /not bound to its session commitment/,
  );
});

test("a validator refuses a self match and an empty provider proof", () => {
  const same = keccak256(stringToBytes("same"));
  assert.match(
    reviewResult(envelopePayload({ inputCommitmentA: same, inputCommitmentB: same }), validatorOptions),
    /self match/,
  );
  assert.match(
    reviewResult(envelopePayload({ providerProofCommitment: `0x${"00".repeat(32)}` }), validatorOptions),
    /provider proof/,
  );
});

test("a validator stays inside its verifier, binder and policy", () => {
  assert.match(reviewResult({ ...envelopePayload(), verifier: BINDER }, validatorOptions), /verifier out of scope/);
  assert.match(reviewResult(envelopePayload({}, { binder: VERIFIER }), validatorOptions), /binder out of scope/);
  assert.match(
    reviewResult(envelopePayload({}, { policyId: keccak256(stringToBytes("other")) }), validatorOptions),
    /policy out of scope/,
  );
  assert.match(reviewResult(envelopePayload({}, { validUntil: 1 }), validatorOptions), /already expired/);
});
