import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import {
  BilateralSession, runSession, requireComparable, interpret,
  boundCandidateAliasCommitment, enrollmentBinding, evaluatorRequest, Outcome, ProtocolError,
} from "./session-protocol.mjs";
import { IdentityTier, Profile, namespace, normalize } from "./asset-identity.mjs";

function identity(overrides = {}) {
  return {
    sellerNamespace: namespace("lei"),
    sellerProfile: Profile.ALNUM_UPPER_FIXED,
    debtorNamespace: namespace("lei"),
    debtorProfile: Profile.ALNUM_UPPER_FIXED,
    invoiceNamespace: namespace("seller"),
    invoiceProfile: Profile.INVOICE_CASE_SENSITIVE,
    tier: IdentityTier.StrictSellerIssued,
    ...overrides,
  };
}

const SCOPE_A = keccak256(stringToBytes("scope-a"));
const SCOPE_B = keccak256(stringToBytes("scope-b"));
const COMMITTED_AT = 1_000_000;
const SESSION_COMMITMENT = keccak256(stringToBytes("session-commitment-1"));

function record(scopeCommitment, overrides = {}) {
  return {
    recordDigest: keccak256(stringToBytes(`record-${scopeCommitment}`)),
    controller: "0x000000000000000000000000000000000000c0a1",
    controllerKeyId: keccak256(stringToBytes(`key-${scopeCommitment}`)),
    organizationId: keccak256(stringToBytes(`org-${scopeCommitment}`)),
    controllerEpoch: 1,
    authorizationVersion: 1,
    scopeCommitment,
    validFrom: COMMITTED_AT - 3600,
    ...overrides,
  };
}

function governance(overrides = {}) {
  return {
    sessionCommitment: SESSION_COMMITMENT,
    committedAt: COMMITTED_AT,
    initiationSignatureA: "0xaa",
    initiationSignatureB: "0xbb",
    candidateAuthorized: true,
    recordA: record(SCOPE_A),
    recordB: record(SCOPE_B),
    ...overrides,
  };
}

function session(overrides = {}) {
  return new BilateralSession({
    sessionId: SESSION_COMMITMENT,
    scopeA: SCOPE_A,
    scopeB: SCOPE_B,
    budget: 4,
    governance: governance(),
    ...overrides,
  });
}

const yes = () => true;
const no = () => false;
const never = () => { throw new Error("FHE_MUST_NOT_RUN"); };

test("an exact match is the only bindable outcome", () => {
  const result = runSession({
    session: session(), identityA: identity(), identityB: identity(),
    evaluateExact: yes, evaluateCandidate: never,
  });
  assert.equal(result.outcome, Outcome.EXACT_MATCH);
  assert.equal(result.bindable, true);
  assert.equal(interpret(result.outcome).publiclySubmittable, true);
});

test("candidate matching does not run merely because exact equality failed", () => {
  const active = session(); // candidate not authorized by either party
  const result = runSession({
    session: active, identityA: identity(), identityB: identity(),
    evaluateExact: no,
    // If the tolerant path were an automatic fallback this would throw.
    evaluateCandidate: never,
  });
  assert.equal(result.outcome, Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES);
  assert.equal(result.bindable, false);
  assert.equal(active.spent, 1, "only the exact query was paid for");
});

test("one-sided authorization is not authorization", () => {
  for (const flags of [
    { candidateAuthorizedByA: true, candidateAuthorizedByB: false },
    { candidateAuthorizedByA: false, candidateAuthorizedByB: true },
  ]) {
    const active = session(flags);
    assert.equal(active.candidateAuthorized, false);
    const result = runSession({
      session: active, identityA: identity(), identityB: identity(),
      evaluateExact: no, evaluateCandidate: never,
    });
    assert.equal(result.outcome, Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES);
  }
});

test("bilaterally authorized candidate matching runs and consumes budget", () => {
  const active = session({ candidateAuthorizedByA: true, candidateAuthorizedByB: true });
  const result = runSession({
    session: active, identityA: identity(), identityB: identity(),
    evaluateExact: no, evaluateCandidate: yes,
  });
  assert.equal(result.outcome, Outcome.RECONCILIATION_REQUIRED);
  assert.equal(result.bindable, false);
  // Two queries were run and two were paid for.
  assert.equal(active.spent, 2);
});

test("candidate matching outside the budget is refused", () => {
  const active = session({ budget: 1, candidateAuthorizedByA: true, candidateAuthorizedByB: true });
  assert.throws(
    () => runSession({
      session: active, identityA: identity(), identityB: identity(),
      evaluateExact: no, evaluateCandidate: yes,
    }),
    new RegExp(ProtocolError.BUDGET_EXHAUSTED),
  );
});

test("RegistryDocument versus StrictSellerIssued is not comparable and runs no FHE", () => {
  const active = session({ candidateAuthorizedByA: true, candidateAuthorizedByB: true });
  const result = runSession({
    session: active,
    identityA: identity(),
    identityB: identity({ tier: IdentityTier.RegistryDocument, invoiceNamespace: namespace("sdi") }),
    // Neither evaluator may be called: NOT_COMPARABLE performs no evaluation.
    evaluateExact: never, evaluateCandidate: never,
  });
  assert.equal(result.outcome, Outcome.NOT_COMPARABLE);
  assert.equal(result.evaluated, false);
  assert.match(result.protocolError, /IDENTITY_AUTHORITY_MISMATCH/);
  assert.equal(active.spent, 0, "an incomparable pair costs no budget");
});

test("a tolerant alias can never bridge authority tiers", () => {
  // Even with candidate matching fully authorized, a cross-tier pair stops at
  // the comparability gate and never reaches the tolerant evaluator.
  const active = session({ candidateAuthorizedByA: true, candidateAuthorizedByB: true });
  const result = runSession({
    session: active,
    identityA: identity({ tier: IdentityTier.RegistryDocument }),
    identityB: identity(),
    evaluateExact: never, evaluateCandidate: never,
  });
  assert.equal(result.outcome, Outcome.NOT_COMPARABLE);
});

test("namespace, profile and scheme mismatches are explicit protocol errors", () => {
  assert.throws(
    () => requireComparable(identity(), identity({ debtorNamespace: namespace("duns") })),
    /IDENTITY_PROFILE_MISMATCH:debtorNamespace/,
  );
  assert.throws(
    () => requireComparable(identity(), identity({ invoiceProfile: Profile.INVOICE_CASE_INSENSITIVE })),
    /IDENTITY_PROFILE_MISMATCH:invoiceProfile/,
  );
  assert.throws(
    () => requireComparable(identity(), { ...identity(), schemeVersion: 99 }),
    /IDENTITY_SCHEME_MISMATCH/,
  );
  assert.equal(requireComparable(identity(), identity()), true);
});

test("NO_MATCH is scoped and is never market completeness", () => {
  const meaning = interpret(Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES);
  assert.equal(meaning.bindable, false);
  assert.equal(meaning.publiclySubmittable, false);
  assert.match(meaning.meaning, /submitted in this session/);
  assert.deepEqual(meaning.notEvidenceOf, [
    "market completeness",
    "the absence of another pledge",
    "that the receivable is unencumbered elsewhere",
  ]);
});

test("a candidate alias is bound to its issuer, session, scope and enrollment", () => {
  const base = {
    issuerKeyId: keccak256(stringToBytes("issuer")),
    candidateProfile: Profile.INVOICE_CASE_INSENSITIVE,
    sourceRecordDigest: keccak256(stringToBytes("source")),
    sessionId: SESSION_COMMITMENT,
    scopeCommitment: keccak256(stringToBytes("scope-a")),
    enrollmentDigest: keccak256(stringToBytes("enrollment")),
    aliasCommitment: keccak256(stringToBytes("alias")),
  };
  const bound = boundCandidateAliasCommitment(base);
  // Changing any bound input changes the commitment, so an alias cannot be
  // lifted into another session, scope, issuer or source record.
  for (const field of ["issuerKeyId", "sourceRecordDigest", "sessionId", "scopeCommitment", "enrollmentDigest"]) {
    assert.notEqual(
      boundCandidateAliasCommitment({ ...base, [field]: keccak256(stringToBytes(`other-${field}`)) }),
      bound,
      `${field} must be bound`,
    );
  }
  // A lossless profile may not produce a candidate alias binding at all.
  assert.throws(
    () => boundCandidateAliasCommitment({ ...base, candidateProfile: Profile.INVOICE_CASE_SENSITIVE }),
    /IDENTITY_PROFILE_MISMATCH/,
  );
  // Incomplete binding fails closed.
  assert.throws(
    () => boundCandidateAliasCommitment({ ...base, sessionId: `0x${"00".repeat(32)}` }),
    /CANDIDATE_BINDING_INCOMPLETE:sessionId/,
  );
});

test("a session outcome is terminal and cannot be re-run", () => {
  const active = session();
  runSession({
    session: active, identityA: identity(), identityB: identity(),
    evaluateExact: no, evaluateCandidate: never,
  });
  assert.throws(
    () => runSession({
      session: active, identityA: identity(), identityB: identity(),
      evaluateExact: yes, evaluateCandidate: never,
    }),
    /SESSION_ALREADY_TERMINAL/,
  );
});

test("a session cannot run without a frozen governance context", () => {
  assert.throws(
    () => session({ governance: undefined }),
    new RegExp(ProtocolError.GOVERNANCE_NOT_FROZEN),
  );
  assert.throws(
    () => session({ governance: governance({ sessionCommitment: `0x${"00".repeat(32)}` }) }),
    new RegExp(ProtocolError.COMMITMENT_MISSING),
  );
});

test("a session cannot run before its commitment is published", () => {
  assert.throws(
    () => session({ governance: governance({ committedAt: 0 }) }),
    new RegExp(ProtocolError.COMMITMENT_NOT_PUBLISHED),
  );
});

test("one controller alone cannot initiate a session", () => {
  assert.throws(
    () => session({ governance: governance({ initiationSignatureB: undefined }) }),
    new RegExp(ProtocolError.INITIATION_NOT_BILATERAL),
  );
  // The same signature twice is one party signing, not two agreeing.
  assert.throws(
    () => session({ governance: governance({ initiationSignatureB: "0xaa" }) }),
    /SESSION_INITIATION_NOT_BILATERAL:identical/,
  );
});

test("the session id is the opaque commitment and nothing else", () => {
  assert.throws(
    () => session({ sessionId: keccak256(stringToBytes("some-other-id")) }),
    new RegExp(ProtocolError.COMMITMENT_MISSING),
  );
  assert.equal(session().sessionCommitment, SESSION_COMMITMENT);
});

test("candidate matching cannot exceed the committed permission", () => {
  // Both parties ask for it at runtime, but the committed intent says exact-only.
  const active = session({
    governance: governance({ candidateAuthorized: false }),
    candidateAuthorizedByA: true,
    candidateAuthorizedByB: true,
  });
  assert.equal(active.candidateAuthorized, false);
  const result = runSession({
    session: active, identityA: identity(), identityB: identity(),
    evaluateExact: no, evaluateCandidate: never,
  });
  assert.equal(result.outcome, Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES);
});

test("an evaluator request binds the commitment and both enrollments", () => {
  const active = session();
  const base = {
    sessionCommitment: SESSION_COMMITMENT,
    enrollmentBindingA: active.enrollmentBindingA,
    enrollmentBindingB: active.enrollmentBindingB,
    tolerant: false,
  };
  const request = evaluatorRequest(base);
  assert.notEqual(
    evaluatorRequest({ ...base, sessionCommitment: keccak256(stringToBytes("other")) }),
    request,
  );
  assert.notEqual(evaluatorRequest({ ...base, tolerant: true }), request);
  assert.notEqual(
    evaluatorRequest({ ...base, enrollmentBindingA: active.enrollmentBindingB }),
    request,
  );
  // An evaluator may not be asked to work against an unpublished commitment.
  assert.throws(
    () => evaluatorRequest({ ...base, sessionCommitment: `0x${"00".repeat(32)}` }),
    /SESSION_COMMITMENT_MISSING:sessionCommitment/,
  );
});

test("an authorization created after initiation cannot govern the session", () => {
  // The record becomes valid one second after the session was opened. That is a
  // controller chosen after the fact, which is exactly what must not apply.
  assert.throws(
    () => session({
      governance: governance({ recordA: record(SCOPE_A, { validFrom: COMMITTED_AT + 1 }) }),
    }),
    /SCOPE_AUTHORIZATION_NOT_PRE_SESSION:A/,
  );
});

test("a governance record must belong to the scope it is frozen for", () => {
  assert.throws(
    () => session({ governance: governance({ recordA: record(SCOPE_B) }) }),
    /SESSION_GOVERNANCE_SCOPE_MISMATCH:A/,
  );
  assert.throws(
    () => session({
      governance: governance({ recordB: { ...record(SCOPE_B), recordDigest: record(SCOPE_A).recordDigest, scopeCommitment: SCOPE_B } }),
    }),
    /SESSION_GOVERNANCE_SCOPE_MISMATCH:identical/,
  );
});

test("an incomplete governance record fails closed", () => {
  for (const [field, value] of [
    ["recordDigest", `0x${"00".repeat(32)}`],
    ["controllerKeyId", `0x${"00".repeat(32)}`],
    ["controllerEpoch", 0],
    ["authorizationVersion", 0],
  ]) {
    assert.throws(
      () => session({ governance: governance({ recordA: record(SCOPE_A, { [field]: value }) }) }),
      new RegExp(`SESSION_GOVERNANCE_INCOMPLETE:A.${field}`),
      `${field} must be required`,
    );
  }
});

test("an enrollment binds the authority it was made under", () => {
  const base = {
    sessionCommitment: SESSION_COMMITMENT,
    scopeCommitment: SCOPE_A,
    record: record(SCOPE_A),
  };
  const bound = enrollmentBinding(base);
  // Rotating any part of the authority changes the binding, so an enrollment
  // made under one controller cannot be replayed under its successor.
  for (const [field, value] of [
    ["recordDigest", keccak256(stringToBytes("rotated-record"))],
    ["controller", "0x000000000000000000000000000000000000c0a2"],
    ["controllerKeyId", keccak256(stringToBytes("rotated-key"))],
    ["controllerEpoch", 2],
    ["authorizationVersion", 2],
  ]) {
    assert.notEqual(
      enrollmentBinding({ ...base, record: record(SCOPE_A, { [field]: value }) }),
      bound,
      `${field} must be bound into enrollment`,
    );
  }
  // A different committed session is a different enrollment.
  assert.notEqual(
    enrollmentBinding({ ...base, sessionCommitment: keccak256(stringToBytes("session-2")) }),
    bound,
  );
});

test("the two sides enroll under different bindings", () => {
  const active = session();
  assert.notEqual(active.enrollmentBindingA, active.enrollmentBindingB);
});

test("every outcome carries its session commitment", () => {
  const context = SESSION_COMMITMENT;
  const exact = runSession({
    session: session(), identityA: identity(), identityB: identity(),
    evaluateExact: yes, evaluateCandidate: never,
  });
  assert.equal(exact.sessionCommitment, context);

  const noMatch = runSession({
    session: session(), identityA: identity(), identityB: identity(),
    evaluateExact: no, evaluateCandidate: never,
  });
  assert.equal(noMatch.sessionCommitment, context);

  // Even the outcome that runs no cryptography reports the authority it ran under.
  const incomparable = runSession({
    session: session(),
    identityA: identity(),
    identityB: identity({ tier: IdentityTier.RegistryDocument }),
    evaluateExact: never, evaluateCandidate: never,
  });
  assert.equal(incomparable.sessionCommitment, context);
});
