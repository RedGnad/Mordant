import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes } from "viem";
import {
  BilateralSession, runSession, requireComparable, interpret,
  boundCandidateAliasCommitment, Outcome, ProtocolError,
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

function session(overrides = {}) {
  return new BilateralSession({
    sessionId: keccak256(stringToBytes("session-1")),
    scopeA: keccak256(stringToBytes("scope-a")),
    scopeB: keccak256(stringToBytes("scope-b")),
    budget: 4,
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
    sessionId: keccak256(stringToBytes("session-1")),
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
