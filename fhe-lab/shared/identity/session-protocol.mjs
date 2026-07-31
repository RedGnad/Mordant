// Bilateral session protocol: what runs before any FHE work, and what the
// private outcome may be.
//
// Two rules drive everything here.
//
// First, incompatible submissions must never produce an asset-mismatch Boolean.
// Reporting "different receivable" when the truth is "these identifiers are not
// comparable" is a silent false negative, and a silent false negative is the one
// failure a double-financing detector cannot afford.
//
// Second, the tolerant candidate path is not a fallback that fires because exact
// equality failed. It is a separate, explicitly authorized, separately budgeted
// query that both parties agree to when the session is initiated.

import { keccak256, encodeAbiParameters, stringToBytes } from "viem";
import { IdentityTier, isLossless } from "./asset-identity.mjs";

export const Outcome = Object.freeze({
  EXACT_MATCH: "EXACT_MATCH",
  RECONCILIATION_REQUIRED: "RECONCILIATION_REQUIRED",
  NO_MATCH_FOR_SUBMITTED_IDENTITIES: "NO_MATCH_FOR_SUBMITTED_IDENTITIES",
  NOT_COMPARABLE: "NOT_COMPARABLE",
});

export const ProtocolError = Object.freeze({
  AUTHORITY_MISMATCH: "IDENTITY_AUTHORITY_MISMATCH",
  PROFILE_MISMATCH: "IDENTITY_PROFILE_MISMATCH",
  SCHEME_MISMATCH: "IDENTITY_SCHEME_MISMATCH",
  CANDIDATE_NOT_AUTHORIZED: "CANDIDATE_FALLBACK_NOT_AUTHORIZED",
  BUDGET_EXHAUSTED: "SCOPE_BUDGET_EXHAUSTED",
  ALIAS_NOT_BOUND: "CANDIDATE_ALIAS_NOT_BOUND",
  GOVERNANCE_NOT_FROZEN: "SESSION_GOVERNANCE_NOT_FROZEN",
  GOVERNANCE_INCOMPLETE: "SESSION_GOVERNANCE_INCOMPLETE",
  GOVERNANCE_SCOPE_MISMATCH: "SESSION_GOVERNANCE_SCOPE_MISMATCH",
  AUTHORIZATION_NOT_PRE_SESSION: "SCOPE_AUTHORIZATION_NOT_PRE_SESSION",
});

const CANDIDATE_BINDING_DOMAIN = keccak256(stringToBytes("mordant.candidate-alias-binding/1"));
const ENROLLMENT_BINDING_DOMAIN = keccak256(stringToBytes("mordant.session-enrollment-binding/1"));
const IDENTITY_SCHEME_VERSION = 3;
const ZERO32 = `0x${"00".repeat(32)}`;

/**
 * Checks one side's frozen scope-governance record.
 *
 * The controller for a session is whoever was authorized when the session was
 * opened. A controller appointed later must not become valid for an earlier
 * session, so the authorization has to predate initiation, and the record is
 * carried by digest rather than by looking up a current controller.
 */
function requireFrozenRecord(side, record, scopeCommitment, openedAt) {
  if (!record) throw new Error(`${ProtocolError.GOVERNANCE_NOT_FROZEN}:${side}`);
  for (const field of ["recordDigest", "controller", "controllerKeyId", "scopeCommitment"]) {
    if (!record[field] || record[field] === ZERO32) {
      throw new Error(`${ProtocolError.GOVERNANCE_INCOMPLETE}:${side}.${field}`);
    }
  }
  for (const field of ["controllerEpoch", "authorizationVersion", "validFrom"]) {
    if (!Number.isInteger(Number(record[field])) || Number(record[field]) <= 0) {
      throw new Error(`${ProtocolError.GOVERNANCE_INCOMPLETE}:${side}.${field}`);
    }
  }
  if (record.scopeCommitment !== scopeCommitment) {
    throw new Error(`${ProtocolError.GOVERNANCE_SCOPE_MISMATCH}:${side}`);
  }
  if (Number(record.validFrom) > Number(openedAt)) {
    throw new Error(`${ProtocolError.AUTHORIZATION_NOT_PRE_SESSION}:${side}`);
  }
  return record;
}

/**
 * The value bound into an FHE enrollment for one side.
 *
 * Binding the frozen governance record into enrollment is what stops a
 * ciphertext enrolled under one authority being reused under another: rotate the
 * controller and every enrollment binding for the new record differs, so an old
 * enrollment cannot be presented as belonging to the new session.
 */
export function enrollmentBinding({ sessionId, scopeCommitment, governanceContextDigest, record }) {
  requireFrozenRecord("enrollment", record, scopeCommitment, record?.validFrom ?? 0);
  if (!governanceContextDigest || governanceContextDigest === ZERO32) {
    throw new Error(`${ProtocolError.GOVERNANCE_INCOMPLETE}:governanceContextDigest`);
  }
  const authority = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "bytes32" }, { type: "uint32" }, { type: "uint32" }],
      [
        record.recordDigest,
        record.controller,
        record.controllerKeyId,
        Number(record.controllerEpoch),
        Number(record.authorizationVersion),
      ],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }],
      [ENROLLMENT_BINDING_DOMAIN, sessionId, scopeCommitment, governanceContextDigest, authority],
    ),
  );
}

/**
 * Pre-FHE comparability gate.
 *
 * Authority tier first: RegistryDocument and StrictSellerIssued are different
 * canonical authority spaces, so comparing them at all is a category error.
 * Cross-tier equivalence needs an authorized pre-existing attestation and a new
 * exact session; a tolerant alias can never bridge authority tiers.
 *
 * Throws rather than returning a Boolean, so an incomparable pair can never be
 * mistaken for a negative match.
 */
export function requireComparable(a, b) {
  if (Number(a.schemeVersion ?? IDENTITY_SCHEME_VERSION) !== Number(b.schemeVersion ?? IDENTITY_SCHEME_VERSION)) {
    throw new Error(ProtocolError.SCHEME_MISMATCH);
  }
  if (Number(a.tier) !== Number(b.tier)) {
    throw new Error(`${ProtocolError.AUTHORITY_MISMATCH}:${a.tier}!=${b.tier}`);
  }
  for (const field of ["sellerNamespace", "debtorNamespace", "invoiceNamespace"]) {
    if (a[field] !== b[field]) throw new Error(`${ProtocolError.PROFILE_MISMATCH}:${field}`);
  }
  for (const field of ["sellerProfile", "debtorProfile", "invoiceProfile"]) {
    if (Number(a[field]) !== Number(b[field])) {
      throw new Error(`${ProtocolError.PROFILE_MISMATCH}:${field}`);
    }
  }
  return true;
}

/** Mirrors the Solidity binding so a client cannot forge or move an alias. */
export function boundCandidateAliasCommitment({
  issuerKeyId, candidateProfile, sourceRecordDigest,
  sessionId, scopeCommitment, enrollmentDigest, aliasCommitment,
}) {
  const zero = `0x${"00".repeat(32)}`;
  for (const [name, value] of Object.entries({
    issuerKeyId, sourceRecordDigest, sessionId, scopeCommitment, enrollmentDigest, aliasCommitment,
  })) {
    if (!value || value === zero) throw new Error(`CANDIDATE_BINDING_INCOMPLETE:${name}`);
  }
  // Only a registered tolerant profile may produce a candidate alias.
  if (isLossless(candidateProfile)) throw new Error(ProtocolError.PROFILE_MISMATCH);

  const source = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint8" }, { type: "bytes32" }, { type: "bytes32" }],
      [issuerKeyId, Number(candidateProfile), sourceRecordDigest, aliasCommitment],
    ),
  );
  const session = keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }],
      [sessionId, scopeCommitment, enrollmentDigest],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint16" }, { type: "bytes32" }, { type: "bytes32" }],
      [CANDIDATE_BINDING_DOMAIN, IDENTITY_SCHEME_VERSION, source, session],
    ),
  );
}

/**
 * A bilateral session. Candidate matching is authorized only when BOTH parties
 * declared it at initiation, and it consumes the session's query budget like any
 * other query.
 */
export class BilateralSession {
  constructor({
    sessionId, scopeA, scopeB, budget, governance,
    candidateAuthorizedByA = false, candidateAuthorizedByB = false,
  }) {
    if (!sessionId || !scopeA || !scopeB) throw new Error("SESSION_SCOPE_REQUIRED");
    if (!Number.isInteger(budget) || budget <= 0) throw new Error("SESSION_BUDGET_REQUIRED");
    // Governance is frozen at initiation, before any enrollment or evaluation.
    // A session with no frozen authority cannot run at all, which is what makes
    // "who was authorized" a question with one answer rather than a lookup that
    // changes underneath the result.
    if (!governance) throw new Error(ProtocolError.GOVERNANCE_NOT_FROZEN);
    if (!governance.contextDigest || governance.contextDigest === ZERO32) {
      throw new Error(`${ProtocolError.GOVERNANCE_INCOMPLETE}:contextDigest`);
    }
    if (!Number.isInteger(Number(governance.openedAt)) || Number(governance.openedAt) <= 0) {
      throw new Error(`${ProtocolError.GOVERNANCE_INCOMPLETE}:openedAt`);
    }
    const recordA = requireFrozenRecord("A", governance.recordA, scopeA, governance.openedAt);
    const recordB = requireFrozenRecord("B", governance.recordB, scopeB, governance.openedAt);
    if (recordA.recordDigest === recordB.recordDigest) {
      throw new Error(`${ProtocolError.GOVERNANCE_SCOPE_MISMATCH}:identical`);
    }

    this.sessionId = sessionId;
    this.scopeA = scopeA;
    this.scopeB = scopeB;
    this.budget = budget;
    this.spent = 0;
    this.governance = { ...governance, recordA, recordB };
    // Each side's enrollment carries the authority it was made under.
    this.enrollmentBindingA = enrollmentBinding({
      sessionId, scopeCommitment: scopeA,
      governanceContextDigest: governance.contextDigest, record: recordA,
    });
    this.enrollmentBindingB = enrollmentBinding({
      sessionId, scopeCommitment: scopeB,
      governanceContextDigest: governance.contextDigest, record: recordB,
    });
    // Authorization is bilateral and fixed at initiation. It cannot be granted
    // later, which is what stops a tolerant query being slipped in after an
    // exact query returned false.
    this.candidateAuthorized = Boolean(candidateAuthorizedByA) && Boolean(candidateAuthorizedByB);
    this.outcome = null;
  }

  get remaining() {
    return this.budget - this.spent;
  }

  spend(count = 1) {
    if (this.spent + count > this.budget) throw new Error(ProtocolError.BUDGET_EXHAUSTED);
    this.spent += count;
  }
}

/**
 * Runs one bilateral session.
 *
 * `evaluateExact` and `evaluateCandidate` are the FHE evaluations, injected so
 * this layer can be tested without a ceremony. Neither is called until the
 * comparability gate passes: NOT_COMPARABLE performs no FHE evaluation at all.
 */
export function runSession({ session, identityA, identityB, evaluateExact, evaluateCandidate }) {
  if (session.outcome !== null) throw new Error("SESSION_ALREADY_TERMINAL");

  // 1. Comparability, before any cryptography.
  try {
    requireComparable(identityA, identityB);
  } catch (error) {
    session.outcome = {
      outcome: Outcome.NOT_COMPARABLE,
      protocolError: error.message,
      evaluated: false,
      bindable: false,
      governanceContextDigest: session.governance.contextDigest,
    };
    return session.outcome;
  }

  // 2. The strict query, paid for from the budget.
  session.spend(1);
  const exact = evaluateExact();
  if (exact) {
    session.outcome = {
      outcome: Outcome.EXACT_MATCH,
      evaluated: true,
      bindable: true,
      governanceContextDigest: session.governance.contextDigest,
    };
    return session.outcome;
  }

  // 3. The tolerant query is a separate authorized query, not an automatic
  //    fallback. Without bilateral authorization the session ends here.
  if (!session.candidateAuthorized) {
    session.outcome = {
      outcome: Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES,
      evaluated: true,
      bindable: false,
      governanceContextDigest: session.governance.contextDigest,
      // Scoped deliberately: this says the two submitted identifiers were not
      // equal. It is not evidence about any other pledge or platform.
      meaning: "the two identifiers submitted in this session were not equal",
    };
    return session.outcome;
  }
  if (session.remaining < 1) throw new Error(ProtocolError.BUDGET_EXHAUSTED);
  session.spend(1);

  const candidate = evaluateCandidate();
  const context = session.governance.contextDigest;
  session.outcome = candidate
    ? {
      outcome: Outcome.RECONCILIATION_REQUIRED,
      evaluated: true,
      bindable: false,
      governanceContextDigest: context,
    }
    : {
      outcome: Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES,
      evaluated: true,
      bindable: false,
      governanceContextDigest: context,
      meaning: "the two identifiers submitted in this session were not equal",
    };
  return session.outcome;
}

/**
 * What a consumer is allowed to conclude. Kept as data so no caller has to
 * remember the scoping rules.
 */
export function interpret(outcome) {
  switch (outcome) {
    case Outcome.EXACT_MATCH:
      return { bindable: true, publiclySubmittable: true, meaning: "the same receivable was pledged twice" };
    case Outcome.RECONCILIATION_REQUIRED:
      return {
        bindable: false,
        publiclySubmittable: false,
        meaning: "the identifiers may describe the same receivable; private reconciliation is required",
      };
    case Outcome.NO_MATCH_FOR_SUBMITTED_IDENTITIES:
      return {
        bindable: false,
        publiclySubmittable: false,
        meaning: "the two identifiers submitted in this session were not equal",
        notEvidenceOf: [
          "market completeness",
          "the absence of another pledge",
          "that the receivable is unencumbered elsewhere",
        ],
      };
    case Outcome.NOT_COMPARABLE:
      return {
        bindable: false,
        publiclySubmittable: false,
        meaning: "the submissions were not comparable; no evaluation was performed",
      };
    default:
      throw new Error("UNKNOWN_OUTCOME");
  }
}
