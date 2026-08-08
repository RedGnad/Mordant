import { randomUUID } from "node:crypto";

import type { Sha256Digest } from "../protection/cleanverse-asset";
import {
  governedResultDigest,
  verifyGovernedResultSignature,
  type GovernedSignedResult,
} from "../protection/protection-evidence";
import {
  EXPERIMENT_PROGRAM_ID,
  GOVERNED_RESULT_SEMANTIC,
  createActionHistoryEvent,
  createGovernanceApprovalEvent,
  createGovernedActionReceipt,
  createPolicySelectionEvent,
  createProposedAction,
  deepFreeze,
  digestValue,
  verifyGovernanceApprovalEvent,
  verifyGovernedActionReceipt,
  verifyPolicyManifest,
  verifyPolicySelectionEvent,
  verifyProposedAction,
  RecoursePolicyError,
  type ActionHistoryEvent,
  type ActionState,
  type ApproverRole,
  type GovernanceApprovalEvent,
  type GovernedActionReceipt,
  type GovernedRecoursePolicy,
  type PolicySelectionEvent,
  type ProposedAction,
  type PrototypeSigner,
} from "./policy";

export type VerifiedGovernedResult = GovernedSignedResult & Readonly<{ digest: Sha256Digest }>;

export type ExposedGovernedResult = Readonly<{
  sourcePath: string;
  digest: Sha256Digest;
  schemaVersion: "mordant.governed-conflict-result/1";
  semantic: typeof GOVERNED_RESULT_SEMANTIC;
  outcome: "CONFLICT" | "NO_CONFLICT";
  releasedAtUnix: number;
  exposedAtUnix: number;
  immutable: true;
}>;

export type ExperimentalCase = Readonly<{
  schemaVersion: "mordant.governed-recourse-experimental-case/1";
  caseId: Sha256Digest;
  runId: string;
  programId: typeof EXPERIMENT_PROGRAM_ID;
  assetIdentity: Sha256Digest;
  currentState: ActionState;
  caseAuthorizationDigest: Sha256Digest;
  policy: GovernedRecoursePolicy | null;
  selection: PolicySelectionEvent | null;
  governedResult: ExposedGovernedResult | null;
  proposedAction: ProposedAction | null;
  approval: GovernanceApprovalEvent | null;
  receipt: GovernedActionReceipt | null;
  consumedApprovalNonces: readonly string[];
  history: readonly ActionHistoryEvent[];
}>;

export type CompletePath = Readonly<{
  state: ExperimentalCase;
  authorizationEvent: ActionHistoryEvent;
}>;

function fail(code: string, message: string): never {
  throw new RecoursePolicyError(code, message);
}

function assertState(state: ExperimentalCase, expected: ActionState): void {
  if (state.currentState !== expected) fail("ACTION_STATE", `Expected ${expected}, received ${state.currentState}`);
}

function lastHistory(state: ExperimentalCase): ActionHistoryEvent {
  const event = state.history.at(-1);
  if (event === undefined) fail("ACTION_HISTORY", "Experimental case has no history head");
  return event;
}

function nextHistory(
  state: ExperimentalCase,
  toState: ActionState,
  atUnix: number,
  evidenceDigest: Sha256Digest,
): ActionHistoryEvent {
  const previous = lastHistory(state);
  if (!Number.isSafeInteger(atUnix) || atUnix < previous.atUnix) fail("ACTION_TIME", "Action history time moved backwards");
  return createActionHistoryEvent({
    ordinal: state.history.length + 1,
    caseId: state.caseId,
    runId: state.runId,
    fromState: state.currentState,
    toState,
    atUnix,
    evidenceDigest,
    previousEventDigest: previous.digest,
  });
}

function append(state: ExperimentalCase, event: ActionHistoryEvent, extra: Partial<ExperimentalCase> = {}): ExperimentalCase {
  return deepFreeze({
    ...state,
    ...extra,
    currentState: event.toState,
    history: [...state.history, event],
  });
}

export function createExperimentalCase(input: Readonly<{
  caseId: Sha256Digest;
  assetIdentity: Sha256Digest;
  authorizedAtUnix: number;
  runId?: string;
}>): ExperimentalCase {
  const runId = input.runId ?? `governed-recourse-experiment-${randomUUID()}`;
  const caseAuthorizationDigest = digestValue({
    schemaVersion: "mordant.governed-recourse-case-authorization/1",
    caseId: input.caseId,
    runId,
    programId: EXPERIMENT_PROGRAM_ID,
    assetIdentity: input.assetIdentity,
    authorizedAtUnix: input.authorizedAtUnix,
    executionMode: "EVIDENCE_ONLY",
    prototypeAuthorization: true,
  });
  const first = createActionHistoryEvent({
    ordinal: 1,
    caseId: input.caseId,
    runId,
    fromState: null,
    toState: "CASE_AUTHORIZED",
    atUnix: input.authorizedAtUnix,
    evidenceDigest: caseAuthorizationDigest,
    previousEventDigest: null,
  });
  return deepFreeze({
    schemaVersion: "mordant.governed-recourse-experimental-case/1",
    caseId: input.caseId,
    runId,
    programId: EXPERIMENT_PROGRAM_ID,
    assetIdentity: input.assetIdentity,
    currentState: "CASE_AUTHORIZED",
    caseAuthorizationDigest,
    policy: null,
    selection: null,
    governedResult: null,
    proposedAction: null,
    approval: null,
    receipt: null,
    consumedApprovalNonces: [],
    history: [first],
  });
}

export function bindPolicy(input: Readonly<{
  state: ExperimentalCase;
  policy: GovernedRecoursePolicy;
  selector: PrototypeSigner;
  selectedAtUnix: number;
  applicabilityAtUnix: number;
  nonce?: string;
}>): ExperimentalCase {
  assertState(input.state, "CASE_AUTHORIZED");
  verifyPolicyManifest(input.policy);
  if (
    input.policy.scope.programId !== input.state.programId
    || input.policy.scope.assetIdentity !== input.state.assetIdentity
  ) fail("POLICY_SCOPE_MISMATCH", "Policy asset or program scope does not match the experimental case");
  const selection = createPolicySelectionEvent({
    caseId: input.state.caseId,
    runId: input.state.runId,
    policy: input.policy,
    selectedAtUnix: input.selectedAtUnix,
    applicabilityAtUnix: input.applicabilityAtUnix,
    nonce: input.nonce ?? `selection-${randomUUID()}`,
    previousEventDigest: lastHistory(input.state).digest,
  }, input.selector);
  const event = nextHistory(input.state, "POLICY_BOUND", input.selectedAtUnix, selection.digest);
  return append(input.state, event, { policy: input.policy, selection });
}

export function exposeGovernedResult(input: Readonly<{
  state: ExperimentalCase;
  governedResult: VerifiedGovernedResult;
  sourcePath: string;
  exposedAtUnix: number;
}>): ExperimentalCase {
  assertState(input.state, "POLICY_BOUND");
  if (input.state.policy === null || input.state.selection === null) fail("POLICY_NOT_BOUND", "Result cannot be exposed without a bound policy");
  verifyGovernedResultSignature(input.governedResult);
  if (governedResultDigest(input.governedResult) !== input.governedResult.digest) fail("GOVERNED_RESULT_DIGEST", "Exact governed-result digest mismatch");
  const accepted = input.state.policy.acceptedGovernedResult;
  if (
    input.governedResult.schemaVersion !== accepted.schemaVersion
    || input.governedResult.serviceId !== accepted.serviceId
    || input.governedResult.serviceVersion !== accepted.serviceVersion
    || input.governedResult.releaseMode !== accepted.releaseMode
    || accepted.semantic !== GOVERNED_RESULT_SEMANTIC
  ) fail("RESULT_SEMANTIC_MISMATCH", "Governed result does not match the exact accepted conflict/no-conflict semantic");
  if (input.governedResult.caseId !== input.state.caseId || input.governedResult.assetIdentity !== input.state.assetIdentity) {
    fail("RESULT_SCOPE_MISMATCH", "Governed result case or asset does not match the bound case");
  }
  verifyPolicySelectionEvent(input.state.selection, input.state.policy, input.exposedAtUnix);
  const result: ExposedGovernedResult = deepFreeze({
    sourcePath: input.sourcePath,
    digest: input.governedResult.digest,
    schemaVersion: input.governedResult.schemaVersion,
    semantic: GOVERNED_RESULT_SEMANTIC,
    outcome: input.governedResult.conflict ? "CONFLICT" : "NO_CONFLICT",
    releasedAtUnix: input.governedResult.releasedAtUnix,
    exposedAtUnix: input.exposedAtUnix,
    immutable: true,
  });
  const event = nextHistory(input.state, "RESULT_AVAILABLE", input.exposedAtUnix, result.digest);
  return append(input.state, event, { governedResult: result });
}

export function evaluatePolicy(state: ExperimentalCase, evaluatedAtUnix: number): ExperimentalCase {
  assertState(state, "RESULT_AVAILABLE");
  if (state.policy === null || state.selection === null || state.governedResult === null) fail("EVALUATION_EVIDENCE", "Policy evaluation evidence is incomplete");
  const proposedAction = createProposedAction({
    caseId: state.caseId,
    runId: state.runId,
    governedResultDigest: state.governedResult.digest,
    conflict: state.governedResult.outcome === "CONFLICT",
    resultExposedAtUnix: state.governedResult.exposedAtUnix,
    policy: state.policy,
    selection: state.selection,
  });
  const evaluated = nextHistory(state, "POLICY_EVALUATED", evaluatedAtUnix, proposedAction.digest);
  let next = append(state, evaluated, { proposedAction });
  if (proposedAction.authorizationMode === "HUMAN_APPROVAL_REQUIRED") {
    const review = nextHistory(next, "REVIEW_REQUIRED", evaluatedAtUnix, proposedAction.digest);
    next = append(next, review);
  }
  return next;
}

export function approveProposedAction(input: Readonly<{
  state: ExperimentalCase;
  approverRole: ApproverRole;
  approver: PrototypeSigner;
  nonce?: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
}>): ExperimentalCase {
  assertState(input.state, "REVIEW_REQUIRED");
  if (input.state.proposedAction === null) fail("PROPOSED_ACTION_MISSING", "Review has no exact proposed action");
  const approval = createGovernanceApprovalEvent({
    proposedAction: input.state.proposedAction,
    approverRole: input.approverRole,
    nonce: input.nonce ?? `approval-${randomUUID()}`,
    issuedAtUnix: input.issuedAtUnix,
    expiresAtUnix: input.expiresAtUnix,
    previousEventDigest: lastHistory(input.state).digest,
  }, input.approver);
  verifyGovernanceApprovalEvent({
    event: approval,
    proposedAction: input.state.proposedAction,
    expectedPreviousEventDigest: lastHistory(input.state).digest,
    atUnix: input.issuedAtUnix,
    consumedNonces: new Set(input.state.consumedApprovalNonces),
  });
  const event = nextHistory(input.state, "REVIEW_APPROVED", input.issuedAtUnix, approval.digest);
  return append(input.state, event, { approval });
}

export function expireReview(state: ExperimentalCase, expiredAtUnix: number): ExperimentalCase {
  assertState(state, "REVIEW_REQUIRED");
  if (state.proposedAction?.approvalExpiresAtUnix === null || state.proposedAction?.approvalExpiresAtUnix === undefined) {
    fail("REVIEW_EXPIRY", "Review has no bounded approval window");
  }
  if (expiredAtUnix <= state.proposedAction.approvalExpiresAtUnix) fail("REVIEW_NOT_EXPIRED", "Review approval window has not expired");
  const expired = nextHistory(state, "REVIEW_EXPIRED", expiredAtUnix, state.proposedAction.digest);
  const afterExpiry = append(state, expired);
  const escalated = nextHistory(afterExpiry, "ESCALATION_REQUIRED", expiredAtUnix, state.proposedAction.digest);
  return append(afterExpiry, escalated);
}

export function authorizeAction(state: ExperimentalCase, authorizedAtUnix: number): ExperimentalCase {
  if (state.proposedAction === null) fail("PROPOSED_ACTION_MISSING", "No exact proposed action can be authorized");
  verifyProposedAction(state.proposedAction);
  let evidenceDigest = state.proposedAction.digest;
  let consumed = [...state.consumedApprovalNonces];
  if (state.proposedAction.authorizationMode === "HUMAN_APPROVAL_REQUIRED") {
    assertState(state, "REVIEW_APPROVED");
    if (state.approval === null) fail("APPROVAL_REQUIRED", "Human-required action has no approval event");
    const reviewEvent = state.history.at(-2);
    if (reviewEvent?.toState !== "REVIEW_REQUIRED" || lastHistory(state).evidenceDigest !== state.approval.digest) {
      fail("APPROVAL_HISTORY", "Approval is not linked to the current review history");
    }
    verifyGovernanceApprovalEvent({
      event: state.approval,
      proposedAction: state.proposedAction,
      expectedPreviousEventDigest: reviewEvent.digest,
      atUnix: authorizedAtUnix,
      consumedNonces: new Set(state.consumedApprovalNonces),
    });
    consumed = [...consumed, state.approval.nonce];
    evidenceDigest = state.approval.digest;
  } else {
    assertState(state, "POLICY_EVALUATED");
    if (state.approval !== null) fail("APPROVAL_NOT_REQUIRED", "Automatic branch cannot use a fake approval");
  }
  const event = nextHistory(state, "ACTION_AUTHORIZED", authorizedAtUnix, evidenceDigest);
  return append(state, event, { consumedApprovalNonces: consumed });
}

export function recordAuthorizedAction(input: Readonly<{
  state: ExperimentalCase;
  recorder: PrototypeSigner;
  recordedAtUnix: number;
}>): CompletePath {
  assertState(input.state, "ACTION_AUTHORIZED");
  const { state } = input;
  if (
    state.policy === null || state.selection === null || state.governedResult === null || state.proposedAction === null
  ) fail("RECEIPT_EVIDENCE", "Cannot record an incomplete action evidence chain");
  const authorizationEvent = lastHistory(state);
  const transition = nextHistory(state, "ACTION_RECORDED", input.recordedAtUnix, state.proposedAction.digest);
  const receipt = createGovernedActionReceipt({
    proposedAction: state.proposedAction,
    policy: state.policy,
    selection: state.selection,
    approval: state.approval,
    governedResultSchema: state.governedResult.schemaVersion,
    governedResultSemantic: state.governedResult.semantic,
    governedResultExposedAtUnix: state.governedResult.exposedAtUnix,
    stateTransition: transition,
    recordedAtUnix: input.recordedAtUnix,
  }, input.recorder);
  verifyGovernedActionReceipt({
    receipt,
    policy: state.policy,
    selection: state.selection,
    approval: state.approval,
    proposedAction: state.proposedAction,
    authorizationEvent,
  });
  return deepFreeze({
    state: append(state, transition, { receipt }),
    authorizationEvent,
  });
}

export function completeGovernedActionPath(input: Readonly<{
  policy: GovernedRecoursePolicy;
  governedResult: VerifiedGovernedResult;
  sourcePath: string;
  selector: PrototypeSigner;
  approver: PrototypeSigner | null;
  approverRole: ApproverRole | null;
  recorder: PrototypeSigner;
  runId: string;
  authorizedAtUnix: number;
  selectedAtUnix: number;
  resultExposedAtUnix: number;
  evaluatedAtUnix: number;
  approvalIssuedAtUnix: number | null;
  approvalExpiresAtUnix: number | null;
  actionAuthorizedAtUnix: number;
  actionRecordedAtUnix: number;
}>): CompletePath {
  let state = createExperimentalCase({
    caseId: input.governedResult.caseId,
    assetIdentity: input.governedResult.assetIdentity,
    authorizedAtUnix: input.authorizedAtUnix,
    runId: input.runId,
  });
  state = bindPolicy({
    state,
    policy: input.policy,
    selector: input.selector,
    selectedAtUnix: input.selectedAtUnix,
    applicabilityAtUnix: input.selectedAtUnix,
    nonce: `${input.runId}-selection-001`,
  });
  state = exposeGovernedResult({
    state,
    governedResult: input.governedResult,
    sourcePath: input.sourcePath,
    exposedAtUnix: input.resultExposedAtUnix,
  });
  state = evaluatePolicy(state, input.evaluatedAtUnix);
  if (state.proposedAction?.authorizationMode === "HUMAN_APPROVAL_REQUIRED") {
    if (
      input.approver === null || input.approverRole === null
      || input.approvalIssuedAtUnix === null || input.approvalExpiresAtUnix === null
    ) fail("APPROVAL_REQUIRED", "Complete human path requires exact approval inputs");
    state = approveProposedAction({
      state,
      approverRole: input.approverRole,
      approver: input.approver,
      nonce: `${input.runId}-approval-001`,
      issuedAtUnix: input.approvalIssuedAtUnix,
      expiresAtUnix: input.approvalExpiresAtUnix,
    });
  }
  state = authorizeAction(state, input.actionAuthorizedAtUnix);
  return recordAuthorizedAction({ state, recorder: input.recorder, recordedAtUnix: input.actionRecordedAtUnix });
}
