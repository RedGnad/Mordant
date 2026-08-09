/**
 * The bounded governed-recourse policy promoted into the Mordant product.
 *
 * This policy is deliberately not a legal rules engine. It consumes only a
 * verified governed conflict Boolean and selects one preconfigured demo action.
 * Legal priority, responsibility, ownership, fraud, default, payout recipient,
 * payout amount and legal correctness are outside this schema.
 */

import { sha256Digest, type Sha256Digest } from "./cleanverse-asset";
import {
  governedResultDigest,
  verifyGovernedResultSignature,
  type GovernedSignedResult,
} from "./protection-evidence";
import {
  PROTECTION_POLICY_VERSION,
  protectionPolicyId,
} from "./protection-case";

export const GOVERNED_RECOURSE_POLICY_SCHEMA = "mordant.governed-recourse-policy/1" as const;
export const GOVERNED_RECOURSE_SELECTION_SCHEMA = "mordant.governed-recourse-policy-selection/1" as const;
export const GOVERNED_ACTION_PLAN_SCHEMA = "mordant.governed-action-plan/1" as const;
export const GOVERNED_RECOURSE_OPERATION_AUTHORIZATION_SCHEMA = "mordant.governed-recourse-operation-authorization/1" as const;
export const GOVERNED_RECOURSE_OPERATION_RECORD_SCHEMA = "mordant.governed-recourse-operation-record/1" as const;
export const GOVERNED_ACTION_EVIDENCE_SCHEMA = "mordant.governed-action-evidence-reference/1" as const;

export const GOVERNED_RECOURSE_POLICY_ID = "mordant.managed-demo.facility-protection" as const;
export const GOVERNED_RECOURSE_POLICY_VERSION = 1 as const;
export const FIRST_IMPLEMENTED_WORKFLOW_ID = "mordant.conflicting-pledge-protection" as const;

export const GOVERNED_RESULT_EXCLUSIONS = Object.freeze([
  "LEGAL_PRIORITY",
  "RESPONSIBILITY",
  "OWNERSHIP",
  "FRAUD",
  "DEFAULT",
  "PAYOUT_RECIPIENT",
  "PAYOUT_AMOUNT",
  "LEGALLY_CORRECT_ACTION",
] as const);

export type GovernedRecoursePolicy = Readonly<{
  schemaVersion: typeof GOVERNED_RECOURSE_POLICY_SCHEMA;
  policyId: typeof GOVERNED_RECOURSE_POLICY_ID;
  policyVersion: typeof GOVERNED_RECOURSE_POLICY_VERSION;
  policyHash: Sha256Digest;
  workflow: Readonly<{
    workflowId: typeof FIRST_IMPLEMENTED_WORKFLOW_ID;
    label: "Conflicting Pledge Protection";
    productPosition: "FIRST_IMPLEMENTED_WORKFLOW";
  }>;
  governedResultContract: Readonly<{
    schemaVersion: "mordant.governed-conflict-result/1";
    serviceId: "mordant.private-pledge-matching";
    serviceVersion: 1;
    resultPolicyId: Sha256Digest;
    resultPolicyVersion: typeof PROTECTION_POLICY_VERSION;
    establishesOnly: readonly ["CONFLICT", "NO_CONFLICT"];
    doesNotEstablish: typeof GOVERNED_RESULT_EXCLUSIONS;
  }>;
  conflict: GovernedActionRule;
  noConflict: GovernedActionRule;
}>;

export type GovernedActionRule = Readonly<{
  selectedGovernedAction: "OPEN_LOCAL_CURE_PATH" | "RECORD_AND_CLOSE";
  actionOwner: "MORDANT_MANAGED_EXECUTION";
  cureWindowSeconds: 86_400 | null;
  deadlineRule: "STARTS_WHEN_LOCAL_CURE_PATH_OPENS" | "NOT_APPLICABLE";
  escalation: "MANUAL_REVIEW_OUTSIDE_MANAGED_RUN" | "NONE";
  requiredApproval: "NONE_FOR_LOCAL_PROTOCOL_DOUBLE";
  actionClass: "LOCAL_PROTOCOL_DOUBLE" | "EVIDENCE_ONLY";
  settlementAuthorization: "NOT_AUTHORIZED";
}>;

type GovernedRecoursePolicyBody = Omit<GovernedRecoursePolicy, "policyHash">;

const POLICY_BODY: GovernedRecoursePolicyBody = Object.freeze({
  schemaVersion: GOVERNED_RECOURSE_POLICY_SCHEMA,
  policyId: GOVERNED_RECOURSE_POLICY_ID,
  policyVersion: GOVERNED_RECOURSE_POLICY_VERSION,
  workflow: Object.freeze({
    workflowId: FIRST_IMPLEMENTED_WORKFLOW_ID,
    label: "Conflicting Pledge Protection",
    productPosition: "FIRST_IMPLEMENTED_WORKFLOW",
  }),
  governedResultContract: Object.freeze({
    schemaVersion: "mordant.governed-conflict-result/1",
    serviceId: "mordant.private-pledge-matching",
    serviceVersion: 1,
    resultPolicyId: protectionPolicyId(),
    resultPolicyVersion: PROTECTION_POLICY_VERSION,
    establishesOnly: Object.freeze(["CONFLICT", "NO_CONFLICT"] as const),
    doesNotEstablish: GOVERNED_RESULT_EXCLUSIONS,
  }),
  conflict: Object.freeze({
    selectedGovernedAction: "OPEN_LOCAL_CURE_PATH",
    actionOwner: "MORDANT_MANAGED_EXECUTION",
    // The existing managed local protocol double opens a fixed 24-hour cure
    // window. The policy commits that existing behavior; it does not reuse the
    // separate Adapter V2/on-chain 600-second configuration.
    cureWindowSeconds: 86_400,
    deadlineRule: "STARTS_WHEN_LOCAL_CURE_PATH_OPENS",
    escalation: "MANUAL_REVIEW_OUTSIDE_MANAGED_RUN",
    requiredApproval: "NONE_FOR_LOCAL_PROTOCOL_DOUBLE",
    actionClass: "LOCAL_PROTOCOL_DOUBLE",
    settlementAuthorization: "NOT_AUTHORIZED",
  }),
  noConflict: Object.freeze({
    selectedGovernedAction: "RECORD_AND_CLOSE",
    actionOwner: "MORDANT_MANAGED_EXECUTION",
    cureWindowSeconds: null,
    deadlineRule: "NOT_APPLICABLE",
    escalation: "NONE",
    requiredApproval: "NONE_FOR_LOCAL_PROTOCOL_DOUBLE",
    actionClass: "EVIDENCE_ONLY",
    settlementAuthorization: "NOT_AUTHORIZED",
  }),
});

export function governedRecoursePolicyHash(
  policy: GovernedRecoursePolicyBody = POLICY_BODY,
): Sha256Digest {
  return sha256Digest("MordantGovernedRecoursePolicy/v1", policy);
}

export const MANAGED_DEMO_GOVERNED_RECOURSE_POLICY: GovernedRecoursePolicy = Object.freeze({
  ...POLICY_BODY,
  policyHash: governedRecoursePolicyHash(),
});

export type GovernedRecoursePolicySelection = Readonly<{
  schemaVersion: typeof GOVERNED_RECOURSE_SELECTION_SCHEMA;
  policyId: typeof GOVERNED_RECOURSE_POLICY_ID;
  policyVersion: typeof GOVERNED_RECOURSE_POLICY_VERSION;
  policyHash: Sha256Digest;
  caseId: Sha256Digest;
  resultPolicyId: Sha256Digest;
  resultPolicyVersion: typeof PROTECTION_POLICY_VERSION;
  selectedAtUnix: number;
  selectionHash: Sha256Digest;
}>;

type GovernedRecoursePolicySelectionBody = Omit<GovernedRecoursePolicySelection, "selectionHash">;

export class GovernedRecoursePolicyError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "GovernedRecoursePolicyError";
  }
}

function positiveUnix(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new GovernedRecoursePolicyError("TIME", `${field} must be a positive Unix timestamp`);
  }
  return value;
}

function exactKeys(value: object, expected: readonly string[], code: string): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length
    || actual.some((key, index) => key !== sortedExpected[index])) {
    throw new GovernedRecoursePolicyError(code, `${code} has unexpected fields`);
  }
}

function digest(value: string, field: string): Sha256Digest {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new GovernedRecoursePolicyError("DIGEST", `${field} must be a SHA-256 digest`);
  }
  return value as Sha256Digest;
}

function selectionHash(body: GovernedRecoursePolicySelectionBody): Sha256Digest {
  return sha256Digest("MordantGovernedRecoursePolicySelection/v1", body);
}

export function selectManagedDemoGovernedRecoursePolicy(input: Readonly<{
  caseId: Sha256Digest;
  resultPolicyId: Sha256Digest;
  resultPolicyVersion: typeof PROTECTION_POLICY_VERSION;
  selectedAtUnix: number;
}>): GovernedRecoursePolicySelection {
  const body: GovernedRecoursePolicySelectionBody = {
    schemaVersion: GOVERNED_RECOURSE_SELECTION_SCHEMA,
    policyId: GOVERNED_RECOURSE_POLICY_ID,
    policyVersion: GOVERNED_RECOURSE_POLICY_VERSION,
    policyHash: MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.policyHash,
    caseId: digest(input.caseId, "caseId"),
    resultPolicyId: digest(input.resultPolicyId, "resultPolicyId"),
    resultPolicyVersion: input.resultPolicyVersion,
    selectedAtUnix: positiveUnix(input.selectedAtUnix, "selectedAtUnix"),
  };
  if (body.resultPolicyId !== protectionPolicyId() || body.resultPolicyVersion !== PROTECTION_POLICY_VERSION) {
    throw new GovernedRecoursePolicyError("RESULT_POLICY_BINDING", "The governed-result policy binding is not supported");
  }
  return Object.freeze({ ...body, selectionHash: selectionHash(body) });
}

export function verifyManagedDemoGovernedRecoursePolicySelection(
  selection: GovernedRecoursePolicySelection,
): void {
  exactKeys(selection, [
    "schemaVersion", "policyId", "policyVersion", "policyHash", "caseId", "resultPolicyId",
    "resultPolicyVersion", "selectedAtUnix", "selectionHash",
  ], "SELECTION_FIELDS");
  const body: GovernedRecoursePolicySelectionBody = {
    schemaVersion: selection.schemaVersion,
    policyId: selection.policyId,
    policyVersion: selection.policyVersion,
    policyHash: selection.policyHash,
    caseId: digest(selection.caseId, "caseId"),
    resultPolicyId: digest(selection.resultPolicyId, "resultPolicyId"),
    resultPolicyVersion: selection.resultPolicyVersion,
    selectedAtUnix: positiveUnix(selection.selectedAtUnix, "selectedAtUnix"),
  };
  if (
    body.schemaVersion !== GOVERNED_RECOURSE_SELECTION_SCHEMA
    || body.policyId !== GOVERNED_RECOURSE_POLICY_ID
    || body.policyVersion !== GOVERNED_RECOURSE_POLICY_VERSION
    || body.policyHash !== MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.policyHash
    || body.resultPolicyId !== protectionPolicyId()
    || body.resultPolicyVersion !== PROTECTION_POLICY_VERSION
    || selection.selectionHash !== selectionHash(body)
  ) {
    throw new GovernedRecoursePolicyError("SELECTION", "Governed recourse policy selection verification failed");
  }
}

export type GovernedActionPlan = Readonly<{
  schemaVersion: typeof GOVERNED_ACTION_PLAN_SCHEMA;
  policyId: typeof GOVERNED_RECOURSE_POLICY_ID;
  policyVersion: typeof GOVERNED_RECOURSE_POLICY_VERSION;
  policyHash: Sha256Digest;
  policySelectionHash: Sha256Digest;
  resultDigest: Sha256Digest;
  resultOutcome: "CONFLICT" | "NO_CONFLICT";
  resultSemantic: "CONFLICT_STATUS_ONLY";
  selectedGovernedAction: GovernedActionRule["selectedGovernedAction"];
  actionOwner: GovernedActionRule["actionOwner"];
  cureWindowSeconds: GovernedActionRule["cureWindowSeconds"];
  deadlineRule: GovernedActionRule["deadlineRule"];
  escalation: GovernedActionRule["escalation"];
  requiredApproval: GovernedActionRule["requiredApproval"];
  actionClass: GovernedActionRule["actionClass"];
  settlementAuthorization: "NOT_AUTHORIZED";
  planHash: Sha256Digest;
}>;

type GovernedActionPlanBody = Omit<GovernedActionPlan, "planHash">;

function planHash(body: GovernedActionPlanBody): Sha256Digest {
  return sha256Digest("MordantGovernedActionPlan/v1", body);
}

export function verifyManagedDemoGovernedActionPlan(plan: GovernedActionPlan): void {
  exactKeys(plan, [
    "schemaVersion", "policyId", "policyVersion", "policyHash", "policySelectionHash", "resultDigest",
    "resultOutcome", "resultSemantic", "selectedGovernedAction", "actionOwner", "cureWindowSeconds",
    "deadlineRule", "escalation", "requiredApproval", "actionClass", "settlementAuthorization", "planHash",
  ], "PLAN_FIELDS");
  const rule = plan.resultOutcome === "CONFLICT"
    ? MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.conflict
    : plan.resultOutcome === "NO_CONFLICT"
      ? MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.noConflict
      : null;
  const body: GovernedActionPlanBody = {
    schemaVersion: plan.schemaVersion,
    policyId: plan.policyId,
    policyVersion: plan.policyVersion,
    policyHash: plan.policyHash,
    policySelectionHash: digest(plan.policySelectionHash, "policySelectionHash"),
    resultDigest: digest(plan.resultDigest, "resultDigest"),
    resultOutcome: plan.resultOutcome,
    resultSemantic: plan.resultSemantic,
    selectedGovernedAction: plan.selectedGovernedAction,
    actionOwner: plan.actionOwner,
    cureWindowSeconds: plan.cureWindowSeconds,
    deadlineRule: plan.deadlineRule,
    escalation: plan.escalation,
    requiredApproval: plan.requiredApproval,
    actionClass: plan.actionClass,
    settlementAuthorization: plan.settlementAuthorization,
  };
  if (rule === null || body.schemaVersion !== GOVERNED_ACTION_PLAN_SCHEMA
    || body.policyId !== GOVERNED_RECOURSE_POLICY_ID || body.policyVersion !== GOVERNED_RECOURSE_POLICY_VERSION
    || body.policyHash !== MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.policyHash
    || body.resultSemantic !== "CONFLICT_STATUS_ONLY"
    || body.selectedGovernedAction !== rule.selectedGovernedAction || body.actionOwner !== rule.actionOwner
    || body.cureWindowSeconds !== rule.cureWindowSeconds || body.deadlineRule !== rule.deadlineRule
    || body.escalation !== rule.escalation || body.requiredApproval !== rule.requiredApproval
    || body.actionClass !== rule.actionClass || body.settlementAuthorization !== "NOT_AUTHORIZED"
    || plan.planHash !== planHash(body)) {
    throw new GovernedRecoursePolicyError("PLAN", "Governed action plan verification failed");
  }
}

/**
 * Selects a policy branch only after the complete governed result verifies.
 * The Boolean is used solely as the branch key; it does not supply action facts.
 */
export function evaluateManagedDemoGovernedRecoursePolicy(input: Readonly<{
  selection: GovernedRecoursePolicySelection;
  governedResult: GovernedSignedResult;
}>): GovernedActionPlan {
  verifyManagedDemoGovernedRecoursePolicySelection(input.selection);
  verifyGovernedResultSignature(input.governedResult);
  const result = input.governedResult;
  if (
    result.schemaVersion !== MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.governedResultContract.schemaVersion
    || result.serviceId !== MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.governedResultContract.serviceId
    || result.serviceVersion !== MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.governedResultContract.serviceVersion
    || result.caseId !== input.selection.caseId
    || result.policyId !== input.selection.resultPolicyId
    || result.policyVersion !== input.selection.resultPolicyVersion
  ) {
    throw new GovernedRecoursePolicyError("RESULT_BINDING", "Governed result does not match the selected policy context");
  }
  if (input.selection.selectedAtUnix >= result.releasedAtUnix) {
    throw new GovernedRecoursePolicyError("POLICY_SHOPPING", "Policy selection must precede governed-result exposure");
  }
  const rule = result.conflict
    ? MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.conflict
    : MANAGED_DEMO_GOVERNED_RECOURSE_POLICY.noConflict;
  const body: GovernedActionPlanBody = {
    schemaVersion: GOVERNED_ACTION_PLAN_SCHEMA,
    policyId: input.selection.policyId,
    policyVersion: input.selection.policyVersion,
    policyHash: input.selection.policyHash,
    policySelectionHash: input.selection.selectionHash,
    resultDigest: governedResultDigest(result),
    resultOutcome: result.conflict ? "CONFLICT" : "NO_CONFLICT",
    resultSemantic: "CONFLICT_STATUS_ONLY",
    selectedGovernedAction: rule.selectedGovernedAction,
    actionOwner: rule.actionOwner,
    cureWindowSeconds: rule.cureWindowSeconds,
    deadlineRule: rule.deadlineRule,
    escalation: rule.escalation,
    requiredApproval: rule.requiredApproval,
    actionClass: rule.actionClass,
    settlementAuthorization: rule.settlementAuthorization,
  };
  return Object.freeze({ ...body, planHash: planHash(body) });
}

export type GovernedRecourseOperationAuthorization = Readonly<{
  schemaVersion: typeof GOVERNED_RECOURSE_OPERATION_AUTHORIZATION_SCHEMA;
  caseId: Sha256Digest;
  policySelectionHash: Sha256Digest;
  planHash: Sha256Digest;
  resultDigest: Sha256Digest;
  selectedGovernedAction: GovernedActionRule["selectedGovernedAction"];
  cureWindowSeconds: GovernedActionRule["cureWindowSeconds"];
  deadlineRule: GovernedActionRule["deadlineRule"];
  settlementAuthorization: "NOT_AUTHORIZED";
  authorizationHash: Sha256Digest;
}>;

type GovernedRecourseOperationAuthorizationBody = Omit<
  GovernedRecourseOperationAuthorization,
  "authorizationHash"
>;

function operationAuthorizationHash(body: GovernedRecourseOperationAuthorizationBody): Sha256Digest {
  return sha256Digest("MordantGovernedRecourseOperationAuthorization/v1", body);
}

/**
 * Turns the already-verified policy plan into the only authorization consumed
 * by a policy-enabled managed recourse operation.
 */
export function authorizeManagedDemoGovernedRecourseOperation(input: Readonly<{
  selection: GovernedRecoursePolicySelection;
  plan: GovernedActionPlan;
}>): GovernedRecourseOperationAuthorization {
  verifyManagedDemoGovernedRecoursePolicySelection(input.selection);
  verifyManagedDemoGovernedActionPlan(input.plan);
  if (input.plan.policySelectionHash !== input.selection.selectionHash) {
    throw new GovernedRecoursePolicyError("OPERATION_SELECTION", "Governed operation plan is not bound to the committed selection");
  }
  const body: GovernedRecourseOperationAuthorizationBody = {
    schemaVersion: GOVERNED_RECOURSE_OPERATION_AUTHORIZATION_SCHEMA,
    caseId: input.selection.caseId,
    policySelectionHash: input.selection.selectionHash,
    planHash: input.plan.planHash,
    resultDigest: input.plan.resultDigest,
    selectedGovernedAction: input.plan.selectedGovernedAction,
    cureWindowSeconds: input.plan.cureWindowSeconds,
    deadlineRule: input.plan.deadlineRule,
    settlementAuthorization: "NOT_AUTHORIZED",
  };
  return Object.freeze({ ...body, authorizationHash: operationAuthorizationHash(body) });
}

export function verifyManagedDemoGovernedRecourseOperationAuthorization(
  authorization: GovernedRecourseOperationAuthorization,
  selection: GovernedRecoursePolicySelection,
  plan: GovernedActionPlan,
): void {
  exactKeys(authorization, [
    "schemaVersion", "caseId", "policySelectionHash", "planHash", "resultDigest",
    "selectedGovernedAction", "cureWindowSeconds", "deadlineRule", "settlementAuthorization",
    "authorizationHash",
  ], "OPERATION_AUTHORIZATION_FIELDS");
  const expected = authorizeManagedDemoGovernedRecourseOperation({ selection, plan });
  if (authorization.authorizationHash !== expected.authorizationHash
    || authorization.schemaVersion !== expected.schemaVersion
    || authorization.caseId !== expected.caseId
    || authorization.policySelectionHash !== expected.policySelectionHash
    || authorization.planHash !== expected.planHash
    || authorization.resultDigest !== expected.resultDigest
    || authorization.selectedGovernedAction !== expected.selectedGovernedAction
    || authorization.cureWindowSeconds !== expected.cureWindowSeconds
    || authorization.deadlineRule !== expected.deadlineRule
    || authorization.settlementAuthorization !== "NOT_AUTHORIZED") {
    throw new GovernedRecoursePolicyError("OPERATION_AUTHORIZATION", "Governed recourse operation authorization verification failed");
  }
}

export type GovernedRecourseOperationRecord = Readonly<{
  schemaVersion: typeof GOVERNED_RECOURSE_OPERATION_RECORD_SCHEMA;
  operationId: string;
  operationParametersDigest: Sha256Digest;
  operationAuthorizationHash: Sha256Digest;
  policySelectionHash: Sha256Digest;
  planHash: Sha256Digest;
  resultDigest: Sha256Digest;
  selectedGovernedAction: GovernedActionRule["selectedGovernedAction"];
  operationOutcome: "LOCAL_CURE_PATH_OPENED" | "NO_CONFLICT_RECORDED_AND_CLOSED";
  recourseOutcomeDigest: Sha256Digest;
  cureWindowSeconds: GovernedActionRule["cureWindowSeconds"];
  cureStartedAtUnix: number | null;
  cureDeadlineUnix: number | null;
  settlementAuthorization: "NOT_AUTHORIZED";
  operationRecordHash: Sha256Digest;
}>;

type GovernedRecourseOperationRecordBody = Omit<GovernedRecourseOperationRecord, "operationRecordHash">;

export type ManagedGovernedRecourseOutcome = Readonly<
  | { opened: true; record: Readonly<Record<string, unknown>> }
  | { opened: false; reason: "SIGNED_RESULT_FALSE" }
>;

function operationRecordHash(body: GovernedRecourseOperationRecordBody): Sha256Digest {
  return sha256Digest("MordantGovernedRecourseOperationRecord/v1", body);
}

function operationId(value: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)) {
    throw new GovernedRecoursePolicyError("OPERATION_ID", "Governed operation id must be a UUID");
  }
  return value;
}

function outcomeRecord(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new GovernedRecoursePolicyError("OPERATION_OUTCOME", "Governed recourse outcome record is required");
  }
  return value as Readonly<Record<string, unknown>>;
}

function outcomeUnix(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new GovernedRecoursePolicyError("CURE_WINDOW", `${field} must be a positive Unix timestamp`);
  }
  return value;
}

/**
 * Verifies the existing operation outcome against the action that authorized
 * it and retains the exact operation/outcome binding. It never derives the
 * authorized action from the governed Boolean.
 */
export function recordManagedDemoGovernedRecourseOperation(input: Readonly<{
  authorization: GovernedRecourseOperationAuthorization;
  operationId: string;
  operationParametersDigest: Sha256Digest;
  recourse: ManagedGovernedRecourseOutcome;
}>): GovernedRecourseOperationRecord {
  const authorization = input.authorization;
  digest(input.operationParametersDigest, "operationParametersDigest");
  let operationOutcome: GovernedRecourseOperationRecord["operationOutcome"];
  let cureStartedAtUnix: number | null;
  let cureDeadlineUnix: number | null;

  switch (authorization.selectedGovernedAction) {
    case "OPEN_LOCAL_CURE_PATH": {
      exactKeys(input.recourse, ["opened", "record"], "OPEN_LOCAL_CURE_PATH_OUTCOME");
      if (input.recourse.opened !== true || authorization.cureWindowSeconds !== 86_400
        || authorization.deadlineRule !== "STARTS_WHEN_LOCAL_CURE_PATH_OPENS") {
        throw new GovernedRecoursePolicyError("CURE_WINDOW", "Local cure-path authorization semantics rejected");
      }
      const record = outcomeRecord(input.recourse.record);
      if (record.caseId !== authorization.caseId || record.resultDigest !== authorization.resultDigest || record.open !== true) {
        throw new GovernedRecoursePolicyError("OPERATION_OUTCOME", "Local cure-path outcome binding rejected");
      }
      cureStartedAtUnix = outcomeUnix(record.boundAtUnix, "boundAtUnix");
      cureDeadlineUnix = outcomeUnix(record.cureDeadlineUnix, "cureDeadlineUnix");
      if (cureDeadlineUnix - cureStartedAtUnix !== authorization.cureWindowSeconds) {
        throw new GovernedRecoursePolicyError("CURE_WINDOW", "Local cure deadline disagrees with the committed policy");
      }
      operationOutcome = "LOCAL_CURE_PATH_OPENED";
      break;
    }
    case "RECORD_AND_CLOSE":
      exactKeys(input.recourse, ["opened", "reason"], "RECORD_AND_CLOSE_OUTCOME");
      if (input.recourse.opened !== false || input.recourse.reason !== "SIGNED_RESULT_FALSE"
        || authorization.cureWindowSeconds !== null || authorization.deadlineRule !== "NOT_APPLICABLE") {
        throw new GovernedRecoursePolicyError("OPERATION_OUTCOME", "Record-and-close outcome binding rejected");
      }
      operationOutcome = "NO_CONFLICT_RECORDED_AND_CLOSED";
      cureStartedAtUnix = null;
      cureDeadlineUnix = null;
      break;
  }

  const body: GovernedRecourseOperationRecordBody = {
    schemaVersion: GOVERNED_RECOURSE_OPERATION_RECORD_SCHEMA,
    operationId: operationId(input.operationId),
    operationParametersDigest: input.operationParametersDigest,
    operationAuthorizationHash: authorization.authorizationHash,
    policySelectionHash: authorization.policySelectionHash,
    planHash: authorization.planHash,
    resultDigest: authorization.resultDigest,
    selectedGovernedAction: authorization.selectedGovernedAction,
    operationOutcome,
    recourseOutcomeDigest: sha256Digest("MordantGovernedRecourseOperationOutcome/v1", input.recourse),
    cureWindowSeconds: authorization.cureWindowSeconds,
    cureStartedAtUnix,
    cureDeadlineUnix,
    settlementAuthorization: "NOT_AUTHORIZED",
  };
  return Object.freeze({ ...body, operationRecordHash: operationRecordHash(body) });
}

export function verifyManagedDemoGovernedRecourseOperationRecord(
  record: GovernedRecourseOperationRecord,
): void {
  exactKeys(record, [
    "schemaVersion", "operationId", "operationParametersDigest", "operationAuthorizationHash",
    "policySelectionHash", "planHash", "resultDigest", "selectedGovernedAction", "operationOutcome",
    "recourseOutcomeDigest", "cureWindowSeconds", "cureStartedAtUnix", "cureDeadlineUnix",
    "settlementAuthorization", "operationRecordHash",
  ], "OPERATION_RECORD_FIELDS");
  const body: GovernedRecourseOperationRecordBody = {
    schemaVersion: record.schemaVersion,
    operationId: operationId(record.operationId),
    operationParametersDigest: digest(record.operationParametersDigest, "operationParametersDigest"),
    operationAuthorizationHash: digest(record.operationAuthorizationHash, "operationAuthorizationHash"),
    policySelectionHash: digest(record.policySelectionHash, "policySelectionHash"),
    planHash: digest(record.planHash, "planHash"),
    resultDigest: digest(record.resultDigest, "resultDigest"),
    selectedGovernedAction: record.selectedGovernedAction,
    operationOutcome: record.operationOutcome,
    recourseOutcomeDigest: digest(record.recourseOutcomeDigest, "recourseOutcomeDigest"),
    cureWindowSeconds: record.cureWindowSeconds,
    cureStartedAtUnix: record.cureStartedAtUnix,
    cureDeadlineUnix: record.cureDeadlineUnix,
    settlementAuthorization: record.settlementAuthorization,
  };
  const conflict = body.selectedGovernedAction === "OPEN_LOCAL_CURE_PATH"
    && body.operationOutcome === "LOCAL_CURE_PATH_OPENED" && body.cureWindowSeconds === 86_400
    && body.cureStartedAtUnix !== null && body.cureDeadlineUnix !== null
    && outcomeUnix(body.cureDeadlineUnix, "cureDeadlineUnix") - outcomeUnix(body.cureStartedAtUnix, "cureStartedAtUnix") === 86_400;
  const noConflict = body.selectedGovernedAction === "RECORD_AND_CLOSE"
    && body.operationOutcome === "NO_CONFLICT_RECORDED_AND_CLOSED" && body.cureWindowSeconds === null
    && body.cureStartedAtUnix === null && body.cureDeadlineUnix === null;
  if (body.schemaVersion !== GOVERNED_RECOURSE_OPERATION_RECORD_SCHEMA
    || (!conflict && !noConflict) || body.settlementAuthorization !== "NOT_AUTHORIZED"
    || record.operationRecordHash !== operationRecordHash(body)) {
    throw new GovernedRecoursePolicyError("OPERATION_RECORD", "Governed recourse operation record verification failed");
  }
}

export type GovernedActionEvidenceReference = Readonly<{
  schemaVersion: typeof GOVERNED_ACTION_EVIDENCE_SCHEMA;
  policySelectionHash: Sha256Digest;
  resultDigest: Sha256Digest;
  actionPlanHash: Sha256Digest;
  selectedGovernedAction: GovernedActionRule["selectedGovernedAction"];
  actionOwner: GovernedActionRule["actionOwner"];
  operationId: string;
  operationAuthorizationHash: Sha256Digest;
  operationParametersDigest: Sha256Digest;
  operationOutcomeDigest: Sha256Digest;
  operationRecordHash: Sha256Digest;
  evidenceDigest: Sha256Digest;
  evidenceClass: "CUSTOM_SUPERVISED_RECEIPT";
  settlementAuthorization: "NOT_AUTHORIZED";
  referenceHash: Sha256Digest;
}>;

type GovernedActionEvidenceReferenceBody = Omit<GovernedActionEvidenceReference, "referenceHash">;

/**
 * Links an existing qualified custom receipt without rewriting or extending it.
 * This reference is evidence of the local protocol-double path only. It is not
 * proof of legal correctness, an institutional approval, or settlement.
 */
export function referenceGovernedActionEvidence(input: Readonly<{
  plan: GovernedActionPlan;
  operation: GovernedRecourseOperationRecord;
  evidenceDigest: Sha256Digest;
}>): GovernedActionEvidenceReference {
  verifyManagedDemoGovernedActionPlan(input.plan);
  verifyManagedDemoGovernedRecourseOperationRecord(input.operation);
  if (input.operation.policySelectionHash !== input.plan.policySelectionHash
    || input.operation.planHash !== input.plan.planHash
    || input.operation.resultDigest !== input.plan.resultDigest
    || input.operation.selectedGovernedAction !== input.plan.selectedGovernedAction) {
    throw new GovernedRecoursePolicyError("EVIDENCE_OPERATION", "Action evidence operation does not match the governed plan");
  }
  const body: GovernedActionEvidenceReferenceBody = {
    schemaVersion: GOVERNED_ACTION_EVIDENCE_SCHEMA,
    policySelectionHash: input.plan.policySelectionHash,
    resultDigest: input.plan.resultDigest,
    actionPlanHash: input.plan.planHash,
    selectedGovernedAction: input.plan.selectedGovernedAction,
    actionOwner: input.plan.actionOwner,
    operationId: input.operation.operationId,
    operationAuthorizationHash: input.operation.operationAuthorizationHash,
    operationParametersDigest: input.operation.operationParametersDigest,
    operationOutcomeDigest: input.operation.recourseOutcomeDigest,
    operationRecordHash: input.operation.operationRecordHash,
    evidenceDigest: digest(input.evidenceDigest, "evidenceDigest"),
    evidenceClass: "CUSTOM_SUPERVISED_RECEIPT",
    settlementAuthorization: "NOT_AUTHORIZED",
  };
  return Object.freeze({
    ...body,
    referenceHash: sha256Digest("MordantGovernedActionEvidenceReference/v1", body),
  });
}
