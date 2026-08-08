import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
  type KeyObject,
} from "node:crypto";

import type { Sha256Digest } from "../protection/cleanverse-asset";

export const POLICY_SCHEMA = "mordant.governed-recourse-policy/1" as const;
export const POLICY_SELECTION_SCHEMA = "mordant.policy-selection-event/1" as const;
export const PROPOSED_ACTION_SCHEMA = "mordant.governed-proposed-action/1" as const;
export const GOVERNANCE_APPROVAL_SCHEMA = "mordant.governance-approval-event/1" as const;
export const ACTION_HISTORY_SCHEMA = "mordant.governed-action-history-event/1" as const;
export const ACTION_RECEIPT_SCHEMA = "mordant.governed-action-receipt/1" as const;
export const EXPERIMENT_PROGRAM_ID = "mordant.governed-recourse-policy-experiment-v1" as const;
export const GOVERNED_RESULT_SEMANTIC = "CONFLICT_OR_NO_CONFLICT_ONLY" as const;

export const ACTION_TYPES = Object.freeze([
  "REVIEW_REQUIRED",
  "RECORD_AND_CLOSE",
  "OPEN_CURE_PATH",
  "MANUAL_ESCALATION",
] as const);
export type ActionType = typeof ACTION_TYPES[number];

export const INSTITUTIONAL_ROLES = Object.freeze([
  "CREDIT_OPERATIONS",
  "RECORDS_OPERATIONS",
  "RISK_OPERATIONS",
] as const);
export type InstitutionalRole = typeof INSTITUTIONAL_ROLES[number];

export const APPROVER_ROLES = Object.freeze([
  "CREDIT_OPS_APPROVER",
  "INSTITUTIONAL_REVIEWER",
] as const);
export type ApproverRole = typeof APPROVER_ROLES[number];

export const ACTION_STATES = Object.freeze([
  "CASE_AUTHORIZED",
  "POLICY_BOUND",
  "RESULT_AVAILABLE",
  "POLICY_EVALUATED",
  "REVIEW_REQUIRED",
  "REVIEW_APPROVED",
  "REVIEW_REJECTED",
  "REVIEW_EXPIRED",
  "ESCALATION_REQUIRED",
  "ACTION_AUTHORIZED",
  "ACTION_RECORDED",
  "ACTION_NOT_AUTHORIZED",
] as const);
export type ActionState = typeof ACTION_STATES[number];

export type AuthorityPurpose =
  | "POLICY_AUTHORITY"
  | "POLICY_SELECTOR"
  | "CREDIT_OPS_APPROVER"
  | "INSTITUTIONAL_REVIEWER"
  | "ACTION_RECORDER";

export type PrototypeAuthority = Readonly<{
  authorityId: Sha256Digest;
  purpose: AuthorityPurpose;
  label: string;
  prototypeAuthority: true;
  algorithm: "Ed25519";
  publicKey: string;
}>;

export type PolicyScope = Readonly<{
  programId: typeof EXPERIMENT_PROGRAM_ID;
  assetClass: "TOKENIZED_PRIVATE_CREDIT";
  assetIdentity: Sha256Digest;
}>;

export type AcceptedGovernedResult = Readonly<{
  semantic: typeof GOVERNED_RESULT_SEMANTIC;
  schemaVersion: "mordant.governed-conflict-result/1";
  serviceId: "mordant.private-pledge-matching";
  serviceVersion: 1;
  releaseMode: "governed-decryptor-v1";
}>;

export type DeadlineRule = Readonly<{
  kind: "RELATIVE_TO_RESULT_EXPOSURE";
  seconds: number;
}>;

export type EscalationRule = Readonly<{
  trigger: "DEADLINE_UNRESOLVED";
  actionType: "MANUAL_ESCALATION";
}>;

export type PolicyBranch = Readonly<{
  governedOutcome: "CONFLICT" | "NO_CONFLICT";
  evaluationActionType: "REVIEW_REQUIRED" | "RECORD_AND_CLOSE";
  authorizedActionType: "RECORD_AND_CLOSE" | "OPEN_CURE_PATH" | "MANUAL_ESCALATION";
  accountableInstitutionalRole: InstitutionalRole;
  authorizationMode: "AUTOMATIC_PERMITTED" | "HUMAN_APPROVAL_REQUIRED";
  allowedApproverRoles: readonly ApproverRole[];
  approvalWindowSeconds: number | null;
  deadlineRule: DeadlineRule | null;
  escalationRule: EscalationRule | null;
  actionConfigurationDigest: Sha256Digest;
}>;

export type SettlementRule = Readonly<{
  permission: "PROHIBITED" | "PERMITTED";
  configurationDigest: Sha256Digest | null;
}>;

export type GovernedRecoursePolicy = Readonly<{
  schemaVersion: typeof POLICY_SCHEMA;
  policyId: string;
  policyVersion: number;
  scope: PolicyScope;
  acceptedGovernedResult: AcceptedGovernedResult;
  effectiveFromUnix: number;
  effectiveUntilUnix: number;
  conflictBranch: PolicyBranch;
  noConflictBranch: PolicyBranch;
  settlement: SettlementRule;
  policyAuthority: PrototypeAuthority;
  digest: Sha256Digest;
  signature: string;
}>;

export type UnsignedGovernedRecoursePolicy = Omit<
  GovernedRecoursePolicy,
  "policyAuthority" | "digest" | "signature"
>;

export type PolicySelectionEvent = Readonly<{
  schemaVersion: typeof POLICY_SELECTION_SCHEMA;
  caseId: Sha256Digest;
  runId: string;
  programId: typeof EXPERIMENT_PROGRAM_ID;
  policyDigest: Sha256Digest;
  selectedAtUnix: number;
  applicabilityAtUnix: number;
  nonce: string;
  previousEventDigest: Sha256Digest;
  selectorAuthority: PrototypeAuthority;
  digest: Sha256Digest;
  signature: string;
}>;

export type ProposedAction = Readonly<{
  schemaVersion: typeof PROPOSED_ACTION_SCHEMA;
  caseId: Sha256Digest;
  runId: string;
  governedResultDigest: Sha256Digest;
  policyDigest: Sha256Digest;
  selectionEventDigest: Sha256Digest;
  governedOutcome: "CONFLICT" | "NO_CONFLICT";
  evaluationActionType: "REVIEW_REQUIRED" | "RECORD_AND_CLOSE";
  actionType: "RECORD_AND_CLOSE" | "OPEN_CURE_PATH" | "MANUAL_ESCALATION";
  accountableInstitutionalRole: InstitutionalRole;
  authorizationMode: "AUTOMATIC_PERMITTED" | "HUMAN_APPROVAL_REQUIRED";
  allowedApproverRoles: readonly ApproverRole[];
  approvalExpiresAtUnix: number | null;
  operationalDeadlineUnix: number | null;
  escalationActionType: "MANUAL_ESCALATION" | null;
  actionConfigurationDigest: Sha256Digest;
  settlementPermission: "PROHIBITED" | "PERMITTED";
  settlementConfigurationDigest: Sha256Digest | null;
  executionMode: "EVIDENCE_ONLY";
  digest: Sha256Digest;
}>;

export type GovernanceApprovalEvent = Readonly<{
  schemaVersion: typeof GOVERNANCE_APPROVAL_SCHEMA;
  caseId: Sha256Digest;
  runId: string;
  governedResultDigest: Sha256Digest;
  policyDigest: Sha256Digest;
  proposedActionDigest: Sha256Digest;
  decision: "APPROVED";
  approverRole: ApproverRole;
  approverAuthority: PrototypeAuthority;
  nonce: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  previousEventDigest: Sha256Digest;
  digest: Sha256Digest;
  signature: string;
}>;

export type ActionHistoryEvent = Readonly<{
  schemaVersion: typeof ACTION_HISTORY_SCHEMA;
  ordinal: number;
  caseId: Sha256Digest;
  runId: string;
  fromState: ActionState | null;
  toState: ActionState;
  atUnix: number;
  evidenceDigest: Sha256Digest;
  previousEventDigest: Sha256Digest | null;
  digest: Sha256Digest;
}>;

export type GovernedActionReceipt = Readonly<{
  schemaVersion: typeof ACTION_RECEIPT_SCHEMA;
  caseId: Sha256Digest;
  runId: string;
  governedResult: Readonly<{
    digest: Sha256Digest;
    schemaVersion: "mordant.governed-conflict-result/1";
    semantic: typeof GOVERNED_RESULT_SEMANTIC;
    outcome: "CONFLICT" | "NO_CONFLICT";
    exposedAtUnix: number;
  }>;
  policy: Readonly<{
    policyId: string;
    policyVersion: number;
    digest: Sha256Digest;
  }>;
  selectionEventDigest: Sha256Digest;
  approvalEventDigest: Sha256Digest | null;
  proposedActionDigest: Sha256Digest;
  resultingAction: Readonly<{
    actionType: "RECORD_AND_CLOSE" | "OPEN_CURE_PATH" | "MANUAL_ESCALATION";
    accountableInstitutionalRole: InstitutionalRole;
    operationalDeadlineUnix: number | null;
    escalationActionType: "MANUAL_ESCALATION" | null;
    actionConfigurationDigest: Sha256Digest;
    settlementPermission: "PROHIBITED" | "PERMITTED";
    settlementConfigurationDigest: Sha256Digest | null;
    executionMode: "EVIDENCE_ONLY";
  }>;
  stateTransition: ActionHistoryEvent;
  recorderAuthority: PrototypeAuthority;
  recordedAtUnix: number;
  digest: Sha256Digest;
  signature: string;
}>;

export type PrototypeSigner = Readonly<{
  authority: PrototypeAuthority;
  privateKey: KeyObject;
}>;

export class RecoursePolicyError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "RecoursePolicyError";
  }
}

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function fail(code: string, message: string): never {
  throw new RecoursePolicyError(code, message);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("CANONICAL_NUMBER", "Canonical policy evidence accepts safe integers only");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!isPlainObject(value)) fail("CANONICAL_VALUE", "Canonical policy evidence accepts plain JSON values only");
  const entries = Object.keys(value).sort().map((key) => {
    const member = value[key];
    if (member === undefined) fail("CANONICAL_UNDEFINED", `Undefined member ${key}`);
    return `${JSON.stringify(key)}:${canonicalJson(member)}`;
  });
  return `{${entries.join(",")}}`;
}

export function digestValue(value: unknown): Sha256Digest {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function assertDigest(value: unknown, code: string, label: string): asserts value is Sha256Digest {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) fail(code, `${label} must be a canonical sha256 digest`);
}

function assertNonEmpty(value: unknown, code: string, label: string): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.trim() !== value) fail(code, `${label} must be non-empty and trimmed`);
}

function assertInteger(value: unknown, code: string, label: string, minimum = 0): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) fail(code, `${label} must be an integer >= ${minimum}`);
}

function assertExactKeys(value: unknown, expected: readonly string[], code: string, label: string): asserts value is Record<string, unknown> {
  if (!isPlainObject(value)) fail(code, `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(code, `${label} has a non-closed field set`);
  }
}

function assertEnum<T extends string>(value: unknown, allowed: readonly T[], code: string, label: string): asserts value is T {
  if (typeof value !== "string" || !allowed.includes(value as T)) fail(code, `${label} is not an allowed value`);
}

function publicKeyFromRaw(publicKey: string): KeyObject {
  let raw: Buffer;
  try {
    raw = Buffer.from(publicKey, "base64");
  } catch {
    fail("AUTHORITY_PUBLIC_KEY", "Prototype authority public key is not base64");
  }
  if (raw.length !== 32 || raw.toString("base64") !== publicKey) {
    fail("AUTHORITY_PUBLIC_KEY", "Prototype authority public key must be canonical raw Ed25519 bytes");
  }
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function authorityBody(authority: Omit<PrototypeAuthority, "authorityId">): object {
  return {
    purpose: authority.purpose,
    label: authority.label,
    prototypeAuthority: authority.prototypeAuthority,
    algorithm: authority.algorithm,
    publicKey: authority.publicKey,
  };
}

export function createPrototypeSigner(purpose: AuthorityPurpose, label: string): PrototypeSigner {
  assertNonEmpty(label, "AUTHORITY_LABEL", "Prototype authority label");
  const seed = createHash("sha256")
    .update(`Mordant governed recourse experiment prototype signer/v1/${purpose}/${label}`)
    .digest();
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKey = Buffer.from(spki).subarray(-32).toString("base64");
  const body = { purpose, label, prototypeAuthority: true as const, algorithm: "Ed25519" as const, publicKey };
  return Object.freeze({
    authority: Object.freeze({ authorityId: digestValue(authorityBody(body)), ...body }),
    privateKey,
  });
}

export function assertPrototypeAuthority(value: unknown, expectedPurpose?: AuthorityPurpose): asserts value is PrototypeAuthority {
  assertExactKeys(value, [
    "authorityId", "purpose", "label", "prototypeAuthority", "algorithm", "publicKey",
  ], "AUTHORITY_FIELDS", "Prototype authority");
  assertDigest(value.authorityId, "AUTHORITY_ID", "Prototype authority ID");
  assertEnum(value.purpose, [
    "POLICY_AUTHORITY", "POLICY_SELECTOR", "CREDIT_OPS_APPROVER", "INSTITUTIONAL_REVIEWER", "ACTION_RECORDER",
  ], "AUTHORITY_PURPOSE", "Prototype authority purpose");
  assertNonEmpty(value.label, "AUTHORITY_LABEL", "Prototype authority label");
  if (value.prototypeAuthority !== true || value.algorithm !== "Ed25519") {
    fail("AUTHORITY_CLASS", "Signer must be explicitly labeled as a prototype Ed25519 authority");
  }
  publicKeyFromRaw(value.publicKey as string);
  if (digestValue(authorityBody(value as unknown as Omit<PrototypeAuthority, "authorityId">)) !== value.authorityId) {
    fail("AUTHORITY_ID", "Prototype authority ID does not match its public envelope");
  }
  if (expectedPurpose !== undefined && value.purpose !== expectedPurpose) {
    fail("AUTHORITY_PURPOSE", `Expected ${expectedPurpose}, received ${String(value.purpose)}`);
  }
}

function signEnvelope(domain: string, body: object, signer: PrototypeSigner): string {
  const message = Buffer.from(`${domain}\n${canonicalJson(body)}`, "utf8");
  return signBytes(null, message, signer.privateKey).toString("base64");
}

function verifyEnvelope(domain: string, body: object, authority: PrototypeAuthority, signature: string, code: string): void {
  const bytes = Buffer.from(signature, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== signature) fail(code, "Signature is not canonical Ed25519 base64");
  const message = Buffer.from(`${domain}\n${canonicalJson(body)}`, "utf8");
  if (!verifyBytes(null, message, publicKeyFromRaw(authority.publicKey), bytes)) fail(code, "Signature verification failed");
}

function policyBody(policy: Omit<GovernedRecoursePolicy, "digest" | "signature">): object {
  return {
    schemaVersion: policy.schemaVersion,
    policyId: policy.policyId,
    policyVersion: policy.policyVersion,
    scope: policy.scope,
    acceptedGovernedResult: policy.acceptedGovernedResult,
    effectiveFromUnix: policy.effectiveFromUnix,
    effectiveUntilUnix: policy.effectiveUntilUnix,
    conflictBranch: policy.conflictBranch,
    noConflictBranch: policy.noConflictBranch,
    settlement: policy.settlement,
    policyAuthority: policy.policyAuthority,
  };
}

function assertDeadlineRule(value: unknown): asserts value is DeadlineRule | null {
  if (value === null) return;
  assertExactKeys(value, ["kind", "seconds"], "POLICY_DEADLINE_FIELDS", "Deadline rule");
  if (value.kind !== "RELATIVE_TO_RESULT_EXPOSURE") fail("POLICY_DEADLINE_KIND", "Deadline rule kind is not allowed");
  assertInteger(value.seconds, "POLICY_DEADLINE_SECONDS", "Deadline seconds", 1);
}

function assertEscalationRule(value: unknown): asserts value is EscalationRule | null {
  if (value === null) return;
  assertExactKeys(value, ["trigger", "actionType"], "POLICY_ESCALATION_FIELDS", "Escalation rule");
  if (value.trigger !== "DEADLINE_UNRESOLVED" || value.actionType !== "MANUAL_ESCALATION") {
    fail("POLICY_ESCALATION_RULE", "Only bounded unresolved-deadline manual escalation is allowed");
  }
}

function assertPolicyBranch(value: unknown, outcome: "CONFLICT" | "NO_CONFLICT"): asserts value is PolicyBranch {
  assertExactKeys(value, [
    "governedOutcome", "evaluationActionType", "authorizedActionType", "accountableInstitutionalRole",
    "authorizationMode", "allowedApproverRoles", "approvalWindowSeconds", "deadlineRule", "escalationRule",
    "actionConfigurationDigest",
  ], "POLICY_BRANCH_FIELDS", `${outcome} branch`);
  if (value.governedOutcome !== outcome) fail("POLICY_BRANCH_OUTCOME", `${outcome} branch outcome mismatch`);
  assertEnum(value.evaluationActionType, ["REVIEW_REQUIRED", "RECORD_AND_CLOSE"], "POLICY_EVALUATION_ACTION", "Evaluation action");
  assertEnum(value.authorizedActionType, ["RECORD_AND_CLOSE", "OPEN_CURE_PATH", "MANUAL_ESCALATION"], "POLICY_AUTHORIZED_ACTION", "Authorized action");
  assertEnum(value.accountableInstitutionalRole, INSTITUTIONAL_ROLES, "POLICY_ACCOUNTABLE_ROLE", "Accountable institutional role");
  assertEnum(value.authorizationMode, ["AUTOMATIC_PERMITTED", "HUMAN_APPROVAL_REQUIRED"], "POLICY_AUTHORIZATION_MODE", "Authorization mode");
  if (!Array.isArray(value.allowedApproverRoles)) fail("POLICY_APPROVER_ROLES", "Allowed approver roles must be an array");
  const uniqueRoles = new Set(value.allowedApproverRoles);
  if (uniqueRoles.size !== value.allowedApproverRoles.length) fail("POLICY_APPROVER_ROLES", "Allowed approver roles must be unique");
  for (const role of value.allowedApproverRoles) assertEnum(role, APPROVER_ROLES, "POLICY_APPROVER_ROLE", "Approver role");
  if (value.authorizationMode === "HUMAN_APPROVAL_REQUIRED") {
    if (value.evaluationActionType !== "REVIEW_REQUIRED" || value.allowedApproverRoles.length < 1) {
      fail("POLICY_HUMAN_APPROVAL", "Human approval requires REVIEW_REQUIRED and at least one closed approver role");
    }
    assertInteger(value.approvalWindowSeconds, "POLICY_APPROVAL_WINDOW", "Approval window seconds", 1);
  } else if (
    value.evaluationActionType !== value.authorizedActionType
    || value.allowedApproverRoles.length !== 0
    || value.approvalWindowSeconds !== null
  ) {
    fail("POLICY_AUTOMATIC_BRANCH", "Automatic branch cannot require or simulate approval");
  }
  assertDeadlineRule(value.deadlineRule);
  assertEscalationRule(value.escalationRule);
  if ((value.deadlineRule === null) !== (value.escalationRule === null)) {
    fail("POLICY_ESCALATION_DEADLINE", "Deadline and unresolved escalation rules must appear together");
  }
  assertDigest(value.actionConfigurationDigest, "POLICY_ACTION_CONFIG", "Action configuration digest");
}

export function assertPolicyManifest(policy: unknown): asserts policy is GovernedRecoursePolicy {
  assertExactKeys(policy, [
    "schemaVersion", "policyId", "policyVersion", "scope", "acceptedGovernedResult", "effectiveFromUnix",
    "effectiveUntilUnix", "conflictBranch", "noConflictBranch", "settlement", "policyAuthority", "digest", "signature",
  ], "POLICY_FIELDS", "Governed recourse policy");
  if (policy.schemaVersion !== POLICY_SCHEMA) fail("POLICY_SCHEMA", "Unsupported governed recourse policy schema");
  assertNonEmpty(policy.policyId, "POLICY_ID", "Policy ID");
  if ((policy.policyId as string).startsWith("sha256:")) {
    fail("POLICY_IDENTITY_NAMESPACE", "Governed recourse policy ID must not reuse the governed-result protection policy digest");
  }
  assertInteger(policy.policyVersion, "POLICY_VERSION", "Policy version", 1);
  assertExactKeys(policy.scope, ["programId", "assetClass", "assetIdentity"], "POLICY_SCOPE_FIELDS", "Policy scope");
  if (policy.scope.programId !== EXPERIMENT_PROGRAM_ID || policy.scope.assetClass !== "TOKENIZED_PRIVATE_CREDIT") {
    fail("POLICY_SCOPE", "Policy scope is outside the bounded experiment");
  }
  assertDigest(policy.scope.assetIdentity, "POLICY_ASSET", "Policy asset identity");
  assertExactKeys(policy.acceptedGovernedResult, [
    "semantic", "schemaVersion", "serviceId", "serviceVersion", "releaseMode",
  ], "POLICY_RESULT_FIELDS", "Accepted governed result");
  if (
    policy.acceptedGovernedResult.semantic !== GOVERNED_RESULT_SEMANTIC
    || policy.acceptedGovernedResult.schemaVersion !== "mordant.governed-conflict-result/1"
    || policy.acceptedGovernedResult.serviceId !== "mordant.private-pledge-matching"
    || policy.acceptedGovernedResult.serviceVersion !== 1
    || policy.acceptedGovernedResult.releaseMode !== "governed-decryptor-v1"
  ) fail("POLICY_RESULT_SEMANTIC", "Policy accepts an unsupported governed-result semantic or schema");
  assertInteger(policy.effectiveFromUnix, "POLICY_EFFECTIVE_FROM", "Effective-from time", 1);
  assertInteger(policy.effectiveUntilUnix, "POLICY_EFFECTIVE_UNTIL", "Effective-until time", 1);
  if (Number(policy.effectiveUntilUnix) <= Number(policy.effectiveFromUnix)) fail("POLICY_EFFECTIVE_RANGE", "Policy effective interval is empty");
  assertPolicyBranch(policy.conflictBranch, "CONFLICT");
  assertPolicyBranch(policy.noConflictBranch, "NO_CONFLICT");
  assertExactKeys(policy.settlement, ["permission", "configurationDigest"], "POLICY_SETTLEMENT_FIELDS", "Settlement rule");
  assertEnum(policy.settlement.permission, ["PROHIBITED", "PERMITTED"], "POLICY_SETTLEMENT_PERMISSION", "Settlement permission");
  if (policy.settlement.permission === "PROHIBITED") {
    if (policy.settlement.configurationDigest !== null) fail("POLICY_SETTLEMENT_CONFIG", "Prohibited settlement cannot carry a configuration digest");
  } else {
    assertDigest(policy.settlement.configurationDigest, "POLICY_SETTLEMENT_CONFIG", "Settlement configuration digest");
  }
  assertPrototypeAuthority(policy.policyAuthority, "POLICY_AUTHORITY");
  assertDigest(policy.digest, "POLICY_DIGEST", "Policy digest");
  assertNonEmpty(policy.signature, "POLICY_SIGNATURE", "Policy signature");
}

export function signPolicyManifest(input: UnsignedGovernedRecoursePolicy, signer: PrototypeSigner): GovernedRecoursePolicy {
  if (signer.authority.purpose !== "POLICY_AUTHORITY") fail("POLICY_AUTHORITY", "Policy must be signed by the prototype policy authority");
  const unsigned = { ...input, policyAuthority: signer.authority };
  const digest = digestValue(policyBody(unsigned));
  const policy = {
    ...unsigned,
    digest,
    signature: signEnvelope("MordantGovernedRecoursePolicy/v1", policyBody(unsigned), signer),
  } as GovernedRecoursePolicy;
  verifyPolicyManifest(policy);
  return deepFreeze(policy);
}

export function verifyPolicyManifest(policy: unknown): asserts policy is GovernedRecoursePolicy {
  assertPolicyManifest(policy);
  const body = policyBody(policy);
  if (digestValue(body) !== policy.digest) fail("POLICY_DIGEST", "Policy digest does not match the closed manifest body");
  verifyEnvelope("MordantGovernedRecoursePolicy/v1", body, policy.policyAuthority, policy.signature, "POLICY_SIGNATURE");
}

export function assertPolicyEffective(policy: GovernedRecoursePolicy, atUnix: number): void {
  verifyPolicyManifest(policy);
  assertInteger(atUnix, "POLICY_APPLICABILITY_TIME", "Policy applicability time", 1);
  if (atUnix < policy.effectiveFromUnix) fail("POLICY_NOT_YET_EFFECTIVE", "Policy is not yet effective at applicability time");
  if (atUnix > policy.effectiveUntilUnix) fail("POLICY_EXPIRED", "Policy expired before applicability time");
}

function selectionBody(event: Omit<PolicySelectionEvent, "digest" | "signature">): object {
  return {
    schemaVersion: event.schemaVersion,
    caseId: event.caseId,
    runId: event.runId,
    programId: event.programId,
    policyDigest: event.policyDigest,
    selectedAtUnix: event.selectedAtUnix,
    applicabilityAtUnix: event.applicabilityAtUnix,
    nonce: event.nonce,
    previousEventDigest: event.previousEventDigest,
    selectorAuthority: event.selectorAuthority,
  };
}

export function createPolicySelectionEvent(input: Readonly<{
  caseId: Sha256Digest;
  runId: string;
  policy: GovernedRecoursePolicy;
  selectedAtUnix: number;
  applicabilityAtUnix: number;
  nonce: string;
  previousEventDigest: Sha256Digest;
}>, signer: PrototypeSigner): PolicySelectionEvent {
  if (signer.authority.purpose !== "POLICY_SELECTOR") fail("SELECTOR_AUTHORITY", "Selection requires the prototype selector authority");
  verifyPolicyManifest(input.policy);
  if (input.applicabilityAtUnix !== input.selectedAtUnix) {
    fail("SELECTION_APPLICABILITY", "V1 requires applicability to be fixed at the signed selection time");
  }
  assertPolicyEffective(input.policy, input.applicabilityAtUnix);
  const unsigned = {
    schemaVersion: POLICY_SELECTION_SCHEMA,
    caseId: input.caseId,
    runId: input.runId,
    programId: EXPERIMENT_PROGRAM_ID,
    policyDigest: input.policy.digest,
    selectedAtUnix: input.selectedAtUnix,
    applicabilityAtUnix: input.applicabilityAtUnix,
    nonce: input.nonce,
    previousEventDigest: input.previousEventDigest,
    selectorAuthority: signer.authority,
  } as const;
  const body = selectionBody(unsigned);
  return deepFreeze({
    ...unsigned,
    digest: digestValue(body),
    signature: signEnvelope("MordantPolicySelectionEvent/v1", body, signer),
  });
}

export function verifyPolicySelectionEvent(
  event: unknown,
  policy: GovernedRecoursePolicy,
  resultExposedAtUnix?: number,
): asserts event is PolicySelectionEvent {
  assertExactKeys(event, [
    "schemaVersion", "caseId", "runId", "programId", "policyDigest", "selectedAtUnix", "applicabilityAtUnix",
    "nonce", "previousEventDigest", "selectorAuthority", "digest", "signature",
  ], "SELECTION_FIELDS", "Policy selection event");
  if (event.schemaVersion !== POLICY_SELECTION_SCHEMA || event.programId !== EXPERIMENT_PROGRAM_ID) fail("SELECTION_SCHEMA", "Unsupported selection event");
  assertDigest(event.caseId, "SELECTION_CASE", "Selection case ID");
  assertNonEmpty(event.runId, "SELECTION_RUN", "Selection run ID");
  assertDigest(event.policyDigest, "SELECTION_POLICY", "Selected policy digest");
  assertInteger(event.selectedAtUnix, "SELECTION_TIME", "Selection time", 1);
  assertInteger(event.applicabilityAtUnix, "SELECTION_APPLICABILITY", "Applicability time", 1);
  if (event.applicabilityAtUnix !== event.selectedAtUnix) {
    fail("SELECTION_APPLICABILITY", "V1 requires applicability to be fixed at the signed selection time");
  }
  assertNonEmpty(event.nonce, "SELECTION_NONCE", "Selection nonce");
  assertDigest(event.previousEventDigest, "SELECTION_PREVIOUS", "Selection previous event digest");
  assertPrototypeAuthority(event.selectorAuthority, "POLICY_SELECTOR");
  assertDigest(event.digest, "SELECTION_DIGEST", "Selection digest");
  assertNonEmpty(event.signature, "SELECTION_SIGNATURE", "Selection signature");
  verifyPolicyManifest(policy);
  if (event.policyDigest !== policy.digest) fail("SELECTION_POLICY", "Selection event does not bind this exact policy");
  assertPolicyEffective(policy, event.applicabilityAtUnix);
  if (resultExposedAtUnix !== undefined && event.selectedAtUnix >= resultExposedAtUnix) {
    fail("POST_RESULT_POLICY_SELECTION", "Policy was not selected before the governed result was exposed for this run");
  }
  if (resultExposedAtUnix !== undefined) assertPolicyEffective(policy, resultExposedAtUnix);
  const body = selectionBody(event as unknown as PolicySelectionEvent);
  if (digestValue(body) !== event.digest) fail("SELECTION_DIGEST", "Selection event digest mismatch");
  verifyEnvelope("MordantPolicySelectionEvent/v1", body, event.selectorAuthority, event.signature as string, "SELECTION_SIGNATURE");
}

function proposedActionBody(action: Omit<ProposedAction, "digest">): object {
  return { ...action };
}

export function createProposedAction(input: Readonly<{
  caseId: Sha256Digest;
  runId: string;
  governedResultDigest: Sha256Digest;
  conflict: boolean;
  resultExposedAtUnix: number;
  policy: GovernedRecoursePolicy;
  selection: PolicySelectionEvent;
}>): ProposedAction {
  verifyPolicySelectionEvent(input.selection, input.policy, input.resultExposedAtUnix);
  const branch = input.conflict ? input.policy.conflictBranch : input.policy.noConflictBranch;
  const unsigned = {
    schemaVersion: PROPOSED_ACTION_SCHEMA,
    caseId: input.caseId,
    runId: input.runId,
    governedResultDigest: input.governedResultDigest,
    policyDigest: input.policy.digest,
    selectionEventDigest: input.selection.digest,
    governedOutcome: input.conflict ? "CONFLICT" as const : "NO_CONFLICT" as const,
    evaluationActionType: branch.evaluationActionType,
    actionType: branch.authorizedActionType,
    accountableInstitutionalRole: branch.accountableInstitutionalRole,
    authorizationMode: branch.authorizationMode,
    allowedApproverRoles: [...branch.allowedApproverRoles],
    approvalExpiresAtUnix: branch.approvalWindowSeconds === null
      ? null
      : input.resultExposedAtUnix + branch.approvalWindowSeconds,
    operationalDeadlineUnix: branch.deadlineRule === null
      ? null
      : input.resultExposedAtUnix + branch.deadlineRule.seconds,
    escalationActionType: branch.escalationRule?.actionType ?? null,
    actionConfigurationDigest: branch.actionConfigurationDigest,
    settlementPermission: input.policy.settlement.permission,
    settlementConfigurationDigest: input.policy.settlement.configurationDigest,
    executionMode: "EVIDENCE_ONLY" as const,
  };
  return deepFreeze({ ...unsigned, digest: digestValue(proposedActionBody(unsigned)) });
}

export function verifyProposedAction(action: unknown): asserts action is ProposedAction {
  assertExactKeys(action, [
    "schemaVersion", "caseId", "runId", "governedResultDigest", "policyDigest", "selectionEventDigest",
    "governedOutcome", "evaluationActionType", "actionType", "accountableInstitutionalRole", "authorizationMode",
    "allowedApproverRoles", "approvalExpiresAtUnix", "operationalDeadlineUnix", "escalationActionType",
    "actionConfigurationDigest", "settlementPermission", "settlementConfigurationDigest", "executionMode", "digest",
  ], "PROPOSED_ACTION_FIELDS", "Proposed action");
  if (action.schemaVersion !== PROPOSED_ACTION_SCHEMA) fail("PROPOSED_ACTION_SCHEMA", "Unsupported proposed action schema");
  assertDigest(action.caseId, "PROPOSED_ACTION_CASE", "Proposed action case ID");
  assertNonEmpty(action.runId, "PROPOSED_ACTION_RUN", "Proposed action run ID");
  assertDigest(action.governedResultDigest, "PROPOSED_ACTION_RESULT", "Proposed action result digest");
  assertDigest(action.policyDigest, "PROPOSED_ACTION_POLICY", "Proposed action policy digest");
  assertDigest(action.selectionEventDigest, "PROPOSED_ACTION_SELECTION", "Proposed action selection digest");
  assertEnum(action.governedOutcome, ["CONFLICT", "NO_CONFLICT"], "PROPOSED_ACTION_OUTCOME", "Governed outcome");
  assertEnum(action.evaluationActionType, ["REVIEW_REQUIRED", "RECORD_AND_CLOSE"], "PROPOSED_ACTION_EVALUATION", "Evaluation action");
  assertEnum(action.actionType, ["RECORD_AND_CLOSE", "OPEN_CURE_PATH", "MANUAL_ESCALATION"], "PROPOSED_ACTION_TYPE", "Action type");
  assertEnum(action.accountableInstitutionalRole, INSTITUTIONAL_ROLES, "PROPOSED_ACTION_ROLE", "Accountable role");
  assertEnum(action.authorizationMode, ["AUTOMATIC_PERMITTED", "HUMAN_APPROVAL_REQUIRED"], "PROPOSED_ACTION_MODE", "Authorization mode");
  if (!Array.isArray(action.allowedApproverRoles)) fail("PROPOSED_ACTION_APPROVERS", "Approver roles must be an array");
  for (const role of action.allowedApproverRoles) assertEnum(role, APPROVER_ROLES, "PROPOSED_ACTION_APPROVER", "Approver role");
  if (action.approvalExpiresAtUnix !== null) assertInteger(action.approvalExpiresAtUnix, "PROPOSED_ACTION_APPROVAL_EXPIRY", "Approval expiry", 1);
  if (action.operationalDeadlineUnix !== null) assertInteger(action.operationalDeadlineUnix, "PROPOSED_ACTION_DEADLINE", "Operational deadline", 1);
  if (action.escalationActionType !== null && action.escalationActionType !== "MANUAL_ESCALATION") fail("PROPOSED_ACTION_ESCALATION", "Unsupported escalation action");
  assertDigest(action.actionConfigurationDigest, "PROPOSED_ACTION_CONFIG", "Action configuration digest");
  assertEnum(action.settlementPermission, ["PROHIBITED", "PERMITTED"], "PROPOSED_ACTION_SETTLEMENT", "Settlement permission");
  if (action.settlementPermission === "PERMITTED") {
    assertDigest(action.settlementConfigurationDigest, "PROPOSED_ACTION_SETTLEMENT_CONFIG", "Settlement configuration digest");
  } else if (action.settlementConfigurationDigest !== null) {
    fail("PROPOSED_ACTION_SETTLEMENT_CONFIG", "Prohibited settlement cannot carry configuration");
  }
  if (action.executionMode !== "EVIDENCE_ONLY") fail("PROPOSED_ACTION_EXECUTION", "Experiment actions must remain evidence-only");
  assertDigest(action.digest, "PROPOSED_ACTION_DIGEST", "Proposed action digest");
  const body = { ...(action as unknown as Record<string, unknown>) };
  delete body.digest;
  if (digestValue(proposedActionBody(body as Omit<ProposedAction, "digest">)) !== action.digest) fail("PROPOSED_ACTION_DIGEST", "Proposed action digest mismatch");
}

function approvalBody(event: Omit<GovernanceApprovalEvent, "digest" | "signature">): object {
  return {
    schemaVersion: event.schemaVersion,
    caseId: event.caseId,
    runId: event.runId,
    governedResultDigest: event.governedResultDigest,
    policyDigest: event.policyDigest,
    proposedActionDigest: event.proposedActionDigest,
    decision: event.decision,
    approverRole: event.approverRole,
    approverAuthority: event.approverAuthority,
    nonce: event.nonce,
    issuedAtUnix: event.issuedAtUnix,
    expiresAtUnix: event.expiresAtUnix,
    previousEventDigest: event.previousEventDigest,
  };
}

export function createGovernanceApprovalEvent(input: Readonly<{
  proposedAction: ProposedAction;
  approverRole: ApproverRole;
  nonce: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  previousEventDigest: Sha256Digest;
}>, signer: PrototypeSigner): GovernanceApprovalEvent {
  verifyProposedAction(input.proposedAction);
  if (input.proposedAction.authorizationMode !== "HUMAN_APPROVAL_REQUIRED") {
    fail("APPROVAL_NOT_REQUIRED", "Automatic action cannot carry a fake governance approval");
  }
  if (!input.proposedAction.allowedApproverRoles.includes(input.approverRole)) fail("UNAUTHORIZED_APPROVER", "Approver role is not allowed by the policy branch");
  if (signer.authority.purpose !== input.approverRole) fail("UNAUTHORIZED_APPROVER", "Approver key purpose does not match the claimed role");
  if (input.issuedAtUnix >= input.expiresAtUnix) fail("APPROVAL_TIME", "Approval expiry must follow issue time");
  if (input.proposedAction.approvalExpiresAtUnix === null || input.expiresAtUnix > input.proposedAction.approvalExpiresAtUnix) {
    fail("APPROVAL_TIME", "Approval exceeds the policy-bounded approval window");
  }
  const unsigned = {
    schemaVersion: GOVERNANCE_APPROVAL_SCHEMA,
    caseId: input.proposedAction.caseId,
    runId: input.proposedAction.runId,
    governedResultDigest: input.proposedAction.governedResultDigest,
    policyDigest: input.proposedAction.policyDigest,
    proposedActionDigest: input.proposedAction.digest,
    decision: "APPROVED" as const,
    approverRole: input.approverRole,
    approverAuthority: signer.authority,
    nonce: input.nonce,
    issuedAtUnix: input.issuedAtUnix,
    expiresAtUnix: input.expiresAtUnix,
    previousEventDigest: input.previousEventDigest,
  };
  const body = approvalBody(unsigned);
  return deepFreeze({
    ...unsigned,
    digest: digestValue(body),
    signature: signEnvelope("MordantGovernanceApprovalEvent/v1", body, signer),
  });
}

export function verifyGovernanceApprovalEvent(input: Readonly<{
  event: unknown;
  proposedAction: ProposedAction;
  expectedPreviousEventDigest: Sha256Digest;
  atUnix: number;
  consumedNonces?: ReadonlySet<string>;
}>): asserts input is Readonly<{
  event: GovernanceApprovalEvent;
  proposedAction: ProposedAction;
  expectedPreviousEventDigest: Sha256Digest;
  atUnix: number;
  consumedNonces?: ReadonlySet<string>;
}> {
  const { event } = input;
  verifyProposedAction(input.proposedAction);
  assertExactKeys(event, [
    "schemaVersion", "caseId", "runId", "governedResultDigest", "policyDigest", "proposedActionDigest", "decision",
    "approverRole", "approverAuthority", "nonce", "issuedAtUnix", "expiresAtUnix", "previousEventDigest", "digest", "signature",
  ], "APPROVAL_FIELDS", "Governance approval event");
  if (event.schemaVersion !== GOVERNANCE_APPROVAL_SCHEMA || event.decision !== "APPROVED") fail("APPROVAL_SCHEMA", "Unsupported governance approval event");
  assertDigest(event.caseId, "APPROVAL_CASE", "Approval case ID");
  assertNonEmpty(event.runId, "APPROVAL_RUN", "Approval run ID");
  assertDigest(event.governedResultDigest, "APPROVAL_RESULT", "Approval governed result digest");
  assertDigest(event.policyDigest, "APPROVAL_POLICY", "Approval policy digest");
  assertDigest(event.proposedActionDigest, "APPROVAL_ACTION", "Approval proposed action digest");
  assertEnum(event.approverRole, APPROVER_ROLES, "APPROVAL_ROLE", "Approval role");
  assertPrototypeAuthority(event.approverAuthority, event.approverRole as ApproverRole);
  assertNonEmpty(event.nonce, "APPROVAL_NONCE", "Approval nonce");
  assertInteger(event.issuedAtUnix, "APPROVAL_ISSUED", "Approval issue time", 1);
  assertInteger(event.expiresAtUnix, "APPROVAL_EXPIRY", "Approval expiry time", 1);
  assertDigest(event.previousEventDigest, "APPROVAL_PREVIOUS", "Approval previous event digest");
  assertDigest(event.digest, "APPROVAL_DIGEST", "Approval digest");
  assertNonEmpty(event.signature, "APPROVAL_SIGNATURE", "Approval signature");
  const action = input.proposedAction;
  if (
    event.caseId !== action.caseId
    || event.runId !== action.runId
    || event.governedResultDigest !== action.governedResultDigest
    || event.policyDigest !== action.policyDigest
    || event.proposedActionDigest !== action.digest
  ) fail("APPROVAL_ACTION_BINDING", "Approval does not bind the exact proposed action and its evidence chain");
  if (!action.allowedApproverRoles.includes(event.approverRole as ApproverRole)) fail("UNAUTHORIZED_APPROVER", "Approval role is not allowed by the policy branch");
  if (event.previousEventDigest !== input.expectedPreviousEventDigest) fail("APPROVAL_PREVIOUS", "Approval does not continue the exact action history");
  if (input.atUnix < event.issuedAtUnix || input.atUnix > event.expiresAtUnix) fail("APPROVAL_EXPIRED", "Approval is not valid at authorization time");
  if (input.consumedNonces?.has(event.nonce as string)) fail("APPROVAL_REPLAY", "Approval nonce has already been consumed");
  const body = approvalBody(event as unknown as GovernanceApprovalEvent);
  if (digestValue(body) !== event.digest) fail("APPROVAL_DIGEST", "Approval digest mismatch");
  verifyEnvelope("MordantGovernanceApprovalEvent/v1", body, event.approverAuthority, event.signature as string, "APPROVAL_SIGNATURE");
}

function historyBody(event: Omit<ActionHistoryEvent, "digest">): object {
  return { ...event };
}

export function createActionHistoryEvent(input: Omit<ActionHistoryEvent, "schemaVersion" | "digest">): ActionHistoryEvent {
  const unsigned = { schemaVersion: ACTION_HISTORY_SCHEMA, ...input };
  return deepFreeze({ ...unsigned, digest: digestValue(historyBody(unsigned)) });
}

export function verifyActionHistoryEvent(event: unknown): asserts event is ActionHistoryEvent {
  assertExactKeys(event, [
    "schemaVersion", "ordinal", "caseId", "runId", "fromState", "toState", "atUnix", "evidenceDigest",
    "previousEventDigest", "digest",
  ], "HISTORY_FIELDS", "Action history event");
  if (event.schemaVersion !== ACTION_HISTORY_SCHEMA) fail("HISTORY_SCHEMA", "Unsupported action history schema");
  assertInteger(event.ordinal, "HISTORY_ORDINAL", "History ordinal", 1);
  assertDigest(event.caseId, "HISTORY_CASE", "History case ID");
  assertNonEmpty(event.runId, "HISTORY_RUN", "History run ID");
  if (event.fromState !== null) assertEnum(event.fromState, ACTION_STATES, "HISTORY_FROM", "History from-state");
  assertEnum(event.toState, ACTION_STATES, "HISTORY_TO", "History to-state");
  assertInteger(event.atUnix, "HISTORY_TIME", "History time", 1);
  assertDigest(event.evidenceDigest, "HISTORY_EVIDENCE", "History evidence digest");
  if (event.previousEventDigest !== null) assertDigest(event.previousEventDigest, "HISTORY_PREVIOUS", "History previous digest");
  assertDigest(event.digest, "HISTORY_DIGEST", "History digest");
  const body = { ...(event as unknown as Record<string, unknown>) };
  delete body.digest;
  if (digestValue(historyBody(body as Omit<ActionHistoryEvent, "digest">)) !== event.digest) fail("HISTORY_DIGEST", "History event digest mismatch");
}

function receiptBody(receipt: Omit<GovernedActionReceipt, "digest" | "signature">): object {
  return { ...receipt };
}

export function createGovernedActionReceipt(input: Readonly<{
  proposedAction: ProposedAction;
  policy: GovernedRecoursePolicy;
  selection: PolicySelectionEvent;
  approval: GovernanceApprovalEvent | null;
  governedResultSchema: "mordant.governed-conflict-result/1";
  governedResultSemantic: typeof GOVERNED_RESULT_SEMANTIC;
  governedResultExposedAtUnix: number;
  stateTransition: ActionHistoryEvent;
  recordedAtUnix: number;
}>, signer: PrototypeSigner): GovernedActionReceipt {
  if (signer.authority.purpose !== "ACTION_RECORDER") fail("RECEIPT_AUTHORITY", "Receipt requires the prototype action recorder");
  verifyPolicyManifest(input.policy);
  verifyPolicySelectionEvent(input.selection, input.policy, input.governedResultExposedAtUnix);
  verifyProposedAction(input.proposedAction);
  verifyActionHistoryEvent(input.stateTransition);
  if (input.proposedAction.authorizationMode === "HUMAN_APPROVAL_REQUIRED" && input.approval === null) {
    fail("APPROVAL_REQUIRED", "Human-required action cannot be recorded without exact approval evidence");
  }
  if (input.proposedAction.authorizationMode === "AUTOMATIC_PERMITTED" && input.approval !== null) {
    fail("APPROVAL_NOT_REQUIRED", "Automatic branch cannot carry a fake approval");
  }
  const action = input.proposedAction;
  const unsigned = {
    schemaVersion: ACTION_RECEIPT_SCHEMA,
    caseId: action.caseId,
    runId: action.runId,
    governedResult: {
      digest: action.governedResultDigest,
      schemaVersion: input.governedResultSchema,
      semantic: input.governedResultSemantic,
      outcome: action.governedOutcome,
      exposedAtUnix: input.governedResultExposedAtUnix,
    },
    policy: {
      policyId: input.policy.policyId,
      policyVersion: input.policy.policyVersion,
      digest: input.policy.digest,
    },
    selectionEventDigest: input.selection.digest,
    approvalEventDigest: input.approval?.digest ?? null,
    proposedActionDigest: action.digest,
    resultingAction: {
      actionType: action.actionType,
      accountableInstitutionalRole: action.accountableInstitutionalRole,
      operationalDeadlineUnix: action.operationalDeadlineUnix,
      escalationActionType: action.escalationActionType,
      actionConfigurationDigest: action.actionConfigurationDigest,
      settlementPermission: action.settlementPermission,
      settlementConfigurationDigest: action.settlementConfigurationDigest,
      executionMode: action.executionMode,
    },
    stateTransition: input.stateTransition,
    recorderAuthority: signer.authority,
    recordedAtUnix: input.recordedAtUnix,
  } as const;
  const body = receiptBody(unsigned);
  return deepFreeze({
    ...unsigned,
    digest: digestValue(body),
    signature: signEnvelope("MordantGovernedActionReceipt/v1", body, signer),
  });
}

export function verifyGovernedActionReceipt(input: Readonly<{
  receipt: unknown;
  policy: GovernedRecoursePolicy;
  selection: PolicySelectionEvent;
  approval: GovernanceApprovalEvent | null;
  proposedAction: ProposedAction;
  authorizationEvent: ActionHistoryEvent;
}>): asserts input is Readonly<{
  receipt: GovernedActionReceipt;
  policy: GovernedRecoursePolicy;
  selection: PolicySelectionEvent;
  approval: GovernanceApprovalEvent | null;
  proposedAction: ProposedAction;
  authorizationEvent: ActionHistoryEvent;
}> {
  const { receipt } = input;
  verifyPolicyManifest(input.policy);
  verifyProposedAction(input.proposedAction);
  verifyActionHistoryEvent(input.authorizationEvent);
  assertExactKeys(receipt, [
    "schemaVersion", "caseId", "runId", "governedResult", "policy", "selectionEventDigest", "approvalEventDigest",
    "proposedActionDigest", "resultingAction", "stateTransition", "recorderAuthority", "recordedAtUnix", "digest", "signature",
  ], "RECEIPT_FIELDS", "Governed action receipt");
  if (receipt.schemaVersion !== ACTION_RECEIPT_SCHEMA) fail("RECEIPT_SCHEMA", "Unsupported governed action receipt schema");
  assertDigest(receipt.caseId, "RECEIPT_CASE", "Receipt case ID");
  assertNonEmpty(receipt.runId, "RECEIPT_RUN", "Receipt run ID");
  assertExactKeys(receipt.governedResult, ["digest", "schemaVersion", "semantic", "outcome", "exposedAtUnix"], "RECEIPT_RESULT_FIELDS", "Receipt governed result");
  assertDigest(receipt.governedResult.digest, "RECEIPT_RESULT", "Receipt governed result digest");
  if (
    receipt.governedResult.schemaVersion !== "mordant.governed-conflict-result/1"
    || receipt.governedResult.semantic !== GOVERNED_RESULT_SEMANTIC
  ) fail("RECEIPT_RESULT_SEMANTIC", "Receipt changes the governed-result semantic");
  assertEnum(receipt.governedResult.outcome, ["CONFLICT", "NO_CONFLICT"], "RECEIPT_OUTCOME", "Receipt governed outcome");
  assertInteger(receipt.governedResult.exposedAtUnix, "RECEIPT_RESULT_TIME", "Result exposure time", 1);
  assertExactKeys(receipt.policy, ["policyId", "policyVersion", "digest"], "RECEIPT_POLICY_FIELDS", "Receipt policy reference");
  assertNonEmpty(receipt.policy.policyId, "RECEIPT_POLICY_ID", "Receipt policy ID");
  assertInteger(receipt.policy.policyVersion, "RECEIPT_POLICY_VERSION", "Receipt policy version", 1);
  assertDigest(receipt.policy.digest, "RECEIPT_POLICY", "Receipt policy digest");
  assertDigest(receipt.selectionEventDigest, "RECEIPT_SELECTION", "Receipt selection digest");
  if (receipt.approvalEventDigest !== null) assertDigest(receipt.approvalEventDigest, "RECEIPT_APPROVAL", "Receipt approval digest");
  assertDigest(receipt.proposedActionDigest, "RECEIPT_ACTION", "Receipt proposed action digest");
  assertExactKeys(receipt.resultingAction, [
    "actionType", "accountableInstitutionalRole", "operationalDeadlineUnix", "escalationActionType",
    "actionConfigurationDigest", "settlementPermission", "settlementConfigurationDigest", "executionMode",
  ], "RECEIPT_ACTION_FIELDS", "Receipt resulting action");
  assertEnum(receipt.resultingAction.actionType, ["RECORD_AND_CLOSE", "OPEN_CURE_PATH", "MANUAL_ESCALATION"], "RECEIPT_ACTION_TYPE", "Receipt action type");
  assertEnum(receipt.resultingAction.accountableInstitutionalRole, INSTITUTIONAL_ROLES, "RECEIPT_ACTION_ROLE", "Receipt accountable role");
  if (receipt.resultingAction.operationalDeadlineUnix !== null) assertInteger(receipt.resultingAction.operationalDeadlineUnix, "RECEIPT_DEADLINE", "Receipt deadline", 1);
  if (receipt.resultingAction.escalationActionType !== null && receipt.resultingAction.escalationActionType !== "MANUAL_ESCALATION") fail("RECEIPT_ESCALATION", "Receipt escalation is not allowed");
  assertDigest(receipt.resultingAction.actionConfigurationDigest, "RECEIPT_ACTION_CONFIG", "Receipt action configuration digest");
  assertEnum(receipt.resultingAction.settlementPermission, ["PROHIBITED", "PERMITTED"], "RECEIPT_SETTLEMENT", "Receipt settlement permission");
  if (receipt.resultingAction.settlementPermission === "PERMITTED") {
    assertDigest(receipt.resultingAction.settlementConfigurationDigest, "RECEIPT_SETTLEMENT_CONFIG", "Receipt settlement configuration digest");
  } else if (receipt.resultingAction.settlementConfigurationDigest !== null) fail("RECEIPT_SETTLEMENT_CONFIG", "Prohibited settlement cannot carry configuration");
  if (receipt.resultingAction.executionMode !== "EVIDENCE_ONLY") fail("RECEIPT_EXECUTION", "Receipt may describe evidence-only execution only");
  verifyActionHistoryEvent(receipt.stateTransition);
  assertPrototypeAuthority(receipt.recorderAuthority, "ACTION_RECORDER");
  assertInteger(receipt.recordedAtUnix, "RECEIPT_RECORDED", "Receipt record time", 1);
  assertDigest(receipt.digest, "RECEIPT_DIGEST", "Receipt digest");
  assertNonEmpty(receipt.signature, "RECEIPT_SIGNATURE", "Receipt signature");

  const action = input.proposedAction;
  if (
    receipt.caseId !== action.caseId || receipt.runId !== action.runId
    || receipt.governedResult.digest !== action.governedResultDigest
    || receipt.governedResult.outcome !== action.governedOutcome
    || receipt.policy.policyId !== input.policy.policyId
    || receipt.policy.policyVersion !== input.policy.policyVersion
    || receipt.policy.digest !== input.policy.digest
    || receipt.selectionEventDigest !== input.selection.digest
    || receipt.proposedActionDigest !== action.digest
  ) fail("RECEIPT_EVIDENCE_CHAIN", "Receipt references do not match the exact result, policy, selection, and proposed action");
  verifyPolicySelectionEvent(input.selection, input.policy, receipt.governedResult.exposedAtUnix as number);
  const approvalDigest = input.approval?.digest ?? null;
  if (receipt.approvalEventDigest !== approvalDigest) fail("RECEIPT_APPROVAL", "Receipt approval reference does not match the exact approval object");
  if (action.authorizationMode === "HUMAN_APPROVAL_REQUIRED" && input.approval === null) fail("APPROVAL_REQUIRED", "Receipt is missing required human approval");
  if (action.authorizationMode === "AUTOMATIC_PERMITTED" && input.approval !== null) fail("APPROVAL_NOT_REQUIRED", "Automatic receipt carries a fake approval");
  if (input.approval !== null) {
    verifyGovernanceApprovalEvent({
      event: input.approval,
      proposedAction: action,
      expectedPreviousEventDigest: input.approval.previousEventDigest,
      atUnix: input.authorizationEvent.atUnix,
    });
  }
  const expectedAction = {
    actionType: action.actionType,
    accountableInstitutionalRole: action.accountableInstitutionalRole,
    operationalDeadlineUnix: action.operationalDeadlineUnix,
    escalationActionType: action.escalationActionType,
    actionConfigurationDigest: action.actionConfigurationDigest,
    settlementPermission: action.settlementPermission,
    settlementConfigurationDigest: action.settlementConfigurationDigest,
    executionMode: action.executionMode,
  };
  if (canonicalJson(receipt.resultingAction) !== canonicalJson(expectedAction)) fail("RECEIPT_RESULTING_ACTION", "Receipt action, deadline, or configuration reference was tampered");
  if (
    input.authorizationEvent.toState !== "ACTION_AUTHORIZED"
    || input.authorizationEvent.caseId !== receipt.caseId
    || input.authorizationEvent.runId !== receipt.runId
    || input.authorizationEvent.evidenceDigest !== (input.approval?.digest ?? action.digest)
  ) fail("RECEIPT_AUTHORIZATION_EVENT", "Receipt authorization event does not bind the exact approved or automatic action");
  if (
    receipt.stateTransition.fromState !== "ACTION_AUTHORIZED"
    || receipt.stateTransition.toState !== "ACTION_RECORDED"
    || receipt.stateTransition.previousEventDigest !== input.authorizationEvent.digest
    || receipt.stateTransition.evidenceDigest !== action.digest
    || receipt.stateTransition.caseId !== receipt.caseId
    || receipt.stateTransition.runId !== receipt.runId
    || receipt.stateTransition.atUnix !== receipt.recordedAtUnix
  ) fail("RECEIPT_STATE_TRANSITION", "Receipt does not bind the exact ACTION_AUTHORIZED to ACTION_RECORDED transition");
  const body = receiptBody(receipt as unknown as GovernedActionReceipt);
  const unsignedBody = { ...(body as Record<string, unknown>) };
  delete unsignedBody.digest;
  delete unsignedBody.signature;
  if (digestValue(unsignedBody) !== receipt.digest) fail("RECEIPT_DIGEST", "Receipt digest mismatch");
  verifyEnvelope("MordantGovernedActionReceipt/v1", unsignedBody, receipt.recorderAuthority, receipt.signature as string, "RECEIPT_SIGNATURE");
}

export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const member of Object.values(value as Record<string, unknown>)) deepFreeze(member);
  }
  return value;
}
