/**
 * Presentation adapter for the capability that is qualified in production today:
 * managed combined intake.
 *
 * The worker shape below is a UI-owned mirror of the fields the deployed service
 * already returns. It is re-validated here rather than trusted, and nothing is
 * inferred: a field the worker has not produced stays null, and no outcome
 * wording is derived from anything other than a governed release that exists.
 */

import {
  ONCHAIN_NOT_CONNECTED,
  ausdcFromAtomic,
  buildStages,
  intakeMode,
  stageOrderFor,
  INTAKE_DISCLOSURE,
  type CapabilitySet,
  type DecisionRail,
  type ExecutionStageId,
  type GovernedRelease,
  type LayeredReceipt,
  type LiveProductState,
  type LiveProductViewModel,
  type ParticipantClaimView,
  type RecourseDecision,
  type EligibilityView,
  type WalletView,
} from "./live-product-view-model";
import {
  classifyCustomReceiptDisclosures,
} from "../../lib/custom-supervised-receipt-disclosures";

export type ManagedWorkerStage =
  | "CASE_CREATED"
  | "MATCH_PREPARED"
  | "PARTICIPANT_A_SUBMITTED"
  | "PARTICIPANT_B_PUBLISHED"
  | "PARTICIPANT_B_SUBMITTED"
  | "EVALUATED"
  | "RELEASED"
  | "RECOURSE_OPENED"
  | "CHRONOLOGY_COMPLETE"
  | "COMPLETE"
  | "ABORTED";

export type ManagedWorkerView = Readonly<{
  schemaVersion: string;
  runId: string;
  executionVariant: "CUSTOM_SUPERVISED";
  stage: ManagedWorkerStage;
  nextOperation: string | null;
  terminalScenario: "conflict" | "no-conflict" | null;
  protectionCase: Readonly<{
    cleanverseAssetDigest: string;
    fheCaseId: string;
    incidentState: string;
    recourseState: string;
    cureDeadline: string | null;
  }>;
  participantArtifactDigests: Readonly<{ participantA: string | null; participantB: string | null }>;
  evaluatedArtifactDigest: string | null;
  governedResult: null | Readonly<{ conflict: boolean; digest: string; releaseMode: string }>;
  recourse: null | Readonly<{ opened: boolean; reason: string | null }>;
  receipt: Readonly<Record<string, unknown>> | null;
}>;

const WORKER_SCHEMA = "mordant.live-worker/1";
const CUSTOM_VIEW_SCHEMA = "mordant.custom-supervised-protection-view/1";
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const MANAGED_STAGES: readonly ManagedWorkerStage[] = Object.freeze([
  "CASE_CREATED",
  "MATCH_PREPARED",
  "PARTICIPANT_A_SUBMITTED",
  "PARTICIPANT_B_PUBLISHED",
  "PARTICIPANT_B_SUBMITTED",
  "EVALUATED",
  "RELEASED",
  "RECOURSE_OPENED",
  "CHRONOLOGY_COMPLETE",
  "COMPLETE",
  "ABORTED",
]);
const INCIDENT_STATES = Object.freeze([
  "AUTHORIZED", "PRIVATE_MATCH_OPEN", "EVALUATED", "CONFLICT_CONFIRMED", "CLEARED",
] as const);
const RECOURSE_STATES = Object.freeze([
  "NOT_OPEN", "CURE_WINDOW", "AVAILABLE", "SIMULATED_AVAILABLE", "REFUSED",
] as const);
const FORBIDDEN_PUBLIC_VIEW_KEYS = Object.freeze([
  "activeFrom", "activeUntil", "supervisedPledgeWindows", "pledges", "admittedClaims", "claim", "productScenario",
]);
const CUSTOM_RECEIPT_SCHEMA = "mordant.custom-supervised-protection-receipt/1" as const;
const CUSTOM_BINDING_SCHEMA = "mordant.protection-binding/2" as const;
const FHE_CIRCUIT = "mordant.identity-full-fhe-256" as const;
const FHE_PARAMETER_PROFILE = "mordant.bgv.identity-full-fhe-256.n15/v1" as const;
const SOURCE_COMMIT = /^(?!0{40}$)[0-9a-f]{40}$/u;
const RECEIPT_CLOCK_CLASSES = Object.freeze(["SIMULATED_PROTOCOL_CLOCK", "REAL_OBSERVED_CLOCK"] as const);
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isIsoInstant(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function carriesForbiddenViewKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(carriesForbiddenViewKey);
  if (!record(value)) return false;
  for (const [key, nestedValue] of Object.entries(value)) {
    if ((FORBIDDEN_PUBLIC_VIEW_KEYS as readonly string[]).includes(key) || carriesForbiddenViewKey(nestedValue)) return true;
  }
  return false;
}

function positiveUnix(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function digest(value: unknown): value is string {
  return typeof value === "string" && SHA256_DIGEST.test(value);
}

type ReceiptExpectation = Readonly<{
  runId: string;
  fheCaseId: string;
  participantA: string;
  participantB: string;
  evaluated: string;
  conflict: boolean;
  governedDigest: string;
  incidentState: string;
  recourseState: string;
}>;

function receiptEvent(value: unknown, ordinal: number, kind: string, atUnix: "positive" | "null"): boolean {
  if (!exactRecord(value, ["ordinal", "kind", "atUnix"]) || value.ordinal !== ordinal || value.kind !== kind) return false;
  return atUnix === "positive" ? positiveUnix(value.atUnix) : value.atUnix === null;
}

/**
 * The terminal custom receipt is an authenticated public artifact in its own
 * schema. Do not forward a loosely-shaped object to the receipt renderer: every
 * member, nested member, enum, digest and cross-reference is closed here.
 */
function parseCustomSupervisedReceipt(
  value: unknown,
  expected: ReceiptExpectation,
): Readonly<Record<string, unknown>> | null {
  if (!exactRecord(value, [
    "schemaVersion", "receiptDigest", "runId", "sourceCommit", "governedFheCommit", "executionVariant",
    "authorization", "execution", "governedResult", "terminal", "chronology", "disclosures",
  ])) return null;
  if (value.schemaVersion !== CUSTOM_RECEIPT_SCHEMA || !digest(value.receiptDigest) || value.runId !== expected.runId
    || typeof value.sourceCommit !== "string" || !SOURCE_COMMIT.test(value.sourceCommit)
    || typeof value.governedFheCommit !== "string" || !SOURCE_COMMIT.test(value.governedFheCommit)
    || value.executionVariant !== "CUSTOM_SUPERVISED") return null;

  if (!exactRecord(value.authorization, ["protectionBindingSchema", "protectionBindingDigest", "fheCaseId", "caseBindingDigest"])
    || value.authorization.protectionBindingSchema !== CUSTOM_BINDING_SCHEMA
    || !digest(value.authorization.protectionBindingDigest)
    || value.authorization.fheCaseId !== expected.fheCaseId
    || !digest(value.authorization.caseBindingDigest)) return null;

  if (!exactRecord(value.execution, [
    "participantArtifactDigests", "evaluatedArtifactDigest", "evaluatorProvenance", "decryptorProvenance", "circuitId", "parameterProfile",
  ]) || !Array.isArray(value.execution.participantArtifactDigests) || value.execution.participantArtifactDigests.length !== 2
    || value.execution.participantArtifactDigests[0] !== expected.participantA
    || value.execution.participantArtifactDigests[1] !== expected.participantB
    || !digest(value.execution.participantArtifactDigests[0]) || !digest(value.execution.participantArtifactDigests[1])
    || value.execution.evaluatedArtifactDigest !== expected.evaluated || !digest(value.execution.evaluatedArtifactDigest)
    || !digest(value.execution.evaluatorProvenance) || !digest(value.execution.decryptorProvenance)
    || value.execution.circuitId !== FHE_CIRCUIT || value.execution.parameterProfile !== FHE_PARAMETER_PROFILE) return null;

  if (!exactRecord(value.governedResult, [
    "conflict", "digest", "releaseMode", "releaseOrdinal", "resultCiphertextDigest", "independentlyRecomputedResultDigest",
  ]) || value.governedResult.conflict !== expected.conflict || value.governedResult.digest !== expected.governedDigest
    || !digest(value.governedResult.digest) || value.governedResult.releaseMode !== "governed-decryptor-v1"
    || value.governedResult.releaseOrdinal !== 1 || !digest(value.governedResult.resultCiphertextDigest)
    || value.governedResult.independentlyRecomputedResultDigest !== value.governedResult.resultCiphertextDigest) return null;

  if (!exactRecord(value.terminal, [
    "incidentState", "recourseState", "recourseOpened", "recourseRefusal", "recourseRecordDigest", "originalReceivableState",
  ]) || value.terminal.incidentState !== expected.incidentState || value.terminal.recourseState !== expected.recourseState
    || value.terminal.recourseOpened !== expected.conflict || value.terminal.originalReceivableState !== "OUTSTANDING_INTACT") return null;
  if (expected.conflict) {
    if (value.terminal.recourseRefusal !== null || !digest(value.terminal.recourseRecordDigest)) return null;
  } else if (value.terminal.recourseRefusal !== "SIGNED_RESULT_FALSE" || value.terminal.recourseRecordDigest !== null) return null;

  if (!exactRecord(value.chronology, ["clockClass", "signedAtUnix", "events"])
    || typeof value.chronology.clockClass !== "string"
    || !(RECEIPT_CLOCK_CLASSES as readonly string[]).includes(value.chronology.clockClass)
    || !positiveUnix(value.chronology.signedAtUnix) || !Array.isArray(value.chronology.events)) return null;
  const events = value.chronology.events;
  const common = receiptEvent(events[0], 1, "PROTECTED_HOLDER_SNAPSHOT_FIXED", "positive")
    && receiptEvent(events[1], 2, "FHE_CASE_CREATED", "positive")
    && receiptEvent(events[2], 3, "PARTICIPANT_A_ARTIFACT_BOUND", "null")
    && receiptEvent(events[3], 4, "PARTICIPANT_B_ARTIFACT_BOUND", "null")
    && receiptEvent(events[4], 5, "FHE_EVALUATION_BOUND", "null")
    && receiptEvent(events[5], 6, "GOVERNED_RESULT_RELEASED", "positive");
  if (!common) return null;
  if (expected.conflict) {
    const finalKind = value.chronology.clockClass === "SIMULATED_PROTOCOL_CLOCK"
      ? "SIMULATED_CURE_WINDOW_COMPLETED"
      : "CURE_WINDOW_COMPLETED";
    if (events.length !== 8 || !receiptEvent(events[6], 7, "RECOURSE_BOUND", "positive")
      || !receiptEvent(events[7], 8, finalKind, "positive")) return null;
  } else if (events.length !== 7 || !receiptEvent(events[6], 7, "RECOURSE_REFUSED_BY_SIGNED_FALSE", "positive")) return null;

  if (classifyCustomReceiptDisclosures(value.disclosures) === null) return null;

  return value;
}

/**
 * Browser-owned exact parser for the public worker projection. The runtime has a
 * matching server parser, but the browser must still reject a malformed or
 * over-broad response instead of rendering whatever a network boundary sent.
 */
export function parseManagedWorkerView(value: unknown): ManagedWorkerView | null {
  if (!exactRecord(value, [
    "schemaVersion", "runId", "executionVariant", "stage", "nextOperation", "terminalScenario",
    "protectionCase", "participantArtifactDigests", "evaluatedArtifactDigest", "governedResult", "recourse", "receipt",
  ])) return null;
  if (value.schemaVersion !== CUSTOM_VIEW_SCHEMA || value.executionVariant !== "CUSTOM_SUPERVISED") return null;
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId)) return null;
  if (typeof value.stage !== "string" || !(MANAGED_STAGES as readonly string[]).includes(value.stage)) return null;
  if (value.nextOperation !== null && (typeof value.nextOperation !== "string" || value.nextOperation.length === 0 || value.nextOperation.length > 120)) return null;
  if (value.terminalScenario !== null && value.terminalScenario !== "conflict" && value.terminalScenario !== "no-conflict") return null;

  if (!exactRecord(value.protectionCase, ["cleanverseAssetDigest", "fheCaseId", "incidentState", "recourseState", "cureDeadline"])) return null;
  if (!SHA256_DIGEST.test(String(value.protectionCase.cleanverseAssetDigest)) || !SHA256_DIGEST.test(String(value.protectionCase.fheCaseId))) return null;
  if (typeof value.protectionCase.incidentState !== "string" || !(INCIDENT_STATES as readonly string[]).includes(value.protectionCase.incidentState)) return null;
  if (typeof value.protectionCase.recourseState !== "string" || !(RECOURSE_STATES as readonly string[]).includes(value.protectionCase.recourseState)) return null;
  if (value.protectionCase.cureDeadline !== null && !isIsoInstant(value.protectionCase.cureDeadline)) return null;

  if (!exactRecord(value.participantArtifactDigests, ["participantA", "participantB"])) return null;
  for (const digest of [value.participantArtifactDigests.participantA, value.participantArtifactDigests.participantB, value.evaluatedArtifactDigest]) {
    if (digest !== null && (typeof digest !== "string" || !SHA256_DIGEST.test(digest))) return null;
  }

  let governedResult: ManagedWorkerView["governedResult"] = null;
  if (value.governedResult !== null) {
    if (!exactRecord(value.governedResult, ["conflict", "digest", "releaseMode"])) return null;
    if (typeof value.governedResult.conflict !== "boolean" || typeof value.governedResult.digest !== "string"
      || !SHA256_DIGEST.test(value.governedResult.digest) || value.governedResult.releaseMode !== "governed-decryptor-v1") return null;
    governedResult = Object.freeze({
      conflict: value.governedResult.conflict,
      digest: value.governedResult.digest,
      releaseMode: value.governedResult.releaseMode,
    });
  }

  let recourse: ManagedWorkerView["recourse"] = null;
  if (value.recourse !== null) {
    if (!exactRecord(value.recourse, ["opened", "reason"])) return null;
    if (typeof value.recourse.opened !== "boolean" || (value.recourse.reason !== null && value.recourse.reason !== "SIGNED_RESULT_FALSE")) return null;
    recourse = Object.freeze({ opened: value.recourse.opened, reason: value.recourse.reason });
  }
  if (governedResult === null) {
    if (value.terminalScenario !== null || recourse !== null || value.receipt !== null) return null;
  } else {
    if (value.terminalScenario !== (governedResult.conflict ? "conflict" : "no-conflict")) return null;
    if (!governedResult.conflict && recourse?.opened === true) return null;
  }
  if (value.stage === "ABORTED" && governedResult !== null) return null;
  if (value.stage === "COMPLETE" && (governedResult === null || value.receipt === null)) return null;
  if (value.receipt !== null && (value.stage !== "COMPLETE" || governedResult === null
    || value.participantArtifactDigests.participantA === null || value.participantArtifactDigests.participantB === null
    || value.evaluatedArtifactDigest === null)) return null;
  const receipt = value.receipt === null ? null : parseCustomSupervisedReceipt(value.receipt, {
    runId: value.runId,
    fheCaseId: value.protectionCase.fheCaseId as string,
    participantA: value.participantArtifactDigests.participantA as string,
    participantB: value.participantArtifactDigests.participantB as string,
    evaluated: value.evaluatedArtifactDigest as string,
    conflict: governedResult?.conflict ?? false,
    governedDigest: governedResult?.digest ?? "",
    incidentState: value.protectionCase.incidentState as string,
    recourseState: value.protectionCase.recourseState as string,
  });
  if (value.receipt !== null && receipt === null) return null;
  if (carriesForbiddenViewKey(value)) return null;

  return Object.freeze({
    schemaVersion: CUSTOM_VIEW_SCHEMA,
    runId: value.runId,
    executionVariant: "CUSTOM_SUPERVISED",
    stage: value.stage as ManagedWorkerStage,
    nextOperation: value.nextOperation as string | null,
    terminalScenario: value.terminalScenario as "conflict" | "no-conflict" | null,
    protectionCase: Object.freeze({
      cleanverseAssetDigest: value.protectionCase.cleanverseAssetDigest as string,
      fheCaseId: value.protectionCase.fheCaseId as string,
      incidentState: value.protectionCase.incidentState as string,
      recourseState: value.protectionCase.recourseState as string,
      cureDeadline: value.protectionCase.cureDeadline as string | null,
    }),
    participantArtifactDigests: Object.freeze({
      participantA: value.participantArtifactDigests.participantA as string | null,
      participantB: value.participantArtifactDigests.participantB as string | null,
    }),
    evaluatedArtifactDigest: value.evaluatedArtifactDigest as string | null,
    governedResult,
    recourse,
    receipt,
  });
}

/** Exact public envelope used by the managed worker's create and read routes. */
export function parseManagedCaseEnvelope(value: unknown): ManagedWorkerView | null {
  if (!exactRecord(value, ["schemaVersion", "view", "progress"])) return null;
  if (value.schemaVersion !== WORKER_SCHEMA || typeof value.progress !== "string" || value.progress.trim() === "" || value.progress.length > 160) return null;
  return parseManagedWorkerView(value.view);
}

/** Fixed for this MVP and shown as such. Not derived from a browser value. */
const PROTECTED_ATOMIC = "100000000";
const RESERVE_ATOMIC = "10000000";
const ASSET_LABEL = "MINV01 · Cleanverse receivable";

const STAGE_INDEX: Readonly<Record<string, number>> = Object.freeze({
  CASE_CREATED: 0,
  MATCH_PREPARED: 1,
  PARTICIPANT_A_SUBMITTED: 2,
  PARTICIPANT_B_PUBLISHED: 3,
  PARTICIPANT_B_SUBMITTED: 3,
  // EVALUATED proves the BGV artifact exists. The next visible phase is
  // governed verification; it is never presented as an evaluation still running.
  EVALUATED: 5,
  RELEASED: 5,
  RECOURSE_OPENED: 6,
  CHRONOLOGY_COMPLETE: 6,
  COMPLETE: 7,
});

const PRIVACY_NOTE =
  "This window is sent to Mordant's managed execution service, which prepares its encryption. "
  + "The FHE evaluator receives ciphertexts only.";

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function nested(receipt: Readonly<Record<string, unknown>>, key: string): Record<string, unknown> {
  const value = receipt[key];
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

/**
 * The single place a product state is decided. Every branch is driven by a field
 * the worker has actually produced.
 */
export function managedProductState(
  view: ManagedWorkerView | null,
  local: Readonly<{ eligibility: EligibilityView["state"]; claimsAuthored: boolean; notice: LiveProductState | null }>,
): LiveProductState {
  if (local.notice !== null) return local.notice;
  if (view === null) {
    if (local.eligibility === "CHECKING") return "ELIGIBILITY_CHECKING";
    if (local.eligibility === "REFUSED") return "ELIGIBILITY_REFUSED";
    if (local.eligibility === "VERIFIED") return local.claimsAuthored ? "CASE_READY" : "CLAIM_A_REQUIRED";
    if (local.eligibility === "ERROR") return "ELIGIBILITY_REQUIRED";
    return "ELIGIBILITY_REQUIRED";
  }

  const released = view.governedResult !== null;
  if (view.stage === "ABORTED") return "EXECUTION_FAILED";
  if (view.stage === "COMPLETE" && view.receipt !== null) return "RECEIPT_SEALED";
  if (released) {
    if (view.governedResult!.conflict) {
      return view.recourse?.opened === true ? "CURE_OPEN" : "CONFLICT_REVEALED";
    }
    return view.recourse !== null && view.recourse.opened === false ? "RECOURSE_REFUSED" : "NO_CONFLICT_REVEALED";
  }
  switch (view.stage) {
    case "CASE_CREATED": return "CASE_READY";
    case "MATCH_PREPARED": return "PREPARING_ENCRYPTION";
    case "PARTICIPANT_A_SUBMITTED": return "PARTICIPANT_A_ENCRYPTED";
    case "PARTICIPANT_B_PUBLISHED":
    case "PARTICIPANT_B_SUBMITTED": return "PARTICIPANT_B_ENCRYPTED";
    case "EVALUATED": return "ENCRYPTED_EVALUATION";
    // `ManagedWorkerView` is already a closed union. Keeping this branch
    // fail-closed protects callers that bypass a parser with a type assertion.
    default: return "EXECUTION_FAILED";
  }
}

function decisionRailFor(
  release: GovernedRelease | null,
  recourse: RecourseDecision | null,
): DecisionRail | null {
  if (release === null) return null;
  if (release.conflict) {
    return Object.freeze({
      nextDecision: "Apply approved cure policy after conflict review",
      responsibleNow: recourse?.responsible ?? "Policy / human review required",
      deadlineIso: recourse?.cureDeadlineIso ?? null,
      deadlineNote: recourse?.cureDeadlineIso === null || recourse?.cureDeadlineIso === undefined
        ? "Approved policy or human review must set any deadline."
        : null,
      consequence: "If approved policy opens a cure window, its configured consequence applies when that window closes unresolved.",
      receiptAvailable: true,
    });
  }
  return Object.freeze({
    nextDecision: "No recourse action is available",
    responsibleNow: null,
    deadlineIso: null,
    deadlineNote: "Configured policy opens no cure window when the submitted windows do not conflict.",
    consequence: "The governed result established no conflict between the submitted windows, so this demo recourse policy does not open a cure path.",
    receiptAvailable: true,
  });
}

function layeredReceipt(receipt: Readonly<Record<string, unknown>> | null, release: GovernedRelease | null): LayeredReceipt | null {
  if (receipt === null) return null;
  const authorization = nested(receipt, "authorization");
  const execution = nested(receipt, "execution");
  const governed = nested(receipt, "governedResult");
  const terminal = nested(receipt, "terminal");
  const artifacts = Array.isArray(execution.participantArtifactDigests) ? execution.participantArtifactDigests : [];
  const disclosureVersion = classifyCustomReceiptDisclosures(receipt.disclosures);

  const summary = [
    { label: "Decision", value: release === null ? "Not released" : release.conflict ? "Conflict confirmed" : "No conflict" },
    {
      label: "Consequence",
      value: text(terminal.recourseRecordDigest) === null
        ? "Configured policy did not open recourse."
        : "Configured recourse policy opened a cure window.",
    },
    {
      label: "Result authority",
      value: "Governed signed Boolean · conflict/no-conflict between the submitted windows only",
    },
    {
      label: "Recourse authority",
      value: "Configured demo policy determines the path; approved policy or human review determine action owner, deadline and escalation.",
    },
    { label: "Asset", value: ASSET_LABEL },
    { label: "Participants", value: "Participant A and Participant B" },
    { label: "Terminal state", value: `${text(terminal.incidentState) ?? "not present"} · ${text(terminal.recourseState) ?? "not present"}` },
    { label: "Original receivable", value: text(terminal.originalReceivableState) ?? "not present" },
  ];

  const technical = [
    { label: "Execution variant", value: text(receipt.executionVariant) ?? "not present" },
    { label: "FHE CaseID", value: text(authorization.fheCaseId) ?? "not present" },
    { label: "Protection-binding digest", value: text(authorization.protectionBindingDigest) ?? "not present" },
    { label: "Case-binding digest", value: text(authorization.caseBindingDigest) ?? "not present" },
    { label: "Participant A artifact digest", value: text(artifacts[0]) ?? "not present" },
    { label: "Participant B artifact digest", value: text(artifacts[1]) ?? "not present" },
    { label: "Evaluated artifact digest", value: text(execution.evaluatedArtifactDigest) ?? "not present" },
    { label: "Governed result digest", value: text(governed.digest) ?? "not present" },
    { label: "Result ciphertext digest", value: text(governed.resultCiphertextDigest) ?? "not present" },
    { label: "Evaluator provenance", value: text(execution.evaluatorProvenance) ?? "not present" },
    { label: "Decryptor provenance", value: text(execution.decryptorProvenance) ?? "not present" },
    { label: "Recourse record digest", value: text(terminal.recourseRecordDigest) ?? "Governed result established no window conflict" },
    { label: "Receipt digest", value: text(receipt.receiptDigest) ?? "not present" },
  ];

  const rawContext = disclosureVersion === "LEGACY"
    ? "Immutable legacy receipt: its digest covers the original wording shown below. That wording is not the current product boundary; the governed signed Boolean is authoritative only for conflict/no-conflict. Configured demo policy determines recourse, while approved policy or human review determine action ownership, deadlines and escalation."
    : "The raw projection is preserved exactly as covered by its receipt digest. The governed signed Boolean is authoritative only for conflict/no-conflict; configured demo policy determines recourse, while approved policy or human review determine action ownership, deadlines and escalation.";

  return Object.freeze({
    summary: Object.freeze(summary),
    technical: Object.freeze(technical),
    rawContext,
    raw: receipt,
  });
}

function claim(
  role: "A" | "B",
  digest: string | null,
  admitted: boolean,
): ParticipantClaimView {
  return Object.freeze({
    role,
    label: role === "A" ? "Participant A" : "Participant B",
    admission: admitted ? "ADMITTED" : "NOT_REQUIRED",
    wallet: null,
    eligibilityVerified: false,
    artifactDigest: digest,
    privacyNote: PRIVACY_NOTE,
  });
}

export function adaptManagedIntake(input: Readonly<{
  view: ManagedWorkerView | null;
  capabilitySet: CapabilitySet;
  eligibility: EligibilityView;
  wallet: WalletView | null;
  claimsAuthored: boolean;
  elapsedSeconds: number | null;
  notice: LiveProductViewModel["notice"];
  noticeState: LiveProductState | null;
}>): LiveProductViewModel {
  const { view, capabilitySet, eligibility, wallet, claimsAuthored, elapsedSeconds } = input;
  const mode = intakeMode(capabilitySet);
  const order: readonly ExecutionStageId[] = stageOrderFor(mode);
  const reached = view === null || view.stage === "ABORTED" ? -1 : STAGE_INDEX[view.stage] ?? -1;

  const release: GovernedRelease | null = view?.governedResult ?? null;
  const recourse: RecourseDecision | null = view?.recourse == null ? null : Object.freeze({
    opened: view.recourse.opened,
    reason: view.recourse.reason,
    // The public worker projection does not carry an approved action owner.
    responsible: null,
    cureDeadlineIso: text(view.protectionCase.cureDeadline ?? null),
    consequence: view.recourse.opened
      ? "The configured recourse policy opened a cure window; its consequence applies if that window closes unresolved."
      : "The governed result established no conflict between the submitted windows.",
  });

  const state = managedProductState(view, {
    eligibility: eligibility.state,
    claimsAuthored,
    notice: input.noticeState,
  });
  const abortedNotice: LiveProductViewModel["notice"] = view?.stage !== "ABORTED"
    ? null
    : {
      title: "This execution stopped before a result was released.",
      body: "No outcome or recourse decision is shown. The run must be reconciled before a new check is started.",
      retryable: false,
    };

  const model: LiveProductViewModel = Object.freeze({
    state,
    capabilities: capabilitySet,
    intake: mode,
    intakeDisclosure: INTAKE_DISCLOSURE[mode],

    runId: view?.runId ?? null,
    caseId: view?.protectionCase.fheCaseId ?? null,
    assetDigest: view?.protectionCase.cleanverseAssetDigest ?? null,
    assetLabel: ASSET_LABEL,
    protectedAmount: ausdcFromAtomic(PROTECTED_ATOMIC),
    reserveAmount: ausdcFromAtomic(RESERVE_ATOMIC),

    wallet,
    eligibility,

    claimA: claim("A", view?.participantArtifactDigests.participantA ?? null, reached >= 2),
    claimB: claim("B", view?.participantArtifactDigests.participantB ?? null, reached >= 3),
    directAdmission: null,
    activeRole: null,
    handoffRequired: false,

    stages: view === null ? [] : buildStages(order, reached),
    elapsedSeconds,
    expectation: view === null || release !== null
      ? null
      : "This usually takes about thirty seconds and can take longer under load.",

    release,
    recourse,
    decisionRail: decisionRailFor(release, recourse),

    // The on-chain capability is not qualified, so the adapter never fabricates one.
    onchain: ONCHAIN_NOT_CONNECTED,
    receipt: layeredReceipt(view?.receipt ?? null, release),

    notice: input.notice ?? abortedNotice,
  });

  return model;
}
