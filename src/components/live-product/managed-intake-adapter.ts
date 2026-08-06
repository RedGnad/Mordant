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
  executionVariant: string;
  stage: string;
  terminalScenario: "conflict" | "no-conflict" | null;
  protectionCase: Readonly<{
    cleanverseAssetDigest: string;
    fheCaseId: string;
    incidentState: string;
    recourseState: string;
    cureDeadline?: string | null;
  }>;
  participantArtifactDigests: Readonly<{ participantA: string | null; participantB: string | null }>;
  evaluatedArtifactDigest: string | null;
  governedResult: null | Readonly<{ conflict: boolean; digest: string; releaseMode: string }>;
  recourse: null | Readonly<{ opened: boolean; reason: string | null }>;
  receipt: Readonly<Record<string, unknown>> | null;
}>;

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
  EVALUATED: 4,
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
    default: return "GOVERNED_VERIFICATION";
  }
}

function decisionRailFor(
  release: GovernedRelease | null,
  recourse: RecourseDecision | null,
): DecisionRail | null {
  if (release === null) return null;
  if (release.conflict) {
    return Object.freeze({
      nextDecision: "Cure the conflict before the deadline",
      responsibleNow: recourse?.responsible ?? "The conflicting pledge holder",
      deadlineIso: recourse?.cureDeadlineIso ?? null,
      deadlineNote: recourse?.cureDeadlineIso === null || recourse?.cureDeadlineIso === undefined
        ? "The signed recourse record carries the deadline."
        : null,
      consequence: "If the cure window closes unresolved, the reserved protection becomes claimable.",
      receiptAvailable: true,
    });
  }
  return Object.freeze({
    nextDecision: "No recourse action is available",
    responsibleNow: null,
    deadlineIso: null,
    deadlineNote: "No cure window opens for a cleared case.",
    consequence: "The signed result cleared the case, so no protection is claimable and the receivable is unchanged.",
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

  const summary = [
    { label: "Decision", value: release === null ? "Not released" : release.conflict ? "Conflict confirmed" : "No conflict" },
    {
      label: "Consequence",
      value: text(terminal.recourseRecordDigest) === null
        ? "Recourse refused. Nothing is claimable."
        : "Recourse opened. A cure window applies.",
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
    { label: "Recourse record digest", value: text(terminal.recourseRecordDigest) ?? "Signed result cleared the case" },
    { label: "Receipt digest", value: text(receipt.receiptDigest) ?? "not present" },
  ];

  return Object.freeze({ summary: Object.freeze(summary), technical: Object.freeze(technical), raw: receipt });
}

function claim(
  role: "A" | "B",
  digest: string | null,
  admitted: boolean,
): ParticipantClaimView {
  return Object.freeze({
    role,
    label: role === "A" ? "Participant A" : "Participant B",
    // The managed intake never re-renders a submitted window: the values leave
    // rendered state at admission and are not read back.
    window: null,
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
  const reached = view === null ? -1 : STAGE_INDEX[view.stage] ?? 0;

  const release: GovernedRelease | null = view?.governedResult ?? null;
  const recourse: RecourseDecision | null = view?.recourse == null ? null : Object.freeze({
    opened: view.recourse.opened,
    reason: view.recourse.reason,
    responsible: view.recourse.opened ? "The conflicting pledge holder" : null,
    cureDeadlineIso: text(view.protectionCase.cureDeadline ?? null),
    consequence: view.recourse.opened
      ? "If the cure window closes unresolved, the reserved protection becomes claimable."
      : "The signed result cleared the case.",
  });

  const state = managedProductState(view, {
    eligibility: eligibility.state,
    claimsAuthored,
    notice: input.noticeState,
  });

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

    notice: input.notice,
  });

  return model;
}
