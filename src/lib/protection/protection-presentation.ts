import type { CanonicalSourceClassificationId, MordantProtectionEvidence } from "./protection-evidence";
import type { RecourseState } from "./protection-case";
import type { ProtectionCaseView } from "./governed-fhe-product-server";

export const PRODUCT_EXECUTION_LABELS = Object.freeze({
  fhe: "Real BGV FHE · local single-host execution",
  web: "Imported completed evidence · public readback",
  recourse: "Local protocol double · no Cleanverse settlement transaction",
  asset: "Cleanverse issuance · live-observed retained record",
});

export const PRIVATE_CONFLICT_STEPS = Object.freeze([
  "Case authorized",
  "Participant A submitted encrypted pledge",
  "Participant B submitted encrypted pledge",
  "FHE evaluation complete",
  "Governed recomputation verified",
  "Final Boolean released",
]);

export function evidenceOutcomeLabel(evidence: MordantProtectionEvidence): string {
  return evidence.governedResult.conflict ? "Conflict confirmed" : "No conflict found";
}

export function recoursePresentation(evidence: MordantProtectionEvidence): Readonly<{
  status: RecourseState;
  label: string;
}> {
  return recourseStatePresentation(evidence.recourseAttestation.attestation.finalRecourseState);
}

export function recourseStatePresentation(status: RecourseState): Readonly<{ status: RecourseState; label: string }> {
  switch (status) {
    case "NOT_OPEN": return { status, label: "Recourse not opened" };
    case "CURE_WINDOW": return { status, label: "Cure / dispute window open" };
    case "AVAILABLE": return { status, label: "Governed recourse available after cure chronology" };
    case "SIMULATED_AVAILABLE": return { status, label: "Simulated protocol clock · recourse would be available after cure" };
    case "REFUSED": return { status, label: "Recourse refused — signed Boolean is false" };
  }
}

export const SOURCE_PRESENTATION: Readonly<Record<CanonicalSourceClassificationId, Readonly<{
  classification: string;
  subject: string;
  detail: string;
}>>> = Object.freeze({
  CLEANVERSE_M11_LIVE_OBSERVED: { classification: "LIVE OBSERVED", subject: "Cleanverse MINV01 asset record", detail: "Retained M-11 issuance and readback evidence" },
  CLEANVERSE_TERMS_DOCUMENTED: { classification: "DOCUMENTED", subject: "Cleanverse documentation version", detail: "Versioned local transcription; not classified as on-chain" },
  N15_GOVERNED_FHE_LOCAL_EXECUTION: { classification: "LOCAL EXECUTION", subject: "N15 BGV evaluation and governed release", detail: "Real single-host subprocess execution" },
  RECOURSE_LOCAL_PROTOCOL_DOUBLE: { classification: "PROTOCOL DOUBLE", subject: "Recourse admission and chronology", detail: "Local adapter; no live settlement" },
  SYNTHETIC_PROTECTED_PLEDGE_FIXTURE: { classification: "FIXTURE", subject: "Protected amount and private pledge contents", detail: "Synthetic hackathon scenario" },
  PRODUCTION_CUSTODY_UNPROVEN: { classification: "UNPROVEN", subject: "Legal issuer identity and production custody", detail: "Not established by retained evidence" },
});

export const CHRONOLOGY_PRESENTATION: Readonly<Record<string, Readonly<{ label: string; classification: string }>>> = Object.freeze({
  PROTECTED_HOLDER_SNAPSHOT_FIXED: { label: "Protected holder snapshot fixed at its signed record date", classification: "PROTECTION BINDING" },
  FHE_CASE_CREATED: { label: "Authorized FHE case created", classification: "SIGNED CASE CLOCK" },
  PARTICIPANT_A_ARTIFACT_BOUND: { label: "Participant A encrypted artifact bound", classification: "ORDERED · NO AUTHORITATIVE TIME" },
  PARTICIPANT_B_ARTIFACT_BOUND: { label: "Participant B encrypted artifact bound", classification: "ORDERED · NO AUTHORITATIVE TIME" },
  FHE_EVALUATION_BOUND: { label: "Fixed N15 evaluation artifact bound", classification: "ORDERED · NO AUTHORITATIVE TIME" },
  GOVERNED_RESULT_RELEASED: { label: "Governed Boolean released and signed", classification: "SIGNED RELEASE CLOCK" },
  RECOURSE_BOUND: { label: "Recourse record durably bound", classification: "DURABLE RECOURSE CLOCK" },
  SIMULATED_CURE_WINDOW_COMPLETED: { label: "Simulated protocol clock advanced beyond cure deadline", classification: "SIMULATION · NOT OBSERVED WALL TIME" },
  CURE_WINDOW_COMPLETED: { label: "Cure window completed", classification: "REAL OBSERVED CLOCK" },
  RECOURSE_REFUSED_BY_SIGNED_FALSE: { label: "Recourse refused by signed false result", classification: "SIGNED RELEASE CLOCK" },
});

export function evidenceForDisplayedCase(
  mode: "imported" | "local",
  imported: MordantProtectionEvidence,
  localView: ProtectionCaseView | null,
): MordantProtectionEvidence | null {
  if (mode === "imported") return imported;
  if (localView === null) return null;
  const local = localView.evidence;
  return local !== null && local !== undefined
    && local.runId === localView.runId
    && local.protectionCase.fheCaseId === localView.protectionCase.fheCaseId
    ? local
    : null;
}
