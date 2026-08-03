import type { MordantProtectionEvidence } from "./protection-evidence";
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
  return recourseStatePresentation(evidence.protectionCase.recourseState);
}

export function recourseStatePresentation(status: RecourseState): Readonly<{ status: RecourseState; label: string }> {
  switch (status) {
    case "NOT_OPEN": return { status, label: "Recourse not opened" };
    case "CURE_WINDOW": return { status, label: "Cure / dispute window open" };
    case "AVAILABLE": return { status, label: "Governed recourse available after cure chronology" };
    case "REFUSED": return { status, label: "Recourse refused — signed Boolean is false" };
  }
}

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
