import type { MordantProtectionEvidence } from "./protection-evidence";

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
  status: "AVAILABLE" | "REFUSED";
  label: string;
}> {
  return evidence.recourse.opened
    ? { status: "AVAILABLE", label: "Governed recourse available after cure chronology" }
    : { status: "REFUSED", label: "Recourse refused — signed Boolean is false" };
}
