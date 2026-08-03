import type { CanonicalSourceClassificationId } from "./protection-evidence";
import type { RecourseState } from "./protection-case";
import type { ProtectionCaseView } from "./governed-fhe-product-server";
import type { PublicProtectionCaseProjection, VerifiedPublicProtectionEvidence } from "./protection-public-view";

/**
 * Public, digest-only projection consumed by the product UI. Keeping this
 * structural prevents the browser from becoming coupled to private execution
 * records when the API starts returning its strict presentation projection.
 */
export type ProtectionEvidencePresentation = VerifiedPublicProtectionEvidence;

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

export function evidenceOutcomeLabel(evidence: ProtectionEvidencePresentation): string {
  return evidence.governedResult.conflict ? "Conflict confirmed" : "No conflict found";
}

export function recoursePresentation(evidence: ProtectionEvidencePresentation): Readonly<{
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

export type LocalStagePresentation = Readonly<{
  stageLabel: string;
  detail: string;
  recourse: Readonly<{ status: RecourseState; label: string }>;
  provisional: boolean;
}>;

export function localStagePresentation(view: ProtectionCaseView): LocalStagePresentation {
  const recourse = recourseStatePresentation(view.protectionCase.recourseState);
  switch (view.stage) {
    case "CASE_CREATED":
      return { stageLabel: "CASE_CREATED", detail: "Durable case created; private-match preparation has not started.", recourse, provisional: true };
    case "MATCH_PREPARED":
      return { stageLabel: "MATCH_PREPARED", detail: "Case-specific key material is prepared; participant submissions are pending.", recourse, provisional: true };
    case "PARTICIPANT_A_SUBMITTED":
    case "PARTICIPANT_B_PUBLISHED":
    case "PARTICIPANT_B_SUBMITTED":
      return { stageLabel: view.stage, detail: "Encrypted synthetic participant submissions are being durably bound.", recourse, provisional: true };
    case "EVALUATED":
      return { stageLabel: "EVALUATED", detail: "The fixed BGV circuit completed; governed recomputation and Boolean release are pending.", recourse, provisional: true };
    case "RELEASED":
      return { stageLabel: "RELEASED", detail: "The governed Boolean is signed; recourse admission has not completed.", recourse, provisional: true };
    case "RECOURSE_OPENED":
      return {
        stageLabel: view.protectionCase.recourseState === "REFUSED" ? "REFUSED" : "RECOURSE_OPENED · CURE_WINDOW",
        detail: view.protectionCase.recourseState === "REFUSED"
          ? "The signed false Boolean refused recourse; final public evidence is not sealed yet."
          : "The local protocol double admitted the recourse record and opened its simulated cure window.",
        recourse,
        provisional: true,
      };
    case "CHRONOLOGY_COMPLETE":
      return { stageLabel: "CHRONOLOGY_COMPLETE", detail: "Simulated cure chronology completed; final public evidence sealing is pending.", recourse, provisional: true };
    case "COMPLETE":
      return {
        stageLabel: "COMPLETE",
        detail: view.evidence === null ? "Backend completion was reported without matching public evidence." : "Final signed public evidence is sealed and available for readback.",
        recourse,
        provisional: view.evidence === null,
      };
    case "ABORTED":
      return { stageLabel: "ABORTED", detail: "The local run stopped and cannot advance without durable reconciliation.", recourse, provisional: true };
  }
}

function record(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null;
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function exactRecord(value: unknown, keys: readonly string[]): value is Readonly<Record<string, unknown>> {
  return record(value) && exactKeys(value, keys);
}

function digest(value: unknown): boolean {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function nullableDigest(value: unknown): boolean {
  return value === null || digest(value);
}

function integer(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value);
}

export function isPublicProtectionCaseProjection(
  value: unknown,
  additionalKeys: readonly string[] = [],
): value is PublicProtectionCaseProjection {
  if (!exactRecord(value, [
    "productScenario", "cleanverseAssetDigest", "cleanverseAsset", "serviceVersion", "protectedAmount", "reserve",
    "holderRecordDate", "holderSnapshot", "holderAllocationDigest", "fheCaseId", "releaseMode", "originalReceivable",
    ...additionalKeys,
  ])) return false;
  const asset = value.cleanverseAsset;
  const amount = value.protectedAmount;
  const reserve = value.reserve;
  const original = value.originalReceivable;
  const holders = value.holderSnapshot;
  if (
    !exactRecord(asset, ["token", "sourceIdentity", "documentationTerms", "tokenDeployment", "issuance"])
    || !exactRecord(asset.token, ["address"])
    || !exactRecord(asset.sourceIdentity, ["cleanverseRequestId"])
    || !exactRecord(asset.documentationTerms, ["version"])
    || !exactRecord(asset.tokenDeployment, ["blockNumber"])
    || !exactRecord(asset.issuance, ["transactionHash"])
    || typeof asset.token.address !== "string"
    || typeof asset.sourceIdentity.cleanverseRequestId !== "string"
    || typeof asset.documentationTerms.version !== "string"
    || typeof asset.tokenDeployment.blockNumber !== "string"
    || typeof asset.issuance.transactionHash !== "string"
    || !exactRecord(amount, ["asset", "minorUnits"])
    || amount.asset !== "aUSDC" || amount.minorUnits !== "100000000"
    || !exactRecord(reserve, ["basisPoints", "minorUnits", "accountingDomain", "executionClassification"])
    || reserve.basisPoints !== 1000 || reserve.minorUnits !== "10000000"
    || reserve.accountingDomain !== "PROTECTION" || reserve.executionClassification !== "PROTOCOL_DOUBLE"
    || !Array.isArray(holders) || holders.length !== 2
    || !holders.every((holder) => exactRecord(holder, ["holderId", "protectedUnits", "allocationBps"])
      && typeof holder.holderId === "string" && typeof holder.protectedUnits === "string" && integer(holder.allocationBps))
    || !exactRecord(original, ["state", "principalMinorUnits", "units", "accountingDomain"])
    || original.state !== "OUTSTANDING_INTACT" || original.principalMinorUnits !== "110000000"
    || original.units !== "100000000" || original.accountingDomain !== "RECEIVABLE"
  ) return false;
  return (
    (value.productScenario === "conflict" || value.productScenario === "no-conflict")
    && digest(value.cleanverseAssetDigest)
    && integer(value.serviceVersion)
    && typeof value.holderRecordDate === "string"
    && digest(value.holderAllocationDigest)
    && digest(value.fheCaseId)
    && value.releaseMode === "governed-decryptor-v1"
  );
}

/**
 * Treat the network response as untrusted even after server cryptographic
 * verification. Every declared projection key is checked recursively and the
 * accepted value is detached before React state can retain it.
 */
export function parseProtectionEvidencePresentation(value: unknown): ProtectionEvidencePresentation | null {
  if (!exactRecord(value, [
    "schemaVersion", "manifestDigest", "runId", "sourceCommit", "governedFheCommit", "scenario",
    "cleanverseAssetDigest", "sourceClassifications", "protectionCase", "protectionAuthorization", "fhe",
    "governedResult", "chronology", "recourse", "recourseAttestation", "originalReceivablePreservation", "execution",
  ])) return null;
  const authorization = value.protectionAuthorization;
  const fhe = value.fhe;
  const governed = value.governedResult;
  const chronology = value.chronology;
  const recourse = value.recourse;
  const recourseAttestation = value.recourseAttestation;
  const preservation = value.originalReceivablePreservation;
  const execution = value.execution;
  if (
    value.schemaVersion !== "mordant.verified-protection-public-view/1"
    || !digest(value.manifestDigest)
    || typeof value.runId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value.runId)
    || typeof value.sourceCommit !== "string" || !/^(?!0{40}$)[0-9a-f]{40}$/u.test(value.sourceCommit)
    || typeof value.governedFheCommit !== "string" || !/^(?!0{40}$)[0-9a-f]{40}$/u.test(value.governedFheCommit)
    || (value.scenario !== "conflict" && value.scenario !== "no-conflict")
    || !digest(value.cleanverseAssetDigest)
    || !Array.isArray(value.sourceClassifications)
    || !value.sourceClassifications.every((entry) => typeof entry === "string" && entry in SOURCE_PRESENTATION)
    || !isPublicProtectionCaseProjection(value.protectionCase)
    || !record(value.protectionCase) || value.protectionCase.productScenario !== value.scenario
    || !exactRecord(authorization, ["bindingDigest", "participantSignatures"])
    || !digest(authorization.bindingDigest)
    || !Array.isArray(authorization.participantSignatures) || authorization.participantSignatures.length !== 2
    || !authorization.participantSignatures.every((signature, index) => exactRecord(signature, ["role", "signature"])
      && signature.role === (index === 0 ? "PARTICIPANT_A" : "PARTICIPANT_B") && typeof signature.signature === "string")
    || !exactRecord(fhe, [
      "caseId", "caseBindingDigest", "profile", "circuitId", "circuitVersion", "participantArtifactDigests",
      "evaluatedArtifactDigest", "resultCiphertextDigest", "independentlyRecomputedResultDigest",
    ])
    || !digest(fhe.caseId) || !digest(fhe.caseBindingDigest)
    || fhe.profile !== "mordant.bgv.identity-full-fhe-256.n15/v1"
    || fhe.circuitId !== "mordant.identity-full-fhe-256" || !integer(fhe.circuitVersion)
    || !Array.isArray(fhe.participantArtifactDigests) || fhe.participantArtifactDigests.length !== 2
    || !fhe.participantArtifactDigests.every(digest)
    || !digest(fhe.evaluatedArtifactDigest) || !digest(fhe.resultCiphertextDigest)
    || !digest(fhe.independentlyRecomputedResultDigest)
    || !exactRecord(governed, ["conflict", "digest", "signature", "releaseAuthorityId", "releaseMode"])
    || typeof governed.conflict !== "boolean" || !digest(governed.digest) || typeof governed.signature !== "string"
    || !digest(governed.releaseAuthorityId) || governed.releaseMode !== "governed-decryptor-v1"
    || !exactRecord(chronology, [
      "clockClass", "signedAtUnix", "simulationAsOfUnix", "cureDeadlineUnix", "finalIncidentState", "finalRecourseState", "events",
    ])
    || (chronology.clockClass !== "SIMULATED_PROTOCOL_CLOCK" && chronology.clockClass !== "REAL_OBSERVED_CLOCK")
    || !integer(chronology.signedAtUnix)
    || (chronology.simulationAsOfUnix !== null && !integer(chronology.simulationAsOfUnix))
    || (chronology.cureDeadlineUnix !== null && !integer(chronology.cureDeadlineUnix))
    || (chronology.finalIncidentState !== "CONFLICT_CONFIRMED" && chronology.finalIncidentState !== "CLEARED")
    || !["AVAILABLE", "SIMULATED_AVAILABLE", "REFUSED"].includes(String(chronology.finalRecourseState))
    || !Array.isArray(chronology.events)
    || !chronology.events.every((event) => exactRecord(event, ["ordinal", "kind", "atUnix"])
      && integer(event.ordinal) && typeof event.kind === "string" && (event.atUnix === null || integer(event.atUnix)))
    || !exactRecord(recourse, ["opened", "refusedReason", "recordDigest", "resultDigest"])
    || typeof recourse.opened !== "boolean"
    || (recourse.refusedReason !== null && recourse.refusedReason !== "SIGNED_RESULT_FALSE")
    || !nullableDigest(recourse.recordDigest) || !nullableDigest(recourse.resultDigest)
    || !exactRecord(recourseAttestation, ["digest", "attestation"]) || !digest(recourseAttestation.digest)
    || !exactRecord(recourseAttestation.attestation, [
      "signature", "chronologyDigest", "finalIncidentState", "finalRecourseState", "clockClass", "simulationAsOfUnix",
    ])
    || typeof recourseAttestation.attestation.signature !== "string"
    || !digest(recourseAttestation.attestation.chronologyDigest)
    || (recourseAttestation.attestation.finalIncidentState !== "CONFLICT_CONFIRMED"
      && recourseAttestation.attestation.finalIncidentState !== "CLEARED")
    || !["AVAILABLE", "SIMULATED_AVAILABLE", "REFUSED"].includes(String(recourseAttestation.attestation.finalRecourseState))
    || (recourseAttestation.attestation.clockClass !== "SIMULATED_PROTOCOL_CLOCK"
      && recourseAttestation.attestation.clockClass !== "REAL_OBSERVED_CLOCK")
    || (recourseAttestation.attestation.simulationAsOfUnix !== null && !integer(recourseAttestation.attestation.simulationAsOfUnix))
    || !exactRecord(preservation, [
      "state", "principalMinorUnits", "units", "reserveAccountingSeparate", "claimBurnedOrTransferredByProtection",
    ])
    || preservation.state !== "OUTSTANDING_INTACT" || preservation.principalMinorUnits !== "110000000"
    || preservation.units !== "100000000" || preservation.reserveAccountingSeparate !== true
    || preservation.claimBurnedOrTransferredByProtection !== false
    || !exactRecord(execution, ["fhe", "deployment", "release", "recourse", "productionIsolationProven"])
    || execution.fhe !== "REAL_BGV_FHE" || execution.deployment !== "LOCAL_SINGLE_HOST"
    || execution.release !== "GOVERNED_DECRYPTOR" || execution.recourse !== "LOCAL_PROTOCOL_DOUBLE"
    || execution.productionIsolationProven !== false
  ) return null;
  return structuredClone(value) as ProtectionEvidencePresentation;
}

export function isProtectionEvidencePresentation(value: unknown): value is ProtectionEvidencePresentation {
  return parseProtectionEvidencePresentation(value) !== null;
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
  imported: ProtectionEvidencePresentation | null,
  localView: ProtectionCaseView | null,
): ProtectionEvidencePresentation | null {
  if (mode === "imported") return imported;
  if (localView === null) return null;
  const local = localView.evidence;
  return local !== null && local !== undefined
    && local.runId === localView.runId
    && local.protectionCase.fheCaseId === localView.protectionCase.fheCaseId
    ? local
    : null;
}
