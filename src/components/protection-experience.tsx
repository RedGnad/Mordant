"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
} from "react";

import {
  CHRONOLOGY_PRESENTATION,
  PRIVATE_CONFLICT_STEPS,
  SOURCE_PRESENTATION,
  evidenceForDisplayedCase,
  isPublicProtectionCaseProjection,
  localStagePresentation,
  parseProtectionEvidencePresentation,
  recoursePresentation,
  recourseStatePresentation,
  type ProtectionEvidencePresentation,
} from "@/lib/protection/protection-presentation";
import type { ProductScenario } from "@/lib/protection/protection-case";
import {
  PROTECTION_RECOVERY_STORAGE_KEY,
  parseProtectionBrowserRecovery,
  pendingCreationRecovery,
  pendingMutationRecovery,
  retentionRequiredRecovery,
  type ProtectionBrowserRecovery,
} from "@/lib/protection/protection-browser-recovery";
import type { ProtectionCaseView } from "@/lib/protection/governed-fhe-product-server";

import { PublicHeader } from "./public-shell";
import styles from "./protection-experience.module.css";

const IMPORTED_ENDPOINT = "/api/protection/conflicting-pledge";
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EXECUTION_STAGES = new Set([
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

type RequestState = "idle" | "loading" | "creating" | "executing" | "resuming" | "retaining";
type HistoryMode = "none" | "push" | "replace";
type UrlAuthority = Readonly<{
  scenario: ProductScenario;
  runId: string | null;
  error: string | null;
}>;
type ReadbackRequirement = Readonly<{
  runId: string;
  scenario: ProductScenario;
  operation: string;
  operationLabel: string;
}>;
type RetentionRequiredView = Readonly<{
  schemaVersion: "mordant.protection-retention-required/1";
  status: "RETENTION_REQUIRED";
  runId: string;
  scenario: ProductScenario;
  recoveryOperation: "retainProtectionEvidence";
}>;

const STAGE_INDEX: Readonly<Record<ProtectionCaseView["stage"], number>> = {
  CASE_CREATED: 0,
  MATCH_PREPARED: 0,
  PARTICIPANT_A_SUBMITTED: 1,
  PARTICIPANT_B_PUBLISHED: 2,
  PARTICIPANT_B_SUBMITTED: 2,
  EVALUATED: 3,
  RELEASED: 5,
  RECOURSE_OPENED: 5,
  CHRONOLOGY_COMPLETE: 5,
  COMPLETE: 5,
  ABORTED: 0,
};

const OPERATION: Readonly<Record<string, Readonly<{ api: string; label: string; support: string; waiting: string }>>> = {
  preparePrivateMatch: {
    api: "preparePrivateMatch",
    label: "Prepare private match",
    support: "Runs the disk preflight, fixes the holder snapshot, and creates the case-specific N15 key.",
    waiting: "Preparing the case-specific N15 key after the durable disk preflight.",
  },
  "submitParticipantPledge:PARTICIPANT_A": {
    api: "submitParticipantA",
    label: "Submit participant A",
    support: "Encrypts participant A’s synthetic pledge in its participant process.",
    waiting: "Participant A is encrypting and binding its synthetic pledge fixture.",
  },
  "submitParticipantPledge:PARTICIPANT_B": {
    api: "submitParticipantB",
    label: "Submit participant B",
    support: "Encrypts participant B’s synthetic pledge and seals the immutable case manifest.",
    waiting: "Participant B is encrypting its fixture and sealing the immutable case manifest.",
  },
  evaluatePrivateConflict: {
    api: "evaluatePrivateConflict",
    label: "Evaluate private conflict",
    support: "Runs the one fixed BGV circuit. This is the longest local step.",
    waiting: "The evaluator is running the fixed BGV circuit. This is normally the longest stage.",
  },
  releaseGovernedResult: {
    api: "releaseGovernedResult",
    label: "Verify and release Boolean",
    support: "The designated decryptor recomputes the circuit, releases one Boolean, and signs it.",
    waiting: "The trusted designated decryptor is recomputing, releasing, and signing one Boolean.",
  },
  openRecourseCase: {
    api: "openRecourseCase",
    label: "Apply retained local rule",
    support: "Verifies the historical retained-case pins and records its local protocol-double branch.",
    waiting: "The local recourse protocol double is verifying the signed-result pins.",
  },
  completeCureChronology: {
    api: "completeCureChronology",
    label: "Simulate cure-window completion",
    support: "Requests the fixed simulated-protocol-clock branch. The signer chooses and authenticates the simulation time.",
    waiting: "The fixed simulated protocol clock is completing the cure chronology.",
  },
  exportProtectionEvidence: {
    api: "exportProtectionEvidence",
    label: "Seal public evidence",
    support: "Exports the public digest-only protection manifest for independent readback.",
    waiting: "The backend is sealing and verifying the public digest-only evidence projection.",
  },
};

const TRUTH_FACTS = Object.freeze([
  "Real observed provenance · retained Cleanverse / Monad testnet asset identity",
  "Local off-chain BGV · synthetic pledge and lender fixtures · no real funds or submissions",
  "Simulated cure time · local recourse protocol double · no live settlement",
  "Trusted designated decryptor · not native Monad FHE, threshold, or trustless release",
]);

function compact(value: string, leading = 11, trailing = 9): string {
  return value.length <= leading + trailing + 1 ? value : `${value.slice(0, leading)}…${value.slice(-trailing)}`;
}

function formatAmount(value: string): string {
  const raw = BigInt(value);
  return `${raw / 1_000_000n}.${((raw % 1_000_000n) / 10_000n).toString().padStart(2, "0")}`;
}

function record(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null;
}

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function exactRecord(value: unknown, expected: readonly string[]): value is Readonly<Record<string, unknown>> {
  return record(value) && exactKeys(value, expected);
}

function digest(value: unknown): boolean {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function parseImportedView(value: unknown): ProtectionEvidencePresentation | null {
  if (!exactRecord(value, ["schemaVersion", "presentation", "evidence"])) return null;
  if (
    value.schemaVersion !== "mordant.protection-imported-view/1"
    || value.presentation !== "IMPORTED_COMPLETED_EVIDENCE"
  ) return null;
  return parseProtectionEvidencePresentation(value.evidence);
}

function parseProtectionCaseView(value: unknown, runId?: string, scenario?: ProductScenario): ProtectionCaseView | null {
  if (!exactRecord(value, [
    "schemaVersion", "runId", "stage", "nextOperation", "protectionCase", "participantArtifactDigests",
    "evaluatedArtifactDigest", "governedResult", "recourse", "evidence", "execution",
  ])) return null;
  const protectionCase = value.protectionCase;
  const participantDigests = value.participantArtifactDigests;
  const governedResult = value.governedResult;
  const recourse = value.recourse;
  const execution = value.execution;
  const projectedEvidence = value.evidence === null ? null : parseProtectionEvidencePresentation(value.evidence);
  if (!record(protectionCase)) return null;
  const provisionalCase: Readonly<Record<string, unknown>> = protectionCase;
  if (
    value.schemaVersion !== "mordant.protection-product-view/1"
    || typeof value.runId !== "string"
    || !RUN_ID.test(value.runId)
    || (runId !== undefined && value.runId !== runId)
    || typeof value.stage !== "string"
    || !EXECUTION_STAGES.has(value.stage)
    || (value.nextOperation !== null && (typeof value.nextOperation !== "string" || OPERATION[value.nextOperation] === undefined))
    || !isPublicProtectionCaseProjection(protectionCase, ["incidentState", "cureDeadline", "recourseState"])
    || !["AUTHORIZED", "PRIVATE_MATCH_OPEN", "EVALUATED", "CONFLICT_CONFIRMED", "CLEARED"].includes(String(provisionalCase.incidentState))
    || (provisionalCase.cureDeadline !== null && typeof provisionalCase.cureDeadline !== "string")
    || !["NOT_OPEN", "CURE_WINDOW", "AVAILABLE", "SIMULATED_AVAILABLE", "REFUSED"].includes(String(provisionalCase.recourseState))
    || (scenario !== undefined && protectionCase.productScenario !== scenario)
    || !exactRecord(participantDigests, ["participantA", "participantB"])
    || (participantDigests.participantA !== null && !digest(participantDigests.participantA))
    || (participantDigests.participantB !== null && !digest(participantDigests.participantB))
    || (value.evaluatedArtifactDigest !== null && !digest(value.evaluatedArtifactDigest))
    || (governedResult !== null && (
      !exactRecord(governedResult, ["conflict", "digest", "releaseMode"])
      || typeof governedResult.conflict !== "boolean" || !digest(governedResult.digest)
      || governedResult.releaseMode !== "governed-decryptor-v1"
    ))
    || (recourse !== null && (
      !exactRecord(recourse, ["opened", "reason"])
      || typeof recourse.opened !== "boolean"
      || (recourse.reason !== null && recourse.reason !== "SIGNED_RESULT_FALSE")
    ))
    || (value.evidence !== null && projectedEvidence === null)
    || (projectedEvidence !== null && (
      projectedEvidence.runId !== value.runId
      || projectedEvidence.scenario !== protectionCase.productScenario
      || projectedEvidence.protectionCase.fheCaseId !== protectionCase.fheCaseId
    ))
    || !exactRecord(execution, ["fhe", "deployment", "webPresentation", "recourse"])
    || execution.fhe !== "REAL_BGV_FHE" || execution.deployment !== "LOCAL_SINGLE_HOST"
    || execution.webPresentation !== "PUBLIC_EVIDENCE_READBACK" || execution.recourse !== "LOCAL_PROTOCOL_DOUBLE"
  ) return null;
  return structuredClone(value) as ProtectionCaseView;
}

function parseRetentionRequiredView(
  value: unknown,
  runId: string,
  scenario: ProductScenario,
): RetentionRequiredView | null {
  if (!exactRecord(value, ["schemaVersion", "status", "runId", "scenario", "recoveryOperation"])) return null;
  if (
    value.schemaVersion !== "mordant.protection-retention-required/1"
    || value.status !== "RETENTION_REQUIRED"
    || value.runId !== runId
    || value.scenario !== scenario
    || value.recoveryOperation !== "retainProtectionEvidence"
  ) return null;
  return structuredClone(value) as RetentionRequiredView;
}

function parseRetainedProtectionView(
  value: unknown,
  runId: string,
  scenario: ProductScenario,
): ProtectionEvidencePresentation | null {
  if (!exactRecord(value, ["schemaVersion", "runId", "scenario", "caseId", "manifestDigest", "evidence"])) return null;
  const evidence = parseProtectionEvidencePresentation(value.evidence);
  if (
    value.schemaVersion !== "mordant.retained-protection-view/1"
    || value.runId !== runId
    || value.scenario !== scenario
    || evidence === null
    || evidence.runId !== runId
    || evidence.scenario !== scenario
    || value.caseId !== evidence.fhe.caseId
    || value.manifestDigest !== evidence.manifestDigest
  ) return null;
  return evidence;
}

class ProtectionResponseFailure extends Error {
  readonly notAdmitted: Readonly<{ runId: string; operation: string }> | null;

  constructor(message: string, notAdmitted: Readonly<{ runId: string; operation: string }> | null) {
    super(message);
    this.name = "ProtectionResponseFailure";
    this.notAdmitted = notAdmitted;
  }
}

async function responseBody(response: Response): Promise<unknown> {
  let value: unknown;
  try {
    value = await response.json() as unknown;
  } catch (error) {
    if (!response.ok) {
      throw new ProtectionResponseFailure("Protection backend returned a non-JSON refusal.", null);
    }
    throw error;
  }
  if (!response.ok) {
    const correlatedNotAdmitted = response.status >= 400 && response.status < 500
      && exactRecord(value, ["schemaVersion", "mutationAdmission", "runId", "operation", "error"])
      && value.schemaVersion === "mordant.local-mutation-error/1"
      && value.mutationAdmission === "NOT_ADMITTED"
      && typeof value.runId === "string"
      && RUN_ID.test(value.runId)
      && typeof value.operation === "string"
      && Object.values(OPERATION).some((operation) => operation.api === value.operation)
      && typeof value.error === "string"
      && value.error.length > 0
      ? { runId: value.runId, operation: value.operation }
      : null;
    throw new ProtectionResponseFailure(
      record(value) && typeof value.error === "string" ? value.error : "Protection backend refused the operation.",
      correlatedNotAdmitted,
    );
  }
  return value;
}

type SupervisedWindowsInput = Readonly<{
  participantA: Readonly<{ activeFrom: number; activeUntil: number }>;
  participantB: Readonly<{ activeFrom: number; activeUntil: number }>;
}>;

const CUSTOM_WINDOW_FIELDS = [
  { key: "aFrom", label: "Participant A pledge start", role: "participantA", bound: "activeFrom" },
  { key: "aUntil", label: "Participant A pledge end", role: "participantA", bound: "activeUntil" },
  { key: "bFrom", label: "Participant B pledge start", role: "participantB", bound: "activeFrom" },
  { key: "bUntil", label: "Participant B pledge end", role: "participantB", bound: "activeUntil" },
] as const;

type CustomWindowKey = (typeof CUSTOM_WINDOW_FIELDS)[number]["key"];

/**
 * Mirrors the server validator. This is operator convenience only: the
 * authoritative rejection happens server-side, and the governed Boolean, not
 * this form, decides the outcome.
 */
function parseCustomWindows(
  values: Readonly<Record<CustomWindowKey, string>>,
): Readonly<{ windows: SupervisedWindowsInput | null; invalid: ReadonlySet<CustomWindowKey>; message: string | null }> {
  const invalid = new Set<CustomWindowKey>();
  const parsed: Partial<Record<CustomWindowKey, number>> = {};
  for (const field of CUSTOM_WINDOW_FIELDS) {
    const raw = values[field.key].trim();
    const value = /^\d+$/u.test(raw) ? Number(raw) : Number.NaN;
    if (!Number.isSafeInteger(value) || value < 0) invalid.add(field.key);
    else parsed[field.key] = value;
  }
  if (invalid.size > 0) {
    return { windows: null, invalid, message: "Each bound must be a whole number, zero or greater. Decimals, signs and text are refused." };
  }
  const windows: SupervisedWindowsInput = {
    participantA: { activeFrom: parsed.aFrom!, activeUntil: parsed.aUntil! },
    participantB: { activeFrom: parsed.bFrom!, activeUntil: parsed.bUntil! },
  };
  for (const [role, keys] of [["A", ["aFrom", "aUntil"]], ["B", ["bFrom", "bUntil"]]] as const) {
    const from = parsed[keys[0]]!;
    const until = parsed[keys[1]]!;
    if (from >= until) {
      keys.forEach((key) => invalid.add(key));
      return { windows: null, invalid, message: `Participant ${role} must start strictly before it ends.` };
    }
  }
  return { windows, invalid, message: null };
}

function writeProtectionUrl(mode: Exclude<HistoryMode, "none">, scenario: ProductScenario, runId: string | null): void {
  if (typeof window === "undefined") return;
  const params = new URLSearchParams({ scenario });
  if (runId !== null) params.set("runId", runId);
  window.history[mode === "push" ? "pushState" : "replaceState"](null, "", `${window.location.pathname}?${params.toString()}`);
}

function readProtectionUrl(search: string): UrlAuthority {
  const params = new URLSearchParams(search);
  const unknown = [...params.keys()].find((key) => key !== "scenario" && key !== "runId");
  const scenarios = params.getAll("scenario");
  const runIds = params.getAll("runId");
  const rawScenario = scenarios[0] ?? null;
  const scenario: ProductScenario = rawScenario === "no-conflict" ? "no-conflict" : "conflict";
  if (unknown !== undefined || scenarios.length > 1 || (rawScenario !== null && rawScenario !== "conflict" && rawScenario !== "no-conflict")) {
    return { scenario, runId: null, error: "The protection scenario URL is invalid. Choose Conflict or No conflict." };
  }
  if (runIds.length > 1 || (runIds[0] !== undefined && !RUN_ID.test(runIds[0])) || (runIds[0] !== undefined && rawScenario === null)) {
    return { scenario, runId: null, error: "The durable local run URL is invalid. A run requires its validated scenario and run identifier." };
  }
  return { scenario, runId: runIds[0] ?? null, error: null };
}

function adapterUrl(origin: string, authority?: Readonly<{ runId?: string; creationRequestId?: string }>): string {
  const url = new URL(origin);
  if (authority?.runId !== undefined) url.searchParams.set("runId", authority.runId);
  if (authority?.creationRequestId !== undefined) url.searchParams.set("creationRequestId", authority.creationRequestId);
  return url.toString();
}

function operationLabel(operation: string): string {
  return Object.values(OPERATION).find((candidate) => candidate.api === operation)?.label
    ?? (operation === "retainProtectionEvidence" ? "evidence retention" : "interrupted local operation");
}

function focusableElements(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(
    "button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
  )).filter((element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true");
}

function EvidenceValue({ label, value, copyable = true }: {
  readonly label: string;
  readonly value: string;
  readonly copyable?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  async function copyValue() {
    if (typeof navigator === "undefined" || navigator.clipboard === undefined) return;
    await navigator.clipboard.writeText(value);
    setCopied(true);
  }
  return (
    <div>
      <dt>{label}</dt>
      <dd><code>{value}</code></dd>
      {copyable ? (
        <button className={styles.copyButton} type="button" onClick={() => void copyValue()} aria-label={`Copy ${label}`}>
          {copied ? "Copied" : "Copy"}
        </button>
      ) : <span className={styles.absentValue}>No digest exists</span>}
      <span className={styles.copyStatus} aria-live="polite">{copied ? `${label} copied exactly.` : ""}</span>
    </div>
  );
}

function EvidenceDrawer({ evidence, onClose, returnFocus }: {
  readonly evidence: ProtectionEvidencePresentation;
  readonly onClose: () => void;
  readonly returnFocus: HTMLButtonElement | null;
}) {
  const drawerRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeRef.current?.focus({ preventScroll: true });
    return () => returnFocus?.focus({ preventScroll: true });
  }, [returnFocus]);

  function handleKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab" || drawerRef.current === null) return;
    const focusable = focusableElements(drawerRef.current);
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }
    const first = focusable[0];
    const last = focusable.at(-1) ?? first;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  const refusal = "ABSENT — signed false Boolean refused recourse; no recourse record was created.";
  const rows = [
    ["Evidence verification", "VERIFIED", true],
    ["Final incident state", evidence.recourseAttestation.attestation.finalIncidentState, true],
    ["Final recourse state", evidence.recourseAttestation.attestation.finalRecourseState, true],
    ["Clock class", evidence.recourseAttestation.attestation.clockClass, true],
    [
      "Signature verification status",
      "VERIFIED — participant, governed-result and recourse-attestation signatures",
      true,
    ],
    ["Source commit", evidence.sourceCommit, true],
    ["Governed-FHE commit", evidence.governedFheCommit, true],
    ["Asset record", evidence.cleanverseAssetDigest, true],
    ["ProtectionBinding digest", evidence.protectionAuthorization.bindingDigest, true],
    ["Protection signature A", evidence.protectionAuthorization.participantSignatures[0].signature, true],
    ["Protection signature B", evidence.protectionAuthorization.participantSignatures[1].signature, true],
    ["FHE CaseID", evidence.fhe.caseId, true],
    ["Case binding", evidence.fhe.caseBindingDigest, true],
    ["Profile", evidence.fhe.profile, true],
    ["Circuit", `${evidence.fhe.circuitId} · v${evidence.fhe.circuitVersion}`, true],
    ["Participant A artifact", evidence.fhe.participantArtifactDigests[0], true],
    ["Participant B artifact", evidence.fhe.participantArtifactDigests[1], true],
    ["Evaluated artifact", evidence.fhe.evaluatedArtifactDigest, true],
    ["Result ciphertext digest", evidence.fhe.resultCiphertextDigest, true],
    ["Recomputed result", evidence.fhe.independentlyRecomputedResultDigest, true],
    ["Governed-result digest", evidence.governedResult.digest, true],
    ["Governed-result signature", evidence.governedResult.signature, true],
    ["Release authority", evidence.governedResult.releaseAuthorityId, true],
    ["Release mode", evidence.governedResult.releaseMode, true],
    ["Governed-result reference in recourse", evidence.recourse.resultDigest ?? "ABSENT — no recourse record references a governed result.", evidence.recourse.resultDigest !== null],
    ["Recourse-record digest", evidence.recourse.recordDigest ?? refusal, evidence.recourse.recordDigest !== null],
    ["Chronology digest", evidence.recourseAttestation.attestation.chronologyDigest, true],
    ["RecourseAttestation digest", evidence.recourseAttestation.digest, true],
    ["Attestation signature", evidence.recourseAttestation.attestation.signature, true],
    ["Protection evidence manifest", evidence.manifestDigest, true],
  ] as const;

  return (
    <div className={styles.drawerBackdrop} data-testid="evidence-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <aside
        className={styles.drawer}
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="evidence-title"
        aria-describedby="evidence-description"
        onKeyDown={handleKeyDown}
      >
        <header className={styles.drawerHeader}>
          <div>
            <p>Public evidence · full digest view</p>
            <h2 id="evidence-title">Case evidence</h2>
          </div>
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close evidence drawer">Close</button>
        </header>
        <div className={styles.drawerBody}>
          <p id="evidence-description" className={styles.drawerNotice}>Only the verified public projection is shown. Values wrap in full and each copy action writes the exact displayed value.</p>
          <dl className={styles.evidenceList}>
            {rows.map(([label, value, copyable]) => <EvidenceValue key={label} label={label} value={value} copyable={copyable} />)}
          </dl>
          <section className={styles.classifications}>
            <h3>Source classifications</h3>
            {evidence.sourceClassifications.map((sourceId) => {
              const source = SOURCE_PRESENTATION[sourceId];
              return (
                <article key={sourceId} data-classification={source.classification}>
                  <strong>{source.classification}</strong>
                  <span>{source.subject}</span>
                  <p>{source.detail}</p>
                </article>
              );
            })}
          </section>
        </div>
      </aside>
    </div>
  );
}

export function ProtectionExperience({
  initialEvidence,
  initialScenario,
  initialRunId,
  initialUrlError,
  localAdapterOrigin,
}: {
  readonly initialEvidence: ProtectionEvidencePresentation | null;
  readonly initialScenario: ProductScenario;
  readonly initialRunId: string | null;
  readonly initialUrlError: string | null;
  readonly localAdapterOrigin: string | null;
}) {
  const [initialAuthority] = useState(() => {
    const projected = initialEvidence === null ? null : parseProtectionEvidencePresentation(initialEvidence);
    const initialError = initialUrlError
      ?? (initialRunId !== null && localAdapterOrigin === null
        ? "Local run resume is unavailable on this deployment. No local execution control is exposed."
        : initialRunId === null && initialEvidence !== null && projected === null
          ? "The initial verified evidence projection was malformed."
          : null);
    return { evidence: initialRunId === null ? projected : null, error: initialError };
  });
  const [initialReadbackRequirement] = useState<ReadbackRequirement | null>(() => (
    initialRunId !== null && localAdapterOrigin !== null
      ? {
        runId: initialRunId,
        scenario: initialScenario,
        operation: "UNKNOWN_AFTER_RELOAD",
        operationLabel: "interrupted local operation",
      }
      : null
  ));
  const [scenario, setScenario] = useState<ProductScenario>(initialScenario);
  // Operator form state for a supervised custom case. It is local component
  // state only: never persisted, never put in the URL, never echoed back after
  // dispatch because the form unmounts once a run is admitted.
  const [customWindows, setCustomWindows] = useState<Record<CustomWindowKey, string>>({
    aFrom: "", aUntil: "", bFrom: "", bUntil: "",
  });
  const [customInvalid, setCustomInvalid] = useState<ReadonlySet<CustomWindowKey>>(new Set());
  const [customError, setCustomError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<ProtectionEvidencePresentation | null>(initialAuthority.evidence);
  const [localView, setLocalView] = useState<ProtectionCaseView | null>(null);
  const [mode, setMode] = useState<"imported" | "local">(initialRunId === null ? "imported" : "local");
  const [requestState, setRequestState] = useState<RequestState>(
    initialRunId !== null && localAdapterOrigin !== null ? "resuming" : "idle",
  );
  const [error, setError] = useState<string | null>(initialAuthority.error);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [resumeRunId, setResumeRunId] = useState<string | null>(initialRunId);
  const [drawerTrigger, setDrawerTrigger] = useState<HTMLButtonElement | null>(null);
  const [readbackRequired, setReadbackRequired] = useState<ReadbackRequirement | null>(initialReadbackRequirement);
  const [recoveryAuthority, setRecoveryAuthority] = useState<ProtectionBrowserRecovery | null>(null);
  const [invalidStoredRecovery, setInvalidStoredRecovery] = useState(false);
  const requestGeneration = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const pendingMutation = useRef<ReadbackRequirement | null>(null);
  const readbackRequirementRef = useRef<ReadbackRequirement | null>(initialReadbackRequirement);
  const recoveryAuthorityRef = useRef<ProtectionBrowserRecovery | null>(null);
  const invalidStoredRecoveryRef = useRef(false);

  const localMode = mode === "local";
  const activeCase = localMode ? localView?.protectionCase ?? null : evidence?.protectionCase ?? null;
  const activeEvidence = evidenceForDisplayedCase(mode, evidence, localView);
  const completedStep = localMode && localView !== null ? STAGE_INDEX[localView.stage] : localMode ? 0 : 5;
  const provisionalStage = localView === null ? null : localStagePresentation(localView);
  const recourse = activeEvidence !== null
    ? recoursePresentation(activeEvidence)
    : provisionalStage?.recourse ?? recourseStatePresentation("NOT_OPEN");
  const signedProductState = activeEvidence?.recourseAttestation.attestation ?? null;
  const conflict = localMode ? localView?.governedResult?.conflict ?? null : evidence?.governedResult.conflict ?? null;
  const currentOperation = readbackRequired !== null || recoveryAuthority?.kind === "RETENTION_REQUIRED"
    || localView?.nextOperation === null || localView?.nextOperation === undefined
    ? null : OPERATION[localView.nextOperation] ?? null;
  const currentRunId = localView?.runId ?? resumeRunId;
  const busy = requestState !== "idle";
  const unresolvedRecovery = recoveryAuthority !== null || invalidStoredRecovery || readbackRequired !== null;

  const retainRecoveryAuthority = useCallback((authority: ProtectionBrowserRecovery): boolean => {
    if (typeof window !== "undefined") {
      try {
        const serialized = JSON.stringify(authority);
        window.sessionStorage.setItem(PROTECTION_RECOVERY_STORAGE_KEY, serialized);
        if (parseProtectionBrowserRecovery(window.sessionStorage.getItem(PROTECTION_RECOVERY_STORAGE_KEY) ?? "") === null) {
          throw new Error("Recovery record verification failed");
        }
      } catch {
        setError("The browser could not durably retain recovery authority. No local operation was dispatched.");
        return false;
      }
    }
    recoveryAuthorityRef.current = authority;
    invalidStoredRecoveryRef.current = false;
    setRecoveryAuthority(authority);
    setInvalidStoredRecovery(false);
    return true;
  }, []);

  const clearVerifiedRecoveryAuthority = useCallback(() => {
    if (typeof window !== "undefined") {
      try {
        window.sessionStorage.removeItem(PROTECTION_RECOVERY_STORAGE_KEY);
      } catch {
        setError("Verified recovery completed, but browser recovery storage could not be cleared. Local mutations remain blocked.");
        return;
      }
    }
    recoveryAuthorityRef.current = null;
    invalidStoredRecoveryRef.current = false;
    setRecoveryAuthority(null);
    setInvalidStoredRecovery(false);
  }, []);

  const beginRequest = useCallback((state: RequestState) => {
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    setRequestState(state);
    return { controller, generation };
  }, []);

  const clearAuthority = useCallback((
    nextScenario: ProductScenario,
    nextMode: "imported" | "local",
    preserveReadbackRequirement = false,
  ) => {
    setScenario(nextScenario);
    setEvidence(null);
    setLocalView(null);
    setMode(nextMode);
    setDrawerOpen(false);
    if (!preserveReadbackRequirement) {
      readbackRequirementRef.current = null;
      setReadbackRequired(null);
    }
  }, []);

  const requireDurableReadback = useCallback((requirement: ReadbackRequirement, reason: string) => {
    pendingMutation.current = null;
    if (recoveryAuthorityRef.current === null && Object.values(OPERATION).some((operation) => (
      operation.api === requirement.operation
    ))) {
      retainRecoveryAuthority(pendingMutationRecovery(requirement.scenario, requirement.runId, requirement.operation));
    }
    readbackRequirementRef.current = requirement;
    setScenario(requirement.scenario);
    setEvidence(null);
    setLocalView(null);
    setMode("local");
    setResumeRunId(requirement.runId);
    setReadbackRequired(requirement);
    setDrawerOpen(false);
    setError(
      `The outcome of ${requirement.operationLabel} is uncertain. Durable GET-only readback is required before any further mutation. ${reason}`,
    );
  }, [retainRecoveryAuthority]);

  const loadImportedScenario = useCallback(async (next: ProductScenario, history: HistoryMode = "none") => {
    const requiredReadback = readbackRequirementRef.current;
    if (pendingMutation.current !== null || requiredReadback !== null || recoveryAuthorityRef.current !== null || invalidStoredRecoveryRef.current) {
      if (requiredReadback !== null) {
        writeProtectionUrl("replace", requiredReadback.scenario, requiredReadback.runId);
      }
      return;
    }
    const request = beginRequest("loading");
    clearAuthority(next, "imported");
    setResumeRunId(null);
    setError(null);
    if (history !== "none") writeProtectionUrl(history, next, null);
    try {
      const response = await fetch(`${IMPORTED_ENDPOINT}?scenario=${next}`, { cache: "no-store", signal: request.controller.signal });
      const imported = parseImportedView(await responseBody(response));
      if (imported === null || imported.scenario !== next) {
        throw new Error("Verified evidence did not match the requested scenario.");
      }
      if (requestGeneration.current !== request.generation) return;
      setEvidence(imported);
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(nextError instanceof Error ? nextError.message : "Evidence readback failed");
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority]);

  const resumeLocalRun = useCallback(async (runId: string, expectedScenario: ProductScenario, history: HistoryMode = "none") => {
    const matchingRequirement = readbackRequirementRef.current?.runId === runId
      && readbackRequirementRef.current.scenario === expectedScenario
      ? readbackRequirementRef.current
      : null;
    readbackRequirementRef.current = matchingRequirement;
    setReadbackRequired(matchingRequirement);
    clearAuthority(expectedScenario, "local", true);
    setResumeRunId(runId);
    setError(null);
    if (history !== "none") writeProtectionUrl(history, expectedScenario, runId);
    if (localAdapterOrigin === null) {
      requestController.current?.abort();
      requestGeneration.current += 1;
      setRequestState("idle");
      setError("Local run resume is unavailable on this deployment. No local execution control is exposed.");
      return;
    }
    const request = beginRequest("resuming");
    try {
      const response = await fetch(adapterUrl(localAdapterOrigin, { runId }), { cache: "no-store", signal: request.controller.signal });
      const body = await responseBody(response);
      const retentionRequired = parseRetentionRequiredView(body, runId, expectedScenario);
      if (retentionRequired !== null) {
        if (requestGeneration.current !== request.generation) return;
        const authority = retentionRequiredRecovery(expectedScenario, runId);
        if (!retainRecoveryAuthority(authority)) return;
        pendingMutation.current = null;
        readbackRequirementRef.current = null;
        setReadbackRequired(null);
        setLocalView(null);
        setError(null);
        return;
      }
      const view = parseProtectionCaseView(body, runId, expectedScenario);
      if (view === null) throw new Error("Durable run readback did not match the URL authority.");
      if (requestGeneration.current !== request.generation) return;
      setLocalView(view);
      setResumeRunId(view.runId);
      readbackRequirementRef.current = null;
      setReadbackRequired(null);
      if (recoveryAuthorityRef.current !== null) clearVerifiedRecoveryAuthority();
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(nextError instanceof Error ? nextError.message : "Durable local run readback failed");
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority, clearVerifiedRecoveryAuthority, localAdapterOrigin, retainRecoveryAuthority]);

  const recoverPendingCreation = useCallback(async (authority: Extract<ProtectionBrowserRecovery, { kind: "CREATION_PENDING" }>) => {
    if (localAdapterOrigin === null) {
      setError("Local creation recovery is unavailable on this deployment. The unresolved recovery record was preserved.");
      return;
    }
    clearAuthority(authority.scenario, "local", true);
    setResumeRunId(null);
    setError(null);
    const request = beginRequest("resuming");
    try {
      const lookupResponse = await fetch(adapterUrl(localAdapterOrigin, {
        creationRequestId: authority.creationRequestId,
      }), { cache: "no-store", signal: request.controller.signal });
      const lookup = parseProtectionCaseView(
        await responseBody(lookupResponse),
        undefined,
        authority.scenario,
      );
      if (lookup === null) throw new Error("Creation lookup did not resolve the exact durable run.");
      writeProtectionUrl("replace", authority.scenario, lookup.runId);
      setResumeRunId(lookup.runId);
      const readbackResponse = await fetch(adapterUrl(localAdapterOrigin, { runId: lookup.runId }), {
        cache: "no-store",
        signal: request.controller.signal,
      });
      const readback = parseProtectionCaseView(
        await responseBody(readbackResponse),
        lookup.runId,
        authority.scenario,
      );
      if (readback === null) throw new Error("Recovered creation failed durable GET-only run verification.");
      if (requestGeneration.current !== request.generation) return;
      setLocalView(readback);
      setResumeRunId(readback.runId);
      readbackRequirementRef.current = null;
      setReadbackRequired(null);
      clearVerifiedRecoveryAuthority();
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(`${nextError instanceof Error ? nextError.message : "Creation recovery failed"} No new case was created.`);
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority, clearVerifiedRecoveryAuthority, localAdapterOrigin]);

  const startLocalRun = useCallback(async () => {
    if (localAdapterOrigin === null || pendingMutation.current !== null || readbackRequirementRef.current !== null) return;
    // The ref is set the moment the stored record is judged invalid; the state follows
    // one flush later. Reading both keeps the block independent of that ordering.
    if (recoveryAuthorityRef.current !== null || invalidStoredRecovery || invalidStoredRecoveryRef.current) return;
    const creationRequestId = globalThis.crypto.randomUUID();
    const creationAuthority = pendingCreationRecovery(scenario, creationRequestId);
    if (!retainRecoveryAuthority(creationAuthority)) return;
    clearAuthority(scenario, "local");
    setResumeRunId(null);
    setError(null);
    const request = beginRequest("creating");
    try {
      const response = await fetch(adapterUrl(localAdapterOrigin), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: "create", scenario, creationRequestId }),
        signal: request.controller.signal,
      });
      const view = parseProtectionCaseView(await responseBody(response), undefined, scenario);
      if (view === null) throw new Error("Local case creation returned a mismatched public view.");
      if (requestGeneration.current !== request.generation) return;
      setLocalView(view);
      setResumeRunId(view.runId);
      writeProtectionUrl("push", scenario, view.runId);
      clearVerifiedRecoveryAuthority();
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(`${nextError instanceof Error ? nextError.message : "Local case creation failed"} Creation recovery remains available; no second create will be sent.`);
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority, clearVerifiedRecoveryAuthority, invalidStoredRecovery, localAdapterOrigin, retainRecoveryAuthority, scenario]);

  const startCustomLocalRun = useCallback(async (windows: SupervisedWindowsInput) => {
    if (localAdapterOrigin === null || pendingMutation.current !== null || readbackRequirementRef.current !== null) return;
    // The ref is set the moment the stored record is judged invalid; the state follows
    // one flush later. Reading both keeps the block independent of that ordering.
    if (recoveryAuthorityRef.current !== null || invalidStoredRecovery || invalidStoredRecoveryRef.current) return;
    const creationRequestId = globalThis.crypto.randomUUID();
    const creationAuthority = pendingCreationRecovery(scenario, creationRequestId);
    if (!retainRecoveryAuthority(creationAuthority)) return;
    clearAuthority(scenario, "local");
    setResumeRunId(null);
    setError(null);
    const request = beginRequest("creating");
    try {
      const response = await fetch(adapterUrl(localAdapterOrigin), {
        method: "POST",
        headers: { "content-type": "application/json" },
        // No scenario is sent at all. The case is authorized under a neutral
        // execution variant, and the view is parsed WITHOUT an expected scenario
        // because only the governed signed Boolean can produce an outcome.
        body: JSON.stringify({ intent: "create", creationRequestId, executionVariant: "CUSTOM_SUPERVISED", pledges: windows }),
        signal: request.controller.signal,
      });
      const view = parseProtectionCaseView(await responseBody(response));
      if (view === null) throw new Error("Local case creation returned a mismatched public view.");
      if (requestGeneration.current !== request.generation) return;
      setLocalView(view);
      setResumeRunId(view.runId);
      // Adopt the scenario the server actually bound, never the routing label.
      const bound = view.protectionCase.productScenario;
      setScenario(bound);
      writeProtectionUrl("push", bound, view.runId);
      clearVerifiedRecoveryAuthority();
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(`${nextError instanceof Error ? nextError.message : "Local case creation failed"} Creation recovery remains available; no second create will be sent.`);
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority, clearVerifiedRecoveryAuthority, invalidStoredRecovery, localAdapterOrigin, retainRecoveryAuthority, scenario]);

  const executeNext = useCallback(async () => {
    if (
      localAdapterOrigin === null || localView === null || currentOperation === null
      || readbackRequired !== null || pendingMutation.current !== null
    ) return;
    const attemptedMutation: ReadbackRequirement = {
      runId: localView.runId,
      scenario,
      operation: currentOperation.api,
      operationLabel: currentOperation.label,
    };
    if (!retainRecoveryAuthority(pendingMutationRecovery(scenario, localView.runId, currentOperation.api))) return;
    pendingMutation.current = attemptedMutation;
    const request = beginRequest("executing");
    setError(null);
    setDrawerOpen(false);
    try {
      const response = await fetch(adapterUrl(localAdapterOrigin), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: "execute", runId: localView.runId, operation: currentOperation.api }),
        signal: request.controller.signal,
      });
      const view = parseProtectionCaseView(await responseBody(response), localView.runId, scenario);
      if (view === null) throw new Error("Local operation readback did not match the durable run.");
      if (requestGeneration.current !== request.generation) {
        requireDurableReadback(attemptedMutation, "The mutating request was superseded after dispatch.");
        return;
      }
      pendingMutation.current = null;
      setLocalView(view);
      readbackRequirementRef.current = null;
      setReadbackRequired(null);
      clearVerifiedRecoveryAuthority();
    } catch (nextError) {
      if (pendingMutation.current !== attemptedMutation) return;
      const reason = nextError instanceof Error ? nextError.message : "Local protection operation failed";
      if (
        nextError instanceof ProtectionResponseFailure
        && nextError.notAdmitted?.runId === attemptedMutation.runId
        && nextError.notAdmitted.operation === attemptedMutation.operation
        && requestGeneration.current === request.generation
      ) {
        pendingMutation.current = null;
        clearVerifiedRecoveryAuthority();
        setError(reason);
        return;
      }
      requireDurableReadback(attemptedMutation, reason);
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [
    beginRequest, clearVerifiedRecoveryAuthority, currentOperation, localAdapterOrigin, localView,
    readbackRequired, requireDurableReadback, retainRecoveryAuthority, scenario,
  ]);

  const finishEvidenceRetention = useCallback(async () => {
    const authority = recoveryAuthorityRef.current;
    if (localAdapterOrigin === null || authority?.kind !== "RETENTION_REQUIRED" || busy) return;
    const request = beginRequest("retaining");
    setError(null);
    try {
      const retentionResponse = await fetch(adapterUrl(localAdapterOrigin), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          intent: "execute",
          runId: authority.runId,
          operation: authority.operation,
        }),
        signal: request.controller.signal,
      });
      if (parseRetainedProtectionView(
        await responseBody(retentionResponse),
        authority.runId,
        authority.scenario,
      ) === null) throw new Error("Evidence retention response failed exact public verification.");
      const readbackResponse = await fetch(adapterUrl(localAdapterOrigin, { runId: authority.runId }), {
        cache: "no-store",
        signal: request.controller.signal,
      });
      const view = parseProtectionCaseView(
        await responseBody(readbackResponse),
        authority.runId,
        authority.scenario,
      );
      if (view === null || view.stage !== "COMPLETE" || view.evidence === null) {
        throw new Error("Retained evidence did not reach verified COMPLETE readback.");
      }
      if (requestGeneration.current !== request.generation) return;
      setScenario(authority.scenario);
      setMode("local");
      setLocalView(view);
      setResumeRunId(view.runId);
      readbackRequirementRef.current = null;
      setReadbackRequired(null);
      clearVerifiedRecoveryAuthority();
      writeProtectionUrl("replace", authority.scenario, authority.runId);
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(`${nextError instanceof Error ? nextError.message : "Evidence retention recovery failed"} The fixed idempotent retention action remains required.`);
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, busy, clearVerifiedRecoveryAuthority, localAdapterOrigin]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const resumeStoredAuthority = (authority: ProtectionBrowserRecovery) => {
      recoveryAuthorityRef.current = authority;
      invalidStoredRecoveryRef.current = false;
      setRecoveryAuthority(authority);
      setInvalidStoredRecovery(false);
      setScenario(authority.scenario);
      setMode("local");
      if (authority.kind === "CREATION_PENDING") {
        void recoverPendingCreation(authority);
        return;
      }
      const requirement = authority.kind === "MUTATION_PENDING" ? {
        runId: authority.runId,
        scenario: authority.scenario,
        operation: authority.operation,
        operationLabel: operationLabel(authority.operation),
      } : null;
      readbackRequirementRef.current = requirement;
      setReadbackRequired(requirement);
      writeProtectionUrl("replace", authority.scenario, authority.runId);
      void resumeLocalRun(authority.runId, authority.scenario);
    };
    const popstate = () => {
      const dispatchedMutation = pendingMutation.current;
      if (dispatchedMutation !== null) {
        requestController.current?.abort();
        requestGeneration.current += 1;
        requireDurableReadback(dispatchedMutation, "Browser navigation interrupted the mutating response after dispatch.");
        setRequestState("idle");
        writeProtectionUrl("replace", dispatchedMutation.scenario, dispatchedMutation.runId);
        return;
      }
      const requiredReadback = readbackRequirementRef.current;
      if (requiredReadback !== null) {
        writeProtectionUrl("replace", requiredReadback.scenario, requiredReadback.runId);
        void resumeLocalRun(requiredReadback.runId, requiredReadback.scenario, "replace");
        return;
      }
      const storedAuthority = recoveryAuthorityRef.current;
      if (storedAuthority !== null) {
        resumeStoredAuthority(storedAuthority);
        return;
      }
      const authority = readProtectionUrl(window.location.search);
      if (authority.error !== null) {
        requestController.current?.abort();
        requestGeneration.current += 1;
        clearAuthority(authority.scenario, authority.runId === null ? "imported" : "local");
        setResumeRunId(null);
        setRequestState("idle");
        setError(authority.error);
      } else if (authority.runId !== null) {
        void resumeLocalRun(authority.runId, authority.scenario);
      } else {
        void loadImportedScenario(authority.scenario);
      }
    };
    window.addEventListener("popstate", popstate);
    let resumeTimer: number | null = null;
    let disposed = false;
    let rawStoredRecovery: string | null = null;
    // The block itself is the ref, and it is still set synchronously here. Only the
    // rendered disclosure is flushed on a timer, so this effect sets no state
    // synchronously. Nothing can start a local run in between: every entry point also
    // reads `invalidStoredRecoveryRef`, which is already true by then.
    //
    // A microtask, not a timer: it settles before the resume scheduled below, which is
    // the same position the inline call held. A later request can then supersede this
    // message exactly as it did before, and a timer would have inverted that.
    const discloseInvalidRecovery = (message: string, settleRequestState: boolean) => {
      queueMicrotask(() => {
        if (disposed) return;
        if (settleRequestState) {
          clearAuthority(initialScenario, "local", true);
          setRequestState("idle");
        }
        setInvalidStoredRecovery(true);
        setError(message);
      });
    };
    try {
      rawStoredRecovery = window.sessionStorage.getItem(PROTECTION_RECOVERY_STORAGE_KEY);
    } catch {
      invalidStoredRecoveryRef.current = true;
      // Unavailable storage never settled the request state, and `requestState` may
      // legitimately still be "resuming".
      discloseInvalidRecovery("Browser recovery storage is unavailable. Local execution remains blocked.", false);
    }
    if (rawStoredRecovery !== null) {
      const stored = parseProtectionBrowserRecovery(rawStoredRecovery);
      if (stored === null) {
        invalidStoredRecoveryRef.current = true;
        discloseInvalidRecovery(
          "The retained browser recovery record is malformed or expired. Confirm supervised abandonment before starting another case.",
          true,
        );
      } else {
        resumeTimer = window.setTimeout(() => resumeStoredAuthority(stored), 0);
      }
    } else if (initialUrlError === null) {
      if (initialRunId !== null) {
        resumeTimer = window.setTimeout(() => void resumeLocalRun(initialRunId, initialScenario), 0);
      } else writeProtectionUrl("replace", initialScenario, null);
    }
    return () => {
      disposed = true;
      if (resumeTimer !== null) window.clearTimeout(resumeTimer);
      window.removeEventListener("popstate", popstate);
      requestController.current?.abort();
      requestGeneration.current += 1;
      pendingMutation.current = null;
    };
  }, [
    clearAuthority, initialRunId, initialScenario, initialUrlError, loadImportedScenario,
    recoverPendingCreation, requireDurableReadback, resumeLocalRun,
  ]);

  const abandonUnresolvedRecovery = useCallback(() => {
    if (typeof window === "undefined") return;
    const confirmed = window.confirm(
      "Abandon the unresolved local recovery record? This does not cancel or roll back backend work, and a case may still exist.",
    );
    if (!confirmed) return;
    try {
      window.sessionStorage.removeItem(PROTECTION_RECOVERY_STORAGE_KEY);
    } catch {
      setError("The unresolved recovery record could not be cleared. No authority changed.");
      return;
    }
    pendingMutation.current = null;
    recoveryAuthorityRef.current = null;
    invalidStoredRecoveryRef.current = false;
    readbackRequirementRef.current = null;
    setRecoveryAuthority(null);
    setInvalidStoredRecovery(false);
    setReadbackRequired(null);
    void loadImportedScenario(scenario, "replace");
  }, [loadImportedScenario, scenario]);

  function openEvidence(event: ReactMouseEvent<HTMLButtonElement>) {
    if (activeEvidence === null) return;
    setDrawerTrigger(event.currentTarget);
    setDrawerOpen(true);
  }

  const protectionStatus = signedProductState?.finalIncidentState.replaceAll("_", " ")
    ?? (localView === null ? "AWAITING VERIFIED CASE" : `${localView.protectionCase.incidentState.replaceAll("_", " ")} · PROVISIONAL`);
  const recourseStatus = signedProductState?.finalRecourseState.replaceAll("_", " ")
    ?? (localView === null ? "AWAITING VERIFIED CASE" : `${localView.protectionCase.recourseState.replaceAll("_", " ")} · PROVISIONAL`);
  const progressText = requestState === "loading"
    ? `Loading verified ${scenario === "conflict" ? "conflict" : "no-conflict"} evidence. Previous case authority is cleared.`
    : requestState === "creating"
      ? "Creating a new durable local case. The browser is waiting for backend readback."
      : requestState === "resuming"
        ? "Reading the last durable backend stage. No operation is being started."
      : requestState === "retaining"
        ? "Finishing the one fixed idempotent evidence-retention operation, then performing GET-only COMPLETE readback."
        : requestState === "executing"
          ? currentOperation?.waiting ?? "Waiting for the fixed backend operation to return its durable stage."
          : recoveryAuthority?.kind === "CREATION_PENDING"
            ? "A creation response is unresolved. Recovery uses creation lookup and GET-only run readback; no second create is available."
            : recoveryAuthority?.kind === "RETENTION_REQUIRED"
              ? "The evaluation and export are complete. One fixed idempotent evidence-retention operation remains."
              : readbackRequired !== null
                ? `Durable GET-only readback required after the uncertain ${readbackRequired.operationLabel} response. No mutation is available.`
                : error !== null && activeCase === null
                  ? "Verified evidence is unavailable. Retry verified evidence loading or resume the retained recovery authority."
                  : activeCase === null
                    ? "No verified case conclusion is loaded."
                    : provisionalStage?.detail ?? "Verified retained public evidence is ready.";
  const conclusionLabel = activeCase === null
    ? busy ? "Verified case loading" : "No verified conclusion"
    : conflict === null ? "Private check in progress" : conflict ? "Conflict confirmed" : "No conflict found";
  const conclusionDetail = activeCase === null
    ? busy ? "Awaiting verified evidence" : "Verified evidence unavailable"
    : activeEvidence !== null
      ? "Case state established by the governed result"
      : `${recourse.label}${localView !== null ? " · provisional backend state" : ""}`;

  return (
    <div
      className={styles.page}
      data-testid="protection-product"
      data-execution={localMode ? "local" : "imported"}
      data-readback-required={unresolvedRecovery ? "true" : "false"}
      aria-busy={busy}
    >
      <div className={styles.pageContent} inert={drawerOpen ? true : undefined} aria-hidden={drawerOpen ? "true" : undefined}>
        <a className={styles.skip} href="#protection-main">Skip to protection case</a>
        <PublicHeader surface="evidence" />

        <main id="protection-main" className={styles.main} tabIndex={-1}>
          <section className={styles.assetHeader}>
            <div className={styles.assetTitle}>
              <p className={styles.eyebrow}>Completed case · retained public readback</p>
              <h1>Retained case evidence for <span>MINV01</span>.</h1>
              <p>Review the governed result, source classifications and chronology for this completed case. Exact digests and signatures remain available in the evidence drawer.</p>
            </div>
            <div className={styles.outcome} data-conflict={conflict === null ? "pending" : conflict ? "true" : "false"}>
              <span>Current conclusion</span>
              <strong>{conclusionLabel}</strong>
              <p>{conclusionDetail}</p>
            </div>
          </section>

          <section className={styles.controlStrip} aria-label="Evidence scenario controls" aria-busy={busy}>
            <div>
              <span>Completed evidence</span>
              <div className={styles.segmented}>
                {(["conflict", "no-conflict"] as const).map((option) => (
                  <button
                    key={option}
                    type="button"
                    aria-pressed={!localMode && scenario === option}
                    disabled={busy || unresolvedRecovery}
                    onClick={() => void loadImportedScenario(option, "push")}
                  >
                    {option === "conflict" ? "Conflict" : "No conflict"}
                  </button>
                ))}
              </div>
            </div>
            <p>{progressText}</p>
            {localAdapterOrigin !== null ? (
              <button className={styles.localButton} type="button" disabled={busy || unresolvedRecovery} onClick={() => void startLocalRun()}>
                {localMode ? "Start a fresh local case" : "Run this case locally"}
              </button>
            ) : null}
          </section>

          {/* Supervised custom case. Local execution mode only, and only until a
              run has been admitted: afterwards the durable step-by-step flow
              takes over. Never rendered in production or imported-evidence mode,
              because localAdapterOrigin is null there. */}
          {localAdapterOrigin !== null && localView === null && !unresolvedRecovery ? (
            <section className={styles.customCase} aria-labelledby="custom-case-title">
              <h3 id="custom-case-title">Custom supervised case</h3>
              <p>
                Enter two private pledge windows. They are encrypted and evaluated by the real BGV
                circuit; the governed decryptor, not this form, determines the result.
              </p>
              {customError === null ? null : (
                <p className={styles.customError} role="alert">{customError}</p>
              )}
              <div className={styles.customGrid}>
                {CUSTOM_WINDOW_FIELDS.map((field) => (
                  <label key={field.key} htmlFor={`custom-${field.key}`}>
                    {field.label}
                    <input
                      id={`custom-${field.key}`}
                      name={field.key}
                      type="text"
                      inputMode="numeric"
                      autoComplete="off"
                      value={customWindows[field.key]}
                      aria-invalid={customInvalid.has(field.key)}
                      disabled={busy}
                      onChange={(event) => {
                        const next = event.target.value;
                        setCustomWindows((current) => ({ ...current, [field.key]: next }));
                      }}
                    />
                  </label>
                ))}
              </div>
              <div className={styles.customFixed}>
                <strong>Fixed by this MVP</strong>
                <ul>
                  <li>Cleanverse asset: MINV01, and its canonical receivable identity</li>
                  <li>Currency, protected amount and the exclusive policy flag</li>
                  <li>Locally generated participant keys</li>
                  <li>The fixed BGV circuit and its parameter profile</li>
                </ul>
              </div>
              <button
                className={styles.localButton}
                type="button"
                disabled={busy}
                onClick={() => {
                  const parsed = parseCustomWindows(customWindows);
                  setCustomInvalid(parsed.invalid);
                  setCustomError(parsed.message);
                  if (parsed.windows === null) return;
                  void startCustomLocalRun(parsed.windows);
                }}
              >
                Run this custom case locally
              </button>
            </section>
          ) : null}

          {error === null ? null : <p className={styles.error} role="alert">{error}</p>}

          {activeCase === null ? (
            <section className={styles.localStatus} data-testid="case-loading-status" aria-live="polite" aria-busy={busy}>
              <p>{invalidStoredRecovery
                ? "Supervised abandonment required"
                : recoveryAuthority?.kind === "CREATION_PENDING"
                  ? "Creation recovery required"
                  : recoveryAuthority?.kind === "RETENTION_REQUIRED"
                    ? "Evidence retention required"
                    : readbackRequired !== null ? "Durable readback required" : busy ? "Verified case loading" : "Verified case unavailable"}</p>
              <strong>{busy
                ? progressText
                : invalidStoredRecovery
                  ? "The stored recovery authority cannot be safely interpreted. It has not been cleared."
                  : recoveryAuthority?.kind === "CREATION_PENDING"
                    ? `${error === null ? "Creation response is unresolved." : error} Look up the existing creation request and verify its durable run with GET only. Do not create another case.`
                    : recoveryAuthority?.kind === "RETENTION_REQUIRED"
                      ? `${error === null ? "Evaluation and export are already complete." : error} Finish only the fixed idempotent evidence-retention operation.`
                : readbackRequired !== null
                  ? `The ${readbackRequired.operationLabel} mutation may or may not have committed. Read durable state before retrying or advancing.`
                  : error ?? "No authoritative case is selected."}</strong>
              {currentRunId === null ? null : <code>Durable run · {currentRunId}</code>}
              {readbackRequired === null ? null : (
                <code data-testid="durable-readback-required">
                  Blocked mutation · {readbackRequired.operation} · GET readback only
                </code>
              )}
              {recoveryAuthority?.kind === "CREATION_PENDING" && localAdapterOrigin !== null && !busy ? (
                <button type="button" onClick={() => void recoverPendingCreation(recoveryAuthority)}>
                  Recover durable creation
                </button>
              ) : null}
              {recoveryAuthority?.kind === "RETENTION_REQUIRED" && localAdapterOrigin !== null && !busy ? (
                <button type="button" onClick={() => void finishEvidenceRetention()}>
                  Finish evidence retention
                </button>
              ) : null}
              {currentRunId !== null && localAdapterOrigin !== null && !busy
                && recoveryAuthority?.kind !== "CREATION_PENDING" && recoveryAuthority?.kind !== "RETENTION_REQUIRED" ? (
                <button type="button" onClick={() => void resumeLocalRun(currentRunId, scenario, "replace")}>
                  Resume durable run
                </button>
              ) : null}
              {error !== null && currentRunId === null && !unresolvedRecovery && !busy ? (
                <button type="button" onClick={() => void loadImportedScenario(scenario, "replace")}>
                  Retry verified evidence loading
                </button>
              ) : null}
              {!unresolvedRecovery ? null : (
                <>
                  <p id="recovery-abandon-caveat">Abandonment only clears this browser record; it does not cancel or roll back backend work.</p>
                  <button type="button" aria-describedby="recovery-abandon-caveat" onClick={abandonUnresolvedRecovery}>
                    Abandon unresolved recovery
                  </button>
                </>
              )}
            </section>
          ) : (
            <>
              {provisionalStage === null || activeEvidence !== null ? null : (
                <section className={styles.provisionalState} data-testid="provisional-product-state" aria-live="polite">
                  <span>Last confirmed durable backend stage · provisional</span>
                  <strong>{provisionalStage.stageLabel}</strong>
                  <p>{provisionalStage.detail} This is not the final signed public attestation.</p>
                </section>
              )}

              <div className={styles.productGrid}>
                <section className={styles.assetCard} aria-labelledby="asset-heading">
                  <header><p>Root product object</p><h2 id="asset-heading">Cleanverse asset</h2></header>
                  <dl>
                    <div><dt>Asset identity</dt><dd>{compact(activeCase.cleanverseAssetDigest)}</dd></div>
                    <div><dt>A-Token / CVA</dt><dd>MINV01 · {compact(activeCase.cleanverseAsset.token.address)}</dd></div>
                    <div><dt>Source</dt><dd>Cleanverse request {activeCase.cleanverseAsset.sourceIdentity.cleanverseRequestId}</dd></div>
                    <div><dt>Issuer identity</dt><dd>Admin address observed · legal identity unproven</dd></div>
                    <div><dt>A-Pass</dt><dd>Holder profiles admitted at retained observation</dd></div>
                    <div><dt>Settlement asset</dt><dd>aUSDC · identity observed, not settled in this slice</dd></div>
                    <div><dt>Terms / policy</dt><dd>{activeCase.cleanverseAsset.documentationTerms.version} documented · min tier 50 observed</dd></div>
                    <div><dt>Issuance</dt><dd>Deployment block {activeCase.cleanverseAsset.tokenDeployment.blockNumber} · {compact(activeCase.cleanverseAsset.issuance.transactionHash)}</dd></div>
                  </dl>
                  <footer><span>REAL OBSERVED PROVENANCE</span><p>Retained issuance/readback evidence; not a fresh browser observation and not Cleanverse conflict detection.</p></footer>
                </section>

                <section className={styles.protectionCard} aria-labelledby="protection-heading">
                  <header><p>Mordant service · v{activeCase.serviceVersion}</p><h2 id="protection-heading">Protection case</h2></header>
                  <div className={styles.moneyDomains}>
                    <article><span>Protected amount</span><strong>{formatAmount(activeCase.protectedAmount.minorUnits)} <small>aUSDC</small></strong><p>Synthetic fixture · no funds</p></article>
                    <article><span>Separate reserve · 10%</span><strong>{formatAmount(activeCase.reserve.minorUnits)} <small>aUSDC</small></strong><p>Local protocol double</p></article>
                  </div>
                  <dl>
                    <div><dt>Protection status</dt><dd>{protectionStatus}</dd></div>
                    <div><dt>Holder record date</dt><dd>{new Date(activeCase.holderRecordDate).toLocaleString("en-GB", { timeZone: "UTC" })} UTC</dd></div>
                    <div><dt>Snapshot</dt><dd>{activeCase.holderSnapshot[0].allocationBps / 100}% / {activeCase.holderSnapshot[1].allocationBps / 100}% synthetic lenders</dd></div>
                    <div><dt>FHE CaseID</dt><dd>{compact(activeCase.fheCaseId)}</dd></div>
                    <div><dt>Recourse</dt><dd>{recourseStatus}</dd></div>
                    <div><dt>Original claim</dt><dd className={styles.intact}>Outstanding · 100 units intact</dd></div>
                  </dl>
                </section>

                <section className={styles.matchCard} aria-labelledby="match-heading" aria-busy={requestState === "executing"}>
                  <header><p>Private conflict check</p><h2 id="match-heading">One fixed Boolean</h2></header>
                  <ol>
                    {PRIVATE_CONFLICT_STEPS.map((step, index) => (
                      <li key={step} data-complete={index <= completedStep ? "true" : "false"}>
                        <i aria-hidden="true">{index < completedStep || !localMode ? "✓" : index === completedStep ? "•" : index + 1}</i>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                  <div className={styles.matchBoundary}>
                    <span>{FHE_PROFILE_LABEL}</span>
                    <span>Evaluator has no decrypt key</span>
                    <span>Trusted designated release · {activeCase.releaseMode}</span>
                  </div>
                  {localMode ? (
                    <div className={styles.progressPanel} aria-live="polite">
                      <strong>{progressText}</strong>
                      <p>A complete local journey normally takes about one minute. The browser may wait while backend progress is durably journaled.</p>
                      {currentRunId === null ? null : <code>Durable run · {currentRunId}</code>}
                      {currentRunId === null ? null : <small>Safe to retain this URL. After interruption, resume reads durable state before any retry.</small>}
                      {error !== null && currentRunId !== null && localAdapterOrigin !== null ? (
                        <button type="button" disabled={busy} onClick={() => void resumeLocalRun(currentRunId, scenario, "replace")}>Resume durable run</button>
                      ) : null}
                    </div>
                  ) : null}
                  {localMode && currentOperation !== null ? (
                    <div className={styles.nextAction}>
                      <p>{currentOperation.support}</p>
                      <button type="button" disabled={busy} onClick={() => void executeNext()}>
                        {requestState === "executing" ? `Working · ${currentOperation.label}` : currentOperation.label}
                      </button>
                    </div>
                  ) : (
                    <button className={styles.evidenceButton} type="button" disabled={activeEvidence === null} onClick={openEvidence}>
                      {activeEvidence === null ? "Evidence available after sealing" : "Open complete evidence"}
                    </button>
                  )}
                </section>
              </div>

              <section className={styles.timeline} aria-labelledby="timeline-heading">
                <header><p>Case chronology</p><h2 id="timeline-heading">Asset → private result → retained local rule</h2></header>
                <ol>
                  {activeEvidence === null ? (
                    <li><time>Provisional</time><i aria-hidden="true" /><div><strong>{provisionalStage?.stageLabel ?? "Canonical chronology pending"}</strong><span>BACKEND STAGE · NOT FINAL SIGNED CHRONOLOGY</span></div></li>
                  ) : activeEvidence.chronology.events.filter((event, index, events) => (
                    events.findIndex((candidate) => candidate.kind === event.kind) === index
                  )).map((event) => {
                    const presentation = CHRONOLOGY_PRESENTATION[event.kind];
                    return (
                      <li key={`${event.ordinal}-${event.kind}`}>
                        <time>{event.atUnix === null ? "Ordered" : new Date(event.atUnix * 1000).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" })}</time>
                        <i aria-hidden="true" />
                        <div><strong>{presentation?.label ?? "Unknown chronology event"}</strong><span>{presentation?.classification ?? "REJECTED EVENT ID"}</span></div>
                      </li>
                    );
                  })}
                  <li className={styles.claimRetained}>
                    <time>Retained</time><i aria-hidden="true" />
                    <div><strong>Original receivable claim remains intact</strong><span>RECEIVABLE DOMAIN · NO PROTECTION BURN OR TRANSFER</span></div>
                  </li>
                </ol>
              </section>
            </>
          )}

          <details className={styles.technicalScope}>
            <summary>Technical scope of this retained case</summary>
            <div className={styles.technicalScopeFacts}>
              {TRUTH_FACTS.map((fact) => <p key={fact}>{fact}</p>)}
            </div>
            <div className={styles.technicalScopeDisclosure}>
              <p>{PRODUCT_CLAIM}</p>
              <p>{PRODUCT_DISCLOSURE}</p>
              {activeEvidence?.chronology.clockClass === "SIMULATED_PROTOCOL_CLOCK" ? (
                <p>Simulation disclosure: cure-window completion and recourse availability are simulated protocol time, not observed wall-clock chronology.</p>
              ) : null}
            </div>
          </details>
        </main>
      </div>

      {drawerOpen && activeEvidence !== null ? (
        <EvidenceDrawer evidence={activeEvidence} onClose={() => setDrawerOpen(false)} returnFocus={drawerTrigger} />
      ) : null}
    </div>
  );
}

const FHE_PROFILE_LABEL = "BGV · IdentityFullFHE256 · N15";
const PRODUCT_CLAIM = "This historical retained case evaluates two synthetic pledge fixtures, releases governed conflict status, then applies its retained local rule to record a protocol-double recourse artifact. It predates the current managed V2 Governed Recourse Policy authority chain.";
const PRODUCT_DISCLOSURE = "The Cleanverse / Monad testnet identity is retained real observed provenance. No real lender funds or submissions are used. The designated decryptor is trusted; threshold release, native Monad FHE, live settlement and production custody isolation are not claimed.";
