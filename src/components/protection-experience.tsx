"use client";

import Link from "next/link";
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
  PRODUCT_EXECUTION_LABELS,
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
import type { ProtectionCaseView } from "@/lib/protection/governed-fhe-product-server";

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

type RequestState = "idle" | "loading" | "creating" | "executing" | "resuming";
type HistoryMode = "none" | "push" | "replace";
type UrlAuthority = Readonly<{
  scenario: ProductScenario;
  runId: string | null;
  error: string | null;
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
    label: "Apply governed result",
    support: "Verifies trusted pins and either opens the cure record or refuses recourse.",
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

async function responseBody(response: Response): Promise<unknown> {
  const value = await response.json() as unknown;
  if (!response.ok) throw new Error(record(value) && typeof value.error === "string" ? value.error : "Protection backend refused the operation.");
  return value;
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

function adapterUrl(origin: string, runId?: string): string {
  const url = new URL(origin);
  if (runId !== undefined) url.searchParams.set("runId", runId);
  return url.toString();
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
  const [scenario, setScenario] = useState<ProductScenario>(initialScenario);
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
  const requestGeneration = useRef(0);
  const requestController = useRef<AbortController | null>(null);

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
  const currentOperation = localView?.nextOperation === null || localView?.nextOperation === undefined
    ? null : OPERATION[localView.nextOperation] ?? null;
  const currentRunId = localView?.runId ?? resumeRunId;
  const busy = requestState !== "idle";

  const beginRequest = useCallback((state: RequestState) => {
    requestController.current?.abort();
    const controller = new AbortController();
    requestController.current = controller;
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    setRequestState(state);
    return { controller, generation };
  }, []);

  const clearAuthority = useCallback((nextScenario: ProductScenario, nextMode: "imported" | "local") => {
    setScenario(nextScenario);
    setEvidence(null);
    setLocalView(null);
    setMode(nextMode);
    setDrawerOpen(false);
  }, []);

  const loadImportedScenario = useCallback(async (next: ProductScenario, history: HistoryMode = "none") => {
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
    clearAuthority(expectedScenario, "local");
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
      const response = await fetch(adapterUrl(localAdapterOrigin, runId), { cache: "no-store", signal: request.controller.signal });
      const view = parseProtectionCaseView(await responseBody(response), runId, expectedScenario);
      if (view === null) throw new Error("Durable run readback did not match the URL authority.");
      if (requestGeneration.current !== request.generation) return;
      setLocalView(view);
      setResumeRunId(view.runId);
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(nextError instanceof Error ? nextError.message : "Durable local run readback failed");
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority, localAdapterOrigin]);

  const startLocalRun = useCallback(async () => {
    if (localAdapterOrigin === null) return;
    clearAuthority(scenario, "local");
    setResumeRunId(null);
    setError(null);
    const request = beginRequest("creating");
    try {
      const response = await fetch(adapterUrl(localAdapterOrigin), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ intent: "create", scenario }),
        signal: request.controller.signal,
      });
      const view = parseProtectionCaseView(await responseBody(response), undefined, scenario);
      if (view === null) throw new Error("Local case creation returned a mismatched public view.");
      if (requestGeneration.current !== request.generation) return;
      setLocalView(view);
      setResumeRunId(view.runId);
      writeProtectionUrl("push", scenario, view.runId);
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(nextError instanceof Error ? nextError.message : "Local case creation failed");
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, clearAuthority, localAdapterOrigin, scenario]);

  const executeNext = useCallback(async () => {
    if (localAdapterOrigin === null || localView === null || currentOperation === null) return;
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
      if (requestGeneration.current !== request.generation) return;
      setLocalView(view);
    } catch (nextError) {
      if (requestGeneration.current !== request.generation) return;
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(nextError instanceof Error ? nextError.message : "Local protection operation failed");
    } finally {
      if (requestGeneration.current === request.generation) setRequestState("idle");
    }
  }, [beginRequest, currentOperation, localAdapterOrigin, localView, scenario]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const popstate = () => {
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
    if (initialUrlError === null) {
      if (initialRunId !== null) {
        resumeTimer = window.setTimeout(() => void resumeLocalRun(initialRunId, initialScenario), 0);
      }
      else writeProtectionUrl("replace", initialScenario, null);
    }
    return () => {
      if (resumeTimer !== null) window.clearTimeout(resumeTimer);
      window.removeEventListener("popstate", popstate);
      requestController.current?.abort();
      requestGeneration.current += 1;
    };
  }, [clearAuthority, initialRunId, initialScenario, initialUrlError, loadImportedScenario, resumeLocalRun]);

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
        : requestState === "executing"
          ? currentOperation?.waiting ?? "Waiting for the fixed backend operation to return its durable stage."
          : provisionalStage?.detail ?? "Verified retained public evidence is ready.";

  return (
    <div className={styles.page} data-testid="protection-product" data-execution={localMode ? "local" : "imported"} aria-busy={busy}>
      <div className={styles.pageContent} inert={drawerOpen ? true : undefined} aria-hidden={drawerOpen ? "true" : undefined}>
        <a className={styles.skip} href="#protection-main">Skip to protection case</a>
        <header className={styles.chrome}>
          <Link href="/" className={styles.brand} aria-label="Mordant home">
            <svg viewBox="0 0 100 100" aria-hidden="true"><rect x="43" width="14" height="100" /><rect y="43" width="100" height="14" /><rect x="43" width="14" height="100" transform="rotate(45 50 50)" /><rect x="43" width="14" height="100" transform="rotate(-45 50 50)" /></svg>
            <span>Mordant</span>
            <small>Asset protection</small>
          </Link>
          <nav aria-label="Protection navigation">
            <Link href="/">Public story</Link>
            <span aria-current="page">Conflicting Pledge Protection</span>
            <button type="button" disabled={activeEvidence === null} onClick={openEvidence}>Evidence</button>
          </nav>
        </header>

        <div className={styles.boundaryBar}>
          <span>{localMode ? PRODUCT_EXECUTION_LABELS.fhe : PRODUCT_EXECUTION_LABELS.web}</span>
          <span>{PRODUCT_EXECUTION_LABELS.recourse}</span>
        </div>

        <section className={styles.truthBoundary} aria-label="MVP evidence and execution boundaries">
          {TRUTH_FACTS.map((fact) => <p key={fact}>{fact}</p>)}
        </section>

        <main id="protection-main" className={styles.main} tabIndex={-1}>
          <section className={styles.assetHeader}>
            <div className={styles.assetTitle}>
              <p className={styles.eyebrow}>Cleanverse receivable provenance · Monad testnet observation</p>
              <h1>Protect <span>MINV01</span> from conflicting pledges.</h1>
              <p>The retained asset identity is the case root. Cleanverse did not detect this synthetic conflict; Mordant’s local off-chain BGV flow evaluates the controlled fixtures.</p>
            </div>
            <div className={styles.outcome} data-conflict={conflict === null ? "pending" : conflict ? "true" : "false"}>
              <span>Current conclusion</span>
              <strong>{conflict === null ? "Private check in progress" : conflict ? "Conflict confirmed" : "No conflict found"}</strong>
              <p>{recourse.label}{activeEvidence === null && localView !== null ? " · provisional backend state" : ""}</p>
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
                    disabled={requestState === "creating" || requestState === "executing"}
                    onClick={() => void loadImportedScenario(option, "push")}
                  >
                    {option === "conflict" ? "Conflict" : "No conflict"}
                  </button>
                ))}
              </div>
            </div>
            <p>{progressText}</p>
            {localAdapterOrigin !== null ? (
              <button className={styles.localButton} type="button" disabled={busy} onClick={() => void startLocalRun()}>
                {localMode ? "Start a fresh local case" : "Run this case locally"}
              </button>
            ) : null}
          </section>

          {error === null ? null : <p className={styles.error} role="alert">{error}</p>}

          {activeCase === null ? (
            <section className={styles.localStatus} data-testid="case-loading-status" aria-live="polite" aria-busy={busy}>
              <p>{busy ? "Verified case loading" : "Verified case unavailable"}</p>
              <strong>{busy ? progressText : error ?? "No authoritative case is selected."}</strong>
              {currentRunId === null ? null : <code>Durable run · {currentRunId}</code>}
              {currentRunId !== null && localAdapterOrigin !== null && !busy ? (
                <button type="button" onClick={() => void resumeLocalRun(currentRunId, scenario, "replace")}>Resume durable run</button>
              ) : null}
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
                <header><p>Case chronology</p><h2 id="timeline-heading">Asset → private result → recourse</h2></header>
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

          <section className={styles.claimBoundary}>
            <p>{PRODUCT_CLAIM}</p>
            <strong>{PRODUCT_DISCLOSURE}</strong>
            {activeEvidence?.chronology.clockClass === "SIMULATED_PROTOCOL_CLOCK" ? (
              <strong>Simulation disclosure: cure-window completion and recourse availability are simulated protocol time, not observed wall-clock chronology.</strong>
            ) : null}
          </section>
        </main>
      </div>

      {drawerOpen && activeEvidence !== null ? (
        <EvidenceDrawer evidence={activeEvidence} onClose={() => setDrawerOpen(false)} returnFocus={drawerTrigger} />
      ) : null}
    </div>
  );
}

const FHE_PROFILE_LABEL = "BGV · IdentityFullFHE256 · N15";
const PRODUCT_CLAIM = "Mordant’s fixed local BGV circuit evaluates two synthetic pledge fixtures and releases one governed Boolean into a local recourse protocol double.";
const PRODUCT_DISCLOSURE = "The Cleanverse / Monad testnet identity is retained real observed provenance. No real lender funds or submissions are used. The designated decryptor is trusted; threshold release, native Monad FHE, live settlement and production custody isolation are not claimed.";
