"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import type { ManagedWorkerView } from "./managed-intake-adapter";
import {
  ManagedResponseRejected,
  readManagedRun,
  startManagedRun,
  type ManagedEligibilityObservation,
  type ManagedWindows,
} from "./managed-run-client";
import styles from "./mini-live-check.module.css";

/**
 * The landing's one falsifiable experiment. It uses the same managed client,
 * launch-token request and worker projection as the full live product. The four
 * plaintext bounds go directly from this browser to that existing worker path;
 * neither this component nor the token route compares the two claims.
 */

const POLL_INTERVAL_MS = 2_000;
const MAX_POLLS = 300;
const FAILURES_BEFORE_UNAVAILABLE = 3;

const FIELD_KEYS = ["aFrom", "aUntil", "bFrom", "bUntil"] as const;
type FieldKey = (typeof FIELD_KEYS)[number];
type WindowDraft = Readonly<Record<FieldKey, string>>;

const DEFAULT_DRAFT: WindowDraft = Object.freeze({
  aFrom: "120",
  aUntil: "420",
  bFrom: "220",
  bUntil: "520",
});

const EXPERIMENT_FACTS = [
  { name: "Input", body: "Cleanverse-provenance MINV01 identity plus two visitor-set private financing-claim windows." },
  { name: "Evaluation", body: "One fixed BGV circuit over ciphertexts; the evaluator sees no window." },
  { name: "Release", body: "One governed signed result. No browser prediction and no earlier verdict." },
] as const;

const EXECUTION_PHASES = [
  "Eligibility confirmed",
  "Encrypted artifacts prepared",
  "BGV evaluation completed",
  "Governed result released",
] as const;

type Phase =
  | Readonly<{ kind: "IDLE" }>
  | Readonly<{ kind: "STARTING" }>
  | Readonly<{ kind: "RUNNING" }>
  | Readonly<{ kind: "BUSY" }>
  | Readonly<{ kind: "REFUSED"; title: string; body: string }>;

type ParsedDraft = Readonly<{
  windows: ManagedWindows | null;
  invalid: readonly FieldKey[];
  message: string | null;
}>;

/** Each claim is validated independently. Cross-claim geometry is never read. */
function parseDraft(draft: WindowDraft): ParsedDraft {
  const invalid: FieldKey[] = [];
  const parsed: Partial<Record<FieldKey, number>> = {};
  for (const key of FIELD_KEYS) {
    const raw = draft[key].trim();
    const value = /^\d+$/u.test(raw) ? Number(raw) : Number.NaN;
    if (!Number.isSafeInteger(value) || value < 0) invalid.push(key);
    else parsed[key] = value;
  }
  if (invalid.length > 0) {
    return Object.freeze({
      windows: null,
      invalid: Object.freeze(invalid),
      message: "Each bound must be a decimal whole number, zero or greater.",
    });
  }
  if (parsed.aFrom! >= parsed.aUntil!) {
    return Object.freeze({
      windows: null,
      invalid: Object.freeze(["aFrom", "aUntil"] as const),
      message: "Financing claim A must start strictly before it ends.",
    });
  }
  if (parsed.bFrom! >= parsed.bUntil!) {
    return Object.freeze({
      windows: null,
      invalid: Object.freeze(["bFrom", "bUntil"] as const),
      message: "Financing claim B must start strictly before it ends.",
    });
  }
  return Object.freeze({
    windows: Object.freeze({
      participantA: Object.freeze({ activeFrom: parsed.aFrom!, activeUntil: parsed.aUntil! }),
      participantB: Object.freeze({ activeFrom: parsed.bFrom!, activeUntil: parsed.bUntil! }),
    }),
    invalid: Object.freeze([]),
    message: null,
  });
}

/** The governed Boolean is the only value allowed to name an outcome. */
function verdictOf(view: ManagedWorkerView | null): "conflict" | "no-conflict" | null {
  if (view === null || view.governedResult === null) return null;
  return view.governedResult.conflict ? "conflict" : "no-conflict";
}

function executionPhase(view: ManagedWorkerView | null, eligibility: ManagedEligibilityObservation | null): number | null {
  if (view?.governedResult !== null && view?.governedResult !== undefined) return 3;
  if (view?.evaluatedArtifactDigest !== null && view?.evaluatedArtifactDigest !== undefined) return 2;
  if (view?.participantArtifactDigests.participantA !== null
    && view?.participantArtifactDigests.participantA !== undefined
    && view.participantArtifactDigests.participantB !== null) return 1;
  return eligibility === null ? null : 0;
}

function shortRunId(runId: string): string {
  return runId.slice(0, 8);
}

function shortDigest(digest: string): string {
  return `${digest.slice(0, 15)}…${digest.slice(-8)}`;
}

export function MiniLiveCheck({ publicTestHolder }: { readonly publicTestHolder: string }) {
  const [draft, setDraft] = useState<WindowDraft>(DEFAULT_DRAFT);
  const [submittedDraft, setSubmittedDraft] = useState<WindowDraft | null>(null);
  const [invalid, setInvalid] = useState<readonly FieldKey[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: "IDLE" });
  const [view, setView] = useState<ManagedWorkerView | null>(null);
  const [eligibility, setEligibility] = useState<ManagedEligibilityObservation | null>(null);
  const [workerOrigin, setWorkerOrigin] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const startedAt = useRef<number | null>(null);
  const polls = useRef(0);
  const failures = useRef(0);

  const verdict = verdictOf(view);
  const terminal = verdict !== null;
  const runId = view?.runId ?? null;
  const governedDigest = view?.governedResult?.digest ?? null;
  const evaluationCompleted = view?.evaluatedArtifactDigest !== null
    && view?.evaluatedArtifactDigest !== undefined;
  const phaseIndex = executionPhase(view, eligibility);
  const busy = phase.kind === "STARTING" || phase.kind === "RUNNING";
  const inputsLocked = busy || terminal;
  const displayedDraft = inputsLocked && submittedDraft !== null ? submittedDraft : draft;

  const updateField = (key: FieldKey, value: string) => {
    if (inputsLocked) return;
    setDraft((current) => Object.freeze({ ...current, [key]: value }));
    setInvalid((current) => current.filter((candidate) => candidate !== key));
    setFormError(null);
  };

  const run = useCallback(async () => {
    if (phase.kind === "STARTING" || phase.kind === "RUNNING") return;
    const parsed = parseDraft(draft);
    setInvalid(parsed.invalid);
    setFormError(parsed.message);
    if (parsed.windows === null) return;

    setSubmittedDraft(draft);
    setPhase({ kind: "STARTING" });
    setView(null);
    setEligibility(null);
    setWorkerOrigin(null);
    setElapsed(0);
    startedAt.current = Date.now();
    polls.current = 0;
    failures.current = 0;

    const outcome = await startManagedRun(publicTestHolder, parsed.windows);
    if (outcome.kind === "BUSY") { setPhase({ kind: "BUSY" }); return; }
    if (outcome.kind === "REJECTED") {
      setPhase({
        kind: "REFUSED",
        title: "The execution response was rejected.",
        body: "No result is shown, because the worker projection could not be verified.",
      });
      return;
    }
    if (outcome.kind === "INELIGIBLE") {
      setPhase({
        kind: "REFUSED",
        title: "The test context is not eligible right now.",
        body: "The A-Pass check is made against the chain at submit time, and it refused.",
      });
      return;
    }
    if (outcome.kind === "FAILED") {
      setPhase({ kind: "REFUSED", title: "The check could not be started.", body: outcome.message });
      return;
    }
    setEligibility(outcome.eligibility);
    setWorkerOrigin(outcome.workerOrigin);
    setView(outcome.view);
    setPhase({ kind: "RUNNING" });
  }, [draft, phase.kind, publicTestHolder]);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void run();
  };

  // The worker's durable projection is the only source of progress.
  useEffect(() => {
    if (phase.kind !== "RUNNING" || runId === null || workerOrigin === null || terminal) return;
    let cancelled = false;
    const timer = setInterval(() => {
      void (async () => {
        if (cancelled) return;
        polls.current += 1;
        if (polls.current > MAX_POLLS) { clearInterval(timer); return; }
        try {
          const next = await readManagedRun(workerOrigin, runId);
          if (cancelled) return;
          failures.current = 0;
          setView(next);
        } catch (error) {
          if (cancelled) return;
          if (error instanceof ManagedResponseRejected) {
            setPhase({
              kind: "REFUSED",
              title: "The execution response was rejected.",
              body: "No result is shown, because the durable worker projection could not be verified.",
            });
            return;
          }
          failures.current += 1;
          if (failures.current >= FAILURES_BEFORE_UNAVAILABLE) {
            setPhase({
              kind: "REFUSED",
              title: "The execution service did not answer.",
              body: `Run ${shortRunId(runId)} is still recorded. The separate completed on-chain proof is unaffected.`,
            });
          }
        }
      })();
    }, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [phase.kind, runId, workerOrigin, terminal]);

  useEffect(() => {
    if (startedAt.current === null || terminal || phase.kind !== "RUNNING") return;
    const timer = setInterval(() => {
      setElapsed(Math.round((Date.now() - (startedAt.current ?? Date.now())) / 1_000));
    }, 1_000);
    return () => clearInterval(timer);
  }, [terminal, phase.kind]);

  return (
    <section
      className={styles.mini}
      id="product"
      aria-labelledby="mini-title"
      data-testid="mini-live-check"
      data-phase={phase.kind}
    >
      <div className={styles.intro}>
        <p className={styles.eyebrow}>Run it now</p>
        <h2 id="mini-title">One receivable. Two private claims. One encrypted answer.</h2>
        <p className={styles.lede}>
          Choose two synthetic financing-claim windows. Mordant will evaluate the private geometry;
          this page will not predict it.
        </p>

        <dl className={styles.boundaries} aria-label="Experiment facts">
          {EXPERIMENT_FACTS.map((item) => (
            <div key={item.name}>
              <dt>{item.name}</dt>
              <dd>{item.body}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className={styles.panel}>
        <form onSubmit={submit} noValidate>
          <div className={styles.windows} aria-label="Synthetic financing claim windows">
            {([
              ["A", "aFrom", "aUntil"],
              ["B", "bFrom", "bUntil"],
            ] as const).map(([label, fromKey, untilKey]) => (
              <fieldset key={label}>
                <legend>Financing claim {label}</legend>
                <label>
                  <span>Active from</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    autoComplete="off"
                    value={displayedDraft[fromKey]}
                    disabled={inputsLocked}
                    aria-invalid={invalid.includes(fromKey)}
                    onChange={(event) => updateField(fromKey, event.currentTarget.value)}
                    data-testid={`claim-${label.toLowerCase()}-from`}
                  />
                </label>
                <label>
                  <span>Active until</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    autoComplete="off"
                    value={displayedDraft[untilKey]}
                    disabled={inputsLocked}
                    aria-invalid={invalid.includes(untilKey)}
                    onChange={(event) => updateField(untilKey, event.currentTarget.value)}
                    data-testid={`claim-${label.toLowerCase()}-until`}
                  />
                </label>
              </fieldset>
            ))}
          </div>

          {formError === null ? null : <p className={styles.formError} role="alert">{formError}</p>}
          <p className={styles.windowNote}>
            Synthetic managed test. Both claims are prepared under one eligible test context; the
            visitor owns neither claim. The evaluator never sees these plaintext windows.
          </p>

          {terminal ? null : (
            <button
              type="submit"
              className={styles.primaryAction}
              disabled={busy}
              data-testid="mini-run"
            >
              {phase.kind === "STARTING" ? "Starting" : phase.kind === "RUNNING" ? "Running" : "Run live check"}
            </button>
          )}
        </form>

        {phase.kind === "IDLE" ? null : (
          <div className={styles.status} role="status" aria-live="polite" data-testid="mini-status">
            {phase.kind === "BUSY" ? (
              <>
                <strong data-testid="mini-busy">A private check is already running.</strong>
                <p>One execution slot exists by design. Try again when the current run completes.</p>
              </>
            ) : phase.kind === "REFUSED" ? (
              <>
                <strong>{phase.title}</strong>
                <p>{phase.body}</p>
              </>
            ) : terminal ? (
              <>
                <strong data-testid="mini-verdict" data-verdict={verdict}>
                  {verdict === "conflict" ? "Conflict confirmed" : "No conflict"}
                </strong>
                <p>
                  {verdict === "conflict"
                    ? "The governed result establishes only that the submitted windows conflict. Approved policy and human review determine action owner, deadline, escalation and responsibility."
                    : "The governed result establishes only that the submitted windows do not conflict. It does not approve credit or establish legal validity; policy and human review determine any next action."}
                </p>
              </>
            ) : (
              <>
                <span className={styles.spinner} aria-hidden="true" />
                <strong>{phase.kind === "STARTING" ? "Checking A-Pass eligibility" : EXECUTION_PHASES[phaseIndex ?? 0]}</strong>
                <span className={styles.elapsed} data-testid="mini-elapsed">{elapsed}s elapsed</span>
              </>
            )}
          </div>
        )}

        {runId === null || eligibility === null ? null : (
          <div className={styles.runIdentity} data-testid="mini-run-identity">
            <span>A-Pass checked · observed at block {eligibility.observedBlock}</span>
            <span>Fresh run · {shortRunId(runId)}</span>
          </div>
        )}

        {phaseIndex === null ? null : (
          <ol className={styles.executionPhases} aria-label="Execution phases">
            {EXECUTION_PHASES.map((label, index) => (
              <li key={label} data-state={index < phaseIndex ? "complete" : index === phaseIndex ? "current" : "pending"}>
                {label}
              </li>
            ))}
          </ol>
        )}

        {terminal && runId !== null && eligibility !== null && evaluationCompleted && governedDigest !== null ? (
          <div className={styles.resultArea}>
            <dl className={styles.proofStrip} aria-label="Proof of this managed run" data-testid="mini-proof-strip">
              <div><dt>Fresh run</dt><dd>{shortRunId(runId)}</dd></div>
              <div><dt>A-Pass checked</dt><dd>Block {eligibility.observedBlock}</dd></div>
              <div><dt>BGV evaluation</dt><dd>Completed</dd></div>
              <div><dt>Governed release</dt><dd>Verified</dd></div>
              <div><dt>Elapsed</dt><dd>{elapsed}s</dd></div>
              <div><dt>Result digest</dt><dd><code>{shortDigest(governedDigest)}</code></dd></div>
            </dl>
            <p className={styles.separateRun}>
              The fresh managed result above did not execute Monad or aUSDC settlement. The proof
              below is a separate hardened two-wallet run: its preconfigured demo policy opened the
              cure path, and deployment configuration—not the Boolean—determined holders and payouts.
            </p>
            <div className={styles.actions}>
              <Link className={styles.primary} href="/protection/verified-run" data-testid="mini-to-verified-run">
                Verify the completed on-chain recourse
              </Link>
              <Link className={styles.secondary} href={`/protection/live?runId=${runId}`}>
                Inspect this managed run
              </Link>
            </div>
          </div>
        ) : null}

        <p className={styles.honesty}>
          Real BGV, managed preparation, one eligible synthetic test context. This is not two
          independent wallets and does not claim a fresh Monad settlement.
        </p>
      </div>
    </section>
  );
}
