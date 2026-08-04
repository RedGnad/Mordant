"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import styles from "./live-execution.module.css";

/**
 * Bounded live-execution surface.
 *
 * Separate from ProtectionExperience on purpose: this component talks only to
 * the managed execution worker, and it never needs the V1 imported-evidence
 * machinery. It shows no outcome wording until the governed decryptor has
 * released a signed Boolean.
 */

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const POLL_INTERVAL_MS = 2_000;
const MAX_POLLS = 300;

const FIELDS = [
  { key: "aFrom", label: "Participant A pledge start", role: "participantA", bound: "activeFrom" },
  { key: "aUntil", label: "Participant A pledge end", role: "participantA", bound: "activeUntil" },
  { key: "bFrom", label: "Participant B pledge start", role: "participantB", bound: "activeFrom" },
  { key: "bUntil", label: "Participant B pledge end", role: "participantB", bound: "activeUntil" },
] as const;

type FieldKey = (typeof FIELDS)[number]["key"];

type LiveView = Readonly<{
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
  }>;
  participantArtifactDigests: Readonly<{ participantA: string | null; participantB: string | null }>;
  evaluatedArtifactDigest: string | null;
  governedResult: null | Readonly<{ conflict: boolean; digest: string; releaseMode: string }>;
  recourse: null | Readonly<{ opened: boolean; reason: string | null }>;
  receipt: Readonly<Record<string, unknown>> | null;
}>;

const STAGE_SEQUENCE = [
  "Case authorized",
  "Private encryption prepared",
  "Participant A encrypted",
  "Participant B encrypted",
  "Encrypted evaluation running",
  "Governed result verification",
  "Recourse application",
  "Receipt sealed",
] as const;

function digestText(value: unknown): string {
  return typeof value === "string" ? value : "not present";
}

/** Only safe, non-private receipt fields are ever rendered. */
function receiptRows(receipt: Readonly<Record<string, unknown>>): ReadonlyArray<readonly [string, string]> {
  const authorization = (receipt.authorization ?? {}) as Record<string, unknown>;
  const execution = (receipt.execution ?? {}) as Record<string, unknown>;
  const governed = (receipt.governedResult ?? {}) as Record<string, unknown>;
  const terminal = (receipt.terminal ?? {}) as Record<string, unknown>;
  const artifacts = (execution.participantArtifactDigests ?? []) as unknown[];
  return [
    ["Execution variant", digestText(receipt.executionVariant)],
    ["Protection-binding digest", digestText(authorization.protectionBindingDigest)],
    ["FHE CaseID", digestText(authorization.fheCaseId)],
    ["Case-binding digest", digestText(authorization.caseBindingDigest)],
    ["Participant A artifact digest", digestText(artifacts[0])],
    ["Participant B artifact digest", digestText(artifacts[1])],
    ["Evaluated artifact digest", digestText(execution.evaluatedArtifactDigest)],
    ["Governed result digest", digestText(governed.digest)],
    ["Result ciphertext digest", digestText(governed.resultCiphertextDigest)],
    ["Evaluator provenance", digestText(execution.evaluatorProvenance)],
    ["Decryptor provenance", digestText(execution.decryptorProvenance)],
    [
      terminal.recourseRecordDigest === null ? "Recourse" : "Recourse record digest",
      terminal.recourseRecordDigest === null ? "Signed result cleared the case" : digestText(terminal.recourseRecordDigest),
    ],
    ["Terminal state", `${digestText(terminal.incidentState)} · ${digestText(terminal.recourseState)}`],
    ["Original receivable", digestText(terminal.originalReceivableState)],
    ["Receipt digest", digestText(receipt.receiptDigest)],
  ];
}

export function LiveExecution({ workerOrigin, initialRunId }: {
  readonly workerOrigin: string;
  readonly initialRunId: string | null;
}) {
  const [values, setValues] = useState<Record<FieldKey, string>>({ aFrom: "120", aUntil: "420", bFrom: "220", bUntil: "520" });
  const [invalid, setInvalid] = useState<ReadonlySet<FieldKey>>(new Set());
  const [formError, setFormError] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(initialRunId);
  const [view, setView] = useState<LiveView | null>(null);
  const [progress, setProgress] = useState<string | null>(null);
  const [status, setStatus] = useState<"idle" | "starting" | "running" | "terminal" | "busy" | "unavailable">(
    initialRunId === null ? "idle" : "running",
  );
  const [drawerOpen, setDrawerOpen] = useState(false);
  const polls = useRef(0);

  const complete = view?.stage === "COMPLETE" && view.receipt !== null;
  const released = view?.governedResult !== null && view?.governedResult !== undefined;

  const parse = useCallback((): { windows: unknown | null; bad: Set<FieldKey>; message: string | null } => {
    const bad = new Set<FieldKey>();
    const parsed: Partial<Record<FieldKey, number>> = {};
    for (const field of FIELDS) {
      const raw = values[field.key].trim();
      const value = /^\d+$/u.test(raw) ? Number(raw) : Number.NaN;
      if (!Number.isSafeInteger(value) || value < 0) bad.add(field.key);
      else parsed[field.key] = value;
    }
    if (bad.size > 0) return { windows: null, bad, message: "Each bound must be a whole number, zero or greater." };
    // Each interval is checked on its own. Participant A is never compared with
    // Participant B here: only the encrypted evaluation may answer that.
    for (const [role, keys] of [["A", ["aFrom", "aUntil"]], ["B", ["bFrom", "bUntil"]]] as const) {
      if (parsed[keys[0]]! >= parsed[keys[1]]!) {
        keys.forEach((key) => bad.add(key));
        return { windows: null, bad, message: `Participant ${role} must start strictly before it ends.` };
      }
    }
    return {
      windows: {
        participantA: { activeFrom: parsed.aFrom!, activeUntil: parsed.aUntil! },
        participantB: { activeFrom: parsed.bFrom!, activeUntil: parsed.bUntil! },
      },
      bad,
      message: null,
    };
  }, [values]);

  const start = useCallback(async () => {
    const { windows, bad, message } = parse();
    setInvalid(bad);
    setFormError(message);
    if (windows === null) return;
    setStatus("starting");
    try {
      const tokenResponse = await fetch("/api/live-protection/token", { method: "POST", cache: "no-store" });
      if (!tokenResponse.ok) throw new Error("Live execution is not available right now.");
      const issued = await tokenResponse.json() as { token: string; workerOrigin: string };
      // The windows go straight to the worker. Vercel never sees them.
      const created = await fetch(`${issued.workerOrigin}/v1/custom-cases`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${issued.token}` },
        body: JSON.stringify(windows),
        cache: "no-store",
      });
      if (created.status === 409) { setStatus("busy"); return; }
      if (!created.ok) throw new Error("The execution service refused the request.");
      const body = await created.json() as { view: LiveView; progress: string };
      // The submitted values leave rendered state at admission.
      setValues({ aFrom: "", aUntil: "", bFrom: "", bUntil: "" });
      setRunId(body.view.runId);
      setView(body.view);
      setProgress(body.progress);
      setStatus("running");
      window.history.pushState(null, "", `/protection/live?runId=${body.view.runId}`);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Live execution could not be started.");
      setStatus("idle");
    }
  }, [parse]);

  useEffect(() => {
    if (runId === null || !RUN_ID.test(runId) || status === "terminal") return;
    let cancelled = false;
    const timer = setInterval(() => {
      void (async () => {
        if (cancelled) return;
        polls.current += 1;
        if (polls.current > MAX_POLLS) { clearInterval(timer); return; }
        try {
          const response = await fetch(`${workerOrigin}/v1/custom-cases/${runId}`, { cache: "no-store" });
          if (!response.ok) return;
          const body = await response.json() as { view: LiveView; progress: string };
          if (cancelled) return;
          setView(body.view);
          setProgress(body.progress);
          if (body.view.stage === "COMPLETE" && body.view.receipt !== null) setStatus("terminal");
        } catch {
          if (!cancelled) setStatus("unavailable");
        }
      })();
    }, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [runId, status, workerOrigin]);

  const reachedIndex = useMemo(() => {
    if (view === null) return -1;
    const map: Record<string, number> = {
      CASE_CREATED: 0, MATCH_PREPARED: 1, PARTICIPANT_A_SUBMITTED: 2,
      PARTICIPANT_B_PUBLISHED: 3, PARTICIPANT_B_SUBMITTED: 3, EVALUATED: 4,
      RELEASED: 5, RECOURSE_OPENED: 6, CHRONOLOGY_COMPLETE: 6, COMPLETE: 7,
    };
    return map[view.stage] ?? 0;
  }, [view]);

  if (status === "busy") {
    return (
      <section className={styles.notice}>
        <h2>A private check is currently running.</h2>
        <p>The next execution slot will open when it completes.</p>
        <a className={styles.secondary} href="/protection?scenario=conflict">View verified protection evidence</a>
      </section>
    );
  }

  if (status === "unavailable") {
    return (
      <section className={styles.notice}>
        <h2>Live execution is unavailable right now.</h2>
        <p>The verified protection evidence remains available.</p>
        <a className={styles.secondary} href="/protection?scenario=conflict">View verified protection evidence</a>
      </section>
    );
  }

  if (runId === null) {
    return (
      <section className={styles.panel}>
        <p className={styles.eyebrow}>Live encrypted execution</p>
        <h1 className={styles.title}>Run a real encrypted conflict check.</h1>
        <p className={styles.lede}>
          Mordant encrypts the submitted demo pledge windows before the FHE evaluator processes them.
          The evaluator receives ciphertexts only.
        </p>
        {formError === null ? null : <p className={styles.error} role="alert">{formError}</p>}
        <div className={styles.grid}>
          {FIELDS.map((field) => (
            <label key={field.key} htmlFor={`live-${field.key}`}>
              {field.label}
              <input
                id={`live-${field.key}`}
                type="text"
                inputMode="numeric"
                autoComplete="off"
                value={values[field.key]}
                aria-invalid={invalid.has(field.key)}
                disabled={status === "starting"}
                onChange={(event) => {
                  const next = event.target.value;
                  setValues((current) => ({ ...current, [field.key]: next }));
                }}
              />
            </label>
          ))}
        </div>
        <div className={styles.fixed}>
          <strong>Fixed for this execution</strong>
          <ul>
            <li>Cleanverse asset MINV01 and its canonical receivable identity</li>
            <li>aUSDC, protected amount and the exclusive pledge policy</li>
            <li>The fixed BGV circuit and its parameter profile</li>
            <li>Governed release by the designated decryptor</li>
          </ul>
        </div>
        <button className={styles.primary} type="button" disabled={status === "starting"} onClick={() => void start()}>
          {status === "starting" ? "Starting encrypted check" : "Start encrypted check"}
        </button>
      </section>
    );
  }

  return (
    <section className={styles.panel}>
      <p className={styles.eyebrow}>Live encrypted execution</p>
      <h1 className={styles.title}>
        {!released
          ? "Private evaluation in progress."
          : view!.governedResult!.conflict ? "Conflict confirmed" : "No conflict found"}
      </h1>
      {!released ? (
        <p className={styles.lede}>
          The evaluator is processing ciphertexts. No result exists until the governed decryptor releases a signed Boolean.
        </p>
      ) : (
        <p className={styles.lede}>
          {view!.governedResult!.conflict ? "Recourse opened" : "Signed result cleared the case"}
        </p>
      )}

      <ol className={styles.stages} aria-live="polite">
        {STAGE_SEQUENCE.map((label, index) => (
          <li key={label} data-state={index < reachedIndex ? "done" : index === reachedIndex ? "active" : "pending"}>
            {label}
          </li>
        ))}
      </ol>
      {progress === null ? null : <p className={styles.progress}>{progress}</p>}
      <code className={styles.run}>Run {runId}</code>

      {!complete ? null : (
        <button className={styles.primary} type="button" onClick={() => setDrawerOpen(true)}>
          View execution receipt
        </button>
      )}

      {!drawerOpen || view?.receipt == null ? null : (
        <div className={styles.drawer} role="dialog" aria-modal="true" aria-label="Execution receipt">
          <header>
            <h2>Execution receipt</h2>
            <button type="button" onClick={() => setDrawerOpen(false)}>Close</button>
          </header>
          <p className={styles.receiptNote}>Local supervised receipt from the managed execution service.</p>
          <dl>
            {receiptRows(view.receipt).map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </section>
  );
}
