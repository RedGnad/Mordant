"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import type { ManagedWorkerStage, ManagedWorkerView } from "./managed-intake-adapter";
import {
  ManagedResponseRejected,
  readManagedRun,
  startManagedRun,
  type ManagedWindows,
} from "./managed-run-client";
import styles from "./mini-live-check.module.css";

/**
 * The shortest honest explanation of Mordant: one verified receivable, two
 * private windows, a real encrypted decision.
 *
 * It runs the SAME managed execution the live product runs, through the same
 * client, against the same single worker slot. There is no fixture branch and no
 * simulated progress: every state below is read from the worker's own durable
 * projection, and no result is shown before the governed release stage.
 *
 * What it deliberately is not: two independent wallets. The managed path
 * prepares both windows on the visitor's behalf under one eligible test context,
 * which is why the copy says so and points at the two-wallet run for the rest.
 */

const POLL_INTERVAL_MS = 2_000;
const MAX_POLLS = 300;
const FAILURES_BEFORE_UNAVAILABLE = 3;

/** Overlapping by construction, so the default run demonstrates a real conflict. */
const DEFAULT_WINDOWS: ManagedWindows = Object.freeze({
  participantA: Object.freeze({ activeFrom: 120, activeUntil: 420 }),
  participantB: Object.freeze({ activeFrom: 220, activeUntil: 520 }),
});

/**
 * What each worker stage means in plain words.
 *
 * Mapped from the worker's own vocabulary rather than invented, so the line on
 * screen can only ever describe a stage the run has actually reached.
 */
const STAGE_LABEL: Readonly<Record<ManagedWorkerStage, string>> = Object.freeze({
  CASE_CREATED: "Authorizing live execution",
  MATCH_PREPARED: "Preparing encrypted artifacts",
  PARTICIPANT_A_SUBMITTED: "Participant A encrypted",
  PARTICIPANT_B_PUBLISHED: "Participant B encrypting",
  PARTICIPANT_B_SUBMITTED: "Participant B encrypted",
  EVALUATED: "BGV evaluation running",
  RELEASED: "Governed result verification",
  RECOURSE_OPENED: "Applying recourse",
  CHRONOLOGY_COMPLETE: "Sealing the receipt",
  COMPLETE: "Complete",
  ABORTED: "Execution stopped",
});

type Phase =
  | Readonly<{ kind: "IDLE" }>
  | Readonly<{ kind: "STARTING" }>
  | Readonly<{ kind: "RUNNING" }>
  | Readonly<{ kind: "BUSY" }>
  | Readonly<{ kind: "REFUSED"; title: string; body: string }>;

const CLEANVERSE_BOUNDARIES = [
  { name: "MINV01", role: "Verified receivable", by: "Cleanverse" },
  { name: "A-Pass", role: "Eligible participant context", by: "Cleanverse" },
  { name: "Mordant", role: "Private conflict decision", by: "Mordant" },
  { name: "aUSDC on Monad", role: "Governed recourse evidence", by: "Monad" },
] as const;

/** The governed Boolean is the only thing allowed to name an outcome. */
function verdictOf(view: ManagedWorkerView | null): "conflict" | "no-conflict" | null {
  if (view === null || view.governedResult === null) return null;
  return view.governedResult.conflict ? "conflict" : "no-conflict";
}

export function MiniLiveCheck({ publicTestHolder }: { readonly publicTestHolder: string }) {
  const [phase, setPhase] = useState<Phase>({ kind: "IDLE" });
  const [view, setView] = useState<ManagedWorkerView | null>(null);
  const [workerOrigin, setWorkerOrigin] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const startedAt = useRef<number | null>(null);
  const polls = useRef(0);
  const failures = useRef(0);

  const verdict = verdictOf(view);
  const terminal = verdict !== null;
  const runId = view?.runId ?? null;

  const run = useCallback(async () => {
    if (phase.kind === "STARTING" || phase.kind === "RUNNING") return;
    setPhase({ kind: "STARTING" });
    setView(null);
    setElapsed(0);
    polls.current = 0;
    failures.current = 0;

    const outcome = await startManagedRun(publicTestHolder, DEFAULT_WINDOWS);
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
    startedAt.current = Date.now();
    setWorkerOrigin(outcome.workerOrigin);
    setView(outcome.view);
    setPhase({ kind: "RUNNING" });
  }, [phase.kind, publicTestHolder]);

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
              body: `Run ${runId} is still recorded. The completed on-chain recourse below is unaffected.`,
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

  const busy = phase.kind === "STARTING" || phase.kind === "RUNNING";
  const stageLine = phase.kind === "STARTING"
    ? "Authorizing live execution"
    : view === null ? null : STAGE_LABEL[view.stage];

  return (
    <section className={styles.mini} aria-labelledby="mini-title" data-testid="mini-live-check" data-phase={phase.kind}>
      <div className={styles.intro}>
        <p className={styles.eyebrow}>Run it now</p>
        <h2 id="mini-title">One receivable. Two private claims. One encrypted answer.</h2>
        <p className={styles.lede}>
          Two lender windows overlap, and neither lender will publish its book to prove it. Run the
          real check on this page: the evaluator sees ciphertexts only, and no answer exists until the
          governed decryptor signs one.
        </p>

        <dl className={styles.boundaries}>
          {CLEANVERSE_BOUNDARIES.map((item) => (
            <div key={item.name} data-by={item.by}>
              <dt>{item.name}</dt>
              <dd>{item.role}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className={styles.panel}>
        <div className={styles.windows} aria-label="The two synthetic pledge windows">
          <div>
            <span>Participant A</span>
            <strong>{DEFAULT_WINDOWS.participantA.activeFrom} → {DEFAULT_WINDOWS.participantA.activeUntil}</strong>
          </div>
          <div>
            <span>Participant B</span>
            <strong>{DEFAULT_WINDOWS.participantB.activeFrom} → {DEFAULT_WINDOWS.participantB.activeUntil}</strong>
          </div>
        </div>
        <p className={styles.windowNote}>
          Synthetic demo windows, prepared under one eligible test context. They overlap, so this run
          should find a conflict. Neither window is ever visible to the evaluator.
        </p>

        {phase.kind === "IDLE" ? null : (
          <div className={styles.status} role="status" aria-live="polite" data-testid="mini-status">
            {phase.kind === "BUSY" ? (
              <>
                <strong data-testid="mini-busy">A private check is already running.</strong>
                <p>
                  One execution slot exists by design, so this check waits rather than running in
                  parallel. Try again when the current run completes.
                </p>
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
                    ? "The governed decryptor recomputed the circuit and signed the result. A cure window opens and recourse becomes claimable."
                    : "The governed decryptor recomputed the circuit and signed an explicit refusal. No protection becomes claimable."}
                </p>
              </>
            ) : (
              <>
                <span className={styles.spinner} aria-hidden="true" />
                <strong>{stageLine}</strong>
                <span className={styles.elapsed} data-testid="mini-elapsed">{elapsed}s elapsed</span>
              </>
            )}
          </div>
        )}

        {terminal ? (
          <div className={styles.actions}>
            <Link className={styles.primary} href="/protection/verified-run" data-testid="mini-to-verified-run">
              See the completed on-chain recourse
            </Link>
            <Link className={styles.secondary} href={runId === null ? "/protection/live" : `/protection/live?runId=${runId}`}>
              Open this run in full
            </Link>
          </div>
        ) : (
          <button
            type="button"
            className={styles.primaryAction}
            onClick={() => { void run(); }}
            disabled={busy}
            data-testid="mini-run"
          >
            {phase.kind === "STARTING" ? "Starting" : phase.kind === "RUNNING" ? "Running" : "Run live check"}
          </button>
        )}

        <p className={styles.honesty}>
          Real BGV. Two runs on this deployment reached the governed result in 28 and 30 seconds. This
          managed check prepares both windows for you under one eligible test context; it is not two
          independent wallets.
        </p>
      </div>
    </section>
  );
}
