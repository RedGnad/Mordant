"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  DEFAULT_RECORDED_CHECKPOINT_ID,
  PROTECTION_STATES,
  RECEIVABLE_STATES,
  RECORDED_CHECKPOINTS,
  compactTechnicalValue,
  deriveLivingView,
  formatDemoAmount,
  isRecordedCheckpointId,
  latestReceiptAction,
  selectRecordedCheckpoint,
  type LivingActionRecord,
  type LivingRunArtifact,
  type LivingSurface,
  type RecordedCheckpointId,
} from "@/lib/dealroom/living-demo";

import { RecordedCheckpointRail, type CheckpointOption } from "./recorded-checkpoint-rail";
import styles from "./transaction-driven-experience.module.css";
import { TransactionProof } from "./transaction-proof";

const LIVE_ENDPOINT = "/api/dealroom/living-demo";
const REVIEW_ENDPOINT = "/api/dealroom/living-demo?source=review";
const POLL_INTERVAL_MS = 400;

type RequestState = "idle" | "executing" | "resetting";
type CheckpointMotion = "idle" | "out-forward" | "out-backward" | "in-forward" | "in-backward";

const PUBLIC_RECORDED_CHECKPOINTS: ReadonlyArray<CheckpointOption> = [
  { id: "funding", label: "Funded", actionId: "approve-funding" },
  { id: "reveal", label: "Conflict detected", actionId: "reveal" },
  { id: "deadline", label: "Responsibility assigned", actionId: "cure-window" },
  { id: "entitlement", label: "Deadline outcome", actionId: "finalize" },
  { id: "claims", label: "Proof retained", actionId: "claim-b" },
];

let retainedReviewRun: LivingRunArtifact | null = null;

async function responseBody(response: Response): Promise<LivingRunArtifact> {
  const body = await response.json() as LivingRunArtifact | { error?: string };
  if (!response.ok || !("schemaVersion" in body)) {
    throw new Error("error" in body && body.error ? body.error : "The controlled run did not answer.");
  }
  return body;
}

function surfaceLabel(surface: LivingSurface): string {
  if (surface === "workspace") return "Deal workspace";
  if (surface === "participant") return "Participant deal room";
  return "Protocol operations";
}

function SourceBoundary({ message }: { readonly message: string }) {
  return (
    <section className={styles.unavailable} data-testid="living-demo-unavailable">
      <p className={styles.sourceLabel}>Controlled demo chain unavailable</p>
      <h1>The transaction-driven mode needs its local execution source.</h1>
      <p>{message}</p>
      <code>pnpm localnet</code>
      <p>The normal product surfaces remain available without `?demo=transactions`.</p>
    </section>
  );
}

export function TransactionDrivenExperience({
  surface,
  mode = "live",
  timeline = "complete",
  initialCheckpoint,
}: {
  readonly surface: LivingSurface;
  readonly mode?: "live" | "review";
  readonly timeline?: "complete" | "public";
  readonly initialCheckpoint?: RecordedCheckpointId;
}) {
  const endpoint = mode === "review" ? REVIEW_ENDPOINT : LIVE_ENDPOINT;
  const readOnly = mode === "review";
  const [run, setRun] = useState<LivingRunArtifact | null>(() => readOnly ? retainedReviewRun : null);
  const [error, setError] = useState<string | null>(null);
  const [requestState, setRequestState] = useState<RequestState>("idle");
  const [proofOpen, setProofOpen] = useState(false);
  const [proofClosing, setProofClosing] = useState(false);
  const [checkpointMotion, setCheckpointMotion] = useState<CheckpointMotion>("idle");
  const defaultCheckpointId = timeline === "public" ? "funding" : DEFAULT_RECORDED_CHECKPOINT_ID;
  const checkpoints = timeline === "public" ? PUBLIC_RECORDED_CHECKPOINTS : RECORDED_CHECKPOINTS;
  const [selectedCheckpointId, setSelectedCheckpointId] = useState<RecordedCheckpointId>(initialCheckpoint ?? defaultCheckpointId);
  const proofTitleRef = useRef<HTMLHeadingElement>(null);
  const proofTriggerRef = useRef<HTMLButtonElement>(null);
  const checkpointTimerRef = useRef<number | null>(null);
  const proofTimerRef = useRef<number | null>(null);
  const requestSequence = useRef(0);

  const refresh = useCallback(async (quiet = false) => {
    const sequence = requestSequence.current + 1;
    requestSequence.current = sequence;
    try {
      const response = await fetch(endpoint, { cache: "no-store" });
      const next = await responseBody(response);
      if (requestSequence.current === sequence) {
        if (readOnly) retainedReviewRun = next;
        setRun(next);
        setError(null);
      }
    } catch (nextError) {
      if (!quiet && requestSequence.current === sequence) {
        setError(nextError instanceof Error ? nextError.message : "Unknown controlled run error");
      }
    }
  }, [endpoint, readOnly]);

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const interval = readOnly ? undefined : window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh(true);
    }, POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initial);
      if (interval !== undefined) window.clearInterval(interval);
      if (checkpointTimerRef.current !== null) window.clearTimeout(checkpointTimerRef.current);
      if (proofTimerRef.current !== null) window.clearTimeout(proofTimerRef.current);
      requestSequence.current += 1;
    };
  }, [readOnly, refresh]);

  useEffect(() => {
    if (!readOnly) return;
    const syncCheckpoint = () => {
      const requested = new URL(window.location.href).searchParams.get("checkpoint");
      const requestedCheckpoint = isRecordedCheckpointId(requested) ? requested : defaultCheckpointId;
      setSelectedCheckpointId(checkpoints.some((checkpoint) => checkpoint.id === requestedCheckpoint)
        ? requestedCheckpoint
        : defaultCheckpointId);
    };
    syncCheckpoint();
    window.addEventListener("popstate", syncCheckpoint);
    return () => window.removeEventListener("popstate", syncCheckpoint);
  }, [checkpoints, defaultCheckpointId, readOnly]);

  const commitCheckpoint = useCallback((id: RecordedCheckpointId) => {
    setSelectedCheckpointId(id);
    setProofOpen(false);
    const url = new URL(window.location.href);
    url.searchParams.set("checkpoint", id);
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
    window.dispatchEvent(new CustomEvent("mordant-checkpoint-change", { detail: { id } }));
  }, []);

  const selectCheckpoint = useCallback((id: RecordedCheckpointId) => {
    if (id === selectedCheckpointId || checkpointMotion !== "idle") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      commitCheckpoint(id);
      return;
    }

    const currentIndex = checkpoints.findIndex((checkpoint) => checkpoint.id === selectedCheckpointId);
    const nextIndex = checkpoints.findIndex((checkpoint) => checkpoint.id === id);
    const direction = nextIndex >= currentIndex ? "forward" : "backward";
    setCheckpointMotion(`out-${direction}`);
    checkpointTimerRef.current = window.setTimeout(() => {
      commitCheckpoint(id);
      setCheckpointMotion(`in-${direction}`);
      window.requestAnimationFrame(() => {
        window.requestAnimationFrame(() => setCheckpointMotion("idle"));
      });
    }, 100);
  }, [checkpointMotion, checkpoints, commitCheckpoint, selectedCheckpointId]);

  const mutate = useCallback(async (body: object, state: RequestState) => {
    requestSequence.current += 1;
    setRequestState(state);
    setError(null);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      const next = await responseBody(response);
      // Invalidate any pending poll before installing the terminal mutation
      // response, so a slower pending read cannot overwrite a confirmed receipt.
      requestSequence.current += 1;
      setRun(next);
    } catch (nextError) {
      requestSequence.current += 1;
      setError(nextError instanceof Error ? nextError.message : "Unknown controlled run error");
      await refresh(true);
    } finally {
      setRequestState("idle");
    }
  }, [endpoint, refresh]);

  const finishProofClose = useCallback(() => {
    setProofClosing(false);
    setProofOpen(false);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => proofTriggerRef.current?.focus({ preventScroll: true }));
    });
  }, []);

  const closeProof = useCallback(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      finishProofClose();
      return;
    }
    setProofClosing(true);
    proofTimerRef.current = window.setTimeout(finishProofClose, 180);
  }, [finishProofClose]);

  const openProof = useCallback(() => {
    setProofClosing(false);
    setProofOpen(true);
  }, []);

  useEffect(() => {
    if (!proofOpen) return;
    window.requestAnimationFrame(() => proofTitleRef.current?.focus({ preventScroll: true }));
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeProof();
    };
    window.addEventListener("keydown", onEscape);
    return () => window.removeEventListener("keydown", onEscape);
  }, [closeProof, proofOpen]);

  const recordedSelection = useMemo(
    () => run === null || !readOnly ? null : selectRecordedCheckpoint(run, selectedCheckpointId),
    [readOnly, run, selectedCheckpointId],
  );
  const displayedRun = recordedSelection?.run ?? run;
  const view = useMemo(
    () => displayedRun === null ? null : deriveLivingView(displayedRun, surface),
    [displayedRun, surface],
  );

  if (run === null) {
    if (error !== null) return <SourceBoundary message={error} />;
    return (
      <section className={styles.loading} aria-busy="true" data-testid="living-demo-loading">
        <p className={styles.sourceLabel}>Controlled demo chain</p>
        <h1>Reading the canonical deal…</h1>
      </section>
    );
  }

  if (view === null || displayedRun === null) return null;

  const proofAction: LivingActionRecord | null = recordedSelection?.action ?? latestReceiptAction(displayedRun);
  const nextAction = displayedRun.nextAction;
  const currentAction = nextAction === null
    ? null : displayedRun.actions.find((action) => action.id === nextAction.id) ?? null;
  const actionPending = displayedRun.status === "running" || requestState === "executing";
  const actionLabel = displayedRun.status === "failed" ? `Retry · ${nextAction?.title ?? "failed action"}`
    : surface === "participant" && nextAction?.id === "claim-a" ? "Claim your protection"
      : nextAction?.title ?? "Canonical run complete";
  const protectionLabel = PROTECTION_STATES[displayedRun.current.protectionState] ?? "Unknown";
  const receivableLabel = RECEIVABLE_STATES[displayedRun.current.receivableState] ?? "Unknown";
  const receipt = proofAction?.receipt;
  const proofButtonLabel = receipt === undefined ? "Open checkpoint proof" : "Open receipt proof";
  const recordedNextStep = nextAction?.id === "cure-window"
    ? "Wait for the recorded cure deadline"
    : nextAction?.title ?? "No further action";
  const triageStatus = view.resolved ? "Resolved" : view.abnormal ? "Needs attention" : "Monitoring";

  if (proofOpen && proofAction !== null) {
    return (
      <TransactionProof
        run={run}
        action={proofAction}
        checkpointLabel={recordedSelection?.checkpoint.label ?? proofAction.title}
        publicTimeline={timeline === "public"}
        closing={proofClosing}
        titleRef={proofTitleRef}
        onClose={closeProof}
      />
    );
  }

  return (
    <section
      className={styles.experience}
      data-testid="living-experience"
      data-surface={surface}
      data-deal-id={run.deal.id}
      data-vault={run.deal.vault}
      data-invoice-root={run.deal.invoiceRoot}
      data-source={run.source.kind}
      data-status={displayedRun.status}
      data-checkpoint={recordedSelection?.checkpoint.id}
      data-checkpoint-motion={checkpointMotion}
      data-execution-mode={mode}
      data-timeline={timeline}
      data-abnormal={view.abnormal ? "true" : "false"}
      data-resolved={view.resolved ? "true" : "false"}
    >
      {readOnly ? null : (
        <header className={styles.runContext}>
          <p className={styles.sourceLabel} data-testid="living-source">{run.source.label}</p>
          <p>{surfaceLabel(surface)} · current block <strong data-testid="living-block">{displayedRun.current.blockNumber}</strong></p>
          <p>Protocol doubles</p>
        </header>
      )}

      {readOnly && timeline === "public" && surface === "participant" && recordedSelection !== null ? (
        <RecordedCheckpointRail
          run={run}
          selectedId={recordedSelection.checkpoint.id}
          surface={surface}
          checkpoints={checkpoints}
          publicTimeline
          compact
          onSelect={selectCheckpoint}
        />
      ) : null}

      {surface === "workspace" ? (
        <div className={styles.workspaceLayout}>
          <aside className={styles.workspaceQueueRegion} aria-label="Deal review queue">
            <section className={styles.workspaceQueueSummary}>
              <p>Review queue</p>
              <strong>One receivable selected</strong>
              <span data-status={triageStatus.toLowerCase().replaceAll(" ", "-")}>{triageStatus}</span>
            </section>
            {readOnly ? (
              recordedSelection !== null ? (
                <RecordedCheckpointRail
                  run={run}
                  selectedId={recordedSelection.checkpoint.id}
                  surface={surface}
                  checkpoints={checkpoints}
                  publicTimeline={timeline === "public"}
                  onSelect={selectCheckpoint}
                />
              ) : null
            ) : <p className={styles.liveQueueNote}>The controlled run advances this selected receivable.</p>}
          </aside>

          <section className={styles.workspaceFocus} data-region="truth" data-dominant="true">
            <p className={styles.eyebrow} data-checkpoint-copy>Selected deal · {view.eyebrow}</p>
            <h1 data-testid="living-conclusion" data-checkpoint-copy>{view.title}</h1>
            <p data-checkpoint-copy>{view.support}</p>
            <div className={styles.workspaceEconomics} aria-label="Separate economic domains">
              <article className={styles.receivable} data-testid="living-receivable-anchor">
                <p>Receivable</p>
                <strong>{formatDemoAmount(run.deal.faceValue)} <small>dSETTLE</small></strong>
                <span>{receivableLabel}</span>
              </article>
              <article className={styles.protection}>
                <p>Protection</p>
                <strong>{formatDemoAmount(run.deal.protectionAmount)} <small>dSETTLE</small></strong>
                <span>{protectionLabel}</span>
              </article>
            </div>
          </section>

          <aside className={styles.workspaceDecision} data-region="responsibility" data-checkpoint-copy>
            <p>Next decision</p>
            <strong>{recordedNextStep}</strong>
            <div><p>Responsible now</p><span>{view.responsible}</span></div>
            {view.deadline === null ? null : <div><p>Deadline</p><time>{view.deadline}</time></div>}
            <div><p>Consequence</p><span>{view.consequence}</span></div>
            {readOnly ? (
              <button
                type="button"
                ref={proofTriggerRef}
                className={styles.proofLink}
                disabled={proofAction === null}
                onClick={openProof}
              >
                {proofButtonLabel}
              </button>
            ) : null}
          </aside>
        </div>
      ) : surface === "participant" ? (
        <div className={styles.participantLayout}>
          <div className={styles.participantRoom}>
            <section className={styles.participantTruth} data-region="truth" data-dominant="true" data-checkpoint-copy>
              <p className={styles.participantStatus}>Your current status · {view.safeAction}</p>
              <h1 data-testid="living-conclusion">{view.title}</h1>
              <p>{view.support}</p>
              {readOnly ? (
                <button type="button" ref={proofTriggerRef} className={styles.participantProofLink} disabled={proofAction === null} onClick={openProof}>
                  {proofButtonLabel}
                </button>
              ) : null}
            </section>

            <section className={styles.participantObligation} data-region="economics" aria-label="Your obligation summary">
              <article className={styles.participantAnchor} data-testid="living-receivable-anchor">
                <p>What remains yours</p>
                <strong>{formatDemoAmount(displayedRun.current.holderAUnits)} <small>invoice units</small></strong>
                <span>{receivableLabel}</span>
              </article>
              <dl className={styles.participantFacts} data-checkpoint-copy>
                <div><dt>Responsible</dt><dd>{view.responsible}</dd></div>
                {view.deadline === null ? null : <div><dt>Deadline</dt><dd><time>{view.deadline}</time></dd></div>}
                <div><dt>Protection</dt><dd>{formatDemoAmount(run.deal.protectionAmount)} dSETTLE · {protectionLabel}</dd></div>
                <div><dt>What it means</dt><dd>{view.consequence}</dd></div>
              </dl>
            </section>
          </div>

          {readOnly && timeline !== "public" && recordedSelection !== null ? (
            <RecordedCheckpointRail
              run={run}
              selectedId={recordedSelection.checkpoint.id}
              surface={surface}
              checkpoints={checkpoints}
              publicTimeline={false}
              onSelect={selectCheckpoint}
            />
          ) : null}
        </div>
      ) : (
        <div className={styles.protocolLayout}>
          {readOnly && recordedSelection !== null ? (
            <aside className={styles.protocolLog}>
              <RecordedCheckpointRail
                run={run}
                selectedId={recordedSelection.checkpoint.id}
                surface={surface}
                checkpoints={checkpoints}
                publicTimeline={timeline === "public"}
                onSelect={selectCheckpoint}
              />
            </aside>
          ) : null}

          <div className={styles.protocolConsole}>
            <section className={styles.protocolTruth} data-region="truth" data-dominant="true">
              <p className={styles.eyebrow} data-checkpoint-copy>{view.abnormal ? "Incident" : "Protocol transition"}</p>
              <h1 data-testid="living-conclusion" data-checkpoint-copy>{view.title}</h1>
              <div className={styles.protocolTransition} data-checkpoint-copy>
                <p>Last confirmed transition</p>
                <strong>{proofAction?.title ?? "No confirmed transition"}</strong>
                <span>{proofAction?.actorLabel ?? view.responsible} · {receipt?.status ?? proofAction?.status ?? "ready"}</span>
              </div>
            </section>

            <section className={styles.protocolDiagnosis} aria-label="Impact, last safe state, and recovery">
              <article className={styles.protocolImpact} data-checkpoint-copy>
                <p>Impact</p>
                <strong>{view.consequence}</strong>
              </article>
              <article>
                <p>{readOnly ? "Last safe state" : "Last safe block"}</p>
                <strong>Receivable · {RECEIVABLE_STATES[proofAction?.before.receivableState ?? displayedRun.lastSafeState.receivableState]}</strong>
                <span>Protection · {PROTECTION_STATES[proofAction?.before.protectionState ?? displayedRun.lastSafeState.protectionState]}</span>
              </article>
              <article className={styles.protocolRecovery} data-checkpoint-copy>
                <p>Recovery</p>
                <strong>{recordedNextStep}</strong>
                {view.deadline === null ? null : <time>{view.deadline}</time>}
                <span>{view.responsible} is responsible.</span>
              </article>
            </section>

            <footer className={styles.protocolProofControl} data-checkpoint-copy>
              <p><strong>{receipt === undefined ? "Checkpoint proof" : "Receipt proof"}</strong><span>Before → action → after</span></p>
              {readOnly ? (
                <button type="button" ref={proofTriggerRef} className={styles.proofLink} disabled={proofAction === null} onClick={openProof}>
                  {proofButtonLabel}
                </button>
              ) : null}
            </footer>
          </div>
        </div>
      )}

      {readOnly ? null : (
        <footer className={styles.controls}>
          <div className={styles.executionControl}>
          <p>
            <span>Controlled execution</span>
            <strong>{nextAction === null ? "Complete" : `${nextAction.actorLabel} · ${nextAction.kind}`}</strong>
          </p>
          <button
            type="button"
            className={styles.execute}
            data-testid="living-run-next"
            data-action-id={nextAction?.id}
            disabled={nextAction === null || actionPending || requestState === "resetting"}
            onClick={() => nextAction === null ? undefined : void mutate({ intent: "execute", actionId: nextAction.id }, "executing")}
          >
            {actionPending ? "Waiting for receipt…" : actionLabel}
          </button>
          {currentAction?.status === "pending" ? (
            <p className={styles.pending} role="status" data-testid="living-pending">
              Pending{currentAction.transactionHash ? <> · <span className={styles.technicalValue}>{compactTechnicalValue(currentAction.transactionHash)}</span></> : " · preparing broadcast"}
            </p>
          ) : null}
          {currentAction?.status === "failed" ? (
            <p className={styles.failed} role="alert" data-testid="living-failed">{currentAction.error}</p>
          ) : null}
          </div>

          <div className={styles.secondaryControls}>
          <button
            type="button"
            ref={proofTriggerRef}
            disabled={proofAction === null}
            onClick={openProof}
          >
            Open receipt proof
          </button>
          <button
            type="button"
            disabled={requestState !== "idle" || displayedRun.status === "running"}
            onClick={() => {
              if (window.confirm("Reset this controlled chain to the canonical clean deal?")) {
                void mutate({ intent: "reset" }, "resetting");
              }
            }}
          >
            {requestState === "resetting" ? "Resetting…" : "Reset canonical run"}
          </button>
          </div>
        </footer>
      )}

      {timeline === "public" ? (
        <aside className={styles.pilotConversion} aria-label="Shadow pilot">
          <p><strong>Use this workflow beside your current process.</strong><span>No funds moved. Human validation remains required.</span></p>
          <Link href="/pilot">Apply for a shadow pilot</Link>
        </aside>
      ) : null}

      {error === null ? null : <p className={styles.requestError} role="alert">{error}</p>}
      <p className="visually-hidden" aria-live="polite" aria-atomic="true">
        Revision {displayedRun.revision}. {view.title}
      </p>
    </section>
  );
}
