"use client";

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

import styles from "./transaction-driven-experience.module.css";

const LIVE_ENDPOINT = "/api/dealroom/living-demo";
const REVIEW_ENDPOINT = "/api/dealroom/living-demo?source=review";
const POLL_INTERVAL_MS = 400;

type RequestState = "idle" | "executing" | "resetting";
type CheckpointOption = {
  id: RecordedCheckpointId;
  label: string;
  actionId: string;
};

const PUBLIC_RECORDED_CHECKPOINTS: ReadonlyArray<CheckpointOption> = [
  { id: "funding", label: "Funded", actionId: "approve-funding" },
  { id: "reveal", label: "Conflict detected", actionId: "reveal" },
  { id: "deadline", label: "Responsibility assigned", actionId: "cure-window" },
  { id: "entitlement", label: "Deadline outcome", actionId: "finalize" },
  { id: "claims", label: "Proof retained", actionId: "claim-b" },
];

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

function RecordedCheckpointRail({
  run,
  selectedId,
  surface,
  checkpoints,
  onSelect,
}: {
  readonly run: LivingRunArtifact;
  readonly selectedId: RecordedCheckpointId;
  readonly surface: LivingSurface;
  readonly checkpoints: ReadonlyArray<CheckpointOption>;
  readonly onSelect: (id: RecordedCheckpointId) => void;
}) {
  const listRef = useRef<HTMLOListElement>(null);

  useEffect(() => {
    const list = listRef.current;
    const selected = list?.querySelector<HTMLElement>("[data-selected='true']");
    if (list === null || list === undefined || selected === null || selected === undefined) return;
    list.scrollLeft = Math.max(0, selected.offsetLeft - (list.clientWidth - selected.offsetWidth) / 2);
  }, [selectedId]);

  return (
    <nav
      className={surface === "workspace" ? styles.workspaceQueue : styles.checkpointStrip}
      aria-label="Recorded run checkpoints"
      data-testid="recorded-checkpoint-rail"
      data-count={checkpoints.length}
    >
      <header>
        <p>Recorded run</p>
        <strong>{checkpoints.length} {checkpoints === PUBLIC_RECORDED_CHECKPOINTS ? "moments" : "checkpoints"}</strong>
      </header>
      <ol ref={listRef}>
        {checkpoints.map((checkpoint, index) => {
          const action = run.actions.find((candidate) => candidate.id === checkpoint.actionId);
          const selected = checkpoint.id === selectedId;
          return (
            <li key={checkpoint.id}>
              <button
                type="button"
                aria-current={selected ? "step" : undefined}
                aria-pressed={selected}
                data-checkpoint-id={checkpoint.id}
                data-selected={selected ? "true" : "false"}
                disabled={action?.status !== "confirmed"}
                onClick={() => onSelect(checkpoint.id)}
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{checkpoint.label}</strong>
                <small>{action?.receipt === undefined ? "Block checkpoint" : "Confirmed receipt"}</small>
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export function TransactionDrivenExperience({
  surface,
  mode = "live",
  timeline = "complete",
}: {
  readonly surface: LivingSurface;
  readonly mode?: "live" | "review";
  readonly timeline?: "complete" | "public";
}) {
  const endpoint = mode === "review" ? REVIEW_ENDPOINT : LIVE_ENDPOINT;
  const readOnly = mode === "review";
  const [run, setRun] = useState<LivingRunArtifact | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [requestState, setRequestState] = useState<RequestState>("idle");
  const [proofOpen, setProofOpen] = useState(false);
  const defaultCheckpointId = timeline === "public" ? "funding" : DEFAULT_RECORDED_CHECKPOINT_ID;
  const checkpoints = timeline === "public" ? PUBLIC_RECORDED_CHECKPOINTS : RECORDED_CHECKPOINTS;
  const [selectedCheckpointId, setSelectedCheckpointId] = useState<RecordedCheckpointId>(defaultCheckpointId);
  const proofTitleRef = useRef<HTMLHeadingElement>(null);
  const proofTriggerRef = useRef<HTMLButtonElement>(null);
  const requestSequence = useRef(0);

  const refresh = useCallback(async (quiet = false) => {
    const sequence = requestSequence.current + 1;
    requestSequence.current = sequence;
    try {
      const response = await fetch(endpoint, { cache: "no-store" });
      const next = await responseBody(response);
      if (requestSequence.current === sequence) {
        setRun(next);
        setError(null);
      }
    } catch (nextError) {
      if (!quiet && requestSequence.current === sequence) {
        setError(nextError instanceof Error ? nextError.message : "Unknown controlled run error");
      }
    }
  }, [endpoint]);

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const interval = readOnly ? undefined : window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh(true);
    }, POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initial);
      if (interval !== undefined) window.clearInterval(interval);
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

  const selectCheckpoint = useCallback((id: RecordedCheckpointId) => {
    setSelectedCheckpointId(id);
    setProofOpen(false);
    const url = new URL(window.location.href);
    url.searchParams.set("checkpoint", id);
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
    window.dispatchEvent(new CustomEvent("mordant-checkpoint-change", { detail: { id } }));
  }, []);

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

  const closeProof = useCallback(() => {
    setProofOpen(false);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => proofTriggerRef.current?.focus({ preventScroll: true }));
    });
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

  if (proofOpen && proofAction !== null) {
    return (
      <section
        className={styles.proof}
        data-testid="living-proof"
        data-deal-id={run.deal.id}
        aria-labelledby="living-proof-title"
      >
        <header className={styles.proofLead}>
          <p className={styles.sourceLabel}>{receipt === undefined ? "Checkpoint proof" : "Receipt proof"}</p>
          <h1 id="living-proof-title" ref={proofTitleRef} tabIndex={-1}>
            {proofAction.title} {receipt === undefined ? "recorded." : "confirmed."}
          </h1>
          <p>{receipt === undefined
            ? "The controlled block checkpoint with its before and after contract reads."
            : "The receipt with its before and after contract reads."}</p>
        </header>

        <dl className={styles.receiptSummary}>
          <div><dt>Actor</dt><dd>{proofAction.actorLabel}</dd></div>
          <div><dt>Transaction</dt><dd className={styles.technicalValue}>{receipt === undefined ? "No transaction" : compactTechnicalValue(receipt.transactionHash)}</dd></div>
          <div><dt>Block</dt><dd className={styles.technicalValue}>{receipt?.blockNumber ?? proofAction.after?.blockNumber ?? proofAction.before.blockNumber}</dd></div>
          <div><dt>Status</dt><dd>{receipt?.status ?? proofAction.status}</dd></div>
        </dl>

        <section className={styles.transitionProof} aria-label="Before action after proof">
          <article>
            <span>Before · block {proofAction.before.blockNumber}</span>
            <strong>{PROTECTION_STATES[proofAction.before.protectionState]}</strong>
            <small>Receivable · {RECEIVABLE_STATES[proofAction.before.receivableState]}</small>
          </article>
          <article className={styles.proofAction}>
            <span>Action</span>
            <strong>{proofAction.title}</strong>
            <small>{proofAction.actorLabel}</small>
          </article>
          <article>
            <span>After · block {proofAction.after?.blockNumber}</span>
            <strong>{PROTECTION_STATES[proofAction.after?.protectionState ?? proofAction.before.protectionState]}</strong>
            <small>Receivable · {RECEIVABLE_STATES[proofAction.after?.receivableState ?? proofAction.before.receivableState]}</small>
          </article>
        </section>

        <details className={styles.technical} data-testid="living-technical-proof">
          <summary>Technical record</summary>
          <dl>
            <div><dt>Source</dt><dd>{run.source.label}</dd></div>
            <div><dt>Run</dt><dd>{run.runId}</dd></div>
            <div><dt>Checkpoint</dt><dd>{recordedSelection?.checkpoint.label ?? proofAction.title}</dd></div>
            {proofAction.contract === null ? null : <div><dt>Contract</dt><dd>{proofAction.contract}</dd></div>}
            {proofAction.method === null ? null : <div><dt>Method</dt><dd>{proofAction.method}</dd></div>}
            <div><dt>Deal</dt><dd>{run.deal.id}</dd></div>
            <div><dt>Vault</dt><dd>{run.deal.vault}</dd></div>
            <div><dt>Invoice root</dt><dd>{run.deal.invoiceRoot}</dd></div>
            {receipt === undefined ? null : <div><dt>Transaction hash</dt><dd>{receipt.transactionHash}</dd></div>}
            <div><dt>Block hash</dt><dd>{receipt?.blockHash ?? proofAction.after?.blockHash ?? proofAction.before.blockHash}</dd></div>
            {receipt === undefined ? null : <div><dt>Gas used</dt><dd>{receipt.gasUsed}</dd></div>}
          </dl>
          {receipt !== undefined && receipt.events.length > 0 ? (
            <section className={styles.events} aria-label="Observed events">
              <p>Observed events</p>
              <ul>{receipt.events.map((event) => <li key={event}>{event}</li>)}</ul>
            </section>
          ) : null}
          {timeline === "public" ? (
            <section className={styles.completeRun} aria-label="Complete recorded run">
              <p>Complete recorded run · {run.actions.filter((action) => action.receipt !== undefined).length} transactions</p>
              <ol>
                {run.actions.filter((action) => action.receipt !== undefined).map((action) => (
                  <li key={action.id}>
                    <span>{action.title}</span>
                    <code>{compactTechnicalValue(action.receipt?.transactionHash ?? "")}</code>
                  </li>
                ))}
              </ol>
            </section>
          ) : null}
        </details>

        <footer className={styles.proofControls}>
          <button type="button" onClick={closeProof}>Back to selected checkpoint</button>
        </footer>
      </section>
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
      data-execution-mode={mode}
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

      {readOnly && recordedSelection !== null && surface !== "workspace" ? (
        <RecordedCheckpointRail
          run={run}
          selectedId={recordedSelection.checkpoint.id}
          surface={surface}
          checkpoints={checkpoints}
          onSelect={selectCheckpoint}
        />
      ) : null}

      {surface === "workspace" ? (
        <div className={styles.workspaceLayout}>
          {readOnly && recordedSelection !== null ? (
            <RecordedCheckpointRail
              run={run}
              selectedId={recordedSelection.checkpoint.id}
              surface={surface}
              checkpoints={checkpoints}
              onSelect={selectCheckpoint}
            />
          ) : <div />}

          <section className={styles.workspaceFocus} data-region="truth" data-dominant="true">
            <p className={styles.eyebrow}>{view.eyebrow}</p>
            <h1 data-testid="living-conclusion">{view.title}</h1>
            <p>{view.support}</p>
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

          <aside className={styles.workspaceDecision} data-region="responsibility">
            <p>Responsible now</p>
            <strong>{view.responsible}</strong>
            {view.deadline === null ? null : <time>{view.deadline}</time>}
            <div><p>Consequence</p><span>{view.consequence}</span></div>
            <div><p>Recorded next step</p><span>{recordedNextStep}</span></div>
            {readOnly ? (
              <button
                type="button"
                ref={proofTriggerRef}
                className={styles.proofLink}
                disabled={proofAction === null}
                onClick={() => setProofOpen(true)}
              >
                {proofButtonLabel}
              </button>
            ) : null}
          </aside>
        </div>
      ) : surface === "participant" ? (
        <div className={`${styles.scene} ${styles.participantScene}`}>
          <section className={styles.truth} data-region="truth" data-dominant="true">
            <p className={styles.eyebrow}>{view.eyebrow}</p>
            <h1 data-testid="living-conclusion">{view.title}</h1>
            <p>{view.support}</p>
          </section>

          <section className={styles.economics} data-region="economics" aria-label="Your separate positions">
            <article className={styles.receivable} data-testid="living-receivable-anchor">
              <p>Your receivable</p>
              <strong>{formatDemoAmount(displayedRun.current.holderAUnits)} <small>units</small></strong>
              <span>{receivableLabel}</span>
            </article>
            <article className={styles.protection}>
              <p>Protection reserve</p>
              <strong>{formatDemoAmount(run.deal.protectionAmount)} <small>dSETTLE</small></strong>
              <span>{protectionLabel}</span>
            </article>
          </section>

          <aside className={styles.responsibility} data-region="responsibility">
            <p>Responsible before deadline</p>
            <strong>{view.responsible}</strong>
            {view.deadline === null ? null : <time>{view.deadline}</time>}
            <span>{view.consequence}</span>
            <em>Your current status · {view.safeAction}</em>
            {readOnly ? (
              <button type="button" ref={proofTriggerRef} className={styles.proofLink} disabled={proofAction === null} onClick={() => setProofOpen(true)}>
                {proofButtonLabel}
              </button>
            ) : null}
          </aside>
        </div>
      ) : (
        <div className={styles.protocolLayout}>
          <section className={styles.protocolTruth} data-region="truth" data-dominant="true">
            <p className={styles.eyebrow}>{view.eyebrow}</p>
            <h1 data-testid="living-conclusion">{view.title}</h1>
            <p>{receipt === undefined
              ? "The controlled checkpoint advanced and the contract state was read back."
              : `${proofAction?.actorLabel ?? view.responsible} completed the transition and the contract state was read back.`}</p>
          </section>

          <section className={styles.protocolDiagnosis} aria-label="Impact, last safe state, and recovery">
            <article>
              <p>Impact</p>
              <strong>{view.consequence}</strong>
            </article>
            <article>
              <p>{readOnly ? "Last safe state" : "Last safe block"}</p>
              <strong>Receivable · {RECEIVABLE_STATES[proofAction?.before.receivableState ?? displayedRun.lastSafeState.receivableState]}</strong>
              <span>Protection · {PROTECTION_STATES[proofAction?.before.protectionState ?? displayedRun.lastSafeState.protectionState]}</span>
            </article>
            <article className={styles.protocolRecovery}>
              <p>Recovery</p>
              <strong>{recordedNextStep}</strong>
              {view.deadline === null ? null : <time>{view.deadline}</time>}
              <span>{view.responsible} is responsible.</span>
            </article>
          </section>

          <footer className={styles.protocolProofControl}>
            <p><strong>{receipt === undefined ? "Checkpoint proof" : "Receipt proof"}</strong><span>Before → action → after</span></p>
            {readOnly ? (
              <button type="button" ref={proofTriggerRef} className={styles.proofLink} disabled={proofAction === null} onClick={() => setProofOpen(true)}>
                {proofButtonLabel}
              </button>
            ) : null}
          </footer>
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
            onClick={() => setProofOpen(true)}
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

      {error === null ? null : <p className={styles.requestError} role="alert">{error}</p>}
      <p className="visually-hidden" aria-live="polite" aria-atomic="true">
        Revision {displayedRun.revision}. {view.title}
      </p>
    </section>
  );
}
