"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  JOURNEY,
  createClients,
  formatUnits6,
  readDealRoomState,
  type DealRoomState,
  type Deployment,
  type JourneyContext,
  type StepOutcome,
} from "@/lib/dealroom/journey";

/**
 * Transaction-driven deal room.
 *
 * Every business step sends a real transaction to the local chain, waits for its receipt and then
 * re-reads state from the contracts. No business control advances on component state alone.
 */

const PROTECTION_STATES = [
  "Unfunded", "Active", "CommitPending", "ConflictConfirmed", "Entitled", "Released",
];
const RECEIVABLE_STATES = ["Unissued", "Outstanding", "Redeemed", "DefaultOutstanding"];

type StepStatus = "idle" | "pending" | "done" | "failed";

type StepRecord = {
  status: StepStatus;
  outcome?: StepOutcome;
  error?: string;
};

function shorten(value: string): string {
  return value.length <= 18 ? value : `${value.slice(0, 10)}…${value.slice(-6)}`;
}

export function DealRoom() {
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [records, setRecords] = useState<Record<string, StepRecord>>({});
  const [state, setState] = useState<DealRoomState | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const response = await fetch("/api/dealroom/deployment", { cache: "no-store" });
        const body = await response.json();
        if (!response.ok) {
          throw new Error(body?.error ?? "The local deployment is unavailable.");
        }
        if (!cancelled) {
          setDeployment(body as Deployment);
        }
      } catch (error) {
        if (!cancelled) {
          setLoadError(error instanceof Error ? error.message : "Unknown error");
        }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // One mutable context per deployment: the conflict signature produced by one step is consumed by
  // the commit and reveal steps.
  const context = useMemo<JourneyContext | null>(
    () => deployment === null ? null : { deployment, ...createClients(deployment) },
    [deployment],
  );

  const refresh = useCallback(async () => {
    if (context === null) {
      return;
    }
    setState(await readDealRoomState(context));
  }, [context]);

  // First read of on-chain state, once the deployment is known.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (context === null) {
        return;
      }
      const next = await readDealRoomState(context);
      if (!cancelled) {
        setState(next);
      }
    })();
    return () => { cancelled = true; };
  }, [context]);

  const runStep = useCallback(async (id: string) => {
    const step = JOURNEY.find((candidate) => candidate.id === id);
    const active = context;
    if (step === undefined || active === null) {
      return;
    }
    setBusy(true);
    setRecords((previous) => ({ ...previous, [id]: { status: "pending" } }));
    try {
      const outcome = await step.run(active);
      setRecords((previous) => ({ ...previous, [id]: { status: "done", outcome } }));
      await refresh();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown failure";
      // Keep the first line only: viem appends the full request body on revert.
      setRecords((previous) => ({
        ...previous,
        [id]: { status: "failed", error: message.split("\n")[0].slice(0, 220) },
      }));
    } finally {
      setBusy(false);
    }
  }, [context, refresh]);

  if (loadError !== null) {
    return (
      <main className="deal-room">
        <section className="deal-room-empty">
          <span className="badge-local">LOCAL / PROTOCOL DOUBLE / SYNTHETIC</span>
          <h1>The local deal room is not running.</h1>
          <p>{loadError}</p>
          <pre>pnpm localnet</pre>
        </section>
      </main>
    );
  }

  if (deployment === null) {
    return (
      <main className="deal-room">
        <section className="deal-room-empty"><p>Loading the local deployment…</p></section>
      </main>
    );
  }

  const nextStepId = JOURNEY.find(
    (step) => (records[step.id]?.status ?? "idle") !== "done",
  )?.id;

  return (
    <main className="deal-room">
      <header className="deal-room-head">
        <div>
          <span className="badge-local" data-testid="honesty-label">
            LOCAL / PROTOCOL DOUBLE / SYNTHETIC
          </span>
          <h1>Mordant deal room</h1>
          <p>{deployment.warning}</p>
        </div>
        <dl className="chain-facts">
          <div><dt>Network</dt><dd>Anvil, chain {deployment.chainId}</dd></div>
          <div><dt>Vault</dt><dd title={deployment.contracts.vault}>{shorten(deployment.contracts.vault)}</dd></div>
          <div><dt>Settlement</dt><dd title={deployment.contracts.settlement}>{shorten(deployment.contracts.settlement)} · double</dd></div>
        </dl>
      </header>

      <section className="deal-room-state" aria-label="Contract state">
        <h2>State read from the contracts</h2>
        {state === null ? <p>Reading…</p> : (
          <div className="state-grid" data-testid="state-grid">
            <article><span>Protection</span><strong data-testid="protection-state">{PROTECTION_STATES[state.protectionState]}</strong></article>
            <article><span>Receivable</span><strong data-testid="receivable-state">{RECEIVABLE_STATES[state.receivableState]}</strong></article>
            <article><span>Reserve locked</span><strong>{formatUnits6(state.bondLocked)}</strong></article>
            <article><span>Entitlement allocated</span><strong data-testid="entitlement">{formatUnits6(state.entitlementAllocated)}</strong></article>
            <article><span>Entitlement claimed</span><strong>{formatUnits6(state.entitlementClaimed)}</strong></article>
            <article><span>Units outstanding</span><strong>{formatUnits6(state.totalSupply)}</strong></article>
            <article><span>Holder A units</span><strong data-testid="holder-a-units">{formatUnits6(state.holderAUnits)}</strong></article>
            <article><span>Holder B units</span><strong data-testid="holder-b-units">{formatUnits6(state.holderBUnits)}</strong></article>
            <article><span>Holder A settled</span><strong data-testid="holder-a-settlement">{formatUnits6(state.holderASettlement)}</strong></article>
            <article><span>Holder B settled</span><strong data-testid="holder-b-settlement">{formatUnits6(state.holderBSettlement)}</strong></article>
            <article><span>Originator proceeds</span><strong data-testid="originator-settlement">{formatUnits6(state.originatorSettlement)}</strong></article>
            <article><span>Redeemed face</span><strong data-testid="redeemed-face">{formatUnits6(state.redeemedFace)}</strong></article>
          </div>
        )}
      </section>

      <ol className="journey" aria-label="Deal room journey">
        {JOURNEY.map((step, index) => {
          const record = records[step.id] ?? { status: "idle" as StepStatus };
          const isNext = step.id === nextStepId;
          return (
            <li key={step.id} className={`journey-step step-${record.status}`} data-testid={`step-${step.id}`}>
              <div className="journey-head">
                <span className="journey-index">{String(index + 1).padStart(2, "0")}</span>
                <div>
                  <h3>{step.title}</h3>
                  <p>{step.detail}</p>
                </div>
                <div className="journey-meta">
                  <span className="role-chip">{step.role}</span>
                  <span className={`kind-chip kind-${step.kind}`}>
                    {step.kind === "transaction" ? "TRANSACTION"
                      : step.kind === "signature" ? "SIGNATURE, NO TX" : "LOCAL CHAIN"}
                  </span>
                </div>
              </div>

              <div className="journey-body">
                <span className="wallet-line">
                  wallet {shorten(deployment.accounts[step.role].address)}
                </span>

                {record.status === "pending" && (
                  <span className="tx-line pending" data-testid={`pending-${step.id}`}>
                    pending, waiting for the receipt…
                  </span>
                )}

                {record.outcome !== undefined && (
                  <div className="tx-line done" data-testid={`receipt-${step.id}`}>
                    {record.outcome.hash !== undefined && (
                      <span>tx <code>{shorten(record.outcome.hash)}</code></span>
                    )}
                    {record.outcome.blockNumber !== undefined && (
                      <span>block {record.outcome.blockNumber}</span>
                    )}
                    {record.outcome.status !== undefined && (
                      <span className="status-ok">{record.outcome.status}</span>
                    )}
                    {record.outcome.gasUsed !== undefined && <span>gas {record.outcome.gasUsed}</span>}
                    {record.outcome.note !== undefined && <em>{record.outcome.note}</em>}
                    {record.outcome.events.length > 0 && (
                      <ul className="event-list">
                        {record.outcome.events.map((event) => <li key={event}>{event}</li>)}
                      </ul>
                    )}
                  </div>
                )}

                {record.status === "failed" && (
                  <div className="tx-line failed" data-testid={`error-${step.id}`}>
                    <strong>reverted</strong> <span>{record.error}</span>
                  </div>
                )}

                <button
                  type="button"
                  className="primary"
                  data-testid={`run-${step.id}`}
                  disabled={busy || (!isNext && record.status !== "failed")}
                  onClick={() => void runStep(step.id)}
                >
                  {record.status === "failed" ? "Retry" : record.status === "done" ? "Done" : "Send"}
                </button>
              </div>
            </li>
          );
        })}
      </ol>
    </main>
  );
}
