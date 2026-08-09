"use client";

import { useEffect, useState } from "react";

import type { ExperimentCommand, ExperimentView } from "@/lib/recourse-policy-experiment/experiment-store";

import styles from "./governed-recourse-policy.module.css";

function shortDigest(value: string | null | undefined): string {
  if (!value) return "—";
  return `${value.slice(0, 16)}…${value.slice(-10)}`;
}

function timestamp(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return new Date(value * 1000).toISOString().replace(".000Z", "Z");
}

function actionLabel(action: string): string {
  return action.replaceAll("_", " ");
}

function nextControl(view: ExperimentView): Readonly<{ label: string; command: ExperimentCommand }> | null {
  switch (view.case.currentState) {
    case "POLICY_BOUND": return { label: "Expose verified governed result", command: { action: "expose-result" } };
    case "RESULT_AVAILABLE": return { label: "Evaluate bound policy", command: { action: "evaluate-policy" } };
    case "REVIEW_REQUIRED": return { label: "Approve this exact action", command: { action: "approve-action" } };
    case "REVIEW_APPROVED":
    case "POLICY_EVALUATED": return { label: "Authorize governed action", command: { action: "authorize-action" } };
    case "ACTION_AUTHORIZED": return { label: "Record evidence-only action", command: { action: "record-action" } };
    default: return null;
  }
}

export function GovernedRecourseExperiment() {
  const [view, setView] = useState<ExperimentView | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    fetch("/api/design-lab/governed-recourse-policy", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("The experimental case API is unavailable.");
        return response.json() as Promise<ExperimentView>;
      })
      .then((body) => {
        if (!active) return;
        setView(body);
        setSelectedPolicy(body.availablePolicies[0]?.policyId ?? "");
      })
      .catch((cause: unknown) => active && setError(cause instanceof Error ? cause.message : "Unable to load experiment"));
    return () => { active = false; };
  }, []);

  async function send(command: ExperimentCommand) {
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/design-lab/governed-recourse-policy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(command),
      });
      const body = await response.json() as ExperimentView | { readonly message?: string };
      if (!response.ok || !("case" in body)) throw new Error("message" in body ? body.message : "The command failed closed.");
      setView(body);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The command failed closed.");
    } finally {
      setPending(false);
    }
  }

  if (view === null) {
    return <main className={styles.loading}>{error ?? "Loading isolated policy experiment…"}</main>;
  }

  const current = view.case;
  const policy = current.policy;
  const result = current.governedResult;
  const proposed = current.proposedAction;
  const receipt = current.receipt;
  const control = nextControl(view);
  const selectedBeforeResult = current.selection !== null && result !== null
    ? current.selection.selectedAtUnix < result.exposedAtUnix
    : null;

  return (
    <main className={styles.page}>
      <header className={styles.header}>
        <div>
          <span className={styles.wordmark}>Mordant</span>
          <span className={styles.divider} />
          <span>Design lab · governed recourse policy</span>
        </div>
        <strong>EXPERIMENTAL · OFF-CHAIN · NO SETTLEMENT</strong>
      </header>

      <section className={styles.hero}>
        <p className={styles.eyebrow}>Recourse layer for tokenized private credit · bounded hypothesis</p>
        <h1>A governed fact can authorize an operational path.</h1>
        <p className={styles.boundary}>
          The signed result establishes only <strong>CONFLICT</strong> or <strong>NO CONFLICT</strong>. It does not establish legal
          responsibility, priority, ownership, default, fraud, action owner, deadline, or payout.
        </p>
      </section>

      <section className={styles.statusStrip} aria-label="Current experiment status">
        <div><span>Case state</span><strong data-testid="case-state">{actionLabel(current.currentState)}</strong></div>
        <div><span>Policy selected before result</span><strong data-testid="selection-before-result">{selectedBeforeResult === null ? "PENDING" : selectedBeforeResult ? "YES" : "NO"}</strong></div>
        <div><span>Execution capability</span><strong>EVIDENCE ONLY</strong></div>
        <div><span>Settlement</span><strong>PROHIBITED</strong></div>
      </section>

      <div className={styles.workspace}>
        <section className={styles.primaryColumn}>
          <article className={styles.panel}>
            <div className={styles.panelHeading}><span>01</span><h2>Immutable governed result</h2></div>
            {result === null ? (
              <p className={styles.empty}>Sealed from this experimental run until policy selection is signed and hash-bound.</p>
            ) : (
              <div className={styles.resultBlock}>
                <strong data-testid="governed-outcome">{result.outcome}</strong>
                <dl>
                  <div><dt>Semantic</dt><dd>{result.semantic}</dd></div>
                  <div><dt>Schema</dt><dd>{result.schemaVersion}</dd></div>
                  <div><dt>Exact digest</dt><dd title={result.digest}>{shortDigest(result.digest)}</dd></div>
                  <div><dt>Experimental exposure</dt><dd>{timestamp(result.exposedAtUnix)}</dd></div>
                  <div><dt>Original signed release</dt><dd>{timestamp(result.releasedAtUnix)}</dd></div>
                </dl>
              </div>
            )}
          </article>

          <article className={styles.panel}>
            <div className={styles.panelHeading}><span>02</span><h2>Applicable policy</h2></div>
            {current.currentState === "CASE_AUTHORIZED" ? (
              <div className={styles.selector}>
                <label htmlFor="policy-fixture">Choose one of exactly two immutable policy fixtures</label>
                <select id="policy-fixture" value={selectedPolicy} onChange={(event) => setSelectedPolicy(event.target.value)} disabled={pending}>
                  {view.availablePolicies.map((fixture) => (
                    <option key={fixture.policyId} value={fixture.policyId}>
                      {fixture.policyId} → {actionLabel(fixture.conflictAction)}
                    </option>
                  ))}
                </select>
                <button type="button" disabled={pending || selectedPolicy.length === 0} onClick={() => send({ action: "bind-policy", policyId: selectedPolicy })}>
                  Bind policy before result
                </button>
              </div>
            ) : policy === null ? null : (
              <dl className={styles.evidenceGrid}>
                <div><dt>Policy ID</dt><dd>{policy.policyId}</dd></div>
                <div><dt>Version</dt><dd>{policy.policyVersion}</dd></div>
                <div><dt>Digest</dt><dd title={policy.digest}>{shortDigest(policy.digest)}</dd></div>
                <div><dt>Authority</dt><dd>{policy.policyAuthority.label}</dd></div>
                <div><dt>Effective</dt><dd>{timestamp(policy.effectiveFromUnix)} — {timestamp(policy.effectiveUntilUnix)}</dd></div>
                <div><dt>Scope</dt><dd>{policy.scope.assetClass}</dd></div>
              </dl>
            )}
          </article>

          <article className={styles.panel}>
            <div className={styles.panelHeading}><span>03</span><h2>Governed action</h2></div>
            {proposed === null ? <p className={styles.empty}>No action is proposed until the bound policy evaluates the immutable result.</p> : (
              <div className={styles.actionBlock}>
                <p><span>Evaluation</span><strong>{actionLabel(proposed.evaluationActionType)}</strong></p>
                <p><span>Proposed action</span><strong data-testid="proposed-action">{actionLabel(proposed.actionType)}</strong></p>
                <p><span>Accountable role</span><strong>{actionLabel(proposed.accountableInstitutionalRole)}</strong></p>
                <p><span>Approval</span><strong>{actionLabel(proposed.authorizationMode)}</strong></p>
                <p><span>Deadline</span><strong>{timestamp(proposed.operationalDeadlineUnix)}</strong></p>
                <p><span>Action digest</span><strong title={proposed.digest}>{shortDigest(proposed.digest)}</strong></p>
              </div>
            )}
            {control !== null && (
              <button className={styles.primaryAction} type="button" disabled={pending} onClick={() => send(control.command)}>
                <span data-testid="next-control">{pending ? "Verifying…" : control.label}</span>
              </button>
            )}
            {error !== null && <p className={styles.error} role="alert">{error}</p>}
          </article>
        </section>

        <aside className={styles.secondaryColumn}>
          <section className={styles.panel}>
            <div className={styles.panelHeading}><span>04</span><h2>Action history</h2></div>
            <ol className={styles.history}>
              {current.history.map((event) => (
                <li key={event.digest}>
                  <span>{String(event.ordinal).padStart(2, "0")}</span>
                  <div><strong>{actionLabel(event.toState)}</strong><small>{timestamp(event.atUnix)}</small></div>
                  <code title={event.digest}>{shortDigest(event.digest)}</code>
                </li>
              ))}
            </ol>
          </section>

          <section className={styles.panel}>
            <div className={styles.panelHeading}><span>05</span><h2>Evidence receipt</h2></div>
            {receipt === null ? <p className={styles.empty}>Receipt is emitted only after authorization and the exact evidence-only state transition.</p> : (
              <div className={styles.receipt}>
                <strong data-testid="receipt-status">INDEPENDENTLY VERIFIABLE</strong>
                <dl>
                  <div><dt>Receipt</dt><dd title={receipt.digest}>{shortDigest(receipt.digest)}</dd></div>
                  <div><dt>Result</dt><dd title={receipt.governedResult.digest}>{shortDigest(receipt.governedResult.digest)}</dd></div>
                  <div><dt>Policy</dt><dd title={receipt.policy.digest}>{shortDigest(receipt.policy.digest)}</dd></div>
                  <div><dt>Selection</dt><dd title={receipt.selectionEventDigest}>{shortDigest(receipt.selectionEventDigest)}</dd></div>
                  <div><dt>Approval</dt><dd title={receipt.approvalEventDigest ?? undefined}>{shortDigest(receipt.approvalEventDigest)}</dd></div>
                  <div><dt>Transition</dt><dd>{actionLabel(receipt.stateTransition.fromState ?? "")} → {actionLabel(receipt.stateTransition.toState)}</dd></div>
                </dl>
              </div>
            )}
          </section>

          <button className={styles.reset} type="button" disabled={pending} onClick={() => send({ action: "reset" })}>
            Start a new isolated run
          </button>
        </aside>
      </div>

      <footer className={styles.footer}>
        Prototype authorities are intentionally reproducible design-lab identities. No production authorization, legal conclusion,
        RPC write, settlement, transaction broadcast, or token movement is available on this route.
      </footer>
    </main>
  );
}
