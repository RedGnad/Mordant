"use client";

import Link from "next/link";
import type { RefObject } from "react";

import {
  PROTECTION_STATES,
  RECEIVABLE_STATES,
  compactTechnicalValue,
  type LivingActionRecord,
  type LivingRunArtifact,
} from "@/lib/dealroom/living-demo";

import styles from "./transaction-driven-experience.module.css";

export function TransactionProof({
  run,
  action,
  checkpointLabel,
  publicTimeline,
  closing,
  titleRef,
  onClose,
}: {
  readonly run: LivingRunArtifact;
  readonly action: LivingActionRecord;
  readonly checkpointLabel: string;
  readonly publicTimeline: boolean;
  readonly closing: boolean;
  readonly titleRef: RefObject<HTMLHeadingElement | null>;
  readonly onClose: () => void;
}) {
  const receipt = action.receipt;

  return (
    <section
      className={styles.proof}
      data-testid="living-proof"
      data-closing={closing ? "true" : "false"}
      data-deal-id={run.deal.id}
      aria-labelledby="living-proof-title"
    >
      <header className={styles.proofLead}>
        <p className={styles.sourceLabel}>{receipt === undefined ? "Checkpoint proof" : "Receipt proof"}</p>
        <h1 id="living-proof-title" ref={titleRef} tabIndex={-1}>
          {action.title} {receipt === undefined ? "recorded." : "confirmed."}
        </h1>
        <p>{receipt === undefined
          ? "The controlled block checkpoint with its before and after contract reads."
          : "The receipt with its before and after contract reads."}</p>
      </header>

      <dl className={styles.receiptSummary}>
        <div><dt>Actor</dt><dd>{action.actorLabel}</dd></div>
        <div><dt>Transaction</dt><dd className={styles.technicalValue}>{receipt === undefined ? "No transaction" : compactTechnicalValue(receipt.transactionHash)}</dd></div>
        <div><dt>Block</dt><dd className={styles.technicalValue}>{receipt?.blockNumber ?? action.after?.blockNumber ?? action.before.blockNumber}</dd></div>
        <div><dt>Status</dt><dd>{receipt?.status ?? action.status}</dd></div>
      </dl>

      <section className={styles.transitionProof} aria-label="Before action after proof">
        <article>
          <span>Before · block {action.before.blockNumber}</span>
          <strong>{PROTECTION_STATES[action.before.protectionState]}</strong>
          <small>Receivable · {RECEIVABLE_STATES[action.before.receivableState]}</small>
        </article>
        <article className={styles.proofAction}>
          <span>Action</span>
          <strong>{action.title}</strong>
          <small>{action.actorLabel}</small>
        </article>
        <article>
          <span>After · block {action.after?.blockNumber}</span>
          <strong>{PROTECTION_STATES[action.after?.protectionState ?? action.before.protectionState]}</strong>
          <small>Receivable · {RECEIVABLE_STATES[action.after?.receivableState ?? action.before.receivableState]}</small>
        </article>
      </section>

      <details className={styles.technical} data-testid="living-technical-proof">
        <summary>Technical record</summary>
        <dl>
          <div><dt>Source</dt><dd>{run.source.label}</dd></div>
          <div><dt>Run</dt><dd>{run.runId}</dd></div>
          <div><dt>Checkpoint</dt><dd>{checkpointLabel}</dd></div>
          {action.contract === null ? null : <div><dt>Contract</dt><dd>{action.contract}</dd></div>}
          {action.method === null ? null : <div><dt>Method</dt><dd>{action.method}</dd></div>}
          <div><dt>Deal</dt><dd>{run.deal.id}</dd></div>
          <div><dt>Vault</dt><dd>{run.deal.vault}</dd></div>
          <div><dt>Invoice root</dt><dd>{run.deal.invoiceRoot}</dd></div>
          {receipt === undefined ? null : <div><dt>Transaction hash</dt><dd>{receipt.transactionHash}</dd></div>}
          <div><dt>Block hash</dt><dd>{receipt?.blockHash ?? action.after?.blockHash ?? action.before.blockHash}</dd></div>
          {receipt === undefined ? null : <div><dt>Gas used</dt><dd>{receipt.gasUsed}</dd></div>}
        </dl>
        {receipt !== undefined && receipt.events.length > 0 ? (
          <section className={styles.events} aria-label="Observed events">
            <p>Observed events</p>
            <ul>{receipt.events.map((event) => <li key={event}>{event}</li>)}</ul>
          </section>
        ) : null}
        {publicTimeline ? (
          <section className={styles.completeRun} aria-label="Complete recorded run">
            <p>Complete recorded run · {run.actions.filter((candidate) => candidate.receipt !== undefined).length} transactions</p>
            <ol>
              {run.actions.filter((candidate) => candidate.receipt !== undefined).map((candidate) => (
                <li key={candidate.id}>
                  <span>{candidate.title}</span>
                  <code>{compactTechnicalValue(candidate.receipt?.transactionHash ?? "")}</code>
                </li>
              ))}
            </ol>
          </section>
        ) : null}
      </details>

      <footer className={styles.proofControls}>
        <button type="button" onClick={onClose}>Back to selected checkpoint</button>
        {publicTimeline ? <Link href="/pilot">Apply for a shadow pilot</Link> : null}
      </footer>
    </section>
  );
}
