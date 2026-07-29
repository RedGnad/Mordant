"use client";

import { useState } from "react";
import { LiveVaultProof } from "@/components/live-vault-proof";
import {
  SYNTHETIC_DEALS,
  getSyntheticDeal,
  type SyntheticDeal,
  type TransitionProof,
} from "@/lib/mordant/product-model";
import {
  GateVector,
  ObservationStamp,
  TransitionJoint,
} from "@/components/structural-ui";
import {
  dealShortId,
  evidenceTone,
  formatRole,
  formatState,
  formatUtc,
  gateToView,
  observationCopy,
  shortReference,
} from "@/components/product-presenters";

type ProofRecord = {
  deal: SyntheticDeal;
  proof: TransitionProof;
};

const PROOF_RECORDS: readonly ProofRecord[] = SYNTHETIC_DEALS.flatMap((deal) =>
  deal.proofs.map((proof) => ({ deal, proof })),
);

const RECOVERY_CHECKLIST = [
  "Refresh the last finalized observation.",
  "Compare the expected and observed protection state.",
  "Re-run simulation without changing receivable units.",
  "Resume only after the protocol gate clears.",
] as const;

export function ProtocolOperations() {
  const defaultProof = PROOF_RECORDS.find((record) => record.proof.id === "proof-protection-settlement") ?? PROOF_RECORDS[0];
  const [selectedProofId, setSelectedProofId] = useState(defaultProof?.proof.id ?? "");
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "failed">("idle");
  const selectedRecord = PROOF_RECORDS.find((record) => record.proof.id === selectedProofId) ?? defaultProof;
  const recoveryDeal = getSyntheticDeal("recovery-required");
  const recoveryAction = recoveryDeal.actions[0];
  const observation = selectedRecord ? observationCopy(selectedRecord.deal.observation) : observationCopy(recoveryDeal.observation);
  const facts = selectedRecord
    ? selectedRecord.proof.evidence.map((item) => ({
      label: item.label,
      value: item.value,
      source: item.source,
      tone: evidenceTone(item.classification),
    }))
    : [];

  async function copyRecoveryChecklist() {
    try {
      await navigator.clipboard.writeText(
        RECOVERY_CHECKLIST.map((step, index) => `${index + 1}. ${step}`).join("\n"),
      );
      setCopyStatus("copied");
    } catch {
      setCopyStatus("failed");
    }
  }

  return (
    <div className="protocol-surface">
      <header className="surface-header protocol-header">
        <div>
          <p className="surface-kicker">Technical surface · diagnostics separated</p>
          <h1 className="surface-title">Protocol operations</h1>
        </div>
        <div>
          <p className="surface-intro">
            Inspect the exact transition, observation source, finality, evidence classification, failed prerequisites, and recovery owner.
          </p>
          <div className="surface-observation" aria-label="Protocol environment context">
            <div><span>Schema</span><strong>product-model.v1</strong></div>
            <div><span>Access</span><strong>Operations only</strong></div>
          </div>
        </div>
      </header>

      <ObservationStamp {...observation} />

      <div className="protocol-layout">
        <aside className="event-rail" aria-label="Synthetic transition evidence">
          <h2 className="structural-heading">Event rail <small>{PROOF_RECORDS.length} records</small></h2>
          <ol>
            {PROOF_RECORDS.map(({ deal, proof }, index) => (
              <li key={proof.id}>
                <button
                  type="button"
                  className="event-row"
                  data-selected={proof.id === selectedProofId ? "true" : "false"}
                  aria-pressed={proof.id === selectedProofId}
                  onClick={() => setSelectedProofId(proof.id)}
                >
                  <span className="event-index mono">{String(index + 1).padStart(2, "0")}</span>
                  <span className="event-row-copy">
                    <strong>{proof.action.name}</strong>
                    <small>{dealShortId(deal)} · {formatState(proof.machine)}</small>
                  </span>
                  <span className="event-finality mono">{formatState(proof.finality.status)}</span>
                </button>
              </li>
            ))}
          </ol>
          <div className="event-legend">
            <span data-tone="observed">Observed on-chain</span>
            <span data-tone="attested">Attested</span>
            <span data-tone="derived">Derived by Mordant</span>
            <span data-tone="external">External / unverified</span>
          </div>
        </aside>

        <section className="protocol-stage" aria-labelledby="transition-stage-heading">
          <header className="protocol-stage-header">
            <div>
              <p className="micro-label">Selected transition</p>
              <h2 id="transition-stage-heading">{selectedRecord?.proof.action.name ?? "No proof selected"}</h2>
              <p>{selectedRecord ? `${dealShortId(selectedRecord.deal)} · ${selectedRecord.deal.label}` : "No synthetic proof is available."}</p>
            </div>
            <span className="status-token" data-tone={selectedRecord?.proof.finality.status === "finalized" ? "positive" : "pending"}>
              {selectedRecord ? formatState(selectedRecord.proof.finality.status) : "Unknown"}
            </span>
          </header>

          {selectedRecord ? (
            <TransitionJoint
              before={formatState(selectedRecord.proof.before.state)}
              action={selectedRecord.proof.action.name}
              after={formatState(selectedRecord.proof.after.state)}
              facts={facts}
            >
              <dl className="raw-proof-fields">
                <div><dt>Reference</dt><dd>{selectedRecord.proof.action.reference}</dd></div>
                <div><dt>Actor role</dt><dd>{formatRole(selectedRecord.proof.action.actorRole)}</dd></div>
                <div><dt>Submitted</dt><dd>{formatUtc(selectedRecord.proof.action.submittedAt)}</dd></div>
                <div><dt>Synthetic block</dt><dd>{selectedRecord.proof.finality.syntheticBlock ?? "Not observed"}</dd></div>
                <div><dt>Confirmations</dt><dd>{selectedRecord.proof.finality.confirmations ?? "Unknown"}</dd></div>
                <div><dt>Proof ID</dt><dd>{selectedRecord.proof.id}</dd></div>
              </dl>
            </TransitionJoint>
          ) : null}

          <section className="proof-boundary" aria-labelledby="proof-boundary-heading">
            <h2 className="structural-heading" id="proof-boundary-heading">Evidence boundary <small>What this screen establishes</small></h2>
            <div className="proof-boundary-grid">
              <div data-tone="observed"><span>Observed</span><p>Transition fields recorded by the synthetic fixture at a named block.</p></div>
              <div data-tone="attested"><span>Attested</span><p>Named signer or participant assertion, without exposing identity payloads.</p></div>
              <div data-tone="derived"><span>Derived</span><p>Readiness and accounting interpretation computed by Mordant.</p></div>
              <div data-tone="external"><span>Not established</span><p>Invoice truth, off-network financing, legal priority, insurance, or production safety.</p></div>
            </div>
          </section>
        </section>

        <aside className="diagnostic-rail">
          <section className="diagnostic-console" aria-labelledby="diagnostic-heading">
            <h2 className="structural-heading" id="diagnostic-heading">Recovery diagnostic <small>Error</small></h2>
            <div className="diagnostic-alert">
              <p className="micro-label">after_state_unavailable</p>
              <h3>Expected after-state could not be reconstructed.</h3>
              <p>The submitted synthetic event has no trustworthy after-state observation. No action is presented as executable.</p>
            </div>
            <dl className="diagnostic-fields">
              <div><dt>Owner</dt><dd>Protocol Operations</dd></div>
              <div><dt>Last safe state</dt><dd>Protection · Active</dd></div>
              <div><dt>Revert selector</dt><dd>Not emitted by fixture</dd></div>
              <div><dt>Gas estimate</dt><dd>Unavailable after failed simulation</dd></div>
              <div><dt>Recovery action</dt><dd>{recoveryAction?.contractAction ?? "Not configured"}</dd></div>
              <div><dt>Deal</dt><dd>{shortReference(recoveryDeal.id)}</dd></div>
            </dl>
          </section>

          {recoveryAction ? <GateVector gates={recoveryAction.gates.map(gateToView)} title="Recovery preconditions" compact /> : null}

          <section className="runbook-panel">
            <p className="micro-label">Runbook · synthetic</p>
            <ol>
              {RECOVERY_CHECKLIST.map((step) => <li key={step}>{step}</li>)}
            </ol>
            <button type="button" className="secondary-action" onClick={() => void copyRecoveryChecklist()}>
              {copyStatus === "copied" ? "Checklist copied" : "Copy recovery checklist"}
            </button>
            {copyStatus === "failed" ? (
              <p className="copy-feedback" role="status">Clipboard unavailable. Select the four steps manually.</p>
            ) : null}
          </section>
        </aside>
      </div>

      <section className="live-observation-bay" aria-labelledby="live-observation-heading">
        <div className="live-observation-copy">
          <p className="micro-label">Optional live observation</p>
          <h2 id="live-observation-heading">Configured vault snapshot</h2>
          <p>A snapshot can corroborate contract fields at one block. It does not establish invoice truth or a legal effect.</p>
        </div>
        <LiveVaultProof />
      </section>
    </div>
  );
}
