"use client";

import { useMemo, useState } from "react";

import { LiveVaultProof } from "@/components/live-vault-proof";
import {
  FolioIdentity,
  GateVector,
  ReadinessVerdict,
  TransitionJoint,
  type EvidenceFact,
} from "@/components/structural-ui";
import {
  SYNTHETIC_DEALS,
  type DealDiagnostic,
  type SyntheticDeal,
  type TransitionProof,
} from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";
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
  id: string;
  kind: "transition";
  deal: SyntheticDeal;
  proof: TransitionProof;
  label: string;
  status: string;
};

type DiagnosticRecord = {
  id: string;
  kind: "diagnostic";
  deal: SyntheticDeal;
  diagnostic: DealDiagnostic;
  label: string;
  status: string;
};

type ProtocolRecord = ProofRecord | DiagnosticRecord;

type ProtocolArtifactContext = Readonly<{
  artifact: string;
  classification: string;
  parameterSetHash: string;
  frozenCommit: string;
  network: Readonly<{ name: string; chainId: number; blockNumber: string }>;
  publicWrites: string;
  settlementEvidence: string;
}>;

const RECORDS: readonly ProtocolRecord[] = [
  ...SYNTHETIC_DEALS.flatMap((deal) =>
    deal.diagnostics.map((diagnostic) => ({
      id: `diagnostic:${deal.scenario}:${diagnostic.code}`,
      kind: "diagnostic" as const,
      deal,
      diagnostic,
      label: diagnostic.code,
      status: diagnostic.severity === "error" ? "Recovery required" : diagnostic.severity,
    })),
  ),
  ...SYNTHETIC_DEALS.flatMap((deal) =>
    deal.proofs.map((proof) => ({
      id: `transition:${proof.id}`,
      kind: "transition" as const,
      deal,
      proof,
      label: proof.action.name,
      status: formatState(proof.finality.status),
    })),
  ),
];

const RECOVERY_CHECKLIST = [
  "Refresh the last finalized observation.",
  "Compare the expected and observed protection state.",
  "Re-run simulation without changing receivable units.",
  "Resume only after the protocol gate clears.",
] as const;

const PROOF_CHECKLIST = [
  "Confirm the selected record and immutable deal identity.",
  "Inspect source, finality, and evidence classification.",
  "Compare before, action, and after fields.",
  "Escalate only diagnostics attached to this record.",
] as const;

function recordObservedAt(record: ProtocolRecord) {
  if (record.kind === "transition") return record.proof.after.observedAt;
  return record.deal.observation.freshness.observedAt;
}

function recordObservation(record: ProtocolRecord) {
  if (record.kind === "transition") {
    return {
      block: record.proof.finality.syntheticBlock ?? "Unknown",
      time: formatUtc(record.proof.after.observedAt),
      finality: formatState(record.proof.finality.status),
      freshness: "Recorded after-state",
      confirmations: record.proof.finality.confirmations,
      source: "Selected transition proof",
    };
  }

  return {
    ...observationCopy(record.deal.observation),
    confirmations: record.deal.observation.finality.confirmations,
    source: "Synthetic fixture",
  };
}

function recordFacts(record: ProtocolRecord): readonly EvidenceFact[] {
  if (record.kind === "transition") {
    const facts = record.proof.evidence.map((item) => ({
      label: item.label,
      value: item.value,
      source: item.source,
      tone: evidenceTone(item.classification),
    }));

    if (facts.some((fact) => fact.tone === "external")) return facts;
    return [
      ...facts,
      {
        label: "External boundary",
        value: "Invoice truth, legal effect, and production safety",
        source: "Not established by this record",
        tone: "external" as const,
      },
    ];
  }

  return [
    {
      label: "Fixture state",
      value: `Synthetic observation at block ${record.deal.observation.finality.syntheticBlock ?? "unknown"}`,
      source: "Synthetic fixture",
      tone: "observed",
    },
    {
      label: "Participant attestation",
      value: "Not attached",
      source: "Not established by the selected diagnostic record",
      tone: "external",
    },
    {
      label: record.diagnostic.code,
      value: record.diagnostic.detail,
      source: "Mordant deterministic diagnostic",
      tone: "derived",
    },
    {
      label: "External boundary",
      value: "Revert cause, legal effect, and production safety",
      source: "Not established by this fixture",
      tone: "external",
    },
  ];
}

function recordTransition(record: ProtocolRecord) {
  if (record.kind === "transition") {
    return {
      before: formatState(record.proof.before.state),
      action: record.proof.action.name,
      after: formatState(record.proof.after.state),
    };
  }

  const previous = record.deal.machines.protection.history.at(-1)?.to ?? "active";
  const action = record.diagnostic.recoveryActionId
    ? record.deal.actions.find((candidate) => candidate.id === record.diagnostic.recoveryActionId)
    : record.deal.actions[0];
  return {
    before: formatState(previous),
    action: action?.contractAction ?? "Transition reference unavailable",
    after: record.diagnostic.category === "recovery" ? "Not reconstructed" : formatState(record.deal.machines.protection.state),
  };
}

export function ProtocolOperations({ artifactContext }: { readonly artifactContext: ProtocolArtifactContext }) {
  const defaultRecord = RECORDS.find((record) =>
    record.kind === "diagnostic" && record.diagnostic.code === "after_state_unavailable",
  ) ?? RECORDS[0];
  const [selectedRecordId, setSelectedRecordId] = useState(defaultRecord?.id ?? "");
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "failed">("idle");
  const selectedRecord = RECORDS.find((record) => record.id === selectedRecordId) ?? defaultRecord;
  const selectedAction = selectedRecord
    ? selectedRecord.kind === "diagnostic" && selectedRecord.diagnostic.recoveryActionId
      ? selectedRecord.deal.actions.find((action) => action.id === selectedRecord.diagnostic.recoveryActionId)
      : selectedRecord.kind === "transition"
        ? selectedRecord.deal.actions.find((action) => action.proofId === selectedRecord.proof.id) ?? selectedRecord.deal.actions[0]
        : selectedRecord.deal.actions[0]
    : undefined;
  const verdict = selectedRecord && selectedAction
    ? deriveReadinessVerdict(selectedRecord.deal, selectedAction)
    : undefined;
  const observation = selectedRecord
    ? recordObservation(selectedRecord)
    : {
        block: "Unknown",
        time: "Not observed",
        finality: "Unknown",
        freshness: "Unknown",
        confirmations: undefined,
        source: "Unavailable",
      };
  const transition = selectedRecord ? recordTransition(selectedRecord) : undefined;
  const facts = selectedRecord ? recordFacts(selectedRecord) : [];
  const checklist = verdict?.code === "RECOVERY_REQUIRED" ? RECOVERY_CHECKLIST : PROOF_CHECKLIST;
  const selectedDiagnostics = useMemo(() => {
    if (!selectedRecord) return [];
    if (selectedRecord.kind === "diagnostic") {
      return [{
        code: selectedRecord.diagnostic.code,
        severity: selectedRecord.diagnostic.severity,
        message: selectedRecord.diagnostic.detail,
        recovery: selectedAction?.contractAction,
      }];
    }
    return selectedRecord.proof.diagnostics.map((diagnostic) => ({
      code: diagnostic.code,
      severity: diagnostic.severity,
      message: diagnostic.message,
      recovery: diagnostic.recovery,
    }));
  }, [selectedAction?.contractAction, selectedRecord]);

  async function copyChecklist() {
    try {
      await navigator.clipboard.writeText(checklist.map((step, index) => `${index + 1}. ${step}`).join("\n"));
      setCopyStatus("copied");
    } catch {
      setCopyStatus("failed");
    }
  }

  if (!selectedRecord || !transition) {
    return <div className="protocol-empty">No synthetic protocol record is available.</div>;
  }

  return (
    <div className="protocol-surface">
      <div className="protocol-grid">
        <aside className="protocol-event-rail" id="events" aria-label="Protocol event and recovery rail">
          <header>
            <p className="micro-label">Observed records</p>
            <h1>Event and recovery rail</h1>
          </header>
          <ol>
            {RECORDS.map((record, index) => (
              <li key={record.id}>
                <button
                  type="button"
                  className="protocol-record-row"
                  data-selected={record.id === selectedRecord.id ? "true" : "false"}
                  data-record-kind={record.kind}
                  aria-pressed={record.id === selectedRecord.id}
                  onClick={() => {
                    setSelectedRecordId(record.id);
                    setCopyStatus("idle");
                  }}
                >
                  <span>{String(index + 1).padStart(2, "0")} · {record.status}</span>
                  <strong>{record.label}</strong>
                  <small>
                    <span>{dealShortId(record.deal)}</span>
                    <span>{recordObservedAt(record) ? formatUtc(recordObservedAt(record)) : "Time unavailable"}</span>
                  </small>
                </button>
              </li>
            ))}
          </ol>
          <div className="protocol-evidence-legend" aria-label="Evidence registration legend">
            <p className="micro-label">Registration legend</p>
            <span data-evidence-class="observed">Observed</span>
            <span data-evidence-class="attested">Attested</span>
            <span data-evidence-class="derived">Derived</span>
            <span data-evidence-class="external">Not established</span>
          </div>
        </aside>

        <section className="protocol-proof-stage" id="diagnostics" aria-labelledby="protocol-record-title">
          <header className="protocol-service-plate">
            <div>Record / {selectedRecord.id}<br />Deal / {selectedRecord.deal.id}</div>
            <div>Schema / {selectedRecord.deal.schemaVersion}<br />Source / synthetic-fixture</div>
            <div>Obs / block {observation.block}<br />Finality / {observation.finality}</div>
          </header>

          <div className="protocol-proof-content">
            <div className="protocol-record-title">
              <div>
                <p className="micro-label">Selected {selectedRecord.kind} record</p>
                <h2 id="protocol-record-title">
                  {selectedRecord.kind === "diagnostic" ? selectedRecord.diagnostic.title : selectedRecord.proof.action.name}
                </h2>
              </div>
              <span className="status-token" data-tone={selectedRecord.status === "Recovery required" ? "critical" : "positive"}>
                {selectedRecord.status}
              </span>
            </div>

            <TransitionJoint
              before={transition.before}
              action={transition.action}
              after={transition.after}
              facts={facts}
            >
              <dl className="protocol-raw-fields">
                <div><dt>Record ID</dt><dd>{selectedRecord.id}</dd></div>
                <div><dt>Deal folio</dt><dd>{dealShortId(selectedRecord.deal)}</dd></div>
                <div><dt>Actor role</dt><dd>{selectedAction ? formatRole(selectedAction.actorRole) : "Not established"}</dd></div>
                <div><dt>{selectedRecord.kind === "transition" ? "After observed" : "Observed"}</dt><dd>{observation.time}</dd></div>
                <div><dt>Synthetic block</dt><dd>{observation.block}</dd></div>
                <div><dt>Confirmations</dt><dd>{observation.confirmations ?? "Unknown"}</dd></div>
                <div><dt>Candidate call</dt><dd>{selectedAction?.contractAction ?? "None"}</dd></div>
                <div><dt>Receivable units</dt><dd>{selectedAction ? formatState(selectedAction.consequence.receivableUnitsEffect) : "Unchanged"}</dd></div>
              </dl>
            </TransitionJoint>

            <footer className="protocol-record-foot">
              <span>Immutable root / {shortReference(selectedRecord.deal.machines.receivable.immutableInvoiceRoot, 24, 14)}</span>
              <FolioIdentity
                folio={dealShortId(selectedRecord.deal)}
                root={selectedRecord.deal.machines.receivable.immutableInvoiceRoot}
                compact
              />
            </footer>

            <details className="protocol-artifact-boundary">
              <summary>
                <span>Pinned M-14 artifact context</span>
                <strong>{artifactContext.classification}</strong>
              </summary>
              <dl>
                <div><dt>Artifact</dt><dd>{artifactContext.artifact}</dd></div>
                <div><dt>Parameter set</dt><dd>{artifactContext.parameterSetHash}</dd></div>
                <div><dt>Frozen contracts</dt><dd>{artifactContext.frozenCommit}</dd></div>
                <div><dt>Recorded network</dt><dd>{artifactContext.network.name} · {artifactContext.network.chainId} · block {artifactContext.network.blockNumber}</dd></div>
                <div><dt>Public writes</dt><dd>{artifactContext.publicWrites}</dd></div>
                <div><dt>Settlement evidence</dt><dd>{artifactContext.settlementEvidence}</dd></div>
              </dl>
              <a href="/protocol/local-journey">Open the local protocol-double journey</a>
              <p>This pinned artifact is separate from the selected synthetic UI fixture and is not evidence of a current production execution.</p>
            </details>
          </div>
        </section>

        <aside className="protocol-diagnostic-rail" id="recovery" aria-label="Selected record diagnostic and runbook">
          {verdict ? <ReadinessVerdict verdict={verdict} compact /> : (
            <section className="protocol-no-verdict">
              <p className="micro-label">Unique readiness verdict</p>
              <h2>Evidence only</h2>
              <p>No candidate action is attached to this selected transition.</p>
            </section>
          )}

          <section className="selected-record-diagnostic" aria-labelledby="selected-diagnostic-heading">
            <h2 className="structural-heading" id="selected-diagnostic-heading">
              Selected-record diagnostic
              <small>{selectedDiagnostics.length || "None"}</small>
            </h2>
            {selectedDiagnostics.length > 0 ? selectedDiagnostics.map((diagnostic) => (
              <div className="diagnostic-entry" data-severity={diagnostic.severity} key={diagnostic.code}>
                <strong>{diagnostic.code}</strong>
                <p>{diagnostic.message}</p>
                <dl>
                  <div><dt>Severity</dt><dd>{diagnostic.severity}</dd></div>
                  <div><dt>Owner</dt><dd>{selectedRecord.deal.nextResponsibility.actorLabel}</dd></div>
                  <div><dt>Recovery</dt><dd>{diagnostic.recovery ?? "No automatic recovery"}</dd></div>
                </dl>
              </div>
            )) : (
              <div className="diagnostic-empty">
                <strong>No diagnostic attached</strong>
                <p>The selected transition record contains no error or warning diagnostic.</p>
              </div>
            )}
          </section>

          {selectedAction ? (
            <GateVector
              gates={selectedAction.gates.map(gateToView)}
              title="Selected-record preconditions"
              compact
            />
          ) : null}

          <section className="protocol-runbook">
            <p className="micro-label">{verdict?.code === "RECOVERY_REQUIRED" ? "Recovery runbook · no automatic retry" : "Inspection checklist"}</p>
            <ol>
              {checklist.map((step) => <li key={step}>{step}</li>)}
            </ol>
            <button type="button" className="secondary-action" onClick={() => void copyChecklist()}>
              {copyStatus === "copied" ? "Checklist copied" : "Copy selected checklist"}
            </button>
            {copyStatus === "failed" ? <p className="copy-feedback" role="status">Clipboard unavailable. Select the listed steps manually.</p> : null}
          </section>
        </aside>
      </div>

      <section className="protocol-live-observation" aria-labelledby="live-observation-heading">
        <div>
          <p className="micro-label">Optional live observation</p>
          <h2 id="live-observation-heading">Configured vault snapshot</h2>
          <p>A snapshot can corroborate contract fields at one block. It does not establish invoice truth or legal effect.</p>
        </div>
        <LiveVaultProof />
      </section>
    </div>
  );
}
