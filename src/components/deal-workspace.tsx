"use client";

import { useState } from "react";
import {
  SYNTHETIC_DEALS,
  assessAction,
  deriveDealSummary,
  type DealScenarioId,
  type SyntheticDeal,
} from "@/lib/mordant/product-model";
import {
  DomainLedger,
  GateVector,
  MachineRail,
  ObservationStamp,
  TransitionJoint,
  type EvidenceFact,
} from "@/components/structural-ui";
import {
  dealShortId,
  evidenceTone,
  formatDomainAmount,
  formatRole,
  formatState,
  formatUtc,
  gateToView,
  observationCopy,
  responsibilityDue,
  shortReference,
} from "@/components/product-presenters";

const RECEIVABLE_STATES = ["Accepted", "Issued", "Outstanding", "Partially redeemed", "Redeemed"] as const;
const PROTECTION_STATES = ["Unfunded", "Active", "Conflict registered", "Cure period", "Claimable", "Settled"] as const;

function dealTone(deal: SyntheticDeal) {
  const posture = deriveDealSummary(deal).posture;
  if (posture === "critical" || posture === "recovery") return "critical";
  if (posture === "attention" || posture === "unknown") return "pending";
  if (posture === "complete") return "positive";
  return "neutral";
}

function latestTransition(deal: SyntheticDeal) {
  const protectionHistory = deal.machines.protection.history;
  const receivableHistory = deal.machines.receivable.history;
  const transition = protectionHistory.at(-1) ?? receivableHistory.at(-1);

  if (!transition) {
    return { before: "Not observed", action: "No transition", after: "Not observed", facts: [] as EvidenceFact[] };
  }

  return {
    before: formatState(transition.from),
    action: transition.action,
    after: formatState(transition.to),
    facts: [
      { label: "Observed at", value: formatUtc(transition.at), tone: "observed" as const },
      { label: "Source", value: "Synthetic fixture event stream", tone: "external" as const },
      { label: "Receivable-unit effect", value: "None unless explicitly redeemed", tone: "derived" as const },
      { label: "Policy scope", value: deal.machines.protection.immutablePolicyId, tone: "attested" as const },
    ],
  };
}

export function DealWorkspace() {
  const [selectedScenario, setSelectedScenario] = useState<DealScenarioId>("cure-expiring");
  const [showExecution, setShowExecution] = useState(false);
  const selected = SYNTHETIC_DEALS.find((deal) => deal.scenario === selectedScenario) ?? SYNTHETIC_DEALS[0];
  const summary = deriveDealSummary(selected);
  const primaryAction = selected.actions[0];
  const assessment = primaryAction ? assessAction(primaryAction, selected.observation) : undefined;
  const gates = primaryAction?.gates.map(gateToView) ?? [];
  const observation = observationCopy(selected.observation);
  const proof = selected.proofs.at(-1);
  const transition = proof
    ? {
      before: formatState(proof.before.state),
      action: proof.action.name,
      after: formatState(proof.after.state),
      facts: proof.evidence.slice(0, 4).map((item) => ({
        label: item.label,
        value: item.value,
        source: item.source,
        tone: evidenceTone(item.classification),
      })),
    }
    : latestTransition(selected);

  function selectDeal(scenario: DealScenarioId) {
    setSelectedScenario(scenario);
    setShowExecution(false);
  }

  return (
    <div className="workspace-surface">
      <header className="surface-header">
        <div>
          <p className="surface-kicker">Operator surface · exception-led</p>
          <h1 className="surface-title">Deal workspace</h1>
        </div>
        <div>
          <p className="surface-intro">
            Monitor what changed, who must act, when the window closes, and whether execution is actually ready.
          </p>
          <div className="surface-observation" aria-label="Workspace observation context">
            <div><span>Portfolio</span><strong>14 synthetic deals</strong></div>
            <div><span>View priority</span><strong>Intervention first</strong></div>
          </div>
        </div>
      </header>

      <div className="workspace-layout">
        <aside className="deal-index" aria-label="Synthetic deal ledger">
          <div className="structural-heading">
            Deal ledger
            <small>14 monitored</small>
          </div>
          <div className="deal-index-columns mono" aria-hidden="true">
            <span>Deal / state</span>
            <span>Next responsibility</span>
          </div>
          <ol className="deal-list">
            {SYNTHETIC_DEALS.map((deal) => {
              const dealSummary = deriveDealSummary(deal);
              const isSelected = deal.scenario === selectedScenario;
              return (
                <li key={deal.scenario}>
                  <button
                    type="button"
                    className="deal-row"
                    data-selected={isSelected ? "true" : "false"}
                    data-tone={dealTone(deal)}
                    aria-pressed={isSelected}
                    onClick={() => selectDeal(deal.scenario)}
                  >
                    <span className="deal-row-rail" aria-hidden="true" />
                    <span className="deal-row-main">
                      <span className="deal-row-topline">
                        <strong>{dealShortId(deal)}</strong>
                        <small>{formatState(dealSummary.protectionState)}</small>
                      </span>
                      <span className="deal-row-label">{deal.label}</span>
                    </span>
                    <span className="deal-row-responsibility">
                      <strong>{deal.nextResponsibility.actorLabel}</strong>
                      <small>{deal.nextResponsibility.dueAt ? formatUtc(deal.nextResponsibility.dueAt) : formatState(deal.nextResponsibility.status)}</small>
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
        </aside>

        <section className="deal-core" aria-labelledby="selected-deal-title">
          <header className="deal-core-header">
            <div>
              <p className="micro-label">Selected deal · {dealShortId(selected)}</p>
              <h2 id="selected-deal-title">{selected.label}</h2>
              <p>{shortReference(selected.machines.receivable.immutableInvoiceRoot, 20, 10)}</p>
            </div>
            <span className="status-token" data-tone={dealTone(selected)}>{formatState(summary.posture)}</span>
          </header>

          <ObservationStamp {...observation} />

          <div className="domain-ledgers">
            <DomainLedger
              domain="receivable"
              label="Receivable remains owned"
              amount={formatDomainAmount(selected.economics.receivable.outstanding)}
              asset={selected.economics.receivable.outstanding.asset.symbol}
              state={formatState(selected.machines.receivable.state)}
              description="Outstanding invoice principal. A protection transition never burns or transfers these units."
              footer={`${selected.economics.receivable.outstandingUnits} of ${selected.economics.receivable.issuedUnits} invoice units outstanding`}
            />
            <DomainLedger
              domain="protection"
              label={selected.machines.protection.state === "cure_period" ? "Protection at risk" : "Protection reserve"}
              amount={formatDomainAmount(selected.economics.protection.lockedReserve)}
              asset={selected.economics.protection.lockedReserve.asset.symbol}
              state={formatState(selected.machines.protection.state)}
              description="Separate funded consequence for the configured protection policy. It is not receivable redemption money."
              footer={`10% synthetic demo parameter · ${formatDomainAmount(selected.economics.protection.protectionPaid)} paid`}
            />
          </div>

          <section className="machine-panel" aria-labelledby="machine-heading">
            <h2 className="structural-heading" id="machine-heading">Independent state machines <small>Never merged</small></h2>
            <MachineRail
              domain="receivable"
              label="Receivable"
              states={RECEIVABLE_STATES}
              current={formatState(selected.machines.receivable.state)}
            />
            <MachineRail
              domain="protection"
              label="Protection"
              states={PROTECTION_STATES}
              current={formatState(selected.machines.protection.state)}
            />
          </section>

          <section className="allocation-panel" aria-labelledby="allocation-heading">
            <h2 className="structural-heading" id="allocation-heading">Record-date allocation <small>Synthetic holders</small></h2>
            <table>
              <thead><tr><th>Participant</th><th>Invoice units</th><th>Receivable share</th><th>Protection share</th></tr></thead>
              <tbody>
                <tr><th scope="row">Holder A</th><td>60</td><td>66.00 aUSDC</td><td>6.00 aUSDC</td></tr>
                <tr><th scope="row">Holder B</th><td>40</td><td>44.00 aUSDC</td><td>4.00 aUSDC</td></tr>
              </tbody>
            </table>
            <p>Protection and receivable redemption remain independent accounting domains.</p>
          </section>

          <section className="workspace-transition" aria-labelledby="transition-heading">
            <h2 className="structural-heading" id="transition-heading">Latest inspectable transition <small>Before · action · after</small></h2>
            <TransitionJoint before={transition.before} action={transition.action} after={transition.after} facts={transition.facts} compact />
          </section>
        </section>

        <aside className="workspace-action-rail">
          <section className="responsibility-panel" data-status={selected.nextResponsibility.status}>
            <p className="micro-label">Next responsibility</p>
            <h2>{selected.nextResponsibility.actorLabel}</h2>
            <p>{selected.nextResponsibility.task}</p>
            <dl>
              <div><dt>Due</dt><dd>{responsibilityDue(selected)}</dd></div>
              <div><dt>If missed</dt><dd>{selected.nextResponsibility.consequenceIfMissed ?? "No configured consequence."}</dd></div>
            </dl>
          </section>

          {gates.length > 0 ? <GateVector gates={gates} /> : (
            <section className="gate-vector"><h2 className="structural-heading">Action readiness <small>No action</small></h2><p className="empty-state">No candidate action is configured for this state.</p></section>
          )}

          {primaryAction ? (
            <section className="action-consequence" aria-labelledby="action-consequence-heading">
              <p className="micro-label">Candidate action</p>
              <h2 id="action-consequence-heading">{primaryAction.label}</h2>
              <p>{primaryAction.consequence.summary}</p>
              <div className="action-consequence-meta">
                <span>Actor <strong>{formatRole(primaryAction.actorRole)}</strong></span>
                <span>Availability <strong>{assessment ? formatState(assessment.availability) : "Unknown"}</strong></span>
                <span>Receivable units <strong>{formatState(primaryAction.consequence.receivableUnitsEffect)}</strong></span>
              </div>
              <button className="primary-action" type="button" onClick={() => setShowExecution((open) => !open)} aria-expanded={showExecution}>
                {showExecution ? "Close execution review" : "Review before execution"}
              </button>
              {showExecution ? (
                <div className="execution-review" role="status">
                  <strong>Synthetic review only</strong>
                  <p>{primaryAction.contractAction}</p>
                  <p>No transaction is submitted from this prototype surface.</p>
                </div>
              ) : null}
            </section>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
