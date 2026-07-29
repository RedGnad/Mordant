"use client";

import { useEffect, useMemo, useState } from "react";

import {
  SYNTHETIC_DEALS,
  deriveDealSummary,
  type DealPosture,
  type DealScenarioId,
  type SyntheticDeal,
} from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";
import {
  DomainLedger,
  FolioIdentity,
  GateVector,
  MachineRail,
  ObservationStamp,
  ReadinessVerdict,
  Rootline,
  TransitionJoint,
  type EvidenceFact,
} from "@/components/structural-ui";
import { TransactionReview } from "@/components/transaction-review";
import {
  dealShortId,
  evidenceTone,
  formatDomainAmount,
  formatRole,
  formatState,
  formatUtc,
  gateToView,
  observationCopy,
  proRateDomainAmount,
  responsibilityDue,
  shortReference,
} from "@/components/product-presenters";

const RECEIVABLE_STATES = ["Accepted", "Issued", "Outstanding", "Partially redeemed", "Redeemed"] as const;
const PROTECTION_STATES = [
  "Unfunded",
  "Funding pending",
  "Active",
  "Conflict registered",
  "Cure period",
  "Claimable",
  "Settled",
] as const;
const RESOLVED_SCENARIOS: readonly DealScenarioId[] = ["completed", "protection-settled"];
const STORAGE_KEY = "mordant.workspace.selected-scenario";

type QueueFilter = "interventions" | "all" | "resolved";

const POSTURE_ORDER: Readonly<Record<DealPosture, number>> = {
  recovery: 0,
  critical: 1,
  attention: 2,
  unknown: 3,
  stable: 4,
  complete: 5,
};

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
      { label: "Fixture timestamp", value: formatUtc(transition.at), tone: "observed" as const },
      { label: "Source", value: "Synthetic fixture event stream", tone: "external" as const },
      { label: "Receivable-unit effect", value: "None unless explicitly redeemed", tone: "derived" as const },
      { label: "Policy scope", value: deal.machines.protection.immutablePolicyId, tone: "attested" as const },
    ],
  };
}

function queueDeadline(deal: SyntheticDeal) {
  if (deal.nextResponsibility.dueAt) {
    return new Intl.DateTimeFormat("en-GB", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
      timeZone: "UTC",
    }).format(new Date(deal.nextResponsibility.dueAt));
  }

  const action = deal.actions[0];
  if (!action) return "No action";
  return deriveReadinessVerdict(deal, action).code.replaceAll("_", " ");
}

function protectionLedgerLabel(deal: SyntheticDeal) {
  const state = deal.machines.protection.state;
  const reservePresent = BigInt(deal.economics.protection.lockedReserve.minorUnits) > 0n;
  const fundedLifecycle = ["active", "conflict_registered", "cure_period", "claimable"].includes(state);
  const reserveLabel = reservePresent && fundedLifecycle ? "Funded protection" : "Protection reserve";

  return `${reserveLabel} · ${formatState(state)}`;
}

export function DealWorkspace() {
  const [selectedScenario, setSelectedScenario] = useState<DealScenarioId>("cure-expiring");
  const [query, setQuery] = useState("");
  const [queueFilter, setQueueFilter] = useState<QueueFilter>("interventions");
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [showExecution, setShowExecution] = useState(false);

  useEffect(() => {
    const task = window.setTimeout(() => {
      const saved = window.localStorage.getItem(STORAGE_KEY);
      if (saved && SYNTHETIC_DEALS.some((deal) => deal.scenario === saved)) {
        setSelectedScenario(saved as DealScenarioId);
      }
    }, 0);
    return () => window.clearTimeout(task);
  }, []);

  const selected = SYNTHETIC_DEALS.find((deal) => deal.scenario === selectedScenario) ?? SYNTHETIC_DEALS[0];
  const summary = deriveDealSummary(selected);
  const primaryAction = selected.actions.find((action) => action.id === selectedActionId) ?? selected.actions[0];
  const verdict = primaryAction ? deriveReadinessVerdict(selected, primaryAction) : undefined;
  const gates = primaryAction?.gates.map(gateToView) ?? [];
  const observation = { ...observationCopy(selected.observation), source: "Synthetic fixture" };
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
  const position = selected.viewer.position;

  const queue = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase("en-US");
    return [...SYNTHETIC_DEALS]
      .filter((deal) => {
        const resolved = RESOLVED_SCENARIOS.includes(deal.scenario);
        if (queueFilter === "interventions" && resolved) return false;
        if (queueFilter === "resolved" && !resolved) return false;
        if (!needle) return true;
        return [
          dealShortId(deal),
          deal.label,
          deal.nextResponsibility.actorLabel,
          deal.machines.receivable.immutableInvoiceRoot,
        ].some((value) => value.toLocaleLowerCase("en-US").includes(needle));
      })
      .sort((a, b) => {
        const postureDelta = POSTURE_ORDER[deriveDealSummary(a).posture] - POSTURE_ORDER[deriveDealSummary(b).posture];
        if (postureDelta !== 0) return postureDelta;
        return (a.nextResponsibility.dueAt ?? "9999").localeCompare(b.nextResponsibility.dueAt ?? "9999");
      });
  }, [query, queueFilter]);

  const interventionCount = SYNTHETIC_DEALS.filter((deal) =>
    ["due_now", "recovery"].includes(deal.nextResponsibility.status),
  ).length;

  function selectDeal(scenario: DealScenarioId) {
    setSelectedScenario(scenario);
    setSelectedActionId(null);
    setShowExecution(false);
    window.localStorage.setItem(STORAGE_KEY, scenario);
  }

  return (
    <div className="workspace-surface">
      <div className="workspace-grid">
        <aside
          className="intervention-queue"
          id="portfolio"
          aria-label="Intervention queue"
          data-testid="workspace-interventions"
        >
          <div className="queue-controls">
            <div className="queue-heading-line">
              <h1>Intervention queue</h1>
              <span>{String(interventionCount).padStart(2, "0")} due now</span>
            </div>
            <label className="queue-search">
              <span className="visually-hidden">Search deals</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search deal, owner, root"
              />
              <select
                aria-label="Filter intervention queue"
                value={queueFilter}
                onChange={(event) => setQueueFilter(event.target.value as QueueFilter)}
              >
                <option value="interventions">Open first</option>
                <option value="all">All deals</option>
                <option value="resolved">Resolved</option>
              </select>
            </label>
          </div>

          <ol className="queue-items">
            {queue.map((deal) => {
              const dealSummary = deriveDealSummary(deal);
              const isSelected = deal.scenario === selectedScenario;
              return (
                <li key={deal.scenario}>
                  <button
                    type="button"
                    className="queue-item"
                    data-selected={isSelected ? "true" : "false"}
                    data-tone={dealTone(deal)}
                    aria-pressed={isSelected}
                    onClick={() => selectDeal(deal.scenario)}
                  >
                    <span className="queue-item-main">
                      <FolioIdentity
                        folio={dealShortId(deal)}
                        root={deal.machines.receivable.immutableInvoiceRoot}
                        compact
                      />
                      <strong>{deal.label}</strong>
                      <small>{deal.nextResponsibility.actorLabel}</small>
                    </span>
                    <span className="queue-item-status">
                      <strong>{formatState(dealSummary.protectionState)}</strong>
                      <small>{queueDeadline(deal)}</small>
                    </span>
                  </button>
                </li>
              );
            })}
            {queue.length === 0 ? (
              <li className="queue-empty-state">
                <strong>No deals match this view.</strong>
                <p>Clear the search or change the queue filter. The selected deal remains open.</p>
                <button type="button" className="text-button" onClick={() => { setQuery(""); setQueueFilter("all"); }}>
                  Show all monitored deals
                </button>
              </li>
            ) : null}
          </ol>

          <div className="queue-summary">
            <span>{queue.length} shown · {SYNTHETIC_DEALS.length} monitored</span>
            <span>Due and recovery first</span>
          </div>
        </aside>

        <section className="workspace-record" aria-labelledby="selected-deal-title">
          <header className="workspace-record-identity">
            <div>
              <div className="workspace-record-kicker">
                <span className="folio-code" data-testid="selected-folio">{dealShortId(selected)}</span>
                <span className="status-token" data-tone={dealTone(selected)}>{formatState(summary.protectionState)}</span>
              </div>
              <h2 id="selected-deal-title">{selected.label}</h2>
              <p>Buyer-accepted synthetic invoice · immutable one-vault / one-root record</p>
            </div>
            <div className="workspace-root-identity">
              <Rootline root={selected.machines.receivable.immutableInvoiceRoot} showLabel={false} />
              <span className="micro-label">Root · {shortReference(selected.machines.receivable.immutableInvoiceRoot, 18, 10)}</span>
              <small>Root-derived navigation index · not cryptographic proof</small>
            </div>
          </header>

          <div className="workspace-domain-pair" aria-label="Independent accounting domains">
            <DomainLedger
              domain="receivable"
              label="Receivable · outstanding"
              amount={formatDomainAmount(selected.economics.receivable.outstanding)}
              asset={selected.economics.receivable.outstanding.asset.symbol}
              state={formatState(selected.machines.receivable.state)}
              role="Buyer owes · holders own"
              location="Receivable vault ledger"
              source="Buyer-accepted synthetic invoice root"
              nextEffect="Redemption burns only redeemed invoice units"
              description={`${selected.economics.receivable.outstandingUnits} / ${selected.economics.receivable.issuedUnits} units remain outstanding. Protection transitions never burn or transfer them.`}
            />
            <DomainLedger
              domain="protection"
              label={protectionLedgerLabel(selected)}
              amount={formatDomainAmount(selected.economics.protection.lockedReserve)}
              asset={selected.economics.protection.lockedReserve.asset.symbol}
              state={formatState(selected.machines.protection.state)}
              role="Originator funds · policy beneficiary receives"
              location="Protection reserve ledger"
              source={selected.machines.protection.immutablePolicyId}
              nextEffect="Policy settlement leaves invoice units untouched"
              description="The 10% reserve is a synthetic demo parameter amortized against protected outstanding principal, not a production price."
            />
          </div>

          <section className="workspace-consequence" aria-label="Economic consequence">
            <p className="micro-label">If the next responsibility is missed</p>
            <strong>{selected.nextResponsibility.consequenceIfMissed ?? "No configured economic consequence."}</strong>
          </section>

          <section className="workspace-transition" id="evidence" aria-labelledby="transition-heading">
            <h2 className="structural-heading" id="transition-heading">
              Latest inspectable transition
              <small>Before · action · after</small>
            </h2>
            <TransitionJoint before={transition.before} action={transition.action} after={transition.after} facts={transition.facts} compact />
          </section>

          <section className="workspace-machines" aria-labelledby="machine-heading">
            <h2 className="visually-hidden" id="machine-heading">Independent state machines</h2>
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

          <details className="workspace-secondary">
            <summary>Record allocation and observation detail</summary>
            <div className="workspace-secondary-grid">
              <ObservationStamp {...observation} />
              <div className="allocation-table-wrap">
                <table>
                  <caption>Deterministic synthetic holder allocation</caption>
                  <thead><tr><th>Participant</th><th>Units</th><th>Receivable exposure</th><th>Protection exposure</th></tr></thead>
                  <tbody>
                    <tr>
                      <th scope="row">Holder A</th>
                      <td>60 / 100</td>
                      <td>{formatDomainAmount(proRateDomainAmount(selected.economics.receivable.outstanding, { invoiceUnits: "60", totalUnits: "100" }))} aUSDC</td>
                      <td>{formatDomainAmount(proRateDomainAmount(selected.economics.protection.lockedReserve, { invoiceUnits: "60", totalUnits: "100" }))} aUSDC</td>
                    </tr>
                    <tr>
                      <th scope="row">Holder B</th>
                      <td>40 / 100</td>
                      <td>{formatDomainAmount(proRateDomainAmount(selected.economics.receivable.outstanding, { invoiceUnits: "40", totalUnits: "100" }))} aUSDC</td>
                      <td>{formatDomainAmount(proRateDomainAmount(selected.economics.protection.lockedReserve, { invoiceUnits: "40", totalUnits: "100" }))} aUSDC</td>
                    </tr>
                  </tbody>
                </table>
                {position ? <p>Connected viewer position: {position.invoiceUnits} / {position.totalUnits} invoice units.</p> : null}
              </div>
            </div>
          </details>

          <footer className="workspace-policy-boundary">
            <span aria-hidden="true" />
            <p>Policy event only — not off-network fraud, legal priority, insurance, or production safety.</p>
            <strong>{dealShortId(selected)}</strong>
          </footer>
        </section>

        <aside className="workspace-decision" aria-label="Readiness and next action">
          {verdict ? (
            <ReadinessVerdict
              verdict={verdict}
              recheckLabel={verdict.recheckAt ? formatUtc(verdict.recheckAt) : undefined}
            />
          ) : (
            <section className="readiness-verdict" data-tone="positive">
              <p className="micro-label">Unique readiness verdict</p>
              <h2>No action due</h2>
              <p className="readiness-cause">This synthetic state has no candidate action configured.</p>
            </section>
          )}

          <section className="workspace-responsibility" data-status={selected.nextResponsibility.status}>
            <div>
              <p className="micro-label">Next responsibility</p>
              <strong>{selected.nextResponsibility.actorLabel}</strong>
              <p>{selected.nextResponsibility.task}</p>
            </div>
            <div className="deadline-seal" data-testid="decision-deadline">
              <span>Due</span>
              <strong>{responsibilityDue(selected)}</strong>
            </div>
          </section>

          {gates.length > 0 ? <GateVector gates={gates} compact /> : null}

          {primaryAction ? (
            <section className="workspace-candidate" aria-labelledby="candidate-action-heading">
              <p className="micro-label">Candidate action · review before commitment</p>
              {selected.actions.length > 1 ? (
                <fieldset className="candidate-selector">
                  <legend>Select one independently assessed action</legend>
                  <div>
                    {selected.actions.map((action) => (
                      <button
                        type="button"
                        key={action.id}
                        aria-pressed={action.id === primaryAction.id}
                        onClick={() => { setSelectedActionId(action.id); setShowExecution(false); }}
                      >
                        {action.label}
                      </button>
                    ))}
                  </div>
                </fieldset>
              ) : null}
              <div className="candidate-summary">
                <div>
                  <h2 id="candidate-action-heading">{primaryAction.label}</h2>
                  <p>{primaryAction.consequence.summary}</p>
                </div>
                <span>{formatRole(primaryAction.actorRole)}<br />{formatState(primaryAction.machine)}</span>
              </div>
              <dl>
                <div><dt>Contract intent</dt><dd>{primaryAction.contractAction}</dd></div>
                <div><dt>Receivable units</dt><dd>{formatState(primaryAction.consequence.receivableUnitsEffect)}</dd></div>
              </dl>
              <button
                className={verdict?.code === "AVAILABLE_NOW" ? "primary-action" : "secondary-action"}
                data-testid="primary-action"
                type="button"
                onClick={() => setShowExecution((open) => !open)}
                aria-expanded={showExecution}
              >
                {verdict?.code === "AVAILABLE_NOW" ? "Review action package" : "Inspect resolution path"}
              </button>
            </section>
          ) : null}
        </aside>
      </div>

      {showExecution && primaryAction && verdict ? (
        <TransactionReview
          action={primaryAction}
          verdict={verdict}
          onClose={() => setShowExecution(false)}
        />
      ) : null}
    </div>
  );
}
