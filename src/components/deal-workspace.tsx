"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  SYNTHETIC_DEALS,
  deriveDealSummary,
  type DealPosture,
  type DealScenarioId,
  type SyntheticDeal,
} from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";
import type { ReadinessVerdictCode } from "@/lib/mordant/readiness";
import {
  GateVector,
  MachineRail,
  ObservationStamp,
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

import styles from "./deal-workspace.module.css";

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
type WorkspaceView = "workspace" | "portfolio" | "evidence";

function viewFromHash(hash: string): WorkspaceView {
  if (hash === "#portfolio") return "portfolio";
  if (hash === "#evidence") return "evidence";
  return "workspace";
}

const POSTURE_ORDER: Readonly<Record<DealPosture, number>> = {
  recovery: 0,
  critical: 1,
  attention: 2,
  unknown: 3,
  stable: 4,
  complete: 5,
};

const READINESS_LABELS: Readonly<Record<ReadinessVerdictCode, string>> = {
  AVAILABLE_NOW: "Available now",
  AVAILABLE_AT: "Available later",
  WRONG_ROLE: "Wrong role",
  CREDENTIAL_REQUIRED: "Credential required",
  FUNDS_REQUIRED: "Funds required",
  PREVIOUS_ACTION_REQUIRED: "Previous action required",
  ALREADY_COMPLETED: "Already completed",
  RECOVERY_REQUIRED: "Recovery required",
};

const PORTFOLIO_STATUS_LABELS: Readonly<Record<DealPosture, string>> = {
  recovery: "Support needed",
  critical: "Needs attention",
  attention: "Waiting on someone",
  unknown: "Being checked",
  stable: "On track",
  complete: "Complete",
};

const PORTFOLIO_READINESS_LABELS: Readonly<Record<ReadinessVerdictCode, string>> = {
  AVAILABLE_NOW: "Action available",
  AVAILABLE_AT: "Available later",
  WRONG_ROLE: "Another party acts",
  CREDENTIAL_REQUIRED: "Identity check needed",
  FUNDS_REQUIRED: "Funding needed",
  PREVIOUS_ACTION_REQUIRED: "Waiting for prior step",
  ALREADY_COMPLETED: "Completed",
  RECOVERY_REQUIRED: "Manual recovery",
};

function verdictTone(code: ReadinessVerdictCode) {
  if (code === "AVAILABLE_NOW" || code === "ALREADY_COMPLETED") return "positive";
  if (code === "AVAILABLE_AT" || code === "PREVIOUS_ACTION_REQUIRED") return "attention";
  return "critical";
}

function deadlineParts(deal: SyntheticDeal) {
  const dueAt = deal.nextResponsibility.dueAt;
  if (!dueAt) return undefined;

  const value = new Date(dueAt);
  return {
    dueAt,
    label: responsibilityDue(deal),
    clock: new Intl.DateTimeFormat("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
      timeZone: "UTC",
    }).format(value),
    date: new Intl.DateTimeFormat("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      timeZone: "UTC",
    }).format(value),
  };
}

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

function portfolioNextStep(deal: SyntheticDeal) {
  if (deal.nextResponsibility.dueAt) return queueDeadline(deal);
  const action = deal.actions[0];
  if (!action) return "No action due";
  return PORTFOLIO_READINESS_LABELS[deriveReadinessVerdict(deal, action).code];
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
  const [workspaceView, setWorkspaceView] = useState<WorkspaceView>("workspace");
  const evidenceDetailRef = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    const task = window.setTimeout(() => {
      const saved = window.localStorage.getItem(STORAGE_KEY);
      if (saved && SYNTHETIC_DEALS.some((deal) => deal.scenario === saved)) {
        setSelectedScenario(saved as DealScenarioId);
      }
    }, 0);
    return () => window.clearTimeout(task);
  }, []);

  useEffect(() => {
    function syncWorkspaceView() {
      const nextView = viewFromHash(window.location.hash);
      setWorkspaceView(nextView);
      if (nextView === "portfolio") setQueueFilter("all");

      window.requestAnimationFrame(() => {
        if (evidenceDetailRef.current) evidenceDetailRef.current.open = nextView === "evidence";
      });

      if (nextView !== "workspace") {
        window.requestAnimationFrame(() => {
          window.requestAnimationFrame(() => window.scrollTo({ top: 0, left: 0, behavior: "auto" }));
        });
      }
    }

    syncWorkspaceView();
    window.addEventListener("hashchange", syncWorkspaceView);
    window.addEventListener("popstate", syncWorkspaceView);

    return () => {
      window.removeEventListener("hashchange", syncWorkspaceView);
      window.removeEventListener("popstate", syncWorkspaceView);
    };
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
  const deadline = deadlineParts(selected);

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
    if (workspaceView === "portfolio") {
      const previousUrl = window.location.href;
      window.history.pushState(null, "", "/#app-main");
      window.dispatchEvent(new HashChangeEvent("hashchange", {
        oldURL: previousUrl,
        newURL: window.location.href,
      }));
    }
  }

  return (
    <div
      className={`workspace-surface ${styles.workspace}`}
      data-testid="m18nws-workspace"
      data-workspace-view={workspaceView}
    >
      <div className="workspace-grid">
        <aside
          className="intervention-queue"
          id="portfolio"
          aria-label={workspaceView === "portfolio" ? "Portfolio deals" : "Intervention queue"}
          data-testid="workspace-interventions"
        >
          <div className="queue-controls">
            <p className={styles.queueEyebrow}>Portfolio</p>
            <div className="queue-heading-line">
              <h1>{workspaceView === "portfolio" ? "All monitored deals" : "Intervention queue"}</h1>
              <span>{String(interventionCount).padStart(2, "0")} due now</span>
            </div>
            <label className="queue-search">
              <span className="visually-hidden">Search deals</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search deal or owner"
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
                      <span className="folio-identity folio-identity-compact">
                        <strong>{dealShortId(deal)}</strong>
                      </span>
                      <strong>{deal.label}</strong>
                      <small>{deal.nextResponsibility.actorLabel}</small>
                    </span>
                    <span className="queue-item-status">
                      <strong>
                        {workspaceView === "portfolio"
                          ? PORTFOLIO_STATUS_LABELS[dealSummary.posture]
                          : formatState(dealSummary.protectionState)}
                      </strong>
                      <small>{workspaceView === "portfolio" ? portfolioNextStep(deal) : queueDeadline(deal)}</small>
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
            <span>Urgent first</span>
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
              <p>Buyer-accepted synthetic invoice · {selected.economics.receivable.outstandingUnits} of {selected.economics.receivable.issuedUnits} units outstanding</p>
            </div>
            <div className="workspace-root-identity">
              <span className="micro-label">Selected deal</span>
              <strong>{formatState(summary.receivableState)}</strong>
              <small>Full identifiers stay in evidence</small>
            </div>
          </header>

          <div className="workspace-domain-pair" aria-label="Independent accounting domains">
            <section
              className="domain-ledger"
              data-domain="receivable"
              data-edge="continuous-double"
              aria-label={`Receivable · outstanding: ${formatDomainAmount(selected.economics.receivable.outstanding)} ${selected.economics.receivable.outstanding.asset.symbol}`}
            >
              <div className="domain-ledger-head">
                <span>Receivable · outstanding</span>
                <strong>{formatState(selected.machines.receivable.state)}</strong>
              </div>
              <p className="domain-ledger-amount">
                <span>{formatDomainAmount(selected.economics.receivable.outstanding)}</span>{" "}
                <small>{selected.economics.receivable.outstanding.asset.symbol}</small>
              </p>
              <p className="domain-ledger-description">
                {selected.economics.receivable.outstandingUnits} / {selected.economics.receivable.issuedUnits} units remain held. Protection cannot move them.
              </p>
            </section>

            <section
              className="domain-ledger"
              data-domain="protection"
              data-edge="interrupted-notch"
              aria-label={`${protectionLedgerLabel(selected)}: ${formatDomainAmount(selected.economics.protection.lockedReserve)} ${selected.economics.protection.lockedReserve.asset.symbol}`}
            >
              <div className="domain-ledger-head">
                <span>{protectionLedgerLabel(selected)}</span>
                <strong>{formatState(selected.machines.protection.state)}</strong>
              </div>
              <p className="domain-ledger-amount">
                <span>{formatDomainAmount(selected.economics.protection.lockedReserve)}</span>{" "}
                <small>{selected.economics.protection.lockedReserve.asset.symbol}</small>
              </p>
              <p className="domain-ledger-description">Separate, conditional reserve. Invoice units stay untouched.</p>
            </section>
          </div>

          <section className="workspace-consequence" aria-label="Economic consequence">
            <p className="micro-label">If this deadline is missed</p>
            <strong>{selected.nextResponsibility.consequenceIfMissed ?? "No configured economic consequence."}</strong>
          </section>

          <details className={styles.whyDetail}>
            <summary>
              <span>Why this deal needs attention</span>
              <span aria-hidden="true" />
            </summary>
            <div className={styles.whyGrid}>
              <p><strong>Who acts</strong>{selected.nextResponsibility.actorLabel} owns the next responsibility.</p>
              <p><strong>What changes</strong>{primaryAction?.consequence.summary ?? "No candidate state change is configured."}</p>
              <p><strong>What stays</strong>Protection events never burn or transfer the underlying invoice units.</p>
            </div>
          </details>

          <details className="workspace-secondary" id="evidence" ref={evidenceDetailRef}>
            <summary>View evidence and allocations</summary>
            <div className="workspace-secondary-grid">
              <section className="workspace-transition" aria-labelledby="transition-heading">
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

              <div className={styles.evidenceIdentity}>
                <p><span>Invoice root</span><strong>{selected.machines.receivable.immutableInvoiceRoot}</strong></p>
                <p><span>Policy</span><strong>{selected.machines.protection.immutablePolicyId}</strong></p>
                <p><span>Short reference</span><strong>{shortReference(selected.machines.receivable.immutableInvoiceRoot, 18, 10)}</strong></p>
              </div>

              <div className={styles.domainEvidence}>
                <section aria-labelledby="receivable-accounting-heading">
                  <h3 id="receivable-accounting-heading">Receivable accounting</h3>
                  <dl className="domain-ledger-context">
                    <div><dt>Role</dt><dd>Buyer owes · holders own</dd></div>
                    <div><dt>Location</dt><dd>Receivable vault ledger</dd></div>
                    <div><dt>Source</dt><dd>Buyer-accepted synthetic invoice root</dd></div>
                    <div><dt>Next effect</dt><dd>Redemption burns only redeemed invoice units</dd></div>
                  </dl>
                </section>
                <section aria-labelledby="protection-accounting-heading">
                  <h3 id="protection-accounting-heading">Protection accounting</h3>
                  <dl className="domain-ledger-context">
                    <div><dt>Role</dt><dd>Originator funds · policy beneficiary receives</dd></div>
                    <div><dt>Location</dt><dd>Protection reserve ledger</dd></div>
                    <div><dt>Source</dt><dd>{selected.machines.protection.immutablePolicyId}</dd></div>
                    <div><dt>Next effect</dt><dd>Policy settlement leaves invoice units untouched</dd></div>
                  </dl>
                  <p className={styles.reserveBoundary}>The 10% reserve is a synthetic demo parameter amortized against protected outstanding principal, not a production price.</p>
                </section>
              </div>

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
          <p className={styles.mobileDecisionContext}>
            <span>{dealShortId(selected)}</span>
            <strong>{selected.label}</strong>
          </p>
          {verdict ? (
            <section
              className="readiness-verdict"
              data-readiness-verdict={verdict.code}
              data-tone={verdictTone(verdict.code)}
            >
              <p className="micro-label">Decision</p>
              <h2>{READINESS_LABELS[verdict.code]}</h2>
              <p className="readiness-cause">{verdict.conclusion}</p>
            </section>
          ) : (
            <section className="readiness-verdict" data-tone="positive">
              <p className="micro-label">Decision</p>
              <h2>No action due</h2>
              <p className="readiness-cause">This synthetic state has no candidate action configured.</p>
            </section>
          )}

          <section className="workspace-responsibility" data-status={selected.nextResponsibility.status}>
            <div>
              <p className="micro-label">Owner now</p>
              <strong>{selected.nextResponsibility.actorLabel}</strong>
              <p>{selected.nextResponsibility.task}</p>
            </div>
            <div className="deadline-seal" data-testid="decision-deadline">
              <span>Deadline</span>
              {deadline ? (
                <time dateTime={deadline.dueAt} aria-label={deadline.label}>
                  <strong>{deadline.clock}</strong>
                  <small>{deadline.date} · UTC</small>
                </time>
              ) : (
                <strong>No deadline</strong>
              )}
            </div>
          </section>

          {primaryAction ? (
            <section className="workspace-candidate" aria-labelledby="candidate-action-heading">
              <p className="micro-label">Next action · review before commitment</p>
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
              <button
                className={verdict?.code === "AVAILABLE_NOW" ? "primary-action" : "secondary-action"}
                data-testid="primary-action"
                type="button"
                onClick={() => setShowExecution((open) => !open)}
                aria-expanded={showExecution}
              >
                {verdict?.code === "AVAILABLE_NOW" ? "Review action package" : "Inspect resolution path"}
              </button>
              <details className={styles.actionDetail}>
                <summary>Action detail</summary>
                <dl>
                  <div><dt>Contract intent</dt><dd>{primaryAction.contractAction}</dd></div>
                  <div><dt>Receivable units</dt><dd>{formatState(primaryAction.consequence.receivableUnitsEffect)}</dd></div>
                </dl>
              </details>
            </section>
          ) : null}

          {verdict ? (
            <details className={styles.readinessDetail}>
              <summary>
                <span>Why this verdict?</span>
                <span aria-hidden="true" />
              </summary>
              <dl className="readiness-facts">
                <div><dt>Cause</dt><dd>{verdict.cause}</dd></div>
                <div><dt>Blocking gate</dt><dd>{verdict.blockingGate?.label ?? "None"}</dd></div>
                <div><dt>Responsible</dt><dd>{verdict.responsible}</dd></div>
                <div><dt>Unlock</dt><dd>{verdict.unlock}</dd></div>
                <div><dt>Re-evaluate</dt><dd>{verdict.recheckAt ? formatUtc(verdict.recheckAt) : "After the next state observation"}</dd></div>
                <div><dt>Economic consequence</dt><dd>{verdict.economicConsequence}</dd></div>
                <div><dt>Next action</dt><dd>{verdict.nextAction}</dd></div>
              </dl>
              {gates.length > 0 ? <GateVector gates={gates} compact /> : null}
            </details>
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
