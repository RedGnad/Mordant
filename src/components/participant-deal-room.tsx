"use client";

import { useState } from "react";

import { getSyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";
import {
  GateVector,
  ReadinessVerdict,
  TransitionJoint,
} from "@/components/structural-ui";
import {
  dealShortId,
  formatDomainAmount,
  formatState,
  formatUtc,
  gateToView,
  proRateDomainAmount,
  shortReference,
} from "@/components/product-presenters";

import styles from "./participant-deal-room.module.css";

function formatParisTime(timestamp: string) {
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "Europe/Paris",
    timeZoneName: "short",
  }).format(new Date(timestamp));
}

function formatDeadline(timestamp: string) {
  const value = new Date(timestamp);

  return {
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

type ParticipantDomainLedgerProps = {
  domain: "receivable" | "protection";
  label: string;
  amount: string;
  asset: string;
  state: string;
  role: string;
  location: string;
  source: string;
  nextEffect: string;
  description: string;
};

function ParticipantDomainLedger({
  domain,
  label,
  amount,
  asset,
  state,
  role,
  location,
  source,
  nextEffect,
  description,
}: ParticipantDomainLedgerProps) {
  const edge = domain === "receivable" ? "continuous-double" : "interrupted-notch";

  return (
    <section
      className="domain-ledger"
      data-domain={domain}
      data-edge={edge}
      aria-label={`${label}: ${amount} ${asset}`}
    >
      <div className="domain-ledger-head">
        <span>{label}</span>
        <strong>{state}</strong>
      </div>
      <p className="domain-ledger-amount"><span>{amount}</span> <small>{asset}</small></p>
      <p className="domain-ledger-description">{description}</p>
      <details className={styles.domainDisclosure}>
        <summary>
          <span>Position detail</span>
          <span className={styles.disclosureSign} aria-hidden="true" />
        </summary>
        <dl className="domain-ledger-context">
          <div><dt>Role</dt><dd>{role}</dd></div>
          <div><dt>Location</dt><dd>{location}</dd></div>
          <div><dt>Source</dt><dd>{source}</dd></div>
          <div><dt>Next effect</dt><dd>{nextEffect}</dd></div>
        </dl>
      </details>
    </section>
  );
}

export function ParticipantDealRoom() {
  const deal = getSyntheticDeal("wrong-role");
  const action = deal.actions[0];
  const verdict = deriveReadinessVerdict(deal, action);
  const position = deal.viewer.position ?? { invoiceUnits: "0" as const, totalUnits: "100" as const };
  const receivableExposure = proRateDomainAmount(deal.economics.receivable.outstanding, position);
  const protectionExposure = proRateDomainAmount(deal.economics.protection.lockedReserve, position);
  const dueAt = deal.nextResponsibility.dueAt ?? "2026-07-29T12:00:00.000Z";
  const deadline = formatDeadline(dueAt);
  const [showReview, setShowReview] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);

  return (
    <div className={`participant-surface ${styles.surface}`}>
      <section className="participant-folio" aria-labelledby="participant-title">
        <header className="participant-critical-band" aria-label="Synthetic deal status">
          <span>Synthetic policy P–CP–01</span>
          <strong>Conflict state · cure window open</strong>
          <time dateTime={dueAt}>Closes {formatUtc(dueAt)}</time>
        </header>

        <div className="participant-columns">
          <article className="participant-record">
            <header className="participant-identity">
              <div className="participant-position" data-testid="participant-position">
                <strong>{dealShortId(deal)}</strong>
                <span>{deal.viewer.label}</span>
                <span>Your position · {position.invoiceUnits} / {position.totalUnits} units</span>
              </div>
              <p className={styles.rootReference} title={deal.machines.receivable.immutableInvoiceRoot}>
                <span>Invoice root</span>
                <code>{shortReference(deal.machines.receivable.immutableInvoiceRoot, 10, 6)}</code>
              </p>
            </header>

            <section className="participant-message">
              <div className={styles.decisionCopy}>
                <p className="micro-label">Your synthetic role view</p>
                <h1 id="participant-title">
                  Your receivable has not moved.
                  <span>You have no action.</span>
                </h1>
                <p className={styles.decisionSupport}>
                  Facility B owns the cure. Your configured Holder role has nothing to sign.
                </p>
              </div>

              <div className={styles.deadline} data-testid="participant-deadline">
                <p><strong>{deal.nextResponsibility.actorLabel}</strong> must cure before</p>
                <time dateTime={dueAt} aria-label={`${deadline.clock} UTC on ${deadline.date}`}>
                  <span>{deadline.clock}</span>
                  <small>UTC</small>
                </time>
                <p>{deadline.date}</p>
              </div>
            </section>

            <div className="participant-domain-pair" aria-label="Your independent economic domains">
              <ParticipantDomainLedger
                domain="receivable"
                label="Your receivable · outstanding"
                amount={formatDomainAmount(receivableExposure)}
                asset={receivableExposure.asset.symbol}
                state={formatState(deal.machines.receivable.state)}
                role={`${position.invoiceUnits} invoice units assigned to this synthetic holder`}
                location="Receivable vault ledger"
                source="Synthetic holder position × outstanding receivable"
                nextEffect="Settlement continues independently"
                description="Your pro-rata receivable position remains owned and outstanding through the protection conflict."
              />
              <ParticipantDomainLedger
                domain="protection"
                label="Potential protection entitlement"
                amount={formatDomainAmount(protectionExposure)}
                asset={protectionExposure.asset.symbol}
                state="Not yet claimable"
                role="Potential pro-rata policy beneficiary"
                location="Separate funded protection reserve"
                source="Synthetic holder position × locked reserve"
                nextEffect="May become claimable only if the cure is missed"
                description="This separately funded amount is not receivable redemption money and is not currently payable."
              />
            </div>

            <section className="participant-consequence" aria-labelledby="participant-consequence-heading">
              <div>
                <p className="micro-label">If the deadline is missed</p>
                <h2 id="participant-consequence-heading">Protection may become claimable.</h2>
              </div>
              <ol>
                <li>Your {position.invoiceUnits} invoice units are neither burned nor transferred.</li>
                <li>Receivable settlement keeps its independent lifecycle.</li>
                <li>Protection remains a separately funded entitlement.</li>
              </ol>
            </section>
          </article>

          <aside className="participant-capability" aria-label="Your current capability">
            <ReadinessVerdict
              verdict={verdict}
              recheckLabel={verdict.recheckAt ? formatUtc(verdict.recheckAt) : undefined}
              compact
            />

            <section className="participant-responsibility">
              <p className="micro-label">Responsible now</p>
              <strong>{deal.nextResponsibility.actorLabel}</strong>
              <p>{deal.nextResponsibility.task}</p>
              <details className={styles.inlineDisclosure}>
                <summary>
                  <span>Timing and consequence</span>
                  <span className={styles.disclosureSign} aria-hidden="true" />
                </summary>
                <dl>
                  <div><dt>UTC deadline</dt><dd>{formatUtc(dueAt)}</dd></div>
                  <div><dt>Your local reference</dt><dd>{formatParisTime(dueAt)}</dd></div>
                  <div><dt>Blocking gate</dt><dd>{verdict.blockingGate?.label ?? "None"}</dd></div>
                  <div><dt>Unlock</dt><dd>{verdict.unlock}</dd></div>
                  <div><dt>Economic consequence</dt><dd>{verdict.economicConsequence}</dd></div>
                  <div><dt>Re-evaluate</dt><dd>{verdict.recheckAt ? formatUtc(verdict.recheckAt) : "After the next state observation"}</dd></div>
                </dl>
              </details>
            </section>

            <section className="participant-actions">
              <p className="micro-label">Safe next step</p>
              <p>{verdict.nextAction}</p>
              <button
                type="button"
                className="primary-action"
                onClick={() => setShowReview((open) => !open)}
                aria-expanded={showReview}
                data-testid="participant-review-action"
              >
                {showReview ? "Close explanation" : "Review what happens next"}
              </button>
              <a
                className="text-button"
                href="#evidence"
                aria-expanded={showEvidence}
                onClick={() => setShowEvidence(true)}
              >
                Inspect evidence
              </a>
              {showReview ? (
                <div className="execution-review" role="status">
                  <strong>No cure action is offered to this synthetic holder.</strong>
                  <p>{verdict.economicConsequence}</p>
                  <p>Capability comes from the configured synthetic role and position, not a live wallet read or manual selector.</p>
                </div>
              ) : null}
            </section>

            <details className={styles.gateDisclosure}>
              <summary>
                <span>Check readiness gates</span>
                <span className={styles.disclosureSign} aria-hidden="true" />
              </summary>
              <GateVector gates={action.gates.map(gateToView)} title="Your readiness inspection" compact />
            </details>
          </aside>

          <div className="participant-evidence-area">
            <details
              className={styles.evidenceDisclosure}
              id="evidence"
              open={showEvidence}
              onToggle={(event) => setShowEvidence(event.currentTarget.open)}
            >
              <summary>
                <span>Evidence</span>
                <strong>Configured scenario · no live read</strong>
                <span className={styles.disclosureSign} aria-hidden="true" />
              </summary>
              <div className={styles.evidenceBody}>
                <section className="participant-proof" aria-labelledby="participant-proof-heading">
                  <div className="participant-proof-heading">
                    <p className="micro-label">What supports this state</p>
                    <h2 id="participant-proof-heading">Inspectable evidence summary</h2>
                  </div>
                  <TransitionJoint
                    before="Not established"
                    action="No transition proof attached"
                    after="Cure period · configured fixture"
                    facts={[
                      {
                        label: "Configured protection state",
                        value: "Cure period is the state supplied by this synthetic scenario",
                        source: "Synthetic product model · not a transition observation",
                        tone: "derived",
                      },
                      {
                        label: "Capability decision",
                        value: "Holder cannot cure; Facility B is the configured responsible role",
                        source: "Role gate + deterministic readiness model",
                        tone: "derived",
                      },
                      {
                        label: "Transition event",
                        value: "No corresponding event is attached to this scenario",
                        source: `Wrong-role fixture · ${deal.proofs.length} transition proofs`,
                        tone: "external",
                      },
                      {
                        label: "Participant signature",
                        value: "No signed participant attestation is attached to this scenario",
                        source: "Not established by the wrong-role fixture",
                        tone: "external",
                      },
                      {
                        label: "External boundary",
                        value: "Off-network financing, fraud, legal priority, insurance",
                        source: "Not established by this prototype",
                        tone: "external",
                      },
                    ]}
                  />
                </section>

                <div
                  className="observation-stamp"
                  data-evidence-class="external"
                  aria-label="Synthetic fixture boundary. No live read, transition event, or participant signature is established."
                >
                  <div><span>Source</span><strong>Wrong-role synthetic fixture</strong></div>
                  <div><span>Transition event</span><strong>Not established</strong></div>
                  <div><span>Participant signature</span><strong>Not established</strong></div>
                  <div><span>Live read</span><strong>Not performed</strong></div>
                  <div><span>Scope</span><strong>Configured state only</strong></div>
                </div>

                <p className={styles.proofBoundary}>
                  <span>Immutable invoice root</span>
                  <code>{deal.machines.receivable.immutableInvoiceRoot}</code>
                </p>
              </div>
            </details>
          </div>
        </div>
      </section>
    </div>
  );
}
