import Link from "next/link";

import { getSyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";
import {
  GateVector,
  ReadinessVerdict,
  TransitionJoint,
} from "@/components/structural-ui";
import {
  formatDomainAmount,
  gateToView,
  proRateDomainAmount,
} from "@/components/product-presenters";

import styles from "./participant-deal-room.module.css";

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
  status: string;
};

function ParticipantDomainLedger({
  domain,
  label,
  amount,
  asset,
  status,
}: ParticipantDomainLedgerProps) {
  const edge = domain === "receivable" ? "continuous-double" : "interrupted-notch";

  return (
    <section
      className="domain-ledger"
      data-domain={domain}
      data-edge={edge}
      data-testid={`participant-domain-${domain}`}
      aria-label={`${label}: ${amount} ${asset}. ${status}.`}
    >
      <p className="domain-ledger-head">
        <span>{label} · <strong>{status}</strong></span>
      </p>
      <p className="domain-ledger-amount">
        <span>{amount}</span> <small>{asset}</small>
      </p>
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
  const responsible = deal.nextResponsibility.actorLabel.replace(" (synthetic)", "");

  return (
    <div className={`participant-surface ${styles.surface}`}>
      <section className="participant-folio" aria-labelledby="participant-title">
        <section
          className="participant-first-view"
          data-testid="participant-first-view"
          data-readiness-verdict={verdict.code}
        >
          <header className="participant-message">
            <div className={styles.decisionCopy}>
              <p className="micro-label">Your position</p>
              <h1 id="participant-title">Your receivable has not moved.</h1>
              <p className={styles.noAction}>You have no action.</p>
            </div>

            <dl className={styles.responsibility} data-testid="participant-deadline">
              <div>
                <dt>Responsible</dt>
                <dd>{responsible}</dd>
              </div>
              <div>
                <dt>Deadline</dt>
                <dd>
                  <time dateTime={dueAt} aria-label={`${deadline.clock} UTC on ${deadline.date}`}>
                    {deadline.clock} UTC · {deadline.date}
                  </time>
                </dd>
              </div>
            </dl>
          </header>

          <div className="participant-domain-pair" aria-label="Your separate economic positions">
            <ParticipantDomainLedger
              domain="receivable"
              label="Receivable"
              amount={formatDomainAmount(receivableExposure, 0)}
              asset={receivableExposure.asset.symbol}
              status="Still held"
            />
            <ParticipantDomainLedger
              domain="protection"
              label="Protection"
              amount={formatDomainAmount(protectionExposure, 0)}
              asset={protectionExposure.asset.symbol}
              status="Not paid"
            />
          </div>

          <p className="participant-consequence" data-testid="participant-deadline-consequence">
            If the cure is missed, protection may become claimable while your receivable remains separate.
          </p>

          <section className="participant-actions" aria-label="Your next step and decision detail">
            <Link className="primary-action" href="/#portfolio" data-testid="participant-primary-action">
              <span aria-hidden="true">←</span>
              Back to portfolio
            </Link>

            <details className={styles.disclosure} name="participant-detail" data-testid="participant-why">
              <summary data-testid="participant-review-action">
                <span>Why?</span>
                <span className={styles.disclosureSign} aria-hidden="true" />
              </summary>
              <div className={styles.disclosureBody} role="status">
                <header className={styles.detailHeading}>
                  <p className="micro-label">Why you wait</p>
                  <h2>The cure belongs to another role.</h2>
                </header>

                <div className={styles.whyGrid}>
                  <p>
                    <strong>No signature needed</strong>
                    No cure action is offered to this synthetic holder. Your role has nothing to sign.
                  </p>
                  <p>
                    <strong>Your receivable stays yours</strong>
                    A protection claim never burns or transfers your invoice units.
                  </p>
                  <p data-testid="participant-position">
                    <strong>Your configured position</strong>
                    Your position · {position.invoiceUnits} / {position.totalUnits} units. This is a synthetic scenario, not a live wallet read or manual selector.
                  </p>
                </div>

                <ReadinessVerdict verdict={verdict} compact />

                <details className={styles.gateDisclosure}>
                  <summary>
                    <span>Technical readiness</span>
                    <span className={styles.disclosureSign} aria-hidden="true" />
                  </summary>
                  <GateVector gates={action.gates.map(gateToView)} title="Your readiness inspection" compact />
                </details>
              </div>
            </details>

            <details
              className={`${styles.disclosure} ${styles.evidenceDisclosure}`}
              id="evidence"
              name="participant-detail"
              data-testid="participant-evidence"
            >
              <summary>
                <span>Evidence</span>
                <span className={styles.disclosureSign} aria-hidden="true" />
              </summary>
              <div className={styles.evidenceBody}>
                <section className="participant-proof" aria-labelledby="participant-proof-heading">
                  <header className="participant-proof-heading">
                    <p className="micro-label">What supports this state</p>
                    <h2 id="participant-proof-heading">Configured scenario, not an observed transaction</h2>
                  </header>
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
          </section>
        </section>
      </section>
    </div>
  );
}
