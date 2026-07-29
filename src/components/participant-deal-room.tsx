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

type ParticipantMoneyRowProps = {
  domain: "receivable" | "protection";
  label: string;
  amount: string;
  asset: string;
  status: string;
};

function ParticipantMoneyRow({
  domain,
  label,
  amount,
  asset,
  status,
}: ParticipantMoneyRowProps) {
  const edge = domain === "receivable" ? "continuous-double" : "interrupted-notch";

  return (
    <div
      className="domain-ledger"
      data-domain={domain}
      data-edge={edge}
      data-testid={`participant-domain-${domain}`}
      aria-label={`${label}: ${amount} ${asset}. ${status}.`}
    >
      <span className={styles.moneyLabel}>{label}</span>
      <p className="domain-ledger-amount">
        <span>{amount}</span> <small>{asset}</small>
      </p>
      <strong className={styles.moneyStatus}>{status}</strong>
    </div>
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
            <div className={styles.outcome}>
              <p className="micro-label">Your update</p>
              <h1 id="participant-title">Nothing you need to do.</h1>
              <p className={styles.reassurance}>
                Your invoice payment is unchanged and remains yours.
              </p>
            </div>

            <p className={styles.responsibility} data-testid="participant-deadline">
              The responsible company (<strong>{responsible}</strong>) is resolving the issue by{" "}
              <time dateTime={dueAt} aria-label={`${deadline.clock} UTC on ${deadline.date}`}>
                {deadline.date}, {deadline.clock} UTC
              </time>.
            </p>
          </header>

          <section className="participant-domain-pair" aria-labelledby="participant-money-heading">
            <h2 id="participant-money-heading">Your money</h2>
            <ParticipantMoneyRow
              domain="receivable"
              label="Invoice payment"
              amount={formatDomainAmount(receivableExposure, 0)}
              asset={receivableExposure.asset.symbol}
              status="Still yours"
            />
            <ParticipantMoneyRow
              domain="protection"
              label="Protection reserve"
              amount={formatDomainAmount(protectionExposure, 0)}
              asset={protectionExposure.asset.symbol}
              status="Backup if unresolved"
            />
          </section>

          <p className="participant-consequence" data-testid="participant-deadline-consequence">
            <strong>If unresolved</strong>
            <span>
              The protection reserve may become available; your invoice remains yours.
            </span>
          </p>

          <section className="participant-actions" aria-label="Your next step and decision detail">
            <Link className="primary-action" href="/#portfolio" data-testid="participant-primary-action">
              <span aria-hidden="true">←</span>
              Back to portfolio
            </Link>

            <details className={styles.disclosure} name="participant-detail" data-testid="participant-why">
              <summary data-testid="participant-review-action">
                <span>Why am I waiting?</span>
                <span className={styles.disclosureSign} aria-hidden="true" />
              </summary>
              <div className={styles.humanDetail} role="status">
                <h2>Another company is resolving the issue.</h2>
                <dl>
                  <div>
                    <dt>Who acts</dt>
                    <dd>{responsible} is responsible for resolving it. You do not need to sign anything.</dd>
                  </div>
                  <div>
                    <dt>What stays yours</dt>
                    <dd>Your invoice payment remains yours throughout this process.</dd>
                  </div>
                  <div>
                    <dt>What happens next</dt>
                    <dd>
                      {responsible} must resolve it before the deadline. If not, the protection reserve may become available.
                    </dd>
                  </div>
                </dl>
              </div>
            </details>

            <details
              className={styles.disclosure}
              id="evidence"
              name="participant-detail"
              data-testid="participant-evidence"
            >
              <summary>
                <span>How do we know?</span>
                <span className={styles.disclosureSign} aria-hidden="true" />
              </summary>
              <div className={styles.trustDetail}>
                <header>
                  <p className="micro-label">Verification summary</p>
                  <h2>This screen uses a configured test scenario.</h2>
                </header>
                <dl className={styles.trustGrid}>
                  <div>
                    <dt>Source</dt>
                    <dd>The product scenario supplies the status shown above.</dd>
                  </div>
                  <div>
                    <dt>Confirmed here</dt>
                    <dd>Your role cannot resolve this issue and no action is offered.</dd>
                  </div>
                  <div>
                    <dt>Not confirmed here</dt>
                    <dd>No live network observation or signed participant record is attached.</dd>
                  </div>
                </dl>

                <details className={styles.technicalDisclosure} data-testid="participant-technical-details">
                  <summary>
                    <span>Technical details</span>
                    <span className={styles.disclosureSign} aria-hidden="true" />
                  </summary>
                  <div className={styles.technicalBody}>
                    <p data-testid="participant-position" className={styles.technicalPosition}>
                      Configured holder position · {position.invoiceUnits} / {position.totalUnits} invoice units
                    </p>

                    <ReadinessVerdict verdict={verdict} compact />

                    <GateVector gates={action.gates.map(gateToView)} title="Your readiness inspection" compact />

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
              </div>
            </details>
          </section>
        </section>
      </section>
    </div>
  );
}
