"use client";

import { useState } from "react";

import { getSyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";
import {
  DomainLedger,
  FolioIdentity,
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
} from "@/components/product-presenters";

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

export function ParticipantDealRoom() {
  const deal = getSyntheticDeal("wrong-role");
  const action = deal.actions[0];
  const verdict = deriveReadinessVerdict(deal, action);
  const position = deal.viewer.position ?? { invoiceUnits: "0" as const, totalUnits: "100" as const };
  const receivableExposure = proRateDomainAmount(deal.economics.receivable.outstanding, position);
  const protectionExposure = proRateDomainAmount(deal.economics.protection.lockedReserve, position);
  const dueAt = deal.nextResponsibility.dueAt ?? "2026-07-29T12:00:00.000Z";
  const [showReview, setShowReview] = useState(false);

  return (
    <div className="participant-surface">
      <section className="participant-folio" aria-labelledby="participant-title">
        <div className="participant-critical-band">
          <span>Critical · synthetic policy P–CP–01</span>
          <strong>Conflict state configured · cure window open</strong>
          <time dateTime={dueAt}>Closes {formatUtc(dueAt)}</time>
        </div>

        <div className="participant-columns">
          <div className="participant-record">
            <header className="participant-identity">
              <div className="participant-position" data-testid="participant-position">
                <strong>{dealShortId(deal)}</strong>
                <span>{deal.viewer.label}</span>
                <span>Your position · {position.invoiceUnits} / {position.totalUnits} units</span>
              </div>
              <FolioIdentity
                folio={dealShortId(deal)}
                root={deal.machines.receivable.immutableInvoiceRoot}
                compact
              />
            </header>

            <section className="participant-message">
              <div>
                <p className="micro-label">Your synthetic role view</p>
                <h1 id="participant-title">
                  This fixture is configured in a conflict state.
                  <span>Your invoice units have not moved.</span>
                </h1>
              </div>
              <p>
                Facility B is responsible for the cure; the configured Holder identity has no cure action. No transition event, participant signature, or live wallet read is attached to this scenario. This synthetic conflict state does not establish off-network financing, fraud, or legal priority.
              </p>
            </section>

            <div className="participant-domain-pair" aria-label="Your independent economic domains">
              <DomainLedger
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
              <DomainLedger
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
                <p className="micro-label">If no cure is completed</p>
                <h2 id="participant-consequence-heading">Your two balances keep separate meanings.</h2>
              </div>
              <ol>
                <li>Protection may become claimable under this configured policy.</li>
                <li>Your {position.invoiceUnits} invoice units are neither burned nor transferred.</li>
                <li>Receivable settlement continues on its independent lifecycle.</li>
              </ol>
            </section>

          </div>

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
              <dl>
                <div><dt>UTC deadline</dt><dd>{formatUtc(dueAt)}</dd></div>
                <div><dt>Your local reference</dt><dd>{formatParisTime(dueAt)}</dd></div>
              </dl>
            </section>

            <GateVector gates={action.gates.map(gateToView)} title="Your readiness inspection" compact />

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
              <a className="text-button" href="#evidence">Inspect evidence</a>
              {showReview ? (
                <div className="execution-review" role="status">
                  <strong>No cure action is offered to this synthetic holder.</strong>
                  <p>{verdict.economicConsequence}</p>
                  <p>Capability comes from the configured synthetic role and position, not a live wallet read or manual selector.</p>
                </div>
              ) : null}
            </section>
          </aside>

          <div className="participant-evidence-area">
            <section className="participant-proof" id="evidence" aria-labelledby="participant-proof-heading">
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
          </div>
        </div>
      </section>
    </div>
  );
}
