"use client";

import { useState } from "react";
import { getSyntheticDeal } from "@/lib/mordant/product-model";
import {
  DomainLedger,
  GateVector,
  ObservationStamp,
  TransitionJoint,
  type GateView,
} from "@/components/structural-ui";
import {
  dealShortId,
  formatDomainAmount,
  formatState,
  formatUtc,
  observationCopy,
  shortReference,
} from "@/components/product-presenters";

type Viewer = "holder" | "facility";

function participantGates(viewer: Viewer, dueAt: string): readonly GateView[] {
  const permitted = viewer === "facility";
  return [
    {
      kind: "identity",
      label: "Identity",
      status: "Clear",
      detail: "Your own synthetic eligibility result is current. No credential details for other participants are shown.",
      tone: "pass",
    },
    {
      kind: "role",
      label: "Role",
      status: permitted ? "Clear" : "Waiting on another party",
      detail: permitted
        ? "This synthetic participant can prepare the Facility B side of the cure."
        : "The cure is reserved to the Originator and Facility B. Holder A has no action in this window.",
      tone: permitted ? "pass" : "blocked",
      ...(!permitted ? { resolution: "Wait for the responsible parties; your receivable position does not change." } : {}),
    },
    {
      kind: "time",
      label: "Time",
      status: "Open now",
      detail: `The cure window closes ${formatUtc(dueAt)}.`,
      tone: "pass",
    },
    {
      kind: "economic",
      label: "Economic",
      status: "No funds required",
      detail: "This cure step does not move receivable redemption money or protection reserve money.",
      tone: "complete",
    },
    {
      kind: "protocol",
      label: "Protocol",
      status: permitted ? "Ready" : "Clear",
      detail: "The synthetic conflict and cure window are observed at a finalized fixture block.",
      tone: "pass",
    },
  ];
}

export function ParticipantDealRoom() {
  const deal = getSyntheticDeal("cure-expiring");
  const [viewer, setViewer] = useState<Viewer>("holder");
  const [showReview, setShowReview] = useState(false);
  const dueAt = deal.nextResponsibility.dueAt ?? "2026-07-29T10:00:00.000Z";
  const permitted = viewer === "facility";
  const observation = observationCopy(deal.observation);

  return (
    <div className="participant-surface">
      <header className="surface-header participant-header">
        <div>
          <p className="surface-kicker">Participant surface · consequence first</p>
          <h1 className="surface-title">Participant deal room</h1>
        </div>
        <div>
          <p className="surface-intro">
            A direct account of the current state, responsible parties, deadline, financial exposure, and supporting evidence.
          </p>
          <div className="surface-observation" aria-label="Deal room context">
            <div><span>Deal</span><strong>{dealShortId(deal)}</strong></div>
            <div><span>Viewing mode</span><strong>{viewer === "holder" ? "Holder A" : "Facility B"}</strong></div>
          </div>
        </div>
      </header>

      <section className="critical-structure" aria-labelledby="critical-state-heading">
        <div className="critical-rail" aria-hidden="true"><span>REC</span><span>02</span><span>CURE</span></div>
        <div className="critical-message">
          <p className="micro-label">Protection policy · intervention open</p>
          <h2 id="critical-state-heading"><span>Conflict registered</span><br />Cure closes in this window.</h2>
          <p>
            A second overlapping pledge was registered inside the mandatory synthetic workflow. This is a policy event, not a claim of off-network fraud or legal priority.
          </p>
        </div>
        <div className="critical-clock">
          <span>Responsible parties</span>
          <strong>Originator + Facility B</strong>
          <span>Cure closes</span>
          <strong>{formatUtc(dueAt)}</strong>
        </div>
      </section>

      <ObservationStamp {...observation} />

      <div className="participant-layout">
        <div className="participant-main-flow">
          <div className="participant-domain-ledgers">
            <DomainLedger
              domain="receivable"
              label="Receivable remains owned"
              amount={formatDomainAmount(deal.economics.receivable.outstanding)}
              asset={deal.economics.receivable.outstanding.asset.symbol}
              state={formatState(deal.machines.receivable.state)}
              description="Your underlying invoice claim remains outstanding through the protection conflict."
              footer={`${deal.economics.receivable.outstandingUnits} invoice units · immutable root ${shortReference(deal.machines.receivable.immutableInvoiceRoot)}`}
            />
            <DomainLedger
              domain="protection"
              label="Protection at risk"
              amount={formatDomainAmount(deal.economics.protection.lockedReserve)}
              asset={deal.economics.protection.lockedReserve.asset.symbol}
              state="Cure period"
              description="This separately funded reserve can become claimable if the configured cure is not completed."
              footer="Protection money · separate from receivable redemption"
            />
          </div>

          <section className="participant-consequence" aria-labelledby="consequence-heading">
            <div className="consequence-spine" aria-hidden="true" />
            <div>
              <p className="micro-label">If the window closes without cure</p>
              <h2 id="consequence-heading">Receivable units remain untouched.</h2>
              <p>The locked 10.00 synthetic aUSDC protection reserve can become a pro-rata holder entitlement. The 110.00 synthetic aUSDC receivable remains independently outstanding.</p>
            </div>
            <ol>
              <li><span>01</span><p><strong>Protection</strong> becomes claimable under this policy.</p></li>
              <li><span>02</span><p><strong>Invoice units</strong> are neither burned nor transferred.</p></li>
              <li><span>03</span><p><strong>Receivable settlement</strong> continues on its own lifecycle.</p></li>
            </ol>
          </section>

          <details className="participant-proof" open>
            <summary>
              <span><small>Evidence</small> Inspect the registered transition</span>
              <span className="mono">4 evidence fields</span>
            </summary>
            <TransitionJoint
              before="Active"
              action="registerSyntheticConflict()"
              after="Cure period"
              facts={[
                { label: "Observed", value: "ConflictRegistered · synthetic fixture", tone: "observed" },
                { label: "Attested", value: "Synthetic pledge signature present", tone: "attested" },
                { label: "Derived", value: "Cure window open", tone: "derived" },
                { label: "Not established", value: "Off-network financing or legal priority", tone: "external" },
              ]}
              compact
            />
          </details>
        </div>

        <aside className="participant-action-rail">
          <fieldset className="viewer-selector">
            <legend>View participant-specific capability</legend>
            <div>
              <button type="button" aria-pressed={viewer === "holder"} onClick={() => { setViewer("holder"); setShowReview(false); }}>Holder A</button>
              <button type="button" aria-pressed={viewer === "facility"} onClick={() => { setViewer("facility"); setShowReview(false); }}>Facility B</button>
            </div>
            <p>Only the selected participant&apos;s own eligibility result is disclosed.</p>
          </fieldset>

          <section className="participant-now" data-permitted={permitted ? "true" : "false"}>
            <p className="micro-label">What can I do now?</p>
            <h2>{permitted ? "Prepare the Facility B cure" : "No action for your role"}</h2>
            <p>{permitted
              ? "All five synthetic readiness checks allow this participant to prepare its side of the cure."
              : "Holder A cannot cure the conflict. The responsible parties must act before the displayed deadline."}</p>
          </section>

          <GateVector gates={participantGates(viewer, dueAt)} compact />

          <section className="participant-action-box">
            <p className="micro-label">Consequence review</p>
            <p>{permitted
              ? "A completed cure returns only the protection state to Active. It does not change receivable ownership."
              : "Waiting does not waive or burn the participant's receivable units."}</p>
            <button
              type="button"
              className={permitted ? "primary-action" : "secondary-action"}
              onClick={() => setShowReview((open) => !open)}
              aria-expanded={showReview}
            >
              {showReview ? "Close review" : permitted ? "Review cure package" : "Review what happens next"}
            </button>
            {showReview ? (
              <div className="execution-review" role="status">
                <strong>{permitted ? "Package ready for synthetic review" : "Waiting on responsible parties"}</strong>
                <p>No financial transaction is submitted from this prototype.</p>
              </div>
            ) : null}
          </section>
        </aside>
      </div>
    </div>
  );
}
