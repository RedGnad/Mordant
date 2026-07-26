"use client";

import { useMemo, useState } from "react";
import { ArrowRight, Check, Fingerprint, LockKeyhole, RotateCcw, ShieldCheck, Split } from "lucide-react";
import { DEMO, holderEntitlement, holderRedemption } from "@/lib/mordant/scenario";
import { LiveVaultProof } from "@/components/live-vault-proof";

type Phase = "ready" | "financed" | "conflict" | "protected" | "settled";

const phases: Phase[] = ["ready", "financed", "conflict", "protected", "settled"];

const copy: Record<Phase, { eyebrow: string; title: string; detail: string }> = {
  ready: {
    eyebrow: "Buyer-accepted invoice",
    title: "$110 claim, verified before funding",
    detail: "The originator, facility and future holders enter through Cleanverse identity and asset rules.",
  },
  financed: {
    eyebrow: "First financing",
    title: "$90 moves. $10 stays ready.",
    detail: "The advance is split once: working capital reaches the originator and the existing reserve backs exclusivity.",
  },
  conflict: {
    eyebrow: "Registered conflict",
    title: "The same invoice is pledged again.",
    detail: "A second verified facility reveals an overlapping exclusive pledge. The holder record date was already fixed.",
  },
  protected: {
    eyebrow: "Funded consequence",
    title: "The holders inherit the reserve.",
    detail: "The bond changes owner. The $110 invoice claim does not disappear, burn or get swapped away.",
  },
  settled: {
    eyebrow: "Invoice repaid",
    title: "$110 settles separately. The bond was extra.",
    detail: "The debtor repayment closes the underlying claim 66/44. It does not reverse the earlier 6/4 protection payout.",
  },
};

export function MordantDemo() {
  const [phase, setPhase] = useState<Phase>("ready");
  const step = phases.indexOf(phase);
  const current = copy[phase];
  const claims = useMemo(
    () => DEMO.holders.map((holder) => ({
      ...holder,
      payout: holderEntitlement(holder.units, DEMO.initialUnits, DEMO.initialBond),
      redemption: holderRedemption(holder.units),
    })),
    [],
  );

  function advance() {
    setPhase(phases[Math.min(step + 1, phases.length - 1)]);
  }

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Mordant home">
          <span className="brand-mark">M</span>
          <span>Mordant</span>
        </a>
        <div className="network-pill"><span /> Monad testnet · local scenario</div>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="kicker">Protection that already has the money</p>
          <h1>One invoice.<br />Two pledges.<br /><em>One consequence.</em></h1>
          <p className="lede">When an originator pledges one invoice twice, its holders inherit the bond.</p>
          <div className="primitive-row" aria-label="Cleanverse integration points">
            <span><Fingerprint size={16} /> CVI identities</span>
            <span><ShieldCheck size={16} /> CVA invoice claim</span>
            <span><LockKeyhole size={16} /> aUSDC reserve</span>
          </div>
        </div>

        <div className="demo-card" aria-live="polite">
          <div className="demo-head">
            <div>
              <span className="micro">LIVE FLOW · SYNTHETIC ASSET</span>
              <h2>{current.eyebrow}</h2>
            </div>
            <span className="step-count">0{step + 1} / 05</span>
          </div>

          <div className="invoice-strip">
            <div><span>Invoice</span><strong>ACME–0042</strong></div>
            <div><span>Face value</span><strong>$110</strong></div>
            <div><span>Due</span><strong>30 days</strong></div>
            <div className="verified"><Check size={14} /> Buyer accepted</div>
          </div>

          <div className="stage">
            <div className="stage-copy">
              <span className={`state-light state-${phase}`} />
              <div><h3>{current.title}</h3><p>{current.detail}</p></div>
            </div>

            <div className="money-grid">
              <article className={step >= 1 ? "active" : ""}>
                <span>Originator receives</span><strong>${step >= 1 ? "90" : "—"}</strong><small>working capital</small>
              </article>
              <article className={step >= 1 ? "active reserve" : ""}>
                <span>Reserve locked</span><strong>${step >= 1 ? "10" : "—"}</strong><small>from existing proceeds</small>
              </article>
            </div>

            <div className={`holder-ledger ${step >= 2 ? "revealed" : ""}`}>
              <div className="ledger-title"><Split size={16} /><span>Holder record date</span><b>{step >= 2 ? "fixed before reveal" : "100 units outstanding"}</b></div>
              {claims.map((claim) => (
                <div className="holder-row" key={claim.id}>
                  <span className="avatar">{claim.id}</span>
                  <span>Holder {claim.id}</span>
                  <strong>{claim.units} invoice units</strong>
                  <ArrowRight size={15} />
                  <b>{step >= 4 ? `+$${claim.payout} + $${claim.redemption}` : step >= 3 ? `+$${claim.payout} bond` : "pending"}</b>
                </div>
              ))}
            </div>

            <div className={`claim-intact ${step >= 3 ? "visible" : ""}`}>
              <Check size={17} /><span>{phase === "settled"
                ? "Invoice repaid independently: $66 / $44 after the $6 / $4 protection payout."
                : "The holders still own all 100 invoice units and the full $110 claim."}</span>
            </div>
          </div>

          <div className="demo-actions">
            <div className="progress" aria-hidden="true">{phases.map((item, index) => <span className={index <= step ? "done" : ""} key={item} />)}</div>
            {phase === "settled" ? (
              <button type="button" className="secondary" onClick={() => setPhase("ready")}><RotateCcw size={17} /> Replay</button>
            ) : (
              <button type="button" className="primary" onClick={advance}>{step === 0 ? "Finance the invoice" : step === 1 ? "Register second pledge" : step === 2 ? "Finalize protection" : "Settle the invoice"}<ArrowRight size={17} /></button>
            )}
          </div>
        </div>
      </section>

      <section className="proof-band">
        <p>Registries stop at the alert.</p>
        <h2>Mordant makes the breach financially legible.</h2>
        <div className="proof-grid">
          <div><span>01</span><strong>Pre-funded</strong><p>No promise to chase later. The reserve is already locked.</p></div>
          <div><span>02</span><strong>Record-date fair</strong><p>Transfers after the hidden commit cannot steal the protection.</p></div>
          <div><span>03</span><strong>Principal-preserving</strong><p>Claiming the reserve never consumes the invoice claim.</p></div>
        </div>
      </section>

      <LiveVaultProof />

      <footer><span>Mordant · Cleanverse Trusted Assets</span><span>Prototype · synthetic invoices · no real funds</span></footer>
    </main>
  );
}
