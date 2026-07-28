"use client";

import { useEffect, useState } from "react";

import {
  DEAL, EVIDENCE, HOLDERS, LIFECYCLE, formatAtomic, formatCountdown, formatDecimal,
} from "@/lib/design-lab/deal-fixture";

export type Variant = "restrained" | "fiduciary" | "radical";

export const VARIANTS: readonly { id: Variant; label: string; note: string }[] = [
  { id: "restrained", label: "Restrained", note: "Aero in the background only" },
  { id: "fiduciary", label: "Fiduciary", note: "Atmosphere, depth, functional glass" },
  { id: "radical", label: "Radical", note: "Environmental, state-driven material" },
];

/** Glyphs so a status never depends on colour alone. */
const STEP_GLYPH: Record<string, string> = {
  done: "✓", current: "◆", blocked: "✕", upcoming: "·",
};

type Props = Readonly<{ initialVariant?: Variant }>;

export function DealDetailStudy({ initialVariant = "radical" }: Props) {
  const [variant, setVariant] = useState<Variant>(initialVariant);
  const [proofOpen, setProofOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [seconds, setSeconds] = useState<number>(DEAL.cureSecondsRemaining);

  /**
   * The countdown is the one live thing on the screen, because the cure window really is running.
   * It stops entirely under prefers-reduced-motion: a ticking figure is motion, and a reader who
   * asked for less of it should get a stable number rather than a moving one.
   */
  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    const query = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (query.matches) return undefined;
    const timer = setInterval(() => setSeconds((value) => Math.max(0, value - 1)), 1000);
    return () => clearInterval(timer);
  }, []);

  // A refresh is shown as a state on the figures, not as a spinner that says nothing.
  useEffect(() => {
    if (!refreshing) return undefined;
    const timer = setTimeout(() => setRefreshing(false), 1400);
    return () => clearTimeout(timer);
  }, [refreshing]);

  const cureOpen = seconds > 0;
  const curePercent = Math.round((seconds / DEAL.cureTotalSeconds) * 100);

  return (
    <div
      className={`lab${refreshing ? " lab-refreshing" : ""}`}
      data-variant={variant}
      data-cure={cureOpen ? "open" : "closed"}
    >
      <div className="lab-sky" aria-hidden="true" />

      <div className="lab-shell">
        <div className="lab-topline">
          <p className="lab-study-note">
            <b>Design study</b>
            <span>Fork rehearsal data. Not a live deployment.</span>
          </p>
          <div className="lab-switch" role="group" aria-label="Visual direction">
            {VARIANTS.map((entry) => (
              <button
                key={entry.id}
                type="button"
                aria-pressed={variant === entry.id}
                onClick={() => setVariant(entry.id)}
                title={entry.note}
              >
                {entry.label}
              </button>
            ))}
          </div>
        </div>

        <header className="lab-head">
          <p className="lab-eyebrow">
            {DEAL.reference} · {DEAL.counterparty} · {DEAL.source}
          </p>
          <h1 className="lab-title">
            A second facility claims the same receivable.
          </h1>
          <p className="lab-subtitle">
            The conflicting pledge is on chain and readable. Until the cure window closes, the
            originator can still cancel it. After that, holder entitlement to the bond is snapshotted.
          </p>
        </header>

        {/* Level 1: what is happening, and when the next thing becomes possible. */}
        <section className="lab-decision" aria-label="Current state">
          <div className="lab-state">
            <span className="lab-state-mark" data-glyph="◆">{DEAL.stateLabel}</span>
            <h2 className="lab-state-title">Cure window open</h2>
            <p className="lab-state-detail">{DEAL.stateDetail}</p>
            <p className="lab-state-detail">
              Custody is unchanged: {formatAtomic(DEAL.custodyUnits)} {DEAL.symbol} units remain with{" "}
              {DEAL.custodian}. Nothing has been released.
            </p>
          </div>

          <figure className="lab-vessel" aria-label="Custody of the invoice units">
            <div className="lab-vessel-body">
              {HOLDERS.map((holder) => (
                <div
                  className="lab-vessel-share"
                  key={holder.id}
                  style={{ flexGrow: holder.units }}
                >
                  <span className="lab-vessel-share-label">
                    {holder.label}
                    <b>{formatAtomic(holder.units)}</b>
                  </span>
                </div>
              ))}
              <div className="lab-vessel-seal" data-revealed="true" aria-hidden="true" />
            </div>
            <figcaption>
              <strong>{formatAtomic(DEAL.custodyUnits)}</strong> {DEAL.symbol} sealed with{" "}
              {DEAL.custodian}, split between two holders. The conflicting pledge is revealed and the
              units have not moved.
            </figcaption>
          </figure>

          <div className="lab-cure">
            <p className="lab-eyebrow">Cure closes in</p>
            <p className="lab-cure-figure" aria-live="off">{formatCountdown(seconds)}</p>
            <div
              className="lab-cure-track"
              role="progressbar"
              aria-valuenow={curePercent}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Cure window remaining"
            >
              <div className="lab-cure-fill" style={{ width: `${curePercent}%` }} />
            </div>
            <p className="lab-step-detail">
              Then protection runs a further {DEAL.protectionEndsInHours} hours before default can be
              marked.
            </p>
            <button
              type="button"
              className="lab-refresh-note"
              onClick={() => setRefreshing(true)}
              aria-label="Refresh on-chain figures"
            >
              {refreshing ? "Refreshing on-chain figures…" : "Refresh figures"}
            </button>
          </div>
        </section>

        {/* Level 1: how much is exposed. Aligned so the four figures compare directly. */}
        <section className="lab-exposure" aria-label="Exposure">
          <dl className="lab-figures">
            <div className="lab-figure">
              <dt>Face value</dt>
              <dd>{formatAtomic(DEAL.faceValue)}</dd>
              <small>atomic {DEAL.currency} · {formatDecimal(DEAL.faceValue)} {DEAL.currency}</small>
            </div>
            <div className="lab-figure">
              <dt>Advance funded</dt>
              <dd>{formatAtomic(DEAL.advance)}</dd>
              <small>atomic {DEAL.currency} · {formatDecimal(DEAL.advance)} {DEAL.currency}</small>
            </div>
            <div className="lab-figure">
              <dt>Protection bond</dt>
              <dd>{formatAtomic(DEAL.bond)}</dd>
              <small>retained from the advance</small>
            </div>
            <div className="lab-figure">
              <dt>Units in custody</dt>
              <dd>{formatAtomic(DEAL.custodyUnits)}</dd>
              <small>{DEAL.symbol} held by the adapter</small>
            </div>
          </dl>
        </section>

        {/* The recourse line: the major structure, showing where this deal is heading. */}
        <section className="lab-recourse" aria-label="Recourse line">
          <div className="lab-section-head">
            <h2>Recourse line</h2>
            <p>Each step is reachable only from the one before it.</p>
          </div>
          <ol className="lab-line">
            {LIFECYCLE.map((step) => (
              <li key={step.id} className="lab-step" data-state={step.state}>
                <span className="lab-step-label" data-glyph={STEP_GLYPH[step.state]}>
                  {step.label}
                </span>
                <span className="lab-step-detail">{step.detail}</span>
              </li>
            ))}
          </ol>
        </section>

        {/* Level 2: operational detail. A table, not a grid of cards. */}
        <section className="lab-section" aria-label="Holder positions">
          <div className="lab-section-head">
            <h2>Holder positions</h2>
            <p>Entitlement is snapshotted at finalisation, not now.</p>
          </div>
          <table className="lab-table">
            <thead>
              <tr>
                <th scope="col">Holder</th>
                <th scope="col" className="hide-narrow">Address</th>
                <th scope="col" className="hide-narrow">A-Pass</th>
                <th scope="col" className="num">Units</th>
                <th scope="col" className="num">Claim on face</th>
              </tr>
            </thead>
            <tbody>
              {HOLDERS.map((holder) => (
                <tr key={holder.id}>
                  <td><strong>{holder.label}</strong></td>
                  <td className="mono hide-narrow">{holder.short}</td>
                  <td className="hide-narrow">
                    <span className="lab-confirmed">{holder.apass === "active" ? "Active" : holder.apass}</span>
                  </td>
                  <td className="num">{formatAtomic(holder.units)}</td>
                  <td className="num">{formatAtomic(holder.claim)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* Level 3: proof. Collapsed by default, always reachable. */}
        <section className="lab-section" aria-label="Evidence">
          <div className="lab-section-head">
            <h2>Evidence</h2>
            <button
              type="button"
              className="lab-proof-toggle"
              aria-expanded={proofOpen}
              onClick={() => setProofOpen((open) => !open)}
            >
              {proofOpen ? "Hide proof detail" : `Show proof detail (${EVIDENCE.length})`}
            </button>
          </div>
          {proofOpen ? (
            <div className="lab-proof">
              {EVIDENCE.map((entry) => (
                <div className="lab-proof-row" key={entry.id}>
                  <div>
                    <p className="lab-step-label" data-glyph={entry.kind === "transaction" ? "TX" : entry.kind === "signature" ? "SIG" : "RD"}>
                      {entry.label}
                    </p>
                    <p className="lab-proof-value">{entry.value}</p>
                    <p className="lab-step-detail">
                      {entry.block ? `Block ${entry.block} · ` : ""}{entry.at}
                    </p>
                  </div>
                  <span className="lab-confirmed">Confirmed</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="lab-step-detail">
              Last transition: conflict revealed at block 48901512, {EVIDENCE[0].short}. Four records
              available.
            </p>
          )}
        </section>

        {/* The one dominant interaction, inert in this study. */}
        <section className="lab-action" aria-label="Next action">
          <div>
            <h2>{DEAL.nextAction}</h2>
            <p>{DEAL.nextActionDetail}</p>
          </div>
          <button type="button" className="lab-cta" disabled title="Prototype only: this study sends nothing">
            {cureOpen ? "Available after cure" : "Finalize conflict"}
          </button>
          <p className="lab-blocked-note">
            {DEAL.viewerBlockedReason} You are viewing as {DEAL.viewerRole}. This is a prototype
            surface: no button here sends a transaction.
          </p>
        </section>
      </div>
    </div>
  );
}
