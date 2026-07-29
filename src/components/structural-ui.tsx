import type { ReactNode } from "react";

export type GateGlyphKind = "identity" | "role" | "time" | "economic" | "protocol";
export type GateTone = "pass" | "wait" | "blocked" | "attention" | "complete";

export type GateView = {
  kind: GateGlyphKind;
  label: string;
  status: string;
  detail: string;
  tone: GateTone;
  resolution?: string;
};

type GateGlyphProps = {
  kind: GateGlyphKind;
};

export function GateGlyph({ kind }: GateGlyphProps) {
  if (kind === "identity") {
    return (
      <svg className="gate-glyph" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M6 3H3v5M18 3h3v5M6 21H3v-5M18 21h3v-5" />
        <circle cx="12" cy="9" r="3" />
        <path d="M7.5 18c.7-2.7 2.2-4 4.5-4s3.8 1.3 4.5 4" />
      </svg>
    );
  }

  if (kind === "role") {
    return (
      <svg className="gate-glyph" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="6" cy="6" r="2.5" />
        <circle cx="18" cy="6" r="2.5" />
        <circle cx="12" cy="18" r="2.5" />
        <path d="M8 7.5l3 7.5M16 7.5L13 15M8.5 6h7" />
      </svg>
    );
  }

  if (kind === "time") {
    return (
      <svg className="gate-glyph" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="8.5" />
        <path d="M12 6.5V12l4 2.5M4 12h2M18 12h2" />
      </svg>
    );
  }

  if (kind === "economic") {
    return (
      <svg className="gate-glyph" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 7h16v11H4zM7 4h10v3M8 12h8M12 9v6" />
        <circle cx="12" cy="12" r="2.5" />
      </svg>
    );
  }

  return (
    <svg className="gate-glyph" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M8 3h8l5 5v8l-5 5H8l-5-5V8z" />
      <path d="M8 12h8M12 8v8" />
      <circle cx="12" cy="12" r="6" />
    </svg>
  );
}

type GateVectorProps = {
  gates: readonly GateView[];
  title?: string;
  compact?: boolean;
};

export function GateVector({ gates, title = "Action readiness", compact = false }: GateVectorProps) {
  return (
    <section className={`gate-vector${compact ? " gate-vector-compact" : ""}`} aria-labelledby={`gate-title-${compact ? "compact" : "full"}`}>
      <h2 className="structural-heading" id={`gate-title-${compact ? "compact" : "full"}`}>
        {title}
        <small>{gates.filter((gate) => gate.tone === "pass" || gate.tone === "complete").length} / {gates.length} clear</small>
      </h2>
      <ol className="gate-list">
        {gates.map((gate, index) => (
          <li className="gate-item" data-gate-tone={gate.tone} key={gate.kind}>
            <span className="gate-index mono" aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
            <GateGlyph kind={gate.kind} />
            <div className="gate-copy">
              <div className="gate-label-line">
                <strong>{gate.label}</strong>
                <span>{gate.status}</span>
              </div>
              <p>{gate.detail}</p>
              {gate.resolution ? <small>{gate.resolution}</small> : null}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

type DomainLedgerProps = {
  domain: "receivable" | "protection";
  label: string;
  amount: string;
  asset: string;
  state: string;
  description: string;
  footer: string;
};

export function DomainLedger({
  domain,
  label,
  amount,
  asset,
  state,
  description,
  footer,
}: DomainLedgerProps) {
  return (
    <section className="domain-ledger" data-domain={domain} aria-label={`${label}: ${amount} ${asset}`}>
      <div className="domain-ledger-rail" aria-hidden="true" />
      <div className="domain-ledger-head">
        <span>{label}</span>
        <strong>{state}</strong>
      </div>
      <p className="domain-ledger-amount"><span>{amount}</span> <small>{asset}</small></p>
      <p className="domain-ledger-description">{description}</p>
      <p className="domain-ledger-footer mono">{footer}</p>
    </section>
  );
}

type MachineRailProps = {
  domain: "receivable" | "protection";
  label: string;
  states: readonly string[];
  current: string;
};

export function MachineRail({ domain, label, states, current }: MachineRailProps) {
  const activeIndex = states.findIndex(
    (state) => state.toLocaleLowerCase("en-US") === current.toLocaleLowerCase("en-US"),
  );

  return (
    <div className="machine-rail" data-domain={domain}>
      <div className="machine-rail-name">
        <span>{label}</span>
        <strong>{current}</strong>
      </div>
      <ol className="machine-states">
        {states.map((state, index) => (
          <li
            className={index === activeIndex ? "machine-state-current" : index < activeIndex ? "machine-state-past" : ""}
            key={state}
          >
            <span aria-hidden="true" />
            <small>{state}</small>
          </li>
        ))}
      </ol>
    </div>
  );
}

export type EvidenceFact = {
  label: string;
  value: string;
  source?: string;
  tone?: "observed" | "attested" | "derived" | "external";
};

type TransitionJointProps = {
  before: string;
  action: string;
  after: string;
  facts?: readonly EvidenceFact[];
  children?: ReactNode;
  compact?: boolean;
};

export function TransitionJoint({ before, action, after, facts = [], children, compact = false }: TransitionJointProps) {
  return (
    <section className={`transition-joint${compact ? " transition-joint-compact" : ""}`} aria-label={`Transition from ${before} to ${after}`}>
      <div className="transition-flow">
        <div className="transition-node">
          <span>Before</span>
          <strong>{before}</strong>
        </div>
        <div className="transition-connector" aria-hidden="true"><span /></div>
        <div className="transition-action-node">
          <span>Action</span>
          <strong>{action}</strong>
        </div>
        <div className="transition-connector" aria-hidden="true"><span /></div>
        <div className="transition-node">
          <span>After</span>
          <strong>{after}</strong>
        </div>
      </div>
      {facts.length > 0 ? (
        <dl className="evidence-facts">
          {facts.map((fact) => (
            <div data-evidence-tone={fact.tone ?? "observed"} key={`${fact.label}-${fact.value}`}>
              <dt>{fact.label}</dt>
              <dd>
                <span>{fact.value}</span>
                {fact.source ? <small>{fact.source}</small> : null}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
      {children}
    </section>
  );
}

type ObservationStampProps = {
  block: string;
  time: string;
  finality: string;
  freshness: string;
};

export function ObservationStamp({ block, time, finality, freshness }: ObservationStampProps) {
  return (
    <div className="observation-stamp" aria-label={`Observed at block ${block}, ${time}. ${finality}. ${freshness}.`}>
      <div><span>Observed block</span><strong>{block}</strong></div>
      <div><span>Timestamp</span><strong>{time}</strong></div>
      <div><span>Finality</span><strong>{finality}</strong></div>
      <div><span>Freshness</span><strong>{freshness}</strong></div>
    </div>
  );
}
