import { useId, type CSSProperties, type ReactNode } from "react";

import { ROOTLINE_USAGE_NOTICE, rootlineSegments } from "@/lib/mordant/identity";
import type { ReadinessVerdict as ReadinessVerdictModel } from "@/lib/mordant/readiness";

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
  tone?: GateTone;
};

export function GateGlyph({ kind, tone = "pass" }: GateGlyphProps) {
  return (
    <svg className="gate-glyph" data-kind={kind} data-tone={tone} viewBox="0 0 16 16" aria-hidden="true">
      {kind === "identity" ? <path d="M5 2H2v3M11 2h3v3M5 14H2v-3M11 14h3v-3M5 8h6" /> : null}
      {kind === "role" ? <path d="M2 2h6v6H2zM8 8h6v6H8zM8 5h3v3" /> : null}
      {kind === "time" ? <path d="M8 2a6 6 0 1 1-4.3 1.8M8 4v4l3 2" /> : null}
      {kind === "economic" ? <path d="M2 2h12v12H2zM5 5h6v6H5z" /> : null}
      {kind === "protocol" ? <path d="M2 8h12M8 2v12M4 4l8 8M12 4l-8 8" /> : null}
      {tone === "blocked" || tone === "attention" ? <path className="gate-glyph-state" d="M12 2h2v2" /> : null}
      {tone === "complete" ? <path className="gate-glyph-state" d="m4 8 2.5 2.5L12 5" /> : null}
    </svg>
  );
}

type GateVectorProps = {
  gates: readonly GateView[];
  title?: string;
  compact?: boolean;
};

export function GateVector({ gates, title = "Readiness inspection", compact = false }: GateVectorProps) {
  const headingId = `gate-title-${compact ? "compact" : "full"}-${title.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}`;

  return (
    <section className={`gate-vector${compact ? " gate-vector-compact" : ""}`} aria-labelledby={headingId}>
      <h2 className="structural-heading" id={headingId}>
        {title}
        <small>Five independent checks</small>
      </h2>
      <ol className="gate-list">
        {gates.map((gate) => (
          <li className="gate-item" data-gate-tone={gate.tone} key={gate.kind}>
            <GateGlyph kind={gate.kind} tone={gate.tone} />
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

type ReadinessVerdictProps = {
  verdict: ReadinessVerdictModel;
  recheckLabel?: string;
  compact?: boolean;
};

const VERDICT_LABELS: Readonly<Record<ReadinessVerdictModel["code"], string>> = {
  AVAILABLE_NOW: "Available now",
  AVAILABLE_AT: "Available at",
  WRONG_ROLE: "Wrong role",
  CREDENTIAL_REQUIRED: "Credential required",
  FUNDS_REQUIRED: "Funds required",
  PREVIOUS_ACTION_REQUIRED: "Previous action required",
  ALREADY_COMPLETED: "Already completed",
  RECOVERY_REQUIRED: "Recovery required",
};

export function ReadinessVerdict({ verdict, recheckLabel, compact = false }: ReadinessVerdictProps) {
  const headingId = useId();
  const label = verdict.code === "AVAILABLE_AT" && recheckLabel
    ? `${VERDICT_LABELS[verdict.code]} ${recheckLabel}`
    : VERDICT_LABELS[verdict.code];
  const tone = verdict.code === "AVAILABLE_NOW" || verdict.code === "ALREADY_COMPLETED"
    ? "positive"
    : verdict.code === "AVAILABLE_AT" || verdict.code === "PREVIOUS_ACTION_REQUIRED"
      ? "attention"
      : "critical";

  return (
    <section
      className={`readiness-verdict${compact ? " readiness-verdict-compact" : ""}`}
      data-readiness-verdict={verdict.code}
      data-tone={tone}
      aria-labelledby={headingId}
    >
      <p className="micro-label">Unique readiness verdict</p>
      <h2 id={headingId}>{label}</h2>
      <p className="readiness-cause">{verdict.cause}</p>
      <dl className="readiness-facts">
        <div><dt>Blocking gate</dt><dd>{verdict.blockingGate?.label ?? "None"}</dd></div>
        <div><dt>Responsible</dt><dd>{verdict.responsible}</dd></div>
        <div><dt>Unlock</dt><dd>{verdict.unlock}</dd></div>
        <div><dt>Re-evaluate</dt><dd>{recheckLabel ?? "After the next state observation"}</dd></div>
        <div><dt>Economic consequence</dt><dd>{verdict.economicConsequence}</dd></div>
        <div><dt>Next action</dt><dd>{verdict.nextAction}</dd></div>
      </dl>
    </section>
  );
}

type RootlineProps = {
  root: string;
  compact?: boolean;
  showLabel?: boolean;
};

export function Rootline({ root, compact = false, showLabel = true }: RootlineProps) {
  const segments = rootlineSegments(root);

  return (
    <div className={`root-index${compact ? " root-index-compact" : ""}`} data-rootline={root}>
      <span className="rootline" aria-hidden="true">
        {segments.map((segment, index) => (
          <i
            key={`${segment.width}-${segment.spacing}-${index}`}
            style={{
              "--root-width": `${segment.width}px`,
              "--root-gap": `${segment.spacing}px`,
            } as CSSProperties}
          />
        ))}
      </span>
      {showLabel ? <small>{ROOTLINE_USAGE_NOTICE}</small> : null}
    </div>
  );
}

type FolioIdentityProps = {
  folio: string;
  root: string;
  compact?: boolean;
};

export function FolioIdentity({ folio, root, compact = false }: FolioIdentityProps) {
  return (
    <div className={`folio-identity${compact ? " folio-identity-compact" : ""}`}>
      <strong>{folio}</strong>
      <Rootline root={root} compact={compact} showLabel={!compact} />
    </div>
  );
}

type DomainLedgerProps = {
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

export function DomainLedger({
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
}: DomainLedgerProps) {
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
      <dl className="domain-ledger-context">
        <div><dt>Role</dt><dd>{role}</dd></div>
        <div><dt>Location</dt><dd>{location}</dd></div>
        <div><dt>Source</dt><dd>{source}</dd></div>
        <div><dt>Next effect</dt><dd>{nextEffect}</dd></div>
      </dl>
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
  const stateIsMapped = activeIndex >= 0;
  const displayedStates = stateIsMapped ? states : [current];

  return (
    <div className="machine-rail" data-domain={domain} data-state-mapped={stateIsMapped ? "true" : "false"}>
      <div className="machine-rail-name">
        <span>{label}</span>
        <strong>{current}</strong>
      </div>
      <ol className="machine-states" aria-label={`${label} lifecycle`}>
        {displayedStates.map((state, index) => {
          const isCurrent = stateIsMapped ? index === activeIndex : true;
          const isPast = stateIsMapped && index < activeIndex;
          const temporal = stateIsMapped
            ? isCurrent
              ? "Current"
              : isPast
                ? "Past"
                : "Upcoming"
            : "Current observed state; lifecycle position is not mapped";
          return (
            <li
              className={isCurrent ? "machine-state-current" : isPast ? "machine-state-past" : ""}
              aria-current={isCurrent ? "step" : undefined}
              key={state}
            >
              <span aria-hidden="true" />
              <small>{state}</small>
              <span className="visually-hidden">{temporal}</span>
            </li>
          );
        })}
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

const EVIDENCE_LABELS: Readonly<Record<NonNullable<EvidenceFact["tone"]>, string>> = {
  observed: "Observed",
  attested: "Attested",
  derived: "Derived",
  external: "Not established",
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
          {facts.map((fact) => {
            const tone = fact.tone ?? "observed";
            return (
              <div data-evidence-class={tone} key={`${fact.label}-${fact.value}`}>
                <dt><span>{EVIDENCE_LABELS[tone]}</span><small>{fact.label}</small></dt>
                <dd>
                  <span>{fact.value}</span>
                  {fact.source ? <small>{fact.source}</small> : null}
                </dd>
              </div>
            );
          })}
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
  source?: string;
};

export function ObservationStamp({ block, time, finality, freshness, source = "Synthetic fixture" }: ObservationStampProps) {
  return (
    <div className="observation-stamp" aria-label={`Observed from ${source} at block ${block}, ${time}. ${finality}. ${freshness}.`}>
      <div><span>Source</span><strong>{source}</strong></div>
      <div><span>Observed block</span><strong>{block}</strong></div>
      <div><span>Timestamp</span><strong>{time}</strong></div>
      <div><span>Finality</span><strong>{finality}</strong></div>
      <div><span>Freshness</span><strong>{freshness}</strong></div>
    </div>
  );
}
