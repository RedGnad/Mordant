import type { CSSProperties, ReactNode } from "react";
import type { Metadata } from "next";
import Link from "next/link";

import {
  DomainLedger,
  FolioIdentity,
  GateVector,
  ObservationStamp,
  ReadinessVerdict,
  TransitionJoint,
  type EvidenceFact,
  type GateView,
} from "@/components/structural-ui";
import {
  dealShortId,
  formatDomainAmount,
  formatRole,
  formatState,
  gateToView,
  observationCopy,
} from "@/components/product-presenters";
import { EVIDENCE_BOUNDARIES, MORDANT_LEXICON, MORDANT_TERMS } from "@/lib/mordant/lexicon";
import { getSyntheticDeal, type DealScenarioId, type SyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";

import styles from "./design-system.module.css";

export const metadata: Metadata = {
  title: "Design system",
  description: "Internal implementation reference for Mordant product foundations and operational instruments.",
  robots: { index: false, follow: false },
};

type PaletteRole = {
  readonly token: string;
  readonly value: string;
  readonly use: string;
  readonly pattern?: "double" | "notched" | "solid" | "dashed" | "interrupted";
};

type PaletteGroup = {
  readonly title: string;
  readonly note: string;
  readonly roles: readonly PaletteRole[];
};

const PALETTE_GROUPS: readonly PaletteGroup[] = [
  {
    title: "Surfaces & structure",
    note: "Quiet documents, raised folios, and the high-contrast proof plane.",
    roles: [
      { token: "--background-primary", value: "#EEF2EF", use: "Primary document" },
      { token: "--background-operational", value: "#E1E8E4", use: "Operational grouping" },
      { token: "--surface-raised", value: "#FBFBF7", use: "Folio and ledger" },
      { token: "--surface-proof", value: "#241A2A", use: "Proof surface" },
      { token: "--text-primary", value: "#211923", use: "Primary text and hard rule" },
      { token: "--border-structural", value: "#8D858F", use: "Structural boundary" },
    ],
  },
  {
    title: "Economic domains",
    note: "Domain color is never reused for readiness, interaction, or evidence.",
    roles: [
      { token: "--domain-receivable", value: "#00696D", use: "Receivable money", pattern: "double" },
      { token: "--domain-protection", value: "#87506F", use: "Protection money", pattern: "notched" },
    ],
  },
  {
    title: "State",
    note: "The state family communicates urgency; language and geometry carry the same meaning.",
    roles: [
      { token: "--state-critical", value: "#AF2858", use: "Blocked or recovery", pattern: "solid" },
      { token: "--state-attention", value: "#945A30", use: "Pending or timed", pattern: "solid" },
      { token: "--state-positive", value: "#276858", use: "Available or complete", pattern: "solid" },
      { token: "--state-neutral", value: "#655D68", use: "Neutral status", pattern: "solid" },
    ],
  },
  {
    title: "Evidence",
    note: "Every evidence color is paired with a visible class label and a distinct line treatment.",
    roles: [
      { token: "--evidence-observed", value: "#1E3D46", use: "Observed", pattern: "solid" },
      { token: "--evidence-attested", value: "#675879", use: "Attested", pattern: "double" },
      { token: "--evidence-derived", value: "#4E6A61", use: "Derived", pattern: "dashed" },
      { token: "--evidence-external", value: "#686D72", use: "Not established", pattern: "interrupted" },
    ],
  },
] as const;

const IDENTITY_SCENARIOS: readonly DealScenarioId[] = [
  "healthy",
  "cure-expiring",
  "wrong-role",
  "recovery-required",
] as const;

const VERDICT_SCENARIOS: readonly DealScenarioId[] = [
  "cure-expiring",
  "healthy",
  "wrong-role",
  "credential-required",
  "funds-missing",
  "prerequisite-missing",
  "completed",
  "recovery-required",
] as const;

const EVIDENCE_BOUNDARY_KEYS = ["observed", "attested", "derived", "external"] as const;

const SYNTHETIC_RECORDS = [
  {
    folio: "MRD-S02487",
    responsibility: "Buyer funds receivable at maturity",
    due: "31 Jul · 14:00 UTC",
    verdict: "AVAILABLE_AT",
    tone: "pending",
  },
  {
    folio: "MRD-S02441",
    responsibility: "Facility B cures registered conflict",
    due: "29 Jul · 12:00 UTC",
    verdict: "WRONG_ROLE",
    tone: "critical",
  },
  {
    folio: "MRD-S02497",
    responsibility: "No intervention due",
    due: "—",
    verdict: "ALREADY_COMPLETED",
    tone: "positive",
  },
] as const;

const EVIDENCE_SPECIMEN: readonly EvidenceFact[] = [
  {
    label: "Transition event",
    value: "ConflictCured",
    source: "Synthetic fixture event stream",
    tone: "observed",
  },
  {
    label: "Buyer acceptance",
    value: "Synthetic acceptance reference present",
    source: "Fixture participant attestation",
    tone: "attested",
  },
  {
    label: "Reserve requirement",
    value: "248,000.00 aUSDC at the 10% demo parameter",
    source: "Mordant deterministic model",
    tone: "derived",
  },
  {
    label: "Legal priority",
    value: "Not established",
    source: "Outside the prototype evidence boundary",
    tone: "external",
  },
] as const;

const EXTREME_GATES: readonly GateView[] = [
  {
    kind: "identity",
    label: "Identity",
    status: "Clear",
    detail: "The viewer-specific synthetic identity check is satisfied.",
    tone: "pass",
  },
  {
    kind: "role",
    label: "Role",
    status: "Blocked",
    detail: "The action belongs to Facility B; the specimen viewer is a Holder.",
    resolution: "Wait for Facility B. Do not imply that the Holder can submit.",
    tone: "blocked",
  },
  {
    kind: "time",
    label: "Time",
    status: "Waiting",
    detail: "The synthetic execution window opens at the displayed timestamp.",
    resolution: "Re-evaluate when the time gate changes.",
    tone: "wait",
  },
  {
    kind: "economic",
    label: "Economic",
    status: "Unknown",
    detail: "Balance and allowance have not been observed for this stress specimen.",
    resolution: "Refresh the viewer-specific economic observation.",
    tone: "attention",
  },
  {
    kind: "protocol",
    label: "Protocol",
    status: "Not required",
    detail: "No protocol prerequisite applies to this action.",
    tone: "complete",
  },
] as const;

function SectionHeader({
  index,
  title,
  headingId,
  children,
}: {
  readonly index: string;
  readonly title: string;
  readonly headingId: string;
  readonly children: ReactNode;
}) {
  return (
    <header className={styles.sectionHeader}>
      <span className={styles.sectionIndex}>{index}</span>
      <div>
        <p className="micro-label">Implementation reference</p>
        <h2 id={headingId}>{title}</h2>
        <p>{children}</p>
      </div>
    </header>
  );
}

function InstrumentLabel({ children, code }: { readonly children: ReactNode; readonly code: string }) {
  return (
    <div className={styles.instrumentLabel}>
      <span>{children}</span>
      <code>{code}</code>
    </div>
  );
}

function DomainPair({ deal }: { readonly deal: SyntheticDeal }) {
  return (
    <div className={styles.domainPair}>
      <DomainLedger
        domain="receivable"
        label="Receivable domain"
        amount={formatDomainAmount(deal.economics.receivable.outstanding)}
        asset={deal.economics.receivable.outstanding.asset.symbol}
        state={formatState(deal.machines.receivable.state)}
        role="Invoice holder"
        location="Receivable vault ledger"
        source="Synthetic receivable fixture"
        nextEffect="Redemption pays the holder and burns only redeemed units"
        description="Buyer-accepted invoice value. This balance is not protection reserve money."
      />
      <DomainLedger
        domain="protection"
        label="Protection domain"
        amount={formatDomainAmount(deal.economics.protection.lockedReserve)}
        asset={deal.economics.protection.lockedReserve.asset.symbol}
        state={formatState(deal.machines.protection.state)}
        role="Protected facility"
        location="Segregated protection reserve"
        source="Synthetic protection fixture"
        nextEffect="Settlement pays protection without touching receivable units"
        description="Demo reserve governed by the protection machine. It is not receivable redemption money."
      />
    </div>
  );
}

function TransitionForDeal({ deal, compact = false }: { readonly deal: SyntheticDeal; readonly compact?: boolean }) {
  const action = deal.actions[0];
  const machine = action?.machine;
  const transition =
    machine === "receivable"
      ? action.consequence.receivableTransition
      : machine === "protection"
        ? action.consequence.protectionTransition
        : undefined;

  return (
    <TransitionJoint
      before={transition ? formatState(transition.from) : formatState(deal.machines.protection.state)}
      action={action?.contractAction ?? "refreshSyntheticObservation()"}
      after={transition ? formatState(transition.to) : "Reconciled state"}
      facts={EVIDENCE_SPECIMEN}
      compact={compact}
    />
  );
}

function DensityFrame({
  density,
  scenario,
  title,
  note,
}: {
  readonly density: "compact" | "default" | "spacious";
  readonly scenario: DealScenarioId;
  readonly title: string;
  readonly note: string;
}) {
  const deal = getSyntheticDeal(scenario);
  const action = deal.actions[0];
  const compact = density === "compact";
  const densityClass =
    density === "compact"
      ? styles.compactFrame
      : density === "spacious"
        ? styles.spaciousFrame
        : styles.defaultFrame;
  const observation = observationCopy(deal.observation);

  if (!action) return null;

  return (
    <article className={`${styles.densityFrame} ${densityClass}`} data-density={density}>
      <header className={styles.densityHeader}>
        <div>
          <p className="micro-label">{density} density</p>
          <h3>{title}</h3>
        </div>
        <p>{note}</p>
      </header>

      <div className={styles.identityBar}>
        <FolioIdentity
          folio={dealShortId(deal)}
          root={deal.machines.receivable.immutableInvoiceRoot}
          compact={compact}
        />
        <span>{formatRole(deal.viewer.role)} view</span>
      </div>

      <div className={styles.verdictAndGates}>
        <div>
          <InstrumentLabel code={`ReadinessVerdict · ${deriveReadinessVerdict(deal, action).code}`}>
            Decision instrument
          </InstrumentLabel>
          <ReadinessVerdict verdict={deriveReadinessVerdict(deal, action)} compact={compact} />
        </div>
        <div>
          <InstrumentLabel code="GateVector · ordered 5-tuple">Readiness inputs</InstrumentLabel>
          <GateVector gates={action.gates.map(gateToView)} compact={compact} title={`${title} gates`} />
        </div>
      </div>

      <div>
        <InstrumentLabel code="DomainLedger · distinct accounting boundary">Economic instruments</InstrumentLabel>
        <DomainPair deal={deal} />
      </div>

      <div>
        <InstrumentLabel code="TransitionJoint · evidence classifications">Proof instrument</InstrumentLabel>
        <TransitionForDeal deal={deal} compact={compact} />
      </div>

      {compact ? null : (
        <ObservationStamp
          block={observation.block}
          time={observation.time}
          finality={observation.finality}
          freshness={observation.freshness}
          source="Synthetic fixture"
        />
      )}
    </article>
  );
}

export default function DesignSystemPage() {
  const identityDeals = IDENTITY_SCENARIOS.map(getSyntheticDeal);
  const verdictCases = VERDICT_SCENARIOS.map((scenario) => {
    const deal = getSyntheticDeal(scenario);
    const action = deal.actions[0];
    return action ? { deal, verdict: deriveReadinessVerdict(deal, action) } : null;
  }).filter((item): item is NonNullable<typeof item> => item !== null);

  return (
    <div className={styles.page}>
      <a className={styles.skipLink} href="#catalog-main">
        Skip to component catalog
      </a>

      <header className={styles.catalogChrome}>
        <Link className={styles.brand} href="/" aria-label="Back to Mordant workspace">
          <span>Mordant</span>
          <small>System index</small>
        </Link>
        <div className={styles.chromeDescriptor}>Product foundations / operational instruments</div>
        <div className={styles.chromeMeta}>
          <span>Internal route</span>
          <span>M19 / M30</span>
        </div>
      </header>

      <div className={styles.catalogLayout}>
        <aside className={styles.catalogNav} aria-label="Design system sections">
          <div>
            <p className="micro-label">Index 01</p>
            <strong>Implementation catalog</strong>
            <p>Semantic tokens and product instruments in their real rendering context.</p>
          </div>
          <nav>
            <a href="#foundations"><span>01</span> Foundations</a>
            <a href="#language"><span>02</span> Official language</a>
            <a href="#identity"><span>03</span> Identity grammar</a>
            <a href="#density"><span>04</span> Density matrix</a>
            <a href="#extremes"><span>05</span> Extreme states</a>
            <a href="#operational"><span>06</span> Operational states</a>
            <a href="#rules"><span>07</span> Product rules</a>
          </nav>
          <p className={styles.syntheticNotice}>
            Synthetic design fixtures only. No real funds, custody, legal assignment, insurance, or production-safety claim.
          </p>
        </aside>

        <main className={styles.catalogMain} id="catalog-main" tabIndex={-1}>
          <section className={styles.hero} aria-labelledby="catalog-title">
            <div>
              <p className="micro-label">Mordant product language · release candidate</p>
              <h1 id="catalog-title">A control surface with a document memory.</h1>
              <p className={styles.heroCopy}>
                The system makes responsibility, readiness, money domains, and evidence legible before it asks for an action.
                This page is the production implementation reference—not a brand moodboard.
              </p>
            </div>
            <dl className={styles.heroRegister}>
              <div><dt>Type families</dt><dd>03</dd></div>
              <div><dt>Readiness gates</dt><dd>05</dd></div>
              <div><dt>Money domains</dt><dd>02</dd></div>
              <div><dt>Evidence classes</dt><dd>04</dd></div>
              <div><dt>Official terms</dt><dd>12</dd></div>
              <div><dt>Operational states</dt><dd>09</dd></div>
            </dl>
          </section>

          <section className={styles.catalogSection} id="foundations" aria-labelledby="foundations-title">
            <SectionHeader index="01" title="Foundations" headingId="foundations-title">
              Typography is assigned by function. Color is assigned by semantic role. Neither is decorative shorthand.
            </SectionHeader>

            <div className={styles.typeRegistry} aria-label="Typography roles">
              <article className={styles.identityType}>
                <div><span>Identity</span><code>--type-identity</code></div>
                <p>Programmable recourse</p>
                <small>Newsreader · folios, conclusions, monetary emphasis</small>
              </article>
              <article className={styles.interfaceType}>
                <div><span>Interface</span><code>--type-interface</code></div>
                <p>Responsibility before transaction</p>
                <small>IBM Plex Sans · navigation, guidance, explanatory copy</small>
              </article>
              <article className={styles.proofType}>
                <div><span>Proof</span><code>--type-proof</code></div>
                <p>MRD-S02487 · block 1402</p>
                <small>IBM Plex Mono · roots, states, times, evidence, machine facts</small>
              </article>
            </div>

            <div className={styles.paletteRegistry}>
              {PALETTE_GROUPS.map((group) => (
                <article className={styles.paletteGroup} key={group.title}>
                  <header>
                    <h3>{group.title}</h3>
                    <p>{group.note}</p>
                  </header>
                  <ul>
                    {group.roles.map((role) => (
                      <li key={role.token}>
                        <span
                          className={styles.swatch}
                          data-pattern={role.pattern}
                          style={{ "--swatch-color": `var(${role.token})` } as CSSProperties}
                          aria-hidden="true"
                        />
                        <span><code>{role.token}</code><small>{role.use}</small></span>
                        <strong>{role.value}</strong>
                      </li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          </section>

          <section className={styles.catalogSection} id="language" aria-labelledby="language-title">
            <SectionHeader index="02" title="Official language" headingId="language-title">
              One canonical term can change register for a participant, an operator, technical evidence, or an error—without changing meaning.
            </SectionHeader>

            <p className={styles.languageNotice} id="language-note">
              These definitions describe synthetic software states and demo accounting. They do not establish legal character,
              priority, insurance, custody, or production eligibility.
            </p>

            <div className={styles.lexiconTableFrame} tabIndex={0} role="region" aria-label="Scrollable official language table">
              <table className={styles.lexiconTable} aria-describedby="language-note">
                <caption className="visually-hidden">
                  Mordant canonical terms with participant, operator, technical, and error usage
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Term</th>
                    <th scope="col">Participant</th>
                    <th scope="col">Operator</th>
                    <th scope="col">Technical</th>
                    <th scope="col">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {MORDANT_TERMS.map((term) => {
                    const entry = MORDANT_LEXICON[term];
                    return (
                      <tr key={term}>
                        <th scope="row"><strong>{entry.label}</strong><code>{term}</code></th>
                        <td data-register="Participant">{entry.participant}</td>
                        <td data-register="Operator">{entry.operator}</td>
                        <td data-register="Technical">{entry.technical}</td>
                        <td data-register="Error">{entry.error}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className={styles.evidenceBoundaryRegistry} aria-labelledby="evidence-language-title">
              <header>
                <p className="micro-label">Canonical evidence classes</p>
                <h3 id="evidence-language-title">Say what the record can establish.</h3>
              </header>
              <dl>
                {EVIDENCE_BOUNDARY_KEYS.map((boundary) => {
                  const definition = EVIDENCE_BOUNDARIES[boundary];
                  return (
                    <div data-boundary={boundary} key={boundary}>
                      <dt>{definition.label}</dt>
                      <dd>{definition.meaning}</dd>
                    </div>
                  );
                })}
              </dl>
            </div>
          </section>

          <section className={styles.catalogSection} id="identity" aria-labelledby="identity-title">
            <SectionHeader index="03" title="Identity grammar" headingId="identity-title">
              Folios are stable human handles. Rootlines are deterministic visual indexes derived from immutable synthetic invoice roots.
            </SectionHeader>

            <div className={styles.identityRegistry}>
              {identityDeals.map((deal) => (
                <article key={deal.id}>
                  <p className="micro-label">{formatState(deal.scenario)}</p>
                  <FolioIdentity folio={dealShortId(deal)} root={deal.machines.receivable.immutableInvoiceRoot} />
                  <code>{deal.machines.receivable.immutableInvoiceRoot}</code>
                </article>
              ))}
            </div>

            <aside className={styles.boundaryNote} aria-label="Identity boundary">
              <span aria-hidden="true">!</span>
              <p>
                Rootlines accelerate matching and navigation. They do not establish invoice truth, authenticity, legal priority,
                duplicate-financing detection, or cryptographic proof.
              </p>
            </aside>
          </section>

          <section className={styles.catalogSection} id="density" aria-labelledby="density-title">
            <SectionHeader index="04" title="Density matrix" headingId="density-title">
              Density follows the task: scan many records, decide one action, or investigate one exception. Meaning stays invariant.
            </SectionHeader>

            <div className={styles.densityStack}>
              <DensityFrame
                density="compact"
                scenario="wrong-role"
                title="Queue scan"
                note="Fast comparison. Causes remain visible while secondary detail collapses."
              />
              <DensityFrame
                density="default"
                scenario="healthy"
                title="Action decision"
                note="The working density for a single responsibility, consequence, and next step."
              />
              <DensityFrame
                density="spacious"
                scenario="recovery-required"
                title="Exception investigation"
                note="More air around evidence and recovery facts; no additional claim of certainty."
              />
            </div>
          </section>

          <section className={styles.catalogSection} id="extremes" aria-labelledby="extremes-title">
            <SectionHeader index="05" title="Extreme states" headingId="extremes-title">
              Every deterministic verdict must hold at the edge: wrong role, missing funds, incomplete prerequisites, completed work, and recovery.
            </SectionHeader>

            <div className={styles.verdictRegistry}>
              {verdictCases.map(({ deal, verdict }) => (
                <article key={verdict.code} data-verdict-code={verdict.code}>
                  <InstrumentLabel code={verdict.code}>{formatState(deal.scenario)}</InstrumentLabel>
                  <ReadinessVerdict verdict={verdict} compact />
                </article>
              ))}
            </div>

            <div className={styles.extremeGrid}>
              <article>
                <InstrumentLabel code="GateVector · mixed status stress">Gate grammar</InstrumentLabel>
                <GateVector gates={EXTREME_GATES} title="Mixed-state gate specimen" />
              </article>
              <article className={styles.proofPlane}>
                <InstrumentLabel code="EvidenceFact · explicit provenance">Evidence boundary</InstrumentLabel>
                <TransitionJoint
                  before="Cure period"
                  action="cureSyntheticConflict()"
                  after="Active"
                  facts={EVIDENCE_SPECIMEN}
                />
              </article>
            </div>
          </section>

          <section className={styles.catalogSection} id="operational" aria-labelledby="operational-title">
            <SectionHeader index="06" title="Operational states" headingId="operational-title">
              Product quality is decided between the happy states: deadlines, bounded waits, incomplete data, confirmation, and deliberate recovery.
            </SectionHeader>

            <div className={styles.operationalGrid}>
              <article className={`${styles.stateSpecimen} ${styles.stateWide}`} data-state="attention" aria-labelledby="deadline-specimen-title">
                <InstrumentLabel code="Responsibility · explicit deadline">Deadline</InstrumentLabel>
                <div className={styles.deadlineSpecimen}>
                  <div>
                    <span className="status-token" data-tone="pending">Due soon</span>
                    <h3 id="deadline-specimen-title">Buyer funds receivable at maturity</h3>
                    <p>The receivable remains outstanding if the responsibility is missed. Protection money is unchanged.</p>
                  </div>
                  <div className={styles.deadlineClock}>
                    <span>Decision deadline</span>
                    <time dateTime="2026-07-31T14:00:00.000Z">31 Jul 2026<br />14:00 UTC</time>
                    <small>Synthetic fixture clock · re-evaluate at the named time</small>
                  </div>
                </div>
              </article>

              <article className={`${styles.stateSpecimen} ${styles.stateWide}`} aria-labelledby="controls-specimen-title">
                <InstrumentLabel code="Native controls · visible labels · 44px targets">Form controls</InstrumentLabel>
                <form className={styles.controlSpecimen} aria-describedby="controls-specimen-note">
                  <div className={styles.controlIntro}>
                    <h3 id="controls-specimen-title">Prepare a synthetic simulation</h3>
                    <p id="controls-specimen-note">Inputs demonstrate control states only. This catalog never submits a transaction.</p>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label htmlFor="catalog-amount">Protection amount</label>
                    <div className={styles.inputWithSuffix}>
                      <input id="catalog-amount" name="catalog-amount" inputMode="decimal" defaultValue="248000.00" aria-describedby="catalog-amount-note" />
                      <span>aUSDC</span>
                    </div>
                    <small id="catalog-amount-note">Synthetic test asset · protection domain</small>
                  </div>
                  <div className={styles.fieldGroup}>
                    <label htmlFor="catalog-role">Submitting role</label>
                    <select id="catalog-role" name="catalog-role" defaultValue="originator">
                      <option value="originator">Originator</option>
                      <option value="facility-b">Facility B</option>
                      <option value="holder">Holder</option>
                    </select>
                    <small>Role is derived from the connected synthetic participant in product surfaces.</small>
                  </div>
                  <label className={styles.checkboxControl}>
                    <input type="checkbox" defaultChecked />
                    <span>I reviewed the domain-specific consequence.</span>
                  </label>
                  <div className={styles.controlActions}>
                    <button className="secondary-action" type="button">Review consequence</button>
                    <button className="primary-action" type="button" disabled>Simulation required</button>
                  </div>
                </form>
              </article>

              <article className={`${styles.stateSpecimen} ${styles.stateWide}`} aria-labelledby="table-specimen-title">
                <InstrumentLabel code="Operational table · row identity preserved">Table</InstrumentLabel>
                <div className={styles.operationalTableFrame} tabIndex={0} role="region" aria-label="Scrollable synthetic responsibility records">
                  <table className={styles.operationalTable}>
                    <caption id="table-specimen-title">Synthetic responsibility queue</caption>
                    <thead>
                      <tr><th scope="col">Folio</th><th scope="col">Responsibility</th><th scope="col">Due</th><th scope="col">Verdict</th></tr>
                    </thead>
                    <tbody>
                      {SYNTHETIC_RECORDS.map((record) => (
                        <tr key={record.folio}>
                          <th scope="row"><code>{record.folio}</code></th>
                          <td>{record.responsibility}</td>
                          <td>{record.due}</td>
                          <td><span className="status-token" data-tone={record.tone}>{record.verdict.replaceAll("_", " ")}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </article>

              <article className={styles.stateSpecimen} aria-labelledby="empty-specimen-title">
                <InstrumentLabel code="Zero records · filter recovery">Empty</InstrumentLabel>
                <div className={styles.emptySpecimen}>
                  <span className={styles.registrationMark} aria-hidden="true" />
                  <h3 id="empty-specimen-title">No responsibilities match this filter</h3>
                  <p>The queue is unchanged. Clear the filter or return to all synthetic records.</p>
                  <button className="secondary-action" type="button">Clear filter</button>
                </div>
              </article>

              <article className={styles.stateSpecimen} aria-labelledby="loading-specimen-title">
                <InstrumentLabel code="Finite wait · explicit stop condition">Bounded loading</InstrumentLabel>
                <div className={styles.loadingSpecimen}>
                  <span className="status-token" data-tone="pending">Static specimen</span>
                  <h3 id="loading-specimen-title">Awaiting synthetic receipt</h3>
                  <p>No request is running in this catalog. Product waits expose the step, elapsed time, and a hard stop.</p>
                  <progress value="2" max="3">Step 2 of 3</progress>
                  <dl>
                    <div><dt>Step</dt><dd>2 of 3</dd></div>
                    <div><dt>Elapsed</dt><dd>18 seconds</dd></div>
                    <div><dt>Stop at</dt><dd>45 seconds</dd></div>
                  </dl>
                </div>
              </article>

              <article className={styles.stateSpecimen} data-state="critical" aria-labelledby="rpc-specimen-title">
                <InstrumentLabel code="Observation failure · last safe state">Network / RPC error</InstrumentLabel>
                <div className={styles.errorSpecimen}>
                  <span className="status-token" data-tone="critical">Observation unavailable</span>
                  <h3 id="rpc-specimen-title">Synthetic RPC did not return a trustworthy state</h3>
                  <p>This is an error specimen; no live request was made. Do not infer readiness, finality, redemption, or protection funding.</p>
                  <dl>
                    <div><dt>Last safe block</dt><dd>1402</dd></div>
                    <div><dt>Source</dt><dd>Synthetic fixture RPC</dd></div>
                    <div><dt>Next step</dt><dd>Retry observation, then reassess</dd></div>
                  </dl>
                </div>
              </article>

              <article className={styles.stateSpecimen} aria-labelledby="overflow-specimen-title">
                <InstrumentLabel code="overflow-wrap:anywhere · copy preserves value">Long-address overflow</InstrumentLabel>
                <div className={styles.overflowSpecimen}>
                  <h3 id="overflow-specimen-title">Immutable identifiers remain inspectable</h3>
                  <p>Visible truncation may aid scanning, but the full synthetic value remains available to select and copy.</p>
                  <div>
                    <span>Vault address</span>
                    <code>0x7f3B8A41D2F98E6c04Abe195Bb4633274f996dF281cAD9E72A04B2f49C8E7A61</code>
                  </div>
                  <div>
                    <span>Invoice root</span>
                    <code>synroot:mordant-demo-invoice-recovery-required-with-an-intentionally-long-inspection-suffix</code>
                  </div>
                </div>
              </article>

              <article className={`${styles.stateSpecimen} ${styles.stateWide}`} aria-labelledby="confirmation-specimen-title">
                <InstrumentLabel code="Review → confirm → readback / explicit recovery">Confirmation & recovery</InstrumentLabel>
                <div className={styles.confirmationGrid}>
                  <section aria-labelledby="confirmation-specimen-title">
                    <p className="micro-label">Before submission</p>
                    <h3 id="confirmation-specimen-title">Confirm the exact consequence</h3>
                    <dl>
                      <div><dt>Action</dt><dd>fundSyntheticProtection()</dd></div>
                      <div><dt>Protection money</dt><dd>248,000.00 aUSDC enters reserve</dd></div>
                      <div><dt>Receivable money</dt><dd>No movement</dd></div>
                      <div><dt>Invoice units</dt><dd>No burn or transfer</dd></div>
                    </dl>
                    <p className={styles.noSubmission}>Catalog specimen · simulation absent · nothing submitted</p>
                  </section>
                  <section className={styles.recoveryPanel} aria-labelledby="recovery-specimen-title">
                    <p className="micro-label">When readback is inconsistent</p>
                    <h3 id="recovery-specimen-title">Stop at the last safe state</h3>
                    <ol>
                      <li>Preserve the submitted reference and last finalized observation.</li>
                      <li>Do not retry automatically or imply settlement.</li>
                      <li>Open the selected-record runbook for Protocol Operations.</li>
                    </ol>
                    <span className="status-token" data-tone="critical">Recovery required</span>
                  </section>
                </div>
              </article>

              <article className={`${styles.stateSpecimen} ${styles.stateWide}`} aria-labelledby="motion-specimen-title">
                <InstrumentLabel code="prefers-reduced-motion · semantic parity">Motion off</InstrumentLabel>
                <div className={styles.motionSpecimen}>
                  <div className={styles.motionTrack} aria-hidden="true"><i /><i /><i /></div>
                  <div>
                    <span className="status-token" data-tone="neutral">Motion optional</span>
                    <h3 id="motion-specimen-title">Meaning survives when movement is removed</h3>
                    <p>State change is conveyed by position, copy, border, and programmatic status. No spinner or continuous animation carries unique information.</p>
                  </div>
                  <dl>
                    <div><dt>Transition</dt><dd>None required</dd></div>
                    <div><dt>Progress</dt><dd>Named step and bounded time</dd></div>
                    <div><dt>Focus</dt><dd>Moves only after an explicit user action</dd></div>
                  </dl>
                </div>
              </article>
            </div>
          </section>

          <section className={styles.catalogSection} id="rules" aria-labelledby="rules-title">
            <SectionHeader index="07" title="Product rules" headingId="rules-title">
              The visual system is only valid when it preserves Mordant’s accounting and evidence boundaries.
            </SectionHeader>

            <ol className={styles.ruleRegistry}>
              <li><span>01</span><p><strong>One action, one verdict.</strong> A screen never asks the user to interpret a score such as “four of five gates”.</p></li>
              <li><span>02</span><p><strong>Responsibility is explicit.</strong> Actor, deadline, unlock condition, and consequence precede the transaction control.</p></li>
              <li><span>03</span><p><strong>Money domains stay separate.</strong> Protection settlement never implies receivable redemption or unit transfer.</p></li>
              <li><span>04</span><p><strong>Evidence carries provenance.</strong> Observed, attested, derived, and not established are visible words—not color alone.</p></li>
              <li><span>05</span><p><strong>Synthetic means synthetic.</strong> Fixture observations and test assets are never presented as production truth or live custody.</p></li>
            </ol>
          </section>

          <footer className={styles.catalogFooter}>
            <span>Mordant system index 01</span>
            <span>Internal implementation route</span>
            <Link href="/">Return to workspace</Link>
          </footer>
        </main>
      </div>
    </div>
  );
}
