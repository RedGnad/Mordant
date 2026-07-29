import type { Metadata } from "next";
import { Archivo } from "next/font/google";
import Link from "next/link";

import {
  formatDomainAmount,
  proRateDomainAmount,
} from "@/components/product-presenters";
import { getSyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";

import styles from "./m18nws-deal-room.module.css";

const archivo = Archivo({
  variable: "--font-m18nws",
  subsets: ["latin"],
  weight: "variable",
  axes: ["wdth"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "M-18NWS Deal Room benchmark",
  description: "Isolated New Wave Swiss design benchmark for a participant decision.",
  robots: {
    index: false,
    follow: false,
    nocache: true,
  },
};

function timeParts(timestamp: string) {
  const value = new Date(timestamp);
  if (Number.isNaN(value.getTime())) throw new Error("The M-18NWS benchmark requires a valid deadline.");

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

function humanize(value: string) {
  const words = value.replaceAll("_", " ");
  return `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

export default function M18NwsDealRoomBenchmark() {
  const deal = getSyntheticDeal("wrong-role");
  const action = deal.actions[0];
  const position = deal.viewer.position;
  const dueAt = deal.nextResponsibility.dueAt;
  const missedDeadlineConsequence = deal.nextResponsibility.consequenceIfMissed;

  if (!action) throw new Error("The M-18NWS wrong-role benchmark requires a modeled action.");
  if (!position) throw new Error("The M-18NWS wrong-role benchmark requires a participant position.");
  if (!dueAt) throw new Error("The M-18NWS wrong-role benchmark requires a source deadline.");
  if (!missedDeadlineConsequence) {
    throw new Error("The M-18NWS wrong-role benchmark requires a modeled missed-deadline consequence.");
  }

  const verdict = deriveReadinessVerdict(deal, action);
  const deadline = timeParts(dueAt);
  const responsible = deal.nextResponsibility.actorLabel.replace(" (synthetic)", "");
  const receivableExposure = proRateDomainAmount(deal.economics.receivable.outstanding, position);
  const protectionExposure = proRateDomainAmount(deal.economics.protection.lockedReserve, position);
  const protectionAfter = action.consequence.protectionTransition?.to;

  return (
    <main
      className={`${archivo.variable} ${styles.page}`}
      data-testid="m18nws-benchmark"
      lang="en"
    >
      <header className={styles.labHeader}>
        <Link className={styles.brand} href="/" aria-label="Mordant — back to portfolio">
          Mordant
        </Link>
        <p className={styles.benchmarkName}>
          <strong>M-18NWS</strong>
          <span>Design benchmark</span>
        </p>
        <p className={styles.fixture}>Synthetic scenario</p>
      </header>

      <section className={styles.firstView} data-testid="m18nws-first-view">
        <section
          className={styles.decisionArea}
          data-testid="m18nws-decision"
          aria-labelledby="m18nws-title"
        >
          <div
            className={styles.position}
            data-testid="m18nws-level-one"
            data-readiness-verdict={verdict.code}
          >
            <p className={styles.eyebrow}>Your position</p>
            <h1 id="m18nws-title">Your receivable has not moved.</h1>
            <p className={styles.noAction}>You have no action.</p>
          </div>

          <div className={styles.deadline} data-testid="m18nws-deadline">
            <p>
              <strong data-testid="m18nws-responsible">{responsible} </strong>
              <span>must cure before </span>
            </p>
            <time dateTime={dueAt} aria-label={`${deadline.clock} UTC on ${deadline.date}`}>
              <span>{deadline.clock}</span>
              <small> UTC.</small>
            </time>
          </div>
        </section>

        <section className={styles.domains} aria-label="Your separate economic positions">
          <article
            className={styles.receivable}
            data-testid="m18nws-domain-receivable"
            data-domain-amount={receivableExposure.minorUnits}
          >
            <h2>Your receivable</h2>
            <p className={styles.amount}>
              {formatDomainAmount(receivableExposure, 0)} <small>{receivableExposure.asset.symbol}</small>
            </p>
            <strong>Still held</strong>
          </article>

          <article
            className={styles.protection}
            data-testid="m18nws-domain-protection"
            data-domain-amount={protectionExposure.minorUnits}
          >
            <span className={styles.protectionBand} aria-hidden="true" />
            <div>
              <h2>Protection concerned</h2>
              <p className={styles.amount}>
                {formatDomainAmount(protectionExposure, 0)} <small>{protectionExposure.asset.symbol}</small>
              </p>
              <strong>Not paid</strong>
            </div>
          </article>
        </section>

        <section
          className={styles.consequence}
          aria-labelledby="m18nws-consequence-title"
          data-testid="m18nws-deadline-consequence"
          data-consequence-source="next-responsibility"
        >
          <p id="m18nws-consequence-title">If the deadline is missed</p>
          <strong>Protection may become claimable.</strong>
          <span>Your receivable remains separate.</span>
        </section>

        <Link className={styles.primaryAction} href="/" data-testid="m18nws-primary-action">
          <span aria-hidden="true">←</span>
          Back to portfolio
        </Link>

        <section className={styles.disclosures} aria-label="Decision detail">
          <details className={styles.disclosure} name="m18nws-detail" data-testid="m18nws-why">
            <summary>
              <span>Why this state?</span>
              <span className={styles.disclosureSign} aria-hidden="true" />
            </summary>
            <div className={styles.disclosureBody}>
              <h2>Why you wait</h2>
              <div className={styles.whyGrid}>
                <p>
                  <strong>Who acts</strong>
                  {responsible} owns the cure action. Your {humanize(deal.viewer.role)} role cannot
                  perform it and has nothing to sign.
                </p>
                <p>
                  <strong>What changes</strong>
                  If {responsible} cures, protection returns to {protectionAfter ? humanize(protectionAfter).toLowerCase() : "its active state"}.
                </p>
                <p>
                  <strong>What stays</strong>
                  The cure does not burn or transfer your receivable units. Your {position.invoiceUnits} units remain held.
                </p>
              </div>
            </div>
          </details>

          <details
            className={`${styles.disclosure} ${styles.evidence}`}
            name="m18nws-detail"
            data-testid="m18nws-evidence"
          >
            <summary>
              <span>View evidence</span>
              <span className={styles.disclosureSign} aria-hidden="true" />
            </summary>
            <div className={styles.disclosureBody}>
              <div className={styles.evidenceIntro}>
                <h2>Configured scenario, not an observed transaction</h2>
                <p>No transition proof, live read, or participant signature is attached.</p>
              </div>
              <dl className={styles.evidenceGrid}>
                <div>
                  <dt>Source</dt>
                  <dd>Existing WRONG_ROLE synthetic product model</dd>
                </div>
                <div>
                  <dt>Before</dt>
                  <dd>{humanize(deal.machines.protection.state)}</dd>
                </div>
                <div>
                  <dt>Action</dt>
                  <dd>{action.label}</dd>
                </div>
                <div>
                  <dt>After</dt>
                  <dd>{protectionAfter ? humanize(protectionAfter) : "Not modeled"}</dd>
                </div>
                <div>
                  <dt>Deadline</dt>
                  <dd>{dueAt}</dd>
                </div>
                <div>
                  <dt>Limits</dt>
                  <dd>Configured state only; no external facts established</dd>
                </div>
                <div>
                  <dt>Identifiers</dt>
                  <dd>{deal.id} · {action.id}</dd>
                </div>
              </dl>
              <p className={styles.boundary}>
                This prototype does not establish external financing, fraud, legal priority,
                insurance, or production safety.
              </p>
            </div>
          </details>
        </section>
      </section>
    </main>
  );
}
