import type { Metadata } from "next";
import Link from "next/link";

import {
  formatDomainAmount,
  proRateDomainAmount,
} from "@/components/product-presenters";
import { getSyntheticDeal } from "@/lib/mordant/product-model";
import { deriveReadinessVerdict } from "@/lib/mordant/readiness";

import styles from "./m18r-deal-room.module.css";

export const metadata: Metadata = {
  title: "M-18R Deal Room benchmark",
  description: "Isolated Mordant design-lab benchmark for a compressed participant decision.",
  robots: {
    index: false,
    follow: false,
    nocache: true,
  },
};

function DomainMark({ domain }: Readonly<{ domain: "receivable" | "protection" }>) {
  if (domain === "receivable") {
    return (
      <svg viewBox="0 0 64 64" aria-hidden="true" focusable="false">
        <path d="M13 9h29l9 9v37H13z" />
        <path d="M42 9v10h9M21 29h22M21 38h22M21 47h14" />
      </svg>
    );
  }

  return (
    <svg viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <path d="M32 8 51 16v15c0 12-7.7 20.8-19 25-11.3-4.2-19-13-19-25V16z" />
      <path d="M23 32h18M32 23v18" />
    </svg>
  );
}

function DeadlineMark() {
  return (
    <svg viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <circle cx="32" cy="32" r="22" />
      <path d="M32 18v15l11 7" />
    </svg>
  );
}

function MordantMark() {
  return (
    <svg viewBox="0 0 42 42" aria-hidden="true" focusable="false">
      <path d="M3 3h16v16H3zM23 23h16v16H23z" />
      <path d="M23 3h16v16H23z" className={styles.markField} />
      <path d="M3 23h16v16H3z" className={styles.markField} />
    </svg>
  );
}

function deadlineParts(timestamp: string) {
  const date = new Intl.DateTimeFormat("fr-FR", {
    day: "numeric",
    month: "long",
    timeZone: "UTC",
  }).format(new Date(timestamp));
  const time = new Intl.DateTimeFormat("fr-FR", {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC",
  }).format(new Date(timestamp));

  return { date, time };
}

function formatParticipantAmount(amount: Parameters<typeof formatDomainAmount>[0]) {
  const [whole, fraction = ""] = formatDomainAmount(amount).split(".");
  const localizedWhole = whole.replaceAll(",", "\u202f");
  return fraction === "00" ? localizedWhole : `${localizedWhole},${fraction}`;
}

export default function M18RDealRoomBenchmark() {
  const deal = getSyntheticDeal("wrong-role");
  const action = deal.actions[0];
  const verdict = deriveReadinessVerdict(deal, action);
  const position = deal.viewer.position ?? { invoiceUnits: "0", totalUnits: "100" };
  const receivableExposure = proRateDomainAmount(deal.economics.receivable.outstanding, position);
  const protectionExposure = proRateDomainAmount(deal.economics.protection.lockedReserve, position);
  const dueAt = deal.nextResponsibility.dueAt;
  if (!dueAt) throw new Error("The M-18R wrong-role benchmark requires a source deadline.");
  const deadline = deadlineParts(dueAt);
  const responsible = deal.nextResponsibility.actorLabel.replace(" (synthetic)", "");
  const hasMissedDeadlineConsequence = Boolean(deal.nextResponsibility.consequenceIfMissed);

  return (
    <main className={styles.page} data-testid="m18r-benchmark" lang="fr">
      <header className={styles.labHeader}>
        <Link className={styles.brand} href="/" aria-label="Mordant — retour au portefeuille">
          <MordantMark />
          <strong>Mordant</strong>
        </Link>
        <div className={styles.labIdentity}>
          <span>Design lab</span>
          <strong>M-18R / Deal Room</strong>
        </div>
        <div className={styles.fixtureLabel}>Scénario synthétique</div>
      </header>

      <section className={styles.firstView} data-testid="m18r-first-view">
        <div
          className={styles.levelOne}
          data-testid="m18r-level-one"
          data-readiness-verdict={verdict.code}
        >
          <div className={styles.statusRail}>
            <span>En attente</span>
            <strong>{responsible}</strong>
            <span className={styles.statusSignal} aria-hidden="true">
              <DeadlineMark />
            </span>
          </div>

          <section className={styles.decision} aria-labelledby="m18r-title">
            <div className={styles.decisionCopy}>
              <h1 id="m18r-title">Vous n’avez rien à faire.</h1>
              <p className={styles.lead}>
                {responsible} doit régulariser avant {deadline.time}. Votre créance n’a pas bougé.
              </p>
            </div>

            <dl className={styles.ownershipGrid}>
              <div>
                <dt>Échéance</dt>
                <dd>
                  <time dateTime={dueAt}>{deadline.date} · {deadline.time} UTC</time>
                </dd>
              </div>
            </dl>
          </section>

          <section className={styles.domains} aria-label="Montants de créance et de protection">
            <article className={styles.receivable} data-testid="m18r-domain-receivable">
              <div className={styles.domainHeading}>
                <DomainMark domain="receivable" />
                <span>Votre créance</span>
              </div>
              <p className={styles.amount}>
                {formatParticipantAmount(receivableExposure)} <small>{receivableExposure.asset.symbol}</small>
              </p>
              <strong>Toujours détenue</strong>
            </article>

            <article className={styles.protection} data-testid="m18r-domain-protection">
              <div className={styles.domainHeading}>
                <DomainMark domain="protection" />
                <span>Protection concernée</span>
              </div>
              <p className={styles.amount}>
                {formatParticipantAmount(protectionExposure)} <small>{protectionExposure.asset.symbol}</small>
              </p>
              <strong>Non versée</strong>
            </article>
          </section>

          <section
            className={styles.consequence}
            aria-labelledby="m18r-consequence"
            data-testid="m18r-deadline-consequence"
            data-consequence-source={hasMissedDeadlineConsequence ? "next-responsibility" : "missing"}
          >
            <DeadlineMark />
            <div>
              <p id="m18r-consequence">À l’échéance</p>
              <strong>
                {hasMissedDeadlineConsequence
                  ? "La protection peut devenir réclamable. La créance reste séparée."
                  : "Aucune conséquence n’est établie dans ce scénario."}
              </strong>
            </div>
          </section>

          <Link className={styles.primaryAction} href="/" data-testid="m18r-primary-action">
            <span>Portefeuille</span>
            <svg viewBox="0 0 28 28" aria-hidden="true" focusable="false">
              <path d="M22 14H6m6-6-6 6 6 6" />
            </svg>
          </Link>
        </div>
      </section>

      <section className={styles.disclosures} aria-label="Informations complémentaires">
        <details className={styles.disclosure} data-testid="m18r-why">
          <summary>
            <span className={styles.disclosureIndex}>02</span>
            <span>Pourquoi&nbsp;?</span>
            <span className={styles.disclosureToggle} aria-hidden="true" />
          </summary>
          <div className={styles.disclosureBody}>
            <div className={styles.explanationLead}>
              <p className={styles.kicker}>Décision du modèle</p>
              <h2>La régularisation appartient à {responsible}, pas à votre rôle.</h2>
            </div>
            <div className={styles.explanationGrid}>
              <article>
                <span>01</span>
                <h3>Votre position</h3>
                <p>Vous détenez {position.invoiceUnits} unités sur {position.totalUnits} dans ce scénario.</p>
              </article>
              <article>
                <span>02</span>
                <h3>La règle appliquée</h3>
                <p>L’action est réservée à {responsible}. Mordant ne vous propose donc aucune signature.</p>
              </article>
              <article>
                <span>03</span>
                <h3>La séparation</h3>
                <p>Un éventuel versement de protection ne brûle ni ne transfère vos unités de créance.</p>
              </article>
            </div>
          </div>
        </details>

        <details className={styles.disclosure} data-testid="m18r-evidence">
          <summary>
            <span className={styles.disclosureIndex}>03</span>
            <span>Voir la preuve</span>
            <span className={styles.disclosureToggle} aria-hidden="true" />
          </summary>
          <div className={styles.disclosureBody}>
            <div className={styles.evidenceIntro}>
              <p className={styles.kicker}>Limite de la démonstration</p>
              <h2>État configuré, pas observation d’une transaction réelle.</h2>
              <p>Cette vue montre uniquement comment Mordant présente et applique le scénario synthétique.</p>
            </div>
            <dl className={styles.evidenceGrid}>
              <div>
                <dt>État de protection</dt>
                <dd>Période de régularisation fournie par le modèle synthétique</dd>
                <span>Dérivé par Mordant</span>
              </div>
              <div>
                <dt>Responsabilité</dt>
                <dd>{responsible} est le rôle configuré pour agir</dd>
                <span>Dérivé par Mordant</span>
              </div>
              <div>
                <dt>Preuve de transition</dt>
                <dd>{deal.proofs.length === 0 ? "Non fournie dans ce scénario" : "Fournie"}</dd>
                <span>Non établie</span>
              </div>
              <div>
                <dt>Lecture et signature</dt>
                <dd>Aucune lecture live ni attestation participant</dd>
                <span>Non établies</span>
              </div>
            </dl>
            <p className={styles.boundary}>
              Ce prototype n’établit ni financement externe, ni fraude, ni priorité juridique, ni assurance.
            </p>
          </div>
        </details>
      </section>
    </main>
  );
}
