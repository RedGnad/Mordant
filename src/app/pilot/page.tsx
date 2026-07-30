import type { Metadata } from "next";

import { PilotApplicationForm } from "@/components/pilot-application-form";
import { PublicFooter, PublicHeader } from "@/components/public-chrome";

import styles from "./pilot.module.css";

export const metadata: Metadata = {
  title: "Apply for a shadow pilot",
  description: "Run Mordant alongside your current receivables process without moving funds or automating production actions.",
};

export default function PilotPage() {
  const acceptingApplications = Boolean(process.env.PILOT_APPLICATION_WEBHOOK_URL?.trim());

  return (
    <div className={styles.page}>
      <a className={styles.skip} href="#pilot-form">Skip to application</a>
      <PublicHeader />
      <main>
        <section className={styles.intro} aria-labelledby="pilot-title">
          <div>
            <p>Shadow pilot</p>
            <h1 id="pilot-title">Test accountable recourse against your current process.</h1>
          </div>
          <div className={styles.promise}>
            <p>Run Mordant alongside your current process, without moving funds or automating production actions.</p>
            <ul>
              <li>Use anonymized or representative portfolio data.</li>
              <li>Keep every decision subject to human validation.</li>
              <li>Compare Mordant with the process your team already trusts.</li>
            </ul>
          </div>
        </section>

        <section className={styles.application} id="pilot-form" aria-labelledby="application-title">
          <header>
            <p>Pilot fit</p>
            <h2 id="application-title">Tell us how your team handles exceptions today.</h2>
          </header>
          <PilotApplicationForm acceptingApplications={acceptingApplications} />
        </section>

        <section className={styles.next} aria-labelledby="next-title">
          <p>What follows</p>
          <div>
            <h2 id="next-title">A scoped operational comparison, not a production rollout.</h2>
            <ol>
              <li><strong>Discovery</strong><span>Confirm the workflow, actors, data boundary, and decision owner.</span></li>
              <li><strong>Shadow run</strong><span>Process agreed exceptions alongside the current operating procedure.</span></li>
              <li><strong>Review</strong><span>Compare resolution time, ambiguity, manual exchanges, and proof completeness.</span></li>
            </ol>
          </div>
        </section>
      </main>
      <PublicFooter />
    </div>
  );
}
