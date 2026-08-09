import type { Metadata } from "next";
import Link from "next/link";

import { PublicShell } from "@/components/public-shell";

import styles from "./not-found.module.css";

export const metadata: Metadata = {
  title: "Page not found",
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <PublicShell surface="landing">
      <section className={styles.panel} aria-labelledby="not-found-title">
        <p className={styles.eyebrow}>404</p>
        <h1 id="not-found-title">This page does not exist.</h1>
        <p className={styles.lede}>The live proof, verified evidence and pilot path are all still here.</p>
        <div className={styles.actions}>
          <Link className={styles.primary} href="/protection/live">Run live proof</Link>
          <Link className={styles.secondary} href="/protection?scenario=conflict">Inspect verified evidence</Link>
          <Link className={styles.secondary} href="/">Back to Mordant</Link>
        </div>
      </section>
    </PublicShell>
  );
}
