import Link from "next/link";

import styles from "./live-unavailable.module.css";

/**
 * Page-level SERVICE_UNAVAILABLE.
 *
 * Reached when the deployment carries no managed execution service. It states
 * that plainly, never implies the product is finished, and keeps the two paths
 * that do work reachable.
 */
export function LiveUnavailable() {
  return (
    <section className={styles.panel} aria-labelledby="live-unavailable-title">
      <p className={styles.eyebrow}>Live proof</p>
      <h1 id="live-unavailable-title">The live proof is not available on this deployment.</h1>
      <p className={styles.lede}>
        This build has no managed execution service configured, so no encrypted check can be started here.
        A completed run and its full evidence remain inspectable.
      </p>
      <div className={styles.actions}>
        <Link className={styles.primary} href="/protection?scenario=conflict">Inspect verified evidence</Link>
        <Link className={styles.secondary} href="/demo">See the lifecycle after a conflict</Link>
      </div>
    </section>
  );
}
