import Link from "next/link";

import styles from "./public-experience.module.css";

export function PublicHeader() {
  return (
    <header className={styles.header}>
      <Link className={styles.brand} href="/">
        <svg className={styles.brandMark} viewBox="0 0 100 100" aria-hidden="true">
          <rect x="43" width="14" height="100" />
          <rect y="43" width="100" height="14" />
          <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
          <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
        </svg>
        <span>Mordant</span>
      </Link>
      <nav aria-label="Public navigation">
        <Link className={styles.optionalNav} href="/#product">How it works</Link>
        <Link className={styles.optionalNav} href="/#integrate">Integration</Link>
        <Link className={styles.protectionNav} href="/protection?scenario=conflict">
          <span className={styles.desktopLabel}>Conflicting Pledge Protection</span>
          <span className={styles.mobileLabel}>Protection</span>
        </Link>
        <Link href="/demo">
          <span className={styles.desktopLabel}>Recorded demo</span>
          <span className={styles.mobileLabel}>Demo</span>
        </Link>
        <Link className={styles.navPrimary} href="/pilot">
          <span className={styles.desktopLabel}>Request a shadow pilot</span>
          <span className={styles.mobileLabel}>Request pilot</span>
        </Link>
      </nav>
    </header>
  );
}

export function PublicFooter() {
  return (
    <footer className={styles.footer}>
      <strong>Mordant</strong>
      <span>Recourse infrastructure for tokenized receivables.</span>
    </footer>
  );
}
