import Link from "next/link";

import styles from "./public-experience.module.css";

export function PublicHeader() {
  return (
    <header className={styles.header}>
      <Link className={styles.brand} href="/">Mordant</Link>
      <nav aria-label="Public navigation">
        <Link className={styles.optionalNav} href="/#problem">Problem</Link>
        <Link className={styles.optionalNav} href="/#integrate">Integrate</Link>
        <Link href="/demo">Recorded demo</Link>
        <Link className={styles.navPrimary} href="/pilot">Apply for a shadow pilot</Link>
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
