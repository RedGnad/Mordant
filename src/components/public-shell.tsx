import Link from "next/link";
import type { ReactNode } from "react";

import styles from "./public-shell.module.css";

/**
 * The one public chrome.
 *
 * Landing, live product, evidence, lifecycle demo and pilot all mount this, so
 * the live product stops rendering outside the brand and the primary action is
 * the same object on every page.
 */

export type PublicSurface = "landing" | "live" | "evidence" | "demo" | "pilot";

const NAVIGATION = [
  { id: "how", href: "/#how", label: "How it works", short: "How" },
  { id: "evidence", href: "/protection/verified-run", label: "Evidence", short: "Evidence" },
  { id: "pilot", href: "/pilot", label: "Pilot", short: "Pilot" },
] as const;

const SURFACE_NAV: Readonly<Record<PublicSurface, string | null>> = {
  landing: null,
  live: null,
  evidence: "evidence",
  demo: null,
  pilot: "pilot",
};

export const LIVE_PRODUCT_HREF = "/protection/live";
export const LIVE_PRODUCT_CTA = "Run the live check";

function BrandMark() {
  return (
    <svg className={styles.mark} viewBox="0 0 100 100" aria-hidden="true">
      <rect x="43" width="14" height="100" />
      <rect y="43" width="100" height="14" />
      <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
      <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
    </svg>
  );
}

export function PublicHeader({ surface }: { readonly surface: PublicSurface }) {
  const activeNav = SURFACE_NAV[surface];
  const onLive = surface === "live";
  const primaryHref = surface === "landing" ? "/#product" : LIVE_PRODUCT_HREF;

  return (
    <header className={styles.header}>
      <Link className={styles.brand} href="/" aria-label="Mordant home">
        <BrandMark />
        <span>Mordant</span>
      </Link>

      <nav className={styles.nav} aria-label="Product navigation">
        {NAVIGATION.map((item) => (
          <Link
            key={item.id}
            className={styles.navLink}
            href={item.href}
            aria-current={activeNav === item.id ? "page" : undefined}
          >
            <span className={styles.tabLabel}>
              <span className={styles.wide}>{item.label}</span>
              <span className={styles.narrow}>{item.short}</span>
            </span>
          </Link>
        ))}
      </nav>

      {onLive ? (
        <p className={styles.ctaCurrent} aria-current="page">
          <span className={styles.ctaLabel}>
            <span className={styles.wide}>Live check</span>
            <span className={styles.narrow}>Live</span>
          </span>
        </p>
      ) : (
        <Link className={styles.cta} href={primaryHref} data-testid="shell-live-cta">
          <span className={styles.ctaLabel}>
            <span className={styles.wide}>{LIVE_PRODUCT_CTA}</span>
            <span className={styles.narrow}>Run check</span>
          </span>
        </Link>
      )}
    </header>
  );
}

export function PublicFooter() {
  return (
    <footer className={styles.footer}>
      <div className={styles.footerBrand}>
        <span className={styles.footerLockup}>
          <BrandMark />
          <strong>Mordant</strong>
        </span>
        <span className={styles.footerLine}>Recourse infrastructure for tokenized receivables.</span>
      </div>
      <nav className={styles.footerNav} aria-label="Footer navigation">
        <Link href="/#product">Run the landing experiment</Link>
        <Link href="/protection/verified-run">Verify completed recourse</Link>
        <Link href={LIVE_PRODUCT_HREF}>Advanced live product</Link>
        <Link href="/protection?scenario=conflict">Retained case evidence</Link>
      </nav>
    </footer>
  );
}

/**
 * `contentId` is the skip-link target. Surfaces that own their own `<main>`
 * (the landing) pass `bare` so the shell does not nest a second one.
 */
export function PublicShell({
  surface,
  children,
  bare = false,
  contentId = "content",
}: {
  readonly surface: PublicSurface;
  readonly children: ReactNode;
  readonly bare?: boolean;
  readonly contentId?: string;
}) {
  return (
    <div className={`${styles.shell} mordant-shell`} data-surface={surface}>
      <a className={styles.skip} href={`#${contentId}`}>Skip to content</a>
      <PublicHeader surface={surface} />
      {bare ? children : <main id={contentId} className={styles.main} tabIndex={-1}>{children}</main>}
      <PublicFooter />
    </div>
  );
}
