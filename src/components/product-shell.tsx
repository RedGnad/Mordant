"use client";

import Link from "next/link";
import { useEffect, useState, type MouseEvent, type ReactNode } from "react";

import styles from "./product-shell.module.css";

type ProductSurface = "workspace" | "deal-room" | "protocol";

type ProductShellProps = {
  active: ProductSurface;
  children: ReactNode;
  mode?: "transaction-demo" | "executed-review" | "public-demo";
};

type ShellDefinition = {
  role: string;
  wallet: string;
  freshness: string;
  caution?: boolean;
  navigation: ReadonlyArray<{
    href: string;
    label: string;
    current?: boolean;
  }>;
};

const SHELLS: Readonly<Record<ProductSurface, ShellDefinition>> = {
  workspace: {
    role: "Originator",
    wallet: "0x71A9…92C4",
    freshness: "Fresh · block 1402",
    navigation: [
      { href: "/#app-main", label: "Workspace", current: true },
      { href: "/#portfolio", label: "Portfolio" },
      { href: "/#evidence", label: "Evidence" },
    ],
  },
  "deal-room": {
    role: "Holder",
    wallet: "0x4B7…A82",
    freshness: "Observed · block 1402",
    navigation: [{ href: "/#portfolio", label: "← Portfolio" }],
  },
  protocol: {
    role: "Protocol operator",
    wallet: "0x0A9…11E",
    freshness: "Public synthetic diagnostics",
    caution: true,
    navigation: [
      { href: "/", label: "← Workspace" },
      { href: "/protocol#events", label: "Events" },
      { href: "/protocol#diagnostics", label: "Diagnostics", current: true },
      { href: "/protocol#recovery", label: "Recovery" },
    ],
  },
};

const TRANSACTION_DEMO_NAVIGATION: Readonly<Record<ProductSurface, ShellDefinition["navigation"]>> = {
  workspace: [
    { href: "/workspace?demo=transactions", label: "Workspace", current: true },
    { href: "/participant?demo=transactions", label: "Participant" },
    { href: "/protocol?demo=transactions", label: "Protocol" },
  ],
  "deal-room": [
    { href: "/workspace?demo=transactions", label: "Workspace" },
    { href: "/participant?demo=transactions", label: "Participant", current: true },
    { href: "/protocol?demo=transactions", label: "Protocol" },
  ],
  protocol: [
    { href: "/workspace?demo=transactions", label: "Workspace" },
    { href: "/participant?demo=transactions", label: "Participant" },
    { href: "/protocol?demo=transactions", label: "Protocol", current: true },
  ],
};

const EXECUTED_REVIEW_NAVIGATION: Readonly<Record<ProductSurface, ShellDefinition["navigation"]>> = {
  workspace: [
    { href: "/workspace", label: "Workspace", current: true },
    { href: "/participant", label: "Participant" },
    { href: "/protocol", label: "Protocol" },
  ],
  "deal-room": [
    { href: "/workspace", label: "Workspace" },
    { href: "/participant", label: "Participant", current: true },
    { href: "/protocol", label: "Protocol" },
  ],
  protocol: [
    { href: "/workspace", label: "Workspace" },
    { href: "/participant", label: "Participant" },
    { href: "/protocol", label: "Protocol", current: true },
  ],
};

const PUBLIC_DEMO_NAVIGATION: Readonly<Record<ProductSurface, ShellDefinition["navigation"]>> = {
  workspace: [
    { href: "/demo?perspective=workspace", label: "Workspace", current: true },
    { href: "/demo?perspective=participant", label: "Participant" },
    { href: "/demo?perspective=protocol", label: "Protocol" },
  ],
  "deal-room": [
    { href: "/demo?perspective=workspace", label: "Workspace" },
    { href: "/demo?perspective=participant", label: "Participant", current: true },
    { href: "/demo?perspective=protocol", label: "Protocol" },
  ],
  protocol: [
    { href: "/demo?perspective=workspace", label: "Workspace" },
    { href: "/demo?perspective=participant", label: "Participant" },
    { href: "/demo?perspective=protocol", label: "Protocol", current: true },
  ],
};

function targetHash(href: string) {
  const hashIndex = href.indexOf("#");
  return hashIndex === -1 ? "" : href.slice(hashIndex);
}

function withCheckpoint(href: string, checkpoint: string): string {
  if (!checkpoint) return href;
  const destination = new URL(href, "https://mordant.local");
  destination.searchParams.set("checkpoint", checkpoint);
  return `${destination.pathname}${destination.search}${destination.hash}`;
}

function revealHashTarget(hash: string, moveFocus = false) {
  if (!hash) return false;

  let id: string;
  try {
    id = decodeURIComponent(hash.slice(1));
  } catch {
    return false;
  }
  const target = document.getElementById(id);
  if (!target) return false;

  const focusTarget = target instanceof HTMLDetailsElement
    ? target.querySelector<HTMLElement>("summary") ?? target
    : target;

  if (target instanceof HTMLDetailsElement) target.open = true;

  if (moveFocus) {
    if (focusTarget === target) focusTarget.setAttribute("tabindex", "-1");
    focusTarget.focus({ preventScroll: true });
  }

  target.scrollIntoView({
    behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
    block: "start",
  });
  return true;
}

export function ProductShell({ active, children, mode }: ProductShellProps) {
  const transactionDemo = mode === "transaction-demo";
  const executedReview = mode === "executed-review";
  const publicDemo = mode === "public-demo";
  const mEx2Mode = transactionDemo || executedReview || publicDemo;
  const surfacePath = active === "workspace" ? "/workspace" : active === "deal-room" ? "/participant" : "/protocol";
  const baseShell = SHELLS[active];
  const shell: ShellDefinition = mEx2Mode ? {
    ...baseShell,
    wallet: transactionDemo ? "Controlled demo signer" : "Recorded signer",
    freshness: transactionDemo ? "Receipt-derived state" : "Checkpoint selected",
    navigation: publicDemo
      ? PUBLIC_DEMO_NAVIGATION[active]
      : transactionDemo ? TRANSACTION_DEMO_NAVIGATION[active] : EXECUTED_REVIEW_NAVIGATION[active],
  } : baseShell;
  const participantShell = active === "deal-room";
  const [activeHash, setActiveHash] = useState("");
  const [activeCheckpoint, setActiveCheckpoint] = useState("");
  const [navigationStatus, setNavigationStatus] = useState("");

  useEffect(() => {
    function syncHash() {
      const hash = window.location.hash;
      setActiveHash(hash);
      setActiveCheckpoint(new URL(window.location.href).searchParams.get("checkpoint") ?? "");
      if (hash) window.requestAnimationFrame(() => revealHashTarget(hash));
    }

    syncHash();
    window.addEventListener("hashchange", syncHash);
    window.addEventListener("popstate", syncHash);
    window.addEventListener("mordant-checkpoint-change", syncHash);

    return () => {
      window.removeEventListener("hashchange", syncHash);
      window.removeEventListener("popstate", syncHash);
      window.removeEventListener("mordant-checkpoint-change", syncHash);
    };
  }, []);

  function handleSectionNavigation(event: MouseEvent<HTMLAnchorElement>, href: string, label: string) {
    const destination = new URL(href, window.location.href);
    if (destination.pathname !== window.location.pathname || !destination.hash) return;

    if (!revealHashTarget(destination.hash, true)) return;

    event.preventDefault();
    const previousUrl = window.location.href;
    window.history.pushState(null, "", `${destination.pathname}${destination.search}${destination.hash}`);
    window.dispatchEvent(new HashChangeEvent("hashchange", {
      oldURL: previousUrl,
      newURL: window.location.href,
    }));
    setActiveHash(destination.hash);
    setNavigationStatus(`${label} view shown`);
  }

  return (
    <div
      className={`${styles.shell} product-shell product-shell-${active}`}
      data-surface={active}
      data-demo-mode={transactionDemo ? "transactions" : executedReview ? "review" : publicDemo ? "public" : undefined}
    >
      <a className="app-skip-link" href="#app-main">
        Skip to product surface
      </a>

      <header
        className={`${styles.chrome} ${participantShell && !mEx2Mode ? styles.participantChrome : ""} product-chrome`}
        data-testid="product-chrome"
      >
        <div className={`${styles.brandLockup} brand-lockup`}>
          <Link
            className="brand-link"
            href={publicDemo ? "/" : mEx2Mode
              ? withCheckpoint(transactionDemo ? "/workspace?demo=transactions" : "/workspace", activeCheckpoint)
              : "/"}
            aria-label={publicDemo ? "Mordant home" : "Mordant workspace"}
          >
            <svg className={styles.brandMark} viewBox="0 0 100 100" aria-hidden="true">
              <rect x="43" width="14" height="100" />
              <rect y="43" width="100" height="14" />
              <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
              <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
            </svg>
            <span className="brand-wordmark">Mordant</span>
            {!participantShell ? <span className="brand-caption">Receivables, with recourse</span> : null}
          </Link>
        </div>

        {shell.navigation.length > 0 ? (
          <nav className={`${styles.navigation} role-navigation`} aria-label={`${shell.role} navigation`}>
            <ul>
              {shell.navigation.map((item) => {
                const href = mEx2Mode ? withCheckpoint(item.href, activeCheckpoint) : item.href;
                const hash = targetHash(href);
                const isCurrent = activeHash ? activeHash === hash : item.current;

                return (
                  <li key={`${active}-${item.href}-${item.label}`}>
                    {item.current && isCurrent ? (
                      <span className="role-navigation-link is-current" aria-current="page">
                        {item.label}
                      </span>
                    ) : (
                      <Link
                        className={isCurrent ? "role-navigation-link is-current" : "role-navigation-link"}
                        href={href}
                        aria-current={isCurrent ? "location" : undefined}
                        onClick={(event) => handleSectionNavigation(event, href, item.label)}
                      >
                        {item.label}
                      </Link>
                    )}
                  </li>
                );
              })}
            </ul>
          </nav>
        ) : null}

        <div className={`${styles.session} session-context`} aria-label="Session context">
          <div className={styles.sessionIdentity} aria-label={`${shell.role} role`}>
            <strong>{shell.role}</strong>
          </div>
          <details className={styles.contextControl}>
            <summary>
              Context
              <i aria-hidden="true" />
            </summary>
            <div className={styles.contextPanel}>
              <strong>Session context</strong>
              <dl>
                <div><dt>Wallet</dt><dd className={styles.technicalValue}>{shell.wallet}</dd></div>
                <div><dt>Network</dt><dd className={styles.technicalValue}>{mEx2Mode ? "Controlled Anvil · 31337" : "Monad testnet · 10143"}</dd></div>
                <div><dt>Freshness</dt><dd className={`${styles.technicalValue} ${shell.caution ? "session-restricted" : "session-fresh"}`}>{shell.freshness}</dd></div>
                <div><dt>View</dt><dd>{participantShell ? "Participant" : active === "protocol" ? "Operations" : "Originator"}</dd></div>
              </dl>
              {transactionDemo ? (
                <Link className={styles.demoModeLink} href={surfacePath}>
                  Return to recorded view
                </Link>
              ) : null}
            </div>
          </details>
        </div>
      </header>

      <div className={`${styles.fixture} fixture-notice`}>
        <span>
          {publicDemo || mEx2Mode
            ? "Recorded demo run · test assets · read-only"
            : participantShell ? "Synthetic · no real funds" : "Synthetic design fixture · no real funds"}
        </span>
        {!mEx2Mode && !participantShell && !transactionDemo ? (
          <span aria-hidden="true">{active === "protocol" ? "Operations" : "Originator"} view</span>
        ) : null}
      </div>

      <p className="visually-hidden" role="status" aria-live="polite">{navigationStatus}</p>

      <main className="product-main" id="app-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
