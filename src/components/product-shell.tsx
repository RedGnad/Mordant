"use client";

import Link from "next/link";
import { useEffect, useState, type MouseEvent, type ReactNode } from "react";

import styles from "./product-shell.module.css";

type ProductSurface = "workspace" | "deal-room" | "protocol";

type ProductShellProps = {
  active: ProductSurface;
  children: ReactNode;
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

function targetHash(href: string) {
  const hashIndex = href.indexOf("#");
  return hashIndex === -1 ? "" : href.slice(hashIndex);
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

export function ProductShell({ active, children }: ProductShellProps) {
  const shell = SHELLS[active];
  const participantShell = active === "deal-room";
  const [activeHash, setActiveHash] = useState("");
  const [navigationStatus, setNavigationStatus] = useState("");

  useEffect(() => {
    function syncHash() {
      const hash = window.location.hash;
      setActiveHash(hash);
      if (hash) window.requestAnimationFrame(() => revealHashTarget(hash));
    }

    syncHash();
    window.addEventListener("hashchange", syncHash);
    window.addEventListener("popstate", syncHash);

    return () => {
      window.removeEventListener("hashchange", syncHash);
      window.removeEventListener("popstate", syncHash);
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
    <div className={`${styles.shell} product-shell product-shell-${active}`} data-surface={active}>
      <a className="app-skip-link" href="#app-main">
        Skip to product surface
      </a>

      <header
        className={`${styles.chrome} ${participantShell ? styles.participantChrome : ""} product-chrome`}
        data-testid="product-chrome"
      >
        <div className={`${styles.brandLockup} brand-lockup`}>
          <Link
            className="brand-link"
            href="/"
            aria-label="Mordant workspace"
          >
            <span className="brand-wordmark">Mordant</span>
            {!participantShell ? <span className="brand-caption">Receivables, with recourse</span> : null}
          </Link>
        </div>

        {shell.navigation.length > 0 ? (
          <nav className={`${styles.navigation} role-navigation`} aria-label={`${shell.role} navigation`}>
            <ul>
              {shell.navigation.map((item) => {
                const hash = targetHash(item.href);
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
                        href={item.href}
                        aria-current={isCurrent ? "location" : undefined}
                        onClick={(event) => handleSectionNavigation(event, item.href, item.label)}
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
                <div><dt>Wallet</dt><dd>{shell.wallet}</dd></div>
                <div><dt>Network</dt><dd>Monad testnet · 10143</dd></div>
                <div><dt>Freshness</dt><dd className={shell.caution ? "session-restricted" : "session-fresh"}>{shell.freshness}</dd></div>
                <div><dt>View</dt><dd>{participantShell ? "Participant" : active === "protocol" ? "Operations" : "Originator"}</dd></div>
              </dl>
            </div>
          </details>
        </div>
      </header>

      <div className={`${styles.fixture} fixture-notice`}>
        <span>{participantShell ? "Synthetic · no real funds" : "Synthetic design fixture · no real funds"}</span>
        {!participantShell ? (
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
