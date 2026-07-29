import Link from "next/link";
import type { ReactNode } from "react";

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
      { href: "/", label: "Workspace", current: true },
      { href: "/#portfolio", label: "Portfolio" },
      { href: "/#evidence", label: "Evidence" },
    ],
  },
  "deal-room": {
    role: "Holder",
    wallet: "0x4B7…A82",
    freshness: "Observed · block 1402",
    navigation: [
      { href: "/", label: "← Portfolio" },
      { href: "/deal-room", label: "Deal room", current: true },
      { href: "/deal-room#evidence", label: "Evidence" },
    ],
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

export function ProductShell({ active, children }: ProductShellProps) {
  const shell = SHELLS[active];

  return (
    <div className={`${styles.shell} product-shell product-shell-${active}`} data-surface={active}>
      <a className="app-skip-link" href="#app-main">
        Skip to product surface
      </a>

      <header className={`${styles.chrome} product-chrome`} data-testid="product-chrome">
        <div className={`${styles.brandLockup} brand-lockup`}>
          <Link className="brand-link" href="/" aria-label="Mordant workspace">
            <span className="brand-wordmark">Mordant</span>
            <span className="brand-caption">Receivables, with recourse</span>
          </Link>
        </div>

        <nav className={`${styles.navigation} role-navigation`} aria-label={`${shell.role} navigation`}>
          <ul>
            {shell.navigation.map((item) => (
              <li key={`${active}-${item.href}-${item.label}`}>
                <Link
                  className={item.current ? "role-navigation-link is-current" : "role-navigation-link"}
                  href={item.href}
                  aria-current={item.current ? "page" : undefined}
                >
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <div className={`${styles.session} session-context`} aria-label="Session context">
          <span>Monad testnet · 10143</span>
          <span>{shell.role} · {shell.wallet}</span>
          <span className={shell.caution ? "session-restricted" : "session-fresh"}>{shell.freshness}</span>
        </div>
      </header>

      <div className={`${styles.fixture} fixture-notice`}>
        <span>Synthetic design fixture · no real funds</span>
        <span aria-hidden="true">{active === "deal-room" ? "Participant" : active === "protocol" ? "Operations" : "Originator"} view</span>
      </div>

      <main className="product-main" id="app-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
