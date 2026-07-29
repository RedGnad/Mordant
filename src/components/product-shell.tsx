import Link from "next/link";
import type { ReactNode } from "react";

type ProductSurface = "workspace" | "deal-room" | "protocol";

type ProductShellProps = {
  active: ProductSurface;
  children: ReactNode;
};

const productNavigation: ReadonlyArray<{
  id: ProductSurface;
  href: "/" | "/deal-room" | "/protocol";
  label: string;
  detail: string;
}> = [
  {
    id: "workspace",
    href: "/",
    label: "Deal workspace",
    detail: "Monitor",
  },
  {
    id: "deal-room",
    href: "/deal-room",
    label: "Participant deal room",
    detail: "Understand",
  },
  {
    id: "protocol",
    href: "/protocol",
    label: "Protocol operations",
    detail: "Inspect",
  },
];

export function ProductShell({ active, children }: ProductShellProps) {
  return (
    <div className="app-shell">
      <a className="app-skip-link" href="#app-main">
        Skip to product surface
      </a>

      <header className="app-header">
        <div className="app-header-brand">
          <Link className="app-brand-link" href="/" aria-label="Mordant deal workspace">
            <span className="app-wordmark">Mordant</span>
            <span className="app-tagline">Programmable recourse</span>
          </Link>
        </div>

        <div className="app-environment" aria-label="Prototype environment">
          <span className="app-environment-item">
            <span className="app-environment-signal" aria-hidden="true" />
            Monad testnet · 10143
          </span>
          <span className="app-environment-item">Synthetic test data</span>
        </div>

        <p className="app-prototype-warning">
          Prototype only — not approved for real funds, legal assignment, or custody.
        </p>
      </header>

      <nav className="app-navigation" aria-label="Product surfaces">
        <ol className="app-navigation-list">
          {productNavigation.map((item, index) => {
            const isActive = item.id === active;

            return (
              <li className="app-navigation-item" key={item.id}>
                <Link
                  className={`app-navigation-link${isActive ? " app-navigation-link-active" : ""}`}
                  href={item.href}
                  aria-current={isActive ? "page" : undefined}
                >
                  <span className="app-navigation-index" aria-hidden="true">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span className="app-navigation-label">{item.label}</span>
                  <span className="app-navigation-detail">{item.detail}</span>
                </Link>
              </li>
            );
          })}
        </ol>
      </nav>

      <main className={`app-main app-main-${active}`} id="app-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
