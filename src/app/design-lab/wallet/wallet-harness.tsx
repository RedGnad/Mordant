"use client";

import { useState } from "react";

import { PublicShell } from "@/components/public-shell";
import { WalletModal } from "@/components/wallet/wallet-modal";
import { WalletProvider } from "@/components/wallet/wallet-provider";

/**
 * Drives the modal in isolation. The `wc` flag selects the configured
 * WalletConnect path so both behaviours can be observed without touching any
 * deployment variable.
 */
export function WalletHarness() {
  const [open, setOpen] = useState(false);
  const configured = typeof window !== "undefined"
    && new URLSearchParams(window.location.search).get("wc") === "configured";

  return (
    <WalletProvider walletConnectProjectId={configured ? "00000000000000000000000000000000" : null}>
      <PublicShell surface="live">
        <section style={{ padding: "48px var(--shell-gutter)" }}>
          <p style={{ font: "11px var(--font-proof), monospace", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)" }}>
            Design harness · not production
          </p>
          <h1 style={{ fontSize: "clamp(28px, 4vw, 44px)", letterSpacing: "-0.04em", margin: "12px 0 22px" }}>
            Wallet modal harness
          </h1>
          <button
            type="button"
            data-testid="open-wallet"
            onClick={() => setOpen(true)}
            style={{
              minHeight: 48, padding: "0 20px", border: "1px solid var(--ink)",
              background: "var(--action-fill)", font: "inherit", fontWeight: 600,
            }}
          >
            Connect a wallet
          </button>
        </section>
        <WalletModal
          open={open}
          role="A"
          receivable="MINV01 · Cleanverse receivable"
          onClose={() => setOpen(false)}
        />
      </PublicShell>
    </WalletProvider>
  );
}
