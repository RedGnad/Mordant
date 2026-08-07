"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { WagmiProvider } from "wagmi";

import { createMordantWagmiConfig } from "./wagmi-config";

/**
 * Wallet runtime for the participant surface.
 *
 * `reconnectOnMount` is false. Restoring a session is allowed to inspect an
 * already authorized connection, but the strictest reading of the rule is that
 * nothing wallet-facing happens without a click, and a page that never calls
 * reconnect on mount cannot open a popup on mount by any path. The visitor
 * reconnects with one deliberate action instead.
 */
export function WalletProvider({
  walletConnectProjectId,
  children,
}: {
  readonly walletConnectProjectId: string | null;
  readonly children: ReactNode;
}) {
  // Created once per mount: a new config on every render would tear down and
  // rebuild the connectors underneath an open modal.
  const [config] = useState(() => createMordantWagmiConfig({ walletConnectProjectId }));
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  }));

  return (
    <WagmiProvider config={config} reconnectOnMount={false}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </WagmiProvider>
  );
}
