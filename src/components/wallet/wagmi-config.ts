import { http, createConfig } from "wagmi";
import { monadTestnet } from "wagmi/chains";
import { injected } from "wagmi/connectors/injected";
import { walletConnect } from "wagmi/connectors/walletConnect";

/**
 * Wagmi configuration for the Mordant participant surface.
 *
 * Injected wallets are discovered through EIP-6963 rather than hard-coded, so a
 * browser with MetaMask, Rabby and Phantom offers three real rows and a browser
 * with none offers none. WalletConnect is added only when a project ID is
 * supplied: an unconfigured WalletConnect would be a dead button, and a dead
 * button is worse than an absent one.
 *
 * `showQrModal` is false on purpose. The pairing URI is rendered inside the
 * Mordant modal, so no third-party interface ever appears over the product.
 */

export const MORDANT_CHAIN = monadTestnet;
export const MORDANT_CHAIN_ID = monadTestnet.id;

export const WALLETCONNECT_METADATA = {
  name: "Mordant",
  description: "Conflicting Pledge Protection for tokenized receivables.",
  url: "https://mordant-two.vercel.app",
  icons: ["https://mordant-two.vercel.app/icon.svg"],
} as const;

export type WagmiSetup = Readonly<{
  /** Server-supplied. Absent means the WalletConnect row is never rendered. */
  walletConnectProjectId: string | null;
}>;

export function createMordantWagmiConfig(setup: WagmiSetup) {
  const connectors = [
    // One connector per EIP-6963 provider, plus the legacy window.ethereum
    // fallback for a browser whose wallet does not announce itself.
    injected({ shimDisconnect: true }),
    ...(setup.walletConnectProjectId === null ? [] : [
      walletConnect({
        projectId: setup.walletConnectProjectId,
        showQrModal: false,
        metadata: { ...WALLETCONNECT_METADATA, icons: [...WALLETCONNECT_METADATA.icons] },
      }),
    ]),
  ];

  return createConfig({
    chains: [MORDANT_CHAIN],
    connectors,
    // Discovery is what produces a real wallet list. Wagmi dedupes by rdns and
    // the presentation layer collapses whatever survives that.
    multiInjectedProviderDiscovery: true,
    transports: { [MORDANT_CHAIN.id]: http() },
    ssr: true,
  });
}

export type MordantWagmiConfig = ReturnType<typeof createMordantWagmiConfig>;
