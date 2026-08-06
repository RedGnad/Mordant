"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useConnect, useConnection, useConnectors, useDisconnect, useSwitchChain } from "wagmi";

import { MORDANT_CHAIN_ID } from "./wagmi-config";
import { dedupeConnectors, providerErrorCode, safeWalletIcon, walletProblemMessage, type ConnectorRow } from "./wallet-presentation";
import type { WalletView } from "../live-product/live-product-view-model";

/**
 * The browser-side wallet surface.
 *
 * Every wallet request is caused by an explicit call from a user gesture. This
 * hook never connects, switches, adds a chain or signs on mount, and it never
 * fires two requests from one action: `pending` gates the connect path and the
 * switch path independently.
 */

export type WalletOption = Readonly<Omit<ConnectorRow, "icon"> & {
  /** Null when the wallet-supplied icon failed the safe-source check. */
  icon: string | null;
  kind: "injected" | "walletconnect" | "other";
}>;

function kindOf(type: string, id: string): WalletOption["kind"] {
  if (type === "walletConnect" || id === "walletConnect") return "walletconnect";
  if (type === "injected") return "injected";
  return "other";
}

export function useMordantWallet() {
  const connection = useConnection();
  const connectors = useConnectors();
  const { connectAsync, isPending: connecting } = useConnect();
  const { disconnectAsync } = useDisconnect();
  const { switchChainAsync, isPending: switching } = useSwitchChain();

  const [problem, setProblem] = useState<string | null>(null);
  const [pairingUri, setPairingUri] = useState<string | null>(null);
  const [rejected, setRejected] = useState(false);
  const inFlight = useRef(false);

  /**
   * WalletConnect emits its pairing URI instead of opening its own modal, so it
   * is captured here and drawn inside the Mordant surface.
   */
  useEffect(() => {
    const wc = connectors.find((connector) => kindOf(connector.type, connector.id) === "walletconnect");
    if (wc === undefined) return;
    const onMessage = (payload: { type: string; data?: unknown }) => {
      if (payload.type === "display_uri" && typeof payload.data === "string") setPairingUri(payload.data);
    };
    wc.emitter.on("message", onMessage);
    return () => { wc.emitter.off("message", onMessage); };
  }, [connectors]);

  const options: readonly WalletOption[] = useMemo(() => {
    const rows = connectors.map((connector) => ({
      uid: connector.uid,
      id: connector.id,
      name: connector.name,
      icon: connector.icon,
      type: connector.type,
    }));
    return dedupeConnectors(rows).map((row) => Object.freeze({
      ...row,
      icon: safeWalletIcon(row.icon),
      kind: kindOf(row.type, row.id),
    }));
  }, [connectors]);

  const walletConnectAvailable = options.some((option) => option.kind === "walletconnect");

  /** One explicit click, one account request. Never called on mount. */
  const connect = useCallback(async (uid: string) => {
    if (inFlight.current) return;
    const connector = connectors.find((candidate) => candidate.uid === uid);
    if (connector === undefined) return;
    inFlight.current = true;
    setProblem(null);
    setRejected(false);
    setPairingUri(null);
    try {
      await connectAsync({ connector });
    } catch (error) {
      const code = providerErrorCode(error);
      setRejected(code === 4001);
      setProblem(walletProblemMessage(code, "This wallet did not complete the connection. Nothing was submitted."));
    } finally {
      inFlight.current = false;
      setPairingUri(null);
    }
  }, [connectAsync, connectors]);

  /** Deliberately separate from connect: a network switch is its own decision. */
  const switchToMonad = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setProblem(null);
    try {
      await switchChainAsync({ chainId: MORDANT_CHAIN_ID });
    } catch (error) {
      const code = providerErrorCode(error);
      setProblem(walletProblemMessage(code, "The network was not switched. Mordant needs Monad testnet."));
    } finally {
      inFlight.current = false;
    }
  }, [switchChainAsync]);

  const disconnect = useCallback(async () => {
    setProblem(null);
    setRejected(false);
    setPairingUri(null);
    await disconnectAsync();
  }, [disconnectAsync]);

  const view: WalletView = useMemo(() => {
    const address = connection.address ?? null;
    const chainId = connection.chainId ?? null;
    const state: WalletView["state"] = connecting || connection.status === "connecting"
      ? "CONNECTING"
      : switching
        ? "SWITCHING_NETWORK"
        : rejected
          ? "REJECTED"
          : address === null
            ? "DISCONNECTED"
            : chainId !== MORDANT_CHAIN_ID
              ? "WRONG_NETWORK"
              : "CONNECTED";

    return Object.freeze({
      state,
      address,
      connectorName: connection.connector?.name ?? null,
      connectorUid: connection.connector?.uid ?? null,
      chainId,
      expectedChainId: MORDANT_CHAIN_ID,
      problem: state === "WRONG_NETWORK" && problem === null
        ? "This wallet is on a different network. Switch it to Monad testnet to continue."
        : problem,
    });
  }, [connection, connecting, switching, rejected, problem]);

  return {
    view,
    options,
    walletConnectAvailable,
    pairingUri,
    busy: connecting || switching,
    connect,
    switchToMonad,
    disconnect,
    clearProblem: useCallback(() => { setProblem(null); setRejected(false); }, []),
  } as const;
}
