"use client";

import { useCallback, useEffect, useState } from "react";
import { Check, ExternalLink, LoaderCircle, RefreshCw } from "lucide-react";

import {
  MonadTestnetPublicConfigError,
  createMonadTestnetReadClient,
  getMonadTestnetPublicConfig,
  readMordantInvoiceVaultSnapshot,
  type MonadTestnetPublicConfig,
  type MordantInvoiceVaultSnapshot,
} from "@/lib/contracts";

type ProofState =
  | { kind: "loading" }
  | { kind: "unconfigured" }
  | { kind: "failed" }
  | {
      kind: "live";
      config: MonadTestnetPublicConfig;
      snapshot: MordantInvoiceVaultSnapshot;
    };

function compactHex(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

export function LiveVaultProof() {
  const [proof, setProof] = useState<ProofState>({ kind: "loading" });

  const refresh = useCallback(async () => {
    // Keep the initial effect asynchronous; user-triggered refreshes still get immediate feedback.
    await Promise.resolve();
    setProof({ kind: "loading" });
    try {
      const config = getMonadTestnetPublicConfig();
      const client = createMonadTestnetReadClient(config);
      const snapshot = await readMordantInvoiceVaultSnapshot(client, config);
      setProof({ kind: "live", config, snapshot });
    } catch (error) {
      setProof(error instanceof MonadTestnetPublicConfigError
        ? { kind: "unconfigured" }
        : { kind: "failed" });
    }
  }, []);

  useEffect(() => {
    const task = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(task);
  }, [refresh]);

  if (proof.kind === "unconfigured") {
    return (
      <section className="chain-proof chain-proof-muted" aria-label="Deployment proof status">
        <div>
          <span className="micro">ONCHAIN PROOF SLOT</span>
          <h2>Awaiting a configured vault.</h2>
          <p>The interface will bind to the fresh Monad testnet vault as soon as its public address is configured.</p>
        </div>
        <span className="proof-status">Unconfigured · no address claimed</span>
      </section>
    );
  }

  if (proof.kind === "loading") {
    return (
      <section className="chain-proof chain-proof-muted" aria-live="polite">
        <LoaderCircle className="spin" size={20} />
        <span>Reading the configured vault at one block…</span>
      </section>
    );
  }

  if (proof.kind === "failed") {
    return (
      <section className="chain-proof chain-proof-muted" aria-live="polite">
        <div>
          <span className="micro">ONCHAIN PROOF UNAVAILABLE</span>
          <p>The configured Monad RPC or vault did not return a valid Mordant snapshot.</p>
        </div>
        <button className="proof-refresh" type="button" onClick={() => void refresh()}>
          <RefreshCw size={15} /> Retry
        </button>
      </section>
    );
  }

  const { config, snapshot } = proof;
  const contractUrl = `${config.explorerUrl}/address/${snapshot.contract.address}`;

  return (
    <section className="chain-proof" aria-label="Live Mordant vault proof">
      <div className="proof-heading">
        <div>
          <span className="micro">LIVE · BLOCK {snapshot.chain.blockNumber}</span>
          <h2>Contract accounting assertion observed.</h2>
        </div>
        <a href={contractUrl} target="_blank" rel="noreferrer">
          {compactHex(snapshot.contract.address)} <ExternalLink size={14} />
        </a>
      </div>
      <div className="proof-readings">
        <article>
          <span>Protection</span>
          <strong>{snapshot.stateMachines.protection.label}</strong>
          <small>Receivable · {snapshot.stateMachines.receivable.label}</small>
        </article>
        <article>
          <span>Reserve lifecycle</span>
          <strong>{snapshot.accounting.bondLifecycleTotal.formatted}</strong>
          <small><Check size={13} /> {snapshot.accounting.bondMatchesInitial && snapshot.accounting.contractAssertionPassed ? "contract-checked" : "mismatch"}</small>
        </article>
        <article>
          <span>Invoice backing</span>
          <strong>{snapshot.supply.outstanding.formatted}</strong>
          <small><Check size={13} /> {snapshot.accounting.supplyMatchesCva ? "1:1 accounted" : "mismatch"}</small>
        </article>
        <article>
          <span>Entitlement left</span>
          <strong>{snapshot.entitlement.unclaimed.formatted}</strong>
          <small>invoice root · {compactHex(snapshot.contract.invoiceRoot)}</small>
        </article>
      </div>
    </section>
  );
}
