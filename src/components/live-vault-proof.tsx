"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Check, ExternalLink, RefreshCw } from "lucide-react";

import "@/app/local-journey.css";

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
  | { kind: "failed"; reason: "timeout" | "read" }
  | {
      kind: "live";
      config: MonadTestnetPublicConfig;
      snapshot: MordantInvoiceVaultSnapshot;
    };

const PROOF_READ_TIMEOUT_MS = 12_000;

class VaultProofTimeoutError extends Error {}

function compactHex(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

export function LiveVaultProof() {
  const [proof, setProof] = useState<ProofState>({ kind: "loading" });
  const requestSequence = useRef(0);

  const refresh = useCallback(async () => {
    const requestId = requestSequence.current + 1;
    requestSequence.current = requestId;

    // Keep the initial effect asynchronous; user-triggered refreshes still get immediate feedback.
    await Promise.resolve();
    if (requestSequence.current !== requestId) {
      return;
    }
    setProof({ kind: "loading" });

    let timeout: number | undefined;
    try {
      const config = getMonadTestnetPublicConfig();
      const client = createMonadTestnetReadClient(config);
      const snapshot = await Promise.race([
        readMordantInvoiceVaultSnapshot(client, config),
        new Promise<never>((_, reject) => {
          timeout = window.setTimeout(
            () => reject(new VaultProofTimeoutError("The snapshot read timed out.")),
            PROOF_READ_TIMEOUT_MS,
          );
        }),
      ]);

      if (requestSequence.current === requestId) {
        setProof({ kind: "live", config, snapshot });
      }
    } catch (error) {
      if (requestSequence.current === requestId) {
        setProof(error instanceof MonadTestnetPublicConfigError
          ? { kind: "unconfigured" }
          : { kind: "failed", reason: error instanceof VaultProofTimeoutError ? "timeout" : "read" });
      }
    } finally {
      if (timeout !== undefined) {
        window.clearTimeout(timeout);
      }
    }
  }, []);

  useEffect(() => {
    const task = window.setTimeout(() => void refresh(), 0);
    return () => {
      window.clearTimeout(task);
      requestSequence.current += 1;
    };
  }, [refresh]);

  if (proof.kind === "unconfigured") {
    return (
      <section className="vault-proof chain-proof chain-proof-muted" data-proof-state="unconfigured" aria-label="Deployment proof status">
        <div>
          <span className="micro">ONCHAIN PROOF SLOT</span>
          <h2>Awaiting a configured vault.</h2>
          <p>The interface will bind to the fresh Monad testnet vault as soon as its public address is configured.</p>
        </div>
        <span className="proof-status" role="status">Unconfigured · no address claimed</span>
      </section>
    );
  }

  if (proof.kind === "loading") {
    return (
      <section
        className="vault-proof chain-proof chain-proof-muted proof-reading"
        data-proof-state="loading"
        aria-labelledby="vault-proof-loading-title"
        aria-busy="true"
      >
        <span className="proof-registration-mark" aria-hidden="true" />
        <div>
          <span className="micro">BOUNDED SNAPSHOT READ</span>
          <h2 id="vault-proof-loading-title">Checking one block-scoped observation.</h2>
          <p>This read resolves as observed, unavailable, or timed out within 12 seconds.</p>
        </div>
        <span className="proof-status" role="status">Pending · no claim yet</span>
      </section>
    );
  }

  if (proof.kind === "failed") {
    return (
      <section
        className="vault-proof chain-proof chain-proof-muted"
        data-proof-state="failed"
        aria-labelledby="vault-proof-failed-title"
        aria-live="polite"
      >
        <div>
          <span className="micro">ONCHAIN PROOF UNAVAILABLE</span>
          <h2 id="vault-proof-failed-title">
            {proof.reason === "timeout" ? "The observation window expired." : "No valid snapshot was returned."}
          </h2>
          <p>
            {proof.reason === "timeout"
              ? "The configured endpoint did not answer within 12 seconds. Nothing is presented as observed."
              : "The configured Monad RPC or vault did not return a valid Mordant snapshot."}
          </p>
        </div>
        <button className="proof-refresh" type="button" onClick={() => void refresh()}>
          <RefreshCw size={15} aria-hidden="true" /> Retry observation
        </button>
      </section>
    );
  }

  const { config, snapshot } = proof;
  const contractUrl = `${config.explorerUrl}/address/${snapshot.contract.address}`;
  const reserveMatches = snapshot.accounting.bondMatchesInitial
    && snapshot.accounting.contractAssertionPassed;
  const supplyMatches = snapshot.accounting.supplyMatchesCva;

  return (
    <section className="vault-proof chain-proof" data-proof-state="live" aria-label="Live Mordant vault proof">
      <div className="proof-heading">
        <div>
          <span className="micro">LIVE · BLOCK {snapshot.chain.blockNumber}</span>
          <h2>Contract accounting assertion observed.</h2>
        </div>
        <a
          href={contractUrl}
          target="_blank"
          rel="noreferrer"
          aria-label={`Inspect contract ${snapshot.contract.address} in the block explorer (opens in a new tab)`}
        >
          {compactHex(snapshot.contract.address)} <ExternalLink size={14} aria-hidden="true" />
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
          <small className="proof-reading-status" data-match={reserveMatches ? "true" : "false"}>
            {reserveMatches ? <Check size={13} aria-hidden="true" /> : null}
            {reserveMatches ? "Contract-checked" : "Mismatch"}
          </small>
        </article>
        <article>
          <span>Invoice backing</span>
          <strong>{snapshot.supply.outstanding.formatted}</strong>
          <small className="proof-reading-status" data-match={supplyMatches ? "true" : "false"}>
            {supplyMatches ? <Check size={13} aria-hidden="true" /> : null}
            {supplyMatches ? "1:1 accounted" : "Mismatch"}
          </small>
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
