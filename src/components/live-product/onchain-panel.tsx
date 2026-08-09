"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import styles from "./onchain-panel.module.css";
import type { OnchainPhase, OnchainView } from "./live-product-view-model";

/**
 * The on-chain half of the consequence.
 *
 * Every value arrives typed from the adapter. No contract address, ABI, amount
 * or event name is written here. A managed run that ends after a bounded local
 * operation is kept distinct from the separate completed hardened recourse run.
 */

const PHASE_LABEL: Readonly<Record<OnchainPhase, string>> = Object.freeze({
  NOT_CONNECTED: "Not connected",
  BRIDGE_ATTESTATION_READY: "Bridge attestation ready",
  SUBMITTING_RELEASE: "Submitting the governed release",
  TRANSACTION_PENDING: "Transaction pending",
  RELEASE_CONSUMED: "Release consumed",
  CURE_OPEN: "Cure window open",
  CURE_SUBMITTED: "Cure submitted",
  CURE_CONFIRMED: "Cure confirmed",
  AWAITING_CURE_DEADLINE: "Waiting for the cure deadline",
  FINALIZATION_AVAILABLE: "Finalization available",
  FINALIZATION_PENDING: "Finalization pending",
  ENTITLEMENT_OPENED: "Entitlement opened",
  CLAIM_PENDING: "Claim pending",
  CLAIM_CONFIRMED: "Claim confirmed",
});

const MONAD_TESTNET_EXPLORER = "https://testnet.monadexplorer.com";
const TRANSACTION_HASH = /^0x[0-9a-fA-F]{64}$/u;
const CONTRACT_ADDRESS = /^0x[0-9a-fA-F]{40}$/u;

function short(value: string | null): string {
  if (value === null) return "not present";
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

/**
 * Future adapter data is untrusted at this rendering boundary. A transaction
 * or address becomes clickable only for the one explicit HTTPS Monad testnet
 * explorer and a strict canonical identifier; otherwise it stays plain text.
 */
export function safeMonadExplorerHref(
  explorerBase: string | null,
  kind: "tx" | "address",
  value: string | null,
): string | null {
  if (explorerBase === null || value === null) return null;
  const pattern = kind === "tx" ? TRANSACTION_HASH : CONTRACT_ADDRESS;
  if (!pattern.test(value)) return null;
  try {
    const base = new URL(explorerBase);
    if (base.protocol !== "https:" || base.origin !== MONAD_TESTNET_EXPLORER
      || base.pathname !== "/" || base.search !== "" || base.hash !== "") return null;
    return `${MONAD_TESTNET_EXPLORER}/${kind}/${value}`;
  } catch {
    return null;
  }
}

/** Phases where the contract's real cure window is the thing to explain. */
const CURE_WINDOW_PHASES: ReadonlySet<OnchainPhase> = new Set<OnchainPhase>([
  "CURE_OPEN",
  "AWAITING_CURE_DEADLINE",
]);

function remainingLabel(deadlineMs: number, nowMs: number): string {
  const seconds = Math.max(0, Math.floor((deadlineMs - nowMs) / 1_000));
  if (seconds === 0) return "the window has closed";
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s remaining`;
}

/**
 * The real cure window, counted down honestly.
 *
 * The contract gives the facility ten real minutes and the product does not
 * pretend otherwise or shorten it. When the deadline passes this says so rather
 * than claiming an outcome the chain has not produced.
 */
function CureWindow({ deadlineIso }: { readonly deadlineIso: string }) {
  const deadlineMs = Date.parse(deadlineIso);
  const [nowMs, setNowMs] = useState<number | null>(null);
  useEffect(() => {
    // Scheduled, not synchronous: setting state inline in an effect cascades a
    // render on mount. The countdown is a display detail and can start on the
    // first tick.
    const timer = setInterval(() => setNowMs(Date.now()), 1_000);
    const first = setTimeout(() => setNowMs(Date.now()), 0);
    return () => {
      clearInterval(timer);
      clearTimeout(first);
    };
  }, []);
  if (!Number.isFinite(deadlineMs)) return null;
  return (
    <div className={styles.cure} data-testid="cure-window">
      <p className={styles.eyebrow}>Cure window</p>
      <p className={styles.cureLine}>
        After conflict confirmation, the historical policy opened recourse. The facility has 10 real
        minutes to cure before this case can be finalized by anyone.
      </p>
      <p className={styles.cureDeadline} data-testid="cure-deadline">
        Deadline {deadlineIso}
        {nowMs === null ? null : <span className={styles.cureRemaining}> · {remainingLabel(deadlineMs, nowMs)}</span>}
      </p>
      <Link className={styles.cureLink} href="/protection/verified-run" data-testid="live-to-verified-run">
        See a separate verified on-chain execution
      </Link>
      <p className={styles.cureNote}>
        That page is a different, already-completed historical Adapter V2 run on Monad. After its
        deadline expired, finalization opened entitlement and both holder claims were paid.
      </p>
    </div>
  );
}

export function OnchainPanel({ view }: { readonly view: OnchainView }) {
  if (view.phase === "NOT_CONNECTED") {
    return (
      <section className={styles.panel} data-connected="false" data-testid="onchain-panel">
        <p className={styles.eyebrow}>Managed run boundary</p>
        <p className={styles.disabled}>
          {view.disabledReason ?? "This managed run ends after its policy-authorized local operation and sealed evidence."}
          {" "}It did not execute a new aUSDC settlement.
        </p>
        <Link className={styles.boundaryLink} href="/protection/verified-run" data-testid="live-to-verified-run">
          Verify the separate completed on-chain recourse
        </Link>
        <p className={styles.boundaryNote}>Opens a separate hardened two-wallet run on Monad testnet.</p>
      </section>
    );
  }

  const hash = view.evidence.transactionHash;
  const transactionHref = safeMonadExplorerHref(view.evidence.explorerBase, "tx", hash);
  const contractHref = safeMonadExplorerHref(view.evidence.explorerBase, "address", view.evidence.contractAddress);

  return (
    <section className={styles.panel} data-connected="true" data-testid="onchain-panel">
      <p className={styles.eyebrow}>Settlement · Monad testnet</p>
      <p className={styles.phase} data-testid="onchain-phase">{PHASE_LABEL[view.phase]}</p>

      <dl className={styles.rows}>
        <div>
          <dt>Transaction</dt>
          <dd>
            {hash === null ? "not present" : transactionHref === null ? short(hash) : (
              <a href={transactionHref} target="_blank" rel="noreferrer noopener">{short(hash)}</a>
            )}
          </dd>
        </div>
        <div><dt>Block</dt><dd>{view.evidence.blockNumber ?? "not present"}</dd></div>
        <div>
          <dt>Contract</dt>
          <dd>
            {view.evidence.contractAddress === null ? "not present" : contractHref === null
              ? short(view.evidence.contractAddress)
              : (
                <a href={contractHref} target="_blank" rel="noreferrer noopener">
                  {short(view.evidence.contractAddress)}
                </a>
              )}
          </dd>
        </div>
      </dl>

      {view.cureDeadlineIso !== null && CURE_WINDOW_PHASES.has(view.phase)
        ? <CureWindow deadlineIso={view.cureDeadlineIso} />
        : null}

      {view.entitlement === null ? null : (
        <div className={styles.entitlement}>
          <p className={styles.eyebrow}>Entitlement</p>
          <ul>
            <li>
              <span>Holder A</span>
              <strong>
                {view.entitlement.holderA?.formatted ?? "0.00"} <small>{view.entitlement.holderA?.symbol ?? "aUSDC"}</small>
              </strong>
              <em>{view.entitlement.claimedByA ? "Claimed" : "Claimable"}</em>
            </li>
            <li>
              <span>Holder B</span>
              <strong>
                {view.entitlement.holderB?.formatted ?? "0.00"} <small>{view.entitlement.holderB?.symbol ?? "aUSDC"}</small>
              </strong>
              <em>{view.entitlement.claimedByB ? "Claimed" : "Claimable"}</em>
            </li>
          </ul>
        </div>
      )}
    </section>
  );
}
