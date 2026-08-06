"use client";

import styles from "./onchain-panel.module.css";
import type { OnchainPhase, OnchainView } from "./live-product-view-model";

/**
 * The on-chain half of the consequence.
 *
 * Every value arrives typed from the adapter. No contract address, ABI, amount
 * or event name is written here, and while `ONCHAIN_RECOURSE_CONNECTED` is off
 * the panel states plainly that the settlement leg is not connected rather than
 * showing a plausible-looking transaction.
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

export function OnchainPanel({ view }: { readonly view: OnchainView }) {
  if (view.phase === "NOT_CONNECTED") {
    return (
      <section className={styles.panel} data-connected="false" data-testid="onchain-panel">
        <p className={styles.eyebrow}>Settlement</p>
        <p className={styles.disabled}>
          {view.disabledReason ?? "On-chain recourse is not connected on this deployment."}
          {" "}The verified governed result above is a synthetic prototype readback; no real funds move here.
          The aUSDC settlement leg is prepared and not yet wired.
        </p>
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
