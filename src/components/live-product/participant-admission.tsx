"use client";

import styles from "./participant-admission.module.css";
import type { DirectAdmissionView } from "./live-product-view-model";

/**
 * The two-wallet admission surface.
 *
 * Its input is intentionally role-local. The active participant can edit and
 * see only their own interval. The other role is represented solely by the
 * public admission status and wallet address returned by the worker.
 */

export type AdmissionActions = Readonly<{
  onConnectWallet?: (role: "A" | "B") => void;
  onSwitchNetwork?: () => void;
  onCheckEligibility?: (role?: "A" | "B") => void;
  onAuthorizeClaim?: (role: "A" | "B") => void;
  onDraftChange?: (key: "activeFrom" | "activeUntil", value: string) => void;
  onContinueAsParticipantB?: () => void;
  onDisconnect?: () => void;
}>;

function shorten(value: string): string {
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function sameAddress(left: string | null | undefined, right: string | null): boolean {
  return left !== null && left !== undefined && right !== null && left.toLowerCase() === right.toLowerCase();
}

function PublicOtherRole({ admission }: { readonly admission: DirectAdmissionView }) {
  const { other } = admission;
  if (!other.admitted) return null;
  return (
    <section className={styles.otherRole} data-testid={`admitted-${other.role}`} aria-label={`${other.label} admission status`}>
      <p className={styles.eyebrow}>{other.label}</p>
      <strong>Admitted</strong>
      <p>
        {other.wallet === null ? "The other participant is admitted." : `Bound wallet ${shorten(other.wallet)}.`}
        {" "}Its claim details are not displayed here.
      </p>
    </section>
  );
}

function RolePanel({ admission, actions, busy }: {
  readonly admission: DirectAdmissionView;
  readonly actions: AdmissionActions;
  readonly busy: boolean;
}) {
  const current = admission.current;
  if (current === null) return null;
  const wallet = current.wallet;
  const connected = wallet !== null && wallet.address !== null;
  const wrongNetwork = wallet?.state === "WRONG_NETWORK";
  const authorizing = current.admission === "AUTHORIZING";
  const duplicate = sameAddress(wallet?.address, admission.other.wallet);
  const retryReady = admission.retryReady;
  const eligibility = current.eligibility;
  const eligible = current.eligibilityVerified;

  return (
    <div className={styles.roles} data-testid="participant-admission">
      <section className={styles.role} data-role={current.role} data-admitted="false" aria-labelledby={`role-${current.role}`}>
        <p className={styles.eyebrow}>{current.label}</p>
        <h3 id={`role-${current.role}`}>Authorize your private claim</h3>

        <ol className={styles.steps}>
          <li data-done={connected}>
            <span>Wallet</span>
            <strong>{connected ? shorten(wallet!.address!) : "Not connected"}</strong>
            {connected ? (
              <button type="button" className={styles.action} disabled={busy} onClick={actions.onDisconnect}>
                Disconnect this wallet
              </button>
            ) : (
              <button type="button" className={styles.action} disabled={busy} onClick={() => actions.onConnectWallet?.(current.role)}>
                Connect a wallet
              </button>
            )}
          </li>

          <li data-done={connected && !wrongNetwork}>
            <span>Network</span>
            <strong>{!connected ? "Monad testnet required" : wrongNetwork ? "Wrong network" : "Monad testnet"}</strong>
            {!wrongNetwork ? null : (
              <button type="button" className={styles.action} disabled={busy} onClick={actions.onSwitchNetwork}>
                Switch to Monad testnet
              </button>
            )}
          </li>

          <li data-done={eligible}>
            <span>Cleanverse A-Pass</span>
            <strong>{eligible
              ? `Verified · block ${eligibility.observedBlock}`
              : eligibility.state === "CHECKING"
                ? "Checking this address"
                : eligibility.state === "REFUSED"
                  ? "Not admitted"
                  : "Not checked"}
            </strong>
            {eligible || !connected || wrongNetwork ? null : (
              <button
                type="button"
                className={styles.action}
                disabled={busy || eligibility.state === "CHECKING"}
                onClick={() => actions.onCheckEligibility?.(current.role)}
              >
                {eligibility.state === "CHECKING" ? "Checking A-Pass" : "Check A-Pass eligibility"}
              </button>
            )}
          </li>
        </ol>

        {eligibility.problem === null ? null : <p className={styles.refused} role="alert">{eligibility.problem}</p>}

        <div className={styles.claimFields}>
          <div className={styles.field}>
            <label htmlFor={`admission-${current.role}-from`}>Active from</label>
            <input
              id={`admission-${current.role}-from`}
              type="text"
              inputMode="numeric"
              autoComplete="off"
              value={current.draft.activeFrom}
              disabled={busy || authorizing || retryReady}
              onChange={(event) => actions.onDraftChange?.("activeFrom", event.target.value)}
            />
          </div>
          <div className={styles.field}>
            <label htmlFor={`admission-${current.role}-until`}>Active until</label>
            <input
              id={`admission-${current.role}-until`}
              type="text"
              inputMode="numeric"
              autoComplete="off"
              value={current.draft.activeUntil}
              disabled={busy || authorizing || retryReady}
              onChange={(event) => actions.onDraftChange?.("activeUntil", event.target.value)}
            />
          </div>
        </div>

        {duplicate ? (
          <p className={styles.refused} role="alert" data-testid={`same-address-${current.role}`}>
            This address already holds the other role in this case. A second participant must use a different address.
          </p>
        ) : null}

        <p className={styles.privacy}>{current.privacyNote}</p>

        <button
          type="button"
          className={styles.primary}
          disabled={busy || authorizing || !connected || wrongNetwork || duplicate || !eligible}
          onClick={() => actions.onAuthorizeClaim?.(current.role)}
        >
          {authorizing
            ? "Waiting for the signature"
            : retryReady
              ? "Retry this signed admission"
              : `Authorize claim ${current.role}`}
        </button>
      </section>
      <PublicOtherRole admission={admission} />
    </div>
  );
}

export function ParticipantAdmission({
  admission,
  actions,
  busy = false,
}: {
  readonly admission: DirectAdmissionView;
  readonly actions: AdmissionActions;
  readonly busy?: boolean;
}) {
  if (admission.handoffRequired) {
    return (
      <section className={styles.handoff} aria-labelledby="handoff-title" data-testid="handoff">
        <p className={styles.eyebrow}>Participant A admitted</p>
        <h3 id="handoff-title">Participant B has not authorized its claim yet.</h3>
        <p className={styles.handoffBody}>
          The private check starts only once both participants are admitted. Participant B must use a
          different address: the same wallet cannot hold both roles in this case.
        </p>
        <p className={styles.privacy}>
          Nothing is disconnected for you. Choose the wallet that represents Participant B when you are
          ready, or leave this page and return to the same case later.
        </p>
        <PublicOtherRole admission={admission} />
        <div className={styles.handoffActions}>
          <button type="button" className={styles.primary} onClick={actions.onContinueAsParticipantB}>
            Continue as Participant B
          </button>
          <button type="button" className={styles.action} onClick={actions.onDisconnect}>
            Disconnect this wallet first
          </button>
        </div>
      </section>
    );
  }

  return <RolePanel admission={admission} actions={actions} busy={busy} />;
}
