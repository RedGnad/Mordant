"use client";

import styles from "./participant-admission.module.css";
import type { ParticipantClaimView, WalletView } from "./live-product-view-model";

/**
 * The two-wallet admission surface.
 *
 * Rendered only when the backend supplies a capability other than the managed
 * combined intake, so it never appears in production today. It presents one role
 * at a time: a participant sees, reviews and authorizes only its own claim, and
 * the handoff between them is an explicit decision rather than an automatic
 * disconnect.
 *
 * It makes no claim about who operates the wallets. Two addresses are two
 * addresses, not two institutions.
 */

export type AdmissionActions = Readonly<{
  onConnectWallet?: (role: "A" | "B") => void;
  onSwitchNetwork?: () => void;
  onAuthorizeClaim?: (role: "A" | "B") => void;
  onContinueAsParticipantB?: () => void;
  onDisconnect?: () => void;
}>;

function shorten(value: string): string {
  return value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function RolePanel({
  claim, wallet, window: claimWindow, sameAddressRefused, actions, busy,
}: {
  readonly claim: ParticipantClaimView;
  readonly wallet: WalletView | null;
  readonly window: Readonly<{ activeFrom: number; activeUntil: number }> | null;
  readonly sameAddressRefused: boolean;
  readonly actions: AdmissionActions;
  readonly busy: boolean;
}) {
  const connected = wallet !== null && wallet.address !== null;
  const wrongNetwork = wallet?.state === "WRONG_NETWORK";
  const admitted = claim.admission === "ADMITTED";
  const authorizing = claim.admission === "AUTHORIZING";

  return (
    <section className={styles.role} data-role={claim.role} data-admitted={admitted} aria-labelledby={`role-${claim.role}`}>
      <p className={styles.eyebrow}>{claim.label}</p>
      <h3 id={`role-${claim.role}`}>
        {admitted ? "Admitted" : claim.role === "A" ? "Authorize claim A" : "Authorize claim B"}
      </h3>

      <ol className={styles.steps}>
        <li data-done={connected}>
          <span>Wallet</span>
          <strong>{connected ? shorten(wallet!.address!) : "Not connected"}</strong>
          {connected || admitted ? null : (
            <button type="button" className={styles.action} disabled={busy} onClick={() => actions.onConnectWallet?.(claim.role)}>
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

        <li data-done={claim.eligibilityVerified}>
          <span>Cleanverse A-Pass</span>
          <strong>{claim.eligibilityVerified ? "Verified for this address" : "Not verified yet"}</strong>
        </li>

        <li data-done={admitted}>
          <span>Claim</span>
          <strong>
            {claimWindow === null
              ? "No interval bound yet"
              : `Active from ${claimWindow.activeFrom} until ${claimWindow.activeUntil}`}
          </strong>
        </li>
      </ol>

      {sameAddressRefused ? (
        <p className={styles.refused} role="alert" data-testid={`same-address-${claim.role}`}>
          This address already holds the other role in this case. A second participant must be a
          different address, so this admission is refused.
        </p>
      ) : null}

      <p className={styles.privacy}>{claim.privacyNote}</p>

      {admitted ? (
        <p className={styles.admitted} data-testid={`admitted-${claim.role}`}>
          One typed authorization was signed for this exact claim. It transfers no funds.
        </p>
      ) : (
        <button
          type="button"
          className={styles.primary}
          disabled={busy || authorizing || !connected || wrongNetwork || !claim.eligibilityVerified || sameAddressRefused}
          onClick={() => actions.onAuthorizeClaim?.(claim.role)}
        >
          {authorizing ? "Waiting for the signature" : `Authorize claim ${claim.role}`}
        </button>
      )}
    </section>
  );
}

export function ParticipantAdmission({
  claimA, claimB, wallet, windowA, windowB, activeRole, handoffRequired, actions, busy = false,
}: {
  readonly claimA: ParticipantClaimView;
  readonly claimB: ParticipantClaimView;
  readonly wallet: WalletView | null;
  readonly windowA: Readonly<{ activeFrom: number; activeUntil: number }> | null;
  readonly windowB: Readonly<{ activeFrom: number; activeUntil: number }> | null;
  readonly activeRole: "A" | "B" | null;
  readonly handoffRequired: boolean;
  readonly actions: AdmissionActions;
  readonly busy?: boolean;
}) {
  // The same address may never hold both roles in a qualified journey.
  const sameAddress = claimA.wallet !== null && claimB.wallet !== null
    && claimA.wallet.toLowerCase() === claimB.wallet.toLowerCase();
  const currentIsA = claimA.wallet !== null && wallet?.address?.toLowerCase() === claimA.wallet.toLowerCase();

  if (handoffRequired) {
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
          ready, or leave this page and return to the same run later.
        </p>
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

  // The active role is expanded, and a role that is already admitted stays
  // visible as a completed panel: a participant needs to see that the other side
  // is in before its own signature means anything.
  const showA = activeRole === null || activeRole === "A" || claimA.admission === "ADMITTED";
  const showB = activeRole === null || activeRole === "B" || claimB.admission === "ADMITTED";

  return (
    <div className={styles.roles} data-testid="participant-admission">
      {!showA ? null : (
        <RolePanel
          claim={claimA}
          wallet={currentIsA || activeRole === "A" ? wallet : null}
          window={windowA}
          sameAddressRefused={false}
          actions={actions}
          busy={busy}
        />
      )}
      {!showB ? null : (
        <RolePanel
          claim={claimB}
          wallet={activeRole === "B" ? wallet : null}
          window={windowB}
          sameAddressRefused={sameAddress}
          actions={actions}
          busy={busy}
        />
      )}
    </div>
  );
}
