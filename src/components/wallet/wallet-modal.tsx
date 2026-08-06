"use client";

import { useCallback, useEffect, useId, useRef, useState } from "react";

import { PairingQr } from "./pairing-qr";
import { useMordantWallet, type WalletOption } from "./use-mordant-wallet";
import styles from "./wallet-modal.module.css";

/**
 * The Mordant wallet modal.
 *
 * Custom on purpose: no third-party kit ever renders over the product, and the
 * surface carries the case context a participant needs before they connect. It
 * opens no wallet request by itself; every request comes from a row the visitor
 * pressed.
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

function WalletRow({ option, onSelect, busy }: {
  readonly option: WalletOption;
  readonly onSelect: (uid: string) => void;
  readonly busy: boolean;
}) {
  return (
    <li>
      <button type="button" className={styles.walletRow} disabled={busy} onClick={() => onSelect(option.uid)}>
        <span className={styles.walletIcon} aria-hidden="true">
          {option.icon === null ? (
            <svg viewBox="0 0 100 100">
              <rect x="43" width="14" height="100" />
              <rect y="43" width="100" height="14" />
              <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
              <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
            </svg>
          ) : (
            // Constrained image source only. Wallet-supplied markup is never
            // inserted into the document, and the URL is deliberately not sent
            // through next/image: that would proxy an untrusted third-party
            // source through our own origin.
            // eslint-disable-next-line @next/next/no-img-element
            <img src={option.icon} alt="" width={22} height={22} loading="lazy" decoding="async" />
          )}
        </span>
        <span className={styles.walletName}>{option.name}</span>
        <span className={styles.walletState}>
          {option.kind === "walletconnect" ? "Scan or pair" : "Detected"}
        </span>
      </button>
    </li>
  );
}

export function WalletModal({
  open,
  role,
  receivable,
  onClose,
}: {
  readonly open: boolean;
  readonly role: "A" | "B";
  readonly receivable: string;
  readonly onClose: () => void;
}) {
  const wallet = useMordantWallet();
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  // Transient messages the visitor caused (a copy, a blocked Escape). The wallet
  // state announcement is derived below rather than stored, so no effect writes
  // state during render.
  const [transient, setTransient] = useState("");

  const injected = wallet.options.filter((option) => option.kind !== "walletconnect");
  const walletConnect = wallet.options.find((option) => option.kind === "walletconnect") ?? null;
  const requestPending = wallet.busy;

  useEffect(() => {
    if (!open) return;
    returnFocus.current = document.activeElement as HTMLElement | null;
    const dialog = dialogRef.current;
    dialog?.querySelector<HTMLElement>(FOCUSABLE)?.focus({ preventScroll: true });
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = overflow;
      returnFocus.current?.focus({ preventScroll: true });
    };
  }, [open]);

  const onKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    // Escape is refused while a wallet request is open: closing the surface
    // would leave a native prompt with nothing behind it.
    if (event.key === "Escape") {
      if (requestPending) {
        setTransient("A wallet request is open. Finish or dismiss it in your wallet first.");
        return;
      }
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const nodes = Array.from(dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    if (nodes.length === 0) return;
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }, [onClose, requestPending]);

  const walletAnnouncement =
    wallet.view.state === "CONNECTED" ? "Wallet connected on Monad testnet."
      : wallet.view.state === "WRONG_NETWORK" ? "Wallet connected on the wrong network."
        : wallet.view.state === "REJECTED" ? "The wallet request was declined."
          : wallet.view.state === "CONNECTING" ? "Waiting for the wallet to respond."
            : "";
  const announcement = transient === "" ? walletAnnouncement : transient;

  if (!open) return null;

  return (
    <div className={styles.backdrop} role="presentation" onMouseDown={(event) => {
      if (event.target === event.currentTarget && !requestPending) onClose();
    }}>
      <div
        ref={dialogRef}
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        onKeyDown={onKeyDown}
      >
        <header className={styles.header}>
          <p className={styles.eyebrow}>Participant {role}</p>
          <h2 id={titleId}>Choose the wallet representing this participant</h2>
          <button type="button" className={styles.close} onClick={onClose} disabled={requestPending}>Close</button>
        </header>

        <dl className={styles.context} id={descriptionId}>
          <div><dt>Protected receivable</dt><dd>{receivable}</dd></div>
          <div><dt>Network</dt><dd>Monad testnet</dd></div>
          <div><dt>Role</dt><dd>Participant {role}</dd></div>
        </dl>

        <p className={styles.note}>
          Connecting does not submit a claim. After eligibility is confirmed, Mordant will request
          one typed authorization for this exact claim.
        </p>

        {wallet.view.problem === null ? null : (
          <p className={styles.problem} role="alert">{wallet.view.problem}</p>
        )}

        {injected.length === 0 ? (
          <p className={styles.empty}>
            No wallet was detected in this browser. Install a wallet extension, or use the mobile
            path if it is offered below.
          </p>
        ) : (
          <ul className={styles.wallets}>
            {injected.map((option) => (
              <WalletRow key={option.uid} option={option} onSelect={wallet.connect} busy={requestPending} />
            ))}
          </ul>
        )}

        {walletConnect === null ? null : (
          <section className={styles.mobile} aria-labelledby={`${titleId}-mobile`}>
            <h3 id={`${titleId}-mobile`}>On a phone</h3>
            {wallet.pairingUri === null ? (
              <ul className={styles.wallets}>
                <WalletRow option={walletConnect} onSelect={wallet.connect} busy={requestPending} />
              </ul>
            ) : (
              <div className={styles.pairing}>
                <div className={styles.qr}>
                  <PairingQr uri={wallet.pairingUri} title="WalletConnect pairing code" />
                </div>
                <div className={styles.pairingText}>
                  <p>Scan this with the wallet app holding this participant&rsquo;s address.</p>
                  <button
                    type="button"
                    className={styles.copy}
                    onClick={() => {
                      void navigator.clipboard?.writeText(wallet.pairingUri ?? "");
                      setTransient("Pairing link copied.");
                    }}
                  >
                    Copy pairing link
                  </button>
                </div>
              </div>
            )}
          </section>
        )}

        <p className={styles.status} role="status" aria-live="polite">{announcement}</p>
      </div>
    </div>
  );
}
