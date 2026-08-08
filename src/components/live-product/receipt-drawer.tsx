"use client";

import { useCallback, useEffect, useId, useRef, useState } from "react";

import type { LayeredReceipt } from "./live-product-view-model";
import styles from "./receipt-drawer.module.css";

/**
 * The layered proof surface.
 *
 * Three layers, disclosed in order: what was decided, what verifies it, and the
 * raw projection. The previous drawer declared `aria-modal` and implemented none
 * of the contract, and its background was a `var(--paper)` that did not resolve
 * at this route, so on a phone the panel and the page overlapped into an
 * unreadable stack. Both are fixed here: an opaque surface, a real focus trap,
 * Escape, focus restoration and scroll lock.
 */

const FOCUSABLE = 'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])';

function Rows({ rows, mono }: { readonly rows: readonly { label: string; value: string }[]; readonly mono: boolean }) {
  const [copied, setCopied] = useState<string | null>(null);
  return (
    <dl className={mono ? styles.proofRows : styles.decisionRows}>
      {rows.map((row) => (
        <div key={row.label}>
          <dt>{row.label}</dt>
          <dd>
            <span>{row.value}</span>
            {!mono ? null : (
              <button
                type="button"
                className={styles.copy}
                onClick={() => {
                  void navigator.clipboard?.writeText(row.value);
                  setCopied(row.label);
                }}
              >
                {copied === row.label ? "Copied" : "Copy"}
              </button>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function ReceiptDrawer({
  open,
  receipt,
  assetLabel,
  onClose,
}: {
  readonly open: boolean;
  readonly receipt: LayeredReceipt;
  readonly assetLabel: string;
  readonly onClose: () => void;
}) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const [rawOpen, setRawOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    returnFocus.current = document.activeElement as HTMLElement | null;
    panelRef.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus({ preventScroll: true });
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
      returnFocus.current?.focus({ preventScroll: true });
    };
  }, [open]);

  const onKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const nodes = Array.from(panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
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
  }, [onClose]);

  if (!open) return null;

  return (
    <div
      className={styles.backdrop}
      role="presentation"
      data-testid="receipt-backdrop"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      <div
        ref={panelRef}
        className={styles.panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="receipt-drawer"
        onKeyDown={onKeyDown}
      >
        <header className={styles.header}>
          <div>
            <p className={styles.eyebrow}>Layer 1 · Decision</p>
            <h2 id={titleId}>Receipt for {assetLabel}</h2>
          </div>
          <button type="button" className={styles.close} onClick={onClose}>Close</button>
        </header>

        <Rows rows={receipt.summary} mono={false} />

        <section className={styles.layer} aria-labelledby={`${titleId}-verification`}>
          <p className={styles.eyebrow} id={`${titleId}-verification`}>Layer 2 · Verification</p>
          <Rows rows={receipt.technical} mono />
        </section>

        <section className={styles.layer} aria-labelledby={`${titleId}-raw`}>
          <p className={styles.eyebrow} id={`${titleId}-raw`}>Layer 3 · Raw evidence</p>
          <p className={styles.rawContext} data-testid="raw-receipt-context">{receipt.rawContext}</p>
          <button
            type="button"
            className={styles.disclose}
            aria-expanded={rawOpen}
            onClick={() => setRawOpen((value) => !value)}
          >
            {rawOpen ? "Hide the verified projection" : "Show the verified projection"}
          </button>
          {!rawOpen || receipt.raw === null ? null : (
            <pre className={styles.raw} tabIndex={0}>{JSON.stringify(receipt.raw, null, 2)}</pre>
          )}
        </section>
      </div>
    </div>
  );
}
