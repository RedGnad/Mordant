"use client";

import { useEffect, useState } from "react";

import {
  parseAdapterCompatibilityReport,
  type AdapterCompatibilityReport,
} from "./adapter-compatibility-client";
import styles from "./adapter-compatibility-panel.module.css";

export type AdapterCompatibilityLoad = Readonly<{
  state: "IDLE" | "LOADING" | "VERIFIED" | "UNAVAILABLE";
  report: AdapterCompatibilityReport | null;
}>;

const IDLE: AdapterCompatibilityLoad = Object.freeze({ state: "IDLE", report: null });

function compact(value: string): string {
  return value.length <= 22 ? value : `${value.slice(0, 12)}…${value.slice(-8)}`;
}

/**
 * One passive GET after a governed release. It is intentionally not a poll,
 * action, signature request or transaction preparation. A malformed answer is
 * indistinguishable from an unavailable report in the presentation.
 */
export function useAdapterCompatibility(enabled: boolean): AdapterCompatibilityLoad {
  const [load, setLoad] = useState<AdapterCompatibilityLoad>(IDLE);

  useEffect(() => {
    if (!enabled) {
      setLoad(IDLE);
      return;
    }
    const controller = new AbortController();
    setLoad(Object.freeze({ state: "LOADING", report: null }));
    void (async () => {
      try {
        const response = await fetch("/api/live-protection/recourse-compatibility", {
          method: "GET",
          cache: "no-store",
          signal: controller.signal,
        });
        let body: unknown;
        try {
          body = await response.json();
        } catch {
          body = null;
        }
        const report = response.ok ? parseAdapterCompatibilityReport(body) : null;
        if (!controller.signal.aborted) {
          setLoad(report === null
            ? Object.freeze({ state: "UNAVAILABLE", report: null })
            : Object.freeze({ state: "VERIFIED", report }));
        }
      } catch {
        if (!controller.signal.aborted) setLoad(Object.freeze({ state: "UNAVAILABLE", report: null }));
      }
    })();
    return () => controller.abort();
  }, [enabled]);

  return load;
}

/** A read-only record of canonical Adapter V2 compatibility—not a bridge control. */
export function AdapterCompatibilityPanel({
  load,
  placement,
}: {
  readonly load: AdapterCompatibilityLoad;
  readonly placement: "ACT" | "PROVE";
}) {
  if (load.state === "IDLE") return null;
  if (load.state !== "VERIFIED" || load.report === null) {
    return (
      <section className={styles.panel} data-status={load.state.toLowerCase()} data-testid="adapter-compatibility">
        <p className={styles.eyebrow}>Adapter V2 · read-only preflight</p>
        <p className={styles.status}>
          {load.state === "LOADING"
            ? "Checking the public Monad testnet compatibility report. No transaction can be sent from this screen."
            : "The Adapter V2 compatibility report is unavailable. On-chain recourse remains disconnected."}
        </p>
      </section>
    );
  }

  const { adapter, participants, pins, retainedVector } = load.report;
  return (
    <section className={styles.panel} data-status="verified" data-placement={placement} data-testid="adapter-compatibility">
      <p className={styles.eyebrow}>Adapter V2 · verified read-only preflight</p>
      <p className={styles.status}>Canonical compatibility is verified on Monad testnet. Settlement remains disconnected here.</p>
      <dl className={styles.rows}>
        <div><dt>Adapter</dt><dd>{compact(adapter.address)} · chain {adapter.chainId}</dd></div>
        <div><dt>Code / roles</dt><dd>{compact(adapter.codeHash)} · holder {adapter.roleHolder}, facility {adapter.roleFacility}</dd></div>
        <div><dt>Reserve</dt><dd>{adapter.availableReserve} atomic available · {adapter.openReserved} open · {adapter.entitledUnpaid} unpaid</dd></div>
        <div><dt>Eligibility</dt><dd>Holder A, Holder B and facility verified; excluded controls remain outside the canonical roles</dd></div>
        <div><dt>Participants</dt><dd>{compact(participants.holderA)} · {compact(participants.holderB)}</dd></div>
        <div><dt>Retained digest test vector</dt><dd>{compact(retainedVector.governedResultDigest)} · historical vector, not this case</dd></div>
        <div><dt>Digest parity</dt><dd>{compact(retainedVector.typedDataDigest)} · {compact(retainedVector.structHash)}</dd></div>
        <div><dt>Authority pin</dt><dd>{compact(pins.governedReleaseAuthorityId)}</dd></div>
      </dl>
    </section>
  );
}
