"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { DirectParticipantExecution } from "./live-product/direct-participant-execution";
import { LiveProduct, type ClaimDraft } from "./live-product/live-product";
import { adaptManagedIntake, type ManagedWorkerView } from "./live-product/managed-intake-adapter";
import {
  ManagedResponseRejected,
  readManagedRun,
  startManagedRun,
  type ManagedWindows,
} from "./live-product/managed-run-client";
import {
  capabilities,
  intakeMode,
  type CapabilitySet,
  type EligibilityView,
  type LiveProductState,
  type LiveProductViewModel,
} from "./live-product/live-product-view-model";
import { WalletProvider } from "./wallet/wallet-provider";

/**
 * Controller for the managed combined intake.
 *
 * It owns only data: eligibility, the launch token, the direct-to-worker
 * submission and the durable poll. Everything visible is decided by the
 * presentation model, so a future intake can reuse the same surface.
 *
 * It shows no outcome wording until the governed decryptor has released a
 * signed Boolean, and it never invents a stage the worker has not reported.
 */

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const POLL_INTERVAL_MS = 2_000;
const MAX_POLLS = 300;
/** A single failed poll is a blip. Only a sustained silence is unavailability. */
const FAILURES_BEFORE_UNAVAILABLE = 3;

const FIELD_KEYS = ["aFrom", "aUntil", "bFrom", "bUntil"] as const;
type FieldKey = (typeof FIELD_KEYS)[number];

const IDLE_ELIGIBILITY: EligibilityView = Object.freeze({
  state: "IDLE", holderAddress: null, chainId: null, gateAddress: null, observedBlock: null, problem: null,
});

type CcpEligibility = Readonly<{
  chainId: number;
  validatorAddress: string;
  gateAddress: string;
  holderAddress: string;
  eligible: boolean;
  observedBlock: number;
}>;

type LiveExecutionProps = Readonly<{
  readonly workerOrigin: string;
  readonly initialRunId: string | null;
  readonly initialCaseCode?: string | null;
  readonly publicTestHolder: string;
  /** Supplied only by the server page after it has evaluated its capability gate. */
  readonly capabilitySet?: CapabilitySet;
  /** Server-supplied and omitted unless WalletConnect is separately qualified. */
  readonly walletConnectProjectId?: string | null;
}>;


function ManagedLiveExecution({ workerOrigin, initialRunId, publicTestHolder, capabilitySet }: Required<Pick<LiveExecutionProps, "workerOrigin" | "initialRunId" | "publicTestHolder">> & Readonly<{ capabilitySet: CapabilitySet }>) {
  const [holder, setHolder] = useState("");
  const [eligibility, setEligibility] = useState<EligibilityView>(IDLE_ELIGIBILITY);
  const [draft, setDraft] = useState<ClaimDraft>({ aFrom: "120", aUntil: "420", bFrom: "220", bUntil: "520" });
  // Kept only by the browser that authored this run. The public worker
  // projection intentionally remains free of plaintext claim windows.
  const [submittedDraft, setSubmittedDraft] = useState<ClaimDraft | null>(null);
  const [invalid, setInvalid] = useState<readonly string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(initialRunId);
  const [view, setView] = useState<ManagedWorkerView | null>(null);
  const [starting, setStarting] = useState(false);
  const [notice, setNotice] = useState<LiveProductViewModel["notice"]>(null);
  const [noticeState, setNoticeState] = useState<LiveProductState | null>(null);
  const [elapsed, setElapsed] = useState<number | null>(null);
  const [restoring, setRestoring] = useState(initialRunId !== null);

  const polls = useRef(0);
  const failures = useRef(0);
  // Seeded in an effect rather than during render: reading the clock while
  // rendering is impure and would differ between server and client.
  const startedAt = useRef<number | null>(null);
  const startingRef = useRef(false);

  const terminal = view?.stage === "ABORTED" || (view?.stage === "COMPLETE" && view.receipt !== null);

  const parse = useCallback((): { windows: ManagedWindows | null; bad: string[]; message: string | null } => {
    const bad: string[] = [];
    const parsed: Partial<Record<FieldKey, number>> = {};
    for (const key of FIELD_KEYS) {
      const raw = draft[key].trim();
      const value = /^\d+$/u.test(raw) ? Number(raw) : Number.NaN;
      if (!Number.isSafeInteger(value) || value < 0) bad.push(key);
      else parsed[key] = value;
    }
    if (bad.length > 0) return { windows: null, bad, message: "Each bound must be a whole number, zero or greater." };
    // Each interval is checked on its own. Participant A is never compared with
    // Participant B here: only the encrypted evaluation may answer that.
    for (const [role, keys] of [["A", ["aFrom", "aUntil"]], ["B", ["bFrom", "bUntil"]]] as const) {
      if (parsed[keys[0]]! >= parsed[keys[1]]!) {
        return { windows: null, bad: [...keys], message: `Participant ${role} must start strictly before it ends.` };
      }
    }
    return {
      windows: {
        participantA: { activeFrom: parsed.aFrom!, activeUntil: parsed.aUntil! },
        participantB: { activeFrom: parsed.bFrom!, activeUntil: parsed.bUntil! },
      },
      bad: [],
      message: null,
    };
  }, [draft]);

  const checkEligibility = useCallback(async (candidate: string) => {
    setEligibility((current) => ({ ...current, state: "CHECKING", problem: null }));
    try {
      const response = await fetch("/api/live-protection/token", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ holderAddress: candidate.trim() }),
        cache: "no-store",
      });
      const body = await response.json() as { eligibility?: CcpEligibility; error?: string };
      if (body.eligibility === undefined) {
        setEligibility({ ...IDLE_ELIGIBILITY, state: "ERROR", problem: body.error ?? "Eligibility could not be checked right now." });
        return;
      }
      const result = body.eligibility;
      setEligibility({
        state: result.eligible ? "VERIFIED" : "REFUSED",
        holderAddress: result.holderAddress,
        chainId: result.chainId,
        gateAddress: result.gateAddress,
        observedBlock: result.observedBlock,
        problem: null,
      });
    } catch {
      setEligibility({ ...IDLE_ELIGIBILITY, state: "ERROR", problem: "Eligibility could not be checked right now." });
    }
  }, []);

  const start = useCallback(async () => {
    if (startingRef.current) return;
    const { windows, bad, message } = parse();
    setInvalid(bad);
    setFormError(message);
    if (windows === null) return;
    startingRef.current = true;
    setStarting(true);
    // Commit and paint the local acknowledgement before token issuance or the
    // worker request can spend several seconds waiting on external services.
    await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    try {
      const outcome = await startManagedRun(eligibility.holderAddress ?? "", windows);
      if (outcome.kind === "BUSY") {
        setNoticeState("BUSY");
        setNotice({
          title: "A private check is already running.",
          body: "One execution slot is available, so this check waits rather than running in parallel. "
            + "The slot opens when the current run completes.",
          retryable: true,
        });
        return;
      }
      if (outcome.kind === "REJECTED") {
        setNoticeState("SERVICE_UNAVAILABLE");
        setNotice({
          title: "The execution response was rejected.",
          body: "No result is shown because the worker projection could not be verified. You may retry the request.",
          retryable: true,
        });
        return;
      }
      if (outcome.kind === "INELIGIBLE") {
        setFormError("This holder is no longer eligible under the active policy.");
        return;
      }
      if (outcome.kind === "FAILED") {
        setFormError(outcome.message);
        return;
      }
      setSubmittedDraft(draft);
      setRunId(outcome.view.runId);
      setView(outcome.view);
      startedAt.current = Date.now();
      window.history.pushState(null, "", `/protection/live?runId=${outcome.view.runId}`);
    } finally {
      startingRef.current = false;
      setStarting(false);
    }
  }, [parse, eligibility.holderAddress, draft]);

  const readRun = useCallback((id: string) => readManagedRun(workerOrigin, id), [workerOrigin]);

  /**
   * A durable run is read once immediately. Without this a completed run
   * announced "evaluation in progress" for a full poll interval, which is the
   * first thing anyone opening a shared run link would have seen.
   */
  useEffect(() => {
    if (runId === null || !RUN_ID.test(runId) || view !== null) return;
    let cancelled = false;
    void (async () => {
      try {
        const next = await readRun(runId);
        if (!cancelled) setView(next);
      } catch (error) {
        if (!cancelled && error instanceof ManagedResponseRejected) {
          setNoticeState("SERVICE_UNAVAILABLE");
          setNotice({
            title: "The execution response was rejected.",
            body: "No result is shown because the durable worker projection could not be verified.",
            retryable: true,
          });
        } else if (!cancelled) {
          failures.current += 1;
        }
      } finally {
        if (!cancelled) setRestoring(false);
      }
    })();
    return () => { cancelled = true; };
  }, [runId, view, readRun]);

  useEffect(() => {
    if (runId === null || !RUN_ID.test(runId) || terminal || noticeState !== null) return;
    let cancelled = false;
    const timer = setInterval(() => {
      void (async () => {
        if (cancelled) return;
        polls.current += 1;
        if (polls.current > MAX_POLLS) { clearInterval(timer); return; }
        try {
          const next = await readRun(runId);
          if (cancelled) return;
          failures.current = 0;
          setView(next);
        } catch (error) {
          if (cancelled) return;
          if (error instanceof ManagedResponseRejected) {
            setNoticeState("SERVICE_UNAVAILABLE");
            setNotice({
              title: "The execution response was rejected.",
              body: "No result is shown because the durable worker projection could not be verified.",
              retryable: true,
            });
            return;
          }
          failures.current += 1;
          if (failures.current >= FAILURES_BEFORE_UNAVAILABLE) {
            setNoticeState("SERVICE_UNAVAILABLE");
            setNotice({
              title: "The execution service did not answer.",
              body: `Run ${runId} is still recorded and this page can resume it. `
                + "The verified evidence for a completed case remains available.",
              retryable: true,
            });
          }
        }
      })();
    }, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(timer); };
  }, [runId, terminal, noticeState, readRun]);

  useEffect(() => {
    if (initialRunId !== null && startedAt.current === null) startedAt.current = Date.now();
  }, [initialRunId]);

  useEffect(() => {
    if (startedAt.current === null || terminal) return;
    const timer = setInterval(() => {
      setElapsed(Math.round((Date.now() - (startedAt.current ?? Date.now())) / 1_000));
    }, 1_000);
    return () => clearInterval(timer);
  }, [terminal]);

  const retry = useCallback(() => {
    failures.current = 0;
    polls.current = 0;
    setNotice(null);
    setNoticeState(null);
  }, []);

  const model = adaptManagedIntake({
    view,
    capabilitySet,
    eligibility,
    wallet: null,
    claimsAuthored: view !== null,
    elapsedSeconds: view === null || terminal ? null : elapsed,
    notice: restoring && view === null && notice === null
      ? { title: "Restoring this run.", body: `Reading the durable state for run ${runId}.`, retryable: false }
      : notice,
    noticeState: restoring && view === null && notice === null ? "RECOVERY_AVAILABLE" : noticeState,
  });

  return (
    <LiveProduct
      model={model}
      draft={draft}
      submittedDraft={submittedDraft}
      invalidFields={invalid}
      formError={formError}
      holderDraft={holder}
      publicTestHolder={publicTestHolder}
      busy={starting}
      actions={{
        onHolderChange: (value) => {
          setHolder(value);
          setEligibility(IDLE_ELIGIBILITY);
        },
        onUsePublicHolder: () => {
          setHolder(publicTestHolder);
          void checkEligibility(publicTestHolder);
        },
        onCheckEligibility: () => void checkEligibility(holder),
        onDraftChange: (key, value) => setDraft((current) => ({ ...current, [key]: value })),
        onStart: () => void start(),
        onRetry: retry,
      }}
    />
  );
}

/**
 * Capability boundary between the already-qualified managed flow and the
 * dormant participant-admission flow. The public page provides the capability
 * set from server-side checks; no browser query or client environment flag can
 * switch intake modes.
 */
export function LiveExecution({
  workerOrigin,
  initialRunId,
  initialCaseCode = null,
  publicTestHolder,
  capabilitySet = capabilities("MANAGED_COMBINED_INTAKE"),
  walletConnectProjectId = null,
}: LiveExecutionProps) {
  const intake = intakeMode(capabilitySet);
  if (intake === "DIRECT_ADMISSION") {
    const qualifiedWalletConnect = capabilitySet.WALLETCONNECT_AVAILABLE ? walletConnectProjectId : null;
    return (
      <WalletProvider walletConnectProjectId={qualifiedWalletConnect}>
        <DirectParticipantExecution
          workerOrigin={workerOrigin}
          initialCaseCode={initialCaseCode}
          publicTestHolder={publicTestHolder}
          capabilitySet={capabilitySet}
        />
      </WalletProvider>
    );
  }

  // The server page currently passes only the managed capability. Any other
  // incomplete future set deliberately degrades to the managed-safe model
  // rather than making a client-side route selectable.
  return (
    <ManagedLiveExecution
      workerOrigin={workerOrigin}
      initialRunId={initialRunId}
      publicTestHolder={publicTestHolder}
      capabilitySet={intake === "MANAGED_COMBINED" ? capabilitySet : capabilities("MANAGED_COMBINED_INTAKE")}
    />
  );
}
