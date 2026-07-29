"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";

import type { DealAction, DomainAmount, MonetaryDomain } from "@/lib/mordant/product-model";
import type { ReadinessVerdict } from "@/lib/mordant/readiness";

import styles from "./transaction-review.module.css";

const REVIEW_STAGES = [
  "discovered",
  "readiness",
  "simulation",
  "consequence",
  "allowance",
  "signature",
  "submitted",
  "pending",
  "confirmed",
  "reread",
  "evidence",
] as const;

type ReviewStageId = (typeof REVIEW_STAGES)[number];

export const TRANSACTION_FAILURE_MODES = [
  "none",
  "wallet_refusal",
  "wrong_network_account",
  "allowance_balance",
  "estimate_revert",
  "deadline",
  "replaced_transaction",
  "missing_receipt",
  "incoherent_readback",
  "partial_recovery",
] as const;

export type TransactionFailureMode = (typeof TRANSACTION_FAILURE_MODES)[number];
export type TransactionReviewDemoMode = "guided" | "failure-lab";

export interface TransactionReviewProps {
  readonly action: DealAction;
  readonly verdict: ReadinessVerdict;
  readonly onClose: () => void;
  /** Selects a deterministic specimen. It never configures a real wallet or network. */
  readonly initialFailure?: TransactionFailureMode;
  readonly demoMode?: TransactionReviewDemoMode;
}

type FailureSpecimen = {
  readonly label: string;
  readonly stage: ReviewStageId | null;
  readonly title: string;
  readonly detail: string;
  readonly recovery: string;
};

const FAILURE_SPECIMENS: Readonly<Record<TransactionFailureMode, FailureSpecimen>> = {
  none: {
    label: "Successful rehearsal",
    stage: null,
    title: "No injected failure",
    detail: "Every step follows the declared synthetic happy path.",
    recovery: "No recovery specimen is selected.",
  },
  wallet_refusal: {
    label: "Wallet refusal",
    stage: "signature",
    title: "Synthetic signature refused",
    detail: "The specimen records a participant declining the wallet request. Nothing is submitted.",
    recovery: "Review the consequence again, then restart only if the participant chooses to proceed.",
  },
  wrong_network_account: {
    label: "Wrong network or account",
    stage: "readiness",
    title: "Synthetic session does not match",
    detail: "The specimen presents an account or network different from the action's declared context.",
    recovery: "Change to the expected synthetic session, reread readiness, and restart the rehearsal.",
  },
  allowance_balance: {
    label: "Allowance or balance",
    stage: "allowance",
    title: "Synthetic economic precondition failed",
    detail: "The specimen cannot establish the bounded allowance or test-asset balance required by the action.",
    recovery: "Resolve the displayed synthetic allowance or balance deficit, then simulate again.",
  },
  estimate_revert: {
    label: "Estimate or revert",
    stage: "simulation",
    title: "Synthetic simulation reverted",
    detail: "The deterministic estimate specimen returns a contract-revert outcome before signature.",
    recovery: "Inspect the declared call and gate state. Do not ask for a signature until simulation succeeds.",
  },
  deadline: {
    label: "Deadline crossed",
    stage: "signature",
    title: "Synthetic execution window changed",
    detail: "The specimen crosses its deadline between consequence review and signature.",
    recovery: "Refresh time readiness and obtain a newly reviewed action package.",
  },
  replaced_transaction: {
    label: "Replaced transaction",
    stage: "pending",
    title: "Synthetic submission was replaced",
    detail: "The pending specimen is superseded by another synthetic submission reference.",
    recovery: "Follow the replacement reference and reconcile only the terminal receipt.",
  },
  missing_receipt: {
    label: "Missing receipt",
    stage: "confirmed",
    title: "Synthetic receipt is unavailable",
    detail: "The specimen cannot retrieve a receipt that satisfies the required finality.",
    recovery: "Keep the action pending, refresh the receipt source, and do not infer confirmation.",
  },
  incoherent_readback: {
    label: "Incoherent readback",
    stage: "reread",
    title: "Synthetic state does not match the reviewed consequence",
    detail: "The post-confirmation readback differs from the transition declared before signature.",
    recovery: "Escalate the mismatch to protocol operations and preserve both observations.",
  },
  partial_recovery: {
    label: "Partial completion or recovery",
    stage: "evidence",
    title: "Synthetic action requires recovery",
    detail: "A partial downstream result prevents the specimen from recording a coherent terminal evidence set.",
    recovery: "Open a recovery record, assign an owner, and retain the partial evidence without calling it complete.",
  },
};

const STAGE_COPY: Readonly<
  Record<ReviewStageId, { readonly label: string; readonly eyebrow: string; readonly description: string }>
> = {
  discovered: {
    label: "Action discovered",
    eyebrow: "Intent",
    description: "Bind this review to one declared action and its current synthetic model.",
  },
  readiness: {
    label: "Readiness",
    eyebrow: "Five gates",
    description: "Carry forward the canonical readiness verdict without converting unknowns into approval.",
  },
  simulation: {
    label: "Simulation",
    eyebrow: "Preflight",
    description: "Rehearse the declared contract call. No RPC, estimate, or transaction is sent.",
  },
  consequence: {
    label: "Consequence review",
    eyebrow: "Economic effect",
    description: "Expose machine transitions, money domains, unit effects, and irreversibility before signature.",
  },
  allowance: {
    label: "Allowance / approval",
    eyebrow: "Economic boundary",
    description: "State whether a bounded test-asset approval would be required in an executable flow.",
  },
  signature: {
    label: "Signature",
    eyebrow: "Participant boundary",
    description: "Record a synthetic signature decision. This interface never opens a wallet.",
  },
  submitted: {
    label: "Submitted",
    eyebrow: "Synthetic reference",
    description: "Create a local rehearsal reference without broadcasting a transaction.",
  },
  pending: {
    label: "Pending",
    eyebrow: "Finality",
    description: "Keep submission and confirmation distinct while the required finality is unresolved.",
  },
  confirmed: {
    label: "Confirmed",
    eyebrow: "Receipt",
    description: "Record the deterministic receipt specimen; do not infer it from elapsed time.",
  },
  reread: {
    label: "State reread",
    eyebrow: "Coherence",
    description: "Compare the post-confirmation synthetic state with the consequence reviewed earlier.",
  },
  evidence: {
    label: "Evidence recorded",
    eyebrow: "Terminal record",
    description: "Persist source, classification, expected effect, and exceptions as one synthetic record.",
  },
};

type StageFact = {
  readonly label: string;
  readonly value: string;
};

type RecordedFailure = {
  readonly stage: ReviewStageId;
  readonly title: string;
  readonly detail: string;
  readonly recovery: string;
  readonly source: "readiness" | "specimen";
};

function formatRole(value: string): string {
  return value
    .split("_")
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function formatState(value: string): string {
  return value
    .split("_")
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function formatAmount(amount: DomainAmount<MonetaryDomain>): string {
  const scale = 10n ** BigInt(amount.asset.decimals);
  const minorUnits = BigInt(amount.minorUnits);
  const whole = minorUnits / scale;
  const fraction = (minorUnits % scale).toString().padStart(amount.asset.decimals, "0").slice(0, 2);

  return `${whole.toLocaleString("en-US")}.${fraction} ${amount.asset.symbol}`;
}

function transitionCopy(action: DealAction): string {
  const transitions = [
    action.consequence.receivableTransition
      ? `Receivable: ${formatState(action.consequence.receivableTransition.from)} → ${formatState(action.consequence.receivableTransition.to)}`
      : null,
    action.consequence.protectionTransition
      ? `Protection: ${formatState(action.consequence.protectionTransition.from)} → ${formatState(action.consequence.protectionTransition.to)}`
      : null,
  ].filter((value): value is string => value !== null);

  return transitions.length === 0 ? "No machine transition declared" : transitions.join(" · ");
}

function moneyCopy(action: DealAction): string {
  if (action.consequence.monetaryEffects.length === 0) return "No money movement declared";

  return action.consequence.monetaryEffects
    .map((effect) => `${formatState(effect.domain)} · ${formatAmount(effect.amount)} · ${effect.label}`)
    .join(" · ");
}

function requiresAllowance(action: DealAction): boolean {
  const economicGate = action.gates.find((gate) => gate.kind === "economic");
  const gateMentionsAllowance = `${economicGate?.code ?? ""} ${economicGate?.detail ?? ""}`
    .toLowerCase()
    .includes("allowance");

  return (
    gateMentionsAllowance ||
    action.consequence.monetaryEffects.some(
      (effect) => effect.direction === "into_vault" || effect.direction === "into_reserve",
    )
  );
}

function syntheticReference(action: DealAction): string {
  const normalized = action.id.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return `synthetic:review:${normalized || "action"}`;
}

function stageFacts(
  stage: ReviewStageId,
  action: DealAction,
  verdict: ReadinessVerdict,
  approvalRequired: boolean,
): readonly StageFact[] {
  switch (stage) {
    case "discovered":
      return [
        { label: "Action", value: action.label },
        { label: "Declared call", value: action.contractAction },
        { label: "Actor", value: formatRole(action.actorRole) },
      ];
    case "readiness":
      return [
        { label: "Verdict", value: verdict.code.replaceAll("_", " ") },
        { label: "Conclusion", value: verdict.conclusion },
        { label: "Responsible", value: verdict.responsible },
      ];
    case "simulation":
      return [
        { label: "Call specimen", value: action.contractAction },
        { label: "Method", value: "Deterministic local rehearsal; no RPC request" },
        { label: "Result", value: "Declared call shape accepted by the synthetic specimen" },
      ];
    case "consequence":
      return [
        { label: "Summary", value: action.consequence.summary },
        { label: "State", value: transitionCopy(action) },
        { label: "Money", value: moneyCopy(action) },
        {
          label: "Invoice units",
          value:
            action.consequence.receivableUnitsEffect === "none"
              ? "No burn or transfer"
              : "Redeemed units are declared for burn",
        },
        { label: "Reversibility", value: action.consequence.irreversible ? "Declared irreversible" : "Not declared irreversible" },
      ];
    case "allowance":
      return [
        {
          label: "Approval",
          value: approvalRequired
            ? "A bounded test-asset approval would be required before execution"
            : "No separate approval is declared for this action",
        },
        { label: "Scope", value: approvalRequired ? moneyCopy(action) : "Not applicable" },
        { label: "Result", value: "Recorded locally; no allowance is read or written" },
      ];
    case "signature":
      return [
        { label: "Requested role", value: formatRole(action.actorRole) },
        { label: "Payload", value: action.contractAction },
        { label: "Result", value: "Synthetic consent recorded; no wallet opened" },
      ];
    case "submitted":
      return [
        { label: "Reference", value: syntheticReference(action) },
        { label: "Broadcast", value: "None — local rehearsal only" },
      ];
    case "pending":
      return [
        { label: "Required finality", value: formatState(action.requiredFinality) },
        { label: "Status", value: "Deterministic pending specimen recorded" },
      ];
    case "confirmed":
      return [
        { label: "Receipt", value: `${syntheticReference(action)}:receipt` },
        { label: "Finality", value: action.requiredFinality === "none" ? "No finality required" : formatState(action.requiredFinality) },
        { label: "Source", value: "Synthetic transaction-review fixture" },
      ];
    case "reread":
      return [
        { label: "Expected transition", value: transitionCopy(action) },
        { label: "Readback", value: "Synthetic post-state matches the reviewed consequence" },
        { label: "External observation", value: "Not established" },
      ];
    case "evidence":
      return [
        { label: "Evidence class", value: "Derived by Mordant · synthetic specimen" },
        { label: "Record", value: `${syntheticReference(action)}:evidence` },
        { label: "Coverage", value: "Intent, gates, consequence, receipt specimen, and readback" },
      ];
  }
}

function readinessFailure(verdict: ReadinessVerdict): RecordedFailure {
  return {
    stage: "readiness",
    title: verdict.conclusion,
    detail: verdict.cause,
    recovery: verdict.unlock,
    source: "readiness",
  };
}

function specimenFailure(mode: TransactionFailureMode, stage: ReviewStageId): RecordedFailure | null {
  const specimen = FAILURE_SPECIMENS[mode];
  if (specimen.stage !== stage) return null;

  return {
    stage,
    title: specimen.title,
    detail: specimen.detail,
    recovery: specimen.recovery,
    source: "specimen",
  };
}

function stageStatus(
  index: number,
  cursor: number,
  failure: RecordedFailure | null,
): "complete" | "current" | "failed" | "queued" {
  if (failure !== null) {
    const failureIndex = REVIEW_STAGES.indexOf(failure.stage);
    if (index < failureIndex) return "complete";
    if (index === failureIndex) return "failed";
    return "queued";
  }

  if (index < cursor) return "complete";
  if (index === cursor) return "current";
  return "queued";
}

function TransactionReviewSession({
  action,
  verdict,
  onClose,
  initialFailure = "none",
  demoMode = "guided",
}: TransactionReviewProps) {
  const headingId = useId();
  const descriptionId = useId();
  const dialogRef = useRef<HTMLElement>(null);
  const [failureMode, setFailureMode] = useState<TransactionFailureMode>(initialFailure);
  const [cursor, setCursor] = useState(0);
  const [failure, setFailure] = useState<RecordedFailure | null>(null);
  const approvalRequired = useMemo(() => requiresAllowance(action), [action]);
  const complete = cursor >= REVIEW_STAGES.length && failure === null;
  const currentStage = complete ? null : REVIEW_STAGES[cursor];

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    dialogRef.current?.focus();

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }

      if (event.key !== "Tab" || dialogRef.current === null) return;

      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), select:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((element) => !element.hasAttribute("hidden"));

      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable.at(-1)!;
      if (event.shiftKey && (document.activeElement === first || document.activeElement === dialogRef.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus();
    };
  }, [onClose]);

  function reset(nextFailureMode = failureMode) {
    setFailureMode(nextFailureMode);
    setCursor(0);
    setFailure(null);
  }

  function advance() {
    if (currentStage === null) return;

    if (currentStage === "readiness" && verdict.code !== "AVAILABLE_NOW") {
      setFailure(readinessFailure(verdict));
      return;
    }

    const injectedFailure = specimenFailure(failureMode, currentStage);
    if (injectedFailure !== null) {
      setFailure(injectedFailure);
      return;
    }

    setCursor((value) => value + 1);
  }

  const progressLabel = failure
    ? `Stopped at ${STAGE_COPY[failure.stage].label}`
    : complete
      ? "Synthetic rehearsal complete"
      : `Step ${cursor + 1} of ${REVIEW_STAGES.length}`;

  return (
    <div className={styles.backdrop} data-testid="transaction-review">
      <section
        ref={dialogRef}
        className={styles.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        aria-describedby={descriptionId}
        tabIndex={-1}
      >
        <header className={styles.header}>
          <div>
            <p className={styles.kicker}>Synthetic transaction rehearsal</p>
            <h2 id={headingId}>{action.label}</h2>
            <p id={descriptionId} className={styles.disclaimer}>
              No wallet, network request, signature, funds, or transaction is used. Every result below is a deterministic demo specimen.
            </p>
          </div>
          <button className={styles.closeButton} type="button" onClick={onClose} aria-label="Close transaction review">
            Close
          </button>
        </header>

        <div className={styles.body}>
          <aside className={styles.controlRail} aria-label="Rehearsal controls and action summary">
            <div className={styles.modeBlock}>
              <p className={styles.sectionLabel}>{demoMode === "failure-lab" ? "Failure laboratory" : "Rehearsal specimen"}</p>
              <label className={styles.fieldLabel} htmlFor={`${headingId}-failure`}>
                Deterministic outcome
              </label>
              <select
                id={`${headingId}-failure`}
                className={styles.select}
                value={failureMode}
                onChange={(event) => reset(event.target.value as TransactionFailureMode)}
              >
                {TRANSACTION_FAILURE_MODES.map((mode) => (
                  <option key={mode} value={mode}>
                    {FAILURE_SPECIMENS[mode].label}
                  </option>
                ))}
              </select>
              <p className={styles.fieldHelp}>{FAILURE_SPECIMENS[failureMode].detail}</p>
            </div>

            <dl className={styles.actionSummary}>
              <div>
                <dt>Readiness</dt>
                <dd data-verdict={verdict.code}>{verdict.code.replaceAll("_", " ")}</dd>
              </div>
              <div>
                <dt>Actor</dt>
                <dd>{formatRole(action.actorRole)}</dd>
              </div>
              <div>
                <dt>Call</dt>
                <dd className={styles.mono}>{action.contractAction}</dd>
              </div>
              <div>
                <dt>Required finality</dt>
                <dd>{formatState(action.requiredFinality)}</dd>
              </div>
            </dl>

            <div className={styles.consequenceCard}>
              <p className={styles.sectionLabel}>Reviewed consequence</p>
              <p>{action.consequence.summary}</p>
              <p className={styles.compactFact}>{transitionCopy(action)}</p>
              <p className={styles.compactFact}>{moneyCopy(action)}</p>
            </div>
          </aside>

          <div className={styles.pipeline}>
            <div className={styles.progressHeader}>
              <div>
                <p className={styles.sectionLabel}>Persistent execution record</p>
                <p className={styles.progressValue}>{progressLabel}</p>
              </div>
              <span className={styles.demoBadge}>Fixture only</span>
            </div>

            <div className={styles.liveRegion} aria-live="polite" aria-atomic="true">
              {failure ? `${failure.title}. ${failure.recovery}` : progressLabel}
            </div>

            <ol className={styles.stageList}>
              {REVIEW_STAGES.map((stage, index) => {
                const copy = STAGE_COPY[stage];
                const status = stageStatus(index, cursor, failure);
                const facts = stageFacts(stage, action, verdict, approvalRequired);
                const revealFacts = status !== "queued";
                const isFailed = status === "failed" && failure !== null;

                return (
                  <li
                    key={stage}
                    className={styles.stage}
                    data-status={status}
                    data-stage={stage}
                    aria-current={status === "current" ? "step" : undefined}
                  >
                    <div className={styles.stageMarker} aria-hidden="true">
                      {status === "complete" ? "✓" : status === "failed" ? "!" : String(index + 1).padStart(2, "0")}
                    </div>
                    <div className={styles.stageContent}>
                      <div className={styles.stageHeading}>
                        <div>
                          <span className={styles.stageEyebrow}>{copy.eyebrow}</span>
                          <h3>{copy.label}</h3>
                        </div>
                        <span className={styles.statusLabel}>
                          {status === "complete"
                            ? "Recorded"
                            : status === "current"
                              ? "In review"
                              : status === "failed"
                                ? "Stopped"
                                : "Not reached"}
                        </span>
                      </div>
                      <p className={styles.stageDescription}>{copy.description}</p>

                      {isFailed ? (
                        <div className={styles.failurePanel} role="alert">
                          <strong>{failure.title}</strong>
                          <p>{failure.detail}</p>
                          <dl>
                            <div>
                              <dt>Recovery</dt>
                              <dd>{failure.recovery}</dd>
                            </div>
                            <div>
                              <dt>Source</dt>
                              <dd>{failure.source === "readiness" ? "Canonical readiness verdict" : "Selected deterministic specimen"}</dd>
                            </div>
                          </dl>
                        </div>
                      ) : revealFacts ? (
                        <dl className={styles.stageFacts}>
                          {facts.map((fact) => (
                            <div key={`${stage}-${fact.label}`}>
                              <dt>{fact.label}</dt>
                              <dd>{fact.value}</dd>
                            </div>
                          ))}
                        </dl>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ol>

            {complete ? (
              <div className={styles.completionPanel} role="status">
                <strong>Synthetic record complete</strong>
                <p>
                  The rehearsal reached a coherent readback and evidence record. This is not evidence of a real transaction or wallet action.
                </p>
              </div>
            ) : null}
          </div>
        </div>

        <footer className={styles.footer}>
          <p>{failure ? failure.recovery : complete ? "Review the persistent record or run another specimen." : STAGE_COPY[currentStage!].description}</p>
          <div className={styles.footerActions}>
            {(failure || complete || cursor > 0) && (
              <button className={styles.secondaryButton} type="button" onClick={() => reset()}>
                Restart rehearsal
              </button>
            )}
            {!failure && !complete ? (
              <button className={styles.primaryButton} type="button" onClick={advance}>
                {currentStage === "discovered" ? "Begin synthetic review" : `Record ${STAGE_COPY[currentStage!].label.toLowerCase()}`}
              </button>
            ) : null}
          </div>
        </footer>
      </section>
    </div>
  );
}

/**
 * A deliberately non-executing transaction review. The keyed session resets
 * when its declared action or initial specimen changes, while the dialog keeps
 * every reached result visible until the user explicitly closes or restarts it.
 */
export function TransactionReview(props: TransactionReviewProps) {
  return (
    <TransactionReviewSession
      key={`${props.action.id}:${props.initialFailure ?? "none"}:${props.demoMode ?? "guided"}`}
      {...props}
    />
  );
}
