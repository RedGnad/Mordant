"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { AdapterCompatibilityPanel, useAdapterCompatibility } from "./adapter-compatibility-panel";
import { OnchainPanel } from "./onchain-panel";
import { ParticipantAdmission } from "./participant-admission";
import { ReceiptDrawer } from "./receipt-drawer";
import styles from "./live-product.module.css";
import {
  CLEANVERSE_LINE,
  LIVE_CHAPTERS,
  chapterFor,
  chapterIndex,
  formatDeadline,
  type LiveProductViewModel,
} from "./live-product-view-model";

/**
 * The live product surface.
 *
 * Five chapters, in order, with only the current one expanded. Runtime stages
 * and on-chain phases are deliberately not chapters: they live in the execution
 * trace and the receipt, so a judge sees a decision rather than thirty states at
 * equal weight.
 */

export type ClaimDraft = Readonly<{ aFrom: string; aUntil: string; bFrom: string; bUntil: string }>;

export type LiveProductActions = Readonly<{
  onHolderChange?: (value: string) => void;
  onUsePublicHolder?: () => void;
  onCheckEligibility?: (role?: "A" | "B") => void;
  onDraftChange?: (key: keyof ClaimDraft, value: string) => void;
  onStart?: () => void;
  onConnectWallet?: (role: "A" | "B") => void;
  onSwitchNetwork?: () => void;
  onAuthorizeClaim?: (role: "A" | "B") => void;
  onDirectDraftChange?: (key: "activeFrom" | "activeUntil", value: string) => void;
  onContinueAsParticipantB?: () => void;
  onDisconnect?: () => void;
  onRetry?: () => void;
}>;

function shorten(value: string | null, lead = 10, tail = 8): string {
  if (value === null) return "not present";
  return value.length <= lead + tail + 1 ? value : `${value.slice(0, lead)}…${value.slice(-tail)}`;
}

/** Two claims on one axis, so an overlap is an economic picture rather than four numbers. */
function ClaimTimeline({ a, b, reveal }: {
  readonly a: readonly [number, number] | null;
  readonly b: readonly [number, number] | null;
  readonly reveal: "none" | "conflict" | "cleared";
}) {
  if (a === null || b === null) return null;
  const min = Math.min(a[0], b[0]);
  const max = Math.max(a[1], b[1]);
  const span = Math.max(1, max - min);
  const bar = (range: readonly [number, number]) => ({
    marginInlineStart: `${((range[0] - min) / span) * 100}%`,
    inlineSize: `${((range[1] - range[0]) / span) * 100}%`,
  });

  return (
    <div className={styles.timeline} data-testid="claim-timeline" data-reveal={reveal} aria-hidden="true">
      <div className={styles.timelineTrack}><span className={styles.timelineBarA} style={bar(a)} /></div>
      <div className={styles.timelineTrack}><span className={styles.timelineBarB} style={bar(b)} /></div>
    </div>
  );
}

function ChapterRail({ current }: { readonly current: number }) {
  return (
    <ol className={styles.chapterRail} aria-label="Live product chapters">
      {LIVE_CHAPTERS.map((chapter, index) => (
        <li
          key={chapter.id}
          data-state={index < current ? "done" : index === current ? "current" : "pending"}
          aria-current={index === current ? "step" : undefined}
        >
          <span className={styles.chapterMarker} aria-hidden="true">
            {index < current ? "✓" : chapter.ordinal}
          </span>
          <span className={styles.chapterTitle}>{chapter.title}</span>
        </li>
      ))}
    </ol>
  );
}

export function LiveProduct({
  model,
  draft,
  invalidFields,
  formError,
  holderDraft,
  publicTestHolder,
  actions,
  busy = false,
}: {
  readonly model: LiveProductViewModel;
  /** The two-claim draft belongs solely to the managed combined intake. */
  readonly draft: ClaimDraft | null;
  readonly invalidFields: readonly string[];
  readonly formError: string | null;
  readonly holderDraft: string;
  readonly publicTestHolder: string;
  readonly actions: LiveProductActions;
  readonly busy?: boolean;
}) {
  const [receiptOpen, setReceiptOpen] = useState(false);
  const [traceOpen, setTraceOpen] = useState(false);
  const chapter = chapterFor(model.state);
  const statusRef = useRef<HTMLElement>(null);
  const previousChapter = useRef(chapter);
  const current = chapterIndex(chapter);
  const released = model.release !== null;
  const adapterCompatibility = useAdapterCompatibility(released);
  const conflict = model.release?.conflict === true;
  const activeStage = model.stages.find((stage) => stage.progress === "active") ?? null;
  const completedStageCount = model.stages.filter((stage) => stage.progress === "done").length;
  const visiblyWorking = busy
    || model.eligibility.state === "CHECKING"
    || model.state === "BUSY"
    || (chapter === "DECIDE" && !released && model.notice === null);
  const statusMode = model.notice !== null ? "attention" : visiblyWorking ? "active" : released ? "complete" : "ready";
  const statusMessage = model.notice !== null
    ? model.notice.title
    : busy && chapter === "AUTHORIZE"
      ? "Creating the case and preparing the secure execution."
      : model.eligibility.state === "CHECKING"
        ? "Reading the active A-Pass policy on Monad testnet."
        : chapter === "DECIDE"
          ? activeStage?.detail ?? "The encrypted execution is advancing through its fixed sequence."
          : chapter === "ACT"
            ? "The governed result is available. Review the case state and configured next decision."
            : chapter === "PROVE"
              ? "The receipt is sealed and ready to inspect."
              : chapter === "AUTHORIZE"
                ? "The participant claims are ready for authorization."
                : "Confirm participant eligibility before a claim enters the case.";
  const deadline = useMemo(
    () => formatDeadline(model.decisionRail?.deadlineIso ?? null),
    [model.decisionRail?.deadlineIso],
  );

  useEffect(() => {
    if (previousChapter.current === chapter) return;
    previousChapter.current = chapter;
    const frame = window.requestAnimationFrame(() => {
      statusRef.current?.scrollIntoView({
        block: "start",
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [chapter]);

  const claimRange = (from: string, until: string): readonly [number, number] | null => {
    const start = Number(from);
    const end = Number(until);
    return Number.isSafeInteger(start) && Number.isSafeInteger(end) && start < end ? [start, end] : null;
  };

  const notice = model.notice;
  // Once the worker has created a run, its public projection deliberately does
  // not carry the private windows. Local defaults or a stale authoring draft
  // must never be used to reconstruct geometry for that durable run.
  const managedDraft = model.intake === "MANAGED_COMBINED" && model.runId === null ? draft : null;
  const managedRunKeepsInputsPrivate = model.intake === "MANAGED_COMBINED" && model.runId !== null;

  return (
    <div className={styles.product} data-state={model.state} data-chapter={chapter}>
      {/* The case bar and the Cleanverse line are always present: an arriving
          judge learns the asset, the network and the division of responsibility
          before anything else. */}
      <header className={styles.caseBar}>
        <div className={styles.caseAsset}>
          <p className={styles.eyebrow}>Cleanverse provenance</p>
          <h1>{model.assetLabel}</h1>
        </div>
        <dl className={styles.caseFacts}>
          <div><dt>Network</dt><dd>Monad testnet</dd></div>
          <div>
            <dt>Protected</dt>
            <dd>{model.protectedAmount?.formatted} <small>{model.protectedAmount?.symbol}</small></dd>
          </div>
          {model.runId === null ? null : <div><dt>Run</dt><dd className={styles.mono}>{shorten(model.runId, 8, 6)}</dd></div>}
        </dl>
      </header>

      <details className={styles.productScope}>
        <summary>Cleanverse verifies provenance and eligibility. Mordant decides conflict only.</summary>
        <p>{CLEANVERSE_LINE}</p>
      </details>

      <ChapterRail current={current} />

      <section
        ref={statusRef}
        className={styles.statusBar}
        data-status={statusMode}
        data-testid="live-status"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        <span className={styles.statusMark} aria-hidden="true"><span /></span>
        <div className={styles.statusCopy}>
          <p>Step {current + 1} of {LIVE_CHAPTERS.length} · {LIVE_CHAPTERS[current]?.title}</p>
          <strong>{statusMessage}</strong>
        </div>
        {model.elapsedSeconds === null ? null : (
          <span className={styles.statusElapsed} data-testid="elapsed" aria-hidden="true">
            {model.elapsedSeconds}s elapsed
          </span>
        )}
      </section>

      <div className={styles.chapterFrame} aria-busy={visiblyWorking}>

      {notice === null ? null : (
        <section className={styles.notice} data-kind={model.state} aria-live="polite">
          <h2>{notice.title}</h2>
          <p>{notice.body}</p>
          {!notice.retryable || actions.onRetry === undefined ? null : (
            <button type="button" className={styles.secondary} onClick={actions.onRetry}>Try again</button>
          )}
        </section>
      )}

      {/* ------------------------------------------------------------ 1 VERIFY */}
      {chapter !== "VERIFY" || notice !== null ? null : (
        <section className={styles.chapter} aria-labelledby="chapter-verify">
          {model.intake === "DIRECT_ADMISSION" && model.directAdmission !== null ? (
            <>
              <h2 id="chapter-verify" className={styles.chapterHeading}>Verify this participant’s A-Pass.</h2>
              <p className={styles.lede}>
                Connect the wallet for this role, then explicitly read its A-Pass verdict on Monad testnet.
                No participant claim can be authorized before that read succeeds.
              </p>
              <ParticipantAdmission
                admission={model.directAdmission}
                busy={busy}
                actions={{
                  onConnectWallet: actions.onConnectWallet,
                  onSwitchNetwork: actions.onSwitchNetwork,
                  onCheckEligibility: actions.onCheckEligibility,
                  onDisconnect: actions.onDisconnect,
                }}
              />
            </>
          ) : (
            <>
              <h2 id="chapter-verify" className={styles.chapterHeading}>
                Who is allowed to take part in this case?
              </h2>
              <p className={styles.lede}>
                Cleanverse holds the A-Pass policy on Monad testnet. Mordant reads its verdict for the address
                you enter. Entering an address checks that address; it does not claim you own it.
              </p>

              {model.eligibility.problem === null ? null : (
                <p className={styles.error} role="alert">{model.eligibility.problem}</p>
              )}
              {model.state !== "ELIGIBILITY_REFUSED" ? null : (
                <p className={styles.error} role="alert">
                  This holder is not admitted by the active policy, so no check can start for it.
                </p>
              )}

              <div className={styles.field}>
                <label htmlFor="ccp-holder">Holder address</label>
                <input
                  id="ccp-holder"
                  type="text"
                  inputMode="text"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="0x..."
                  value={holderDraft}
                  disabled={model.eligibility.state === "CHECKING"}
                  onChange={(event) => actions.onHolderChange?.(event.target.value)}
                />
              </div>

              <div className={styles.testHolder}>
                <p>A Cleanverse UAT A-Pass holder is published for testing this policy.</p>
                <code>{publicTestHolder}</code>
                <button
                  type="button"
                  className={styles.secondary}
                  disabled={model.eligibility.state === "CHECKING"}
                  onClick={() => actions.onUsePublicHolder?.()}
                >
                  Use the public test holder
                </button>
              </div>

              {model.eligibility.state !== "VERIFIED" ? null : (
                <p className={styles.verified} data-testid="eligibility-verified">
                  A-Pass verified · chain {model.eligibility.chainId} · gate {shorten(model.eligibility.gateAddress)}
                  {" "}· block {model.eligibility.observedBlock}
                </p>
              )}

              <button
                type="button"
                className={styles.primary}
                disabled={model.eligibility.state === "CHECKING" || holderDraft.trim() === ""}
                onClick={() => actions.onCheckEligibility?.()}
              >
                {model.eligibility.state === "CHECKING" ? "Checking A-Pass eligibility" : "Check A-Pass eligibility"}
              </button>
            </>
          )}
        </section>
      )}

      {/* ------------------------------------------------------------ 2 AUTHORIZE */}
      {chapter !== "AUTHORIZE" || notice !== null ? null : (
        <section className={styles.chapter} aria-labelledby="chapter-authorize">
          <h2 id="chapter-authorize" className={styles.chapterHeading}>
            Two private claims on the same receivable.
          </h2>
          <p className={styles.lede}>
            Each participant holds a pledge with its own active interval. The workflow does not require
            either lender to disclose its pledge window to the counterparty.
          </p>

          {managedDraft === null ? null : (
            <ClaimTimeline
              a={claimRange(managedDraft.aFrom, managedDraft.aUntil)}
              b={claimRange(managedDraft.bFrom, managedDraft.bUntil)}
              reveal="none"
            />
          )}

          {model.intake !== "DIRECT_ADMISSION" || model.directAdmission === null ? null : (
            <ParticipantAdmission
              admission={model.directAdmission}
              busy={busy}
              actions={{
                onConnectWallet: actions.onConnectWallet,
                onSwitchNetwork: actions.onSwitchNetwork,
                onCheckEligibility: actions.onCheckEligibility,
                onAuthorizeClaim: actions.onAuthorizeClaim,
                onDraftChange: actions.onDirectDraftChange,
                onContinueAsParticipantB: actions.onContinueAsParticipantB,
                onDisconnect: actions.onDisconnect,
              }}
            />
          )}

          {!managedRunKeepsInputsPrivate ? null : (
            <p className={styles.privacy} data-testid="managed-private-inputs-unavailable">
              Private claim windows are not retained in this public projection.
            </p>
          )}

          {model.intake !== "MANAGED_COMBINED" || managedDraft === null ? null : (
          <div className={styles.claims}>
            {(["A", "B"] as const).map((role) => {
              const fromKey = role === "A" ? "aFrom" : "bFrom";
              const untilKey = role === "A" ? "aUntil" : "bUntil";
              const claim = role === "A" ? model.claimA : model.claimB;
              return (
                <article key={role} className={styles.claim} data-role={role}>
                  <p className={styles.eyebrow}>Participant {role}</p>
                  <strong>{role === "A" ? "Already financed it" : "Is about to finance it"}</strong>
                  {model.intake === "MANAGED_COMBINED" ? null : (
                    <p className={styles.claimWallet}>
                      {claim.wallet === null ? "No wallet bound yet" : shorten(claim.wallet)}
                    </p>
                  )}
                  <div className={styles.claimFields}>
                    <div className={styles.field}>
                      <label htmlFor={`live-${fromKey}`}>Active from</label>
                      <input
                        id={`live-${fromKey}`}
                        type="text"
                        inputMode="numeric"
                        autoComplete="off"
                        value={managedDraft[fromKey]}
                        aria-invalid={invalidFields.includes(fromKey)}
                        disabled={busy}
                        onChange={(event) => actions.onDraftChange?.(fromKey, event.target.value)}
                      />
                    </div>
                    <div className={styles.field}>
                      <label htmlFor={`live-${untilKey}`}>Active until</label>
                      <input
                        id={`live-${untilKey}`}
                        type="text"
                        inputMode="numeric"
                        autoComplete="off"
                        value={managedDraft[untilKey]}
                        aria-invalid={invalidFields.includes(untilKey)}
                        disabled={busy}
                        onChange={(event) => actions.onDraftChange?.(untilKey, event.target.value)}
                      />
                    </div>
                  </div>
                  {model.intake === "MANAGED_COMBINED" ? null : (
                    <p className={styles.privacy}>{claim.privacyNote}</p>
                  )}
                </article>
              );
            })}
          </div>
          )}

          {formError === null ? null : <p className={styles.error} role="alert">{formError}</p>}

          <details className={styles.scopeDetails}>
            <summary>Privacy and execution scope · no funds or receivable move</summary>
            <p className={styles.disclosure} data-testid="intake-disclosure">{model.intakeDisclosure}</p>
            {model.intake !== "MANAGED_COMBINED" ? null : (
              <p className={styles.privacy}>{model.claimA.privacyNote}</p>
            )}
            <p className={styles.privacy}>
              Authorizing a claim does not transfer funds and does not move the receivable.
            </p>
          </details>

          {model.intake !== "MANAGED_COMBINED" || managedDraft === null ? null : (
            <button type="button" className={styles.primary} disabled={busy} onClick={actions.onStart}>
              {busy ? "Starting the confidential check" : "Run the confidential check"}
            </button>
          )}
        </section>
      )}

      {/* ------------------------------------------------------------ 3 DECIDE */}
      {chapter !== "DECIDE" || notice !== null ? null : (
        <section className={styles.chapter} aria-labelledby="chapter-decide">
          <h2 id="chapter-decide" className={styles.chapterHeading}>Deciding privately.</h2>
          <p className={styles.waitFact}>
            No result exists until the governed decryptor releases a signed Boolean.
            {model.expectation === null ? "" : ` ${model.expectation}`}
          </p>

          <div className={styles.executionProgress} data-testid="execution-progress">
            <div className={styles.executionTrack} aria-hidden="true">
              {model.stages.map((stage) => <span key={stage.id} data-progress={stage.progress} />)}
            </div>
            <p>
              <strong>{completedStageCount} of {model.stages.length} secure stages observed</strong>
              <span>{activeStage?.label ?? "Waiting for governed release"}</span>
            </p>
          </div>

          {!managedRunKeepsInputsPrivate ? null : (
            <p className={styles.privacy} data-testid="managed-private-inputs-unavailable">
              Private claim windows are not retained in this public projection.
            </p>
          )}

          <button
            type="button"
            className={styles.disclose}
            aria-expanded={traceOpen}
            onClick={() => setTraceOpen((value) => !value)}
          >
            {traceOpen ? "Hide the execution trace" : "Show the execution trace"}
          </button>
          {!traceOpen ? null : (
            <ol className={styles.trace} data-testid="execution-trace">
              {model.stages.map((stage) => (
                <li key={stage.id} data-progress={stage.progress}>{stage.label}</li>
              ))}
            </ol>
          )}
        </section>
      )}

      {/* ------------------------------------------------------------ 4 ACT */}
      {(chapter !== "ACT" && chapter !== "PROVE") || notice !== null || !released ? null : (
        <section
          className={styles.reveal}
          data-outcome={conflict ? "conflict" : "cleared"}
          aria-labelledby="chapter-act"
          data-testid="reveal"
        >
          <p className={styles.eyebrow}>Governed result</p>
          <h2 id="chapter-act" className={styles.revealHeading}>
            {conflict ? "Conflict confirmed." : "No conflict."}
          </h2>
          <p className={styles.revealLede}>
            {conflict
              ? "The governed result establishes only that the private claim windows conflict. The original receivable remains outstanding and intact."
              : "The governed result establishes only that the private claim windows do not conflict. The configured policy assigned no reserve."}
          </p>

          {!managedRunKeepsInputsPrivate ? null : (
            <p className={styles.privacy} data-testid="managed-private-inputs-unavailable">
              Private claim windows are not retained in this public projection.
            </p>
          )}

          {model.decisionRail === null ? null : (
            <dl className={styles.decisionRail} data-testid="decision-rail">
              <div>
                <dt>Next decision</dt>
                <dd>{model.decisionRail.nextDecision}</dd>
              </div>
              <div>
                <dt>Action owner</dt>
                <dd>{model.decisionRail.responsibleNow ?? "No action owner required."}</dd>
              </div>
              <div>
                <dt>Policy deadline</dt>
                <dd data-testid="deadline">
                  {deadline === null
                    ? model.decisionRail.deadlineNote ?? "No deadline applies."
                    : `${deadline.absolute} · ${deadline.relative}`}
                </dd>
              </div>
              <div>
                <dt>Consequence</dt>
                <dd>{model.decisionRail.consequence}</dd>
              </div>
            </dl>
          )}

          {conflict ? null : (
            <p className={styles.privacy}>
              Financing may continue subject to the rest of your workflow. This is not a credit approval.
            </p>
          )}

          <OnchainPanel view={model.onchain} />
          <AdapterCompatibilityPanel load={adapterCompatibility} placement="ACT" />

          {model.receipt === null || chapter === "PROVE" ? null : (
            <button type="button" className={styles.primary} onClick={() => setReceiptOpen(true)}>
              Open receipt
            </button>
          )}
        </section>
      )}

      {/* ------------------------------------------------------------ 5 PROVE */}
      {chapter !== "PROVE" || notice !== null || model.receipt === null ? null : (
        <section className={styles.chapter} aria-labelledby="chapter-prove" data-testid="prove">
          <p className={styles.eyebrow}>Receipt sealed</p>
          <h2 id="chapter-prove" className={styles.chapterHeading}>
            Every step of this decision is verifiable.
          </h2>
          <dl className={styles.proveRows}>
            {model.receipt.summary.slice(0, 4).map((row) => (
              <div key={row.label}><dt>{row.label}</dt><dd>{row.value}</dd></div>
            ))}
          </dl>
          <AdapterCompatibilityPanel load={adapterCompatibility} placement="PROVE" />
          <button type="button" className={styles.primary} onClick={() => setReceiptOpen(true)}>
            Open the full receipt
          </button>
        </section>
      )}

      {model.receipt === null ? null : (
        <ReceiptDrawer
          open={receiptOpen}
          receipt={model.receipt}
          assetLabel={model.assetLabel}
          onClose={() => setReceiptOpen(false)}
        />
      )}
      </div>
    </div>
  );
}
