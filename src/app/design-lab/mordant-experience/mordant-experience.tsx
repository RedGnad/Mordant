"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import styles from "./mordant-experience.module.css";

export type ExperienceStory = {
  sourceScenario: string;
  receivable: {
    amount: string;
    asset: string;
    units: string;
  };
  protection: {
    amount: string;
    asset: string;
  };
  responsible: string;
  deadline: {
    iso: string;
    clock: string;
    full: string;
  };
  modeledResolution: {
    before: string;
    action: string;
    contractAction: string;
    after: string;
    receivableEffect: string;
  };
  technicalRecord: {
    dealId: string;
    actionId: string;
    invoiceRoot: string;
    observation: string;
  };
};

type FrameId = "calm" | "exception" | "isolated" | "participant" | "deadline" | "resolved";
type DominantObject = "truth" | "receivable" | "protection";
type RuptureObject = "protection" | "responsibility" | null;

type ExperienceFrame = {
  id: FrameId;
  surface: string;
  arc: string;
  eyebrow: string;
  title: string;
  support: string;
  receivableLabel: string;
  receivableStatus?: string;
  protectionLabel: string;
  protectionStatus?: string;
  dominant: DominantObject;
  rupture: RuptureObject;
  next: string;
};

const TOTAL_FRAMES = 6;

function experienceFrames(story: ExperienceStory): readonly ExperienceFrame[] {
  return [
    {
      id: "calm",
      surface: "Deal workspace",
      arc: "Scan",
      eyebrow: "Configured starting state",
      title: "The portfolio starts quiet.",
      support: "One receivable. No intervention is due.",
      receivableLabel: "Your receivable",
      receivableStatus: "Funded · outstanding",
      protectionLabel: "Protection",
      protectionStatus: "Active",
      dominant: "receivable",
      rupture: null,
      next: "Let the exception appear",
    },
    {
      id: "exception",
      surface: "Deal workspace",
      arc: "Scan",
      eyebrow: "Configured exception",
      title: "A conflict was detected.",
      support: "Only protection changed. Your receivable is unchanged.",
      receivableLabel: "Your receivable",
      protectionLabel: "Protection",
      dominant: "protection",
      rupture: "protection",
      next: "Isolate this deal",
    },
    {
      id: "isolated",
      surface: "Deal workspace",
      arc: "Isolate → Act",
      eyebrow: "Current truth",
      title: `${story.responsible} must resolve by ${story.deadline.clock}.`,
      support: "Everything else has been removed.",
      receivableLabel: "Your receivable",
      protectionLabel: "Protection",
      protectionStatus: "Cure window open",
      dominant: "truth",
      rupture: "responsibility",
      next: "See the holder view",
    },
    {
      id: "participant",
      surface: "Participant deal room",
      arc: "Reassure → Explain",
      eyebrow: "Your position",
      title: "Nothing you need to do.",
      support: "Your invoice payment is unchanged and remains yours.",
      receivableLabel: "Invoice payment",
      protectionLabel: "Potential protection",
      dominant: "truth",
      rupture: "protection",
      next: "Advance to the deadline",
    },
    {
      id: "deadline",
      surface: "Consequence",
      arc: "Act",
      eyebrow: "Decision point",
      title: `${story.deadline.clock}.`,
      support: "A cure keeps protection active.",
      receivableLabel: "Invoice payment",
      receivableStatus: "Remains yours",
      protectionLabel: "Potential protection",
      dominant: "truth",
      rupture: "responsibility",
      next: "Show the modeled resolution",
    },
    {
      id: "resolved",
      surface: "Modeled resolution",
      arc: "Prove",
      eyebrow: "Modeled outcome",
      title: "A cure would restore protection.",
      support: "The model leaves the receivable unchanged.",
      receivableLabel: "Your receivable",
      protectionLabel: "Protection",
      dominant: "truth",
      rupture: null,
      next: "Open retained record",
    },
  ];
}

function DomainAmount({ amount, asset }: { amount: string; asset: string }) {
  return (
    <p className={styles.amount}>
      {amount} <small>{asset}</small>
    </p>
  );
}

export function MordantExperience({ story }: { story: ExperienceStory }) {
  const frames = experienceFrames(story);
  const [frameIndex, setFrameIndex] = useState(0);
  const [proofOpen, setProofOpen] = useState(false);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const proofTitleRef = useRef<HTMLHeadingElement>(null);
  const proofTriggerRef = useRef<HTMLButtonElement>(null);
  const hasMounted = useRef(false);
  const frame = frames[frameIndex];

  const closeProof = useCallback(() => {
    setProofOpen(false);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => proofTriggerRef.current?.focus({ preventScroll: true }));
    });
  }, []);

  useEffect(() => {
    if (!hasMounted.current) {
      hasMounted.current = true;
      return;
    }

    window.requestAnimationFrame(() => titleRef.current?.focus({ preventScroll: true }));
  }, [frameIndex]);

  useEffect(() => {
    if (!proofOpen) return;

    window.requestAnimationFrame(() => proofTitleRef.current?.focus({ preventScroll: true }));

    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeProof();
    };

    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [closeProof, proofOpen]);

  const goToFrame = (nextIndex: number) => {
    setProofOpen(false);
    setFrameIndex(Math.min(TOTAL_FRAMES - 1, Math.max(0, nextIndex)));
  };

  return (
    <main
      className={styles.page}
      data-testid="mordant-experience"
      data-frame={frame.id}
      data-frame-index={frameIndex + 1}
      data-source-scenario={story.sourceScenario}
    >
      <a className={styles.skipLink} href="#experience-stage">
        Skip to the scenario
      </a>

      <header className={styles.labHeader}>
        <Link className={styles.brand} href="/" aria-label="Mordant — open the product">
          Mordant
        </Link>
        <p className={styles.labName}>Experience study · M-EX1</p>
        <p className={styles.fixture}>One configured deal · no real funds</p>
      </header>

      {proofOpen ? (
        <section
          className={styles.proofStage}
          id="experience-stage"
          data-testid="experience-proof-mode"
          aria-labelledby="experience-proof-title"
        >
          <div className={styles.proofLead}>
            <p className={styles.eyebrow}>Retained record</p>
            <h1 id="experience-proof-title" ref={proofTitleRef} tabIndex={-1}>
              What this walkthrough can establish.
            </h1>
          </div>

          <dl className={styles.trustSummary} data-testid="experience-trust-summary">
            <div>
              <dt>Configured</dt>
              <dd>{story.modeledResolution.before} before the modeled action</dd>
            </div>
            <div>
              <dt>Derived</dt>
              <dd>{story.modeledResolution.after} after the modeled cure</dd>
            </div>
            <div>
              <dt>Not observed</dt>
              <dd>{story.technicalRecord.observation}</dd>
            </div>
            <div>
              <dt>Not established</dt>
              <dd>No external financing, legal priority, insurance, or production safety claim.</dd>
            </div>
          </dl>

          <details className={styles.technicalRecord} data-testid="experience-technical-record">
            <summary>Technical record</summary>
            <dl>
              <div>
                <dt>Scenario</dt>
                <dd>{story.sourceScenario}</dd>
              </div>
              <div>
                <dt>Deal</dt>
                <dd>{story.technicalRecord.dealId}</dd>
              </div>
              <div>
                <dt>Invoice root</dt>
                <dd>{story.technicalRecord.invoiceRoot}</dd>
              </div>
              <div>
                <dt>Modeled action</dt>
                <dd>{story.modeledResolution.action} · {story.modeledResolution.contractAction}</dd>
              </div>
              <div>
                <dt>Action record</dt>
                <dd>{story.technicalRecord.actionId}</dd>
              </div>
              <div>
                <dt>Receivable effect</dt>
                <dd>{story.modeledResolution.receivableEffect}</dd>
              </div>
              <div>
                <dt>Configured holder position</dt>
                <dd>{story.receivable.units} invoice units</dd>
              </div>
            </dl>
          </details>

          <footer className={styles.proofActions}>
            <button type="button" onClick={closeProof}>
              Back to resolution
            </button>
            <Link href="/">Open the deal workspace</Link>
          </footer>
        </section>
      ) : (
        <section
          className={styles.stage}
          id="experience-stage"
          data-testid="experience-stage"
          aria-labelledby="experience-title"
        >
          <header className={styles.stageMeta}>
            <p>
              <strong>{frame.surface}</strong>
              <span>{frame.arc}</span>
            </p>
            <p className={styles.frameCount} aria-label={`Step ${frameIndex + 1} of ${TOTAL_FRAMES}`}>
              {String(frameIndex + 1).padStart(2, "0")} / {String(TOTAL_FRAMES).padStart(2, "0")}
            </p>
          </header>

          <div className={styles.canvas} data-testid="experience-canvas">
            <section
              className={styles.truth}
              data-region="truth"
              data-dominant={frame.dominant === "truth" ? "true" : undefined}
            >
              <p className={styles.eyebrow}>{frame.eyebrow}</p>
              <h1 id="experience-title" ref={titleRef} tabIndex={-1}>
                {frame.title}
              </h1>
              <p className={styles.support} data-testid="experience-support">{frame.support}</p>
            </section>

            <section className={styles.economics} data-region="economics" aria-label="Separate economic domains">
              <article
                className={styles.receivable}
                data-receivable-anchor
                data-testid="experience-receivable"
                data-dominant={frame.dominant === "receivable" ? "true" : undefined}
              >
                <p className={styles.domainLabel}>{frame.receivableLabel}</p>
                <DomainAmount amount={story.receivable.amount} asset={story.receivable.asset} />
                {frame.receivableStatus ? <p className={styles.domainStatus}>{frame.receivableStatus}</p> : null}
              </article>

              <article
                className={styles.protection}
                data-testid="experience-protection"
                data-dominant={frame.dominant === "protection" ? "true" : undefined}
                data-rupture={frame.rupture === "protection" ? "true" : undefined}
              >
                <p className={styles.domainLabel}>{frame.protectionLabel}</p>
                {frame.id === "deadline" ? null : (
                  <DomainAmount amount={story.protection.amount} asset={story.protection.asset} />
                )}
                {frame.protectionStatus ? <p className={styles.domainStatus}>{frame.protectionStatus}</p> : null}
              </article>
            </section>

            {frameIndex >= 2 && frameIndex <= 4 ? (
              <aside
                className={styles.responsibility}
                data-region="responsibility"
                data-rupture={frame.rupture === "responsibility" ? "true" : undefined}
              >
                {frame.id === "isolated" ? (
                  <>
                    <p className={styles.responsibilityLabel}>Your safe next step</p>
                    <strong>Wait</strong>
                    <p>No holder action is available.</p>
                  </>
                ) : null}

                {frame.id === "participant" ? (
                  <>
                    <p className={styles.responsibilityLabel}>Responsible before</p>
                    <strong>{story.responsible}</strong>
                    <time dateTime={story.deadline.iso}>{story.deadline.full}</time>
                    <p>If unresolved, protection may become available.</p>
                  </>
                ) : null}

                {frame.id === "deadline" ? (
                  <>
                    <p className={styles.responsibilityLabel}>Responsible party</p>
                    <strong>{story.responsible}</strong>
                    <p>
                      If unresolved, {story.protection.amount} {story.protection.asset} may become claimable.
                    </p>
                  </>
                ) : null}
              </aside>
            ) : null}
          </div>

          <footer className={styles.transport} aria-label="Scenario controls">
            <button
              type="button"
              className={styles.previous}
              disabled={frameIndex === 0}
              onClick={() => goToFrame(frameIndex - 1)}
            >
              Previous
            </button>

            <progress max={TOTAL_FRAMES} value={frameIndex + 1} aria-label={`Step ${frameIndex + 1} of ${TOTAL_FRAMES}`} />

            {frame.id === "resolved" ? (
              <button
                type="button"
                className={styles.next}
                ref={proofTriggerRef}
                onClick={() => setProofOpen(true)}
              >
                {frame.next}
              </button>
            ) : (
              <button type="button" className={styles.next} onClick={() => goToFrame(frameIndex + 1)}>
                {frame.next}
              </button>
            )}
          </footer>

          <p className="visually-hidden" aria-live="polite" aria-atomic="true">
            Step {frameIndex + 1} of {TOTAL_FRAMES}.
          </p>
        </section>
      )}
    </main>
  );
}
