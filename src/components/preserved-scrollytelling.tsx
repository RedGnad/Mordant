"use client";

import { useEffect, useRef, useState } from "react";

import styles from "./public-experience.module.css";

/**
 * Preserved accepted PR30 Stable / Conflict / Recourse / Proof scrollytelling.
 *
 * This is intentionally not mounted by the compressed landing. Its four-state
 * model, three junction marks, scroll thresholds, button mechanics, responsive
 * stepper and reduced-motion CSS preserve the accepted system; only institutional
 * copy was narrowed so conflict detection cannot be read as assigning liability.
 */

export type PreservedScrollytellingProof = Readonly<{
  action: string;
  block: number | string;
}>;

const TRANSFORMATION = [
  {
    id: "stable",
    label: "Stable",
    title: "One receivable. One valid position.",
    protection: "Aligned",
    consequence: "Financing proceeds. Nothing to decide.",
  },
  {
    id: "conflict",
    label: "Conflict",
    title: "Two claims. One obligation.",
    protection: "Conflict suspected",
    consequence: "The workflow does not require either lender to disclose its pledge window to the counterparty.",
  },
  {
    id: "recourse",
    label: "Recourse",
    title: "Policy-defined recourse becomes explicit.",
    protection: "Accountable path",
    consequence: "Approved policy or human review defines the action owner, deadline and consequence.",
  },
  {
    id: "proof",
    label: "Proof",
    title: "The transition is retained.",
    protection: "Receipt issued",
    consequence: "Every step is verifiable after the fact.",
  },
] as const;

const TRANSFORMATION_SCROLL_THRESHOLDS = [0, 0.15, 0.4, 0.7] as const;

/**
 * The sticky scroll scene only runs where it has room. Everywhere else the four
 * states are a stepper in normal flow, which is a different composition rather
 * than the same one shrunk. This query must stay in step with the matching
 * fallback block in the stylesheet.
 */
const STICKY_SCENE = "(min-width: 1280px) and (min-height: 721px)";

const JUNCTION_MARK_CLASSES = [
  styles.claimMarkPrimary,
  styles.claimMarkSatelliteOne,
  styles.claimMarkSatelliteTwo,
] as const;

function Symbol({ className }: { readonly className: string }) {
  return (
    <svg className={className} viewBox="0 0 100 100" aria-hidden="true">
      <rect x="43" width="14" height="100" />
      <rect y="43" width="100" height="14" />
      <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
      <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
    </svg>
  );
}

export function PreservedScrollytelling({ proof }: {
  readonly proof: PreservedScrollytellingProof;
}) {
  const [step, setStep] = useState(0);
  const transformationRef = useRef<HTMLElement>(null);
  const scrollFrame = useRef<number | null>(null);
  const moment = TRANSFORMATION[step];

  useEffect(() => {
    const section = transformationRef.current;
    if (section === null) return;

    const updateFromScroll = () => {
      scrollFrame.current = null;
      // Below the sticky breakpoint the four states are sequential blocks, so
      // scroll position must not drive the selection at all.
      if (!window.matchMedia(STICKY_SCENE).matches) return;
      const bounds = section.getBoundingClientRect();
      const range = Math.max(1, section.offsetHeight - window.innerHeight);
      const progress = Math.min(1, Math.max(0, -bounds.top / range));
      let nextStep = 0;
      TRANSFORMATION_SCROLL_THRESHOLDS.forEach((threshold, index) => {
        if (progress >= threshold) nextStep = index;
      });
      setStep((current) => current === nextStep ? current : nextStep);
    };

    const onScroll = () => {
      if (scrollFrame.current !== null) return;
      scrollFrame.current = window.requestAnimationFrame(updateFromScroll);
    };

    updateFromScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (scrollFrame.current !== null) window.cancelAnimationFrame(scrollFrame.current);
    };
  }, []);

  const selectStep = (index: number) => {
    const section = transformationRef.current;
    if (section === null) return;
    setStep(index);
    if (!window.matchMedia(STICKY_SCENE).matches) return;
    const range = Math.max(0, section.offsetHeight - window.innerHeight);
    const threshold = TRANSFORMATION_SCROLL_THRESHOLDS[index] ?? 0;
    const targetProgress = index === 0 ? 0 : Math.min(1, threshold + 0.01);
    const sectionTop = window.scrollY + section.getBoundingClientRect().top;
    window.scrollTo({ top: sectionTop + (range * targetProgress), behavior: "instant" });
  };

  return (
    <section
      className={styles.transformation}
      id="how"
      aria-labelledby="transformation-title"
      data-state={moment.id}
      ref={transformationRef}
    >
      <div className={styles.transformationSticky}>
        <div className={styles.transformationTitle}>
          <p className={styles.eyebrow}>How it works</p>
          <h2 id="transformation-title" aria-live="polite">
            <span key={moment.id}>{moment.title}</span>
          </h2>
          <p className={styles.transformationConsequence} aria-live="polite">
            <span key={`${moment.id}-consequence`}>{moment.consequence}</span>
          </p>
        </div>

        <div className={styles.scene} aria-label={`Transformation state: ${moment.label}`}>
          <div className={styles.receivableLane}>
            <strong>Receivable</strong>
          </div>

          <div className={styles.claim} aria-hidden={step === 0}>
            <span>Second claim</span>
            {JUNCTION_MARK_CLASSES.map((markClass) => (
              <Symbol className={`${styles.claimMark} ${markClass}`} key={markClass} />
            ))}
          </div>

          <div className={styles.protectionLane}>
            <svg className={styles.protectionRail} viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true">
              <path className={styles.protectionRailPath} d="M 0 16 L 100 16" vectorEffect="non-scaling-stroke" />
            </svg>
            <strong>Protection</strong>
            <small key={moment.id}>{moment.protection}</small>
          </div>

          <div className={styles.recourseLock} aria-hidden={step !== 2}>
            <div><span>Action owner</span><strong>Policy / human review required</strong></div>
            <div><span>Deadline</span><strong>Set by approved policy or human review</strong></div>
            <div><span>Consequence</span><strong>Configured policy determines the cure path</strong></div>
          </div>

          <div className={styles.receiptNode} aria-hidden={step < 3}>
            <span>Receipt</span>
            <strong>{proof.action}</strong>
            <small>Block {proof.block}</small>
          </div>
        </div>

        <nav className={styles.stateControls} aria-label="Transformation states">
          {TRANSFORMATION.map((state, index) => (
            <button
              type="button"
              key={state.id}
              aria-pressed={index === step}
              onClick={() => selectStep(index)}
            >
              {state.label}
            </button>
          ))}
        </nav>
      </div>
    </section>
  );
}
