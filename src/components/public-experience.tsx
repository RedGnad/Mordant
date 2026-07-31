"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type PointerEvent } from "react";

import { PublicFooter, PublicHeader } from "./public-chrome";
import styles from "./public-experience.module.css";

type PublicProof = {
  actor: string;
  action: string;
  before: string;
  after: string;
  block: number | string;
  deadline: string;
};

const TRANSFORMATION = [
  {
    id: "stable",
    label: "Stable",
    title: "One receivable. One valid position.",
    protection: "Aligned",
  },
  {
    id: "conflict",
    label: "Conflict",
    title: "Two claims. One obligation.",
    protection: "Conflict detected",
  },
  {
    id: "recourse",
    label: "Recourse",
    title: "Responsibility becomes explicit.",
    protection: "Accountable path",
  },
  {
    id: "proof",
    label: "Proof",
    title: "The transition is retained.",
    protection: "Receipt issued",
  },
] as const;

const TRANSFORMATION_SCROLL_THRESHOLDS = [0, 0.15, 0.4, 0.7] as const;

const INTEGRATION_STEPS = [
  {
    label: "Context enters",
    detail: "Asset state + events",
    story: "Authorized receivable context enters without moving funds.",
  },
  {
    label: "Recourse is established",
    detail: "Responsibility + deadline",
    story: "Policy turns an exception into responsibility, a deadline, and a consequence.",
  },
  {
    label: "Action returns",
    detail: "Action + receipt",
    story: "Your team receives the next safe action and a verifiable receipt.",
  },
] as const;

export function PublicExperience({ proof }: { readonly proof: PublicProof }) {
  const [step, setStep] = useState(0);
  const [integrationStep, setIntegrationStep] = useState(0);
  const pageRef = useRef<HTMLDivElement>(null);
  const heroRef = useRef<HTMLElement>(null);
  const transformationRef = useRef<HTMLElement>(null);
  const integrationFlowRef = useRef<HTMLDivElement>(null);
  const integrationPathRef = useRef<SVGPathElement>(null);
  const integrationSignalRef = useRef<SVGGElement>(null);
  const heroScrollFrame = useRef<number | null>(null);
  const scrollFrame = useRef<number | null>(null);
  const integrationScrollFrame = useRef<number | null>(null);
  const integrationMotionFrame = useRef<number | null>(null);
  const integrationMotionProgress = useRef(0);
  const moment = TRANSFORMATION[step];

  useEffect(() => {
    const page = pageRef.current;
    if (page === null) return;
    const chapters = Array.from(page.querySelectorAll<HTMLElement>("[data-reveal]"));
    page.dataset.motionReady = "true";

    if (!("IntersectionObserver" in window) || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      chapters.forEach((chapter) => { chapter.dataset.visible = "true"; });
      return;
    }

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        (entry.target as HTMLElement).dataset.visible = "true";
        observer.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -12%", threshold: 0.08 });
    chapters.forEach((chapter) => observer.observe(chapter));
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const hero = heroRef.current;
    if (hero === null || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const updateHeroParallax = () => {
      heroScrollFrame.current = null;
      const bounds = hero.getBoundingClientRect();
      const progress = Math.min(1, Math.max(0, -bounds.top / Math.max(1, bounds.height)));
      hero.style.setProperty("--symbol-scroll-y", `${progress * -64}px`);
    };

    const onHeroScroll = () => {
      if (heroScrollFrame.current !== null) return;
      heroScrollFrame.current = window.requestAnimationFrame(updateHeroParallax);
    };

    updateHeroParallax();
    window.addEventListener("scroll", onHeroScroll, { passive: true });
    window.addEventListener("resize", onHeroScroll);
    return () => {
      window.removeEventListener("scroll", onHeroScroll);
      window.removeEventListener("resize", onHeroScroll);
      if (heroScrollFrame.current !== null) window.cancelAnimationFrame(heroScrollFrame.current);
    };
  }, []);

  useEffect(() => {
    const section = transformationRef.current;
    if (section === null) return;

    const updateFromScroll = () => {
      scrollFrame.current = null;
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

  useEffect(() => {
    const flow = integrationFlowRef.current;
    if (flow === null) return;

    const updateFromScroll = () => {
      integrationScrollFrame.current = null;
      const bounds = flow.getBoundingClientRect();
      const activeTop = window.innerHeight * 0.78;
      const activeBottom = window.innerHeight * 0.22;
      if (bounds.top > activeTop || bounds.bottom < activeBottom) return;

      const range = activeTop - activeBottom + bounds.height;
      const progress = Math.min(1, Math.max(0, (activeTop - bounds.top) / Math.max(1, range)));
      const nextStep = progress < 0.34 ? 0 : progress < 0.68 ? 1 : 2;
      setIntegrationStep((current) => current === nextStep ? current : nextStep);
    };

    const onScroll = () => {
      if (integrationScrollFrame.current !== null) return;
      integrationScrollFrame.current = window.requestAnimationFrame(updateFromScroll);
    };

    updateFromScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (integrationScrollFrame.current !== null) window.cancelAnimationFrame(integrationScrollFrame.current);
    };
  }, []);

  useEffect(() => {
    const path = integrationPathRef.current;
    const signal = integrationSignalRef.current;
    if (path === null || signal === null) return;

    const targets = [0, 0.633, 1];
    const from = integrationMotionProgress.current;
    const to = targets[integrationStep] ?? 0;
    const length = path.getTotalLength();
    const placeSignal = (progress: number) => {
      const point = path.getPointAtLength(length * progress);
      signal.setAttribute("transform", `translate(${point.x} ${point.y})`);
      integrationMotionProgress.current = progress;
    };

    if (integrationMotionFrame.current !== null) {
      window.cancelAnimationFrame(integrationMotionFrame.current);
    }

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || from === to) {
      placeSignal(to);
      return;
    }

    const startedAt = performance.now();
    const duration = 280 + Math.abs(to - from) * 360;
    const animate = (now: number) => {
      const elapsed = Math.min(1, (now - startedAt) / duration);
      const eased = 1 - Math.pow(1 - elapsed, 3);
      placeSignal(from + ((to - from) * eased));
      if (elapsed < 1) integrationMotionFrame.current = window.requestAnimationFrame(animate);
      else integrationMotionFrame.current = null;
    };
    integrationMotionFrame.current = window.requestAnimationFrame(animate);

    return () => {
      if (integrationMotionFrame.current !== null) {
        window.cancelAnimationFrame(integrationMotionFrame.current);
        integrationMotionFrame.current = null;
      }
    };
  }, [integrationStep]);

  const selectStep = (index: number) => {
    const section = transformationRef.current;
    if (section === null) return;
    const range = Math.max(0, section.offsetHeight - window.innerHeight);
    const threshold = TRANSFORMATION_SCROLL_THRESHOLDS[index] ?? 0;
    const targetProgress = index === 0 ? 0 : Math.min(1, threshold + 0.01);
    const position = section.offsetTop + (range * targetProgress);
    window.scrollTo({ top: position, behavior: "instant" });
    setStep(index);
  };

  const moveHeroSymbol = (event: PointerEvent<HTMLElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 22;
    const y = ((event.clientY - bounds.top) / bounds.height - 0.5) * 14;
    event.currentTarget.style.setProperty("--symbol-x", `${x}px`);
    event.currentTarget.style.setProperty("--symbol-y", `${y}px`);
  };

  const resetHeroSymbol = (event: PointerEvent<HTMLElement>) => {
    event.currentTarget.style.setProperty("--symbol-x", "0px");
    event.currentTarget.style.setProperty("--symbol-y", "0px");
  };

  return (
    <div className={styles.page} ref={pageRef}>
      <a className={styles.skip} href="#content">Skip to content</a>
      <PublicHeader />

      <main id="content">
        <section
          className={styles.hero}
          aria-labelledby="hero-title"
          ref={heroRef}
          onPointerMove={moveHeroSymbol}
          onPointerLeave={resetHeroSymbol}
        >
          <h1 id="hero-title">
            <span className={styles.heroLine}><span>Conflict</span></span>
            <span className={styles.heroLine}>
              <span className={styles.heroPhrase}><span>became</span> <span>recourse.</span></span>
            </span>
          </h1>
          <div className={styles.heroSymbolField} aria-hidden="true">
            <div className={styles.heroSymbolRotation}>
              <svg className={styles.heroSymbol} viewBox="0 0 100 100">
                <rect x="43" width="14" height="100" />
                <rect y="43" width="100" height="14" />
                <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
                <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
              </svg>
            </div>
          </div>
          <p className={styles.heroSupport}>Governed execution and evidence for receivables exceptions.</p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="#product">See how Mordant works</Link>
            <Link className={styles.secondary} href="#integrate">See how it integrates</Link>
          </div>
        </section>

        <section
          className={styles.transformation}
          id="product"
          aria-labelledby="transformation-title"
          data-state={moment.id}
          ref={transformationRef}
        >
          <div className={styles.transformationSticky}>
            <div className={styles.transformationTitle}>
              <h2 id="transformation-title" aria-live="polite">
                <span key={moment.id}>{moment.title}</span>
              </h2>
            </div>

            <div className={styles.scene} aria-label={`Transformation state: ${moment.label}`}>
              <div className={styles.receivableLane}>
                <strong>Receivable</strong>
              </div>

              <div className={styles.claim} aria-hidden={step === 0}>
                <span>Second claim</span>
                <svg className={styles.claimMark} viewBox="0 0 100 100" aria-hidden="true">
                  <rect x="43" width="14" height="100" />
                  <rect y="43" width="100" height="14" />
                  <rect x="43" width="14" height="100" transform="rotate(45 50 50)" />
                  <rect x="43" width="14" height="100" transform="rotate(-45 50 50)" />
                </svg>
              </div>

              <div className={styles.protectionLane}>
                <svg className={styles.protectionRail} viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true">
                  <path className={styles.protectionRailPath} d="M 0 16 L 100 16" vectorEffect="non-scaling-stroke" />
                </svg>
                <strong>Protection</strong>
                <small key={moment.id}>{moment.protection}</small>
              </div>

              <div className={styles.recourseLock} aria-hidden={step < 2}>
                <div><span>Responsible</span><strong>{proof.actor}</strong></div>
                <div><span>Deadline</span><strong>{proof.deadline}</strong></div>
                <div><span>Consequence</span><strong>Protection becomes claimable</strong></div>
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

        <section className={styles.proof} aria-labelledby="proof-title" data-reveal>
          <header>
            <h2 id="proof-title">One receipt. One verifiable transition.</h2>
          </header>
          <dl>
            <div><dt>Actor</dt><dd>{proof.actor}</dd></div>
            <div><dt>Action</dt><dd>{proof.action}</dd></div>
            <div><dt>Before</dt><dd>{proof.before}</dd></div>
            <div><dt>After</dt><dd>{proof.after}</dd></div>
            <div><dt>Block</dt><dd>{proof.block}</dd></div>
          </dl>
          <div className={styles.proofActions}>
            <Link className={styles.proofCta} href="/demo?checkpoint=reveal">Open the complete recorded demo</Link>
          </div>
        </section>

        <section className={styles.integration} id="integrate" aria-labelledby="integration-title" data-reveal>
          <header>
            <h2 id="integration-title">Your platform records the asset. Mordant establishes what happens next.</h2>
          </header>
          <div className={styles.integrationBody}>
            <div className={styles.flow} data-step={integrationStep} aria-label="Interactive integration path" ref={integrationFlowRef}>
              <div className={styles.flowCanvas}>
                <svg className={styles.flowGraphic} viewBox="0 0 1000 180" aria-hidden="true">
                  <defs>
                    <linearGradient id="integration-route-gradient" gradientUnits="userSpaceOnUse" x1="40" y1="0" x2="920" y2="0">
                      <stop offset="0" stopColor="var(--receivable)" />
                      <stop offset="43.18%" stopColor="var(--receivable)" />
                      <stop offset="43.18%" stopColor="var(--protection)" />
                      <stop offset="63.64%" stopColor="var(--protection)" />
                      <stop offset="63.64%" stopColor="var(--action)" />
                      <stop offset="100%" stopColor="var(--action)" />
                    </linearGradient>
                  </defs>
                  <path ref={integrationPathRef} className={styles.flowRoute} d="M40 102H420L500 34H600L710 102H920" />
                  <g ref={integrationSignalRef} className={styles.integrationSignal} transform="translate(40 102)">
                    <rect x="-18" y="-18" width="36" height="36" />
                  </g>
                </svg>
                <p className={styles.integrationStory} aria-live="polite">
                  <span key={integrationStep}>{INTEGRATION_STEPS[integrationStep].story}</span>
                </p>
              </div>
              <div className={styles.integrationStages} aria-label="Integration stages">
                {INTEGRATION_STEPS.map((stage, index) => (
                  <button
                    type="button"
                    key={stage.label}
                    aria-pressed={integrationStep === index}
                    onClick={() => setIntegrationStep(index)}
                    onFocus={() => setIntegrationStep(index)}
                    onPointerEnter={() => setIntegrationStep(index)}
                  >
                    <strong>{stage.label}</strong>
                    <small>{stage.detail}</small>
                  </button>
                ))}
              </div>
            </div>
            <div className={styles.io}>
              <section>
                <h3>Inputs</h3>
                <ul>
                  <li>receivable identity</li>
                  <li>participants and roles</li>
                  <li>protection policy</li>
                  <li>contract events</li>
                </ul>
              </section>
              <section>
                <h3>Outputs</h3>
                <ul>
                  <li>responsibility</li>
                  <li>safe next action</li>
                  <li>economic consequence</li>
                  <li>verifiable evidence</li>
                </ul>
              </section>
            </div>
          </div>
          <div className={styles.integrationExit}>
            <p className={styles.accessNote}>Recorded demo available. Private pilots are permissioned; production access is closed.</p>
            <div>
              <Link className={styles.secondary} href="/workspace">View the product surfaces</Link>
              <Link className={styles.primary} href="/pilot">Apply for a shadow pilot</Link>
            </div>
          </div>
        </section>
      </main>

      <PublicFooter />
    </div>
  );
}
