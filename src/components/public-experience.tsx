"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

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

const INTEGRATION_STEPS = [
  {
    label: "Your platform",
    detail: "Asset state + events",
    story: "Authorized receivable context enters without moving funds.",
  },
  {
    label: "Mordant",
    detail: "Responsibility + deadline",
    story: "Policy turns an exception into responsibility, a deadline, and a consequence.",
  },
  {
    label: "Your operations",
    detail: "Action + receipt",
    story: "Your team receives the next safe action and a verifiable receipt.",
  },
] as const;

export function PublicExperience({ proof }: { readonly proof: PublicProof }) {
  const [step, setStep] = useState(0);
  const [integrationStep, setIntegrationStep] = useState(1);
  const pageRef = useRef<HTMLDivElement>(null);
  const transformationRef = useRef<HTMLElement>(null);
  const scrollFrame = useRef<number | null>(null);
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
    const section = transformationRef.current;
    if (section === null) return;

    const updateFromScroll = () => {
      scrollFrame.current = null;
      const bounds = section.getBoundingClientRect();
      const range = Math.max(1, section.offsetHeight - window.innerHeight);
      const progress = Math.min(1, Math.max(0, -bounds.top / range));
      const nextStep = Math.min(TRANSFORMATION.length - 1, Math.floor(progress * TRANSFORMATION.length));
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
    const range = Math.max(0, section.offsetHeight - window.innerHeight);
    const position = section.offsetTop + (range * index / (TRANSFORMATION.length - 1));
    window.scrollTo({ top: position, behavior: "instant" });
    setStep(index);
  };

  return (
    <div className={styles.page} ref={pageRef}>
      <a className={styles.skip} href="#content">Skip to content</a>
      <PublicHeader />

      <main id="content">
        <section className={styles.hero} aria-labelledby="hero-title">
          <p className={styles.heroCategory}>Recourse infrastructure / tokenized receivables</p>
          <h1 id="hero-title">
            <span>Conflict</span>
            <span>becomes recourse.</span>
          </h1>
          <p className={styles.heroSupport}>Mordant establishes responsibility, deadline, consequence, and proof.</p>
          <p className={styles.heroAudience}>For credit / operations teams</p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="#product">See the transformation</Link>
            <Link className={styles.secondary} href="#integrate">Evaluate the integration</Link>
          </div>
          <div className={styles.heroSeed} aria-hidden="true">
            <span>Receivable / stable</span>
            <i />
            <span>Protection / aligned</span>
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
            <header className={styles.transformationHeader}>
              <p>Conflict / accountable recourse</p>
              <span aria-live="polite">{moment.label}</span>
            </header>

            <div className={styles.transformationTitle}>
              <h2 id="transformation-title" aria-live="polite">{moment.title}</h2>
              <p>Receivable remains unchanged.</p>
            </div>

            <div className={styles.scene} aria-label={`Transformation state: ${moment.label}`}>
              <div className={styles.receivableLane}>
                <span>Stable anchor</span>
                <strong>Receivable</strong>
                <small>Outstanding</small>
              </div>

              <div className={styles.claim} aria-hidden={step === 0}>
                <span>Second claim</span>
              </div>

              <div className={styles.protectionLane}>
                <span>Conditional domain</span>
                <strong>Protection</strong>
                <small>{moment.protection}</small>
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
            <p>Evidence retained</p>
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
            <p>For receivable platforms</p>
            <h2 id="integration-title">Your platform records the asset. Mordant establishes what happens next.</h2>
          </header>
          <div className={styles.integrationBody}>
            <div className={styles.flow} aria-label="Integration flow">
              <button type="button" aria-pressed={integrationStep === 0} onClick={() => setIntegrationStep(0)}>
                <strong>{INTEGRATION_STEPS[0].label}</strong>
                <small>{INTEGRATION_STEPS[0].detail}</small>
              </button>
              <i aria-hidden="true" />
              <button type="button" aria-pressed={integrationStep === 1} onClick={() => setIntegrationStep(1)}>
                <strong>{INTEGRATION_STEPS[1].label}</strong>
                <small>{INTEGRATION_STEPS[1].detail}</small>
              </button>
              <i aria-hidden="true" />
              <button type="button" aria-pressed={integrationStep === 2} onClick={() => setIntegrationStep(2)}>
                <strong>{INTEGRATION_STEPS[2].label}</strong>
                <small>{INTEGRATION_STEPS[2].detail}</small>
              </button>
            </div>
            <p className={styles.integrationStory} aria-live="polite">
              <span key={integrationStep}>{INTEGRATION_STEPS[integrationStep].story}</span>
            </p>
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
