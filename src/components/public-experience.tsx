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
    id: "flow",
    label: "In flow",
    title: "The path is clear.",
    protection: "Aligned",
  },
  {
    id: "change",
    label: "Change observed",
    title: "An obligation changes.",
    protection: "Change observed",
  },
  {
    id: "path",
    label: "Path assigned",
    title: "The next move becomes clear.",
    protection: "Path assigned",
  },
  {
    id: "proof",
    label: "Proof retained",
    title: "The decision is retained.",
    protection: "Receipt issued",
  },
] as const;

export function PublicExperience({ proof }: { readonly proof: PublicProof }) {
  const [step, setStep] = useState(0);
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
    setStep(index);
    const range = Math.max(0, section.offsetHeight - window.innerHeight);
    const position = section.offsetTop + (range * index / (TRANSFORMATION.length - 1));
    window.scrollTo({ top: position, behavior: "instant" });
  };

  return (
    <div className={styles.page} ref={pageRef}>
      <a className={styles.skip} href="#content">Skip to content</a>
      <PublicHeader />

      <main id="content">
        <section className={styles.hero} aria-labelledby="hero-title">
          <p className={styles.heroCategory}>Operational recourse / tokenized receivables</p>
          <h1 id="hero-title">
            <span>Exceptions</span>
            <span>become clear action.</span>
          </h1>
          <p className={styles.heroSupport}>Mordant establishes who acts next, by when, and retains the proof.</p>
          <p className={styles.heroAudience}>For credit &amp; operations teams</p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="#product">See the transformation</Link>
            <Link className={styles.secondary} href="#integrate">Evaluate the integration</Link>
          </div>
          <div className={styles.heroSeed} aria-hidden="true">
            <span>Asset state / continuous</span>
            <i />
            <span>Recourse / ready</span>
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
              <p>From change / to a clear path</p>
              <span aria-live="polite">{moment.label}</span>
            </header>

            <div className={styles.transformationTitle}>
              <h2 id="transformation-title" aria-live="polite">
                <span key={moment.id}>{moment.title}</span>
              </h2>
              <p>Receivable remains unchanged.</p>
            </div>

            <div className={styles.scene} aria-label={`Transformation state: ${moment.label}`}>
              <div className={styles.receivableLane}>
                <span>Stable anchor</span>
                <strong>Receivable</strong>
                <small>Outstanding</small>
              </div>

              <div className={styles.claim} aria-hidden={step === 0}>
                <span>New obligation</span>
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
            <Link className={styles.proofPrimary} href="/pilot">Apply for a shadow pilot</Link>
          </div>
        </section>

        <section className={styles.integration} id="integrate" aria-labelledby="integration-title" data-reveal>
          <header>
            <p>For receivable platforms</p>
            <h2 id="integration-title">A policy and recourse layer between asset state and action.</h2>
          </header>
          <div className={styles.integrationBody}>
            <div className={styles.flow} aria-label="Integration flow">
              <span>Your receivable platform</span>
              <i aria-hidden="true">↓</i>
              <strong>Mordant policy + recourse layer</strong>
              <i aria-hidden="true">↓</i>
              <span>Actions · deadlines · receipts</span>
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
          <Link className={styles.secondary} href="/workspace">View the product surfaces</Link>
          <p className={styles.accessNote}>Current access: recorded demo. Private pilots are permissioned; production access is closed.</p>
        </section>
      </main>

      <PublicFooter />
    </div>
  );
}
