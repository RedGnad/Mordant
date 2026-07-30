"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

import styles from "./public-experience.module.css";

type PublicProof = {
  actor: string;
  action: string;
  before: string;
  after: string;
  block: number | string;
  transactionHash: string;
};

type SignatureStage = "ready" | "collision" | "isolation" | "recourse" | "proof";

function compactHash(value: string) {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-8)}` : value;
}

function RecourseTransformation({ proof }: { readonly proof: PublicProof }) {
  const [stage, setStage] = useState<SignatureStage>("ready");
  const sceneRef = useRef<HTMLDivElement>(null);
  const timersRef = useRef<number[]>([]);
  const dragOriginRef = useRef<{ x: number; y: number } | null>(null);
  const draggedRef = useRef(false);

  const clearSequence = useCallback(() => {
    timersRef.current.forEach((timer) => window.clearTimeout(timer));
    timersRef.current = [];
  }, []);

  useEffect(() => clearSequence, [clearSequence]);

  const start = useCallback(() => {
    if (stage !== "ready") return;
    clearSequence();
    setStage("collision");
    timersRef.current = [
      window.setTimeout(() => setStage("isolation"), 420),
      window.setTimeout(() => setStage("recourse"), 1_050),
    ];
  }, [clearSequence, stage]);

  const replay = useCallback(() => {
    clearSequence();
    setStage("ready");
    sceneRef.current?.style.setProperty("--claim-drag-x", "0px");
    sceneRef.current?.style.setProperty("--claim-drag-y", "0px");
  }, [clearSequence]);

  function respondToPointer(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.pointerType === "touch" || sceneRef.current === null) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 6;
    const y = ((event.clientY - bounds.top) / bounds.height - 0.5) * -6;
    sceneRef.current.style.setProperty("--tilt-x", `${y.toFixed(2)}deg`);
    sceneRef.current.style.setProperty("--tilt-y", `${x.toFixed(2)}deg`);
  }

  function resetPerspective() {
    sceneRef.current?.style.setProperty("--tilt-x", "0deg");
    sceneRef.current?.style.setProperty("--tilt-y", "0deg");
  }

  function beginDrag(event: ReactPointerEvent<HTMLButtonElement>) {
    if (stage !== "ready") return;
    dragOriginRef.current = { x: event.clientX, y: event.clientY };
    draggedRef.current = false;
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function dragClaim(event: ReactPointerEvent<HTMLButtonElement>) {
    const origin = dragOriginRef.current;
    if (origin === null || sceneRef.current === null || stage !== "ready") return;
    const dx = Math.max(-90, Math.min(90, event.clientX - origin.x));
    const dy = Math.max(-80, Math.min(80, event.clientY - origin.y));
    if (Math.hypot(dx, dy) > 6) draggedRef.current = true;
    sceneRef.current.style.setProperty("--claim-drag-x", `${dx}px`);
    sceneRef.current.style.setProperty("--claim-drag-y", `${dy}px`);
  }

  function finishDrag() {
    dragOriginRef.current = null;
    if (draggedRef.current) start();
    draggedRef.current = false;
  }

  const message = stage === "ready"
    ? { title: "One receivable. One aligned protection.", body: "Introduce a second claim to see Mordant establish recourse." }
    : stage === "collision"
      ? { title: "Two claims. One receivable.", body: "The claims cannot occupy the same economic position." }
      : stage === "isolation"
        ? { title: "Mordant isolates the conflict.", body: "The receivable remains stable while the conditional domain separates." }
        : { title: "Conflict turned into accountable recourse.", body: "Responsibility, deadline, consequence, and proof now agree." };

  if (stage === "proof") {
    return (
      <section className={styles.signatureProof} aria-label="Retained receipt proof">
        <header>
          <span>Receipt proof · retained M-EX2 run</span>
          <h2>Conflict confirmed.</h2>
        </header>
        <dl>
          <div><dt>Actor</dt><dd>{proof.actor}</dd></div>
          <div><dt>Action</dt><dd>{proof.action}</dd></div>
          <div><dt>Before</dt><dd>{proof.before}</dd></div>
          <div><dt>After</dt><dd>{proof.after}</dd></div>
          <div><dt>Block</dt><dd>{proof.block}</dd></div>
          <div><dt>Transaction</dt><dd className={styles.signatureHash}>{compactHash(proof.transactionHash)}</dd></div>
        </dl>
        <div>
          <button type="button" onClick={replay}>Replay</button>
          <Link href="/demo?checkpoint=reveal">Open full recorded run</Link>
        </div>
      </section>
    );
  }

  return (
    <section className={styles.signature} aria-labelledby="signature-title">
      <div
        className={styles.signatureStage}
        ref={sceneRef}
        data-stage={stage}
        onPointerMove={respondToPointer}
        onPointerLeave={resetPerspective}
      >
        <i className={styles.signatureLineA} aria-hidden="true" />
        <i className={styles.signatureLineB} aria-hidden="true" />
        <div className={styles.signaturePlane}>
          <article className={styles.signatureReceivable}>
            <span>Funded receivable</span>
            <strong>110.00</strong>
            <small>dSETTLE · stable</small>
          </article>
          <article className={styles.signatureProtection}>
            <span>Protection</span>
            <strong>10.00</strong>
            <small>dSETTLE · aligned</small>
          </article>
          <button
            type="button"
            className={styles.conflictingClaim}
            aria-label="Introduce a conflicting claim"
            disabled={stage !== "ready"}
            onClick={start}
            onPointerDown={beginDrag}
            onPointerMove={dragClaim}
            onPointerUp={finishDrag}
            onPointerCancel={finishDrag}
          >
            <span>Second claim</span>
            <strong>10.00</strong>
            <small>Introduce a conflicting claim</small>
          </button>
          <div className={styles.recourseObjects} aria-hidden={stage !== "recourse"}>
            <article><span>Responsible party</span><strong>Facility B</strong></article>
            <article><span>Deadline</span><strong>30 Jul · 01:40 UTC</strong></article>
            <article><span>Economic consequence</span><strong>10.00 dSETTLE claimable</strong></article>
          </div>
        </div>
      </div>
      <footer className={styles.signatureMessage} aria-live="polite">
        <div>
          <h2 id="signature-title">{message.title}</h2>
          <p>{message.body}</p>
        </div>
        {stage === "ready" ? (
          <button type="button" onClick={start}>Introduce a conflicting claim</button>
        ) : stage === "recourse" ? (
          <div className={styles.signatureResultActions}>
            <button type="button" onClick={() => setStage("proof")}>Inspect the proof</button>
            <button type="button" onClick={replay}>Replay</button>
          </div>
        ) : <span>Resolving…</span>}
      </footer>
    </section>
  );
}

const TRANSFORMATION = [
  {
    label: "Receivable funded",
    title: "The receivable is funded.",
    detail: "Ownership is recorded and the economic position is clear.",
  },
  {
    label: "Conflict detected",
    title: "A conflicting claim is detected.",
    detail: "The receivable stays intact while protection leaves alignment.",
  },
  {
    label: "Responsibility assigned",
    title: "The responsible party is identified.",
    detail: "Everyone sees who must act. No one has to interpret the contract state.",
  },
  {
    label: "Deadline established",
    title: "A deadline and consequence are established.",
    detail: "Inaction now has a known, enforceable outcome.",
  },
  {
    label: "Proof retained",
    title: "The state change is retained as proof.",
    detail: "The decision is replaced by a verifiable before and after record.",
  },
] as const;

export function PublicExperience({ proof }: { readonly proof: PublicProof }) {
  const [step, setStep] = useState(0);
  const pageRef = useRef<HTMLDivElement>(null);
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

  return (
    <div className={styles.page} ref={pageRef}>
      <a className={styles.skip} href="#content">Skip to content</a>
      <header className={styles.header}>
        <Link className={styles.brand} href="/">Mordant</Link>
        <nav aria-label="Public navigation">
          <a href="#problem">Problem</a>
          <a href="#integrate">Integrate</a>
          <Link href="/demo">Recorded demo</Link>
        </nav>
      </header>

      <main id="content">
        <section className={styles.hero} aria-labelledby="hero-title">
          <div className={styles.heroCopy}>
            <p>Programmable recourse for tokenized receivables</p>
            <h1 id="hero-title">Tokenized assets automate ownership. Mordant automates recourse.</h1>
            <p>Detect conflicting claims, assign responsibility, enforce deadlines, and retain verifiable evidence for tokenized receivables.</p>
            <div className={styles.actions}>
              <Link className={styles.primary} href="/demo">See Mordant resolve a conflict</Link>
              <a className={styles.secondary} href="#product">Explore the product</a>
            </div>
          </div>
          <RecourseTransformation proof={proof} />
        </section>

        <section className={styles.gap} id="problem" aria-labelledby="gap-title" data-reveal>
          <p>01 · The gap</p>
          <h2 id="gap-title">Tokenization records who owns an asset. It does not decide what happens when obligations conflict.</h2>
        </section>

        <section className={styles.transformation} id="product" aria-labelledby="transformation-title" data-reveal>
          <header>
            <p>02 · The transformation</p>
            <span>{String(step + 1).padStart(2, "0")} / 05</span>
          </header>
          <div
            className={styles.scene}
            data-displaced={step > 0 && step < TRANSFORMATION.length - 1 ? "true" : "false"}
            data-resolved={step === TRANSFORMATION.length - 1 ? "true" : "false"}
          >
            <article className={styles.receivable}>
              <span>Stable anchor</span>
              <strong>Receivable</strong>
              <small>Ownership remains unchanged</small>
            </article>
            <article className={styles.protection}>
              <span>Conditional domain</span>
              <strong>Protection</strong>
              <small>{moment.label}</small>
              <div className={styles.sceneStatus} data-visible={step >= 2 && step < TRANSFORMATION.length - 1 ? "true" : "false"}>
                <span>Responsible party identified</span>
                <time data-visible={step >= 3 ? "true" : "false"}>Deadline established</time>
              </div>
            </article>
          </div>
          <div className={styles.sceneCopy} aria-live="polite">
            <div>
              <h2 id="transformation-title">{moment.title}</h2>
              <p>{moment.detail}</p>
            </div>
            <button type="button" onClick={() => setStep((current) => (current + 1) % TRANSFORMATION.length)}>
              {step === TRANSFORMATION.length - 1 ? "Restart" : "Continue"}
            </button>
          </div>
        </section>

        <section className={styles.value} aria-labelledby="value-title" data-reveal>
          <header>
            <p>03 · The value</p>
            <h2 id="value-title">Conflict becomes an operational path.</h2>
          </header>
          <div>
            <article><span>01</span><h3>Know who must act</h3></article>
            <article><span>02</span><h3>Know what happens next</h3></article>
            <article><span>03</span><h3>Prove how the state changed</h3></article>
          </div>
        </section>

        <section className={styles.integration} id="integrate" aria-labelledby="integration-title" data-reveal>
          <header>
            <p>04 · Built to integrate</p>
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
        </section>

        <section className={styles.proof} aria-labelledby="proof-title" data-reveal>
          <header>
            <p>05 · Proof</p>
            <h2 id="proof-title">One receipt. One verifiable transition.</h2>
          </header>
          <dl>
            <div><dt>Actor</dt><dd>{proof.actor}</dd></div>
            <div><dt>Action</dt><dd>{proof.action}</dd></div>
            <div><dt>Before</dt><dd>{proof.before}</dd></div>
            <div><dt>After</dt><dd>{proof.after}</dd></div>
            <div><dt>Block</dt><dd>{proof.block}</dd></div>
          </dl>
          <Link className={styles.proofCta} href="/demo?checkpoint=reveal">Open the complete recorded demo</Link>
        </section>
      </main>

      <footer className={styles.footer}>
        <strong>Mordant</strong>
        <span>Recourse infrastructure for tokenized receivables.</span>
      </footer>
    </div>
  );
}
