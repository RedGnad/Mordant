"use client";

import Link from "next/link";
import { useState } from "react";

import styles from "./public-experience.module.css";

type PublicProof = {
  actor: string;
  action: string;
  before: string;
  after: string;
  block: number | string;
};

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
  const moment = TRANSFORMATION[step];

  return (
    <div className={styles.page}>
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
          <p>Programmable recourse for tokenized receivables</p>
          <h1 id="hero-title">Tokenized assets automate ownership. Mordant automates recourse.</h1>
          <p>Detect conflicting claims, assign responsibility, enforce deadlines, and retain verifiable evidence for tokenized receivables.</p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="/demo">See Mordant resolve a conflict</Link>
            <a className={styles.secondary} href="#product">Explore the product</a>
          </div>
        </section>

        <section className={styles.gap} id="problem" aria-labelledby="gap-title">
          <p>01 · The gap</p>
          <h2 id="gap-title">Tokenization records who owns an asset. It does not decide what happens when obligations conflict.</h2>
        </section>

        <section className={styles.transformation} id="product" aria-labelledby="transformation-title">
          <header>
            <p>02 · The transformation</p>
            <span>{String(step + 1).padStart(2, "0")} / 05</span>
          </header>
          <div className={styles.scene} data-displaced={step > 0 ? "true" : "false"}>
            <article className={styles.receivable}>
              <span>Stable anchor</span>
              <strong>Receivable</strong>
              <small>Ownership remains unchanged</small>
            </article>
            <article className={styles.protection}>
              <span>Conditional domain</span>
              <strong>Protection</strong>
              <small>{moment.label}</small>
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

        <section className={styles.value} aria-labelledby="value-title">
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

        <section className={styles.integration} id="integrate" aria-labelledby="integration-title">
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

        <section className={styles.proof} aria-labelledby="proof-title">
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
