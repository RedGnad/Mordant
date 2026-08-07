"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

import { LIVE_PRODUCT_CTA, LIVE_PRODUCT_HREF, PublicFooter, PublicHeader } from "./public-shell";
import styles from "./public-experience.module.css";

type PublicProof = {
  actor: string;
  action: string;
  before: string;
  after: string;
  block: number | string;
  chain: string;
};

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
    consequence: "Neither lender will publish its book to prove it.",
  },
  {
    id: "recourse",
    label: "Recourse",
    title: "Responsibility becomes explicit.",
    protection: "Accountable path",
    consequence: "A named party, a cure window, a priced consequence.",
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

const CONSEQUENCES = [
  {
    id: "cleared",
    verdict: "No conflict",
    title: "Recourse is explicitly refused.",
    body: "The signed result clears the case. No protection becomes claimable, and financing continues subject to the rest of your workflow.",
    status: "Live today",
  },
  {
    id: "conflict",
    verdict: "Conflict confirmed",
    title: "A cure window opens.",
    body: "The signed result names who is responsible and fixes the deadline carried by the recourse record. The original receivable stays outstanding and intact.",
    status: "Live today",
  },
  {
    id: "claimable",
    verdict: "Conflict uncured",
    title: "Fixed aUSDC recourse becomes claimable.",
    body: "When the cure window closes unresolved, the reserved protection is claimable by the affected holder. This has been executed on Monad testnet: a real 600-second window expired uncured, anyone could finalize, and both holders were paid.",
    status: "Live today",
  },
] as const;

/**
 * The integration path, told as the product actually works.
 *
 * Four stages rather than three, because the Cleanverse boundary and the private
 * decision are different responsibilities and a judge must not read them as one.
 * Cleanverse says what the asset is and who may participate; Mordant decides,
 * privately, whether the claims collide; the governed signature is what turns
 * that answer into money moving on Monad.
 */
const JUNCTION_MARK_CLASSES = [
  styles.claimMarkPrimary,
  styles.claimMarkSatelliteOne,
  styles.claimMarkSatelliteTwo,
] as const;

const INTEGRATION_STEPS = [
  {
    label: "Cleanverse verifies",
    detail: "MINV01 + A-Pass",
    story: "Cleanverse establishes the receivable and which wallets may hold a claim against it.",
  },
  {
    label: "Mordant decides privately",
    detail: "BGV over ciphertexts",
    story: "The evaluator runs the fixed circuit over ciphertexts and holds no decryption key.",
  },
  {
    label: "Governed result",
    detail: "Signed Boolean",
    story: "A designated decryptor recomputes the circuit and signs the answer. No result exists before that signature.",
  },
  {
    label: "Monad recourse",
    detail: "aUSDC settlement",
    story: "The signed result opens or refuses recourse, and the aUSDC claims settle on Monad testnet.",
  },
] as const;

const BOUNDARIES = [
  {
    title: "Observed provenance",
    body: "The Cleanverse and Monad testnet asset identity is retained real evidence.",
  },
  {
    title: "Managed preparation",
    body: "Mordant's managed execution service prepares and encrypts the inputs. There is no participant-device encryption.",
  },
  {
    title: "Ciphertext-only evaluation",
    body: "The FHE evaluator receives ciphertexts and holds no decryption key.",
  },
  {
    title: "Trusted release",
    body: "A designated decryptor recomputes the circuit and signs the result. This is not native Monad FHE, threshold release or trustless decryption.",
  },
  {
    title: "Synthetic pledge book",
    body: "The lender pledge intervals are synthetic fixtures and the protected notional is illustrative. No real lender book is represented.",
  },
  {
    title: "Real but bounded settlement",
    body: "The cure window, the permissionless finalization and the aUSDC claims are real on Monad testnet, at deliberately small amounts. Execution is supervised single-host and is not production authorized.",
  },
  {
    title: "Single execution slot",
    body: "One managed execution slot is available. A second visitor waits rather than running in parallel.",
  },
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

export function PublicExperience({ proof }: { readonly proof: PublicProof }) {
  const [step, setStep] = useState(0);
  const [integrationStep, setIntegrationStep] = useState(0);
  const pageRef = useRef<HTMLDivElement>(null);
  const transformationRef = useRef<HTMLElement>(null);
  const scrollFrame = useRef<number | null>(null);
  const heroRef = useRef<HTMLElement>(null);
  const integrationFlowRef = useRef<HTMLDivElement>(null);
  const integrationPathRef = useRef<SVGPathElement>(null);
  const integrationSignalRef = useRef<SVGGElement>(null);
  const heroScrollFrame = useRef<number | null>(null);
  const integrationScrollFrame = useRef<number | null>(null);
  const integrationMotionFrame = useRef<number | null>(null);
  const integrationMotionProgress = useRef(0);
  const integrationInteractionLockUntil = useRef(0);
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

    const chapterObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        (entry.target as HTMLElement).dataset.visible = "true";
        chapterObserver.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -12%", threshold: 0.08 });
    chapters.forEach((chapter) => chapterObserver.observe(chapter));
    return () => chapterObserver.disconnect();
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
    const flow = integrationFlowRef.current;
    if (flow === null) return;

    const updateFromScroll = () => {
      integrationScrollFrame.current = null;
      if (performance.now() < integrationInteractionLockUntil.current) return;
      const bounds = flow.getBoundingClientRect();
      const activeTop = window.innerHeight * 0.88;
      const activeBottom = window.innerHeight * 0.18;
      if (bounds.top > activeTop || bounds.bottom < activeBottom) return;

      const range = activeTop - activeBottom + bounds.height;
      const progress = Math.min(1, Math.max(0, (activeTop - bounds.top) / Math.max(1, range)));
      const nextStep = progress < 0.2 ? 0 : progress < 0.44 ? 1 : progress < 0.68 ? 2 : 3;
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

    const targets = [0, 0.42, 0.633, 1];
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
    setStep(index);
    if (!window.matchMedia(STICKY_SCENE).matches) return;
    const range = Math.max(0, section.offsetHeight - window.innerHeight);
    const threshold = TRANSFORMATION_SCROLL_THRESHOLDS[index] ?? 0;
    const targetProgress = index === 0 ? 0 : Math.min(1, threshold + 0.01);
    const sectionTop = window.scrollY + section.getBoundingClientRect().top;
    window.scrollTo({ top: sectionTop + (range * targetProgress), behavior: "instant" });
  };

  const moveHeroSymbol = (event: ReactPointerEvent<HTMLElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 22;
    const y = ((event.clientY - bounds.top) / bounds.height - 0.5) * 14;
    event.currentTarget.style.setProperty("--symbol-x", `${x}px`);
    event.currentTarget.style.setProperty("--symbol-y", `${y}px`);
  };

  const resetHeroSymbol = (event: ReactPointerEvent<HTMLElement>) => {
    event.currentTarget.style.setProperty("--symbol-x", "0px");
    event.currentTarget.style.setProperty("--symbol-y", "0px");
  };

  const selectIntegrationStep = (index: number, interactionTimestamp: number) => {
    integrationInteractionLockUntil.current = interactionTimestamp + 500;
    setIntegrationStep(index);
  };

  return (
    <div className={styles.page} ref={pageRef}>
      <a className={styles.skip} href="#content">Skip to content</a>
      <PublicHeader surface="landing" />

      <main id="content">
        {/* 1. Hero */}
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
              <Symbol className={styles.heroSymbol} />
            </div>
          </div>
          <p className={styles.heroPromise}>When private claims collide, Mordant keeps tokenized credit moving.</p>
          <p className={styles.heroSupport}>
            Mordant privately detects conflicting pledges on verified receivables and turns confirmed
            conflicts into governed, auditable recourse, without exposing lender records to the evaluator.
          </p>
          <div className={styles.actions}>
            <Link className={styles.primary} href={LIVE_PRODUCT_HREF}>{LIVE_PRODUCT_CTA}</Link>
            <Link className={styles.secondary} href="/protection?scenario=conflict">Inspect verified evidence</Link>
          </div>
          <p className={styles.heroNote}>A real encrypted check on a verified receivable. Usually about a minute.</p>
        </section>

        {/* 2. The economic problem */}
        <section className={styles.problem} id="problem" aria-labelledby="problem-title" data-reveal>
          <header>
            <p className={styles.eyebrow}>The economic problem</p>
            <h2 id="problem-title">One receivable can carry two financing claims, and neither lender can prove it.</h2>
          </header>
          <div className={styles.problemBody}>
            <div className={styles.claimants}>
              <article>
                <p>Lender A</p>
                <strong>Already financed it.</strong>
                <span>Holds a pledge over the receivable with its own active window.</span>
              </article>
              <article>
                <p>Lender B</p>
                <strong>Is about to finance it.</strong>
                <span>Holds a pledge whose window may already overlap A&rsquo;s.</span>
              </article>
            </div>
            <div className={styles.problemStatement}>
              <p>
                Publishing a pledge book is how a lender loses its book. So the two windows stay private,
                the overlap stays invisible, and the safe decision is to stop lending.
              </p>
              <p className={styles.problemPayoff}>
                Credit stops because nobody can check without disclosing.
              </p>
            </div>
          </div>
        </section>

        {/* 3. The transformation */}
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
                <div><span>Responsible</span><strong>{proof.actor}</strong></div>
                <div><span>Deadline</span><strong>Fixed by the signed recourse record</strong></div>
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

        {/* 4. The actual product */}
        <section className={styles.product} id="product" aria-labelledby="product-title" data-reveal>
          <header>
            <p className={styles.eyebrow}>The product</p>
            <h2 id="product-title">Conflicting Pledge Protection</h2>
          </header>
          <div className={styles.productBody}>
            <p className={styles.productLede}>
              Mordant&rsquo;s first workflow for keeping tokenized credit moving through private conflict.
            </p>
            {/* The three Cleanverse boundaries, named once and precisely. A judge
                must be able to see what Cleanverse provides and what it does not
                without reading the whole page: it verifies the asset and who may
                participate, and it does not perform the private decision. */}
            <dl className={styles.cleanverseFacts} aria-label="What Cleanverse provides">
              <div>
                <dt>MINV01</dt>
                <dd>The verified receivable. Cleanverse establishes the asset; it is the RWA in this case.</dd>
              </div>
              <div>
                <dt>A-Pass</dt>
                <dd>Participant eligibility. Cleanverse decides which wallets may hold a claim against it.</dd>
              </div>
              <div>
                <dt>aUSDC</dt>
                <dd>The compliant settlement rail the consequence is paid on. A rail, not the receivable.</dd>
              </div>
            </dl>
            <p className={styles.cleanverseNote}>
              Cleanverse verifies the asset and who may participate. The private conflict decision is
              Mordant&rsquo;s, and Cleanverse never sees a pledge window.
            </p>
            <dl className={styles.productFacts}>
              <div>
                <dt>What enters</dt>
                <dd>A verified Cleanverse receivable and two private pledge windows.</dd>
              </div>
              <div>
                <dt>What is evaluated</dt>
                <dd>One fixed circuit over ciphertexts. The evaluator never sees a window.</dd>
              </div>
              <div>
                <dt>What is released</dt>
                <dd>One signed Boolean from the designated decryptor. Nothing before it.</dd>
              </div>
              <div>
                <dt>What you keep</dt>
                <dd>A named responsibility, a deadline, a consequence and a verifiable receipt.</dd>
              </div>
            </dl>
          </div>
        </section>

        {/* 5. Live execution invitation */}
        <section className={styles.invitation} aria-labelledby="invitation-title" data-reveal>
          <div className={styles.invitationText}>
            <p className={styles.eyebrow}>Run it</p>
            <h2 id="invitation-title">The check on this site is real, and it usually takes about a minute.</h2>
            <p>
              Your two claim windows go to Mordant&rsquo;s managed execution service, which prepares and
              encrypts them. The evaluator then runs the fixed circuit over ciphertexts only. No result
              exists until the designated decryptor releases a signed Boolean.
            </p>
            <div className={styles.actions}>
              <Link className={styles.primary} href={LIVE_PRODUCT_HREF}>{LIVE_PRODUCT_CTA}</Link>
            </div>
          </div>

          {/* The old integration flow, verbatim in structure: the same 3fr/9fr
              composition, the same measured motion path, the same hover, focus
              and click selection with a 500ms lock so a deliberate choice is not
              immediately overridden by scrolling. Only the route is a stage
              longer, because the truthful narrative has four responsibilities
              rather than three. */}
          <div className={styles.flow} data-step={integrationStep} aria-label="Interactive integration path" ref={integrationFlowRef}>
            <div className={styles.flowCanvas}>
              <svg className={styles.flowGraphic} viewBox="0 0 1000 180" aria-hidden="true">
                <path ref={integrationPathRef} className={styles.flowMotionPath} d="M40 102H392L460 34H612L680 102H920" />
                <path className={`${styles.flowRouteSegment} ${styles.flowRouteInput}`} pathLength="352" d="M40 102H392" />
                <path className={`${styles.flowRouteSegment} ${styles.flowRoutePolicy}`} pathLength="164" d="M392 102H392L460 34H540" />
                <path className={`${styles.flowRouteSegment} ${styles.flowRouteGoverned}`} pathLength="168" d="M540 34H612L680 102" />
                <path className={`${styles.flowRouteSegment} ${styles.flowRouteAction}`} pathLength="240" d="M680 102H920" />
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
                  onClick={(event) => selectIntegrationStep(index, event.timeStamp)}
                  onFocus={(event) => selectIntegrationStep(index, event.timeStamp)}
                  onPointerEnter={(event) => selectIntegrationStep(index, event.timeStamp)}
                >
                  <strong>{stage.label}</strong>
                  <small>{stage.detail}</small>
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* 6. Economic consequence */}
        <section className={styles.consequence} aria-labelledby="consequence-title" data-reveal>
          <header>
            <p className={styles.eyebrow}>What follows the result</p>
            <h2 id="consequence-title">The answer is not the product. The consequence is.</h2>
          </header>
          <div className={styles.consequenceList}>
            {CONSEQUENCES.map((item) => (
              <article key={item.id} data-outcome={item.id}>
                <p className={styles.consequenceVerdict}>{item.verdict}</p>
                <strong>{item.title}</strong>
                <p>{item.body}</p>
                <span className={styles.consequenceStatus} data-live={item.status === "Live today" ? "true" : "false"}>
                  {item.status}
                </span>
              </article>
            ))}
          </div>
        </section>

        {/* 7. Evidence and receipt */}
        <section className={styles.proof} aria-labelledby="proof-title" data-reveal>
          <header>
            <p className={styles.eyebrowOnProof}>Earned after the result</p>
            <h2 id="proof-title">One receipt. One verifiable transition.</h2>
          </header>
          <dl>
            <div><dt>Actor</dt><dd>{proof.actor}</dd></div>
            <div><dt>Action</dt><dd>{proof.action}</dd></div>
            <div><dt>Before</dt><dd>{proof.before}</dd></div>
            <div><dt>After</dt><dd>{proof.after}</dd></div>
            <div><dt>Block</dt><dd>{proof.block}</dd></div>
            <div><dt>Chain</dt><dd>{proof.chain}</dd></div>
          </dl>
          <p className={styles.proofNote}>
            This receipt comes from the recorded lifecycle run, not from the live encrypted check.
            A live run seals its own receipt, which you can inspect the moment it exists. One such run
            has already been settled on Monad testnet, end to end, with every transaction public.
          </p>
          <div className={styles.proofActions}>
            <Link className={styles.proofPrimary} href={LIVE_PRODUCT_HREF}>{LIVE_PRODUCT_CTA}</Link>
            <Link className={styles.proofSecondary} href="/protection/verified-run" data-testid="landing-to-verified-run">
              See the settled run
            </Link>
            <Link className={styles.proofSecondary} href="/protection?scenario=conflict">Inspect verified evidence</Link>
            <Link className={styles.proofSecondary} href="/demo?checkpoint=reveal">See the full lifecycle</Link>
          </div>
        </section>

        {/* 8. Truth boundary */}
        <section className={styles.boundaries} id="boundaries" aria-labelledby="boundaries-title" data-reveal>
          <header>
            <p className={styles.eyebrow}>Boundaries</p>
            <h2 id="boundaries-title">What this is, and what it is not.</h2>
          </header>
          <dl className={styles.boundaryList}>
            {BOUNDARIES.map((item) => (
              <div key={item.title}>
                <dt>{item.title}</dt>
                <dd>{item.body}</dd>
              </div>
            ))}
          </dl>
          <p className={styles.boundaryNote}>
            Two-wallet participant admission, the on-chain cure window and the aUSDC claims have each run
            end to end on Monad testnet. The completed run is linked above, with every transaction on the
            public explorer, so none of it has to be taken on trust.
          </p>
        </section>

        {/* 9. Pilot */}
        <section className={styles.pilot} aria-labelledby="pilot-title" data-reveal>
          <div>
            <p className={styles.eyebrow}>Pilot</p>
            <h2 id="pilot-title">Test accountable recourse beside the process you already trust.</h2>
          </div>
          <div className={styles.actions}>
            <Link className={styles.secondary} href="/pilot">Apply for a shadow pilot</Link>
          </div>
        </section>
      </main>

      <PublicFooter />
    </div>
  );
}
