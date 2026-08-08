"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

import { MiniLiveCheck } from "./live-product/mini-live-check";
import { LIVE_PRODUCT_CTA, PublicFooter, PublicHeader } from "./public-shell";
import styles from "./public-experience.module.css";

/**
 * The integration path, told as the product actually works.
 *
 * Four stages rather than three, because the Cleanverse boundary and the private
 * decision are different responsibilities and a judge must not read them as one.
 * Cleanverse says what the asset is and who may participate; Mordant decides,
 * privately, whether the claims collide; the governed result establishes only
 * that conflict status; policy and human review own every consequence.
 */
const INTEGRATION_STEPS = [
  {
    label: "Cleanverse verifies",
    detail: "MINV01 + A-Pass",
    story: "Cleanverse verifies MINV01 provenance and identity plus participant eligibility, not legal validity or enforceability.",
  },
  {
    label: "Mordant decides privately",
    detail: "BGV over ciphertexts",
    story: "The evaluator runs the fixed circuit over ciphertexts and holds no decryption key.",
  },
  {
    label: "Governed result",
    detail: "Signed conflict status",
    story: "The governed result establishes only whether the submitted claim windows conflict. Policy and human review determine every next action.",
  },
  {
    label: "Monad recourse",
    detail: "Bounded aUSDC rail",
    story: "In the separate hardened run, preconfigured demo policy opened the cure path and deployment configuration determined holders and payouts before settlement.",
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

export function PublicExperience({ liveCheckHolder }: {
  /** The eligible managed test context, or null when the worker is unreachable. */
  readonly liveCheckHolder: string | null;
}) {
  const [integrationStep, setIntegrationStep] = useState(0);
  const pageRef = useRef<HTMLDivElement>(null);
  const heroRef = useRef<HTMLElement>(null);
  const integrationFlowRef = useRef<HTMLDivElement>(null);
  const integrationPathRef = useRef<SVGPathElement>(null);
  const integrationSignalRef = useRef<SVGGElement>(null);
  const heroScrollFrame = useRef<number | null>(null);
  const integrationScrollFrame = useRef<number | null>(null);
  const integrationMotionFrame = useRef<number | null>(null);
  const integrationMotionProgress = useRef(0);
  const integrationInteractionLockUntil = useRef(0);

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
      hero.style.setProperty("--symbol-scroll-rotation", `${progress * 12}deg`);
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

  const moveHeroSymbol = (event: ReactPointerEvent<HTMLElement>) => {
    const hero = heroRef.current;
    if (hero === null) return;
    const x = (event.clientX / Math.max(1, window.innerWidth) - 0.5) * 22;
    const y = (event.clientY / Math.max(1, window.innerHeight) - 0.5) * 14;
    hero.style.setProperty("--symbol-x", `${x}px`);
    hero.style.setProperty("--symbol-y", `${y}px`);
  };

  const resetHeroSymbol = () => {
    const hero = heroRef.current;
    if (hero === null) return;
    hero.style.setProperty("--symbol-x", "0px");
    hero.style.setProperty("--symbol-y", "0px");
  };

  const selectIntegrationStep = (index: number, interactionTimestamp: number) => {
    integrationInteractionLockUntil.current = interactionTimestamp + 500;
    setIntegrationStep(index);
  };

  return (
    <div className={styles.page} ref={pageRef}>
      <a className={styles.skip} href="#content">Skip to content</a>
      <PublicHeader surface="landing" />

      <main id="content" onPointerMove={moveHeroSymbol} onPointerLeave={resetHeroSymbol}>
        {/* 1. Hero */}
        <section
          className={styles.hero}
          aria-labelledby="hero-title"
          ref={heroRef}
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
          <p className={styles.heroPromise}>When private claims collide, keep tokenized credit moving.</p>
          <p className={styles.heroSupport}>
            Mordant privately checks whether financing claims conflict,<br className={styles.supportBreak} /> then turns a
            confirmed conflict into governed recourse.
          </p>
          <div className={styles.actions}>
            <Link className={styles.primary} href="#product">{LIVE_PRODUCT_CTA}</Link>
            <Link className={styles.secondary} href="/protection?scenario=conflict">Inspect verified evidence</Link>
          </div>
        </section>

        {/* 2. The real check, immediately. The economic problem this replaced
            said the same thing in a paragraph; here a visitor can run it. */}
        {liveCheckHolder === null ? null : <MiniLiveCheck publicTestHolder={liveCheckHolder} />}

        {/* 3. The one retained responsibility model after the experiment. */}
        <section className={styles.invitation} id="how" aria-labelledby="invitation-title" data-reveal>
          <div className={styles.invitationText}>
            <p className={styles.eyebrow}>Responsibility</p>
            <h2 id="invitation-title">One path. Four bounded responsibilities.</h2>
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

        {/* 4. One completed hardened proof object, explicitly separate. */}
        <section className={styles.hardenedProof} aria-labelledby="hardened-proof-title" data-reveal>
          <div>
            <p className={styles.eyebrowOnProof}>Completed hardened proof</p>
            <h2 id="hardened-proof-title">Verify the consequence, not a claim about it.</h2>
            <p>
              This opens a separate hardened two-wallet run. Its governed result established conflict;
              preconfigured demo policy applied; Adapter opened the cure path; deployment configuration
              determined holders and payouts; on-chain aUSDC settlement then completed.
            </p>
          </div>
          <Link className={styles.proofPrimary} href="/protection/verified-run" data-testid="landing-to-verified-run">
            Verify the completed on-chain recourse
          </Link>
        </section>

      </main>

      <PublicFooter />
    </div>
  );
}
