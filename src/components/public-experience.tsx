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
    story: "Mordant checks the encrypted claim windows without holding the decryption key.",
  },
  {
    label: "Governed result",
    detail: "Signed conflict status",
    story: "The governed result establishes only whether the submitted claim windows conflict. A precommitted governed recourse policy selects the next bounded action; human approval applies where that policy requires it.",
  },
  {
    label: "Onchain recourse",
    detail: "Bounded aUSDC rail",
    story: "In the separate hardened run, preconfigured demo policy opened the cure path and deployment configuration determined holders and payouts before settlement.",
  },
] as const;

const SCROLL_DRIVEN_INTEGRATION = "(min-width: 901px) and (min-height: 620px)";
// The decision colour owns a short horizontal runway on both junctions.
// Those few pixels keep a colour change and a direction change from collapsing
// into the same sharp, visually broken corner.
const INTEGRATION_RUNWAY = 10;
const INTEGRATION_ROUTE = "M150 120H390L470 40H660L740 120H1050";
const INTEGRATION_DIAGONAL_LENGTH = Math.hypot(80, 80);
const INTEGRATION_ROUTE_LENGTH = 240 + INTEGRATION_DIAGONAL_LENGTH + 190 + INTEGRATION_DIAGONAL_LENGTH + 310;
const INTEGRATION_REVEAL_INSET = 12;
// Exact distances to the four authored junctions. Rounded progress values put
// the travelling square a few pixels beyond a corner at some viewport scales.
const INTEGRATION_TARGETS = [
  230 / INTEGRATION_ROUTE_LENGTH,
  (240 + INTEGRATION_DIAGONAL_LENGTH) / INTEGRATION_ROUTE_LENGTH,
  (240 + INTEGRATION_DIAGONAL_LENGTH + 190 + INTEGRATION_DIAGONAL_LENGTH + INTEGRATION_RUNWAY) / INTEGRATION_ROUTE_LENGTH,
  1,
] as const;
const INTEGRATION_INITIAL_REVEAL = Math.max(
  0,
  INTEGRATION_TARGETS[0] - (INTEGRATION_REVEAL_INSET / INTEGRATION_ROUTE_LENGTH),
);

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
  const integrationRevealRef = useRef<SVGPathElement>(null);
  const integrationSignalRef = useRef<SVGGElement>(null);
  const integrationTetherRef = useRef<SVGLineElement>(null);
  const heroScrollFrame = useRef<number | null>(null);
  const integrationScrollFrame = useRef<number | null>(null);
  const integrationMotionFrame = useRef<number | null>(null);
  const integrationMotionProgress = useRef<number>(INTEGRATION_TARGETS[0]);
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
      hero.style.setProperty("--symbol-scroll-y", `${progress * -88}px`);
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
      if (!window.matchMedia(SCROLL_DRIVEN_INTEGRATION).matches
        || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const bounds = flow.getBoundingClientRect();
      // The state changes while the whole rail still occupies the viewport.
      // Basing this on the rail's top (rather than its full height) prevents the
      // final state from arriving only after the hardened-proof section appears.
      const activeStart = window.innerHeight * 0.76;
      const activeEnd = window.innerHeight * 0.34;
      if (bounds.top > activeStart || bounds.top < activeEnd) return;

      const progress = Math.min(1, Math.max(0, (activeStart - bounds.top) / Math.max(1, activeStart - activeEnd)));
      const nextStep = progress < 0.2 ? 0 : progress < 0.46 ? 1 : progress < 0.72 ? 2 : 3;
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
    const reveal = integrationRevealRef.current;
    const signal = integrationSignalRef.current;
    const tether = integrationTetherRef.current;
    if (path === null || reveal === null || signal === null || tether === null) return;

    const from = integrationMotionProgress.current;
    const to = INTEGRATION_TARGETS[integrationStep] ?? INTEGRATION_TARGETS[0];
    const length = path.getTotalLength();
    const placeSignal = (progress: number) => {
      const distance = length * progress;
      const point = path.getPointAtLength(distance);
      const precedingPoint = path.getPointAtLength(Math.max(0, distance - 2));
      const incomingAngle = Math.atan2(
        point.y - precedingPoint.y,
        point.x - precedingPoint.x,
      ) * (180 / Math.PI);
      // Stop the masked route just inside the travelling square. This prevents
      // the next coloured segment from peeking beyond a junction; the tether
      // below overlaps this inset and keeps the route visibly continuous.
      const revealProgress = Math.max(0, (distance - INTEGRATION_REVEAL_INSET) / length);
      // The route is causal: it ends beneath the travelling signal in either
      // direction. Reverse playback therefore retracts in exact lockstep and
      // can never expose a responsibility the signal has not reached.
      reveal.setAttribute("stroke-dashoffset", `${1 - revealProgress}`);
      signal.setAttribute("transform", `translate(${point.x} ${point.y})`);
      const signalColour = progress <= INTEGRATION_TARGETS[0]
        ? "var(--receivable)"
        : progress <= INTEGRATION_TARGETS[2]
          ? "var(--protection)"
          : "var(--action)";
      signal.style.setProperty("--integration-signal-colour", signalColour);
      // A short, co-moving incoming segment removes sub-pixel gaps caused by
      // SVG mask rasterisation. It sits behind the square and follows the real
      // path tangent, so it cannot reveal any future part of the route.
      tether.setAttribute("transform", `rotate(${incomingAngle})`);
      integrationMotionProgress.current = progress;
    };

    if (integrationMotionFrame.current !== null) {
      window.cancelAnimationFrame(integrationMotionFrame.current);
    }

    signal.dataset.arrived = "false";
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || from === to) {
      placeSignal(to);
      signal.dataset.arrived = "true";
      return;
    }

    const startedAt = performance.now();
    const duration = 280 + Math.abs(to - from) * 360;
    const animate = (now: number) => {
      // A first rAF timestamp can be a fraction earlier than performance.now().
      // Clamping both ends prevents reverse motion from briefly overshooting
      // beyond the completed route and leaving a permanent mask fragment.
      const elapsed = Math.min(1, Math.max(0, (now - startedAt) / duration));
      const eased = 1 - Math.pow(1 - elapsed, 3);
      placeSignal(from + ((to - from) * eased));
      if (elapsed < 1) integrationMotionFrame.current = window.requestAnimationFrame(animate);
      else {
        signal.dataset.arrived = "true";
        integrationMotionFrame.current = null;
      }
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
    integrationInteractionLockUntil.current = interactionTimestamp + 900;
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
            <Link className={styles.secondary} href="/protection/verified-run">Inspect verified evidence</Link>
          </div>
        </section>

        {/* 2. The real check, immediately. The economic problem this replaced
            said the same thing in a paragraph; here a visitor can run it. */}
        {liveCheckHolder === null ? null : <MiniLiveCheck publicTestHolder={liveCheckHolder} />}

        {/* 3. The one retained responsibility model after the experiment. */}
        <section className={styles.invitation} id="how" aria-labelledby="invitation-title" data-reveal>
          <div className={styles.invitationText}>
            <p className={styles.eyebrow}>Responsibility</p>
            <h2 id="invitation-title">
              <span>One path.</span>{" "}
              <span>Four bounded responsibilities.</span>
            </h2>
          </div>

          {/* The four institutional boundaries remain distinct, but the compact
              landing gives their route the full editorial width. The preserved
              Stable / Conflict / Recourse / Proof scrollytelling remains unmounted. */}
          <div className={styles.flow} data-step={integrationStep} aria-label="Interactive integration path" ref={integrationFlowRef}>
            <div className={styles.flowCanvas}>
              <svg className={styles.flowGraphic} viewBox="0 0 1200 180" aria-hidden="true">
                <defs>
                  <mask id="integration-route-reveal" maskUnits="userSpaceOnUse" x="100" y="0" width="1000" height="180">
                    <path
                      ref={integrationRevealRef}
                      className={styles.flowRouteReveal}
                      d={INTEGRATION_ROUTE}
                      pathLength="1"
                      strokeDasharray="1"
                      strokeDashoffset={1 - INTEGRATION_INITIAL_REVEAL}
                    />
                  </mask>
                </defs>
                <path ref={integrationPathRef} className={styles.flowMotionPath} d={INTEGRATION_ROUTE} />
                <g mask="url(#integration-route-reveal)">
                  <path className={`${styles.flowRouteSegment} ${styles.flowRouteInput}`} d="M150 120H380" />
                  <path className={`${styles.flowRouteSegment} ${styles.flowRouteDecision}`} d="M380 120H390L470 40H660L740 120H750" />
                  <path className={`${styles.flowRouteSegment} ${styles.flowRouteAction}`} d="M750 120H1050" />
                </g>
                <g ref={integrationSignalRef} className={styles.integrationSignal} data-arrived="true" transform="translate(380 120)">
                  <line ref={integrationTetherRef} className={styles.integrationTether} x1="-42" y1="0" x2="2" y2="0" />
                  <rect x="-18" y="-18" width="36" height="36" />
                </g>
              </svg>
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
                  <span className={styles.integrationStageIndex}>0{index + 1}</span>
                  <span className={styles.integrationStageCopy}>
                    <strong>{stage.label}</strong>
                    <small>{stage.detail}</small>
                  </span>
                </button>
              ))}
            </div>
            <p className={styles.integrationStory} aria-live="polite">
              <span key={integrationStep}>{INTEGRATION_STEPS[integrationStep].story}</span>
            </p>
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
