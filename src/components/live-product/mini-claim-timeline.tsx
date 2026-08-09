"use client";

import {
  useRef,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";

import styles from "./mini-live-check.module.css";

export const MINI_TIMELINE_MIN = 0;
export const MINI_TIMELINE_MAX = 600;
const DRAG_STEP = 20;
const PAGE_STEP = 100;

type ClaimBounds = Readonly<{
  from: string;
  until: string;
}>;

type ClaimLaneProps = Readonly<{
  claim: "A" | "B";
  bounds: ClaimBounds;
  disabled: boolean;
  onChange: (edge: "from" | "until", value: string) => void;
}>;

type TimelineProps = Readonly<{
  claimA: ClaimBounds;
  claimB: ClaimBounds;
  disabled: boolean;
  onChangeA: ClaimLaneProps["onChange"];
  onChangeB: ClaimLaneProps["onChange"];
}>;

type VisualWindow = Readonly<{ from: number; until: number }>;

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

/** Reads one lane only. It deliberately has no access to the other claim. */
function visualWindowOf(bounds: ClaimBounds): VisualWindow | null {
  const from = /^\d+$/u.test(bounds.from.trim()) ? Number(bounds.from) : Number.NaN;
  const until = /^\d+$/u.test(bounds.until.trim()) ? Number(bounds.until) : Number.NaN;
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(until)) return null;
  if (from < MINI_TIMELINE_MIN || until > MINI_TIMELINE_MAX || from >= until) return null;
  return Object.freeze({ from, until });
}

function positionOf(value: number): string {
  return `${((value - MINI_TIMELINE_MIN) / (MINI_TIMELINE_MAX - MINI_TIMELINE_MIN)) * 100}%`;
}

function ClaimLane({ claim, bounds, disabled, onChange }: ClaimLaneProps) {
  const track = useRef<HTMLDivElement | null>(null);
  const visual = visualWindowOf(bounds);

  const move = (edge: "from" | "until", rawValue: number) => {
    if (visual === null || disabled) return;
    const minimum = edge === "from" ? MINI_TIMELINE_MIN : visual.from + 1;
    const maximum = edge === "from" ? visual.until - 1 : MINI_TIMELINE_MAX;
    onChange(edge, String(clamp(rawValue, minimum, maximum)));
  };

  const moveFromPointer = (edge: "from" | "until", clientX: number) => {
    const boundsRect = track.current?.getBoundingClientRect();
    if (boundsRect === undefined || boundsRect.width === 0) return;
    const ratio = clamp((clientX - boundsRect.left) / boundsRect.width, 0, 1);
    const raw = MINI_TIMELINE_MIN + ratio * (MINI_TIMELINE_MAX - MINI_TIMELINE_MIN);
    move(edge, Math.round(raw / DRAG_STEP) * DRAG_STEP);
  };

  const handlePointerDown = (edge: "from" | "until", event: ReactPointerEvent<HTMLSpanElement>) => {
    if (disabled || visual === null) return;
    event.preventDefault();
    const pointerId = event.pointerId;
    moveFromPointer(edge, event.clientX);
    const drag = (moveEvent: globalThis.PointerEvent) => {
      if (moveEvent.pointerId !== pointerId) return;
      moveFromPointer(edge, moveEvent.clientX);
    };
    const stop = (endEvent: globalThis.PointerEvent) => {
      if (endEvent.pointerId !== pointerId) return;
      window.removeEventListener("pointermove", drag);
      window.removeEventListener("pointerup", stop);
      window.removeEventListener("pointercancel", stop);
    };
    window.addEventListener("pointermove", drag);
    window.addEventListener("pointerup", stop);
    window.addEventListener("pointercancel", stop);
  };

  const handleKeyDown = (edge: "from" | "until", event: KeyboardEvent<HTMLSpanElement>) => {
    if (visual === null || disabled) return;
    const current = edge === "from" ? visual.from : visual.until;
    let next: number | null = null;
    if (event.key === "ArrowLeft" || event.key === "ArrowDown") next = current - DRAG_STEP;
    if (event.key === "ArrowRight" || event.key === "ArrowUp") next = current + DRAG_STEP;
    if (event.key === "PageDown") next = current - PAGE_STEP;
    if (event.key === "PageUp") next = current + PAGE_STEP;
    if (event.key === "Home") next = edge === "from" ? MINI_TIMELINE_MIN : visual.from + 1;
    if (event.key === "End") next = edge === "from" ? visual.until - 1 : MINI_TIMELINE_MAX;
    if (next === null) return;
    event.preventDefault();
    move(edge, next);
  };

  const renderHandle = (edge: "from" | "until", value: number) => {
    const name = edge === "from" ? "active from" : "active until";
    const minimum = edge === "from" ? MINI_TIMELINE_MIN : (visual?.from ?? MINI_TIMELINE_MIN) + 1;
    const maximum = edge === "from" ? (visual?.until ?? MINI_TIMELINE_MAX) - 1 : MINI_TIMELINE_MAX;
    return (
      <span
        className={styles.timelineHandle}
        style={{ "--handle-position": positionOf(value) } as CSSProperties}
        role="slider"
        tabIndex={disabled ? -1 : 0}
        aria-label={`Financing claim ${claim} ${name}`}
        aria-valuemin={minimum}
        aria-valuemax={maximum}
        aria-valuenow={value}
        aria-valuetext={`${value} synthetic units`}
        aria-disabled={disabled}
        data-testid={`claim-${claim.toLowerCase()}-${edge}-handle`}
        onKeyDown={(event) => handleKeyDown(edge, event)}
        onPointerDown={(event) => handlePointerDown(edge, event)}
      >
        <span aria-hidden="true" />
      </span>
    );
  };

  return (
    <div className={styles.timelineLane} data-testid={`claim-${claim.toLowerCase()}-lane`}>
      <span className={styles.laneLabel}>Claim {claim}</span>
      <div className={styles.laneTrack} ref={track}>
        {visual === null ? (
          <span className={styles.invalidLane}>Enter valid bounds</span>
        ) : (
          <>
            <span
              className={styles.timelineBand}
              style={{
                "--band-start": positionOf(visual.from),
                "--band-end": positionOf(visual.until),
              } as CSSProperties}
              aria-hidden="true"
            />
            {renderHandle("from", visual.from)}
            {renderHandle("until", visual.until)}
          </>
        )}
      </div>
      <output className={styles.laneValues} aria-live="off">
        {visual === null ? "—" : `${visual.from}–${visual.until}`}
      </output>
    </div>
  );
}

/**
 * A neutral direct-manipulation view of visitor-entered geometry. It never
 * receives, derives or styles an interpretation of the relationship between lanes.
 */
export function MiniClaimTimeline({
  claimA,
  claimB,
  disabled,
  onChangeA,
  onChangeB,
}: TimelineProps) {
  return (
    <div className={styles.timeline} data-testid="mini-claim-timeline">
      <div className={styles.timelineHeading}>
        <strong>Shared synthetic timeline · 0–600</strong>
      </div>
      <p className={styles.timelineExplanation}>
        Place both financing claims on the same timeline. These are synthetic time units for the demo—not dates or block numbers.
      </p>
      <div className={styles.timelinePlot}>
        <ClaimLane claim="A" bounds={claimA} disabled={disabled} onChange={onChangeA} />
        <ClaimLane claim="B" bounds={claimB} disabled={disabled} onChange={onChangeB} />
        <div className={styles.timelineTicks} aria-hidden="true">
          {[0, 100, 200, 300, 400, 500, 600].map((tick) => (
            <span key={tick} data-mobile-tick={tick % 200 === 0 ? "true" : "false"}>{tick}</span>
          ))}
        </div>
      </div>
      <p className={styles.timelineBoundary}>
        Placement only. The browser never interprets the relationship between these claims.
      </p>
    </div>
  );
}
