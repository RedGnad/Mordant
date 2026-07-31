"use client";

import { useEffect, useRef } from "react";

import type {
  LivingRunArtifact,
  LivingSurface,
  RecordedCheckpointId,
} from "@/lib/dealroom/living-demo";

import styles from "./transaction-driven-experience.module.css";

export type CheckpointOption = {
  id: RecordedCheckpointId;
  label: string;
  actionId: string;
};

export function RecordedCheckpointRail({
  run,
  selectedId,
  surface,
  checkpoints,
  publicTimeline,
  compact = false,
  onSelect,
}: {
  readonly run: LivingRunArtifact;
  readonly selectedId: RecordedCheckpointId;
  readonly surface: LivingSurface;
  readonly checkpoints: ReadonlyArray<CheckpointOption>;
  readonly publicTimeline: boolean;
  readonly compact?: boolean;
  readonly onSelect: (id: RecordedCheckpointId) => void;
}) {
  const listRef = useRef<HTMLOListElement>(null);
  const railClass = compact
    ? styles.recordedTimeline
    : surface === "workspace"
    ? styles.workspaceQueue
    : surface === "participant"
      ? styles.participantHistory
      : styles.protocolTimeline;
  const railHeading = compact
    ? "Recorded case"
    : surface === "workspace"
    ? "Recorded case activity"
    : surface === "participant"
      ? "Your deal history"
      : "Confirmed transitions";
  const railSummary = compact
    ? "Choose a moment"
    : surface === "participant"
    ? "Choose a moment"
    : `${checkpoints.length} ${publicTimeline ? "moments" : "checkpoints"}`;

  useEffect(() => {
    const list = listRef.current;
    const selected = list?.querySelector<HTMLElement>("[data-selected='true']");
    if (list === null || list === undefined || selected === null || selected === undefined) return;
    const selectedOffset = window.matchMedia("(max-width: 760px)").matches
      ? selected.offsetLeft - 16
      : selected.offsetLeft - (list.clientWidth - selected.offsetWidth) / 2;
    list.scrollLeft = Math.max(0, selectedOffset);
  }, [selectedId]);

  return (
    <nav
      className={railClass}
      aria-label="Recorded run checkpoints"
      data-testid="recorded-checkpoint-rail"
      data-count={checkpoints.length}
      data-surface={surface}
      data-density={compact ? "compact" : "full"}
    >
      <header>
        <p>{railHeading}</p>
        <strong>{railSummary}</strong>
      </header>
      <ol ref={listRef}>
        {checkpoints.map((checkpoint) => {
          const action = run.actions.find((candidate) => candidate.id === checkpoint.actionId);
          const selected = checkpoint.id === selectedId;
          const checkpointMeta = surface === "protocol"
            ? `${action?.actorLabel ?? "Protocol"} · ${action?.status ?? "unavailable"}`
            : selected
              ? "Selected state"
              : action?.status === "confirmed" ? "Recorded" : "Unavailable";
          return (
            <li key={checkpoint.id}>
              <button
                type="button"
                aria-current={selected ? "step" : undefined}
                aria-pressed={selected}
                data-checkpoint-id={checkpoint.id}
                data-selected={selected ? "true" : "false"}
                disabled={action?.status !== "confirmed"}
                onClick={() => onSelect(checkpoint.id)}
              >
                <span className={styles.checkpointMarker} aria-hidden="true" />
                <strong>{checkpoint.label}</strong>
                {compact ? null : <small>{checkpointMeta}</small>}
              </button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
