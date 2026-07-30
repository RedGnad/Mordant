import type { Metadata } from "next";

import { PublicExperience } from "@/components/public-experience";
import { PROTECTION_STATES } from "@/lib/dealroom/living-demo";
import { getLivingDemoReviewRun } from "@/lib/dealroom/living-demo-review-server";

export const metadata: Metadata = {
  title: "Recourse for tokenized receivables",
  description: "Mordant turns confirmed receivables exceptions into governed action and verifiable evidence.",
};

export default function Home() {
  const run = getLivingDemoReviewRun();
  const action = run.actions.find((candidate) => candidate.id === "reveal");

  if (action === undefined || action.after == null || action.receipt === undefined) {
    throw new Error("The public proof checkpoint is missing from the retained run.");
  }

  const deadline = new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC",
  }).format(new Date(Number(action.after.pendingConflict.cureDeadline) * 1000));

  return (
    <PublicExperience proof={{
      actor: action.actorLabel,
      action: action.title,
      before: PROTECTION_STATES[action.before.protectionState],
      after: PROTECTION_STATES[action.after.protectionState],
      block: action.receipt.blockNumber,
      deadline: `${deadline} UTC`,
    }} />
  );
}
