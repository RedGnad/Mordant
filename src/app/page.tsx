import type { Metadata } from "next";

import { PublicExperience } from "@/components/public-experience";
import { PROTECTION_STATES } from "@/lib/dealroom/living-demo";
import { getLivingDemoReviewRun } from "@/lib/dealroom/living-demo-review-server";

export const metadata: Metadata = {
  title: "Recourse for tokenized receivables",
  description: "Mordant detects conflicting claims, assigns responsibility, enforces deadlines, and retains verifiable evidence.",
};

export default function Home() {
  const run = getLivingDemoReviewRun();
  const action = run.actions.find((candidate) => candidate.id === "reveal");

  if (action === undefined || action.after == null || action.receipt === undefined) {
    throw new Error("The public proof checkpoint is missing from the retained run.");
  }

  return (
    <PublicExperience proof={{
      actor: action.actorLabel,
      action: action.title,
      before: PROTECTION_STATES[action.before.protectionState],
      after: PROTECTION_STATES[action.after.protectionState],
      block: action.receipt.blockNumber,
    }} />
  );
}
