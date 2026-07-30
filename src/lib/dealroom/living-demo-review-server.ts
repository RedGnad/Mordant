import "server-only";

import reviewArtifact from "../../../docs/evidence/m-ux2-public-complete-run-2026-07-30.json";

import {
  CONTROLLED_CHAIN_SOURCE,
  type LivingRunArtifact,
} from "@/lib/dealroom/living-demo";

function validateReviewArtifact(value: unknown): LivingRunArtifact {
  const run = value as LivingRunArtifact;
  const lastAction = run.actions?.at(-1);
  if (
    run.schemaVersion !== 1
    || run.source?.label !== CONTROLLED_CHAIN_SOURCE
    || run.source?.kind !== "controlled-demo-chain"
    || run.status !== "complete"
    || run.current?.protectionState !== 4
    || run.current?.receivableState !== 2
    || run.actions.length !== 14
    || lastAction?.id !== "redeem-b"
    || lastAction.status !== "confirmed"
    || lastAction.receipt?.status !== "success"
    || lastAction.after?.blockHash !== run.current.blockHash
  ) {
    throw new Error("The retained M-UX2 public review artifact is not a complete confirmed run.");
  }
  return run;
}

const RETAINED_REVIEW = validateReviewArtifact(reviewArtifact);

export function getLivingDemoReviewRun(): LivingRunArtifact {
  return RETAINED_REVIEW;
}
