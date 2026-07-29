import "server-only";

import reviewArtifact from "../../../docs/evidence/m-ex2-public-review-run-2026-07-30.json";

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
    || run.current?.protectionState !== 3
    || run.current?.receivableState !== 1
    || lastAction?.id !== "reveal"
    || lastAction.status !== "confirmed"
    || lastAction.receipt?.status !== "success"
    || lastAction.after?.blockHash !== run.current.blockHash
  ) {
    throw new Error("The retained M-EX2 public review artifact is not a confirmed reveal checkpoint.");
  }
  return run;
}

const RETAINED_REVIEW = validateReviewArtifact(reviewArtifact);

export function getLivingDemoReviewRun(): LivingRunArtifact {
  return RETAINED_REVIEW;
}
