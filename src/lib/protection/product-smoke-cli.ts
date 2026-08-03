import { join } from "node:path";

import type { ProductScenario } from "./protection-case";
import {
  completeCureChronology,
  createProtectionCase,
  evaluatePrivateConflict,
  exportProtectionEvidence,
  openRecourseCase,
  preparePrivateMatch,
  releaseGovernedResult,
  retainProtectionEvidence,
  submitParticipantPledge,
  validateRetainedPublicArtifacts,
} from "./governed-fhe-product-server";

async function main() {
  const scenario = process.argv[2] as ProductScenario | undefined;
  if (scenario !== "conflict" && scenario !== "no-conflict") {
    throw new Error("usage: product-smoke-cli <conflict|no-conflict>");
  }
  let view = await createProtectionCase(scenario);
  view = await preparePrivateMatch(view.runId);
  view = await submitParticipantPledge(view.runId, "PARTICIPANT_A");
  view = await submitParticipantPledge(view.runId, "PARTICIPANT_B");
  view = await evaluatePrivateConflict(view.runId);
  view = await releaseGovernedResult(view.runId);
  view = await openRecourseCase(view.runId);
  const exactRetry = await openRecourseCase(view.runId);
  if (JSON.stringify(exactRetry.recourse) !== JSON.stringify(view.recourse)) {
    throw new Error("exact recourse retry was not idempotent");
  }
  if (scenario === "conflict") view = await completeCureChronology(view.runId);
  view = await exportProtectionEvidence(view.runId);
  const destination = join(
    process.cwd(),
    "docs",
    "evidence",
    "conflicting-pledge-protection",
    `${scenario}.json`,
  );
  retainProtectionEvidence(view.runId, destination);
  const validation = validateRetainedPublicArtifacts(view.runId);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "mordant.protection-smoke/1",
    scenario,
    runId: view.runId,
    stage: view.stage,
    conflict: view.governedResult?.conflict,
    recourseOpened: view.recourse?.opened,
    originalReceivable: view.protectionCase.originalReceivable.state,
    evidenceDigest: validation.evidenceDigest,
    governedResultDigest: validation.governedResultDigest,
    privateMarkersAbsent: validation.privateMarkersAbsent,
    retainedEvidence: destination,
  }, null, 2)}\n`);
}

void main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
