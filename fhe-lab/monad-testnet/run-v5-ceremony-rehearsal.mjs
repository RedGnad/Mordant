#!/usr/bin/env node
// Fresh local Run6 session followed only by the recoverable FHE key ceremony.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";

import { Journal, STATES } from "./v5-journal.mjs";
import { startLocalChain } from "./v5-local-chain.mjs";
import {
  artifact, CHAIN_ID, deployStack, localRunCapabilities,
} from "./v5-rehearsal-support.mjs";
import { runAdmissionPipeline } from "./v5-journalized-runner.mjs";
import {
  CEREMONY_STAGES, createLocalCeremonyCapability, runCeremonyPipeline,
} from "./v5-ceremony-flow.mjs";

const execFileAsync = promisify(execFile);

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

const rootOption = option("--root");
if (!rootOption) throw new Error("--root is required");
const root = resolve(rootOption);
const repoRoot = resolve(option("--repo") ?? process.cwd());
const journalPath = join(root, "journal.json");
const ceremonyRoot = join(root, "ceremony");
await mkdir(root, { recursive: true, mode: 0o700 });
const { stdout: sourceCommitOutput } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: repoRoot });
const sourceCommit = sourceCommitOutput.trim();

const chain = await startLocalChain();
let admission;
try {
  const stack = await deployStack(chain);
  const journal = await Journal.open(journalPath, { sourceCommit, chainId: CHAIN_ID });
  const capabilities = localRunCapabilities(chain, stack);
  const context = {
    chainId: CHAIN_ID,
    chain,
    client: chain.client,
    journal,
    capabilities,
    label: "recoverable-ceremony-rehearsal",
    privateRoot: join(root, "private"),
    topology: {
      at: stack.at,
      roles: stack.roles,
      config: stack.config,
      issuerKeyId: stack.issuerKeyId,
    },
    participants: {
      controllerA: stack.accounts.controllerA.address,
      controllerB: stack.accounts.controllerB.address,
    },
  };
  const paused = await runAdmissionPipeline(context);
  assert.equal(paused.at(-1).stage, "AWAITING_VAULT_APASS");
  const eligibility = await artifact("eligibility");
  const vault = context.journal.stage("VAULT_CREATED").predictedVault;
  const hash = await stack.tx.write(stack.accounts.deployer, {
    address: stack.at.eligibility,
    abi: eligibility.abi,
    functionName: "setIdentityValid",
    args: [vault, true],
  });
  const receipt = await chain.client.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, "success");
  await runAdmissionPipeline(context);
  assert.equal(context.journal.state("SESSION_COMMITTED"), STATES.CONFIRMED);
  assert.equal(context.journal.stage("SESSION_COMMITTED").verified, true);
  admission = {
    sessionCommitment: context.journal.stage("SESSION_COMMITTED").sessionCommitment,
    sessionNullifier: context.journal.stage("SESSION_COMMITTED").sessionNullifier,
    localChainId: CHAIN_ID,
  };
} finally {
  chain.stop();
}

const ceremonyStartedAt = Date.now();
const boundaries = [];
for (const stage of CEREMONY_STAGES) {
  let journal = await Journal.open(journalPath, { sourceCommit, chainId: CHAIN_ID });
  const retainReadyProcesses = stage === "CEREMONY_OPERATOR_3_READY";
  let ceremony = createLocalCeremonyCapability({
    repoRoot, ceremonyRoot, runnerJournal: journalPath, retainReadyProcesses,
  });
  await runCeremonyPipeline({ journal, ceremony, chainId: CHAIN_ID, stopAfter: stage });
  assert.equal(journal.state(stage), STATES.CONFIRMED, stage);
  const observed = await ceremony.inspect();
  boundaries.push({ stage, progress: observed.progress, ceremonyId: observed.context.ceremonyId,
    readyCount: observed.readyCount, stepDigest: observed.stepDigest, manifestDigest: observed.manifestDigest });
  if (retainReadyProcesses) {
    const shutdown = await ceremony.shutdownRetainedReadyProcesses(stage);
    boundaries.push({
      stage: "CRASH_AFTER_RUNNER_CONFIRMATION_BEFORE_PROCESS_SHUTDOWN",
      progress: observed.progress,
      readyCount: observed.readyCount,
      ceremonyId: observed.context.ceremonyId,
      stepDigest: observed.stepDigest,
      shutdown,
    });
  }

  // The existing protocol creates the contribution locally with operator
  // readiness, but the coordinator publishes them one-by-one. Exercise both
  // non-durable network interruption points before confirming the grouped
  // durable contribution stage.
  if (stage === "CEREMONY_OPERATOR_3_READY") {
    for (const checkpoint of ["contribution-1", "contribution-2"]) {
      ceremony = createLocalCeremonyCapability({ repoRoot, ceremonyRoot, runnerJournal: journalPath });
      await ceremony.runCheckpoint(checkpoint);
      const partial = await ceremony.inspect();
      boundaries.push({ stage: `CRASH_AFTER_${checkpoint.toUpperCase().replace("-", "_")}`,
        progress: partial.progress, readyCount: partial.readyCount,
        ceremonyId: partial.context.ceremonyId, stepDigest: partial.stepDigest });
    }
  }
  if (stage === "CEREMONY_COLLECTIVE_PUBLIC_KEY_COMPLETED") {
    ceremony = createLocalCeremonyCapability({ repoRoot, ceremonyRoot, runnerJournal: journalPath });
    await ceremony.runCheckpoint("relin-one");
    const partial = await ceremony.inspect();
    boundaries.push({ stage: "CRASH_AFTER_PARTIAL_EVALUATION_KEY", progress: partial.progress,
      readyCount: partial.readyCount, ceremonyId: partial.context.ceremonyId, stepDigest: partial.stepDigest });
  }
}

const completedJournal = await Journal.open(journalPath, { sourceCommit, chainId: CHAIN_ID });
const completedCeremony = createLocalCeremonyCapability({ repoRoot, ceremonyRoot, runnerJournal: journalPath });
const beforeRepeat = await completedCeremony.inspect();
await runCeremonyPipeline({ journal: completedJournal, ceremony: completedCeremony, chainId: CHAIN_ID });
const afterRepeat = await completedCeremony.inspect();
assert.equal(afterRepeat.stepDigest, beforeRepeat.stepDigest);
assert.deepEqual(afterRepeat.coreDigests, beforeRepeat.coreDigests);
for (const forbidden of [
  "ENROLLMENTS_ADMITTED", "EVALUATION_COMPLETED", "OPERATOR_RECOMPUTATION_COMPLETED",
  "THRESHOLD_RELEASE_COMPLETED", "VALIDATOR_ATTESTATIONS_COMPLETED", "DISCLOSURE_CONSENTS_COMPLETED",
  "BINDING_PREPARED", "BINDING_BROADCAST", "BINDING_CONFIRMED",
]) {
  assert.equal(completedJournal.state(forbidden), STATES.NOT_STARTED, forbidden);
}
const report = {
  schemaVersion: "mordant.recoverable-ceremony-local-rehearsal/1",
  classification: "FRESH LOCAL ONLY — NO MONAD BROADCAST",
  sourceCommit,
  admission,
  ceremonyId: afterRepeat.context.ceremonyId,
  rosterDigest: afterRepeat.rosterDigest,
  manifestDigest: afterRepeat.manifestDigest,
  operatorStepDigest: afterRepeat.stepDigest,
  attestations: afterRepeat.attestations,
  secretAudits: afterRepeat.audits,
  coreDigests: afterRepeat.coreDigests,
  crashBoundaries: boundaries,
  completedCeremonyRepeatRefused: true,
  stoppedAt: "CEREMONY_COMPLETED",
  totalCeremonyWallMillis: Date.now() - ceremonyStartedAt,
  oneHostLimitation: "process separation on one host is not independent organizational custody",
  productVerdict: "PRIVATE MATCHING AND GOVERNED RECOURSE: NOT PROVEN",
};
const reportPath = join(ceremonyRoot, "public", "local-rehearsal.json");
await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o644 });
process.stdout.write(`${JSON.stringify({ reportPath, ceremonyId: report.ceremonyId,
  manifestDigest: report.manifestDigest, stoppedAt: report.stoppedAt }, null, 2)}\n`);
