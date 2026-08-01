#!/usr/bin/env node
// Continue an existing durable V5 session through CEREMONY_COMPLETED only.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { Journal, STATES } from "./v5-journal.mjs";
import {
  createLocalCeremonyCapability, runCeremonyPipeline,
} from "./v5-ceremony-flow.mjs";

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

const journalPath = resolve(option("--journal") ?? process.env.V5_RUN_JOURNAL ?? "");
const ceremonyRoot = resolve(option("--ceremony-root") ?? process.env.V5_CEREMONY_ROOT ?? "");
const repoRoot = resolve(option("--repo") ?? process.cwd());
const stopAfter = option("--stop-after") ?? undefined;

if (!option("--journal") && !process.env.V5_RUN_JOURNAL) throw new Error("--journal is required");
if (!option("--ceremony-root") && !process.env.V5_CEREMONY_ROOT) throw new Error("--ceremony-root is required");

const header = JSON.parse(await readFile(journalPath, "utf8"));
const journal = await Journal.open(journalPath, {
  sourceCommit: header.sourceCommit,
  chainId: Number(header.chainId),
});
if (journal.state("SESSION_COMMITTED") !== STATES.CONFIRMED || !journal.stage("SESSION_COMMITTED").verified) {
  throw new Error("SESSION_COMMITTED must be independently verified before the ceremony");
}
const ceremony = createLocalCeremonyCapability({ repoRoot, ceremonyRoot, runnerJournal: journalPath });
await runCeremonyPipeline({ journal, ceremony, chainId: Number(header.chainId), stopAfter });
const completed = journal.stage("CEREMONY_COMPLETED");
process.stdout.write(`${JSON.stringify({
  stage: "CEREMONY_COMPLETED",
  state: completed.state,
  ceremonyId: completed.verification?.ceremonyId ?? journal.stage("CEREMONY_CONTEXT_PREPARED").ceremonyId,
  manifestDigest: completed.verification?.manifestDigest ?? null,
  productVerdict: "PRIVATE MATCHING AND GOVERNED RECOURSE: NOT PROVEN",
}, null, 2)}\n`);
