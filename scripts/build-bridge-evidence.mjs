#!/usr/bin/env node
/**
 * Assembles the direct-participant bridge evidence for a completed run.
 *
 * The evidence is the artifact the BridgeExecutor verifies before it will
 * prepare anything, and it is assembled here from the run's own durable
 * outputs: the case binding, the durable admission ledger, the submission and
 * evaluation digests, the governed result as published, and the custom receipt.
 * Nothing is invented and nothing is copied from a caller.
 *
 *   node scripts/build-bridge-evidence.mjs --run <runId> [--run-root <path>]
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const argument = (name, fallback = null) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
};

const runId = argument("--run") ?? process.env.MORDANT_ACTIVATION_RUN_ID;
if (!runId) throw new Error("--run <runId> is required");
const runRoot = argument("--run-root") ?? join(process.env.MORDANT_WORKER_DATA_ROOT ?? ".", "runs");
const dir = join(runRoot, runId);

const sourceCommit = process.env.MORDANT_PROTECTION_SOURCE_COMMIT;
if (typeof sourceCommit !== "string" || !/^[0-9a-f]{40}$/u.test(sourceCommit)) {
  throw new Error("MORDANT_PROTECTION_SOURCE_COMMIT must be a full lowercase commit id");
}

const assembly = await import("../.product-test-dist/src/lib/protection/direct-participant-evidence-assembly.js");
const evidence = assembly.assembleDirectParticipantBridgeEvidence(runRoot, runId, sourceCommit);

const out = join(dir, "direct-participant-bridge-evidence.json");
writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`);
process.stdout.write(`wrote ${out}\n  evidenceDigest ${evidence.evidenceDigest}\n  governedResultDigest ${evidence.governedResultDigest}\n`);
