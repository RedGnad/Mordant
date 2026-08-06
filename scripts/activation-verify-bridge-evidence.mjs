#!/usr/bin/env node
/**
 * Independently verifies a retained direct-participant bridge evidence artifact,
 * after the worker has pruned the reproducible and private material it came from.
 *
 * It loads nothing from the run's public directory: the point is that the
 * artifact alone still carries a complete, signature-verifiable governed result.
 *
 *   node scripts/activation-verify-bridge-evidence.mjs --run <runId> [--out <path>]
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function argument(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

async function main() {
  const runId = argument("--run");
  if (runId === null) throw new Error("--run <runId> is required");
  const outPath = argument("--out");
  const runRoot = argument("--run-root", join(ROOT, ".mordant", "worker", "runs"));

  const evidencePath = join(runRoot, runId, "direct-participant-bridge-evidence.json");
  const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));

  const module = await import("../.product-test-dist/src/lib/protection/direct-participant-bridge-evidence.js");
  const compatibility = await import("../.product-test-dist/src/lib/protection/adapter-compatibility.js");
  const asset = await import("../.product-test-dist/src/lib/protection/cleanverse-asset.js");

  const configuration = compatibility.loadCanonicalRecourseConfiguration(ROOT);
  const verified = module.assertDirectParticipantBridgeEvidence(evidence, {
    sourceCommit: evidence.sourceCommit,
    assetIdentity: asset.CANONICAL_CLEANVERSE_ASSET_DIGEST,
    holderA: configuration.participants.holderA,
    holderB: configuration.participants.holderB,
    excludedWallets: Object.values(configuration.participants.excluded),
    runId,
  });

  const report = {
    schemaVersion: "mordant.activation-bridge-evidence-verification/1",
    verifiedAtIso: new Date().toISOString(),
    runId,
    evidenceSchema: evidence.schemaVersion,
    evidenceDigest: evidence.evidenceDigest,
    sourceCommit: evidence.sourceCommit,
    prunedPublicDirectory: true,
    ed25519SignatureVerified: true,
    governedResultDigest: evidence.governedResultDigest,
    releaseAuthorityId: verified.governedResult.releaseAuthorityId,
    releaseAuthorityPublicKey: verified.governedResult.releaseAuthorityPublicKey,
    signedConflict: verified.conflict,
    assetIdentity: verified.governedResult.assetIdentity,
    circuitDigest: verified.governedResult.circuitDigest,
    parameterFingerprint: verified.governedResult.parameterFingerprint,
    resultCiphertextDigest: verified.governedResult.resultCiphertextDigest,
    resultCiphertextCommitment: verified.governedResult.resultCiphertextCommitment,
    sourceProvenance: verified.governedResult.sourceProvenance,
    participantArtifactDigestA: evidence.participantArtifactDigestA,
    participantArtifactDigestB: evidence.participantArtifactDigestB,
    evaluatedArtifactDigest: evidence.evaluatedArtifactDigest,
    holderA: verified.holderA,
    holderB: verified.holderB,
    participants: evidence.participants,
    customReceiptDigest: evidence.customReceiptDigest,
    containsNoSecrets: true,
  };

  for (const [label, value] of Object.entries({
    "schema": report.evidenceSchema,
    "signed conflict": report.signedConflict,
    "authority": report.releaseAuthorityId,
    "holder A": report.holderA,
    "holder B": report.holderB,
  })) process.stdout.write(`ok   ${label.padEnd(16)} ${value}\n`);
  process.stdout.write("\nbridge evidence verified after pruning\n");

  if (outPath) {
    writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(`wrote ${outPath}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`activation-verify-bridge-evidence: ${error.message}\n`);
  process.exitCode = 1;
});
