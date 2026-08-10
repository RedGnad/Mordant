import assert from "node:assert/strict";
import { chmodSync, cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadCanonicalRecourseConfiguration } from "./adapter-compatibility";
import { CANONICAL_CLEANVERSE_ASSET_DIGEST } from "./cleanverse-asset";
import { assertDirectParticipantBridgeEvidence } from "./direct-participant-bridge-evidence";
import {
  DirectParticipantEvidenceAssemblyError,
  assembleDirectParticipantBridgeEvidence,
} from "./direct-participant-evidence-assembly";

/**
 * A durable run fixture, retained so the assembler is exercised against real
 * worker output rather than a hand-written shape.
 */
const FIXTURE = "test/fixtures/direct-participant-run";
const RUN = "68f91d48-534f-4583-851e-7d9b880ce0dc";
const SOURCE_COMMIT = "0".repeat(40);

const available = existsSync(join(process.cwd(), FIXTURE, RUN, "execution.json"));

function makeWritable(path: string): void {
  // The worker publishes its artifacts read-only, and cpSync preserves that.
  // A tamper control has to be able to write, so the staged copy is relaxed.
  chmodSync(path, 0o700);
  if (!statSync(path).isDirectory()) return;
  for (const entry of readdirSync(path)) makeWritable(join(path, entry));
}

function stagedRun(): string {
  const root = mkdtempSync(join(tmpdir(), "mordant-evidence-"));
  cpSync(join(process.cwd(), FIXTURE), root, { recursive: true });
  makeWritable(root);
  return root;
}

function accepts(runRoot: string): void {
  const evidence = assembleDirectParticipantBridgeEvidence(runRoot, RUN, SOURCE_COMMIT);
  const configuration = loadCanonicalRecourseConfiguration(process.cwd(), "case");
  assertDirectParticipantBridgeEvidence(evidence, {
    sourceCommit: SOURCE_COMMIT,
    runId: RUN,
    assetIdentity: CANONICAL_CLEANVERSE_ASSET_DIGEST,
    holderA: configuration.participants.holderA,
    holderB: configuration.participants.holderB,
    excludedWallets: Object.values(configuration.participants.excluded),
  });
}

/** Applies a tamper to one durable artifact and reports how the chain refuses. */
function refusalAfterTamper(relative: string, mutate: (value: Record<string, unknown>) => void): string {
  const runRoot = stagedRun();
  try {
    const path = join(runRoot, RUN, relative);
    const value = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    mutate(value);
    writeFileSync(path, JSON.stringify(value, null, 2));
    try {
      accepts(runRoot);
    } catch (error) {
      return (error as { code?: string }).code ?? (error as Error).name;
    }
    return assert.fail(`tampering with ${relative} was accepted`);
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
}

test("assembly is deterministic for the same durable run", { skip: !available }, () => {
  const runRoot = stagedRun();
  try {
    const first = assembleDirectParticipantBridgeEvidence(runRoot, RUN, SOURCE_COMMIT);
    const second = assembleDirectParticipantBridgeEvidence(runRoot, RUN, SOURCE_COMMIT);
    assert.equal(first.evidenceDigest, second.evidenceDigest);
    assert.deepEqual(first, second);
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("assembled evidence is accepted by the canonical executor validation", { skip: !available }, () => {
  const runRoot = stagedRun();
  try {
    assert.doesNotThrow(() => accepts(runRoot));
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------ tamper controls

test("a changed participant admission digest is refused", { skip: !available }, () => {
  const code = refusalAfterTamper(join("admissions", "participant_a.json"), (record) => {
    record.authorizationDigest = `sha256:${"99".repeat(32)}`;
  });
  assert.ok(code.length > 0, "the chain must name its refusal");
});

test("a changed participant wallet is refused", { skip: !available }, () => {
  const code = refusalAfterTamper(join("admissions", "participant_b.json"), (record) => {
    record.participantWallet = "0x9999999999999999999999999999999999999999";
  });
  assert.ok(code.length > 0);
});

test("a changed case binding is refused", { skip: !available }, () => {
  const code = refusalAfterTamper(join("public", "case-binding.json"), (record) => {
    record.caseId = `sha256:${"99".repeat(32)}`;
  });
  assert.ok(code.length > 0);
});

test("a changed governed result is refused", { skip: !available }, () => {
  const code = refusalAfterTamper(join("public", "governed-conflict-result.json"), (record) => {
    record.conflict = false;
  });
  assert.ok(code.length > 0);
});

test("a changed release authority is refused", { skip: !available }, () => {
  const code = refusalAfterTamper(join("public", "case-binding.json"), (record) => {
    record.releaseAuthorityId = `sha256:${"99".repeat(32)}`;
  });
  assert.ok(code.length > 0);
});

test("a changed evaluation digest is refused", { skip: !available }, () => {
  const code = refusalAfterTamper("execution.json", (record) => {
    (record.evaluation as Record<string, unknown>).artifactDigest = `sha256:${"99".repeat(32)}`;
  });
  assert.ok(code.length > 0);
});

test("assembly refuses a run that has not produced its digests yet", { skip: !available }, () => {
  const runRoot = stagedRun();
  try {
    const path = join(runRoot, RUN, "execution.json");
    const value = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    delete value.evaluation;
    writeFileSync(path, JSON.stringify(value, null, 2));
    assert.throws(
      () => assembleDirectParticipantBridgeEvidence(runRoot, RUN, SOURCE_COMMIT),
      (error: unknown) => error instanceof DirectParticipantEvidenceAssemblyError && error.code === "INCOMPLETE_EXECUTION",
    );
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});

test("assembly refuses an unusable source commit", { skip: !available }, () => {
  const runRoot = stagedRun();
  try {
    assert.throws(
      () => assembleDirectParticipantBridgeEvidence(runRoot, RUN, "not-a-commit"),
      (error: unknown) => error instanceof DirectParticipantEvidenceAssemblyError && error.code === "SOURCE_COMMIT",
    );
  } finally {
    rmSync(runRoot, { recursive: true, force: true });
  }
});
