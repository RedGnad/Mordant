import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";

import { createProtectionOrchestrator, type ProtectionRuntimeOptions } from "./governed-fhe-product-server";
import {
  SupervisedPledgeWindowsError,
  assertSupervisedPledgeWindows,
  isSupervisedPledgeWindows,
} from "./supervised-pledge-windows";

const CONFLICTING = {
  participantA: { activeFrom: 120, activeUntil: 420 },
  participantB: { activeFrom: 220, activeUntil: 520 },
} as const;

const DISJOINT = {
  participantA: { activeFrom: 120, activeUntil: 300 },
  participantB: { activeFrom: 420, activeUntil: 620 },
} as const;

function rejects(label: string, value: unknown, code: string): void {
  assert.throws(
    () => assertSupervisedPledgeWindows(value),
    (error: unknown) => error instanceof SupervisedPledgeWindowsError && error.code === code,
    `${label} must be rejected with ${code}`,
  );
}

test("the exact custom pledge shape is accepted and frozen", () => {
  const windows = assertSupervisedPledgeWindows(structuredClone(CONFLICTING));
  assert.equal(windows.participantA.activeFrom, 120);
  assert.equal(windows.participantB.activeUntil, 520);
  assert.equal(Object.isFrozen(windows), true);
  assert.equal(Object.isFrozen(windows.participantA), true);
  assert.equal(isSupervisedPledgeWindows(structuredClone(DISJOINT)), true);
});

test("every malformed custom pledge shape is rejected without coercion", () => {
  const window = () => ({ activeFrom: 1, activeUntil: 2 });

  rejects("null", null, "PLEDGE_WINDOWS_FIELDS");
  rejects("array", [], "PLEDGE_WINDOWS_FIELDS");
  rejects("string", "conflict", "PLEDGE_WINDOWS_FIELDS");
  rejects("missing participantB", { participantA: window() }, "PLEDGE_WINDOWS_FIELDS");
  rejects("unknown top-level key", { ...CONFLICTING, participantC: window() }, "PLEDGE_WINDOWS_FIELDS");
  rejects("null participant", { participantA: window(), participantB: null }, "PLEDGE_WINDOW_FIELDS");
  rejects("unknown window key", {
    participantA: { ...window(), note: "x" }, participantB: window(),
  }, "PLEDGE_WINDOW_FIELDS");
  rejects("missing activeUntil", { participantA: { activeFrom: 1 }, participantB: window() }, "PLEDGE_WINDOW_FIELDS");

  // No coercion of any kind.
  rejects("numeric string", { participantA: { activeFrom: "1", activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("float", { participantA: { activeFrom: 1.5, activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("NaN", { participantA: { activeFrom: Number.NaN, activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("Infinity", { participantA: { activeFrom: 1, activeUntil: Number.POSITIVE_INFINITY }, participantB: window() }, "PLEDGE_WINDOW_UNTIL");
  rejects("boolean", { participantA: { activeFrom: true, activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("null bound", { participantA: { activeFrom: null, activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("negative", { participantA: { activeFrom: -1, activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("negative zero", { participantA: { activeFrom: -0, activeUntil: 2 }, participantB: window() }, "PLEDGE_WINDOW_FROM");
  rejects("beyond safe integers", {
    participantA: { activeFrom: 1, activeUntil: Number.MAX_SAFE_INTEGER + 2 }, participantB: window(),
  }, "PLEDGE_WINDOW_UNTIL");
  rejects("bigint", { participantA: { activeFrom: 1, activeUntil: 2 }, participantB: { activeFrom: 1, activeUntil: 2n } }, "PLEDGE_WINDOW_UNTIL");
});

test("activeFrom >= activeUntil is rejected before any dispatch", () => {
  const window = () => ({ activeFrom: 1, activeUntil: 2 });
  rejects("equal bounds", { participantA: { activeFrom: 5, activeUntil: 5 }, participantB: window() }, "PLEDGE_WINDOW_ORDER");
  rejects("inverted bounds", { participantA: { activeFrom: 9, activeUntil: 4 }, participantB: window() }, "PLEDGE_WINDOW_ORDER");
  rejects("inverted on B", { participantA: window(), participantB: { activeFrom: 700, activeUntil: 700 } }, "PLEDGE_WINDOW_ORDER");
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "mordant-custom-pledge-"));
  const base: ProtectionRuntimeOptions = {
    runRoot: join(root, "runs"),
    binRoot: join(root, "bin"),
    retentionRoot: join(root, "retained"),
    importedEvidenceRoot: join(root, "imported"),
    expectedSourceCommit: "b5587f6489933c6dc462da7fda56e57bd5f9e31b",
    skipBinaryBuild: true,
    statfsAvailableBytes: () => Number.MAX_SAFE_INTEGER,
    // A freshly created case has published nothing yet, so reconciliation only
    // needs an empty inspection. No FHE work is involved in these tests.
    binaryRunner: async <T>(binary: string) => {
      if (binary !== "inspect") throw new Error(`unexpected binary ${binary}`);
      return {
        finalized: false, evaluationAdmission: false, releaseAdmission: false,
        foundationPrivateComplete: false, releasePrivateComplete: false, ambiguous: false,
      } as T;
    },
  };
  return { root, base };
}

const RUN_A = "33333333-3333-4333-8333-333333333333";
const RUN_B = "44444444-4444-4444-8444-444444444444";

test("the fixed-fixture create path is unchanged and stores no override", async () => {
  const { base } = await harness();
  const view = await createProtectionOrchestrator(base).createProtectionCase("no-conflict", RUN_A);
  assert.equal(view.protectionCase.productScenario, "no-conflict");
  const state = JSON.parse(readFileSync(join(base.runRoot!, RUN_A, "execution.json"), "utf8")) as Record<string, unknown>;
  assert.equal("supervisedPledgeWindows" in state, false);
});

test("a custom case is authorized under the neutral V2 variant, whatever the windows", async () => {
  const { base } = await harness();
  // Overlapping and non-overlapping windows must produce the SAME neutral
  // pre-release shape. Nothing about the expected result is derivable here.
  const overlapping = await createProtectionOrchestrator(base)
    .createProtectionCase("conflict", RUN_A, structuredClone(CONFLICTING));
  const disjoint = await createProtectionOrchestrator(base)
    .createProtectionCase("conflict", RUN_B, structuredClone(DISJOINT));

  for (const runId of [RUN_A, RUN_B]) {
    const state = JSON.parse(readFileSync(join(base.runRoot!, runId, "execution.json"), "utf8")) as Record<string, unknown>;
    assert.equal(state.executionVariant, "CUSTOM_SUPERVISED");
  }
  // Neither case exposes a governed result before release.
  assert.equal(overlapping.governedResult, null);
  assert.equal(disjoint.governedResult, null);
  // The two cases differ only by their random nonce, never by an outcome.
  assert.notEqual(overlapping.protectionCase.fheCaseId, disjoint.protectionCase.fheCaseId);
});

test("custom windows never reach the public view or the operation journal", async () => {
  const { base } = await harness();
  // Distinctive bounds, so a bare substring search is a meaningful leak test
  // rather than a coincidence against digests or ordinary small integers.
  const distinctive = {
    participantA: { activeFrom: 918_273_641, activeUntil: 918_273_644 },
    participantB: { activeFrom: 918_273_642, activeUntil: 918_273_646 },
  };
  const view = await createProtectionOrchestrator(base).createProtectionCase("conflict", RUN_A, distinctive);
  assert.equal(view.protectionCase.productScenario, "conflict");

  const serializedView = JSON.stringify(view);
  for (const secret of [
    "918273641", "918273644", "918273642", "918273646",
    "supervisedPledgeWindows", "activeFrom", "activeUntil",
  ]) {
    assert.equal(serializedView.includes(secret), false, `public view leaked ${secret}`);
  }

  const journal = await readFile(join(base.runRoot!, RUN_A, "operation-journal.json"), "utf8").catch(() => "");
  for (const secret of [
    "918273641", "918273644", "918273642", "918273646",
    "supervisedPledgeWindows", "activeFrom", "activeUntil",
  ]) {
    assert.equal(journal.includes(secret), false, `journal leaked ${secret}`);
  }
});

test("custom windows live only in the private execution state", async () => {
  const { base } = await harness();
  await createProtectionOrchestrator(base).createProtectionCase("conflict", RUN_A, structuredClone(CONFLICTING));
  const state = JSON.parse(readFileSync(join(base.runRoot!, RUN_A, "execution.json"), "utf8")) as Record<string, unknown>;
  assert.deepEqual(state.supervisedPledgeWindows, CONFLICTING);
});

test("an invalid custom window is refused at create, before any run directory work", async () => {
  const { base } = await harness();
  await assert.rejects(
    () => createProtectionOrchestrator(base).createProtectionCase("conflict", RUN_A, {
      participantA: { activeFrom: 9, activeUntil: 4 },
      participantB: { activeFrom: 1, activeUntil: 2 },
    } as never),
    (error: unknown) => error instanceof SupervisedPledgeWindowsError && error.code === "PLEDGE_WINDOW_ORDER",
  );
});

test("creation recovery preserves the custom private run", async () => {
  const { base } = await harness();
  const first = await createProtectionOrchestrator(base)
    .createProtectionCase("conflict", RUN_A, structuredClone(CONFLICTING));
  // A lost create response is replayed through a fresh orchestrator.
  const recovered = await createProtectionOrchestrator(base)
    .createProtectionCase("conflict", RUN_A, structuredClone(CONFLICTING));
  assert.equal(recovered.runId, first.runId);
  assert.equal(recovered.protectionCase.fheCaseId, first.protectionCase.fheCaseId);
  const state = JSON.parse(readFileSync(join(base.runRoot!, RUN_A, "execution.json"), "utf8")) as Record<string, unknown>;
  assert.deepEqual(state.supervisedPledgeWindows, CONFLICTING);
});
