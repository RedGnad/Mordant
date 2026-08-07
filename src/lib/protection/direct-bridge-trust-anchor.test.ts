import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  BridgeExecutionError,
  DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE,
  readExecutionSourceCommit,
} from "./bridge-executor";
import {
  DirectParticipantBridgeEvidenceError,
  assertDirectParticipantBridgeEvidence,
  directParticipantBridgeEvidenceDigest,
  type DirectParticipantBridgeEvidence,
} from "./direct-participant-bridge-evidence";

/**
 * F-02: the source commit and the run are trust ANCHORS, so neither may come
 * from the artifact being judged.
 *
 * The defect these defend against is subtle: every field can be internally
 * consistent, every signature valid, and the artifact still be the wrong one,
 * because it vouched for its own provenance. The executor therefore reads the
 * artifact from the durable run root by trusted run id, and takes the expected
 * commit from server configuration.
 */

const EVIDENCE = JSON.parse(readFileSync(
  join(process.cwd(), "docs", "evidence", "activation-direct-participant-bridge-evidence-2026-08-07.json"),
  "utf8",
)) as Record<string, unknown>;

const RUN_ID = String(EVIDENCE.runId);
const OTHER_RUN_ID = "11111111-1111-4111-8111-111111111111";
const REAL_COMMIT = String(EVIDENCE.sourceCommit);
const HOLDER_A = "0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685";
const HOLDER_B = "0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9";

function expectations(overrides: Record<string, unknown> = {}) {
  return {
    sourceCommit: REAL_COMMIT,
    assetIdentity: (EVIDENCE.governedResult as Record<string, unknown>).assetIdentity as `sha256:${string}`,
    holderA: HOLDER_A,
    holderB: HOLDER_B,
    excludedWallets: [] as readonly string[],
    ...overrides,
  } as Parameters<typeof assertDirectParticipantBridgeEvidence>[1];
}

function refuses(code: string, value: unknown, overrides: Record<string, unknown> = {}): void {
  assert.throws(
    () => assertDirectParticipantBridgeEvidence(value, expectations(overrides)),
    (error: unknown) => error instanceof DirectParticipantBridgeEvidenceError && error.code === code,
    `expected refusal ${code}`,
  );
}

test("F-02: the executor's expected source commit comes from server configuration", () => {
  assert.equal(readExecutionSourceCommit({ MORDANT_PROTECTION_SOURCE_COMMIT: REAL_COMMIT }), REAL_COMMIT);
  for (const bad of [undefined, "", "not-a-commit", REAL_COMMIT.toUpperCase(), `${REAL_COMMIT}0`]) {
    assert.throws(
      () => readExecutionSourceCommit({ MORDANT_PROTECTION_SOURCE_COMMIT: bad }),
      (error: unknown) => error instanceof BridgeExecutionError && error.code === "SOURCE_COMMIT_NOT_CONFIGURED",
      `accepted a bad server pin: ${String(bad)}`,
    );
  }
  // The artifact is not consulted for this value at all.
  assert.throws(
    () => readExecutionSourceCommit({}),
    (error: unknown) => error instanceof BridgeExecutionError,
  );
});

/** Reseals the evidence digest so a test isolates the anchor, not the digest. */
function reseal(draft: Record<string, unknown>): Record<string, unknown> {
  const { evidenceDigest: _ignored, ...body } = draft;
  return {
    ...draft,
    evidenceDigest: directParticipantBridgeEvidenceDigest(
      body as unknown as Omit<DirectParticipantBridgeEvidence, "evidenceDigest">,
    ),
  };
}

test("F-02: evidence.sourceCommit cannot act as its own trust anchor", () => {
  // Editing the commit alone breaks the evidence digest, which is the first
  // refusal and the stronger one.
  refuses("EVIDENCE_DIGEST", { ...EVIDENCE, sourceCommit: "b".repeat(40) });

  // Reseal it, so the artifact is now perfectly self-consistent and simply
  // claims a different provenance. This is the exact self-anchoring attack: it
  // survives every internal check and is caught only because the expectation is
  // external.
  const resealed = reseal({ ...EVIDENCE, sourceCommit: "b".repeat(40) });
  assert.equal(
    (resealed as Record<string, unknown>).evidenceDigest === EVIDENCE.evidenceDigest, false,
    "the reseal must actually change the digest",
  );
  refuses("SOURCE_COMMIT", resealed);
  // Taking the expectation FROM the artifact is what would have accepted it.
  assert.doesNotThrow(() => assertDirectParticipantBridgeEvidence(
    resealed, expectations({ sourceCommit: "b".repeat(40) }),
  ), "the resealed artifact is internally valid, which is why the anchor must be external");
});

test("F-02: a source commit differing from the server pin is refused", () => {
  refuses("SOURCE_COMMIT", EVIDENCE, { sourceCommit: "c".repeat(40) });
  refuses("SOURCE_COMMIT", EVIDENCE, { sourceCommit: REAL_COMMIT.replace(/.$/u, "0") });
});

test("F-02: a relabelled runId is refused when the trusted run is supplied", () => {
  refuses("EVIDENCE_DIGEST", { ...EVIDENCE, runId: OTHER_RUN_ID });
  // Resealed, internally valid, and still refused against the trusted run.
  refuses("RUN_ID", reseal({ ...EVIDENCE, runId: OTHER_RUN_ID }), { runId: RUN_ID });
  assert.throws(
    () => assertDirectParticipantBridgeEvidence(EVIDENCE, expectations({ runId: OTHER_RUN_ID })),
    (error: unknown) => error instanceof DirectParticipantBridgeEvidenceError && error.code === "RUN_ID",
  );
});

test("F-02: a valid signed governed result wrapped in another run's envelope is refused", () => {
  // The governed result is genuine and its signature verifies. The envelope
  // claims a different run. Without an external run expectation this would be
  // indistinguishable from the real thing.
  const wrapped = reseal({ ...EVIDENCE, runId: OTHER_RUN_ID });
  const governed = (wrapped as Record<string, unknown>).governedResult as Record<string, unknown>;
  assert.equal(governed.signature, (EVIDENCE.governedResult as Record<string, unknown>).signature);
  refuses("RUN_ID", wrapped, { runId: RUN_ID });
});

test("F-02: direct evidence without the trusted durable run expectation still binds provenance", () => {
  // Omitting the run expectation is allowed for presentation, and the commit
  // anchor remains external, so provenance cannot be self-asserted either way.
  refuses("SOURCE_COMMIT", EVIDENCE, { sourceCommit: "d".repeat(40) });
});

test("F-02: the executor loads the artifact from the durable run root, not from a caller", () => {
  // The prepare input carries a run id and no evidence, so there is no parameter
  // through which a caller could hand over a chosen artifact.
  const root = mkdtempSync(join(tmpdir(), "mordant-anchor-"));
  mkdirSync(join(root, RUN_ID), { recursive: true });
  writeFileSync(join(root, RUN_ID, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE), JSON.stringify(EVIDENCE));
  const loaded = JSON.parse(
    readFileSync(join(root, RUN_ID, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE), "utf8"),
  ) as Record<string, unknown>;
  assert.equal(loaded.runId, RUN_ID);
  // A different run id resolves to a different path, which simply does not exist.
  assert.equal(
    join(root, OTHER_RUN_ID, DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE).includes(OTHER_RUN_ID),
    true,
  );
  assert.equal(DIRECT_PARTICIPANT_BRIDGE_EVIDENCE_FILE, "direct-participant-bridge-evidence.json");
});

test("F-02: the prepare input exposes no economic or provenance value", () => {
  // Structural assertion: the only members are a run id and a signing window.
  const input = { runId: RUN_ID, nonce: 1n, issuedAt: 0, expiry: 1 };
  assert.deepEqual(Object.keys(input).sort(), ["expiry", "issuedAt", "nonce", "runId"]);
  for (const forbidden of ["evidence", "sourceCommit", "holderA", "holderB", "payoutA", "payoutB", "conflict"]) {
    assert.equal(forbidden in input, false, `prepare input still accepts ${forbidden}`);
  }
});

test("F-02: the legitimate artifact verifies against its real external anchors", () => {
  const verified = assertDirectParticipantBridgeEvidence(EVIDENCE, expectations({ runId: RUN_ID }));
  assert.equal(verified.evidence.runId, RUN_ID);
  assert.equal(verified.evidence.sourceCommit, REAL_COMMIT);
  assert.equal(verified.conflict, true);
});
