import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  EVIDENCE_PATH,
  EXACT_CLAIM,
  SCHEMA_VERSION,
  digestEvidenceBody,
  validateN2IsolationEvidence,
} from "./validate-n2-isolation-evidence.mjs";

function retainedEvidence() {
  return JSON.parse(readFileSync(EVIDENCE_PATH, "utf8"));
}

function resign(evidence) {
  const body = structuredClone(evidence);
  delete body.evidenceDigest;
  return { ...body, evidenceDigest: digestEvidenceBody(body) };
}

test("the retained N=2 artifact satisfies the proof-grade schema and invariants", () => {
  const evidence = retainedEvidence();
  assert.equal(evidence.schemaVersion, SCHEMA_VERSION);
  assert.equal(evidence.exactClaimSupported, EXACT_CLAIM);
  assert.deepEqual(validateN2IsolationEvidence(evidence), []);
});

test("the validator rejects an altered evidence body without a matching digest", () => {
  const evidence = retainedEvidence();
  evidence.concurrency.executionOverlapMs += 1;
  assert.match(validateN2IsolationEvidence(evidence).join("\n"), /evidenceDigest/u);
});

test("the validator rejects weakened native concurrency evidence even when resigned", () => {
  const evidence = retainedEvidence();
  evidence.concurrency.nativeEvaluatorsSimultaneous.observed = false;
  evidence.concurrency.nativeEvaluatorsSimultaneous.processCount = 0;
  assert.match(validateN2IsolationEvidence(resign(evidence)).join("\n"), /native evaluator/u);
});

test("the validator requires canonical 404 and UNKNOWN_CASE cross-worker refusals", () => {
  const evidence = retainedEvidence();
  evidence.isolation.foreignReads.workerAReadingRunB.code = "ROUTE";
  assert.match(validateN2IsolationEvidence(resign(evidence)).join("\n"), /404\/UNKNOWN_CASE/u);
});

test("the validator rejects absolute paths and private input fields", () => {
  const absolutePath = retainedEvidence();
  absolutePath.nativeBuild.outputRootId = "/tmp/native-binaries";
  assert.match(validateN2IsolationEvidence(resign(absolutePath)).join("\n"), /absolute path/u);

  const privateWindow = retainedEvidence();
  privateWindow.slots[0].activeFrom = 120;
  assert.match(validateN2IsolationEvidence(resign(privateWindow)).join("\n"), /forbidden key/u);
});

test("the validator rejects a widened claim and a mismatched receipt", () => {
  const widened = retainedEvidence();
  widened.exactClaimSupported = "Execution scales linearly.";
  assert.match(validateN2IsolationEvidence(resign(widened)).join("\n"), /exact supported claim/u);

  const mismatchedReceipt = retainedEvidence();
  mismatchedReceipt.isolation.receipts.slotB.runId = mismatchedReceipt.slots[0].request.runId;
  assert.match(validateN2IsolationEvidence(resign(mismatchedReceipt)).join("\n"), /slot B terminal receipt/u);
});
