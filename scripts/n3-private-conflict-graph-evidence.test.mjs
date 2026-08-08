#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  N3_EVIDENCE_RELATIVE_PATH,
  N3_EVIDENCE_VERDICT,
  computeN3EvidenceDigest,
  validateN3PrivateConflictGraphEvidence,
} from "./validate-n3-private-conflict-graph-evidence.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ARTIFACT_PATH = join(ROOT, N3_EVIDENCE_RELATIVE_PATH);
const COMPILED_CORE_PATH = join(
  ROOT,
  ".product-test-dist/src/lib/protection/receivable-conflict-session.js",
);
const ALTERNATE_DIGEST = `sha256:${"f".repeat(64)}`;

const core = await import(pathToFileURL(COMPILED_CORE_PATH).href);
const retainedEvidence = JSON.parse(readFileSync(ARTIFACT_PATH, "utf8"));

function cloneEvidence() {
  return structuredClone(retainedEvidence);
}

async function reseal(evidence) {
  evidence.evidenceDigest = await computeN3EvidenceDigest(evidence);
  return evidence;
}

async function expectValidatorCode(evidence, code) {
  await assert.rejects(
    validateN3PrivateConflictGraphEvidence({ evidence }),
    (error) => {
      assert.equal(error?.code, code);
      return true;
    },
  );
}

async function expectValidatorFailure(evidence, pattern) {
  await assert.rejects(validateN3PrivateConflictGraphEvidence({ evidence }), pattern);
}

function flipSignature(signature) {
  const bytes = Buffer.from(signature, "base64");
  assert.ok(bytes.length > 0, "retained signature must decode");
  bytes[0] ^= 0x01;
  return bytes.toString("base64");
}

function pairByLabel(evidence, label) {
  const pair = evidence.graph.pairs.find((candidate) => candidate.label === label);
  assert.ok(pair, `missing retained pair ${label}`);
  return pair;
}

function relationForPair(aggregate, pair) {
  const relation = aggregate.pairRelations.find((candidate) => (
    candidate.claimPair.pairId === pair.leaf.claimPair.pairId
  ));
  assert.ok(relation, `missing aggregate relation ${pair.label}`);
  return relation;
}

function replayEvidence({ skipLabel, corruptLabel } = {}) {
  const evidence = retainedEvidence;
  const session = new core.ReceivableConflictSession({
    graphSessionId: evidence.graph.session.graphSessionId,
    receivableIdentity: evidence.graph.session.receivableIdentity,
    issuedAtUnix: evidence.graph.session.issuedAtUnix,
    expiresAtUnix: evidence.graph.session.expiresAtUnix,
    pins: evidence.graph.aggregate.pins,
  });
  const claimsById = new Map(evidence.graph.claims.map((claim) => (
    [claim.authorization.claimId, claim.authorization]
  )));
  const pairsById = new Map(evidence.graph.pairs.map((pair) => (
    [pair.leaf.claimPair.pairId, pair]
  )));
  let corruptionError = null;

  for (const event of evidence.graph.chronology.events) {
    if (event.kind === "CLAIM_ADMITTED") {
      const claim = claimsById.get(event.claimId);
      assert.ok(claim, "chronology admitted an unknown claim");
      session.admitClaim(claim, event.occurredAt);
      continue;
    }
    if (event.kind === "ADMISSIONS_SEALED") {
      session.sealAdmissions(event.occurredAt);
      continue;
    }
    if (event.kind !== "PAIR_COMPLETED") continue;
    const pair = pairsById.get(event.pairId);
    assert.ok(pair, "chronology completed an unknown pair");
    if (pair.label === skipLabel) return { session, corruptionError };

    const leaf = structuredClone(pair.leaf);
    if (pair.label === corruptLabel) {
      leaf.governedResult.signature = flipSignature(leaf.governedResult.signature);
    }
    try {
      session.ingestPairEvidence(leaf, pair.binding, pair.intent, leaf.execution.completedAt);
    } catch (error) {
      if (pair.label !== corruptLabel) throw error;
      corruptionError = error;
    }
  }
  return { session, corruptionError };
}

test("accepts the exact retained N=3 proof envelope", async () => {
  const result = await validateN3PrivateConflictGraphEvidence({ evidence: retainedEvidence });
  assert.equal(result.verdict, N3_EVIDENCE_VERDICT);
  assert.equal(result.evidenceDigest, retainedEvidence.evidenceDigest);
  assert.equal(result.aggregateRoot, retainedEvidence.graph.aggregate.aggregateRoot);
});

test("rejects an altered evidence body when the canonical outer digest is stale", async () => {
  const candidate = cloneEvidence();
  candidate.assertions[0].description += " altered";
  await expectValidatorCode(candidate, "EVIDENCE_DIGEST");
});

test("binds each retained raw Go inspection report into its sanitized leaf", async () => {
  const candidate = cloneEvidence();
  candidate.graph.pairs[0].inspectReport.submissionA.artifactBytes += 1;
  await reseal(candidate);
  await expectValidatorCode(candidate, "INSPECTION_REPORT_DIGEST");
});

test("rejects raw interval openings even inside assertion evidence", async () => {
  const candidate = cloneEvidence();
  candidate.assertions[0].evidence.activeFrom = 100;
  candidate.assertions[0].evidence.activeUntil = 200;
  await reseal(candidate);
  await expectValidatorCode(candidate, "EVIDENCE_SANITATION");
});

test("rejects an absolute filesystem path from retained evidence", async () => {
  const candidate = cloneEvidence();
  candidate.assertions[0].evidence.operatorPath = "/tmp/mordant-private-opening.json";
  await reseal(candidate);
  await expectValidatorCode(candidate, "EVIDENCE_SANITATION");
});

test("rejects a cross-session evidence leaf", async () => {
  const candidate = cloneEvidence();
  candidate.graph.pairs[0].leaf.graphSessionId = ALTERNATE_DIGEST;
  await reseal(candidate);
  await expectValidatorFailure(candidate, /CROSS_SESSION_LEAF/u);
});

for (const mutation of [
  { name: "asset", field: "assetIdentity", value: ALTERNATE_DIGEST },
  { name: "policy", field: "policyId", value: ALTERNATE_DIGEST },
  { name: "circuit", field: "circuitId", value: "mordant.unreviewed-circuit" },
  { name: "parameter profile", field: "parameterFingerprint", value: ALTERNATE_DIGEST },
]) {
  test(`rejects an independently mutated ${mutation.name} pin before signature acceptance`, async () => {
    const candidate = cloneEvidence();
    candidate.graph.pairs[0].leaf.governedResult[mutation.field] = mutation.value;
    await reseal(candidate);
    await expectValidatorFailure(candidate, /PAIR_RESULT_PINS/u);
  });
}

test("a missing A/C leaf remains PARTIAL and cannot support a global all-clear", async () => {
  const { session } = replayEvidence({ skipLabel: "A/C" });
  const aggregate = session.aggregate();
  const missingRelation = relationForPair(aggregate, pairByLabel(retainedEvidence, "A/C"));
  assert.equal(missingRelation.state, "PENDING");
  assert.equal(aggregate.completeness, "PARTIAL");
  assert.equal(aggregate.reviewState, "AWAITING_EVIDENCE");
  assert.equal(aggregate.globalAllClear, null);
  assert.throws(
    () => core.claimGlobalAllClear(aggregate.completeness, aggregate.pairRelations),
    /ALL_CLEAR_INCOMPLETE/u,
  );

  const candidate = cloneEvidence();
  candidate.graph.pairs.splice(1, 1);
  await reseal(candidate);
  await expectValidatorCode(candidate, "GRAPH_PAIRS");
});

test("a corrupt A/C signature is isolated while A/B and B/C remain independently valid", async () => {
  const nodes = retainedEvidence.graph.aggregate.nodes;
  for (const label of ["A/B", "B/C"]) {
    const pair = pairByLabel(retainedEvidence, label);
    assert.doesNotThrow(() => core.verifyGraphPairEvidenceLeaf(
      pair.leaf,
      pair.binding,
      pair.intent,
      nodes,
      retainedEvidence.graph.aggregate.pins,
    ));
  }

  const { session, corruptionError } = replayEvidence({ corruptLabel: "A/C" });
  assert.match(String(corruptionError), /PAIR_RESULT_SIGNATURE/u);
  const aggregate = session.aggregate();
  assert.equal(relationForPair(aggregate, pairByLabel(retainedEvidence, "A/B")).state, "CONFLICT");
  assert.equal(relationForPair(aggregate, pairByLabel(retainedEvidence, "A/C")).state, "FAILED");
  assert.equal(relationForPair(aggregate, pairByLabel(retainedEvidence, "B/C")).state, "CONFLICT");
  assert.equal(aggregate.completeness, "PARTIAL");
  assert.equal(aggregate.globalAllClear, null);

  const candidate = cloneEvidence();
  const corruptPair = pairByLabel(candidate, "A/C");
  corruptPair.leaf.governedResult.signature = flipSignature(corruptPair.leaf.governedResult.signature);
  await reseal(candidate);
  await expectValidatorFailure(candidate, /PAIR_RESULT_SIGNATURE/u);
});

test("denies an unrelated claimant and rejects an overbroad claimant projection", async () => {
  assert.throws(
    () => core.projectClaimantGraph(retainedEvidence.graph.aggregate, ALTERNATE_DIGEST),
    /CLAIMANT_MEMBERSHIP/u,
  );

  const candidate = cloneEvidence();
  const claimant = candidate.graph.projections.claimants[0];
  const unrelated = candidate.graph.aggregate.pairRelations.find((relation) => (
    relation.claimPair.leftClaimId !== claimant.claimId
      && relation.claimPair.rightClaimId !== claimant.claimId
  ));
  assert.ok(unrelated, "three-node graph must have one pair unrelated to each claimant");
  claimant.relations.push(unrelated);
  await reseal(candidate);
  await expectValidatorFailure(candidate, /GRAPH_PROJECTIONS|CLAIMANT_PROJECTION_SCOPE/u);
});

test("refuses to derive a global all-clear from one non-conflicting pair", () => {
  const pair = pairByLabel(retainedEvidence, "A/C");
  const relation = relationForPair(retainedEvidence.graph.aggregate, pair);
  assert.equal(relation.state, "NO_CONFLICT_UNDER_POLICY");
  assert.throws(
    () => core.claimGlobalAllClear("COMPLETE", [relation]),
    /ALL_CLEAR_INCOMPLETE/u,
  );
});

test("rejects a tampered side-effect claim", async () => {
  const candidate = cloneEvidence();
  candidate.sideEffectScan.pairs[0].recourseRecordPresent = true;
  await reseal(candidate);
  await expectValidatorCode(candidate, "SIDE_EFFECT_RECOURSE_RECORD");
});

test("rejects a zeroization claim that the experiment cannot make", async () => {
  const candidate = cloneEvidence();
  candidate.retention.productionModel.authorizationPrivateKeyZeroizationClaimed = true;
  await reseal(candidate);
  await expectValidatorCode(candidate, "RETENTION_PRODUCTION_PRIVATE_KEY_ZEROIZATION");
});

test("rejects any widening of the supported review boundary", async () => {
  const candidate = cloneEvidence();
  candidate.supportedClaims.push("The experiment supports arbitrary N and concurrent pair execution.");
  await reseal(candidate);
  await expectValidatorCode(candidate, "SUPPORTED_CLAIMS");
});
