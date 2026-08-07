import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  CaseAdapterProofError,
  loadCaseAdapterDeploymentProof,
  loadCaseAdapterDeploymentProofForRun,
  resolveCaseAdapterDeploymentProofFile,
} from "./case-adapter-deployment-proof";

/**
 * F-04 resolution: the proof that settles a case must be the one naming THAT
 * adapter and THAT run, found by its contents.
 *
 * The defect these defend against is a resolver that knows one file name. Every
 * later case-specific deployment retains its own proof, so a fixed name silently
 * answers a question about run B with the evidence of run A, and every downstream
 * check then verifies the wrong deployment perfectly. The rule here is narrow:
 * content decides, exactly one claimant decides, and a claimant that is malformed
 * is still the claimant, so it fails rather than being stepped over.
 */

const REVIEWED_FILE = "recourse-adapter-v2-deployment-2026-08-06.json";

const HISTORICAL_FILE = "activation-case-adapter-deployment-2026-08-07.json";
const HISTORICAL_ADAPTER = "0x00efE6AAcaC6Aa94A3c66d8F09D310197600D935";
const HISTORICAL_RUN = "76005a0c-2787-4c50-b196-636e45b71781";

const HARDENED_FILE = "hardened-case-adapter-deployment-2026-08-07.json";
const HARDENED_ADAPTER = "0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1";
const HARDENED_RUN = "e618abc2-0ac7-4d79-b201-44959a54b68c";

function committed(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(process.cwd(), "docs", "evidence", name), "utf8")) as Record<string, unknown>;
}

/** A scratch evidence root holding exactly the named proof files and nothing else. */
function evidenceRoot(files: Readonly<Record<string, Record<string, unknown>>>): string {
  const root = mkdtempSync(join(tmpdir(), "mordant-proof-resolution-"));
  const directory = join(root, "docs", "evidence");
  mkdirSync(directory, { recursive: true });
  cpSync(join(process.cwd(), "docs", "evidence", REVIEWED_FILE), join(directory, REVIEWED_FILE));
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(join(directory, name), JSON.stringify(contents, null, 2));
  }
  return root;
}

/** The two retained proofs as committed, so the fixtures are the real artifacts. */
function bothProofs(): Record<string, Record<string, unknown>> {
  return { [HISTORICAL_FILE]: committed(HISTORICAL_FILE), [HARDENED_FILE]: committed(HARDENED_FILE) };
}

function refuses(code: string, act: () => unknown): void {
  assert.throws(
    act,
    (error: unknown) => error instanceof CaseAdapterProofError && error.code === code,
    `expected refusal ${code}`,
  );
}

/** Makes `name` the newest file in the root, so any mtime preference would show. */
function makeNewest(root: string, name: string): void {
  const future = new Date(Date.now() + 3_600_000);
  utimesSync(join(root, "docs", "evidence", name), future, future);
}

test("F-04 resolution: the first historical proof is found by its contents", () => {
  const root = evidenceRoot(bothProofs());
  assert.equal(resolveCaseAdapterDeploymentProofFile(HISTORICAL_ADAPTER, HISTORICAL_RUN, root), HISTORICAL_FILE);
  const proof = loadCaseAdapterDeploymentProofForRun(HISTORICAL_ADAPTER, HISTORICAL_RUN, root);
  assert.equal(proof.address.toLowerCase(), HISTORICAL_ADAPTER.toLowerCase());
  assert.equal(proof.runId, HISTORICAL_RUN);
  assert.equal(proof.immutables.cureWindow, 600);
});

test("F-04 resolution: the current hardened proof is found by its contents", () => {
  const root = evidenceRoot(bothProofs());
  assert.equal(resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, root), HARDENED_FILE);
  const proof = loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN, root);
  assert.equal(proof.address.toLowerCase(), HARDENED_ADAPTER.toLowerCase());
  assert.equal(proof.runId, HARDENED_RUN);
  assert.equal(proof.immutables.cureWindow, 600);
  // The two proofs are genuinely different deployments of the reviewed contract:
  // same masked artifact, different live runtime and different authority pin.
  const historical = loadCaseAdapterDeploymentProofForRun(HISTORICAL_ADAPTER, HISTORICAL_RUN, root);
  assert.notEqual(proof.deployedCodeHash, historical.deployedCodeHash);
  assert.notEqual(
    proof.immutables.expectedGovernedReleaseAuthorityId,
    historical.immutables.expectedGovernedReleaseAuthorityId,
  );
  assert.equal(proof.artifactMaskedHash, historical.artifactMaskedHash);
});

test("F-04 resolution: both retained proofs resolve in the real committed evidence tree", () => {
  // The regression that matters: in the repository as it stands, each run finds
  // its own proof and neither is reachable only because it was named first.
  assert.equal(resolveCaseAdapterDeploymentProofFile(HISTORICAL_ADAPTER, HISTORICAL_RUN), HISTORICAL_FILE);
  assert.equal(resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN), HARDENED_FILE);
  assert.equal(loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN).runId, HARDENED_RUN);
});

test("F-04 resolution: zero matching proofs is a refusal, not a fallback", () => {
  // Only the historical proof is retained, and the hardened run is asked for.
  const historicalOnly = evidenceRoot({ [HISTORICAL_FILE]: committed(HISTORICAL_FILE) });
  refuses("PROOF_UNRESOLVED", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, historicalOnly));
  refuses("PROOF_UNRESOLVED", () => loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN, historicalOnly));
  // An evidence directory with no proof at all, and one with no directory.
  const empty = evidenceRoot({});
  refuses("PROOF_UNRESOLVED", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, empty));
  const absent = mkdtempSync(join(tmpdir(), "mordant-proof-resolution-absent-"));
  refuses("PROOF_DIRECTORY", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, absent));
});

test("F-04 resolution: two proofs for the same adapter and run are ambiguous, and the newest does not win", () => {
  const duplicate = { ...bothProofs(), "zzz-second-copy.json": committed(HARDENED_FILE) };
  const root = evidenceRoot(duplicate);
  makeNewest(root, "zzz-second-copy.json");
  refuses("PROOF_AMBIGUOUS", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, root));
  refuses("PROOF_AMBIGUOUS", () => loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN, root));
  // The refusal names the claimants, so an operator can see what collided.
  assert.throws(
    () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, root),
    (error: unknown) => error instanceof CaseAdapterProofError
      && error.message.includes(HARDENED_FILE)
      && error.message.includes("zzz-second-copy.json"),
  );
  // A disagreeing second copy is no better: two answers is still no answer, so a
  // hostile duplicate cannot be resolved by preferring either one.
  const conflicting = committed(HARDENED_FILE);
  (conflicting.immutables as Record<string, unknown>).cureWindow = 60;
  const contested = evidenceRoot({ ...bothProofs(), "aaa-earlier-copy.json": conflicting });
  refuses("PROOF_AMBIGUOUS", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, contested));
  // The other run is untouched by the collision on this one.
  assert.equal(resolveCaseAdapterDeploymentProofFile(HISTORICAL_ADAPTER, HISTORICAL_RUN, contested), HISTORICAL_FILE);
});

test("F-04 resolution: a proof matching only the run cannot answer for another address", () => {
  const root = evidenceRoot(bothProofs());
  // The hardened run exists and the historical address exists, but no retained
  // proof claims that pair, so the half-match is refused rather than returned.
  refuses("PROOF_UNRESOLVED", () => resolveCaseAdapterDeploymentProofFile(HISTORICAL_ADAPTER, HARDENED_RUN, root));
  refuses(
    "PROOF_UNRESOLVED",
    () => resolveCaseAdapterDeploymentProofFile("0x1111111111111111111111111111111111111111", HARDENED_RUN, root),
  );
  refuses("PROOF_ADDRESS", () => resolveCaseAdapterDeploymentProofFile("not-an-address", HARDENED_RUN, root));
});

test("F-04 resolution: a proof matching only the address cannot answer for another run", () => {
  const root = evidenceRoot(bothProofs());
  refuses("PROOF_UNRESOLVED", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HISTORICAL_RUN, root));
  refuses(
    "PROOF_UNRESOLVED",
    () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, "11111111-1111-4111-8111-111111111111", root),
  );
  refuses("PROOF_RUN", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, "", root));
});

test("F-04 resolution: a malformed proof that claims this run fails, it is never stepped over", () => {
  // Each mutation keeps the claimed address and run intact, so the file stays the
  // one and only claimant. The strict parser and the reviewed-owner check are
  // still what refuse it, which is the point: resolution added no leniency.
  const malformed: readonly (readonly [string, (proof: Record<string, unknown>) => void])[] = [
    ["PROOF_MASKED", (proof) => { proof.maskedMatchesReviewedArtifact = false; }],
    ["PROOF_MASKED", (proof) => { proof.deployedMaskedHash = `0x${"9".repeat(64)}`; }],
    ["PROOF_DIGEST", (proof) => { proof.deployedCodeHash = "0xnothex"; }],
    ["PROOF_DIGEST", (proof) => { proof.transactionHash = "0xshort"; }],
    ["PROOF_NUMBER", (proof) => { proof.runtimeBytes = 0; }],
    ["PROOF_IMMUTABLES", (proof) => { delete (proof.immutables as Record<string, unknown>).cureWindow; }],
    ["PROOF_OWNER", (proof) => {
      (proof.immutables as Record<string, unknown>).owner = "0x3333333333333333333333333333333333333333";
    }],
  ];
  for (const [code, mutate] of malformed) {
    const broken = committed(HARDENED_FILE);
    mutate(broken);
    // The healthy historical proof sits right next to it and must not be borrowed.
    const root = evidenceRoot({ [HISTORICAL_FILE]: committed(HISTORICAL_FILE), [HARDENED_FILE]: broken });
    assert.equal(resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, root), HARDENED_FILE);
    refuses(code, () => loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN, root));
  }
  // A malformed claimant beside a healthy one for the SAME pair is ambiguous, so
  // breaking a proof can never promote a second one into its place.
  const beside = evidenceRoot({
    ...bothProofs(),
    "zzz-broken-copy.json": { ...committed(HARDENED_FILE), maskedMatchesReviewedArtifact: false },
  });
  refuses("PROOF_AMBIGUOUS", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, beside));
});

test("F-04 resolution: a foreign proof cannot be substituted by its file name", () => {
  // The hardened name over the historical contents: the name is the lie, so the
  // resolver must read past it and find no claimant for the hardened run.
  const disguised = evidenceRoot({ [HARDENED_FILE]: committed(HISTORICAL_FILE) });
  refuses("PROOF_UNRESOLVED", () => resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, disguised));
  // And the historical contents still answer for the historical run under that
  // misleading name, because only the contents were ever consulted.
  assert.equal(resolveCaseAdapterDeploymentProofFile(HISTORICAL_ADAPTER, HISTORICAL_RUN, disguised), HARDENED_FILE);
  // The same indifference in the other direction: the real hardened proof is
  // found under a name that says nothing about it.
  const renamed = evidenceRoot({ "unrelated-evidence.json": committed(HARDENED_FILE) });
  assert.equal(resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, renamed), "unrelated-evidence.json");
  assert.equal(loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN, renamed).runId, HARDENED_RUN);
});

test("F-04 resolution: unrelated and unreadable evidence neither matches nor blocks", () => {
  const root = evidenceRoot({
    ...bothProofs(),
    "other-schema.json": { schemaVersion: "mordant.something-else/1", address: HARDENED_ADAPTER, runId: HARDENED_RUN },
    "array-evidence.json": [] as unknown as Record<string, unknown>,
  });
  writeFileSync(join(root, "docs", "evidence", "not-json.json"), "{ this is not json");
  makeNewest(root, "not-json.json");
  assert.equal(resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, root), HARDENED_FILE);
  // A directory that happens to end in .json is not a candidate either.
  mkdirSync(join(root, "docs", "evidence", "directory.json"));
  assert.equal(resolveCaseAdapterDeploymentProofFile(HARDENED_ADAPTER, HARDENED_RUN, root), HARDENED_FILE);
  rmSync(join(root, "docs", "evidence", "directory.json"), { recursive: true });
});

test("F-04 resolution: the historical fixed-name loader is unchanged and still authoritative", () => {
  const root = evidenceRoot(bothProofs());
  // Untouched: it still reads its one historical name, which is exactly why it
  // could not answer for the hardened run and why resolution had to be added
  // beside it rather than folded into it.
  const historical = loadCaseAdapterDeploymentProof(HISTORICAL_ADAPTER, HISTORICAL_RUN, root);
  assert.equal(historical.runId, HISTORICAL_RUN);
  refuses("PROOF_ADDRESS", () => loadCaseAdapterDeploymentProof(HARDENED_ADAPTER, HARDENED_RUN, root));
  // Pointed at the hardened file explicitly it still enforces every F-04 check.
  const hardened = loadCaseAdapterDeploymentProof(HARDENED_ADAPTER, HARDENED_RUN, root, HARDENED_FILE);
  assert.equal(hardened.runId, HARDENED_RUN);
  refuses("PROOF_RUN", () => loadCaseAdapterDeploymentProof(HARDENED_ADAPTER, HISTORICAL_RUN, root, HARDENED_FILE));
  // Resolution returns the same object the authoritative loader returns.
  assert.deepEqual(loadCaseAdapterDeploymentProofForRun(HARDENED_ADAPTER, HARDENED_RUN, root), hardened);
});
