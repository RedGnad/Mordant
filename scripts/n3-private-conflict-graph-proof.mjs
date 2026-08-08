#!/usr/bin/env node
/**
 * Bounded N=3 private-conflict graph proof.
 *
 * This harness invokes the existing two-party governed BGV path three times,
 * strictly sequentially, and stops each pair at RELEASED. It does not call the
 * live worker, recourse, evidence export, adapters, cure or settlement.
 */

import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SOURCE_ROOT = process.cwd();
const REPOSITORY = "RedGnad/Mordant";
const REQUIRED_BRANCH = "experiment/n3-private-conflict-graph";
const SCHEMA_VERSION = "mordant.n3-private-conflict-graph-evidence/1";
const EVIDENCE_DIGEST_DOMAIN = "MordantN3PrivateConflictGraphProofEvidence/v1";
const EXACT_VERDICT = "PASS — N=3 PRIVATE CONFLICT GRAPH PROOF READY FOR REVIEW";
const EVIDENCE_PATH = resolve(
  SOURCE_ROOT,
  "docs",
  "evidence",
  "n3-private-conflict-graph",
  "n3-private-conflict-graph-proof-2026-08-09.json",
);
const GO_ROOT = resolve(SOURCE_ROOT, "fhe-lab", "lattigo");
const TEST_STUB_ROOT = resolve(SOURCE_ROOT, "test", "stubs");
const COMPILED_ROOT = resolve(SOURCE_ROOT, ".product-test-dist", "src", "lib", "protection");

const MODULE_DEFINITIONS = Object.freeze([
  {
    id: "proofHarness",
    source: "scripts/n3-private-conflict-graph-proof.mjs",
    compiled: null,
  },
  {
    id: "graphCore",
    source: "src/lib/protection/receivable-conflict-session.ts",
    compiled: ".product-test-dist/src/lib/protection/receivable-conflict-session.js",
  },
  {
    id: "graphRunner",
    source: "src/lib/protection/receivable-conflict-session-runner.ts",
    compiled: ".product-test-dist/src/lib/protection/receivable-conflict-session-runner.js",
  },
  {
    id: "graphStore",
    source: "src/lib/protection/receivable-conflict-session-store.ts",
    compiled: ".product-test-dist/src/lib/protection/receivable-conflict-session-store.js",
  },
  {
    id: "pairOrchestrator",
    source: "src/lib/protection/governed-fhe-product-server.ts",
    compiled: ".product-test-dist/src/lib/protection/governed-fhe-product-server.js",
  },
]);

const BINARY_DEFINITIONS = Object.freeze([
  { id: "keygen", name: "mordant-fhe-keygen", package: "./cmd/mordant-fhe-keygen" },
  { id: "client", name: "mordant-fhe-client", package: "./cmd/mordant-fhe-client" },
  { id: "evaluator", name: "mordant-fhe-evaluator", package: "./cmd/mordant-fhe-evaluator" },
  { id: "decryptor", name: "mordant-fhe-decryptor", package: "./cmd/mordant-fhe-decryptor" },
  { id: "inspect", name: "mordant-fhe-inspect", package: "./cmd/mordant-fhe-inspect" },
]);

const NATIVE_BUILD_FLAGS = Object.freeze(["-mod=readonly", "-trimpath", "-buildvcs=false"]);
const ADMISSION_ORDER = Object.freeze(["A", "B", "C"]);
const PAIR_EXECUTION_ORDER = Object.freeze(["A/B", "A/C", "B/C"]);
const EXPECTED_STATES = Object.freeze([
  Object.freeze({ label: "A/B", state: "CONFLICT" }),
  Object.freeze({ label: "A/C", state: "NO_CONFLICT_UNDER_POLICY" }),
  Object.freeze({ label: "B/C", state: "CONFLICT" }),
]);
const FORBIDDEN_ARTIFACT_CLASSES = Object.freeze([
  "RECOURSE",
  "EVIDENCE_EXPORT",
  "ADAPTER",
  "CURE",
  "SETTLEMENT",
]);
const TEMPORARY_ROOT_CLASSES = Object.freeze([
  "PAIR_RUN_ROOT",
  "OPERATOR_AUDIT_EVIDENCE_ROOT",
  "PRIVATE_CLAIM_ROOT",
  "NATIVE_BINARY_ROOT",
  "GO_BUILD_CACHE",
]);

const SUPPORTED_CLAIMS = Object.freeze([
  "Three separately authorized opaque graph claims over one synthetic receivable were admitted in order A, B, C.",
  "The existing reviewed two-party BGV primitive produced three independent signed governed Booleans sequentially.",
  "A/B is CONFLICT, A/C is NO_CONFLICT_UNDER_POLICY, and B/C is CONFLICT.",
  "Every expected canonical pair has a retained intent, binding, independently verified signed result, and evidence leaf.",
  "The aggregate is COMPLETE and REVIEW_READY, with scoped operator, claimant, and public projections.",
  "Execution stopped at RELEASED and created no recourse, evidence-export, adapter, cure, or settlement artifacts.",
  "Exact claim openings were persisted only in temporary operator-private filesystem roots, which were removed by explicit ordinary cleanup after evidence capture; caller-managed process-memory references and secure erasure are not claimed.",
]);

const UNSUPPORTED_CLAIMS = Object.freeze([
  "This is an N-party FHE circuit or an N-party ciphertext-reuse design.",
  "The existing production worker supports concurrent pair execution or increased throughput.",
  "The experiment proves production deployment, horizontal scaling, or high availability.",
  "Conflict edges automatically determine one incident, multiple incidents, recourse, cure, or settlement.",
  "The proof moves tokens, deploys adapters, or exercises settlement.",
  "Ordinary unlink is secure erasure or proves forensic deletion of private material.",
  "Native binary bytes remain available for independent post-cleanup re-hashing.",
  "The experiment supports arbitrary N or any receivable beyond the bounded synthetic N=3 case.",
]);

const temporaryRoots = [];

function iso(now = Date.now()) {
  return new Date(now).toISOString();
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

function readJson(path) {
  const entry = lstatSync(path);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`Refused non-regular JSON artifact ${basename(path)}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function hasPathPrefix(parent, child) {
  const relation = relative(parent, child);
  return relation === "" || (
    relation !== ".."
    && !relation.startsWith(`..${sep}`)
    && !isAbsolute(relation)
  );
}

function assertOutsideRepository(path, label) {
  const repository = realpathSync(SOURCE_ROOT);
  const physical = realpathSync(path);
  if (hasPathPrefix(repository, physical) || hasPathPrefix(physical, repository)) {
    throw new Error(`${label} must be outside the repository`);
  }
  return physical;
}

function createTemporaryRoot(rootClass, prefix) {
  const created = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const physicalTmp = realpathSync(tmpdir());
  if (dirname(created) !== physicalTmp || !basename(created).startsWith(prefix)) {
    throw new Error(`Unexpected mkdtemp result for ${rootClass}`);
  }
  assertOutsideRepository(created, rootClass);
  temporaryRoots.push(Object.freeze({ rootClass, path: created, prefix }));
  return created;
}

function validateRegisteredTemporaryRoot(record) {
  if (!temporaryRoots.includes(record)) throw new Error("Unregistered temporary root refused");
  const physicalTmp = realpathSync(tmpdir());
  const resolved = resolve(record.path);
  if (
    dirname(resolved) !== physicalTmp
    || !basename(resolved).startsWith(record.prefix)
    || hasPathPrefix(realpathSync(SOURCE_ROOT), resolved)
    || resolved === physicalTmp
  ) {
    throw new Error(`Unsafe temporary cleanup target for ${record.rootClass}`);
  }
}

function cleanupAllTemporaryRoots() {
  for (const record of [...temporaryRoots].reverse()) {
    validateRegisteredTemporaryRoot(record);
    if (existsSync(record.path)) rmSync(record.path, { recursive: true, force: false });
    if (existsSync(record.path)) throw new Error(`Temporary cleanup failed for ${record.rootClass}`);
  }
  return temporaryRoots.every((record) => !existsSync(record.path));
}

function cleanupPairCaseRoot(runRoot, pairRunId) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(pairRunId)) {
    throw new Error("Pair cleanup requires a canonical UUIDv4 run ID");
  }
  const runRecord = temporaryRoots.find((record) => record.rootClass === "PAIR_RUN_ROOT");
  if (runRecord === undefined || runRecord.path !== runRoot) throw new Error("Pair run root is not a validated mkdtemp root");
  validateRegisteredTemporaryRoot(runRecord);
  const target = resolve(runRoot, pairRunId);
  if (dirname(target) !== runRoot || !existsSync(target)) throw new Error("Unsafe or missing pair cleanup target");
  const entry = lstatSync(target);
  if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error("Pair cleanup target is not a regular directory");
  const physicalTarget = realpathSync(target);
  if (dirname(physicalTarget) !== realpathSync(runRoot)) throw new Error("Pair cleanup escaped its mkdtemp root");
  rmSync(target, { recursive: true, force: false });
  if (existsSync(target)) throw new Error("Pair case cleanup failed");
}

function walkRelativeArtifacts(root) {
  const files = [];
  const entries = [];
  const visit = (path) => {
    const entry = lstatSync(path);
    if (entry.isSymbolicLink()) throw new Error("Pair artifact scan refused a symbolic link");
    if (entry.isDirectory()) {
      if (path !== root) entries.push(relative(root, path).split(sep).join("/"));
      for (const name of readdirSync(path).sort()) visit(join(path, name));
      return;
    }
    if (!entry.isFile()) throw new Error("Pair artifact scan refused a non-regular file");
    const relativePath = relative(root, path).split(sep).join("/");
    entries.push(relativePath);
    files.push(relativePath);
  };
  visit(root);
  return { entries, files };
}

function forbiddenArtifactMatches(files) {
  const patterns = [
    /(?:^|[-_.])recourse(?:[-_.]|$)/iu,
    /(?:^|[-_.])evidence(?:[-_.]|$)/iu,
    /(?:^|[-_.])adapter(?:[-_.]|$)/iu,
    /(?:^|[-_.])cure(?:[-_.]|$)/iu,
    /(?:^|[-_.])settlement(?:[-_.]|$)/iu,
  ];
  return files.filter((path) => patterns.some((pattern) => pattern.test(basename(path))));
}

function pairSideEffectScan(runRoot, pairRunId, label, requiredOperations) {
  const pairRoot = resolve(runRoot, pairRunId);
  if (dirname(pairRoot) !== runRoot) throw new Error("Pair scan escaped its run root");
  const journal = readJson(join(pairRoot, "operation-journal.json"));
  const execution = readJson(join(pairRoot, "execution.json"));
  if (!Array.isArray(journal.records)) throw new Error("Pair operation journal is malformed");
  const operations = journal.records.map((record) => record.operation);
  const operationOutcomes = journal.records.map((record) => ({
    operation: record.operation,
    outcome: record.outcome,
  }));
  const forbiddenOperationMatches = operations.filter((operation) => (
    /recourse|evidence|adapter|cure|settlement/iu.test(operation)
  ));
  const { entries, files } = walkRelativeArtifacts(pairRoot);
  const artifacts = forbiddenArtifactMatches(entries);
  const exactOperations = JSON.stringify(operations) === JSON.stringify(requiredOperations);
  const allCompleted = operationOutcomes.every((record) => record.outcome === "COMPLETED");
  const recourseState = execution.protectionCase?.recourseState ?? null;
  const cureDeadline = execution.protectionCase?.cureDeadline ?? null;
  const recourseRecordPresent = files.includes("public/recourse-record.json");
  const publicEvidencePresent = files.includes("public/evidence.json");
  const terminalStage = execution.stage ?? null;
  const scan = {
    label,
    terminalStage,
    operations,
    operationOutcomes,
    scannedFileCount: files.length,
    forbiddenOperationMatches,
    forbiddenArtifactMatches: artifacts,
    recourseState,
    cureDeadline,
    recourseRecordPresent,
    publicEvidencePresent,
    pairCaseRootCleanupPerformed: false,
    cleanupMethod: "ORDINARY_RECURSIVE_UNLINK_AFTER_LEAF_CAPTURE",
  };
  const passed = terminalStage === "RELEASED"
    && exactOperations
    && allCompleted
    && forbiddenOperationMatches.length === 0
    && artifacts.length === 0
    && recourseState === "NOT_OPEN"
    && cureDeadline === null
    && !recourseRecordPresent
    && !publicEvidencePresent;
  return { scan, passed };
}

function containsAbsoluteFilesystemPath(value) {
  if (typeof value !== "string") return false;
  return /(?:^|[\s"'(])\/(?:Users|home|tmp|private|var|opt|Volumes|workspace|root)(?:\/|$)/u.test(value)
    || /(?:^|[\s"'(])[A-Za-z]:[\\/]/u.test(value)
    || /(?:^|[\s"'(])\\\\[^\\]/u.test(value)
    || /file:\/\//iu.test(value);
}

function sanitationViolations(value, path = "$") {
  const violations = [];
  const forbiddenKeys = new Set([
    "activeFrom",
    "activeUntil",
    "salt",
    "authorizationPrivateKey",
    "privateKey",
    "runRoot",
    "publicRoot",
    "privateRoot",
    "binRoot",
    "goCache",
    "ciphertext",
    "ciphertextObject",
    "resultCiphertext",
  ]);
  const visit = (current, currentPath) => {
    if (containsAbsoluteFilesystemPath(current)) {
      violations.push(`${currentPath}: absolute path`);
    }
    if (Array.isArray(current)) {
      current.forEach((entry, index) => visit(entry, `${currentPath}[${index}]`));
      return;
    }
    if (current !== null && typeof current === "object") {
      for (const [key, entry] of Object.entries(current)) {
        const retentionMetadata = currentPath === "$.retention.declaration.privateExactClaimOpenings"
          && key === "authorizationPrivateKey"
          && entry === "NOT_PERSISTED";
        if (forbiddenKeys.has(key) && !retentionMetadata) {
          violations.push(`${currentPath}.${key}: forbidden key`);
        }
        visit(entry, `${currentPath}.${key}`);
      }
    }
  };
  visit(value, path);
  return violations;
}

async function git(...args) {
  const { stdout } = await execFileAsync("git", args, { cwd: SOURCE_ROOT, maxBuffer: 8 << 20 });
  return stdout.trim();
}

async function assertStartingCommitIsAncestor(startingCommit) {
  try {
    await execFileAsync("git", ["merge-base", "--is-ancestor", startingCommit, "HEAD"], { cwd: SOURCE_ROOT });
  } catch {
    throw new Error("The graph experiment starting commit is not an ancestor of HEAD");
  }
}

function compiledPath(name) {
  return resolve(COMPILED_ROOT, name);
}

async function importCompiled(path) {
  if (!existsSync(path)) throw new Error(`Missing compiled module ${relative(SOURCE_ROOT, path)}`);
  return import(pathToFileURL(path).href);
}

async function loadCompiledModules() {
  const configuredNodePaths = (process.env.NODE_PATH ?? "")
    .split(delimiter)
    .filter(Boolean)
    .map((entry) => resolve(SOURCE_ROOT, entry));
  if (!configuredNodePaths.includes(TEST_STUB_ROOT)) {
    throw new Error("NODE_PATH must include ./test/stubs before loading the compiled server-only orchestrator");
  }
  const [core, runner, store, engine, asset, protectionCase, protectionEvidence] = await Promise.all([
    importCompiled(compiledPath("receivable-conflict-session.js")),
    importCompiled(compiledPath("receivable-conflict-session-runner.js")),
    importCompiled(compiledPath("receivable-conflict-session-store.js")),
    importCompiled(compiledPath("governed-fhe-product-server.js")),
    importCompiled(compiledPath("cleanverse-asset.js")),
    importCompiled(compiledPath("protection-case.js")),
    importCompiled(compiledPath("protection-evidence.js")),
  ]);
  return { core, runner, store, engine, asset, protectionCase, protectionEvidence };
}

async function buildFreshNativeBinaries(sourceCommit, sourceTree) {
  if (process.env.MORDANT_N3_BIN_ROOT !== undefined || process.env.MORDANT_GOVERNED_FHE_BIN_DIR !== undefined) {
    throw new Error("Prepopulated native binary roots are refused for proof-grade execution");
  }
  const binRoot = createTemporaryRoot("NATIVE_BINARY_ROOT", "mordant-n3-proof-binaries-");
  const goCache = createTemporaryRoot("GO_BUILD_CACHE", "mordant-n3-proof-go-cache-");
  const startedAt = iso();
  const [{ stdout: goVersion }, { stdout: goToolchain }, { stdout: goos }, { stdout: goarch }] = await Promise.all([
    execFileAsync("go", ["env", "GOVERSION"], { cwd: GO_ROOT }),
    execFileAsync("go", ["env", "GOTOOLCHAIN"], { cwd: GO_ROOT }),
    execFileAsync("go", ["env", "GOOS"], { cwd: GO_ROOT }),
    execFileAsync("go", ["env", "GOARCH"], { cwd: GO_ROOT }),
  ]);
  const binaries = [];
  process.stdout.write("Building five governed-FHE executables from the committed experiment checkout.\n");
  for (const definition of BINARY_DEFINITIONS) {
    const output = join(binRoot, definition.name);
    await execFileAsync("go", [
      "build",
      ...NATIVE_BUILD_FLAGS,
      "-o",
      output,
      definition.package,
    ], {
      cwd: GO_ROOT,
      env: { ...process.env, CGO_ENABLED: "0", GOCACHE: goCache },
      maxBuffer: 8 << 20,
    });
    if (!existsSync(output) || !statSync(output).isFile()) {
      throw new Error(`Fresh native build did not produce ${definition.name}`);
    }
    binaries.push(Object.freeze({
      id: definition.id,
      name: definition.name,
      package: definition.package,
      bytes: statSync(output).size,
      sha256: sha256File(output),
    }));
  }
  return {
    binRoot,
    hashes: Object.freeze(Object.fromEntries(binaries.map((binary) => [binary.id, binary.sha256]))),
    evidence: Object.freeze({
      proofGrade: true,
      builtDuringProof: true,
      prepopulatedBinaryRootAccepted: false,
      sourceCommit,
      sourceTree,
      startedAt,
      completedAt: iso(),
      toolchain: Object.freeze({
        goVersion: goVersion.trim(),
        goToolchain: goToolchain.trim(),
        goos: goos.trim(),
        goarch: goarch.trim(),
        cgoEnabled: false,
      }),
      flags: NATIVE_BUILD_FLAGS,
      binaries: Object.freeze(binaries),
    }),
  };
}

function sourceModuleEvidence() {
  return MODULE_DEFINITIONS.map((definition) => {
    const sourcePath = resolve(SOURCE_ROOT, definition.source);
    if (!existsSync(sourcePath)) throw new Error(`Missing source module ${definition.source}`);
    if (definition.compiled === null) {
      return Object.freeze({
        id: definition.id,
        source: definition.source,
        compiled: null,
        sourceSha256: sha256File(sourcePath),
        compiledSha256: null,
      });
    }
    const outputPath = resolve(SOURCE_ROOT, definition.compiled);
    if (!existsSync(outputPath)) throw new Error(`Missing compiled module ${definition.compiled}`);
    return Object.freeze({
      id: definition.id,
      source: definition.source,
      compiled: definition.compiled,
      sourceSha256: sha256File(sourcePath),
      compiledSha256: sha256File(outputPath),
    });
  });
}

function pairLabelFor(claimPair, claimLabels) {
  const labels = [
    claimLabels.get(claimPair.leftClaimId),
    claimLabels.get(claimPair.rightClaimId),
  ];
  if (labels.some((label) => label === undefined)) throw new Error("Pair references an unknown graph claim");
  return labels.sort((left, right) => ADMISSION_ORDER.indexOf(left) - ADMISSION_ORDER.indexOf(right)).join("/");
}

function createPairReader(runRoot) {
  return async (pairRunId, fileName) => {
    if (!Object.values({
      caseBinding: "case-binding.json",
      evaluatedConflict: "evaluated-conflict.json",
      governedResult: "governed-conflict-result.json",
    }).includes(fileName)) {
      throw new Error("Pair reader refused an unsupported public artifact");
    }
    return readJson(join(runRoot, pairRunId, "public", fileName));
  };
}

function createPairInspector(
  runRoot,
  inspectBinary,
  inspectBinaryDigest,
  publicInspectionReportDigest,
  createPairPublicInspection,
  inspectReports,
) {
  return async (pairRunId) => {
    const publicRoot = join(runRoot, pairRunId, "public");
    const { stdout } = await execFileAsync(inspectBinary, [
      "-mode",
      "public",
      "-public-root",
      publicRoot,
    ], { maxBuffer: 8 << 20 });
    const report = JSON.parse(stdout);
    if (
      report?.finalized !== true
      || report?.evaluationAdmission !== true
      || report?.releaseAdmission !== false
      || report?.foundationPrivateComplete !== false
      || report?.releasePrivateComplete !== false
      || report?.ambiguous !== false
      || report?.recourse !== undefined
      || report?.evidence !== undefined
      || report?.submissionA === undefined
      || report?.submissionB === undefined
      || report?.evaluation === undefined
      || report?.release === undefined
    ) {
      throw new Error("Independent public inspection did not verify a complete RELEASED pair");
    }
    const inspectionReportDigest = publicInspectionReportDigest(report);
    const inspection = createPairPublicInspection({
      finalized: report.finalized,
      evaluationAdmission: report.evaluationAdmission,
      releaseVerified: report.release !== undefined,
      ambiguous: report.ambiguous,
      recoursePresent: report.recourse !== undefined && report.recourse !== null,
      publicEvidencePresent: report.evidence !== undefined && report.evidence !== null,
      resultDigest: report.release.resultDigest,
      conflict: report.release.conflict,
      releaseMode: report.release.releaseMode,
      participantArtifactDigests: Object.freeze([
        report.submissionA.artifactDigest,
        report.submissionB.artifactDigest,
      ]),
      evaluatedArtifactDigest: report.evaluation.artifactDigest,
      inspectBinaryDigest,
      inspectionReportDigest,
    });
    if (inspectReports.has(pairRunId)) throw new Error("Pair public inspection report was recorded twice");
    inspectReports.set(pairRunId, Object.freeze(report));
    return inspection;
  };
}

function check(assertions, id, description, pass, evidence) {
  const assertion = Object.freeze({ id, description, pass: Boolean(pass), evidence: Object.freeze(evidence) });
  assertions.push(assertion);
  return assertion.pass;
}

function stableClaimBinding(graphPairs, claimId) {
  const relevant = graphPairs.filter((pair) => (
    pair.leaf.claimPair.leftClaimId === claimId || pair.leaf.claimPair.rightClaimId === claimId
  ));
  if (relevant.length !== 2) return false;
  const intentBindings = relevant.map((pair) => pair.intent.claimBindings.find((binding) => binding.claimId === claimId));
  const roleBindings = relevant.map((pair) => pair.binding.roleBindings.find((binding) => binding.claimId === claimId));
  return intentBindings.every((binding) => binding !== undefined)
    && roleBindings.every((binding) => binding !== undefined)
    && new Set(intentBindings.map((binding) => binding.claimNodeDigest)).size === 1
    && new Set(intentBindings.map((binding) => binding.claimCommitment)).size === 1
    && new Set(intentBindings.map((binding) => binding.claimAuthorizationDigest)).size === 1
    && new Set(roleBindings.map((binding) => binding.claimNodeDigest)).size === 1
    && new Set(roleBindings.map((binding) => binding.pairParticipantId)).size === 2;
}

async function main() {
  const branch = await git("branch", "--show-current");
  const sourceCommit = await git("rev-parse", "HEAD");
  const sourceTree = await git("rev-parse", "HEAD^{tree}");
  const checkoutStatus = await git("status", "--porcelain=v1", "--untracked-files=all");
  if (branch !== REQUIRED_BRANCH) throw new Error(`Proof requires branch ${REQUIRED_BRANCH}`);
  if (checkoutStatus !== "") throw new Error("Commit every experiment/proof change before proof execution");
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit) || !/^[0-9a-f]{40}$/u.test(sourceTree)) {
    throw new Error("Full committed source and tree pins are required");
  }
  if (process.env.MORDANT_PROTECTION_SOURCE_COMMIT !== sourceCommit) {
    throw new Error("MORDANT_PROTECTION_SOURCE_COMMIT must exactly match HEAD");
  }

  const modules = await loadCompiledModules();
  const {
    core,
    runner,
    store: storeModule,
    engine,
    asset,
    protectionCase,
    protectionEvidence,
  } = modules;
  if (core.N3_STARTING_COMMIT !== "9ea6652dbf61c6227e3a21183e628a7356b6df18") {
    throw new Error("Unexpected graph experiment starting commit");
  }
  await assertStartingCommitIsAncestor(core.N3_STARTING_COMMIT);
  const baseCommit = await git("merge-base", "HEAD", "origin/main");
  if (baseCommit !== core.N3_STARTING_COMMIT) {
    throw new Error("Experiment branch no longer has the required origin/main base");
  }

  const sourceModules = sourceModuleEvidence();
  const runRoot = createTemporaryRoot("PAIR_RUN_ROOT", "mordant-n3-proof-pair-runs-");
  const operatorRoot = createTemporaryRoot(
    "OPERATOR_AUDIT_EVIDENCE_ROOT",
    "mordant-n3-proof-operator-evidence-",
  );
  const privateRoot = createTemporaryRoot("PRIVATE_CLAIM_ROOT", "mordant-n3-proof-private-claims-");
  const nativeBuild = await buildFreshNativeBinaries(sourceCommit, sourceTree);

  const pins = Object.freeze({
    startingCommit: core.N3_STARTING_COMMIT,
    executionSourceCommit: sourceCommit,
    executionSourceTree: sourceTree,
    governedFheSourceCommit: protectionEvidence.EXPECTED_GOVERNED_FHE_COMMIT,
    assetIdentity: asset.CANONICAL_CLEANVERSE_ASSET_DIGEST,
    policyId: protectionCase.protectionPolicyId(),
    policyVersion: 1,
    serviceId: "mordant.private-pledge-matching",
    serviceVersion: 1,
    circuitId: protectionCase.FHE_CIRCUIT,
    circuitVersion: 5,
    circuitDigest: core.EXPECTED_CIRCUIT_DIGEST,
    parameterProfile: protectionCase.FHE_PARAMETER_PROFILE,
    parameterFingerprint: core.EXPECTED_PARAMETER_FINGERPRINT,
    releaseMode: protectionCase.GOVERNED_RELEASE_MODE,
    nativeBinaries: nativeBuild.hashes,
  });
  core.assertGraphPins(pins);

  const graphSessionId = core.newGraphSessionId();
  const issuedAtUnix = Math.floor(Date.now() / 1_000) - 1;
  const expiresAtUnix = issuedAtUnix + 4 * 60 * 60;
  const claimInputs = [
    { label: "A", activeFrom: 100, activeUntil: 400 },
    { label: "B", activeFrom: 200, activeUntil: 600 },
    { label: "C", activeFrom: 500, activeUntil: 800 },
  ];
  const privateClaims = claimInputs.map((input) => core.createGraphClaimAuthorization({
    graphSessionId,
    receivableIdentity: asset.CANONICAL_CLEANVERSE_ASSET_DIGEST,
    participantRef: core.participantReference(),
    activeFrom: input.activeFrom,
    activeUntil: input.activeUntil,
    issuedAtUnix,
    expiresAtUnix,
  }));
  const claimLabels = new Map(privateClaims.map((claim, index) => [
    claim.authorization.claimId,
    ADMISSION_ORDER[index],
  ]));

  const sessionStore = storeModule.createReceivableConflictSessionStore({
    publicRoot: operatorRoot,
    privateRoot,
  });
  const pairScans = [];
  const persistence = Object.freeze({
    writePublicClaimAuthorization: sessionStore.writePublicClaimAuthorization,
    writePrivateClaimRecord: sessionStore.writePrivateClaimRecord,
    writePairIntent: sessionStore.writePairIntent,
    writePairBinding: sessionStore.writePairBinding,
    writeEvidenceLeaf: (sessionId, pairId, leaf) => {
      const result = sessionStore.writeEvidenceLeaf(sessionId, pairId, leaf);
      const label = pairLabelFor(leaf.claimPair, claimLabels);
      const { scan, passed } = pairSideEffectScan(
        runRoot,
        leaf.pairRunId,
        label,
        core.REQUIRED_PAIR_OPERATIONS,
      );
      cleanupPairCaseRoot(runRoot, leaf.pairRunId);
      const retainedScan = Object.freeze({ ...scan, pairCaseRootCleanupPerformed: true });
      pairScans.push(retainedScan);
      if (!passed) throw new Error(`Pair ${label} crossed the RELEASED-only proof boundary`);
      return result;
    },
    writeAggregate: sessionStore.writeAggregate,
    writeProjection: sessionStore.writeProjection,
    writeChronology: sessionStore.writeChronology,
    writeRetentionDeclaration: sessionStore.writeRetentionDeclaration,
  });

  const orchestrator = engine.createProtectionOrchestrator({
    runRoot,
    binRoot: nativeBuild.binRoot,
    goRoot: GO_ROOT,
    importedEvidenceRoot: join(runRoot, "unused-imported-evidence"),
    retentionRoot: join(runRoot, "unused-retained-evidence"),
    skipBinaryBuild: true,
    expectedSourceCommit: sourceCommit,
    directParticipantAdmissionEnabled: false,
  });
  const readPairJson = createPairReader(runRoot);
  const inspectReports = new Map();
  const inspectPair = createPairInspector(
    runRoot,
    join(nativeBuild.binRoot, "mordant-fhe-inspect"),
    nativeBuild.hashes.inspect,
    core.publicInspectionReportDigest,
    core.createPairPublicInspection,
    inspectReports,
  );

  process.stdout.write("Executing A/B, A/C and B/C through the reviewed pair engine, sequentially.\n");
  const result = await runner.runReceivableConflictSession({
    graphSessionId,
    receivableIdentity: asset.CANONICAL_CLEANVERSE_ASSET_DIGEST,
    issuedAtUnix,
    expiresAtUnix,
    pins,
    claims: privateClaims,
    orchestrator,
    readJson: readPairJson,
    inspect: inspectPair,
    persist: persistence,
    now: () => new Date(),
    newPairRunId: () => randomUUID(),
  });

  if (result.leaves.length !== 3 || result.intents.length !== 3 || result.bindings.length !== 3) {
    const failures = result.failures.map((failure) => `${failure.phase}:${failure.code}`).join(",");
    throw new Error(`The real pair runner did not produce all three complete leaves (${failures || "no failure detail"})`);
  }
  const intentByPair = new Map(result.intents.map((intent) => [intent.claimPair.pairId, intent]));
  const bindingByPair = new Map(result.bindings.map((binding) => [binding.claimPair.pairId, binding]));
  const graphPairs = result.leaves
    .slice()
    .sort((left, right) => left.execution.executionOrdinal - right.execution.executionOrdinal)
    .map((leaf) => {
      const intent = intentByPair.get(leaf.claimPair.pairId);
      const binding = bindingByPair.get(leaf.claimPair.pairId);
      const inspectReport = inspectReports.get(leaf.pairRunId);
      if (intent === undefined || binding === undefined || inspectReport === undefined) {
        throw new Error("Pair leaf lost its intent, binding or public inspection report");
      }
      if (leaf.inspection.inspectionReportDigest !== core.publicInspectionReportDigest(inspectReport)) {
        throw new Error("Pair leaf public inspection report digest mismatch");
      }
      return Object.freeze({
        label: pairLabelFor(leaf.claimPair, claimLabels),
        intent,
        binding,
        leaf,
        inspectReport,
      });
    });
  const actualStates = graphPairs.map((pair) => Object.freeze({ label: pair.label, state: pair.leaf.state }));
  if (JSON.stringify(graphPairs.map((pair) => pair.label)) !== JSON.stringify(PAIR_EXECUTION_ORDER)) {
    throw new Error("Pair execution order was not A/B then A/C then B/C");
  }

  for (const pair of graphPairs) {
    core.verifyGraphPairEvidenceLeaf(
      pair.leaf,
      pair.binding,
      pair.intent,
      result.aggregate.nodes,
      pins,
    );
  }
  core.verifyAggregateManifest(result.aggregate, result.chronology, result.leaves);
  core.verifyConflictGraphProjections(result.aggregate, result.projections);

  const retentionDeclaration = sessionStore.readRetentionDeclaration(graphSessionId);
  if (retentionDeclaration === null) throw new Error("Retention declaration was not durably recorded");
  const graph = Object.freeze({
    session: Object.freeze({
      graphSessionId,
      receivableIdentity: asset.CANONICAL_CLEANVERSE_ASSET_DIGEST,
      issuedAtUnix,
      expiresAtUnix,
      admissionOrder: ADMISSION_ORDER,
      expectedClaimCount: 3,
      expectedPairExecutionOrder: PAIR_EXECUTION_ORDER,
    }),
    claims: Object.freeze(privateClaims.map((claim, index) => Object.freeze({
      label: ADMISSION_ORDER[index],
      authorization: claim.authorization,
    }))),
    pairs: Object.freeze(graphPairs),
    aggregate: result.aggregate,
    chronology: result.chronology,
    projections: result.projections,
  });

  const assertions = [];
  check(assertions, "source-pin", "clean committed experiment source and environment pins match",
    branch === REQUIRED_BRANCH && baseCommit === core.N3_STARTING_COMMIT
      && process.env.MORDANT_PROTECTION_SOURCE_COMMIT === sourceCommit,
    { branch, startingCommit: core.N3_STARTING_COMMIT, executionCommit: sourceCommit, executionTree: sourceTree });
  check(assertions, "native-build", "exactly five required native binaries were freshly built with fixed flags",
    nativeBuild.evidence.binaries.length === 5
      && JSON.stringify(nativeBuild.evidence.flags) === JSON.stringify(NATIVE_BUILD_FLAGS)
      && nativeBuild.evidence.binaries.every((binary) => /^sha256:[0-9a-f]{64}$/u.test(binary.sha256)),
    { binaryIds: nativeBuild.evidence.binaries.map((binary) => binary.id), flags: nativeBuild.evidence.flags });
  check(assertions, "claim-set", "three opaque authorized claims are admitted in A/B/C order",
    graph.claims.length === 3 && new Set(graph.claims.map((claim) => claim.authorization.claimId)).size === 3,
    { labels: graph.claims.map((claim) => claim.label), claimIds: graph.claims.map((claim) => claim.authorization.claimId) });
  check(assertions, "pair-set", "all three canonical pairs have complete intent, binding and leaf records",
    graph.pairs.length === 3 && JSON.stringify(graph.pairs.map((pair) => pair.label)) === JSON.stringify(PAIR_EXECUTION_ORDER),
    { labels: graph.pairs.map((pair) => pair.label), pairIds: graph.pairs.map((pair) => pair.leaf.claimPair.pairId) });
  check(assertions, "governed-results", "real signed pair results match the required N=3 relation set",
    JSON.stringify(actualStates) === JSON.stringify(EXPECTED_STATES),
    { expectedStates: EXPECTED_STATES, actualStates });
  check(assertions, "governed-signatures", "every complete governed result passed core signature and binding verification",
    graph.pairs.every((pair) => /^sha256:[0-9a-f]{64}$/u.test(pair.leaf.governedResultDigest)),
    { resultDigests: graph.pairs.map((pair) => ({ label: pair.label, digest: pair.leaf.governedResultDigest })) });
  check(assertions, "public-inspection", "the fresh inspect binary independently verified every public pair release",
    graph.pairs.every((pair) => pair.leaf.inspection.releaseVerified
      && !pair.leaf.inspection.ambiguous
      && !pair.leaf.inspection.recoursePresent
      && !pair.leaf.inspection.publicEvidencePresent
      && pair.leaf.inspection.inspectBinaryDigest === nativeBuild.hashes.inspect),
    { inspections: graph.pairs.map((pair) => ({ label: pair.label, digest: pair.leaf.inspection.inspectionDigest })) });
  check(assertions, "stable-claim-binding", "claim A remains stably bound across A/B and A/C with fresh pair-local identities",
    stableClaimBinding(graph.pairs, graph.claims[0].authorization.claimId),
    { claimId: graph.claims[0].authorization.claimId, pairs: ["A/B", "A/C"] });
  const freshnessFields = [
    graph.pairs.map((pair) => pair.intent.pairRunId),
    graph.pairs.map((pair) => pair.binding.caseId),
    graph.pairs.map((pair) => pair.binding.caseBinding.publicKeyDigest),
    graph.pairs.map((pair) => pair.binding.caseBinding.releaseAuthorityId),
  ];
  check(assertions, "fresh-pair-keys", "all pair runs, cases, BGV public keys and release authorities are distinct",
    freshnessFields.every((values) => new Set(values).size === 3),
    { distinctCounts: freshnessFields.map((values) => new Set(values).size) });
  check(assertions, "aggregate-complete", "aggregate is complete and review-ready without a global all-clear",
    result.aggregate.completeness === "COMPLETE"
      && result.aggregate.reviewState === "REVIEW_READY"
      && result.aggregate.globalAllClear === false
      && result.aggregate.expectedPairs.length === 3,
    { completeness: result.aggregate.completeness, reviewState: result.aggregate.reviewState,
      globalAllClear: result.aggregate.globalAllClear, aggregateRoot: result.aggregate.aggregateRoot });
  check(assertions, "sequential-execution", "pair jobs ran one at a time in the required order",
    result.maxConcurrentPairsObserved === 1
      && result.aggregate.execution.strictlySequential
      && result.aggregate.execution.scheduling === "SEQUENTIAL",
    { pairOrder: graph.pairs.map((pair) => pair.label), maxConcurrentPairsObserved: result.maxConcurrentPairsObserved });
  check(assertions, "projection-privacy", "public and claimant projections retain their canonical scopes",
    result.projections.public.resolvedPairCount === 3
      && result.projections.claimants.length === 3
      && result.projections.claimants.every((projection) => projection.relations.length === 2),
    { publicProjection: result.projections.public,
      claimantRelationCounts: result.projections.claimants.map((projection) => projection.relations.length) });
  check(assertions, "recourse-boundary", "all pair roots stopped at RELEASED without forbidden side effects",
    pairScans.length === 3 && pairScans.every((scan) => scan.terminalStage === "RELEASED"
      && scan.forbiddenOperationMatches.length === 0
      && scan.forbiddenArtifactMatches.length === 0
      && !scan.recourseRecordPresent && !scan.publicEvidencePresent),
    { pairScans: pairScans.map((scan) => ({ label: scan.label, terminalStage: scan.terminalStage,
      forbiddenOperationMatches: scan.forbiddenOperationMatches,
      forbiddenArtifactMatches: scan.forbiddenArtifactMatches })) });
  check(assertions, "retention-disclosure", "private opening retention is explicit and makes no automatic cleanup or secure-erasure claim",
    retentionDeclaration.privateExactClaimOpenings.disposition === "PERSIST_UNTIL_EXPLICIT_OPERATOR_CLEANUP"
      && retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKey === "NOT_PERSISTED"
      && retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKeyLifetime
        === "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED"
      && retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKeyZeroizationClaimed === false
      && retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKeyGarbageCollectionTimingClaimed === false
      && retentionDeclaration.privateExactClaimOpenings.automaticCleanup === false
      && retentionDeclaration.privateExactClaimOpenings.secureErasureClaim === false
      && result.aggregate.retention.authorizationPrivateKeyZeroizationClaimed === false
      && result.aggregate.retention.authorizationPrivateKeyGarbageCollectionTimingClaimed === false
      && result.aggregate.retention.publicEvidenceContainsOpenings === false,
    { disposition: retentionDeclaration.privateExactClaimOpenings.disposition,
      authorizationPrivateKeyLifetime:
        retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKeyLifetime,
      authorizationPrivateKeyZeroizationClaimed:
        retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKeyZeroizationClaimed,
      authorizationPrivateKeyGarbageCollectionTimingClaimed:
        retentionDeclaration.privateExactClaimOpenings.authorizationPrivateKeyGarbageCollectionTimingClaimed,
      automaticCleanup: retentionDeclaration.privateExactClaimOpenings.automaticCleanup,
      secureErasureClaim: retentionDeclaration.privateExactClaimOpenings.secureErasureClaim });

  const allTemporaryRootsRemoved = cleanupAllTemporaryRoots();
  check(assertions, "operator-cleanup", "validated temporary roots were removed by explicit ordinary operator cleanup",
    allTemporaryRootsRemoved && pairScans.every((scan) => scan.pairCaseRootCleanupPerformed),
    { operatorCleanupPerformed: true, cleanupMethod: "ORDINARY_UNLINK_AFTER_EVIDENCE_CAPTURE",
      pairCaseRootsRemoved: pairScans.filter((scan) => scan.pairCaseRootCleanupPerformed).length,
      allTemporaryRootsRemoved });

  const source = Object.freeze({
    repository: REPOSITORY,
    branch,
    startingCommit: core.N3_STARTING_COMMIT,
    executionCommit: sourceCommit,
    executionTree: sourceTree,
    baseCommit,
    cleanCommittedCheckout: true,
    sourceCommitEnvironmentMatched: true,
    modules: Object.freeze(sourceModules),
  });
  const execution = Object.freeze({
    scheduling: "SEQUENTIAL",
    workerArchitecture: "UNCHANGED_SINGLE_SLOT",
    maxConcurrentPairsObserved: result.maxConcurrentPairsObserved,
    pairExecutionOrder: PAIR_EXECUTION_ORDER,
    expectedStates: EXPECTED_STATES,
    actualStates: Object.freeze(actualStates),
    stoppedAtStage: "RELEASED",
    inspectedBy: "mordant-fhe-inspect",
    recourseBoundaryPreserved: true,
  });
  const sideEffectScan = Object.freeze({
    forbiddenArtifactClasses: FORBIDDEN_ARTIFACT_CLASSES,
    pairs: Object.freeze(pairScans),
    allPairsReleased: pairScans.length === 3 && pairScans.every((scan) => scan.terminalStage === "RELEASED"),
    allForbiddenMatchesAbsent: pairScans.every((scan) => (
      scan.forbiddenOperationMatches.length === 0 && scan.forbiddenArtifactMatches.length === 0
    )),
  });
  const retention = Object.freeze({
    declaration: retentionDeclaration,
    productionModel: Object.freeze({
      exactIntervalsAndSaltsPersistPrivateUntilExplicitOperatorCleanup: true,
      authorizationPrivateKeyPersisted: false,
      authorizationPrivateKeyLifetime: "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
      authorizationPrivateKeyZeroizationClaimed: false,
      authorizationPrivateKeyGarbageCollectionTimingClaimed: false,
      automaticTerminalCleanup: false,
      secureErasureClaimed: false,
      deletionTrigger: "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY",
      publicEvidenceContainsOpenings: false,
    }),
    operatorCleanupPerformed: true,
    cleanupMethod: "ORDINARY_UNLINK_AFTER_EVIDENCE_CAPTURE",
    cleanupSecureErasureClaimed: false,
    pairCaseRootsRemoved: pairScans.length,
    temporaryRootClassesRemoved: TEMPORARY_ROOT_CLASSES,
    allTemporaryRootsRemoved,
  });

  const generatedAt = iso();
  const draftWithoutSanitationAssertion = {
    schemaVersion: SCHEMA_VERSION,
    evidenceDigestDomain: EVIDENCE_DIGEST_DOMAIN,
    verdict: EXACT_VERDICT,
    generatedAt,
    source,
    nativeBuild: nativeBuild.evidence,
    graph,
    execution,
    sideEffectScan,
    retention,
    assertions,
    supportedClaims: SUPPORTED_CLAIMS,
    unsupportedClaims: UNSUPPORTED_CLAIMS,
  };
  const preliminaryViolations = sanitationViolations(draftWithoutSanitationAssertion);
  check(assertions, "evidence-sanitation", "retained proof contains no raw openings, salts, private keys, absolute paths or ciphertexts",
    preliminaryViolations.length === 0,
    { violationCount: preliminaryViolations.length });

  const body = {
    ...draftWithoutSanitationAssertion,
    assertions: Object.freeze([...assertions]),
  };
  const finalViolations = sanitationViolations(body);
  if (finalViolations.length !== 0) {
    throw new Error(`Retained evidence sanitation failed with ${finalViolations.length} violation(s)`);
  }
  if (!body.assertions.every((assertion) => assertion.pass)) {
    throw new Error("One or more N=3 proof assertions failed");
  }
  const evidence = Object.freeze({
    ...body,
    evidenceDigest: core.graphDigest(EVIDENCE_DIGEST_DOMAIN, body),
  });
  mkdirSync(dirname(EVIDENCE_PATH), { recursive: true, mode: 0o700 });
  writeFileSync(EVIDENCE_PATH, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  const readback = readJson(EVIDENCE_PATH);
  const { evidenceDigest, ...readbackBody } = readback;
  if (evidenceDigest !== core.graphDigest(EVIDENCE_DIGEST_DOMAIN, readbackBody)) {
    throw new Error("Retained proof evidence failed canonical digest readback");
  }
  process.stdout.write(`${EXACT_VERDICT}\nEvidence: ${relative(SOURCE_ROOT, EVIDENCE_PATH)}\n`);
}

main().catch((error) => {
  try {
    cleanupAllTemporaryRoots();
  } catch (cleanupError) {
    process.stderr.write(`Cleanup failure: ${cleanupError?.message ?? "unknown error"}\n`);
  }
  process.stderr.write(`BLOCKED — N=3 PROOF HARNESS DID NOT COMPLETE: ${error?.message ?? "unknown error"}\n`);
  process.exitCode = 1;
});
