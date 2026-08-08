#!/usr/bin/env node

/**
 * Independent, read-only verifier for the retained bounded N=3 proof envelope.
 *
 * Compile the TypeScript verifier before invoking this script:
 *
 *   pnpm exec tsc -p tsconfig.product-tests.json
 *   node scripts/validate-n3-private-conflict-graph-evidence.mjs
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const N3_EVIDENCE_SCHEMA = "mordant.n3-private-conflict-graph-evidence/1";
export const N3_EVIDENCE_DIGEST_DOMAIN = "MordantN3PrivateConflictGraphProofEvidence/v1";
export const N3_EVIDENCE_VERDICT = "PASS — N=3 PRIVATE CONFLICT GRAPH PROOF READY FOR REVIEW";
export const N3_STARTING_COMMIT = "9ea6652dbf61c6227e3a21183e628a7356b6df18";
export const N3_EVIDENCE_RELATIVE_PATH =
  "docs/evidence/n3-private-conflict-graph/n3-private-conflict-graph-proof-2026-08-09.json";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMPILED_GRAPH_CORE = ".product-test-dist/src/lib/protection/receivable-conflict-session.js";
const EXPECTED_REPOSITORY = "RedGnad/Mordant";
const EXPECTED_BRANCH = "experiment/n3-private-conflict-graph";
const EXPECTED_LABELS = Object.freeze(["A", "B", "C"]);
const EXPECTED_PAIR_LABELS = Object.freeze(["A/B", "A/C", "B/C"]);
const EXPECTED_STATES = Object.freeze([
  Object.freeze({ label: "A/B", state: "CONFLICT" }),
  Object.freeze({ label: "A/C", state: "NO_CONFLICT_UNDER_POLICY" }),
  Object.freeze({ label: "B/C", state: "CONFLICT" }),
]);
const EXPECTED_OPERATIONS = Object.freeze([
  "preparePrivateMatch",
  "submitParticipantA",
  "submitParticipantB",
  "finalizeParticipantSubmissions",
  "evaluatePrivateConflict",
  "releaseGovernedResult",
]);
const EXPECTED_MODULES = Object.freeze([
  Object.freeze({
    id: "proofHarness",
    source: "scripts/n3-private-conflict-graph-proof.mjs",
    compiled: null,
  }),
  Object.freeze({
    id: "graphCore",
    source: "src/lib/protection/receivable-conflict-session.ts",
    compiled: ".product-test-dist/src/lib/protection/receivable-conflict-session.js",
  }),
  Object.freeze({
    id: "graphRunner",
    source: "src/lib/protection/receivable-conflict-session-runner.ts",
    compiled: ".product-test-dist/src/lib/protection/receivable-conflict-session-runner.js",
  }),
  Object.freeze({
    id: "graphStore",
    source: "src/lib/protection/receivable-conflict-session-store.ts",
    compiled: ".product-test-dist/src/lib/protection/receivable-conflict-session-store.js",
  }),
  Object.freeze({
    id: "pairOrchestrator",
    source: "src/lib/protection/governed-fhe-product-server.ts",
    compiled: ".product-test-dist/src/lib/protection/governed-fhe-product-server.js",
  }),
]);
const EXPECTED_BINARIES = Object.freeze([
  Object.freeze({ id: "keygen", name: "mordant-fhe-keygen", package: "./cmd/mordant-fhe-keygen" }),
  Object.freeze({ id: "client", name: "mordant-fhe-client", package: "./cmd/mordant-fhe-client" }),
  Object.freeze({ id: "evaluator", name: "mordant-fhe-evaluator", package: "./cmd/mordant-fhe-evaluator" }),
  Object.freeze({ id: "decryptor", name: "mordant-fhe-decryptor", package: "./cmd/mordant-fhe-decryptor" }),
  Object.freeze({ id: "inspect", name: "mordant-fhe-inspect", package: "./cmd/mordant-fhe-inspect" }),
]);
const EXPECTED_BUILD_FLAGS = Object.freeze(["-mod=readonly", "-trimpath", "-buildvcs=false"]);
const EXPECTED_FORBIDDEN_ARTIFACT_CLASSES = Object.freeze([
  "RECOURSE",
  "EVIDENCE_EXPORT",
  "ADAPTER",
  "CURE",
  "SETTLEMENT",
]);
const EXPECTED_TEMPORARY_ROOT_CLASSES = Object.freeze([
  "PAIR_RUN_ROOT",
  "OPERATOR_AUDIT_EVIDENCE_ROOT",
  "PRIVATE_CLAIM_ROOT",
  "NATIVE_BINARY_ROOT",
  "GO_BUILD_CACHE",
]);
const EXPECTED_ASSERTION_IDS = Object.freeze([
  "source-pin",
  "native-build",
  "claim-set",
  "pair-set",
  "governed-results",
  "governed-signatures",
  "public-inspection",
  "stable-claim-binding",
  "fresh-pair-keys",
  "aggregate-complete",
  "sequential-execution",
  "projection-privacy",
  "recourse-boundary",
  "retention-disclosure",
  "operator-cleanup",
  "evidence-sanitation",
]);

export const N3_SUPPORTED_CLAIMS = Object.freeze([
  "Three separately authorized opaque graph claims over one synthetic receivable were admitted in order A, B, C.",
  "The existing reviewed two-party BGV primitive produced three independent signed governed Booleans sequentially.",
  "A/B is CONFLICT, A/C is NO_CONFLICT_UNDER_POLICY, and B/C is CONFLICT.",
  "Every expected canonical pair has a retained intent, binding, independently verified signed result, and evidence leaf.",
  "The aggregate is COMPLETE and REVIEW_READY, with scoped operator, claimant, and public projections.",
  "Execution stopped at RELEASED and created no recourse, evidence-export, adapter, cure, or settlement artifacts.",
  "Exact claim openings were persisted only in temporary operator-private filesystem roots, which were removed by explicit ordinary cleanup after evidence capture; caller-managed process-memory references and secure erasure are not claimed.",
]);

export const N3_UNSUPPORTED_CLAIMS = Object.freeze([
  "This is an N-party FHE circuit or an N-party ciphertext-reuse design.",
  "The existing production worker supports concurrent pair execution or increased throughput.",
  "The experiment proves production deployment, horizontal scaling, or high availability.",
  "Conflict edges automatically determine one incident, multiple incidents, recourse, cure, or settlement.",
  "The proof moves tokens, deploys adapters, or exercises settlement.",
  "Ordinary unlink is secure erasure or proves forensic deletion of private material.",
  "Native binary bytes remain available for independent post-cleanup re-hashing.",
  "The experiment supports arbitrary N or any receivable beyond the bounded synthetic N=3 case.",
]);

export class N3EvidenceValidationError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "N3EvidenceValidationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new N3EvidenceValidationError(code, message);
}

function plainObject(value, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, "plain JSON object required");
  }
  return value;
}

function exactKeys(value, expected, code) {
  const record = plainObject(value, code);
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(code, "unexpected or missing fields");
  }
  return record;
}

function exactArray(value, length, code) {
  if (!Array.isArray(value) || value.length !== length) fail(code, `exactly ${length} entries required`);
  return value;
}

function exactString(value, expected, code) {
  if (typeof value !== "string" || (expected !== undefined && value !== expected)) {
    fail(code, "unexpected string value");
  }
  return value;
}

function exactBoolean(value, expected, code) {
  if (typeof value !== "boolean" || value !== expected) fail(code, "unexpected Boolean value");
}

function safeInteger(value, code, { positive = false, nonNegative = false } = {}) {
  if (!Number.isSafeInteger(value) || (positive && value <= 0) || (nonNegative && value < 0)) {
    fail(code, "safe integer requirement failed");
  }
  return value;
}

function sha256Digest(value, code) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)
    || /^sha256:0{64}$/u.test(value)) {
    fail(code, "non-zero lowercase SHA-256 digest required");
  }
  return value;
}

function gitCommit(value, code) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value) || /^0{40}$/u.test(value)) {
    fail(code, "full non-zero lowercase Git commit required");
  }
  return value;
}

function canonicalIso(value, code) {
  if (typeof value !== "string") fail(code, "canonical UTC timestamp required");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    fail(code, "canonical UTC timestamp required");
  }
  return milliseconds;
}

function assertSameArray(actual, expected, code) {
  exactArray(actual, expected.length, code);
  if (actual.some((entry, index) => entry !== expected[index])) fail(code, "ordered values changed");
}

function assertSameStates(actual, code) {
  exactArray(actual, EXPECTED_STATES.length, code);
  for (let index = 0; index < EXPECTED_STATES.length; index += 1) {
    const state = exactKeys(actual[index], ["label", "state"], code);
    exactString(state.label, EXPECTED_STATES[index].label, code);
    exactString(state.state, EXPECTED_STATES[index].state, code);
  }
}

function digestBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function safeRelativePath(value, code) {
  exactString(value, undefined, code);
  if (value.length === 0 || isAbsolute(value) || win32.isAbsolute(value) || value.includes("\0")) {
    fail(code, "repository-relative path required");
  }
  const normalized = value.split(/[\\/]+/u);
  if (normalized.some((entry) => entry === "" || entry === "." || entry === "..")) {
    fail(code, "canonical repository-relative path required");
  }
  return value;
}

function insideRoot(root, path, code) {
  const relation = relative(root, path);
  if (relation === "" || relation === ".." || relation.startsWith(`..${sep}`) || isAbsolute(relation)) {
    fail(code, "path escaped the repository root");
  }
}

function gitOutput(root, args, code, encoding = "utf8") {
  try {
    return execFileSync("git", args, {
      cwd: root,
      encoding,
      maxBuffer: 32 << 20,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    fail(code, "required Git provenance could not be verified");
  }
}

let graphCorePromise;

async function loadGraphCore(root) {
  if (root === ROOT && graphCorePromise !== undefined) return graphCorePromise;
  const compiled = join(root, COMPILED_GRAPH_CORE);
  insideRoot(root, compiled, "COMPILED_GRAPH_CORE");
  const load = import(pathToFileURL(compiled).href).catch(() => {
    fail("COMPILED_GRAPH_CORE", "compile tsconfig.product-tests.json before validating N=3 evidence");
  });
  if (root === ROOT) graphCorePromise = load;
  const core = await load;
  for (const name of [
    "canonicalClaimPair",
    "canonicalGraphJson",
    "claimGlobalAllClear",
    "createPairPublicInspection",
    "graphDigest",
    "projectClaimantGraph",
    "publicInspectionReportDigest",
    "verifyAggregateManifest",
    "verifyConflictGraphProjections",
    "verifyGraphClaimAuthorization",
    "verifyGraphPairBinding",
    "verifyGraphPairEvidenceLeaf",
    "verifyGraphPairIntent",
  ]) {
    if (typeof core[name] !== "function") fail("COMPILED_GRAPH_CORE", "required graph verifier export is missing");
  }
  return core;
}

function evidenceBody(evidence) {
  const body = { ...evidence };
  delete body.evidenceDigest;
  return body;
}

export async function computeN3EvidenceDigest(evidence, options = {}) {
  const root = options.root === undefined ? ROOT : resolve(options.root);
  const core = await loadGraphCore(root);
  return core.graphDigest(N3_EVIDENCE_DIGEST_DOMAIN, evidenceBody(plainObject(evidence, "EVIDENCE_BODY")));
}

function containsAbsoluteFilesystemPath(value) {
  if (typeof value !== "string") return false;
  return /(?:^|[\s"'(])\/(?:Users|home|tmp|private|var|opt|Volumes|workspace|root)(?:\/|$)/u.test(value)
    || /(?:^|[\s"'(])[A-Za-z]:[\\/]/u.test(value)
    || /(?:^|[\s"'(])\\\\[^\\]/u.test(value)
    || /file:\/\//iu.test(value);
}

function assertSanitizedEvidence(value, path = "$") {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) assertSanitizedEvidence(value[index], `${path}[${index}]`);
    return;
  }
  if (value !== null && typeof value === "object") {
    const record = plainObject(value, "EVIDENCE_SANITATION");
    for (const [key, nested] of Object.entries(record)) {
      const normalized = key.replace(/[-_]/gu, "").toLowerCase();
      const declarationKey = path === "$.retention.declaration.privateExactClaimOpenings"
        && (key === "authorizationPrivateKey" || key === "authorizationPrivateKeyLifetime");
      if (["activefrom", "activeuntil", "opening", "salt", "privatekey", "secretkey"].includes(normalized)
        || (normalized === "authorizationprivatekey" && !declarationKey)) {
        fail("EVIDENCE_SANITATION", "raw opening or private-key field present in retained evidence");
      }
      assertSanitizedEvidence(nested, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === "string") {
    if (containsAbsoluteFilesystemPath(value)
      || /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/u.test(value)
      || /(?:secret-key|decryptor-signing-key)\.bin/iu.test(value)) {
      fail("EVIDENCE_SANITATION", "absolute path or private material present in retained evidence");
    }
  }
}

const sourceVerificationCache = new Map();

async function verifySource(source, root, core) {
  const sourceRecord = exactKeys(source, [
    "repository",
    "branch",
    "startingCommit",
    "executionCommit",
    "executionTree",
    "baseCommit",
    "cleanCommittedCheckout",
    "sourceCommitEnvironmentMatched",
    "modules",
  ], "SOURCE_FIELDS");
  exactString(sourceRecord.repository, EXPECTED_REPOSITORY, "SOURCE_REPOSITORY");
  exactString(sourceRecord.branch, EXPECTED_BRANCH, "SOURCE_BRANCH");
  exactString(sourceRecord.startingCommit, N3_STARTING_COMMIT, "SOURCE_STARTING_COMMIT");
  exactString(sourceRecord.baseCommit, N3_STARTING_COMMIT, "SOURCE_BASE_COMMIT");
  gitCommit(sourceRecord.executionCommit, "SOURCE_EXECUTION_COMMIT");
  gitCommit(sourceRecord.executionTree, "SOURCE_EXECUTION_TREE");
  exactBoolean(sourceRecord.cleanCommittedCheckout, true, "SOURCE_CLEAN_CHECKOUT");
  exactBoolean(sourceRecord.sourceCommitEnvironmentMatched, true, "SOURCE_ENVIRONMENT_PIN");

  const modules = exactArray(sourceRecord.modules, EXPECTED_MODULES.length, "SOURCE_MODULES");
  for (let index = 0; index < EXPECTED_MODULES.length; index += 1) {
    const expected = EXPECTED_MODULES[index];
    const moduleEvidence = exactKeys(modules[index], ["id", "source", "compiled", "sourceSha256", "compiledSha256"], "SOURCE_MODULE");
    exactString(moduleEvidence.id, expected.id, "SOURCE_MODULE_ID");
    exactString(moduleEvidence.source, expected.source, "SOURCE_MODULE_PATH");
    safeRelativePath(moduleEvidence.source, "SOURCE_MODULE_PATH");
    sha256Digest(moduleEvidence.sourceSha256, "SOURCE_MODULE_DIGEST");
    if (expected.compiled === null) {
      if (moduleEvidence.compiled !== null || moduleEvidence.compiledSha256 !== null) {
        fail("SOURCE_MODULE_COMPILED", "proof harness has no compiled projection");
      }
    } else {
      exactString(moduleEvidence.compiled, expected.compiled, "SOURCE_MODULE_COMPILED");
      safeRelativePath(moduleEvidence.compiled, "SOURCE_MODULE_COMPILED");
      sha256Digest(moduleEvidence.compiledSha256, "SOURCE_MODULE_COMPILED_DIGEST");
    }
  }

  const cacheKey = core.canonicalGraphJson(sourceRecord);
  if (sourceVerificationCache.has(cacheKey)) return sourceVerificationCache.get(cacheKey);
  const verification = Promise.resolve().then(() => {
    gitOutput(root, ["cat-file", "-e", `${sourceRecord.executionCommit}^{commit}`], "SOURCE_EXECUTION_COMMIT");
    const tree = gitOutput(root, ["rev-parse", `${sourceRecord.executionCommit}^{tree}`], "SOURCE_EXECUTION_TREE").trim();
    if (tree !== sourceRecord.executionTree) fail("SOURCE_EXECUTION_TREE", "execution tree does not belong to execution commit");
    const base = gitOutput(root, ["merge-base", sourceRecord.startingCommit, sourceRecord.executionCommit], "SOURCE_ANCESTRY").trim();
    if (base !== sourceRecord.baseCommit) fail("SOURCE_ANCESTRY", "execution commit does not descend from the exact starting commit");
    gitOutput(root, ["merge-base", "--is-ancestor", sourceRecord.executionCommit, "HEAD"], "SOURCE_ANCESTRY");

    for (const moduleEvidence of modules) {
      const sourcePath = join(root, moduleEvidence.source);
      insideRoot(root, sourcePath, "SOURCE_MODULE_PATH");
      const committed = gitOutput(
        root,
        ["show", `${sourceRecord.executionCommit}:${moduleEvidence.source}`],
        "SOURCE_MODULE_GIT_OBJECT",
        null,
      );
      if (digestBytes(committed) !== moduleEvidence.sourceSha256
        || digestBytes(readFileSync(sourcePath)) !== moduleEvidence.sourceSha256) {
        fail("SOURCE_MODULE_DIGEST", "source module bytes do not match the committed execution source");
      }
      if (moduleEvidence.compiled !== null) {
        const compiledPath = join(root, moduleEvidence.compiled);
        insideRoot(root, compiledPath, "SOURCE_MODULE_COMPILED");
        if (digestBytes(readFileSync(compiledPath)) !== moduleEvidence.compiledSha256) {
          fail("SOURCE_MODULE_COMPILED_DIGEST", "compiled verifier bytes do not match retained provenance");
        }
      }
    }
  });
  sourceVerificationCache.set(cacheKey, verification);
  return verification;
}

function verifyNativeBuild(nativeBuild, source, pins) {
  const build = exactKeys(nativeBuild, [
    "proofGrade",
    "builtDuringProof",
    "prepopulatedBinaryRootAccepted",
    "sourceCommit",
    "sourceTree",
    "startedAt",
    "completedAt",
    "toolchain",
    "flags",
    "binaries",
  ], "NATIVE_BUILD_FIELDS");
  exactBoolean(build.proofGrade, true, "NATIVE_PROOF_GRADE");
  exactBoolean(build.builtDuringProof, true, "NATIVE_FRESH_BUILD");
  exactBoolean(build.prepopulatedBinaryRootAccepted, false, "NATIVE_PREPOPULATED_ROOT");
  exactString(build.sourceCommit, source.executionCommit, "NATIVE_SOURCE_COMMIT");
  exactString(build.sourceTree, source.executionTree, "NATIVE_SOURCE_TREE");
  const started = canonicalIso(build.startedAt, "NATIVE_BUILD_STARTED");
  const completed = canonicalIso(build.completedAt, "NATIVE_BUILD_COMPLETED");
  if (completed <= started) fail("NATIVE_BUILD_TIME", "native build completion must follow start");

  const toolchain = exactKeys(build.toolchain, ["goVersion", "goToolchain", "goos", "goarch", "cgoEnabled"], "NATIVE_TOOLCHAIN_FIELDS");
  if (typeof toolchain.goVersion !== "string" || !/^go1\.[0-9]+(?:\.[0-9]+)?(?:[a-z0-9.-]*)$/u.test(toolchain.goVersion)
    || typeof toolchain.goToolchain !== "string" || toolchain.goToolchain.length === 0
    || typeof toolchain.goos !== "string" || !/^[a-z0-9]+$/u.test(toolchain.goos)
    || typeof toolchain.goarch !== "string" || !/^[a-z0-9]+$/u.test(toolchain.goarch)) {
    fail("NATIVE_TOOLCHAIN", "Go toolchain identity is malformed");
  }
  exactBoolean(toolchain.cgoEnabled, false, "NATIVE_CGO");
  assertSameArray(build.flags, EXPECTED_BUILD_FLAGS, "NATIVE_BUILD_FLAGS");

  const binaries = exactArray(build.binaries, EXPECTED_BINARIES.length, "NATIVE_BINARIES");
  const seenDigests = new Set();
  for (let index = 0; index < EXPECTED_BINARIES.length; index += 1) {
    const expected = EXPECTED_BINARIES[index];
    const binary = exactKeys(binaries[index], ["id", "name", "package", "bytes", "sha256"], "NATIVE_BINARY_FIELDS");
    exactString(binary.id, expected.id, "NATIVE_BINARY_ID");
    exactString(binary.name, expected.name, "NATIVE_BINARY_NAME");
    exactString(binary.package, expected.package, "NATIVE_BINARY_PACKAGE");
    if (!/^\.\/cmd\/[a-z0-9-]+$/u.test(binary.package)) {
      fail("NATIVE_BINARY_PACKAGE", "canonical governed-FHE command package required");
    }
    safeInteger(binary.bytes, "NATIVE_BINARY_BYTES", { positive: true });
    sha256Digest(binary.sha256, "NATIVE_BINARY_DIGEST");
    if (binary.sha256 !== pins.nativeBinaries[expected.id]) fail("NATIVE_BINARY_PIN", "native build and aggregate pin disagree");
    if (seenDigests.has(binary.sha256)) fail("NATIVE_BINARY_FRESHNESS", "native executables must have distinct byte digests");
    seenDigests.add(binary.sha256);
  }
  return { started, completed, binaries };
}

function verifyRawInspection(report, pair, pins, core) {
  const raw = exactKeys(report, [
    "foundation",
    "submissionA",
    "submissionB",
    "finalized",
    "evaluationAdmission",
    "evaluation",
    "releaseAdmission",
    "foundationPrivateComplete",
    "releasePrivateComplete",
    "release",
    "protectionBindingDigest",
    "ambiguous",
  ], "INSPECTION_REPORT_FIELDS");
  const foundation = exactKeys(raw.foundation, ["bindingDigest", "report"], "INSPECTION_FOUNDATION_FIELDS");
  sha256Digest(foundation.bindingDigest, "INSPECTION_FOUNDATION_DIGEST");
  if (foundation.bindingDigest !== pair.binding.caseBindingDigest) fail("INSPECTION_FOUNDATION_BINDING", "inspection case binding mismatch");
  const keygenReport = exactKeys(foundation.report, [
    "duration",
    "parameterBytes",
    "publicKeyBytes",
    "relinearizationKeyBytes",
    "galoisKeyBytes",
    "publicArtifactBytes",
    "privateArtifactBytes",
  ], "INSPECTION_KEYGEN_REPORT_FIELDS");
  safeInteger(keygenReport.duration, "INSPECTION_KEYGEN_DURATION", { nonNegative: true });
  for (const field of ["parameterBytes", "publicKeyBytes", "relinearizationKeyBytes", "publicArtifactBytes"]) {
    safeInteger(keygenReport[field], "INSPECTION_KEYGEN_BYTES", { positive: true });
  }
  safeInteger(keygenReport.privateArtifactBytes, "INSPECTION_PRIVATE_BYTES", { nonNegative: true });
  if (!Array.isArray(keygenReport.galoisKeyBytes) || keygenReport.galoisKeyBytes.length === 0
    || keygenReport.galoisKeyBytes.some((bytes) => !Number.isSafeInteger(bytes) || bytes <= 0)) {
    fail("INSPECTION_GALOIS_KEYS", "inspection Galois-key byte counts rejected");
  }

  const submissions = [raw.submissionA, raw.submissionB];
  for (let index = 0; index < submissions.length; index += 1) {
    const submission = exactKeys(submissions[index], ["artifactDigest", "ciphertextBytes", "artifactBytes"], "INSPECTION_SUBMISSION_FIELDS");
    sha256Digest(submission.artifactDigest, "INSPECTION_SUBMISSION_DIGEST");
    safeInteger(submission.ciphertextBytes, "INSPECTION_SUBMISSION_BYTES", { positive: true });
    safeInteger(submission.artifactBytes, "INSPECTION_SUBMISSION_BYTES", { positive: true });
    if (submission.artifactDigest !== pair.leaf.participantArtifactDigests[index]) {
      fail("INSPECTION_SUBMISSION_BINDING", "inspection participant artifact mismatch");
    }
  }
  const evaluation = exactKeys(raw.evaluation, ["artifactDigest", "resultBytes", "artifactBytes"], "INSPECTION_EVALUATION_FIELDS");
  sha256Digest(evaluation.artifactDigest, "INSPECTION_EVALUATION_DIGEST");
  safeInteger(evaluation.resultBytes, "INSPECTION_EVALUATION_BYTES", { positive: true });
  safeInteger(evaluation.artifactBytes, "INSPECTION_EVALUATION_BYTES", { positive: true });
  if (evaluation.artifactDigest !== pair.leaf.evaluatedArtifactDigest) {
    fail("INSPECTION_EVALUATION_BINDING", "inspection evaluated artifact mismatch");
  }

  const release = exactKeys(raw.release, [
    "resultDigest",
    "conflict",
    "releaseMode",
    "resultBytes",
    "exactRetry",
    "trustedRecoursePins",
  ], "INSPECTION_RELEASE_FIELDS");
  sha256Digest(release.resultDigest, "INSPECTION_RESULT_DIGEST");
  safeInteger(release.resultBytes, "INSPECTION_RESULT_BYTES", { positive: true });
  exactBoolean(release.exactRetry, true, "INSPECTION_EXACT_RETRY");
  const trusted = exactKeys(release.trustedRecoursePins, [
    "participantArtifactDigestA",
    "participantArtifactDigestB",
    "evaluatedArtifactDigest",
    "recomputedResultCiphertextDigest",
    "resultCiphertextCommitment",
    "decryptorProvenance",
    "releaseMode",
    "releaseAuthorityId",
  ], "INSPECTION_TRUSTED_PIN_FIELDS");
  for (const [field, value] of Object.entries(trusted)) {
    if (field !== "releaseMode") sha256Digest(value, "INSPECTION_TRUSTED_PIN");
  }
  const result = pair.leaf.governedResult;
  if (release.resultDigest !== pair.leaf.governedResultDigest
    || release.conflict !== result.conflict
    || release.releaseMode !== result.releaseMode
    || trusted.participantArtifactDigestA !== pair.leaf.participantArtifactDigests[0]
    || trusted.participantArtifactDigestB !== pair.leaf.participantArtifactDigests[1]
    || trusted.evaluatedArtifactDigest !== pair.leaf.evaluatedArtifactDigest
    || trusted.recomputedResultCiphertextDigest !== result.resultCiphertextDigest
    || trusted.resultCiphertextCommitment !== result.resultCiphertextCommitment
    || trusted.decryptorProvenance !== pins.nativeBinaries.decryptor
    || trusted.releaseMode !== result.releaseMode
    || trusted.releaseAuthorityId !== result.releaseAuthorityId) {
    fail("INSPECTION_RELEASE_BINDING", "raw inspection does not bind the governed result");
  }
  exactBoolean(raw.finalized, true, "INSPECTION_FINALIZED");
  exactBoolean(raw.evaluationAdmission, true, "INSPECTION_EVALUATION_ADMISSION");
  exactBoolean(raw.releaseAdmission, false, "INSPECTION_PUBLIC_RELEASE_ADMISSION");
  exactBoolean(raw.foundationPrivateComplete, false, "INSPECTION_PUBLIC_PRIVATE_FOUNDATION");
  exactBoolean(raw.releasePrivateComplete, false, "INSPECTION_PUBLIC_PRIVATE_RELEASE");
  exactBoolean(raw.ambiguous, false, "INSPECTION_AMBIGUITY");
  sha256Digest(raw.protectionBindingDigest, "INSPECTION_PROTECTION_BINDING");

  const inspectionReportDigest = core.publicInspectionReportDigest(raw);
  if (inspectionReportDigest !== pair.leaf.inspection.inspectionReportDigest) {
    fail("INSPECTION_REPORT_DIGEST", "raw inspection report digest mismatch");
  }
  const derived = core.createPairPublicInspection({
    finalized: raw.finalized,
    evaluationAdmission: raw.evaluationAdmission,
    releaseVerified: raw.release !== undefined,
    ambiguous: raw.ambiguous,
    recoursePresent: Object.hasOwn(raw, "recourse"),
    publicEvidencePresent: Object.hasOwn(raw, "evidence"),
    resultDigest: release.resultDigest,
    conflict: release.conflict,
    releaseMode: release.releaseMode,
    participantArtifactDigests: [
      trusted.participantArtifactDigestA,
      trusted.participantArtifactDigestB,
    ],
    evaluatedArtifactDigest: trusted.evaluatedArtifactDigest,
    inspectBinaryDigest: pins.nativeBinaries.inspect,
    inspectionReportDigest,
  });
  if (core.canonicalGraphJson(derived) !== core.canonicalGraphJson(pair.leaf.inspection)) {
    fail("INSPECTION_PROJECTION", "leaf inspection is not the sanitized raw-report projection");
  }
}

function verifyGraph(graph, core) {
  const graphRecord = exactKeys(graph, ["session", "claims", "pairs", "aggregate", "chronology", "projections"], "GRAPH_FIELDS");
  const aggregate = plainObject(graphRecord.aggregate, "GRAPH_AGGREGATE");
  const session = exactKeys(graphRecord.session, [
    "graphSessionId",
    "receivableIdentity",
    "issuedAtUnix",
    "expiresAtUnix",
    "admissionOrder",
    "expectedClaimCount",
    "expectedPairExecutionOrder",
  ], "GRAPH_SESSION_FIELDS");
  sha256Digest(session.graphSessionId, "GRAPH_SESSION_ID");
  sha256Digest(session.receivableIdentity, "GRAPH_RECEIVABLE");
  safeInteger(session.issuedAtUnix, "GRAPH_ISSUED_AT", { positive: true });
  safeInteger(session.expiresAtUnix, "GRAPH_EXPIRES_AT", { positive: true });
  if (session.expiresAtUnix <= session.issuedAtUnix) fail("GRAPH_SESSION_TIME", "graph expiry must follow issue time");
  assertSameArray(session.admissionOrder, EXPECTED_LABELS, "GRAPH_ADMISSION_ORDER");
  safeInteger(session.expectedClaimCount, "GRAPH_CLAIM_COUNT", { positive: true });
  if (session.expectedClaimCount !== 3) fail("GRAPH_CLAIM_COUNT", "bounded proof requires exactly three claims");
  assertSameArray(session.expectedPairExecutionOrder, EXPECTED_PAIR_LABELS, "GRAPH_PAIR_ORDER");
  if (session.graphSessionId !== aggregate.graphSessionId || session.receivableIdentity !== aggregate.receivableIdentity
    || session.issuedAtUnix !== aggregate.issuedAtUnix || session.expiresAtUnix !== aggregate.expiresAtUnix) {
    fail("GRAPH_SESSION_BINDING", "session header and aggregate disagree");
  }

  const claims = exactArray(graphRecord.claims, 3, "GRAPH_CLAIMS");
  const nodes = [];
  const claimsByLabel = new Map();
  for (let index = 0; index < claims.length; index += 1) {
    const claim = exactKeys(claims[index], ["label", "authorization"], "GRAPH_CLAIM_FIELDS");
    exactString(claim.label, EXPECTED_LABELS[index], "GRAPH_CLAIM_LABEL");
    core.verifyGraphClaimAuthorization(claim.authorization);
    if (claim.authorization.graphSessionId !== session.graphSessionId
      || claim.authorization.receivableIdentity !== session.receivableIdentity) {
      fail("GRAPH_CLAIM_BINDING", "claim is not bound to the retained session and receivable");
    }
    nodes.push(claim.authorization);
    claimsByLabel.set(claim.label, claim.authorization);
  }
  if (new Set(nodes.map((node) => node.claimId)).size !== 3
    || new Set(nodes.map((node) => node.participantRef)).size !== 3) {
    fail("GRAPH_CLAIM_UNIQUENESS", "claim or participant reference was reused");
  }
  const sortedNodes = [...nodes].sort((left, right) => left.claimId.localeCompare(right.claimId));
  if (core.canonicalGraphJson(sortedNodes) !== core.canonicalGraphJson(aggregate.nodes)) {
    fail("GRAPH_AGGREGATE_NODES", "aggregate node set differs from admission records");
  }

  const pairs = exactArray(graphRecord.pairs, 3, "GRAPH_PAIRS");
  const leaves = [];
  const distinctFields = {
    pairRunId: [],
    caseId: [],
    caseBindingDigest: [],
    publicKeyDigest: [],
    evaluationKeyManifestDigest: [],
    evaluatedArtifactDigest: [],
    governedResultDigest: [],
    releaseAuthorityId: [],
    releaseAuthorityPublicKey: [],
    resultCiphertextDigest: [],
    resultCiphertextCommitment: [],
  };
  const participantArtifacts = [];
  let priorCompleted = Number.NEGATIVE_INFINITY;
  let firstStarted = Number.POSITIVE_INFINITY;
  for (let index = 0; index < pairs.length; index += 1) {
    const pair = exactKeys(pairs[index], ["label", "intent", "binding", "leaf", "inspectReport"], "GRAPH_PAIR_FIELDS");
    const label = EXPECTED_PAIR_LABELS[index];
    exactString(pair.label, label, "GRAPH_PAIR_LABEL");
    const [leftLabel, rightLabel] = label.split("/");
    const expectedPair = core.canonicalClaimPair(
      claimsByLabel.get(leftLabel).claimId,
      claimsByLabel.get(rightLabel).claimId,
    );
    if (core.canonicalGraphJson(pair.intent.claimPair) !== core.canonicalGraphJson(expectedPair)
      || core.canonicalGraphJson(pair.binding.claimPair) !== core.canonicalGraphJson(expectedPair)
      || core.canonicalGraphJson(pair.leaf.claimPair) !== core.canonicalGraphJson(expectedPair)) {
      fail("GRAPH_PAIR_BINDING", "labeled pair does not match its canonical graph claims");
    }
    core.verifyGraphPairIntent(pair.intent, nodes);
    core.verifyGraphPairBinding(pair.binding, pair.intent, nodes, aggregate.pins);
    core.verifyGraphPairEvidenceLeaf(pair.leaf, pair.binding, pair.intent, nodes, aggregate.pins);
    verifyRawInspection(pair.inspectReport, pair, aggregate.pins, core);
    if (pair.leaf.state !== EXPECTED_STATES[index].state
      || pair.leaf.governedResult.conflict !== (EXPECTED_STATES[index].state === "CONFLICT")) {
      fail("GRAPH_PAIR_RESULT", "signed pair result differs from the bounded expected result");
    }
    if (pair.leaf.execution.executionOrdinal !== index + 1
      || core.canonicalGraphJson(pair.leaf.execution.operations) !== core.canonicalGraphJson(EXPECTED_OPERATIONS)) {
      fail("GRAPH_PAIR_EXECUTION", "pair operation or ordinal changed");
    }
    const started = canonicalIso(pair.leaf.execution.startedAt, "GRAPH_PAIR_STARTED");
    const completed = canonicalIso(pair.leaf.execution.completedAt, "GRAPH_PAIR_COMPLETED");
    if (completed <= started || started < priorCompleted) fail("GRAPH_PAIR_SEQUENTIAL", "pair executions overlap or run backwards");
    firstStarted = Math.min(firstStarted, started);
    priorCompleted = completed;
    leaves.push(pair.leaf);

    for (const key of Object.keys(distinctFields)) {
      let value;
      if (key === "publicKeyDigest" || key === "evaluationKeyManifestDigest") value = pair.binding.caseBinding[key];
      else if (key in pair.leaf) value = pair.leaf[key];
      else value = pair.leaf.governedResult[key];
      distinctFields[key].push(value);
    }
    participantArtifacts.push(...pair.leaf.participantArtifactDigests);
  }
  for (const [field, values] of Object.entries(distinctFields)) {
    if (values.some((value) => value === undefined) || new Set(values).size !== 3) {
      fail("GRAPH_PAIR_FRESHNESS", `${field} was reused across independent pairs`);
    }
  }
  if (new Set(participantArtifacts).size !== 6) fail("GRAPH_PAIR_FRESHNESS", "participant artifacts were reused across pairs");

  const chronology = exactKeys(graphRecord.chronology, ["schemaVersion", "graphSessionId", "events", "digest"], "GRAPH_CHRONOLOGY_FIELDS");
  sha256Digest(chronology.digest, "GRAPH_CHRONOLOGY_DIGEST");
  if (!Array.isArray(chronology.events)) fail("GRAPH_CHRONOLOGY_EVENTS", "chronology event array required");
  core.verifyAggregateManifest(aggregate, chronology, leaves);
  core.verifyConflictGraphProjections(aggregate, graphRecord.projections);
  if (aggregate.completeness !== "COMPLETE" || aggregate.reviewState !== "REVIEW_READY"
    || aggregate.globalAllClear !== false || !aggregate.nodesSealed
    || aggregate.trueConflictEdges.length !== 2 || aggregate.reviewHandoff.evidenceReferences.length !== 3) {
    fail("GRAPH_AGGREGATE_STATE", "aggregate is not the exact complete review-ready bounded result");
  }
  return { aggregate, claims, pairs, leaves, firstStarted, lastCompleted: priorCompleted };
}

function verifyExecution(execution, aggregate) {
  const record = exactKeys(execution, [
    "scheduling",
    "workerArchitecture",
    "maxConcurrentPairsObserved",
    "pairExecutionOrder",
    "expectedStates",
    "actualStates",
    "stoppedAtStage",
    "inspectedBy",
    "recourseBoundaryPreserved",
  ], "EXECUTION_FIELDS");
  exactString(record.scheduling, "SEQUENTIAL", "EXECUTION_SCHEDULING");
  exactString(record.workerArchitecture, "UNCHANGED_SINGLE_SLOT", "EXECUTION_WORKER");
  if (record.maxConcurrentPairsObserved !== 1 || aggregate.execution.maxConcurrentPairsObserved !== 1
    || aggregate.execution.scheduling !== record.scheduling
    || aggregate.execution.workerArchitecture !== record.workerArchitecture
    || !aggregate.execution.strictlySequential) {
    fail("EXECUTION_SEQUENTIAL", "single-slot sequential execution claim changed");
  }
  assertSameArray(record.pairExecutionOrder, EXPECTED_PAIR_LABELS, "EXECUTION_PAIR_ORDER");
  assertSameStates(record.expectedStates, "EXECUTION_EXPECTED_STATES");
  assertSameStates(record.actualStates, "EXECUTION_ACTUAL_STATES");
  exactString(record.stoppedAtStage, "RELEASED", "EXECUTION_STOP_STAGE");
  exactString(record.inspectedBy, "mordant-fhe-inspect", "EXECUTION_INSPECTOR");
  exactBoolean(record.recourseBoundaryPreserved, true, "EXECUTION_RECOURSE_BOUNDARY");
}

function verifySideEffects(sideEffectScan, pairs) {
  const scan = exactKeys(sideEffectScan, [
    "forbiddenArtifactClasses",
    "pairs",
    "allPairsReleased",
    "allForbiddenMatchesAbsent",
  ], "SIDE_EFFECT_FIELDS");
  assertSameArray(scan.forbiddenArtifactClasses, EXPECTED_FORBIDDEN_ARTIFACT_CLASSES, "SIDE_EFFECT_CLASSES");
  const scannedPairs = exactArray(scan.pairs, 3, "SIDE_EFFECT_PAIRS");
  for (let index = 0; index < scannedPairs.length; index += 1) {
    const record = exactKeys(scannedPairs[index], [
      "label",
      "terminalStage",
      "operations",
      "operationOutcomes",
      "scannedFileCount",
      "forbiddenOperationMatches",
      "forbiddenArtifactMatches",
      "recourseState",
      "cureDeadline",
      "recourseRecordPresent",
      "publicEvidencePresent",
      "pairCaseRootCleanupPerformed",
      "cleanupMethod",
    ], "SIDE_EFFECT_PAIR_FIELDS");
    exactString(record.label, EXPECTED_PAIR_LABELS[index], "SIDE_EFFECT_PAIR_LABEL");
    exactString(record.terminalStage, "RELEASED", "SIDE_EFFECT_TERMINAL_STAGE");
    assertSameArray(record.operations, EXPECTED_OPERATIONS, "SIDE_EFFECT_OPERATIONS");
    const outcomes = exactArray(record.operationOutcomes, EXPECTED_OPERATIONS.length, "SIDE_EFFECT_OUTCOMES");
    for (let operationIndex = 0; operationIndex < outcomes.length; operationIndex += 1) {
      const outcome = exactKeys(outcomes[operationIndex], ["operation", "outcome"], "SIDE_EFFECT_OUTCOME_FIELDS");
      exactString(outcome.operation, EXPECTED_OPERATIONS[operationIndex], "SIDE_EFFECT_OUTCOME_OPERATION");
      exactString(outcome.outcome, "COMPLETED", "SIDE_EFFECT_OUTCOME");
    }
    safeInteger(record.scannedFileCount, "SIDE_EFFECT_SCANNED_FILES", { positive: true });
    exactArray(record.forbiddenOperationMatches, 0, "SIDE_EFFECT_OPERATION_MATCH");
    exactArray(record.forbiddenArtifactMatches, 0, "SIDE_EFFECT_ARTIFACT_MATCH");
    exactString(record.recourseState, "NOT_OPEN", "SIDE_EFFECT_RECOURSE_STATE");
    if (record.cureDeadline !== null) fail("SIDE_EFFECT_CURE", "cure deadline must be absent");
    exactBoolean(record.recourseRecordPresent, false, "SIDE_EFFECT_RECOURSE_RECORD");
    exactBoolean(record.publicEvidencePresent, false, "SIDE_EFFECT_PUBLIC_EVIDENCE");
    exactBoolean(record.pairCaseRootCleanupPerformed, true, "SIDE_EFFECT_PAIR_CLEANUP");
    exactString(record.cleanupMethod, "ORDINARY_RECURSIVE_UNLINK_AFTER_LEAF_CAPTURE", "SIDE_EFFECT_CLEANUP_METHOD");
    if (pairs[index].leaf.execution.terminalStage !== record.terminalStage
      || pairs[index].leaf.inspection.recoursePresent !== record.recourseRecordPresent
      || pairs[index].leaf.inspection.publicEvidencePresent !== record.publicEvidencePresent) {
      fail("SIDE_EFFECT_GRAPH_BINDING", "side-effect scan and pair leaf disagree");
    }
  }
  exactBoolean(scan.allPairsReleased, true, "SIDE_EFFECT_ALL_RELEASED");
  exactBoolean(scan.allForbiddenMatchesAbsent, true, "SIDE_EFFECT_ALL_ABSENT");
}

function verifyRetention(retention, aggregate, graphSessionId) {
  const record = exactKeys(retention, [
    "declaration",
    "productionModel",
    "operatorCleanupPerformed",
    "cleanupMethod",
    "cleanupSecureErasureClaimed",
    "pairCaseRootsRemoved",
    "temporaryRootClassesRemoved",
    "allTemporaryRootsRemoved",
  ], "RETENTION_FIELDS");
  const declaration = exactKeys(record.declaration, ["schemaVersion", "sessionId", "privateExactClaimOpenings"], "RETENTION_DECLARATION_FIELDS");
  exactString(declaration.schemaVersion, "mordant.receivable-conflict-retention/1", "RETENTION_SCHEMA");
  exactString(declaration.sessionId, graphSessionId, "RETENTION_SESSION");
  const privateOpenings = exactKeys(declaration.privateExactClaimOpenings, [
    "record",
    "retainedFields",
    "authorizationPrivateKey",
    "authorizationPrivateKeyLifetime",
    "authorizationPrivateKeyZeroizationClaimed",
    "authorizationPrivateKeyGarbageCollectionTimingClaimed",
    "location",
    "disposition",
    "automaticCleanup",
    "operatorCleanupRequired",
    "secureErasureClaim",
  ], "RETENTION_PRIVATE_FIELDS");
  exactString(privateOpenings.record, "private-claim-record.json", "RETENTION_RECORD");
  assertSameArray(privateOpenings.retainedFields, ["activeFrom", "activeUntil", "salt"], "RETENTION_RETAINED_FIELDS");
  exactString(privateOpenings.authorizationPrivateKey, "NOT_PERSISTED", "RETENTION_PRIVATE_KEY");
  exactString(
    privateOpenings.authorizationPrivateKeyLifetime,
    "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
    "RETENTION_PRIVATE_KEY_LIFETIME",
  );
  exactBoolean(
    privateOpenings.authorizationPrivateKeyZeroizationClaimed,
    false,
    "RETENTION_PRIVATE_KEY_ZEROIZATION",
  );
  exactBoolean(
    privateOpenings.authorizationPrivateKeyGarbageCollectionTimingClaimed,
    false,
    "RETENTION_PRIVATE_KEY_GC_TIMING",
  );
  exactString(privateOpenings.location, "PRIVATE_ROOT_ONLY", "RETENTION_LOCATION");
  exactString(privateOpenings.disposition, "PERSIST_UNTIL_EXPLICIT_OPERATOR_CLEANUP", "RETENTION_DISPOSITION");
  exactBoolean(privateOpenings.automaticCleanup, false, "RETENTION_AUTOMATIC_CLEANUP");
  exactBoolean(privateOpenings.operatorCleanupRequired, true, "RETENTION_OPERATOR_CLEANUP");
  exactBoolean(privateOpenings.secureErasureClaim, false, "RETENTION_SECURE_ERASURE");

  const production = exactKeys(record.productionModel, [
    "exactIntervalsAndSaltsPersistPrivateUntilExplicitOperatorCleanup",
    "authorizationPrivateKeyPersisted",
    "authorizationPrivateKeyLifetime",
    "authorizationPrivateKeyZeroizationClaimed",
    "authorizationPrivateKeyGarbageCollectionTimingClaimed",
    "automaticTerminalCleanup",
    "secureErasureClaimed",
    "deletionTrigger",
    "publicEvidenceContainsOpenings",
  ], "RETENTION_PRODUCTION_FIELDS");
  exactBoolean(production.exactIntervalsAndSaltsPersistPrivateUntilExplicitOperatorCleanup, true, "RETENTION_EXACT_OPENINGS");
  exactBoolean(production.authorizationPrivateKeyPersisted, false, "RETENTION_PRODUCTION_PRIVATE_KEY");
  exactString(
    production.authorizationPrivateKeyLifetime,
    "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
    "RETENTION_PRODUCTION_PRIVATE_KEY_LIFETIME",
  );
  exactBoolean(
    production.authorizationPrivateKeyZeroizationClaimed,
    false,
    "RETENTION_PRODUCTION_PRIVATE_KEY_ZEROIZATION",
  );
  exactBoolean(
    production.authorizationPrivateKeyGarbageCollectionTimingClaimed,
    false,
    "RETENTION_PRODUCTION_PRIVATE_KEY_GC_TIMING",
  );
  exactBoolean(production.automaticTerminalCleanup, false, "RETENTION_TERMINAL_CLEANUP");
  exactBoolean(production.secureErasureClaimed, false, "RETENTION_PRODUCTION_ERASURE");
  exactString(production.deletionTrigger, "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY", "RETENTION_DELETION_TRIGGER");
  exactBoolean(production.publicEvidenceContainsOpenings, false, "RETENTION_PUBLIC_OPENINGS");
  if (!aggregate.retention.exactIntervalsRetained || !aggregate.retention.saltRetained
    || aggregate.retention.authorizationPrivateKeyRetained
    || aggregate.retention.authorizationPrivateKeyLifetime
      !== "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED"
    || aggregate.retention.authorizationPrivateKeyZeroizationClaimed
    || aggregate.retention.authorizationPrivateKeyGarbageCollectionTimingClaimed
    || aggregate.retention.automaticTerminalDeletion || aggregate.retention.secureErasureClaimed
    || aggregate.retention.publicEvidenceContainsOpenings
    || aggregate.retention.deletionTrigger !== production.deletionTrigger) {
    fail("RETENTION_AGGREGATE_BINDING", "aggregate and explicit retention model disagree");
  }
  exactBoolean(record.operatorCleanupPerformed, true, "RETENTION_CLEANUP_PERFORMED");
  exactString(record.cleanupMethod, "ORDINARY_UNLINK_AFTER_EVIDENCE_CAPTURE", "RETENTION_CLEANUP_METHOD");
  exactBoolean(record.cleanupSecureErasureClaimed, false, "RETENTION_CLEANUP_ERASURE");
  if (record.pairCaseRootsRemoved !== 3) fail("RETENTION_PAIR_ROOTS", "exactly three pair roots must be removed");
  assertSameArray(record.temporaryRootClassesRemoved, EXPECTED_TEMPORARY_ROOT_CLASSES, "RETENTION_TEMPORARY_ROOTS");
  exactBoolean(record.allTemporaryRootsRemoved, true, "RETENTION_ALL_ROOTS_REMOVED");
}

function verifyAssertions(assertions) {
  const records = exactArray(assertions, EXPECTED_ASSERTION_IDS.length, "ASSERTIONS");
  for (let index = 0; index < records.length; index += 1) {
    const record = exactKeys(records[index], ["id", "description", "pass", "evidence"], "ASSERTION_FIELDS");
    exactString(record.id, EXPECTED_ASSERTION_IDS[index], "ASSERTION_ID");
    if (typeof record.description !== "string" || record.description.trim().length < 8) {
      fail("ASSERTION_DESCRIPTION", "meaningful assertion description required");
    }
    exactBoolean(record.pass, true, "ASSERTION_PASS");
    if (Object.keys(plainObject(record.evidence, "ASSERTION_EVIDENCE")).length === 0) {
      fail("ASSERTION_EVIDENCE", "assertion evidence object cannot be empty");
    }
  }
}

function verifyClaimBoundary(supportedClaims, unsupportedClaims) {
  assertSameArray(supportedClaims, N3_SUPPORTED_CLAIMS, "SUPPORTED_CLAIMS");
  assertSameArray(unsupportedClaims, N3_UNSUPPORTED_CLAIMS, "UNSUPPORTED_CLAIMS");
}

function readEvidence(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > (32 << 20)) {
    fail("EVIDENCE_FILE", "retained evidence must be a bounded regular file");
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail("EVIDENCE_JSON", "retained evidence is not valid JSON");
  }
}

export async function validateN3PrivateConflictGraphEvidence(options = {}) {
  const root = options.root === undefined ? ROOT : resolve(options.root);
  const artifactPath = options.artifactPath === undefined
    ? join(root, N3_EVIDENCE_RELATIVE_PATH)
    : resolve(options.artifactPath);
  const evidence = options.evidence === undefined ? readEvidence(artifactPath) : options.evidence;
  const envelope = exactKeys(evidence, [
    "schemaVersion",
    "evidenceDigestDomain",
    "verdict",
    "generatedAt",
    "source",
    "nativeBuild",
    "graph",
    "execution",
    "sideEffectScan",
    "retention",
    "assertions",
    "supportedClaims",
    "unsupportedClaims",
    "evidenceDigest",
  ], "EVIDENCE_FIELDS");
  exactString(envelope.schemaVersion, N3_EVIDENCE_SCHEMA, "EVIDENCE_SCHEMA");
  exactString(envelope.evidenceDigestDomain, N3_EVIDENCE_DIGEST_DOMAIN, "EVIDENCE_DIGEST_DOMAIN");
  exactString(envelope.verdict, N3_EVIDENCE_VERDICT, "EVIDENCE_VERDICT");
  const generatedAt = canonicalIso(envelope.generatedAt, "EVIDENCE_GENERATED_AT");
  sha256Digest(envelope.evidenceDigest, "EVIDENCE_DIGEST_FORMAT");
  const core = await loadGraphCore(root);
  const expectedDigest = core.graphDigest(N3_EVIDENCE_DIGEST_DOMAIN, evidenceBody(envelope));
  if (envelope.evidenceDigest !== expectedDigest) fail("EVIDENCE_DIGEST", "canonical evidence body digest mismatch");
  assertSanitizedEvidence(envelope);

  verifyClaimBoundary(envelope.supportedClaims, envelope.unsupportedClaims);
  const graph = verifyGraph(envelope.graph, core);
  verifyExecution(envelope.execution, graph.aggregate);
  verifySideEffects(envelope.sideEffectScan, graph.pairs);
  verifyRetention(envelope.retention, graph.aggregate, graph.aggregate.graphSessionId);
  verifyAssertions(envelope.assertions);
  await verifySource(envelope.source, root, core);
  if (envelope.source.startingCommit !== graph.aggregate.pins.startingCommit
    || envelope.source.executionCommit !== graph.aggregate.pins.executionSourceCommit
    || envelope.source.executionTree !== graph.aggregate.pins.executionSourceTree) {
    fail("SOURCE_GRAPH_PIN", "source envelope and graph pins disagree");
  }
  const native = verifyNativeBuild(envelope.nativeBuild, envelope.source, graph.aggregate.pins);
  if (native.completed > graph.firstStarted) {
    fail("EVIDENCE_EXECUTION_TIME", "pair execution predates completion of the fresh native build");
  }
  if (graph.lastCompleted > generatedAt || native.completed > generatedAt) {
    fail("EVIDENCE_GENERATION_TIME", "evidence predates its fresh native build or pair execution");
  }
  for (const pair of graph.pairs) {
    if (pair.leaf.evaluatorProvenance !== graph.aggregate.pins.nativeBinaries.evaluator
      || pair.leaf.governedResult.sourceProvenance !== graph.aggregate.pins.nativeBinaries.decryptor
      || pair.leaf.inspection.inspectBinaryDigest !== graph.aggregate.pins.nativeBinaries.inspect) {
      fail("NATIVE_LEAF_PIN", "pair evidence does not bind the fresh evaluator/decryptor/inspect binaries");
    }
  }
  return Object.freeze({
    schemaVersion: envelope.schemaVersion,
    evidenceDigest: envelope.evidenceDigest,
    aggregateRoot: graph.aggregate.aggregateRoot,
    verdict: envelope.verdict,
  });
}

function commandArtifactPath(argv) {
  if (argv.length === 0) return join(ROOT, N3_EVIDENCE_RELATIVE_PATH);
  if (argv.length === 2 && argv[0] === "--artifact" && typeof argv[1] === "string" && argv[1].length > 0) {
    return resolve(argv[1]);
  }
  fail("ARGUMENTS", "usage: validate-n3-private-conflict-graph-evidence.mjs [--artifact <path>]");
}

async function main() {
  const artifactPath = commandArtifactPath(process.argv.slice(2));
  const result = await validateN3PrivateConflictGraphEvidence({ artifactPath });
  process.stdout.write(`${result.verdict}\n`);
}

const invokedPath = process.argv[1] === undefined ? null : resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : "unknown validation failure";
    process.stderr.write(`validate-n3-private-conflict-graph-evidence: ${message}\n`);
    process.exitCode = 1;
  });
}
