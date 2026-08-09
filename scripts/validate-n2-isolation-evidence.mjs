#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_ROOT = dirname(fileURLToPath(import.meta.url));
export const EVIDENCE_PATH = resolve(
  SCRIPT_ROOT,
  "..",
  "docs",
  "evidence",
  "n2-isolated-execution-proof-2026-08-08.json",
);
export const SCHEMA_VERSION = "mordant.n2-isolated-execution-evidence/2";
export const EXACT_CLAIM = "Multiple isolated execution slots can run concurrently.";
export const PASS_VERDICT = "PASS — N=2 ISOLATED EXECUTION PROVEN WITH EXISTING WORKERS";

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BINARY_DEFINITIONS = Object.freeze([
  "keygen",
  "client",
  "evaluator",
  "decryptor",
  "recourse",
  "inspect",
  "retain",
].map((shortName) => ({
  shortName,
  name: `mordant-fhe-${shortName}`,
  package: `./cmd/mordant-fhe-${shortName}`,
})));
const REQUIRED_OPERATIONS = Object.freeze([
  "preparePrivateMatch",
  "submitParticipantA",
  "submitParticipantB",
  "finalizeParticipantSubmissions",
  "evaluatePrivateConflict",
  "releaseGovernedResult",
  "openRecourseCase",
  "exportProtectionEvidence",
]);
const REQUIRED_ASSERTIONS = Object.freeze([
  "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
  "native-evaluator-concurrency",
  "source-build-link",
  "process-model",
  "retained-evidence-sanitation",
]);

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function digestEvidenceBody(body) {
  return `sha256:${createHash("sha256")
    .update(`MORDANT_N2_ISOLATION_EVIDENCE_V2\n${canonicalJson(body)}`)
    .digest("hex")}`;
}

function sanitationViolations(value, path = "$") {
  const violations = [];
  const forbiddenKeys = /^(?:activeFrom|activeUntil|launchToken|tokenSecret|hmacSecret|privateKey|decryptorPrivate|participantPrivate|binaryRoot|durableRoot|journalPath|receiptPath|executionPath|pid|port)$/iu;
  const visit = (current, currentPath) => {
    if (typeof current === "string" && /^(?:\/|[A-Za-z]:[\\/])/u.test(current)) {
      violations.push(`${currentPath}: absolute path`);
    }
    if (Array.isArray(current)) {
      current.forEach((entry, index) => visit(entry, `${currentPath}[${index}]`));
      return;
    }
    if (current !== null && typeof current === "object") {
      for (const [key, entry] of Object.entries(current)) {
        if (forbiddenKeys.test(key)) violations.push(`${currentPath}.${key}: forbidden key`);
        if (key === "evaluationOverlapMs") violations.push(`${currentPath}.${key}: legacy metric name`);
        visit(entry, `${currentPath}.${key}`);
      }
    }
  };
  visit(value, path);
  return violations;
}

function isTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function assertionMap(evidence) {
  return new Map(Array.isArray(evidence.assertions)
    ? evidence.assertions.map((assertion) => [assertion?.id, assertion])
    : []);
}

export function validateN2IsolationEvidence(evidence) {
  const errors = [];
  const check = (condition, message) => {
    if (!condition) errors.push(message);
  };
  check(evidence !== null && typeof evidence === "object" && !Array.isArray(evidence), "evidence must be an object");
  if (errors.length > 0) return errors;

  const { evidenceDigest, ...body } = evidence;
  check(evidence.schemaVersion === SCHEMA_VERSION, `schemaVersion must be ${SCHEMA_VERSION}`);
  check(evidence.verdict === PASS_VERDICT, "verdict must be the exact PASS verdict");
  check(evidence.exactClaimSupported === EXACT_CLAIM, "exact supported claim changed or is absent");
  check(SHA256.test(evidenceDigest), "evidenceDigest must be a SHA-256 digest");
  check(evidenceDigest === digestEvidenceBody(body), "evidenceDigest does not match the canonical evidence body");

  const source = evidence.auditedSource ?? {};
  check(source.repository === "RedGnad/Mordant", "audited repository is not pinned");
  check(COMMIT.test(source.baseCommit), "base commit must be a full lowercase SHA");
  check(COMMIT.test(source.commit), "audited commit must be a full lowercase SHA");
  check(COMMIT.test(source.tree), "audited tree must be a full lowercase SHA");
  check(source.trackedCheckoutClean === true, "audited checkout was not recorded clean");
  check(source.workerEntrypoint === "scripts/mordant-live-worker.mjs", "unexpected worker entrypoint");
  check(source.compiledEngine === ".product-test-dist/src/lib/protection/governed-fhe-product-server.js", "unexpected compiled engine");
  check(SHA256.test(source.workerEntrypointDigest), "worker entrypoint digest is invalid");
  check(SHA256.test(source.compiledEngineDigest), "compiled engine digest is invalid");

  const build = evidence.nativeBuild ?? {};
  check(build.proofGrade === true, "native build is not marked proof-grade");
  check(build.builtDuringProof === true, "native binaries were not built during the proof");
  check(build.prepopulatedBinaryRootAccepted === false, "prepopulated binary roots must be rejected");
  check(build.auditedSourceCommit === source.commit, "native build commit does not match audited commit");
  check(build.auditedSourceTree === source.tree, "native build tree does not match audited tree");
  check(build.sourceRoot === "fhe-lab/lattigo", "unexpected native source root");
  check(build.outputRootId === "proof-native-binaries", "native output must use the portable proof root ID");
  check(isTimestamp(build.buildStartedAt) && isTimestamp(build.buildCompletedAt), "native build timestamps are invalid");
  check(Date.parse(build.buildCompletedAt) >= Date.parse(build.buildStartedAt), "native build time ordering is invalid");
  check(typeof build.goVersion === "string" && /^go\d/u.test(build.goVersion), "Go version is missing");
  check(build.mode?.command === "go build", "native build command is not go build");
  check(build.mode?.moduleMode === "readonly", "native build did not use readonly module mode");
  check(build.mode?.trimpath === true, "native build did not use trimpath");
  check(build.mode?.cgoEnabled === false, "native build did not disable CGO");
  check(["darwin", "linux"].includes(build.mode?.goos), "native build GOOS is invalid");
  check(["arm64", "amd64"].includes(build.mode?.goarch), "native build GOARCH is invalid");
  check(Array.isArray(build.binaries) && build.binaries.length === 7, "native build must contain all seven binaries");
  const binaryMap = new Map(Array.isArray(build.binaries)
    ? build.binaries.map((binary) => [binary?.name, binary])
    : []);
  for (const expected of BINARY_DEFINITIONS) {
    const binary = binaryMap.get(expected.name);
    check(binary?.package === expected.package, `${expected.name} package is missing or changed`);
    check(SHA256.test(binary?.sha256), `${expected.name} digest is invalid`);
    check(Number.isSafeInteger(binary?.bytes) && binary.bytes > 0, `${expected.name} byte count is invalid`);
    check(isTimestamp(binary?.startedAt) && isTimestamp(binary?.completedAt), `${expected.name} timestamps are invalid`);
  }

  const model = evidence.processModel ?? {};
  check(model.workerCount === 2, "process model must contain exactly two workers");
  check(model.workerRuntime === "node", "unexpected worker runtime");
  check(model.workerEntrypoint === source.workerEntrypoint, "process model worker does not match audited source");
  check(model.compiledEngine === source.compiledEngine, "process model engine does not match audited source");
  check(model.intakeProfile === "MANAGED_COMBINED_INTAKE", "managed combined-intake profile is required");
  check(model.maxActiveCasesPerWorker === 1, "one-active-case invariant changed");
  check(model.separatePorts === true && model.separateDurableRoots === true, "ports and durable roots must be separate");
  check(model.sharedFreshNativeBinaryManifest === true, "workers did not share the fresh native manifest");

  const concurrency = evidence.concurrency ?? {};
  check(Number.isFinite(concurrency.acceptanceStartSkewMs) && concurrency.acceptanceStartSkewMs >= 0,
    "acceptance start skew is invalid");
  check(Number.isFinite(concurrency.executionOverlapMs)
    && concurrency.executionOverlapMs >= concurrency.minimumMaterialExecutionOverlapMs
    && concurrency.minimumMaterialExecutionOverlapMs >= 1_000,
  "material execution overlap is not established");
  check(Number.isFinite(concurrency.evaluationOperationOverlapMs)
    && concurrency.evaluationOperationOverlapMs > 0,
  "evaluation operation overlap is not established");
  check(typeof concurrency.evaluationOperationMetric === "string"
    && concurrency.evaluationOperationMetric.includes("operation-journal intervals")
    && concurrency.evaluationOperationMetric.includes("not represented as")
    && concurrency.evaluationOperationMetric.includes("native process-runtime duration"),
  "evaluation operation metric is not bounded honestly");
  check(isTimestamp(concurrency.bothWorkersBusyObservedAt), "simultaneous BUSY observation is missing");
  check(concurrency.processSamplingAvailable === true, "native process sampling was unavailable");
  const native = concurrency.nativeEvaluatorsSimultaneous ?? {};
  check(native.observed === true, "simultaneous native evaluators were not observed");
  check(isTimestamp(native.observedAt), "native evaluator observation timestamp is missing");
  check(Number.isInteger(native.processCount) && native.processCount >= 2, "native evaluator process count is invalid");
  check(JSON.stringify(native.slots) === JSON.stringify(["A", "B"]), "native evaluator observation must cover slots A and B");
  check(native.binaryName === "mordant-fhe-evaluator", "native evaluator binary identity changed");

  check(Array.isArray(evidence.slots) && evidence.slots.length === 2, "exactly two slot records are required");
  const slots = new Map(Array.isArray(evidence.slots) ? evidence.slots.map((slot) => [slot?.label, slot]) : []);
  const slotA = slots.get("A") ?? {};
  const slotB = slots.get("B") ?? {};
  check(slotA.submittedCase === "overlapping", "slot A must use the overlapping case");
  check(slotB.submittedCase === "separated", "slot B must use the separated case");
  for (const [label, slot] of [["A", slotA], ["B", slotB]]) {
    const lower = label.toLowerCase();
    check(slot.process?.workerId === `slot-${lower}-worker`, `slot ${label} worker ID is invalid`);
    check(slot.process?.portId === `slot-${lower}-port`, `slot ${label} port ID is invalid`);
    check(slot.process?.durableRootId === `slot-${lower}-root`, `slot ${label} durable root ID is invalid`);
    check(isTimestamp(slot.process?.startedAt) && isTimestamp(slot.process?.readyAt), `slot ${label} process timestamps are invalid`);
    check(slot.request?.status === 201, `slot ${label} was not independently accepted`);
    check(RUN_ID.test(slot.request?.runId), `slot ${label} run ID is invalid`);
    check(isTimestamp(slot.request?.startedAt) && isTimestamp(slot.request?.acceptedAt), `slot ${label} request timestamps are invalid`);
    check(isTimestamp(slot.timing?.executionStartedAt)
      && isTimestamp(slot.timing?.evaluationOperationStartedAt)
      && isTimestamp(slot.timing?.evaluationOperationTerminalAt)
      && isTimestamp(slot.timing?.terminalJournalAt)
      && isTimestamp(slot.timing?.terminalReceiptObservedAt), `slot ${label} execution timestamps are invalid`);
    check(Number.isFinite(slot.timing?.executionDurationMs) && slot.timing.executionDurationMs > 0,
      `slot ${label} execution duration is invalid`);
    check(SHA256.test(slot.outcome?.governedResultDigest), `slot ${label} governed result digest is invalid`);
    check(SHA256.test(slot.outcome?.receiptDigest), `slot ${label} receipt digest is invalid`);
    check(slot.artifacts?.evaluatedArtifact?.name === "evaluated-conflict.json", `slot ${label} evaluated artifact is missing`);
    check(slot.artifacts?.evaluatedArtifact?.artifactId === `${lower}-evaluated-conflict`, `slot ${label} artifact ID is invalid`);
    check(slot.artifacts?.evaluatedArtifact?.digest === slot.artifacts?.evaluatedArtifactDigest,
      `slot ${label} evaluated artifact digest does not match receipt provenance`);
    check(SHA256.test(slot.artifacts?.evaluatorProvenance)
      && slot.artifacts.evaluatorProvenance === binaryMap.get("mordant-fhe-evaluator")?.sha256,
    `slot ${label} evaluator provenance does not match the fresh build`);
    check(SHA256.test(slot.artifacts?.decryptorProvenance)
      && slot.artifacts.decryptorProvenance === binaryMap.get("mordant-fhe-decryptor")?.sha256,
    `slot ${label} decryptor provenance does not match the fresh build`);
    const completed = new Set(Array.isArray(slot.artifacts?.completedJournalOperations)
      ? slot.artifacts.completedJournalOperations
        .filter((operation) => ["COMPLETED", "RECONCILED"].includes(operation?.outcome))
        .map((operation) => operation.operation)
      : []);
    for (const operation of REQUIRED_OPERATIONS) {
      check(completed.has(operation), `slot ${label} did not complete ${operation}`);
    }
  }
  check(slotA.request?.runId !== slotB.request?.runId, "slot run IDs must differ");
  check(slotA.artifacts?.evaluatedArtifactDigest !== slotB.artifacts?.evaluatedArtifactDigest,
    "evaluated artifacts must be independent");
  check(slotA.outcome?.conflict === true
    && slotA.outcome?.incidentState === "CONFLICT_CONFIRMED"
    && slotA.outcome?.recourseOpened === true,
  "slot A governed conflict outcome is incorrect");
  check(slotB.outcome?.conflict === false
    && slotB.outcome?.incidentState === "CLEARED"
    && slotB.outcome?.recourseOpened === false
    && slotB.outcome?.recourseRefusal === "SIGNED_RESULT_FALSE",
  "slot B governed no-conflict outcome is incorrect");

  const isolation = evidence.isolation ?? {};
  for (const [name, read] of Object.entries(isolation.foreignReads ?? {})) {
    check(read?.status === 404 && read?.code === "UNKNOWN_CASE", `${name} must fail closed with 404/UNKNOWN_CASE`);
  }
  check(Object.keys(isolation.foreignReads ?? {}).length === 2, "both cross-worker reads are required");
  check(isolation.roots?.slotA?.rootId === "slot-a-root"
    && JSON.stringify(isolation.roots.slotA.runIds) === JSON.stringify([slotA.request?.runId])
    && isolation.roots.slotA.foreignRunMatches === 0, "slot A root is not isolated");
  check(isolation.roots?.slotB?.rootId === "slot-b-root"
    && JSON.stringify(isolation.roots.slotB.runIds) === JSON.stringify([slotB.request?.runId])
    && isolation.roots.slotB.foreignRunMatches === 0, "slot B root is not isolated");
  check(isolation.journals?.slotA?.journalId === "slot-a-journal"
    && isolation.journals.slotA.foreignRunReferenced === false, "slot A journal references foreign state");
  check(isolation.journals?.slotB?.journalId === "slot-b-journal"
    && isolation.journals.slotB.foreignRunReferenced === false, "slot B journal references foreign state");
  check(isolation.receipts?.slotA?.runId === slotA.request?.runId
    && isolation.receipts.slotA.receiptDigest === slotA.outcome?.receiptDigest
    && isTimestamp(isolation.receipts.slotA.observedAt), "slot A terminal receipt is invalid");
  check(isolation.receipts?.slotB?.runId === slotB.request?.runId
    && isolation.receipts.slotB.receiptDigest === slotB.outcome?.receiptDigest
    && isTimestamp(isolation.receipts.slotB.observedAt), "slot B terminal receipt is invalid");

  const assertions = assertionMap(evidence);
  for (const id of REQUIRED_ASSERTIONS) {
    check(assertions.get(id)?.pass === true, `required assertion ${id} is absent or failed`);
  }
  check(assertions.size === REQUIRED_ASSERTIONS.length, "unexpected assertion set");

  const unsupported = Array.isArray(evidence.claimsNotSupported) ? evidence.claimsNotSupported.join(" ").toLowerCase() : "";
  for (const boundary of [
    "routing or pooling", "linearly", "throughput", "n>2", "autoscaling", "load balancing",
    "high availability", "settlement scalability", "production-ready", "one worker slot",
  ]) {
    check(unsupported.includes(boundary), `unsupported-claim boundary is missing: ${boundary}`);
  }

  const sanitation = sanitationViolations(evidence);
  check(sanitation.length === 0, `retained evidence sanitation failed: ${sanitation.join("; ")}`);
  return errors;
}

export function readAndValidateEvidence(path = EVIDENCE_PATH) {
  const evidence = JSON.parse(readFileSync(path, "utf8"));
  return { evidence, errors: validateN2IsolationEvidence(evidence) };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const path = process.argv[2] === undefined ? EVIDENCE_PATH : resolve(process.argv[2]);
  try {
    const { evidence, errors } = readAndValidateEvidence(path);
    if (errors.length > 0) {
      errors.forEach((error) => process.stderr.write(`- ${error}\n`));
      process.exitCode = 1;
    } else {
      process.stdout.write(`Validated ${evidence.schemaVersion}: ${evidence.evidenceDigest}\n`);
    }
  } catch (error) {
    process.stderr.write(`Evidence validation failed: ${error?.message ?? "unknown error"}\n`);
    process.exitCode = 1;
  }
}
