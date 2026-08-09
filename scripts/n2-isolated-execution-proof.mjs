#!/usr/bin/env node
/**
 * Test-only N=2 execution-isolation proof.
 *
 * The harness builds every native executable from the audited checkout, then
 * launches exactly two authentic managed-intake workers. The workers share
 * immutable source and freshly built binaries, but have separate ports and
 * mkdtemp durable roots. It adds no dispatcher, pool, queue, adapter factory,
 * production replica, or change to the worker's one-active-case invariant.
 */

import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { promisify } from "node:util";

import { signLaunchToken } from "./mordant-live-worker.mjs";

const execFileAsync = promisify(execFile);
const SOURCE_ROOT = process.cwd();
const WORKER_SCRIPT = resolve(SOURCE_ROOT, "scripts", "mordant-live-worker.mjs");
const COMPILED_ENGINE = resolve(
  SOURCE_ROOT,
  ".product-test-dist",
  "src",
  "lib",
  "protection",
  "governed-fhe-product-server.js",
);
const EVIDENCE_PATH = resolve(
  SOURCE_ROOT,
  "docs",
  "evidence",
  "n2-isolated-execution-proof-2026-08-08.json",
);
const REPOSITORY = "RedGnad/Mordant";
const SCHEMA_VERSION = "mordant.n2-isolated-execution-evidence/2";
const ORIGIN = "https://n2-isolation-proof.example";
const AUDIENCE = "MORDANT_N2_ISOLATION_PROOF";
const TERMINAL_TIMEOUT_MS = Number(process.env.MORDANT_N2_TIMEOUT_MS ?? 15 * 60 * 1_000);
const POLL_MS = 100;
const MIN_MATERIAL_OVERLAP_MS = 1_000;
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

// These are private test inputs. Only the scenario classification is retained.
const WINDOWS = Object.freeze({
  A: {
    participantA: { activeFrom: 120, activeUntil: 420 },
    participantB: { activeFrom: 220, activeUntil: 520 },
  },
  B: {
    participantA: { activeFrom: 120, activeUntil: 220 },
    participantB: { activeFrom: 320, activeUntil: 420 },
  },
});

function iso(now = Date.now()) {
  return new Date(now).toISOString();
}

function delay(ms) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sha256File(path, stripFinalNewline = false) {
  let bytes = readFileSync(path);
  if (stripFinalNewline && bytes.at(-1) === 0x0a) bytes = bytes.subarray(0, bytes.length - 1);
  return sha256Bytes(bytes);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(value);
}

function evidenceDigest(body) {
  return sha256Bytes(Buffer.from(`MORDANT_N2_ISOLATION_EVIDENCE_V2\n${canonicalJson(body)}`, "utf8"));
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function directoryBytes(path) {
  if (!existsSync(path)) return 0;
  const stat = lstatSync(path);
  if (!stat.isDirectory()) return stat.size;
  return readdirSync(path).reduce((total, entry) => total + directoryBytes(join(path, entry)), 0);
}

function filesContaining(root, needle) {
  if (!existsSync(root)) return [];
  const matches = [];
  const visit = (path) => {
    const stat = lstatSync(path);
    if (stat.isDirectory()) {
      for (const entry of readdirSync(path)) visit(join(path, entry));
      return;
    }
    if (basename(path).includes(needle)) matches.push(path);
    if (path.endsWith(".json") && stat.size <= 16 * 1024 * 1024) {
      if (readFileSync(path, "utf8").includes(needle)) matches.push(path);
    }
  };
  visit(root);
  return [...new Set(matches)];
}

function runDirectories(root) {
  const runRoot = join(root, "runs");
  if (!existsSync(runRoot)) return [];
  return readdirSync(runRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^[0-9a-f-]{36}$/u.test(entry.name))
    .map((entry) => entry.name)
    .sort();
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
        visit(entry, `${currentPath}.${key}`);
      }
    }
  };
  visit(value, path);
  return violations;
}

async function git(...args) {
  const { stdout } = await execFileAsync("git", args, { cwd: SOURCE_ROOT });
  return stdout.trim();
}

async function reservePorts(count) {
  const servers = [];
  try {
    for (let index = 0; index < count; index += 1) {
      const server = createServer();
      servers.push(server);
      server.listen(0, "127.0.0.1");
      await new Promise((resolveListening, reject) => {
        server.once("listening", resolveListening);
        server.once("error", reject);
      });
    }
    return servers.map((server) => server.address().port);
  } finally {
    await Promise.all(servers.map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  }
}

async function hostBuildTarget() {
  const [{ stdout: kernel }, { stdout: machine }] = await Promise.all([
    execFileAsync("uname", ["-s"]),
    execFileAsync("uname", ["-m"]),
  ]);
  const os = kernel.trim().toLowerCase();
  const architecture = machine.trim().toLowerCase();
  const goos = os === "darwin" ? "darwin" : os === "linux" ? "linux" : null;
  const goarch = ["arm64", "aarch64"].includes(architecture)
    ? "arm64"
    : ["x86_64", "amd64"].includes(architecture) ? "amd64" : null;
  if (goos === null || goarch === null) {
    throw new Error(`Unsupported native proof build target: ${os}/${architecture}`);
  }
  return { goos, goarch, hostKernel: kernel.trim(), hostMachine: machine.trim() };
}

async function buildFreshBinaries(sourceCommit, sourceTree) {
  if (process.env.MORDANT_N2_BIN_ROOT !== undefined) {
    throw new Error("MORDANT_N2_BIN_ROOT is not accepted for proof-grade execution; binaries must be built fresh");
  }
  const buildStartedAt = iso();
  const goRoot = join(SOURCE_ROOT, "fhe-lab", "lattigo");
  const binRoot = mkdtempSync(join(tmpdir(), "mordant-n2-proof-binaries-"));
  const goCache = mkdtempSync(join(tmpdir(), "mordant-n2-proof-go-cache-"));
  const target = await hostBuildTarget();
  const [{ stdout: goVersion }, { stdout: goToolchain }] = await Promise.all([
    execFileAsync("go", ["env", "GOVERSION"], { cwd: goRoot }),
    execFileAsync("go", ["env", "GOTOOLCHAIN"], { cwd: goRoot }),
  ]);
  const builds = [];
  process.stdout.write("Building all seven native executables from the audited checkout.\n");
  for (const definition of BINARY_DEFINITIONS) {
    const outputPath = join(binRoot, definition.name);
    const startedAt = iso();
    await execFileAsync("go", [
      "build",
      "-mod=readonly",
      "-trimpath",
      "-o",
      outputPath,
      definition.package,
    ], {
      cwd: goRoot,
      env: {
        ...process.env,
        CGO_ENABLED: "0",
        GOCACHE: goCache,
        GOOS: target.goos,
        GOARCH: target.goarch,
      },
      maxBuffer: 8 << 20,
    });
    if (!existsSync(outputPath)) throw new Error(`Fresh native build did not produce ${definition.name}`);
    builds.push({
      name: definition.name,
      package: definition.package,
      startedAt,
      completedAt: iso(),
      bytes: statSync(outputPath).size,
      sha256: sha256File(outputPath),
    });
  }
  const hashes = Object.fromEntries(BINARY_DEFINITIONS.map((definition) => [
    definition.shortName,
    builds.find((build) => build.name === definition.name).sha256,
  ]));
  return {
    binRoot: realpathSync(binRoot),
    hashes,
    retained: {
      proofGrade: true,
      builtDuringProof: true,
      prepopulatedBinaryRootAccepted: false,
      auditedSourceCommit: sourceCommit,
      auditedSourceTree: sourceTree,
      sourceRoot: "fhe-lab/lattigo",
      outputRootId: "proof-native-binaries",
      buildStartedAt,
      buildCompletedAt: iso(),
      goVersion: goVersion.trim(),
      goToolchain: goToolchain.trim(),
      host: target,
      mode: {
        command: "go build",
        moduleMode: "readonly",
        trimpath: true,
        cgoEnabled: false,
        goos: target.goos,
        goarch: target.goarch,
      },
      binaries: builds,
    },
  };
}

function createSlot(label, scenario, port, root, sourceCommit, binaries) {
  return {
    label,
    scenario,
    workerId: `slot-${label.toLowerCase()}-worker`,
    portId: `slot-${label.toLowerCase()}-port`,
    rootId: `slot-${label.toLowerCase()}-root`,
    journalId: `slot-${label.toLowerCase()}-journal`,
    port,
    root: realpathSync(root),
    sourceCommit,
    binaries,
    tokenSecret: randomBytes(32).toString("hex"),
    process: null,
    pid: null,
    processStartedAt: null,
    readyAt: null,
    requestStartedAt: null,
    acceptedAt: null,
    acceptanceStatus: null,
    runId: null,
    timeline: [],
    terminalObservedAt: null,
    terminalView: null,
    evaluatedArtifactObservation: null,
    peakRootBytes: 0,
    finalRootBytes: 0,
    maxWorkerRssBytes: null,
    maxNativeChildRssBytes: null,
    stdout: [],
    stderr: [],
  };
}

function retainLines(target, chunk) {
  const lines = String(chunk).split("\n").map((line) => line.trim()).filter(Boolean);
  target.push(...lines);
  if (target.length > 80) target.splice(0, target.length - 80);
}

function startSlot(slot) {
  const environment = {
    ...process.env,
    NODE_ENV: "production",
    NODE_PATH: join(SOURCE_ROOT, "test", "stubs"),
    PORT: String(slot.port),
    MORDANT_WORKER_DATA_ROOT: slot.root,
    MORDANT_WORKER_TOKEN_SECRET: slot.tokenSecret,
    MORDANT_WORKER_TOKEN_AUDIENCE: AUDIENCE,
    MORDANT_WORKER_ALLOWED_ORIGIN: ORIGIN,
    MORDANT_WORKER_MAX_ACTIVE_CASES: "1",
    MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION: "disabled",
    MORDANT_PROTECTION_SOURCE_COMMIT: slot.sourceCommit,
    MORDANT_GOVERNED_FHE_BIN_DIR: slot.binaries.binRoot,
    // Managed intake never invokes the participant eligibility reader. This
    // local URL lets the existing worker construct that dormant dependency.
    MORDANT_MONAD_RPC_URL: "http://127.0.0.1:1",
  };
  slot.processStartedAt = iso();
  slot.process = spawn(process.execPath, [WORKER_SCRIPT], {
    cwd: SOURCE_ROOT,
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  slot.pid = slot.process.pid;
  slot.process.stdout.on("data", (chunk) => retainLines(slot.stdout, chunk));
  slot.process.stderr.on("data", (chunk) => retainLines(slot.stderr, chunk));
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  let body = null;
  try { body = await response.json(); } catch { /* status is still evidence */ }
  return { response, body };
}

async function waitReady(slot) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (slot.process.exitCode !== null) {
      throw new Error(`Worker ${slot.label} exited before READY: ${slot.stderr.join(" | ")}`);
    }
    try {
      const { response, body } = await fetchJson(`http://127.0.0.1:${slot.port}/health`);
      if (response.status === 200 && body?.status === "READY" && body?.worker === "IDLE") {
        slot.readyAt = iso();
        slot.readyHealth = body;
        return;
      }
    } catch { /* socket is not listening yet */ }
    await delay(100);
  }
  throw new Error(`Worker ${slot.label} did not become READY`);
}

function launchToken(slot) {
  const now = Date.now();
  return signLaunchToken({
    tokenId: randomUUID(),
    issuedAt: now,
    expiresAt: now + 60_000,
    audience: AUDIENCE,
    action: "CREATE_CUSTOM_CASE",
  }, slot.tokenSecret);
}

async function admit(slot) {
  slot.requestStartedAt = iso();
  const { response, body } = await fetchJson(`http://127.0.0.1:${slot.port}/v1/custom-cases`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${launchToken(slot)}`,
      "content-type": "application/json",
      origin: ORIGIN,
    },
    body: JSON.stringify(WINDOWS[slot.label]),
  });
  slot.acceptedAt = iso();
  slot.acceptanceStatus = response.status;
  slot.runId = body?.view?.runId ?? null;
  if (body?.view?.stage) slot.timeline.push({ observedAt: slot.acceptedAt, stage: body.view.stage });
  if (response.status !== 201 || typeof slot.runId !== "string") {
    throw new Error(`Worker ${slot.label} admission failed (${response.status}): ${JSON.stringify(body)}`);
  }
}

function observeEvaluatedArtifact(slot) {
  if (slot.evaluatedArtifactObservation !== null || slot.runId === null) return;
  const path = join(slot.root, "runs", slot.runId, "public", "evaluated-conflict.json");
  if (!existsSync(path)) return;
  const stat = statSync(path);
  slot.evaluatedArtifactObservation = {
    observedAt: iso(),
    path,
    bytes: stat.size,
    digest: sha256File(path, true),
  };
}

async function processSnapshot(slots, concurrency) {
  try {
    const { stdout } = await execFileAsync("ps", ["-axo", "pid=,ppid=,rss=,command="], { maxBuffer: 8 << 20 });
    const processes = stdout.split("\n").map((line) => {
      const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/u);
      return match === null ? null : {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        rssBytes: Number(match[3]) * 1024,
        command: match[4],
      };
    }).filter(Boolean);
    const evaluators = [];
    for (const slot of slots) {
      const worker = processes.find((entry) => entry.pid === slot.pid);
      if (worker !== undefined) {
        slot.maxWorkerRssBytes = Math.max(slot.maxWorkerRssBytes ?? 0, worker.rssBytes);
      }
      const children = processes.filter((entry) => entry.ppid === slot.pid);
      for (const child of children) {
        slot.maxNativeChildRssBytes = Math.max(slot.maxNativeChildRssBytes ?? 0, child.rssBytes);
        if (child.command.includes(join(slot.binaries.binRoot, "mordant-fhe-evaluator"))) {
          evaluators.push({ slot: slot.label, pid: child.pid, rssBytes: child.rssBytes });
        }
      }
    }
    if (
      concurrency.nativeEvaluatorsSimultaneous === null
      && evaluators.some((entry) => entry.slot === "A")
      && evaluators.some((entry) => entry.slot === "B")
    ) {
      concurrency.nativeEvaluatorsSimultaneous = {
        observedAt: iso(),
        processes: evaluators.filter((entry) => ["A", "B"].includes(entry.slot)),
      };
    }
  } catch {
    concurrency.processSamplingAvailable = false;
  }
}

async function observeUntilTerminal(slots, concurrency) {
  const deadline = Date.now() + TERMINAL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const observedAt = iso();
    const statuses = await Promise.all(slots.map(async (slot) => {
      try {
        return await fetchJson(`http://127.0.0.1:${slot.port}/v1/custom-cases/${slot.runId}`);
      } catch {
        return { response: null, body: null };
      }
    }));
    const health = await Promise.all(slots.map(async (slot) => {
      try { return await fetchJson(`http://127.0.0.1:${slot.port}/health`); } catch { return { body: null }; }
    }));
    if (
      concurrency.bothWorkersBusyObservedAt === null
      && health.every((sample) => sample.body?.worker === "BUSY")
    ) concurrency.bothWorkersBusyObservedAt = observedAt;

    for (let index = 0; index < slots.length; index += 1) {
      const slot = slots[index];
      const view = statuses[index].body?.view;
      if (view?.stage && slot.timeline.at(-1)?.stage !== view.stage) {
        slot.timeline.push({ observedAt, stage: view.stage });
        process.stdout.write(`[${slot.label}] ${view.stage}\n`);
      }
      if (view?.stage === "COMPLETE" && view.receipt !== null && slot.terminalView === null) {
        slot.terminalObservedAt = observedAt;
        slot.terminalView = view;
      }
      observeEvaluatedArtifact(slot);
      slot.peakRootBytes = Math.max(slot.peakRootBytes, directoryBytes(slot.root));
    }
    await processSnapshot(slots, concurrency);
    if (slots.every((slot) => slot.terminalView !== null)) return;
    await delay(POLL_MS);
  }
  throw new Error(`N=2 proof exceeded ${TERMINAL_TIMEOUT_MS} ms`);
}

function completedOperation(journal, name) {
  return journal.records.find((record) => record.operation === name
    && ["COMPLETED", "RECONCILED"].includes(record.outcome));
}

function intervalOverlapMs(first, second) {
  const start = Math.max(Date.parse(first.start), Date.parse(second.start));
  const end = Math.min(Date.parse(first.end), Date.parse(second.end));
  return Math.max(0, end - start);
}

function collectSlotEvidence(slot) {
  const runRoot = join(slot.root, "runs", slot.runId);
  const journalPath = join(runRoot, "operation-journal.json");
  const receiptPath = join(runRoot, "custom-supervised-receipt.json");
  const executionPath = join(runRoot, "execution.json");
  const journal = readJson(journalPath);
  const receipt = readJson(receiptPath);
  const execution = readJson(executionPath);
  const evaluation = completedOperation(journal, "evaluatePrivateConflict");
  const release = completedOperation(journal, "releaseGovernedResult");
  const first = journal.records[0];
  const last = journal.records.at(-1);
  slot.finalRootBytes = directoryBytes(slot.root);
  return {
    journalPath,
    receiptPath,
    executionPath,
    journal,
    receipt,
    execution,
    evaluation,
    release,
    interval: { start: first?.createdAt, end: last?.terminalAt },
  };
}

async function foreignRead(slot, foreignRunId) {
  const { response, body } = await fetchJson(
    `http://127.0.0.1:${slot.port}/v1/custom-cases/${foreignRunId}`,
  );
  return { status: response.status, code: body?.code ?? null };
}

async function stopSlot(slot) {
  if (slot.process === null || slot.process.exitCode !== null) return;
  slot.process.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveExit) => slot.process.once("exit", resolveExit)),
    delay(5_000),
  ]);
  if (slot.process.exitCode === null) slot.process.kill("SIGKILL");
}

function retainedSlot(slot, evidence) {
  const receipt = evidence.receipt;
  const evaluation = evidence.evaluation;
  const release = evidence.release;
  return {
    label: slot.label,
    submittedCase: slot.scenario,
    process: {
      workerId: slot.workerId,
      portId: slot.portId,
      durableRootId: slot.rootId,
      startedAt: slot.processStartedAt,
      readyAt: slot.readyAt,
    },
    request: {
      startedAt: slot.requestStartedAt,
      acceptedAt: slot.acceptedAt,
      status: slot.acceptanceStatus,
      runId: slot.runId,
    },
    timing: {
      executionStartedAt: evidence.interval.start,
      evaluationOperationStartedAt: evaluation?.createdAt ?? null,
      evaluationOperationTerminalAt: evaluation?.terminalAt ?? null,
      releaseStartedAt: release?.createdAt ?? null,
      releaseTerminalAt: release?.terminalAt ?? null,
      terminalJournalAt: evidence.interval.end,
      terminalReceiptObservedAt: slot.terminalObservedAt,
      executionDurationMs: Date.parse(evidence.interval.end) - Date.parse(evidence.interval.start),
      timeline: slot.timeline,
    },
    outcome: {
      conflict: receipt.governedResult.conflict,
      incidentState: receipt.terminal.incidentState,
      recourseOpened: receipt.terminal.recourseOpened,
      recourseRefusal: receipt.terminal.recourseRefusal,
      governedResultDigest: receipt.governedResult.digest,
      receiptDigest: receipt.receiptDigest,
    },
    artifacts: {
      evaluatedArtifact: {
        artifactId: `${slot.label.toLowerCase()}-evaluated-conflict`,
        name: "evaluated-conflict.json",
        observedAt: slot.evaluatedArtifactObservation?.observedAt ?? null,
        bytes: slot.evaluatedArtifactObservation?.bytes ?? null,
        digest: slot.evaluatedArtifactObservation?.digest ?? null,
      },
      evaluatedArtifactDigest: receipt.execution.evaluatedArtifactDigest,
      evaluatorProvenance: receipt.execution.evaluatorProvenance,
      decryptorProvenance: receipt.execution.decryptorProvenance,
      completedJournalOperations: evidence.journal.records.map((record) => ({
        sequence: record.sequence,
        operation: record.operation,
        outcome: record.outcome,
        createdAt: record.createdAt,
        terminalAt: record.terminalAt,
      })),
    },
    observations: {
      maxWorkerRssBytes: slot.maxWorkerRssBytes,
      maxNativeChildRssBytes: slot.maxNativeChildRssBytes,
      peakRootBytes: slot.peakRootBytes,
      finalRootBytes: slot.finalRootBytes,
    },
  };
}

async function main() {
  const branch = await git("branch", "--show-current");
  const sourceCommit = await git("rev-parse", "HEAD");
  const sourceTree = await git("rev-parse", "HEAD^{tree}");
  const baseCommit = await git("merge-base", "HEAD", "origin/main");
  const trackedChanges = await git("status", "--porcelain", "--untracked-files=no");
  if (trackedChanges !== "") {
    throw new Error("Commit tracked proof/source changes before execution so the audited source pin is exact");
  }
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit) || !/^[0-9a-f]{40}$/u.test(sourceTree)) {
    throw new Error("Full lowercase source commit and tree pins are required");
  }
  if (!existsSync(COMPILED_ENGINE)) throw new Error("The compiled product engine is missing; run the package command");

  const binaries = await buildFreshBinaries(sourceCommit, sourceTree);
  const [portA, portB] = await reservePorts(2);
  const rootA = mkdtempSync(join(tmpdir(), "mordant-n2-slot-a-"));
  const rootB = mkdtempSync(join(tmpdir(), "mordant-n2-slot-b-"));
  const slots = [
    createSlot("A", "overlapping", portA, rootA, sourceCommit, binaries),
    createSlot("B", "separated", portB, rootB, sourceCommit, binaries),
  ];
  const concurrency = {
    processSamplingAvailable: true,
    bothWorkersBusyObservedAt: null,
    nativeEvaluatorsSimultaneous: null,
  };
  const assertions = [];
  const check = (id, description, pass, evidence) => {
    assertions.push({ id, description, pass: Boolean(pass), evidence });
  };

  let evidenceA;
  let evidenceB;
  try {
    slots.forEach(startSlot);
    await Promise.all(slots.map(waitReady));
    process.stdout.write("Both workers independently reported READY.\n");
    await Promise.all(slots.map(admit));
    process.stdout.write(`Accepted A=${slots[0].runId} B=${slots[1].runId}.\n`);
    await observeUntilTerminal(slots, concurrency);

    evidenceA = collectSlotEvidence(slots[0]);
    evidenceB = collectSlotEvidence(slots[1]);
    const foreignFromA = await foreignRead(slots[0], slots[1].runId);
    const foreignFromB = await foreignRead(slots[1], slots[0].runId);
    const runIds = slots.map((slot) => slot.runId);
    const executionOverlapMs = intervalOverlapMs(evidenceA.interval, evidenceB.interval);
    const evaluationOperationOverlapMs = intervalOverlapMs(
      { start: evidenceA.evaluation.createdAt, end: evidenceA.evaluation.terminalAt },
      { start: evidenceB.evaluation.createdAt, end: evidenceB.evaluation.terminalAt },
    );
    const acceptanceStartSkewMs = Math.abs(
      Date.parse(slots[0].requestStartedAt) - Date.parse(slots[1].requestStartedAt),
    );
    const rootAJsonForeign = filesContaining(slots[0].root, slots[1].runId);
    const rootBJsonForeign = filesContaining(slots[1].root, slots[0].runId);
    const runDirectoriesA = runDirectories(slots[0].root);
    const runDirectoriesB = runDirectories(slots[1].root);
    const operationsA = evidenceA.journal.records.map((record) => record.operation);
    const operationsB = evidenceB.journal.records.map((record) => record.operation);
    const allRequiredOperations = REQUIRED_OPERATIONS.every((operation) => (
      completedOperation(evidenceA.journal, operation) && completedOperation(evidenceB.journal, operation)
    ));

    check("1", "both worker slots become READY independently",
      slots.every((slot) => slot.readyHealth?.status === "READY" && slot.readyHealth?.worker === "IDLE"),
      slots.map((slot) => ({ label: slot.label, workerId: slot.workerId, readyAt: slot.readyAt })));
    check("2", "durable roots are distinct", slots[0].root !== slots[1].root,
      { rootIds: slots.map((slot) => slot.rootId), distinct: slots[0].root !== slots[1].root });
    check("3", "requests are independently accepted",
      slots.every((slot) => slot.acceptanceStatus === 201),
      slots.map((slot) => ({ label: slot.label, status: slot.acceptanceStatus, acceptedAt: slot.acceptedAt })));
    check("4", "generated run IDs differ", runIds[0] !== runIds[1], { runIds });
    check("5", "both runs materially overlap in wall-clock execution",
      executionOverlapMs >= MIN_MATERIAL_OVERLAP_MS && concurrency.bothWorkersBusyObservedAt !== null,
      { executionOverlapMs, minimumMs: MIN_MATERIAL_OVERLAP_MS,
        bothWorkersBusyObservedAt: concurrency.bothWorkersBusyObservedAt, acceptanceStartSkewMs });
    check("6", "both reach the genuine evaluation path",
      allRequiredOperations
        && evidenceA.receipt.execution.evaluatorProvenance === binaries.hashes.evaluator
        && evidenceB.receipt.execution.evaluatorProvenance === binaries.hashes.evaluator
        && evidenceA.receipt.execution.decryptorProvenance === binaries.hashes.decryptor
        && evidenceB.receipt.execution.decryptorProvenance === binaries.hashes.decryptor,
      { operationsA, operationsB, evaluatorBinary: binaries.hashes.evaluator,
        decryptorBinary: binaries.hashes.decryptor, evaluationOperationOverlapMs });
    check("7", "evaluated artifacts exist independently",
      slots.every((slot) => slot.evaluatedArtifactObservation !== null)
        && slots[0].evaluatedArtifactObservation.path.startsWith(slots[0].root)
        && slots[1].evaluatedArtifactObservation.path.startsWith(slots[1].root)
        && slots[0].evaluatedArtifactObservation.digest === evidenceA.receipt.execution.evaluatedArtifactDigest
        && slots[1].evaluatedArtifactObservation.digest === evidenceB.receipt.execution.evaluatedArtifactDigest
        && evidenceA.receipt.execution.evaluatedArtifactDigest !== evidenceB.receipt.execution.evaluatedArtifactDigest,
      { artifacts: slots.map((slot) => ({ label: slot.label,
        artifactId: `${slot.label.toLowerCase()}-evaluated-conflict`,
        digest: slot.evaluatedArtifactObservation?.digest ?? null })) });
    check("8", "governed result A is correct",
      evidenceA.receipt.governedResult.conflict === true
        && evidenceA.receipt.terminal.incidentState === "CONFLICT_CONFIRMED"
        && evidenceA.receipt.terminal.recourseOpened === true,
      { conflict: evidenceA.receipt.governedResult.conflict,
        incidentState: evidenceA.receipt.terminal.incidentState,
        recourseOpened: evidenceA.receipt.terminal.recourseOpened });
    check("9", "governed result B is correct",
      evidenceB.receipt.governedResult.conflict === false
        && evidenceB.receipt.terminal.incidentState === "CLEARED"
        && evidenceB.receipt.terminal.recourseOpened === false
        && evidenceB.receipt.terminal.recourseRefusal === "SIGNED_RESULT_FALSE",
      { conflict: evidenceB.receipt.governedResult.conflict,
        incidentState: evidenceB.receipt.terminal.incidentState,
        recourseOpened: evidenceB.receipt.terminal.recourseOpened,
        recourseRefusal: evidenceB.receipt.terminal.recourseRefusal });
    check("10", "root A contains no run or journal state belonging to B",
      JSON.stringify(evidenceA.journal).includes(slots[1].runId) === false
        && rootAJsonForeign.length === 0
        && JSON.stringify(runDirectoriesA) === JSON.stringify([slots[0].runId]),
      { rootId: slots[0].rootId, runIds: runDirectoriesA, foreignRunMatches: rootAJsonForeign.length });
    check("11", "root B contains no run or journal state belonging to A",
      JSON.stringify(evidenceB.journal).includes(slots[0].runId) === false
        && rootBJsonForeign.length === 0
        && JSON.stringify(runDirectoriesB) === JSON.stringify([slots[1].runId]),
      { rootId: slots[1].rootId, runIds: runDirectoriesB, foreignRunMatches: rootBJsonForeign.length });
    check("12", "worker A cannot retrieve run B with the canonical unknown-case response",
      foreignFromA.status === 404 && foreignFromA.code === "UNKNOWN_CASE", foreignFromA);
    check("13", "worker B cannot retrieve run A with the canonical unknown-case response",
      foreignFromB.status === 404 && foreignFromB.code === "UNKNOWN_CASE", foreignFromB);
    check("14", "both obtain their own terminal receipt",
      evidenceA.receipt.runId === slots[0].runId
        && evidenceB.receipt.runId === slots[1].runId
        && slots.every((slot) => slot.terminalView?.receipt?.runId === slot.runId),
      slots.map((slot, index) => ({ label: slot.label, runId: slot.runId,
        receiptRunId: [evidenceA, evidenceB][index].receipt.runId,
        terminalReceiptObservedAt: slot.terminalObservedAt })));
    check("15", "neither journal references the foreign run",
      !JSON.stringify(evidenceA.journal).includes(slots[1].runId)
        && !JSON.stringify(evidenceB.journal).includes(slots[0].runId),
      { journals: [
        { journalId: slots[0].journalId, foreignRunReferenced: false },
        { journalId: slots[1].journalId, foreignRunReferenced: false },
      ] });
    check("native-evaluator-concurrency",
      "one native evaluator child from each slot is observed alive in the same process snapshot",
      concurrency.processSamplingAvailable
        && concurrency.nativeEvaluatorsSimultaneous !== null
        && new Set(concurrency.nativeEvaluatorsSimultaneous.processes.map((entry) => entry.slot)).size === 2,
      concurrency.nativeEvaluatorsSimultaneous === null ? { observed: false } : {
        observed: true,
        observedAt: concurrency.nativeEvaluatorsSimultaneous.observedAt,
        processCount: concurrency.nativeEvaluatorsSimultaneous.processes.length,
        slots: [...new Set(concurrency.nativeEvaluatorsSimultaneous.processes.map((entry) => entry.slot))].sort(),
      });
    check("source-build-link", "both workers use binaries freshly built from the same audited checkout",
      binaries.retained.builtDuringProof
        && binaries.retained.auditedSourceCommit === sourceCommit
        && binaries.retained.auditedSourceTree === sourceTree
        && binaries.retained.binaries.length === BINARY_DEFINITIONS.length
        && slots.every((slot) => slot.readyHealth?.version === sourceCommit)
        && evidenceA.receipt.sourceCommit === sourceCommit
        && evidenceB.receipt.sourceCommit === sourceCommit,
      { sourceCommit, sourceTree, nativeBinaryCount: binaries.retained.binaries.length,
        workerScriptDigest: sha256File(WORKER_SCRIPT), compiledEngineDigest: sha256File(COMPILED_ENGINE) });
    check("process-model", "exactly two authentic worker processes use separate ports and one-case semantics",
      slots.length === 2 && slots[0].pid !== slots[1].pid && slots[0].port !== slots[1].port,
      slots.map((slot) => ({ label: slot.label, workerId: slot.workerId,
        portId: slot.portId, maxActiveCases: 1 })));

    const nativeEvaluatorObservation = concurrency.nativeEvaluatorsSimultaneous === null ? {
      observed: false,
      observedAt: null,
      processCount: 0,
      slots: [],
      binaryName: "mordant-fhe-evaluator",
    } : {
      observed: true,
      observedAt: concurrency.nativeEvaluatorsSimultaneous.observedAt,
      processCount: concurrency.nativeEvaluatorsSimultaneous.processes.length,
      slots: [...new Set(concurrency.nativeEvaluatorsSimultaneous.processes.map((entry) => entry.slot))].sort(),
      binaryName: "mordant-fhe-evaluator",
    };
    const body = {
      schemaVersion: SCHEMA_VERSION,
      verdict: null,
      auditedSource: {
        repository: REPOSITORY,
        branch,
        baseCommit,
        commit: sourceCommit,
        tree: sourceTree,
        trackedCheckoutClean: true,
        workerEntrypoint: relative(SOURCE_ROOT, WORKER_SCRIPT),
        workerEntrypointDigest: sha256File(WORKER_SCRIPT),
        compiledEngine: relative(SOURCE_ROOT, COMPILED_ENGINE),
        compiledEngineDigest: sha256File(COMPILED_ENGINE),
      },
      nativeBuild: binaries.retained,
      processModel: {
        workerCount: 2,
        workerRuntime: "node",
        workerEntrypoint: relative(SOURCE_ROOT, WORKER_SCRIPT),
        compiledEngine: relative(SOURCE_ROOT, COMPILED_ENGINE),
        intakeProfile: "MANAGED_COMBINED_INTAKE",
        maxActiveCasesPerWorker: 1,
        separatePorts: true,
        separateDurableRoots: true,
        sharedFreshNativeBinaryManifest: true,
      },
      concurrency: {
        acceptanceStartSkewMs,
        executionOverlapMs,
        evaluationOperationOverlapMs,
        evaluationOperationMetric: "Overlap of durable evaluatePrivateConflict operation-journal intervals; this is broader than, and is not represented as, native process-runtime duration.",
        minimumMaterialExecutionOverlapMs: MIN_MATERIAL_OVERLAP_MS,
        bothWorkersBusyObservedAt: concurrency.bothWorkersBusyObservedAt,
        processSamplingAvailable: concurrency.processSamplingAvailable,
        nativeEvaluatorsSimultaneous: nativeEvaluatorObservation,
      },
      slots: [retainedSlot(slots[0], evidenceA), retainedSlot(slots[1], evidenceB)],
      isolation: {
        foreignReads: {
          workerAReadingRunB: foreignFromA,
          workerBReadingRunA: foreignFromB,
        },
        roots: {
          slotA: { rootId: slots[0].rootId, runIds: runDirectoriesA, foreignRunMatches: rootAJsonForeign.length },
          slotB: { rootId: slots[1].rootId, runIds: runDirectoriesB, foreignRunMatches: rootBJsonForeign.length },
        },
        journals: {
          slotA: { journalId: slots[0].journalId, foreignRunReferenced: false },
          slotB: { journalId: slots[1].journalId, foreignRunReferenced: false },
        },
        receipts: {
          slotA: { runId: slots[0].runId, receiptDigest: evidenceA.receipt.receiptDigest,
            observedAt: slots[0].terminalObservedAt },
          slotB: { runId: slots[1].runId, receiptDigest: evidenceB.receipt.receiptDigest,
            observedAt: slots[1].terminalObservedAt },
        },
      },
      assertions,
      exactClaimSupported: null,
      claimsNotSupported: [
        "Production routing or pooling is implemented.",
        "Execution capacity scales linearly.",
        "Any production throughput level is established.",
        "N>2 execution isolation is established.",
        "Autoscaling, load balancing, or high availability is implemented.",
        "Settlement scalability is established.",
        "Horizontal execution is production-ready.",
        "The public deployment exposes more than its intentional one worker slot.",
      ],
    };
    const preSanitationViolations = sanitationViolations(body);
    check("retained-evidence-sanitation",
      "retained evidence contains no absolute paths, raw private windows, tokens, secrets, or private material",
      preSanitationViolations.length === 0,
      { violationCount: preSanitationViolations.length });
    body.assertions = assertions;
    const passed = assertions.every((assertion) => assertion.pass);
    body.verdict = passed
      ? "PASS — N=2 ISOLATED EXECUTION PROVEN WITH EXISTING WORKERS"
      : "FAIL — PROOF REQUIRES PRODUCTION ARCHITECTURE CHANGES";
    body.exactClaimSupported = passed ? "Multiple isolated execution slots can run concurrently." : null;
    const summary = { ...body, evidenceDigest: evidenceDigest(body) };
    mkdirSync(dirname(EVIDENCE_PATH), { recursive: true, mode: 0o700 });
    writeFileSync(EVIDENCE_PATH, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write(`${summary.verdict}\nEvidence: ${EVIDENCE_PATH}\n`);
    if (!passed) process.exitCode = 1;
  } finally {
    await Promise.all(slots.map(stopSlot));
  }
}

main().catch((error) => {
  process.stderr.write(`FAIL — PROOF HARNESS DID NOT COMPLETE: ${error?.message ?? "unknown error"}\n`);
  process.exitCode = 1;
});
