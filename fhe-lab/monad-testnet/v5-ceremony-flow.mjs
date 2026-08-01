// Recoverable Gate 1 dealerless 2-of-3 ceremony stages.
//
// The runner reads only <root>/public. The execution capability can launch the
// isolated lab to one named checkpoint, but exposes neither an operator path nor
// a signing/decryption key. Operator-private recovery remains inside each
// ceremony-operator process and its 0700/0600 ledger.
import {
  createHash, createPublicKey, randomBytes, verify as verifySignature,
} from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  chmod, mkdir, readFile, stat, writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";

import { JournalError } from "./v5-journal.mjs";
import { defineStage, runPipeline } from "./v5-stage.mjs";
import { POLICY_ID } from "./v5-rehearsal-support.mjs";

const execFileAsync = promisify(execFile);
const hex32 = /^(?:0x)?[0-9a-fA-F]{64}$/;
const statusDomain = Buffer.from("mordant.ceremony.operator-statement/v4");
const auditDomain = Buffer.from("mordant.ceremony.operator-secret-audit/v1");
const contextDomain = Buffer.from("mordant.ceremony.context/v1\0");
const rosterDomain = Buffer.from("mordant.ceremony.roster/v4");
const ed25519SPKIPrefix = Buffer.from("302a300506032b6570032100", "hex");
const manifestDomain = Buffer.from("mordant.ceremony.key-manifest/v4");
const manifestStatementBytes = manifestDomain.length + 6 * 32;

const META = new Set([
  "state", "preparedAt", "inputDigest", "confirmedAt", "outputDigest", "verified",
  "verifiedAt", "verification", "receipt", "failedAt", "reason",
]);

const frozenRecord = (entry) =>
  Object.fromEntries(Object.entries(entry).filter(([key]) => !META.has(key)));

const sha256 = (value) => createHash("sha256").update(value).digest();
const sha256Hex = (value) => `0x${sha256(value).toString("hex")}`;
const strip0x = (value) => String(value).replace(/^0x/i, "").toLowerCase();

function uint(value, bytes) {
  const out = Buffer.alloc(bytes);
  let remaining = BigInt(value);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new JournalError("CEREMONY_INTEGER_OVERFLOW", String(value));
  return out;
}

function exactHex(value, label) {
  if (!hex32.test(value ?? "")) throw new JournalError("CEREMONY_CONTEXT_INVALID", label);
  return Buffer.from(strip0x(value), "hex");
}

async function readJSON(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function fileDigest(path) {
  return sha256Hex(await readFile(path));
}

function rosterDigest(roster) {
  if (roster.threshold !== 2 || roster.points?.length !== 3 || roster.signingPublicKeys?.length !== 3) {
    throw new JournalError("CEREMONY_NOT_2_OF_3", "roster");
  }
  const chunks = [
    rosterDomain,
    exactHex(roster.parameterFingerprint, "parameter fingerprint"),
    uint(roster.threshold, 2),
    exactHex(roster.ceremonyId, "ceremony id"),
    uint(roster.keyEpoch, 8),
    uint(roster.points.length, 2),
  ];
  let previous = 0n;
  const identities = new Set();
  roster.points.forEach((point, index) => {
    const numeric = BigInt(point);
    const key = exactHex(roster.signingPublicKeys[index], `operator ${point} key`);
    if (numeric <= previous || identities.has(key.toString("hex"))) {
      throw new JournalError("CEREMONY_ROSTER_INVALID", `operator ${point}`);
    }
    previous = numeric;
    identities.add(key.toString("hex"));
    chunks.push(uint(numeric, 8), key);
  });
  return sha256(Buffer.concat(chunks));
}

function verifyContext(context) {
  if (context.schemaVersion !== "mordant.ceremony-context/1" ||
      context.ceremonyProtocol !== "mordant.ceremony.network-request/v4" ||
      context.manifestSchema !== "mordant.collective-key-manifest/4" ||
      context.threshold !== 2 || context.operatorPoints?.length !== 3 ||
      context.operatorSigningKeys?.length !== 3 || context.circuitVersion !== 5 ||
      context.releaseLayoutVersion !== 1 || context.serializationVersion !== 1 ||
      !hex32.test(context.ceremonyId) || !hex32.test(context.parameterFingerprint) ||
      !hex32.test(context.circuitHash) || !hex32.test(context.policyId) ||
      !hex32.test(context.sessionCommitment) || !hex32.test(context.contextNonce)) {
    throw new JournalError("CEREMONY_CONTEXT_INVALID", "schema or binding");
  }
  const canonical = { ...context, ceremonyId: "" };
  const observed = sha256(Buffer.concat([contextDomain, Buffer.from(JSON.stringify(canonical))])).toString("hex");
  if (observed !== strip0x(context.ceremonyId)) {
    throw new JournalError("CEREMONY_CONTEXT_DRIFT", observed);
  }
  if (Object.keys(context.runtimeBinarySha256 ?? {}).sort().join(",") !==
      ["ceremony-client", "ceremony-coordinator", "ceremony-evaluator", "ceremony-operator"].join(",")) {
    throw new JournalError("CEREMONY_RUNTIME_SET_INVALID", "binary set");
  }
  for (const digest of Object.values(context.runtimeBinarySha256)) exactHex(digest, "runtime binary digest");
  return context;
}

function verifyRosterAgainstContext(roster, context) {
  const digest = rosterDigest(roster);
  if (strip0x(roster.ceremonyId) !== strip0x(context.ceremonyId) ||
      strip0x(roster.parameterFingerprint) !== strip0x(context.parameterFingerprint) ||
      JSON.stringify(roster.points) !== JSON.stringify(context.operatorPoints) ||
      JSON.stringify(roster.signingPublicKeys) !== JSON.stringify(context.operatorSigningKeys)) {
    throw new JournalError("CEREMONY_ROSTER_CONTEXT_DRIFT", roster.ceremonyId);
  }
  return digest;
}

function verifySignedStatus(raw, roster, expectedRosterDigest) {
  if (!raw || !Number.isInteger(raw.point) || !raw.statement || typeof raw.signature !== "string") {
    throw new JournalError("CEREMONY_STATUS_INVALID", "shape");
  }
  const index = roster.points.indexOf(raw.point);
  if (index < 0 || raw.statement.point !== raw.point ||
      strip0x(raw.statement.rosterDigest) !== expectedRosterDigest.toString("hex") ||
      raw.statement.holdsOwnShareOnly !== true) {
    throw new JournalError("CEREMONY_STATUS_BINDING_DRIFT", String(raw.point));
  }
  const statementBytes = Buffer.from(JSON.stringify(raw.statement));
  const digest = sha256(Buffer.concat([statusDomain, statementBytes]));
  const publicKey = createPublicKey({
    key: Buffer.concat([ed25519SPKIPrefix, exactHex(roster.signingPublicKeys[index], "operator key")]),
    format: "der", type: "spki",
  });
  const signature = Buffer.from(raw.signature, "hex");
  if (signature.length !== 64 || !verifySignature(null, digest, publicKey, signature)) {
    throw new JournalError("CEREMONY_STATUS_SIGNATURE_INVALID", String(raw.point));
  }
  return raw.statement;
}

function operationCount(statement, operation) {
  return (statement.steps ?? []).filter((step) => Number(step.operation) === operation).length;
}

async function optionalJSON(path) {
  try {
    return await readJSON(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

export async function inspectCeremonyPublic(ceremonyRoot) {
  const publicRoot = join(ceremonyRoot, "public");
  const context = verifyContext(await readJSON(join(publicRoot, "ceremony-context.json")));
  const roster = await readJSON(join(publicRoot, "roster.json"));
  const digest = verifyRosterAgainstContext(roster, context);
  const statuses = [];
  for (const point of roster.points) {
    const raw = await optionalJSON(join(publicRoot, `operator-status-${point}.json`));
    if (raw) statuses.push(verifySignedStatus(raw, roster, digest));
  }
  const byPoint = new Map(statuses.map((statement) => [statement.point, statement]));
  if (byPoint.size !== statuses.length) throw new JournalError("CEREMONY_OPERATOR_STATE_INCONSISTENT", "duplicate point");
  if (statuses.length > roster.points.length ||
      statuses.some((statement, index) => statement.point !== roster.points[index])) {
    throw new JournalError("CEREMONY_OPERATOR_STATE_INCONSISTENT", "readiness is not a canonical roster prefix");
  }

  let progress = 1;
  if (statuses.length > 0) progress = 2;
  const all = (predicate) => statuses.length === 3 && statuses.every(predicate);
  if (all((value) => operationCount(value, 1) === 1)) progress = 3;
  if (all((value) => operationCount(value, 2) === 1 && value.crsCommitment && !/^0+$/.test(value.crsCommitment))) progress = 4;
  if (all((value) => operationCount(value, 5) === 1)) progress = 5;
  if (all((value) => operationCount(value, 6) === 1 && operationCount(value, 7) === 1)) progress = 6;
  if (all((value) => operationCount(value, 8) === 9)) progress = 7;

  let statement = null;
  try {
    statement = await readFile(join(publicRoot, "ceremony-manifest-statement.bin"));
    if (statement.length !== manifestStatementBytes || !statement.subarray(0, manifestDomain.length).equals(manifestDomain)) {
      throw new JournalError("CEREMONY_MANIFEST_INVALID", "canonical statement");
    }
    progress = Math.max(progress, 8);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const manifestDigest = statement ? sha256(statement) : null;
  const attestations = [];
  if (statement) {
    for (let index = 0; index < roster.points.length; index += 1) {
      const point = roster.points[index];
      try {
        const signature = await readFile(join(publicRoot, `manifest-attestation-${point}.bin`));
        const publicKey = createPublicKey({
          key: Buffer.concat([ed25519SPKIPrefix, exactHex(roster.signingPublicKeys[index], "operator key")]),
          format: "der", type: "spki",
        });
        if (signature.length !== 64 || !verifySignature(null, manifestDigest, publicKey, signature)) {
          throw new JournalError("CEREMONY_MANIFEST_SIGNATURE_INVALID", String(point));
        }
        attestations.push({ point, digest: sha256Hex(signature) });
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        break;
      }
    }
    if (attestations.length > 0) progress = Math.max(progress, 8 + attestations.length);
  }

  const coreFiles = [
    "ceremony-context.json", "roster.json", "ceremony-manifest-statement.bin",
    "manifest-attestation-1.bin", "manifest-attestation-2.bin", "manifest-attestation-3.bin",
    "collective-public-material.bin", "collective-evaluation-keys.bin", "key-manifest.json", "ceremony-evidence.json",
  ];
  const coreDigests = {};
  for (const name of coreFiles) {
    try { coreDigests[name] = await fileDigest(join(publicRoot, name)); } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const finalFiles = ["collective-public-material.bin", "collective-evaluation-keys.bin", "key-manifest.json", "ceremony-evidence.json"];
  if (finalFiles.every((name) => coreDigests[name])) progress = Math.max(progress, 12);
  const audits = [];
  if (progress >= 12) {
    const expectedOperationCounts = new Map([
      [1, 1], [2, 1], [3, 1], [4, 1], [5, 1], [6, 1], [7, 1], [8, 9], [9, 1],
    ]);
    if (!all((value) => value.steps?.length === 17 &&
        [...expectedOperationCounts].every(([operation, count]) => operationCount(value, operation) === count))) {
      throw new JournalError("CEREMONY_OPERATOR_STATE_INCONSISTENT", "repeated or missing ceremony step");
    }
    const manifest = await readJSON(join(publicRoot, "key-manifest.json"));
    const publicKeyDigest = statement
      .subarray(manifestDomain.length + 2 * 32, manifestDomain.length + 3 * 32).toString("hex");
    const relinDigest = statement.subarray(manifestDomain.length + 3 * 32, manifestDomain.length + 4 * 32);
    const galoisDigest = statement.subarray(manifestDomain.length + 4 * 32, manifestDomain.length + 5 * 32);
    const evaluationDigest = sha256(Buffer.concat([
      Buffer.from("mordant.ceremony.evaluation-key-summary/v4"), relinDigest, galoisDigest,
    ])).toString("hex");
    const expectedAttestations = [];
    for (const point of roster.points) {
      const signature = await readFile(join(publicRoot, `manifest-attestation-${point}.bin`));
      expectedAttestations.push(`${point}:${signature.toString("hex")}`);
    }
    if (manifest.threshold !== 2 || strip0x(manifest.ceremonyId) !== strip0x(context.ceremonyId) ||
        strip0x(manifest.publicKeyCommitment) !== publicKeyDigest ||
        JSON.stringify(manifest.attestations) !== JSON.stringify(expectedAttestations) || attestations.length !== 3 ||
        !all((value) => value.sealed && !value.holdsLocalSecretKey &&
          strip0x(value.publicKeyDigest) === publicKeyDigest &&
          strip0x(value.evaluationKeyDigest) === evaluationDigest &&
          strip0x(value.manifestDigest) === manifestDigest.toString("hex"))) {
      throw new JournalError("CEREMONY_FINAL_READBACK_MISMATCH", "manifest/status");
    }
    for (let index = 0; index < roster.points.length; index += 1) {
      const point = roster.points[index];
      const signedAudit = await readJSON(join(publicRoot, `operator-secret-audit-${point}.json`));
      if (signedAudit.point !== point || signedAudit.report?.point !== point ||
          signedAudit.report.noLeaks !== true || signedAudit.report.positiveControlDetected !== true ||
          signedAudit.report.positiveControlRemoved !== true || signedAudit.report.leakHits?.length !== 0 ||
          signedAudit.report.roots?.some((path) => path.split("/").includes("operators"))) {
        throw new JournalError("CEREMONY_SECRET_AUDIT_FAILED", String(point));
      }
      const digest = sha256(Buffer.concat([auditDomain, Buffer.from(JSON.stringify(signedAudit.report))]));
      const publicKey = createPublicKey({
        key: Buffer.concat([ed25519SPKIPrefix, exactHex(roster.signingPublicKeys[index], "operator key")]),
        format: "der", type: "spki",
      });
      const signature = Buffer.from(signedAudit.signature, "hex");
      if (signature.length !== 64 || !verifySignature(null, digest, publicKey, signature)) {
        throw new JournalError("CEREMONY_SECRET_AUDIT_SIGNATURE_INVALID", String(point));
      }
      audits.push({ point, reportDigest: sha256Hex(Buffer.from(JSON.stringify(signedAudit.report))) });
    }
    const filesystemAudit = await readJSON(join(publicRoot, "operator-filesystem-audit.json"));
    const requiredPrivateFiles = roster.points.flatMap((point) => [
      `operators/${point}/identity.key`, `operators/${point}/operator.bin`,
    ]);
    if (filesystemAudit.passed !== true || !Array.isArray(filesystemAudit.checks) ||
        requiredPrivateFiles.some((path) => !filesystemAudit.checks
          .some((entry) => entry.path === path && entry.restricted))) {
      throw new JournalError("CEREMONY_FILESYSTEM_AUDIT_FAILED", "private modes or ownership");
    }
    const processSnapshot = await readJSON(join(publicRoot, "process-snapshot.json"));
    const operatorProcesses = processSnapshot.processes
      ?.filter((entry) => entry.role?.startsWith("threshold-operator-")) ?? [];
    if (operatorProcesses.length !== 3 || new Set(operatorProcesses.map((entry) => entry.pid)).size !== 3 ||
        operatorProcesses.some((entry) =>
          JSON.stringify(entry.environmentKeys) !== JSON.stringify(["GOMAXPROCS", "PATH", "TMPDIR"]) ||
          !entry.temporaryDirectory || !entry.workingDirectory || entry.parentPid !== processSnapshot.parentPid)) {
      throw new JournalError("CEREMONY_PROCESS_AUDIT_FAILED", "separation or environment");
    }
    const resources = await readJSON(join(publicRoot, "ceremony-resources.json"));
    if (!resources.publicBundleBytes || !resources.combinedDiskBytesAtSnapshot || !resources.freeDiskBytes ||
        Object.keys(resources.operatorDiskBytes ?? {}).length !== 3 || resources.ceremonyWallMillis < 0) {
      throw new JournalError("CEREMONY_RESOURCE_REPORT_INVALID", "missing measurement");
    }
    progress = 13;
  }
  const stepDigest = sha256Hex(Buffer.from(JSON.stringify(statuses.map((value) => ({ point: value.point, steps: value.steps })))));
  return {
    context, roster, rosterDigest: `0x${digest.toString("hex")}`, statuses, readyCount: statuses.length, progress,
    manifestDigest: manifestDigest ? `0x${manifestDigest.toString("hex")}` : null,
    attestations, audits, coreDigests, stepDigest,
  };
}

async function pathExists(path) {
  try { return (await stat(path)).isFile(); } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function isolatedEnvironment(temporary) {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    TMPDIR: temporary,
    GOMAXPROCS: process.env.GOMAXPROCS ?? "4",
  };
}

async function isolatedBuildEnvironment(temporary) {
  const { stdout } = await execFileAsync("go", ["env", "-json", "GOCACHE", "GOMODCACHE", "GOPATH"], {
    env: process.env,
  });
  const values = JSON.parse(stdout);
  return {
    ...isolatedEnvironment(temporary),
    GOCACHE: values.GOCACHE,
    GOMODCACHE: values.GOMODCACHE,
    GOPATH: values.GOPATH,
  };
}

export function createLocalCeremonyCapability({
  repoRoot,
  ceremonyRoot,
  outputRoot = null,
  runnerJournal = null,
  retainReadyProcesses = false,
}) {
  const moduleRoot = resolve(repoRoot, "fhe-lab/lattigo");
  const root = resolve(ceremonyRoot);
  const out = resolve(outputRoot ?? join(root, "public", "recovery-evidence"));
  const labBinary = join(root, "bin", "ceremony-lab");
  const contextBasePath = join(root, "public", "ceremony-context-base.json");
  const temporary = join(root, "runner-tmp");
  const additionalAuditRoots = runnerJournal ? [resolve(runnerJournal)] : [];

  function withAuditRoots(commandArguments) {
    const expanded = [...commandArguments];
    for (const path of additionalAuditRoots) expanded.push("--audit-root", path);
    return expanded;
  }

  async function invoke(commandArguments) {
    await mkdir(temporary, { recursive: true, mode: 0o700 });
    await chmod(temporary, 0o700);
    return execFileAsync(labBinary, commandArguments, {
      cwd: moduleRoot, env: await isolatedBuildEnvironment(temporary), maxBuffer: 4 << 20,
    });
  }

  return Object.freeze({
    root,
    async prepareContext({ chainId, policyId, sessionCommitment, existingNonce }) {
      if (await pathExists(join(root, "public", "ceremony-context.json"))) {
        const observed = await inspectCeremonyPublic(root);
        if (Number(observed.context.chainId) !== Number(chainId) ||
            strip0x(observed.context.policyId) !== strip0x(policyId) ||
            strip0x(observed.context.sessionCommitment) !== strip0x(sessionCommitment)) {
          throw new JournalError("CEREMONY_CONTEXT_DRIFT", "prepared public context differs from the session");
        }
        return observed.context;
      }
      await mkdir(join(root, "bin"), { recursive: true, mode: 0o700 });
      await mkdir(join(root, "public"), { recursive: true, mode: 0o700 });
      await mkdir(temporary, { recursive: true, mode: 0o700 });
      await chmod(temporary, 0o700);
      const base = {
        schemaVersion: "mordant.ceremony-context-base/1",
        chainId: Number(chainId), policyId: strip0x(policyId), policyVersion: 1,
        sessionCommitment: strip0x(sessionCommitment),
        contextNonce: strip0x(existingNonce ?? randomBytes(32).toString("hex")),
      };
      if (await pathExists(contextBasePath)) {
        const existing = await readJSON(contextBasePath);
        if (JSON.stringify(existing) !== JSON.stringify(base)) {
          throw new JournalError("CEREMONY_CONTEXT_DRIFT", "base file");
        }
      } else {
        await writeFile(contextBasePath, `${JSON.stringify(base, null, 2)}\n`, { mode: 0o600, flag: "wx" });
      }
      await execFileAsync("go", ["build", "-o", labBinary, "./cmd/ceremony-lab"], {
        cwd: moduleRoot, env: await isolatedBuildEnvironment(temporary), maxBuffer: 4 << 20,
      });
      await invoke(withAuditRoots([
        "--root", root, "--out", out, "--repo", moduleRoot, "--setup-only", "--ceremony-only",
        "--context-base", contextBasePath,
      ]));
      return (await inspectCeremonyPublic(root)).context;
    },
    async runCheckpoint(checkpoint) {
      const args = ["--root", root, "--out", out, "--repo", moduleRoot, "--resume", "--ceremony-only"];
      const readyMatch = /^ready-(1|2|3)$/.exec(checkpoint ?? "");
      if (checkpoint === "ready-only" || readyMatch) {
        args.push("--ready-only", "--ready-through", readyMatch?.[1] ?? "3");
        if (retainReadyProcesses) args.push("--retain-ready-operators");
      }
      else if (checkpoint) args.push("--stop-after", checkpoint);
      await invoke(withAuditRoots(args));
      const observed = await inspectCeremonyPublic(root);
      return { progress: observed.progress, stepDigest: observed.stepDigest, coreDigests: observed.coreDigests };
    },
    async inspect() { return inspectCeremonyPublic(root); },
    async shutdownRetainedReadyProcesses(confirmedStage) {
      if (!retainReadyProcesses || confirmedStage !== "CEREMONY_OPERATOR_3_READY") {
        throw new JournalError("CEREMONY_PROCESS_AUDIT_FAILED", "unbounded retained-process shutdown request");
      }
      const snapshot = await readJSON(join(root, "public", "process-snapshot.json"));
      const operators = snapshot.processes
        ?.filter((entry) => entry.role?.startsWith("threshold-operator-")) ?? [];
      if (operators.length !== 3 || new Set(operators.map((entry) => entry.pid)).size !== 3 ||
          operators.some((entry) => !Number.isSafeInteger(entry.pid) || entry.pid <= 1)) {
        throw new JournalError("CEREMONY_PROCESS_AUDIT_FAILED", "invalid retained operator PID set");
      }
      const alive = (pid) => {
        try {
          process.kill(pid, 0);
          return true;
        } catch (error) {
          if (error.code === "ESRCH") return false;
          throw error;
        }
      };
      if (!operators.every((entry) => alive(entry.pid))) {
        throw new JournalError("CEREMONY_PROCESS_AUDIT_FAILED", "operator exited before runner confirmation");
      }
      for (const entry of operators) process.kill(entry.pid, "SIGINT");
      const deadline = Date.now() + 5_000;
      while (operators.some((entry) => alive(entry.pid)) && Date.now() < deadline) {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
      }
      for (const entry of operators) {
        if (alive(entry.pid)) process.kill(entry.pid, "SIGKILL");
      }
      const killDeadline = Date.now() + 2_000;
      while (operators.some((entry) => alive(entry.pid)) && Date.now() < killDeadline) {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
      }
      if (operators.some((entry) => alive(entry.pid))) {
        throw new JournalError("CEREMONY_PROCESS_AUDIT_FAILED", "retained operator did not stop");
      }
      const report = {
        schemaVersion: "mordant.ceremony-post-confirmation-shutdown/1",
        confirmedStage,
        stateAtShutdown: "CONFIRMED",
        operatorCount: operators.length,
        allObservedAliveBeforeShutdown: true,
        allStoppedAfterShutdown: true,
        capturedAtUtc: new Date().toISOString(),
      };
      await writeFile(join(root, "public", "runner-post-confirmation-shutdown.json"),
        `${JSON.stringify(report, null, 2)}\n`, { mode: 0o644 });
      return report;
    },
    async reconcileCompleted() {
      const before = await inspectCeremonyPublic(root);
      await invoke(withAuditRoots(["--root", root, "--out", out, "--repo", moduleRoot, "--resume", "--ceremony-only"]));
      const after = await inspectCeremonyPublic(root);
      const log = await readFile(join(root, "public", "logs", "ceremony-coordinator.stdout"), "utf8");
      if (!log.includes("CEREMONY_COORDINATOR_RECONCILED") || before.stepDigest !== after.stepDigest ||
          JSON.stringify(before.coreDigests) !== JSON.stringify(after.coreDigests)) {
        throw new JournalError("CEREMONY_COMPLETION_REPEATED", "completed reconciliation changed public authority or steps");
      }
      return { beforeStepDigest: before.stepDigest, afterStepDigest: after.stepDigest, coreDigests: after.coreDigests };
    },
  });
}

export const CEREMONY_STAGES = Object.freeze([
  "CEREMONY_CONTEXT_PREPARED", "CEREMONY_IDENTITIES_CONFIRMED",
  "CEREMONY_OPERATOR_1_READY", "CEREMONY_OPERATOR_2_READY", "CEREMONY_OPERATOR_3_READY",
  "CEREMONY_CONTRIBUTIONS_GENERATED", "CEREMONY_CONTRIBUTIONS_EXCHANGED",
  "CEREMONY_COLLECTIVE_PUBLIC_KEY_COMPLETED", "CEREMONY_RELINEARIZATION_COMPLETED",
  "CEREMONY_GALOIS_COMPLETED", "CEREMONY_EVALUATION_KEY_BUNDLE_COMPLETED",
  "CEREMONY_PUBLIC_MANIFEST_CONSTRUCTED", "CEREMONY_MANIFEST_SIGNATURE_1",
  "CEREMONY_MANIFEST_SIGNATURE_2", "CEREMONY_MANIFEST_SIGNATURE_3",
  "CEREMONY_PUBLIC_BUNDLE_VERIFIED", "CEREMONY_COMPLETED",
]);

const definitions = [
  ["CEREMONY_IDENTITIES_CONFIRMED", null, 1],
  ["CEREMONY_OPERATOR_1_READY", "ready-1", 2, 1],
  ["CEREMONY_OPERATOR_2_READY", "ready-2", 2, 2],
  ["CEREMONY_OPERATOR_3_READY", "ready-3", 2, 3],
  ["CEREMONY_CONTRIBUTIONS_GENERATED", "contributions", 3],
  ["CEREMONY_CONTRIBUTIONS_EXCHANGED", "crs-sealed", 4],
  ["CEREMONY_COLLECTIVE_PUBLIC_KEY_COMPLETED", "public-key", 5],
  ["CEREMONY_RELINEARIZATION_COMPLETED", "relin-complete", 6],
  ["CEREMONY_GALOIS_COMPLETED", "galois-complete", 7],
  ["CEREMONY_EVALUATION_KEY_BUNDLE_COMPLETED", "evaluation-key-complete", 7],
  ["CEREMONY_PUBLIC_MANIFEST_CONSTRUCTED", "manifest-constructed", 8],
  ["CEREMONY_MANIFEST_SIGNATURE_1", "signature-1", 9],
  ["CEREMONY_MANIFEST_SIGNATURE_2", "signature-2", 10],
  ["CEREMONY_MANIFEST_SIGNATURE_3", "signature-3", 11],
  ["CEREMONY_PUBLIC_BUNDLE_VERIFIED", "confirmed", 13],
];

function genericStage(name, checkpoint, minimumProgress, minimumReadyCount = 0) {
  const reached = (observed) =>
    observed.progress >= minimumProgress && observed.readyCount >= minimumReadyCount;
  return defineStage({
    name,
    prepare: async ({ journal, existing }) => existing ? frozenRecord(existing) : {
      ceremonyId: journal.stage("CEREMONY_CONTEXT_PREPARED").ceremonyId,
      contextDigest: journal.stage("CEREMONY_CONTEXT_PREPARED").contextDigest,
      checkpoint,
      minimumProgress,
      minimumReadyCount,
    },
    execute: checkpoint ? async ({ prepared, execution }) => {
      if (!execution?.runCheckpoint) throw new JournalError("CEREMONY_CAPABILITY_MISSING", name);
      return { outputs: await execution.runCheckpoint(prepared.checkpoint) };
    } : async () => ({ outputs: {} }),
    reconcile: async ({ ceremony }) => {
      try {
        const observed = await ceremony.inspect();
        if (reached(observed)) {
          return { alreadyDone: true, outputs: {
            ceremonyId: observed.context.ceremonyId,
            reconciledProgress: observed.progress,
            readyCount: observed.readyCount,
            stepDigest: observed.stepDigest,
          } };
        }
        return null;
      } catch (error) {
        if (error.code === "ENOENT") return null;
        return { ambiguous: true, reason: error.code ?? error.message };
      }
    },
    verify: async ({ ceremony, journal }) => {
      const completionReconciliation = name === "CEREMONY_PUBLIC_BUNDLE_VERIFIED"
        ? await ceremony.reconcileCompleted()
        : null;
      const observed = await ceremony.inspect();
      const prepared = journal.stage(name);
      return {
        ok: reached(observed) && strip0x(observed.context.ceremonyId) === strip0x(prepared.ceremonyId),
        evidence: { progress: observed.progress, readyCount: observed.readyCount, stepDigest: observed.stepDigest,
          manifestDigest: observed.manifestDigest, completionReconciliation },
      };
    },
  });
}

export function createCeremonyStages() {
  return [
    defineStage({
      name: "CEREMONY_CONTEXT_PREPARED",
      async prepare({ journal, ceremony, chainId, existing }) {
        if (existing) return frozenRecord(existing);
        const session = journal.stage("SESSION_COMMITTED");
        const context = await ceremony.prepareContext({
          chainId, policyId: POLICY_ID, sessionCommitment: session.sessionCommitment,
        });
        return {
          ceremonyId: context.ceremonyId,
          contextDigest: sha256Hex(Buffer.from(JSON.stringify(context))),
          sessionCommitment: session.sessionCommitment,
          chainId: Number(chainId), policyId: POLICY_ID,
          publicContext: context,
        };
      },
      reconcile: async ({ ceremony, journal, chainId }) => {
        try {
          const observed = await ceremony.inspect();
          const session = journal.stage("SESSION_COMMITTED");
          if (Number(observed.context.chainId) !== Number(chainId) ||
              strip0x(observed.context.sessionCommitment) !== strip0x(session.sessionCommitment)) {
            return { ambiguous: true, reason: "persisted ceremony context belongs to another session" };
          }
          return { alreadyDone: true, outputs: {
            ceremonyId: observed.context.ceremonyId,
            contextDigest: sha256Hex(Buffer.from(JSON.stringify(observed.context))),
            sessionCommitment: session.sessionCommitment,
            chainId: Number(chainId), policyId: POLICY_ID,
            publicContext: observed.context,
          } };
        } catch (error) {
          if (error.code === "ENOENT") return null;
          return { ambiguous: true, reason: error.code ?? error.message };
        }
      },
      execute: async () => ({ outputs: {} }),
      verify: async ({ ceremony, journal }) => {
        const observed = await ceremony.inspect();
        const entry = journal.stage("CEREMONY_CONTEXT_PREPARED");
        return { ok: strip0x(observed.context.ceremonyId) === strip0x(entry.ceremonyId) &&
          sha256Hex(Buffer.from(JSON.stringify(observed.context))) === entry.contextDigest };
      },
    }),
    ...definitions.map(([name, checkpoint, progress, readyCount]) =>
      genericStage(name, checkpoint, progress, readyCount)),
    defineStage({
      name: "CEREMONY_COMPLETED",
      prepare: async ({ journal, existing }) => existing ? frozenRecord(existing) : {
        ceremonyId: journal.stage("CEREMONY_CONTEXT_PREPARED").ceremonyId,
        verifiedBundleDigest: sha256Hex(Buffer.from(JSON.stringify(
          journal.stage("CEREMONY_PUBLIC_BUNDLE_VERIFIED").verification ?? {},
        ))),
      },
      reconcile: async ({ ceremony }) => {
        try {
          const observed = await ceremony.inspect();
          return observed.progress >= 13
            ? { alreadyDone: true, outputs: { stepDigest: observed.stepDigest, coreDigests: observed.coreDigests } }
            : null;
        } catch (error) {
          if (error.code === "ENOENT") return null;
          return { ambiguous: true, reason: error.code ?? error.message };
        }
      },
      execute: async () => ({ outputs: {} }),
      verify: async ({ ceremony, journal }) => {
        const observed = await ceremony.inspect();
        const bundle = journal.stage("CEREMONY_PUBLIC_BUNDLE_VERIFIED");
        return { ok: observed.progress >= 13 &&
          observed.stepDigest === (bundle.verification?.stepDigest ?? observed.stepDigest),
          evidence: { ceremonyId: observed.context.ceremonyId, stepDigest: observed.stepDigest,
            manifestDigest: observed.manifestDigest, coreDigests: observed.coreDigests } };
      },
    }),
  ];
}

export async function runCeremonyPipeline(context) {
  return runPipeline(createCeremonyStages(), {
    ...context,
    executionForStage: (name) => CEREMONY_STAGES.includes(name)
      ? Object.freeze({ runCheckpoint: (checkpoint) => context.ceremony.runCheckpoint(checkpoint) })
      : undefined,
  });
}
