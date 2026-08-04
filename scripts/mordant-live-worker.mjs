#!/usr/bin/env node
/**
 * Mordant live execution worker.
 *
 * One managed process that runs the existing custom V2 BGV engine for a public
 * visitor. It exposes exactly three endpoints and nothing else: no admin API,
 * no operation selection, no path or binary input.
 *
 * Durable state lives entirely under MORDANT_WORKER_DATA_ROOT. Binaries stay in
 * the immutable container image.
 *
 * The worker never predicts a result. It runs the fixed journey and reports
 * only what the engine has durably produced; the governed signed Boolean is the
 * sole authority for any terminal wording.
 */

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statfsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const WORKER_SCHEMA = "mordant.live-worker/1";

const TOKEN_MEMBERS = ["tokenId", "issuedAt", "expiresAt", "audience", "action"];
const MAX_BODY_BYTES = 1_024;
const MAX_TOKEN_LIFETIME_MS = 5 * 60 * 1_000;
const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export class WorkerError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// ---------------------------------------------------------------- configuration

function requiredEnv(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.trim() === "") {
    throw new WorkerError(500, "CONFIG", `${name} is required`);
  }
  return value;
}

function positiveIntEnv(environment, name, fallback) {
  const raw = environment[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new WorkerError(500, "CONFIG", `${name} must be a positive integer`);
  return value;
}

export function readWorkerConfiguration(environment = process.env) {
  const secret = requiredEnv(environment, "MORDANT_WORKER_TOKEN_SECRET");
  if (secret.length < 32) throw new WorkerError(500, "CONFIG", "MORDANT_WORKER_TOKEN_SECRET must be at least 32 characters");
  const allowedOrigin = requiredEnv(environment, "MORDANT_WORKER_ALLOWED_ORIGIN");
  let origin;
  try {
    origin = new URL(allowedOrigin);
  } catch {
    throw new WorkerError(500, "CONFIG", "MORDANT_WORKER_ALLOWED_ORIGIN must be an absolute origin");
  }
  if (origin.protocol !== "https:" && origin.hostname !== "127.0.0.1" && origin.hostname !== "localhost") {
    throw new WorkerError(500, "CONFIG", "MORDANT_WORKER_ALLOWED_ORIGIN must be HTTPS outside local development");
  }
  return Object.freeze({
    dataRoot: environment.MORDANT_WORKER_DATA_ROOT ?? "/data/mordant",
    tokenSecret: secret,
    tokenAudience: requiredEnv(environment, "MORDANT_WORKER_TOKEN_AUDIENCE"),
    allowedOrigin: origin.origin,
    maxActiveCases: positiveIntEnv(environment, "MORDANT_WORKER_MAX_ACTIVE_CASES", 1),
    dailyCaseLimit: positiveIntEnv(environment, "MORDANT_WORKER_DAILY_CASE_LIMIT", 24),
    diskFloorBytes: positiveIntEnv(environment, "MORDANT_WORKER_DISK_FLOOR_BYTES", 2_187_329_536),
    cooldownMs: positiveIntEnv(environment, "MORDANT_WORKER_COOLDOWN_MS", 15_000),
    caseLifetimeMs: positiveIntEnv(environment, "MORDANT_WORKER_CASE_LIFETIME_MS", 15 * 60 * 1_000),
    retainedReceipts: positiveIntEnv(environment, "MORDANT_WORKER_RETAINED_RECEIPTS", 50),
    port: positiveIntEnv(environment, "PORT", 8080),
    version: environment.MORDANT_PROTECTION_SOURCE_COMMIT ?? "unknown",
  });
}

// ---------------------------------------------------------------- launch token

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function canonicalTokenPayload(claims) {
  // Fixed member order so the signature is stable across implementations.
  return JSON.stringify({
    tokenId: claims.tokenId,
    issuedAt: claims.issuedAt,
    expiresAt: claims.expiresAt,
    audience: claims.audience,
    action: claims.action,
  });
}

export function signLaunchToken(claims, secret) {
  const payload = canonicalTokenPayload(claims);
  const signature = createHmac("sha256", secret).update(payload).digest();
  return `${base64url(payload)}.${base64url(signature)}`;
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

/**
 * Verifies signature, audience, action and expiry. Single use is enforced
 * separately against the durable registry, because that must be atomic with
 * admission.
 */
export function verifyLaunchToken(token, configuration, nowMs) {
  if (typeof token !== "string" || token.length > 2_048) throw new WorkerError(401, "TOKEN_FORMAT", "A launch token is required");
  const parts = token.split(".");
  if (parts.length !== 2) throw new WorkerError(401, "TOKEN_FORMAT", "Malformed launch token");
  let claims;
  try {
    claims = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw new WorkerError(401, "TOKEN_FORMAT", "Malformed launch token");
  }
  if (!exactKeys(claims, TOKEN_MEMBERS)) throw new WorkerError(401, "TOKEN_MEMBERS", "Launch token members are not exact");
  const expected = createHmac("sha256", configuration.tokenSecret).update(canonicalTokenPayload(claims)).digest();
  let supplied;
  try {
    supplied = Buffer.from(parts[1], "base64url");
  } catch {
    throw new WorkerError(401, "TOKEN_SIGNATURE", "Launch token signature rejected");
  }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new WorkerError(401, "TOKEN_SIGNATURE", "Launch token signature rejected");
  }
  if (claims.audience !== configuration.tokenAudience) throw new WorkerError(401, "TOKEN_AUDIENCE", "Launch token audience rejected");
  if (claims.action !== "CREATE_CUSTOM_CASE") throw new WorkerError(401, "TOKEN_ACTION", "Launch token action rejected");
  for (const field of ["issuedAt", "expiresAt"]) {
    if (!Number.isSafeInteger(claims[field]) || claims[field] <= 0) throw new WorkerError(401, "TOKEN_TIME", "Launch token timing rejected");
  }
  if (typeof claims.tokenId !== "string" || !RUN_ID.test(claims.tokenId)) throw new WorkerError(401, "TOKEN_ID", "Launch token identifier rejected");
  if (claims.expiresAt <= nowMs) throw new WorkerError(401, "TOKEN_EXPIRED", "Launch token has expired");
  if (claims.expiresAt - claims.issuedAt > MAX_TOKEN_LIFETIME_MS) throw new WorkerError(401, "TOKEN_LIFETIME", "Launch token lifetime is too long");
  if (claims.issuedAt > nowMs + 60_000) throw new WorkerError(401, "TOKEN_TIME", "Launch token is not yet valid");
  return claims;
}

// ---------------------------------------------------------------- durable state

export function workerPaths(configuration) {
  const root = configuration.dataRoot;
  return Object.freeze({
    root,
    runRoot: join(root, "runs"),
    consumedTokens: join(root, "consumed-tokens"),
    receipts: join(root, "receipts"),
    admissionLog: join(root, "admissions.json"),
  });
}

export function ensureWorkerLayout(configuration) {
  const paths = workerPaths(configuration);
  for (const directory of [paths.root, paths.runRoot, paths.consumedTokens, paths.receipts]) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  return paths;
}

/**
 * Atomic single-use claim. `wx` fails if the token was already consumed, so a
 * replay cannot win a race with the original request.
 */
export function claimToken(paths, tokenId, nowMs) {
  const target = join(paths.consumedTokens, `${tokenId}.json`);
  try {
    writeFileSync(target, JSON.stringify({ tokenId, consumedAt: nowMs }), { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error && error.code === "EEXIST") throw new WorkerError(409, "TOKEN_REPLAY", "This launch token has already been used");
    throw error;
  }
}

function readJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return fallback;
  }
}

export function readAdmissions(paths) {
  const value = readJson(paths.admissionLog, null);
  if (value === null || !Array.isArray(value.admitted)) return { admitted: [] };
  return value;
}

export function recordAdmission(paths, runId, nowMs, dailyLimit) {
  const log = readAdmissions(paths);
  const dayAgo = nowMs - 24 * 60 * 60 * 1_000;
  const admitted = log.admitted.filter((entry) => entry.at > dayAgo);
  admitted.push({ runId, at: nowMs });
  writeFileSync(paths.admissionLog, JSON.stringify({ admitted }), { mode: 0o600 });
  return admitted.length <= dailyLimit;
}

export function admittedInLastDay(paths, nowMs) {
  const dayAgo = nowMs - 24 * 60 * 60 * 1_000;
  return readAdmissions(paths).admitted.filter((entry) => entry.at > dayAgo).length;
}

export function freeDiskBytes(root) {
  try {
    const stats = statfsSync(root);
    return Number(stats.bavail) * Number(stats.bsize);
  } catch {
    return 0;
  }
}

// ---------------------------------------------------------------- input validation

/**
 * Each interval is validated on its own. Participant A is never compared with
 * Participant B here: the worker must not be able to anticipate the circuit's
 * answer.
 */
export function assertLiveWindows(value) {
  if (!exactKeys(value, ["participantA", "participantB"])) {
    throw new WorkerError(400, "WINDOWS_SHAPE", "Exactly participantA and participantB are required");
  }
  const windows = {};
  for (const role of ["participantA", "participantB"]) {
    const entry = value[role];
    if (!exactKeys(entry, ["activeFrom", "activeUntil"])) {
      throw new WorkerError(400, "WINDOW_SHAPE", `${role} must carry exactly activeFrom and activeUntil`);
    }
    for (const bound of ["activeFrom", "activeUntil"]) {
      const raw = entry[bound];
      if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < 0 || Object.is(raw, -0)) {
        throw new WorkerError(400, "WINDOW_VALUE", `${role} ${bound} must be a non-negative safe integer`);
      }
    }
    if (entry.activeFrom >= entry.activeUntil) {
      throw new WorkerError(400, "WINDOW_ORDER", `${role} activeFrom must be strictly before activeUntil`);
    }
    windows[role] = { activeFrom: entry.activeFrom, activeUntil: entry.activeUntil };
  }
  return windows;
}

// ---------------------------------------------------------------- safe projections

export function healthBody(state) {
  return {
    schemaVersion: WORKER_SCHEMA,
    status: state.ready ? "READY" : "UNAVAILABLE",
    worker: state.busy ? "BUSY" : "IDLE",
    acceptingCases: state.accepting,
    diskSufficient: state.diskSufficient,
    version: state.version,
  };
}

/**
 * The only case projection the public ever receives. It is the engine's own
 * strict custom V2 view plus a bounded progress label; nothing is added that
 * could imply an outcome before governed release.
 */
export function liveCaseBody(view, progress) {
  return {
    schemaVersion: WORKER_SCHEMA,
    view,
    progress,
  };
}

export const LIVE_STAGES = Object.freeze({
  CASE_CREATED: "Case authorized",
  MATCH_PREPARED: "Private encryption prepared",
  PARTICIPANT_A_SUBMITTED: "Participant A encrypted",
  PARTICIPANT_B_PUBLISHED: "Participant B encrypted",
  PARTICIPANT_B_SUBMITTED: "Participant B encrypted",
  EVALUATED: "Encrypted evaluation running",
  RELEASED: "Governed result verification",
  RECOURSE_OPENED: "Recourse application",
  CHRONOLOGY_COMPLETE: "Recourse application",
  COMPLETE: "Receipt sealed",
  ABORTED: "Execution stopped",
});

export function progressFor(stage) {
  return LIVE_STAGES[stage] ?? "Private evaluation in progress";
}

// ---------------------------------------------------------------- fixed journey

/**
 * The one journey a public visitor can cause. There is no operation selection:
 * the sequence is fixed here, and step 8 is conditional only on the governed
 * signed Boolean the engine already produced.
 */
export async function runFixedJourney(orchestrator, runId, onStage) {
  await onStage(await orchestrator.preparePrivateMatch(runId));
  await onStage(await orchestrator.submitParticipantPledge(runId, "PARTICIPANT_A"));
  await onStage(await orchestrator.submitParticipantPledge(runId, "PARTICIPANT_B"));
  await onStage(await orchestrator.evaluatePrivateConflict(runId));
  const released = await orchestrator.releaseGovernedResult(runId);
  await onStage(released);
  await onStage(await orchestrator.openRecourseCase(runId));
  // Only a true governed Boolean opens a cure chronology. This reads the
  // engine's released result, never an anticipated one.
  const custom = await orchestrator.readCustomSupervisedCase(runId);
  if (custom.governedResult?.conflict === true) {
    await onStage(await orchestrator.completeCureChronology(runId));
  }
  await onStage(await orchestrator.exportProtectionEvidence(runId));
  return orchestrator.readCustomSupervisedCase(runId);
}

/**
 * After a receipt is verified, the large reproducible cryptographic artifacts
 * are no longer needed to present or verify the terminal result. The receipt,
 * the compact journal and the execution record are preserved.
 */
export function pruneReproducibleArtifacts(runRoot, runId) {
  const removed = [];
  for (const directory of ["public", "decryptor-private", "participant-private"]) {
    const target = join(runRoot, runId, directory);
    if (existsSync(target)) {
      rmSync(target, { recursive: true, force: true });
      removed.push(directory);
    }
  }
  return removed;
}

export function retainedReceiptRunIds(runRoot) {
  if (!existsSync(runRoot)) return [];
  return readdirSync(runRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && RUN_ID.test(entry.name))
    .filter((entry) => existsSync(join(runRoot, entry.name, "custom-supervised-receipt.json")))
    .map((entry) => entry.name);
}

// ---------------------------------------------------------------- http surface

function send(response, status, body) {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  response.end(encoded);
}

async function readBoundedBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new WorkerError(413, "BODY_SIZE", "Request body is too large");
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(raw);
  } catch {
    throw new WorkerError(400, "BODY_JSON", "An exact JSON body is required");
  }
}

export function assertAllowedOrigin(request, configuration) {
  const origin = request.headers.origin;
  if (typeof origin !== "string" || origin !== configuration.allowedOrigin) {
    throw new WorkerError(403, "ORIGIN", "Request origin rejected");
  }
}

export function createLiveWorker(options) {
  const configuration = options.configuration;
  const paths = ensureWorkerLayout(configuration);
  const createOrchestrator = options.createOrchestrator;
  const now = options.now ?? (() => Date.now());

  const state = {
    busy: false,
    draining: false,
    activeRunId: null,
    lastCompletedAt: 0,
    lastView: new Map(),
    lastProgress: new Map(),
  };

  function diskSufficient() {
    return freeDiskBytes(paths.root) >= configuration.diskFloorBytes;
  }

  function accepting(nowMs) {
    return !state.draining
      && !state.busy
      && diskSufficient()
      && nowMs - state.lastCompletedAt >= configuration.cooldownMs
      && admittedInLastDay(paths, nowMs) < configuration.dailyCaseLimit;
  }

  async function persistStage(runId, view) {
    state.lastView.set(runId, view);
    state.lastProgress.set(runId, progressFor(view.stage));
  }

  async function admitCase(windows, nowMs) {
    const orchestrator = createOrchestrator();
    const runId = randomUUID();
    const created = await orchestrator.createProtectionCase("conflict", runId, windows);
    if (created.runId !== runId) throw new WorkerError(500, "RUN_ID", "Case creation did not bind the generated run identifier");
    const view = await orchestrator.readCustomSupervisedCase(runId);
    await persistStage(runId, view);
    state.busy = true;
    state.activeRunId = runId;

    // The journey continues in the background; the visitor polls for progress.
    void (async () => {
      const started = now();
      try {
        const terminal = await runFixedJourney(orchestrator, runId, (next) => persistStage(runId, next));
        if (terminal.receipt === null) throw new WorkerError(500, "RECEIPT", "Terminal receipt is missing");
        const pruned = pruneReproducibleArtifacts(paths.runRoot, runId);
        await persistStage(runId, terminal);
        state.lastProgress.set(runId, progressFor("COMPLETE"));
        options.onComplete?.({ runId, pruned, durationMs: now() - started });
      } catch (error) {
        state.lastProgress.set(runId, "Execution stopped");
        options.onError?.({ runId, error });
      } finally {
        state.busy = false;
        state.activeRunId = null;
        state.lastCompletedAt = now();
      }
    })();
    return { runId, view };
  }

  async function handle(request, response) {
    const nowMs = now();
    const url = new URL(request.url ?? "/", "http://worker.invalid");

    if (request.method === "GET" && url.pathname === "/health") {
      return send(response, 200, healthBody({
        ready: !state.draining,
        busy: state.busy,
        accepting: accepting(nowMs),
        diskSufficient: diskSufficient(),
        version: configuration.version,
      }));
    }

    if (request.method === "POST" && url.pathname === "/v1/custom-cases") {
      if (url.search !== "") throw new WorkerError(400, "QUERY", "Query parameters are not accepted");
      assertAllowedOrigin(request, configuration);
      const contentType = String(request.headers["content-type"] ?? "");
      if (!contentType.startsWith("application/json")) throw new WorkerError(415, "CONTENT_TYPE", "application/json is required");
      const authorization = String(request.headers.authorization ?? "");
      if (!authorization.startsWith("Bearer ")) throw new WorkerError(401, "TOKEN_FORMAT", "A launch token is required");
      const claims = verifyLaunchToken(authorization.slice(7), configuration, nowMs);
      if (state.draining) throw new WorkerError(503, "DRAINING", "The worker is shutting down");
      if (state.busy) throw new WorkerError(409, "BUSY", "A private check is currently running");
      if (!diskSufficient()) throw new WorkerError(507, "DISK", "Insufficient durable storage for a new case");
      if (nowMs - state.lastCompletedAt < configuration.cooldownMs) throw new WorkerError(429, "COOLDOWN", "The next execution slot is not open yet");
      if (admittedInLastDay(paths, nowMs) >= configuration.dailyCaseLimit) throw new WorkerError(429, "DAILY_LIMIT", "The daily execution limit has been reached");
      const body = await readBoundedBody(request);
      const windows = assertLiveWindows(body);
      // Claimed only once every other precondition holds, so a refused request
      // does not burn the visitor's token.
      claimToken(paths, claims.tokenId, nowMs);
      recordAdmission(paths, claims.tokenId, nowMs, configuration.dailyCaseLimit);
      const admitted = await admitCase(windows, nowMs);
      return send(response, 201, liveCaseBody(admitted.view, progressFor(admitted.view.stage)));
    }

    if (request.method === "GET" && url.pathname.startsWith("/v1/custom-cases/")) {
      const runId = url.pathname.slice("/v1/custom-cases/".length);
      if (!RUN_ID.test(runId)) throw new WorkerError(404, "RUN_ID", "Unknown case");
      const orchestrator = createOrchestrator();
      try {
        const view = await orchestrator.readCustomSupervisedCase(runId);
        state.lastView.set(runId, view);
        return send(response, 200, liveCaseBody(view, progressFor(view.stage)));
      } catch (error) {
        // While an engine operation holds the run, the last durably observed
        // view is the honest answer. It is never fabricated.
        const cached = state.lastView.get(runId);
        if (cached !== undefined) return send(response, 200, liveCaseBody(cached, state.lastProgress.get(runId) ?? progressFor(cached.stage)));
        throw error instanceof WorkerError ? error : new WorkerError(404, "UNKNOWN_CASE", "Unknown case");
      }
    }

    throw new WorkerError(404, "ROUTE", "Unknown route");
  }

  const server = createServer((request, response) => {
    handle(request, response).catch((error) => {
      const status = error instanceof WorkerError ? error.status : (error?.status ?? 500);
      const code = error instanceof WorkerError ? error.code : "WORKER";
      const message = error instanceof WorkerError ? error.message : "The execution service refused the request";
      send(response, status, { schemaVersion: WORKER_SCHEMA, error: message, code });
    });
  });

  return Object.freeze({
    server,
    paths,
    configuration,
    state,
    drain: () => { state.draining = true; },
    isBusy: () => state.busy,
  });
}

// ---------------------------------------------------------------- entry point

/**
 * Startup reconciliation never invents completion. It only reports what the
 * durable journal already proves, and leaves anything ambiguous visible as an
 * unavailable case rather than guessing.
 */
export function reconcileOnStartup(paths) {
  const receipts = retainedReceiptRunIds(paths.runRoot);
  const runs = existsSync(paths.runRoot)
    ? readdirSync(paths.runRoot, { withFileTypes: true }).filter((e) => e.isDirectory() && RUN_ID.test(e.name)).map((e) => e.name)
    : [];
  return { retainedReceipts: receipts.length, durableRuns: runs.length, incomplete: runs.filter((r) => !receipts.includes(r)) };
}

async function main() {
  const configuration = readWorkerConfiguration(process.env);
  const paths = ensureWorkerLayout(configuration);
  // The engine writes every durable artifact below the attached volume.
  process.env.MORDANT_PROTECTION_RUN_ROOT = paths.runRoot;
  process.env.MORDANT_PROTECTION_RETENTION_ROOT = paths.receipts;

  const engine = await import("../.product-test-dist/src/lib/protection/governed-fhe-product-server.js");
  const summary = reconcileOnStartup(paths);
  process.stdout.write(`${JSON.stringify({ event: "startup", ...summary, version: configuration.version })}\n`);

  const worker = createLiveWorker({
    configuration,
    createOrchestrator: () => engine.createProtectionOrchestrator(),
    onComplete: (result) => process.stdout.write(`${JSON.stringify({ event: "case-complete", ...result })}\n`),
    onError: (result) => process.stderr.write(`${JSON.stringify({ event: "case-failed", runId: result.runId, code: result.error?.code ?? "ENGINE" })}\n`),
  });

  worker.server.listen(configuration.port, "0.0.0.0", () => {
    process.stdout.write(`${JSON.stringify({ event: "listening", port: configuration.port })}\n`);
  });

  // Railway sends SIGTERM before replacing the container. Stop admitting, let
  // any running engine operation finish its durable write, then exit.
  const shutdown = () => {
    worker.drain();
    process.stdout.write(`${JSON.stringify({ event: "draining", busy: worker.isBusy() })}\n`);
    worker.server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 20_000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (process.argv[1] && process.argv[1].endsWith("mordant-live-worker.mjs")) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({ event: "fatal", code: error?.code ?? "STARTUP", message: error?.message ?? "startup failed" })}\n`);
    process.exit(1);
  });
}
