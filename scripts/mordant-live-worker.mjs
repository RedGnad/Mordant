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
/**
 * An admission body carries a typed authorization and a wallet signature, which
 * are larger than a pair of integers but still bounded. An ERC-1271 signature can
 * exceed 65 bytes, so the allowance is generous without being open-ended.
 */
const ADMISSION_BODY_BYTES = 8_192;
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
    // How long a neutral case waits for its second participant. Two people using
    // two wallets need longer than one operator filling in a form.
    participantCaseLifetimeMs: positiveIntEnv(environment, "MORDANT_WORKER_PARTICIPANT_CASE_LIFETIME_MS", 30 * 60 * 1_000),
    chainId: positiveIntEnv(environment, "MORDANT_WORKER_CHAIN_ID", 10_143),
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
    /** Durable creation time per case, so abandonment is measured, not guessed. */
    caseClock: join(root, "case-clock"),
  });
}

/**
 * A case's creation instant, recorded once and read back after any restart.
 *
 * Abandonment has to survive a container replacement, so it cannot be derived
 * from in-memory state. `wx` keeps the first value: a restart never resets a
 * case's clock and so never silently extends its life.
 */
export function recordCaseStart(paths, runId, nowMs) {
  const target = join(paths.caseClock, `${runId}.json`);
  try {
    writeFileSync(target, JSON.stringify({ runId, createdAtUnix: Math.floor(nowMs / 1_000) }), { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (!error || error.code !== "EEXIST") throw error;
  }
  return readCaseStart(paths, runId, nowMs);
}

export function readCaseStart(paths, runId, nowMs) {
  const record = readJson(join(paths.caseClock, `${runId}.json`), null);
  const stored = record === null ? null : record.createdAtUnix;
  return Number.isSafeInteger(stored) && stored > 0 ? stored : Math.floor(nowMs / 1_000);
}

export function ensureWorkerLayout(configuration) {
  const paths = workerPaths(configuration);
  for (const directory of [paths.root, paths.runRoot, paths.consumedTokens, paths.receipts, paths.caseClock]) {
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

/**
 * The only participant-case projection the public receives.
 *
 * It is the engine's own strict custom V2 view plus the admission ledger's own
 * public-safe projection. Wallet addresses appear because a participant has to be
 * able to see that the other role is a different wallet; no interval, no
 * commitment preimage and nothing implying an outcome appears.
 */
export function participantCaseBody(view, admission) {
  return {
    schemaVersion: WORKER_SCHEMA,
    view,
    admission,
    progress: progressFor(view.stage),
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
  // Engine operations return the V1 product view, which carries a placeholder
  // productScenario and no terminalScenario. That must never reach a public
  // response, so after every step the custom V2 projection is read back and it
  // is that projection, and only that, which is cached and served.
  const step = async (operation) => {
    await operation();
    const view = await orchestrator.readCustomSupervisedCase(runId);
    await onStage(view);
    return view;
  };
  await step(() => orchestrator.preparePrivateMatch(runId));
  await step(() => orchestrator.submitParticipantPledge(runId, "PARTICIPANT_A"));
  await step(() => orchestrator.submitParticipantPledge(runId, "PARTICIPANT_B"));
  return finishJourney(orchestrator, runId, step);
}

/**
 * The remainder of the journey once both participants have admitted and each has
 * already published its own artifact.
 *
 * There is no submission step here: each wallet's claim was encrypted at its own
 * admission, so nothing is left for the coordinator to supply. Evaluation is
 * reached only because the engine itself reports both submissions finalized.
 */
export async function runPostAdmissionJourney(orchestrator, runId, onStage) {
  const step = async (operation) => {
    await operation();
    const view = await orchestrator.readCustomSupervisedCase(runId);
    await onStage(view);
    return view;
  };
  return finishJourney(orchestrator, runId, step);
}

async function finishJourney(orchestrator, runId, step) {
  await step(() => orchestrator.evaluatePrivateConflict(runId));
  await step(() => orchestrator.releaseGovernedResult(runId));
  const afterRecourse = await step(() => orchestrator.openRecourseCase(runId));
  // Only a released true Boolean opens a cure chronology, read from the engine's
  // own governed result and never anticipated.
  if (afterRecourse.governedResult?.conflict === true) {
    await step(() => orchestrator.completeCureChronology(runId));
  }
  return step(() => orchestrator.exportProtectionEvidence(runId));
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
  // The entered intervals are private execution input, whichever path supplied
  // them. They are needed only until both participant submissions are published,
  // so a terminal case keeps no copy on the volume. The receipt and the journal
  // never carried them, and the durable admission ledger keeps only commitments,
  // so the admissions themselves stay provable after this.
  const executionPath = join(runRoot, runId, "execution.json");
  if (existsSync(executionPath)) {
    const state = readJson(executionPath, null);
    let pruned = false;
    if (state !== null && state.supervisedPledgeWindows !== undefined) {
      delete state.supervisedPledgeWindows;
      pruned = true;
    }
    if (state !== null && state.admittedClaims !== undefined) {
      for (const role of Object.keys(state.admittedClaims)) {
        delete state.admittedClaims[role].claim;
      }
      pruned = true;
    }
    if (pruned) {
      writeFileSync(executionPath, JSON.stringify(state), { mode: 0o600 });
      removed.push("private-input");
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

/**
 * Cross-origin headers for the one browser origin this worker serves.
 *
 * The page runs on Vercel and posts here directly, so without these the browser blocks
 * the response before the origin allowlist is ever consulted. The configured origin is
 * echoed verbatim and never `*`: a wildcard would let any page read a run.
 */
function corsHeaders(requestOrigin, allowedOrigin) {
  if (allowedOrigin === null || requestOrigin !== allowedOrigin) return { vary: "Origin" };
  return {
    "access-control-allow-origin": allowedOrigin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function send(response, status, body, cors = {}) {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...cors,
  });
  response.end(encoded);
}

async function readBoundedBody(request, limit = MAX_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw new WorkerError(413, "BODY_SIZE", "Request body is too large");
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
    /** Cases awaiting their second participant. */
    openCases: new Set(),
    /** Cases whose post-admission journey is already running. */
    running: new Set(),
  };

  const admissionService = () => {
    if (options.admission === undefined) {
      throw new WorkerError(404, "ROUTE", "Participant admission is not configured");
    }
    return options.admission;
  };

  /**
   * One dependency set per request. A fresh orchestrator per request is the same
   * discipline the existing routes use: durable state, never in-memory state, is
   * what carries a case across requests and restarts.
   */
  const dependencies = () => {
    const service = admissionService();
    return {
      orchestrator: createOrchestrator(),
      runRoot: paths.runRoot,
      verifyingService: configuration.allowedOrigin,
      chainId: configuration.chainId,
      verifyApass: service.verifyApass,
      verifyTypedData: service.verifyTypedData,
      now: () => Math.floor(now() / 1_000),
      caseLifetimeSeconds: Math.floor(configuration.participantCaseLifetimeMs / 1_000),
    };
  };

  const readCaseStartFor = (caseCode, nowMs) => {
    const runId = admissionService().resolveCaseCode(paths.runRoot, caseCode);
    return runId === null ? Math.floor(nowMs / 1_000) : readCaseStart(paths, runId, nowMs);
  };

  function assertJsonRequest(request) {
    const contentType = String(request.headers["content-type"] ?? "");
    if (!contentType.startsWith("application/json")) {
      throw new WorkerError(415, "CONTENT_TYPE", "application/json is required");
    }
  }

  function bearer(request) {
    const authorization = String(request.headers.authorization ?? "");
    if (!authorization.startsWith("Bearer ")) throw new WorkerError(401, "TOKEN_FORMAT", "A launch token is required");
    return authorization.slice(7);
  }

  function assertAdmitting(nowMs) {
    if (state.draining) throw new WorkerError(503, "DRAINING", "The worker is shutting down");
    if (state.busy) throw new WorkerError(409, "BUSY", "A private check is currently running");
    if (!diskSufficient()) throw new WorkerError(507, "DISK", "Insufficient durable storage for a new case");
    if (nowMs - state.lastCompletedAt < configuration.cooldownMs) {
      throw new WorkerError(429, "COOLDOWN", "The next execution slot is not open yet");
    }
    if (admittedInLastDay(paths, nowMs) >= configuration.dailyCaseLimit) {
      throw new WorkerError(429, "DAILY_LIMIT", "The daily execution limit has been reached");
    }
    if (state.openCases.size >= configuration.maxActiveCases) {
      throw new WorkerError(409, "OPEN_CASE", "A case is already waiting for its participants");
    }
  }

  function beginPostAdmissionJourney(runId) {
    state.running.add(runId);
    state.busy = true;
    state.activeRunId = runId;
    state.openCases.delete(runId);
    void (async () => {
      const started = now();
      try {
        const terminal = await runPostAdmissionJourney(orchestratorFor(runId), runId, (next) => persistStage(runId, next));
        if (terminal?.receipt == null) throw new WorkerError(500, "RECEIPT", "Terminal receipt is missing");
        const pruned = pruneReproducibleArtifacts(paths.runRoot, runId);
        await persistStage(runId, terminal);
        state.lastProgress.set(runId, progressFor("COMPLETE"));
        options.onComplete?.({ runId, pruned, durationMs: now() - started });
      } catch (error) {
        state.lastProgress.set(runId, "Execution stopped");
        options.onError?.({ runId, error });
      } finally {
        state.running.delete(runId);
        state.busy = false;
        state.activeRunId = null;
        state.lastCompletedAt = now();
      }
    })();
  }

  const orchestratorFor = () => createOrchestrator();

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
        if (terminal?.receipt == null) throw new WorkerError(500, "RECEIPT", "Terminal receipt is missing");
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
    const cors = corsHeaders(request.headers.origin ?? null, configuration.allowedOrigin ?? null);

    // Preflight is answered for the known routes only, and never reveals which of them
    // currently holds a run.
    if (request.method === "OPTIONS") {
      const known = url.pathname === "/v1/custom-cases" || url.pathname.startsWith("/v1/custom-cases/")
        || url.pathname === "/v1/participant-cases" || url.pathname.startsWith("/v1/participant-cases/")
        || url.pathname === "/health";
      if (!known) throw new WorkerError(404, "ROUTE", "Unknown route");
      response.writeHead(204, { "cache-control": "no-store, max-age=0", ...cors });
      response.end();
      return undefined;
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return send(response, 200, healthBody({
        ready: !state.draining,
        busy: state.busy,
        accepting: accepting(nowMs),
        diskSufficient: diskSufficient(),
        version: configuration.version,
      }), cors);
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
      return send(response, 201, liveCaseBody(admitted.view, progressFor(admitted.view.stage)), cors);
    }

    // ---------------------------------------------------------- participant admission
    //
    // The two-wallet path. A neutral case is created with no private input at
    // all, then each A-Pass-eligible wallet signs and submits only its own claim.
    // There is no operation selector on any of these routes: the role is a closed
    // two-value member, and every other step is decided by durable state.

    if (request.method === "POST" && url.pathname === "/v1/participant-cases") {
      if (url.search !== "") throw new WorkerError(400, "QUERY", "Query parameters are not accepted");
      assertAllowedOrigin(request, configuration);
      assertJsonRequest(request);
      const claims = verifyLaunchToken(bearer(request), configuration, nowMs);
      assertAdmitting(nowMs);
      const body = await readBoundedBody(request);
      // A neutral case carries nothing. An empty object is the whole body.
      if (!exactKeys(body, [])) throw new WorkerError(400, "BODY_MEMBERS", "A neutral case takes no members");
      claimToken(paths, claims.tokenId, nowMs);
      recordAdmission(paths, claims.tokenId, nowMs, configuration.dailyCaseLimit);
      const created = await admissionService().createParticipantCase(dependencies());
      recordCaseStart(paths, created.runId, nowMs);
      state.lastView.set(created.runId, created.view);
      state.lastProgress.set(created.runId, progressFor(created.view.stage));
      state.openCases.add(created.runId);
      return send(response, 201, participantCaseBody(created.view, created.admission), cors);
    }

    if (request.method === "GET" && url.pathname.startsWith("/v1/participant-cases/")) {
      const caseCode = url.pathname.slice("/v1/participant-cases/".length);
      const readback = await admissionService().readParticipantCase(
        dependencies(), caseCode, readCaseStartFor(caseCode, nowMs),
      );
      return send(response, 200, participantCaseBody(readback.view, readback.admission), cors);
    }

    if (request.method === "POST" && url.pathname.endsWith("/challenge")
      && url.pathname.startsWith("/v1/participant-cases/")) {
      if (url.search !== "") throw new WorkerError(400, "QUERY", "Query parameters are not accepted");
      assertAllowedOrigin(request, configuration);
      assertJsonRequest(request);
      const caseCode = url.pathname.slice("/v1/participant-cases/".length, -"/challenge".length);
      const body = await readBoundedBody(request);
      if (!exactKeys(body, ["role", "participantWallet", "claim"])) {
        throw new WorkerError(400, "BODY_MEMBERS", "The challenge members are not exact");
      }
      // The nonce and both timestamps are server-issued, so a browser cannot
      // choose its own replay window.
      const challenge = await admissionService().participantAdmissionChallenge(
        dependencies(), caseCode, body.role, body.participantWallet, body.claim,
      );
      return send(response, 200, { schemaVersion: WORKER_SCHEMA, challenge }, cors);
    }

    if (request.method === "POST" && url.pathname.endsWith("/admissions")
      && url.pathname.startsWith("/v1/participant-cases/")) {
      if (url.search !== "") throw new WorkerError(400, "QUERY", "Query parameters are not accepted");
      assertAllowedOrigin(request, configuration);
      assertJsonRequest(request);
      if (!diskSufficient()) throw new WorkerError(507, "DISK", "Insufficient durable storage");
      const caseCode = url.pathname.slice("/v1/participant-cases/".length, -"/admissions".length);
      const body = await readBoundedBody(request, ADMISSION_BODY_BYTES);
      const service = admissionService();
      const admitted = await service.admitParticipant(
        dependencies(),
        service.assertAdmissionRequest({ ...body, caseCode }),
        readCaseStartFor(caseCode, nowMs),
      );
      state.lastView.set(admitted.runId, admitted.view);
      state.lastProgress.set(admitted.runId, progressFor(admitted.view.stage));
      // Both roles present: the remainder of the journey is reachable and starts
      // now. It is never started with one participant, because the engine itself
      // refuses evaluation until both submissions are finalized.
      if (admitted.admission.bothAdmitted && !state.running.has(admitted.runId)) {
        beginPostAdmissionJourney(admitted.runId);
      }
      return send(response, admitted.newlyAdmitted ? 201 : 200, {
        schemaVersion: WORKER_SCHEMA,
        role: admitted.role,
        participantWallet: admitted.participantWallet,
        eligibilityBlock: admitted.eligibilityBlock,
        newlyAdmitted: admitted.newlyAdmitted,
        view: admitted.view,
        admission: admitted.admission,
        progress: progressFor(admitted.view.stage),
      }, cors);
    }

    if (request.method === "GET" && url.pathname.startsWith("/v1/custom-cases/")) {
      const runId = url.pathname.slice("/v1/custom-cases/".length);
      if (!RUN_ID.test(runId)) throw new WorkerError(404, "RUN_ID", "Unknown case");
      const orchestrator = createOrchestrator();
      try {
        const view = await orchestrator.readCustomSupervisedCase(runId);
        state.lastView.set(runId, view);
        return send(response, 200, liveCaseBody(view, progressFor(view.stage)), cors);
      } catch (error) {
        // While an engine operation holds the run, the last durably observed
        // view is the honest answer. It is never fabricated.
        const cached = state.lastView.get(runId);
        if (cached !== undefined) return send(response, 200, liveCaseBody(cached, state.lastProgress.get(runId) ?? progressFor(cached.stage)), cors);
        throw error instanceof WorkerError ? error : new WorkerError(404, "UNKNOWN_CASE", "Unknown case");
      }
    }

    throw new WorkerError(404, "ROUTE", "Unknown route");
  }

  const server = createServer((request, response) => {
    handle(request, response).catch((error) => {
      // A typed admission refusal already says exactly what is wrong and carries
      // no private value; anything else collapses to a generic refusal so an
      // internal message can never reach a visitor.
      const admission = options.admission?.admissionFailure?.(error);
      const typed = error instanceof WorkerError
        ? { status: error.status, code: error.code, message: error.message }
        : admission !== undefined && admission.code !== "ADMISSION"
          ? admission
          : { status: error?.status ?? 500, code: "WORKER", message: "The execution service refused the request" };
      send(response, typed.status, { schemaVersion: WORKER_SCHEMA, error: typed.message, code: typed.code },
        corsHeaders(request.headers.origin ?? null, configuration.allowedOrigin ?? null));
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
  const service = await import("../.product-test-dist/src/lib/protection/participant-admission-service.js");
  const store = await import("../.product-test-dist/src/lib/protection/participant-admission-store.js");
  const eligibility = await import("../.product-test-dist/src/lib/protection/ccp-eligibility.js");
  const verifier = await import("../.product-test-dist/src/lib/protection/participant-typed-data-verifier.js");
  const summary = reconcileOnStartup(paths);
  process.stdout.write(`${JSON.stringify({ event: "startup", ...summary, version: configuration.version })}\n`);

  // The compliance reader and the signature verifier are built once. Both refuse
  // to exist at all without a configured Monad RPC, so a misconfigured deployment
  // fails at startup rather than admitting someone on an unchecked policy.
  const reader = eligibility.createCcpReader();
  const admission = {
    ...service,
    resolveCaseCode: store.resolveCaseCode,
    verifyApass: (wallet) => eligibility.verifyCcpEligibility(wallet, reader),
    verifyTypedData: verifier.createMonadTypedDataVerifier(),
  };

  const worker = createLiveWorker({
    configuration,
    admission,
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
