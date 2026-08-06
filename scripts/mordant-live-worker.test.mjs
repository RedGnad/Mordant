import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

import {
  assertLiveWindows,
  claimToken,
  createLiveWorker,
  ensureWorkerLayout,
  healthBody,
  liveCaseBody,
  progressFor,
  pruneReproducibleArtifacts,
  readWorkerConfiguration,
  reconcileOnStartup,
  signLaunchToken,
  verifyLaunchToken,
  WorkerError,
} from "./mordant-live-worker.mjs";

const SECRET = "0123456789abcdef0123456789abcdef0123456789";
const AUDIENCE = "MORDANT_RAILWAY_WORKER";
const ORIGIN = "https://mordant-two.vercel.app";

function configuration(overrides = {}) {
  return readWorkerConfiguration({
    MORDANT_WORKER_DATA_ROOT: mkdtempSync(join(tmpdir(), "mordant-worker-")),
    MORDANT_WORKER_TOKEN_SECRET: SECRET,
    MORDANT_WORKER_TOKEN_AUDIENCE: AUDIENCE,
    MORDANT_WORKER_ALLOWED_ORIGIN: ORIGIN,
    MORDANT_WORKER_DISK_FLOOR_BYTES: "1024",
    MORDANT_WORKER_COOLDOWN_MS: "1",
    MORDANT_PROTECTION_SOURCE_COMMIT: "b5587f6489933c6dc462da7fda56e57bd5f9e31b",
    ...overrides,
  });
}

function token(nowMs, overrides = {}) {
  return signLaunchToken({
    tokenId: randomUUID(),
    issuedAt: nowMs,
    expiresAt: nowMs + 60_000,
    audience: AUDIENCE,
    action: "CREATE_CUSTOM_CASE",
    ...overrides,
  }, overrides.secret ?? SECRET);
}

const WINDOWS = {
  participantA: { activeFrom: 120, activeUntil: 420 },
  participantB: { activeFrom: 220, activeUntil: 520 },
};

// ------------------------------------------------------------------ token gate

test("a valid launch token is accepted, and every malformed variant is refused", () => {
  const config = configuration();
  const nowMs = 1_800_000_000_000;
  assert.equal(verifyLaunchToken(token(nowMs), config, nowMs).action, "CREATE_CUSTOM_CASE");

  const refusals = {
    TOKEN_EXPIRED: token(nowMs, { expiresAt: nowMs - 1 }),
    TOKEN_AUDIENCE: token(nowMs, { audience: "SOMETHING_ELSE" }),
    TOKEN_ACTION: token(nowMs, { action: "DELETE_EVERYTHING" }),
    TOKEN_LIFETIME: token(nowMs, { expiresAt: nowMs + 60 * 60 * 1_000 }),
    TOKEN_ID: token(nowMs, { tokenId: "not-a-uuid" }),
  };
  for (const [code, value] of Object.entries(refusals)) {
    assert.throws(() => verifyLaunchToken(value, config, nowMs),
      (error) => error instanceof WorkerError && error.code === code, `${code} must be refused`);
  }
  // A signature made with another secret must not verify.
  assert.throws(() => verifyLaunchToken(token(nowMs, { secret: "f".repeat(48) }), config, nowMs),
    (error) => error.code === "TOKEN_SIGNATURE");
  // Structural mangling.
  for (const bad of ["", "abc", "a.b.c", "notbase64.notbase64"]) {
    assert.throws(() => verifyLaunchToken(bad, config, nowMs), (error) => error instanceof WorkerError);
  }
  // An extra claim member is refused rather than ignored.
  const extra = signLaunchToken({ tokenId: randomUUID(), issuedAt: nowMs, expiresAt: nowMs + 1_000, audience: AUDIENCE, action: "CREATE_CUSTOM_CASE" }, SECRET);
  const [payload, signature] = extra.split(".");
  const widened = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  widened.scope = "everything";
  const forged = `${Buffer.from(JSON.stringify(widened)).toString("base64url")}.${signature}`;
  assert.throws(() => verifyLaunchToken(forged, config, nowMs), (error) => error instanceof WorkerError);
});

test("a launch token can be claimed exactly once", () => {
  const config = configuration();
  const paths = ensureWorkerLayout(config);
  const tokenId = randomUUID();
  claimToken(paths, tokenId, Date.now());
  assert.throws(() => claimToken(paths, tokenId, Date.now()),
    (error) => error instanceof WorkerError && error.code === "TOKEN_REPLAY");
});

// ------------------------------------------------------------------ input gate

test("only exact non-negative ordered windows are accepted, with no A/B comparison", () => {
  assert.deepEqual(assertLiveWindows(structuredClone(WINDOWS)), WINDOWS);
  // Disjoint windows are equally valid input: the worker must not judge them.
  assert.doesNotThrow(() => assertLiveWindows({
    participantA: { activeFrom: 120, activeUntil: 300 },
    participantB: { activeFrom: 420, activeUntil: 620 },
  }));
  const refusals = {
    WINDOWS_SHAPE: [null, [], "x", { participantA: WINDOWS.participantA }, { ...WINDOWS, participantC: WINDOWS.participantA }],
    WINDOW_SHAPE: [{ ...WINDOWS, participantB: { activeFrom: 1 } }, { ...WINDOWS, participantB: { activeFrom: 1, activeUntil: 2, note: "x" } }],
    WINDOW_VALUE: [
      { ...WINDOWS, participantB: { activeFrom: "220", activeUntil: 520 } },
      { ...WINDOWS, participantB: { activeFrom: 1.5, activeUntil: 520 } },
      { ...WINDOWS, participantB: { activeFrom: -1, activeUntil: 520 } },
      { ...WINDOWS, participantB: { activeFrom: null, activeUntil: 520 } },
      { ...WINDOWS, participantB: { activeFrom: 1, activeUntil: Number.MAX_SAFE_INTEGER + 2 } },
    ],
    WINDOW_ORDER: [{ ...WINDOWS, participantB: { activeFrom: 520, activeUntil: 520 } }],
  };
  for (const [code, values] of Object.entries(refusals)) {
    for (const value of values) {
      assert.throws(() => assertLiveWindows(value),
        (error) => error instanceof WorkerError && error.code === code,
        `${JSON.stringify(value)} must be refused with ${code}`);
    }
  }
});

// ------------------------------------------------------------------ safe output

test("health exposes no path, secret or run content", () => {
  const body = healthBody({ ready: true, busy: false, accepting: true, diskSufficient: true, version: "abc" });
  assert.deepEqual(Object.keys(body).sort(),
    ["acceptingCases", "diskSufficient", "schemaVersion", "status", "version", "worker"]);
  const encoded = JSON.stringify(body);
  for (const forbidden of ["/data", "/Users", "secret", "token", "runs"]) {
    assert.equal(encoded.includes(forbidden), false, `health leaked ${forbidden}`);
  }
});

test("a pre-release case body carries no outcome and no raw input", () => {
  const view = {
    schemaVersion: "mordant.custom-supervised-protection-view/1",
    runId: "11111111-1111-4111-8111-111111111111",
    executionVariant: "CUSTOM_SUPERVISED",
    stage: "MATCH_PREPARED", nextOperation: "submitParticipantPledge:PARTICIPANT_A",
    terminalScenario: null,
    protectionCase: {
      cleanverseAssetDigest: `sha256:${"a".repeat(64)}`, fheCaseId: `sha256:${"b".repeat(64)}`,
      incidentState: "PRIVATE_MATCH_OPEN", recourseState: "NOT_OPEN", cureDeadline: null,
    },
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null, governedResult: null, recourse: null, receipt: null,
  };
  const encoded = JSON.stringify(liveCaseBody(view, progressFor("MATCH_PREPARED")));
  for (const forbidden of ["120", "420", "220", "520", "activeFrom", "activeUntil", "productScenario", "conflict"]) {
    assert.equal(encoded.includes(forbidden), false, `pre-release body leaked ${forbidden}`);
  }
  assert.equal(JSON.parse(encoded).progress, "Private encryption prepared");
});

test("progress labels never anticipate an outcome", () => {
  for (const stage of ["CASE_CREATED", "MATCH_PREPARED", "PARTICIPANT_A_SUBMITTED", "PARTICIPANT_B_SUBMITTED", "EVALUATED"]) {
    const label = progressFor(stage);
    assert.equal(/conflict|cleared|refus/iu.test(label), false, `${stage} label anticipates an outcome: ${label}`);
  }
});

// ------------------------------------------------------------------ http surface

function mockEngineOrchestrator(behaviour) {
  const stages = [];
  const view = (stage, extra = {}) => ({
    schemaVersion: "mordant.custom-supervised-protection-view/1",
    runId: behaviour.runId, executionVariant: "CUSTOM_SUPERVISED",
    stage, nextOperation: null, terminalScenario: null,
    protectionCase: {
      cleanverseAssetDigest: `sha256:${"a".repeat(64)}`, fheCaseId: `sha256:${"b".repeat(64)}`,
      incidentState: "AUTHORIZED", recourseState: "NOT_OPEN", cureDeadline: null,
    },
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null, governedResult: null, recourse: null, receipt: null,
    ...extra,
  });
  return {
    stages,
    createProtectionCase: async (_s, runId) => { behaviour.runId = runId; stages.push("create"); return { runId }; },
    readCustomSupervisedCase: async () => view("CASE_CREATED"),
    preparePrivateMatch: async () => { stages.push("prepare"); return view("MATCH_PREPARED"); },
    submitParticipantPledge: async () => { stages.push("submit"); return view("PARTICIPANT_A_SUBMITTED"); },
    evaluatePrivateConflict: async () => { stages.push("evaluate"); return view("EVALUATED"); },
    releaseGovernedResult: async () => { stages.push("release"); return view("RELEASED"); },
    openRecourseCase: async () => { stages.push("recourse"); return view("RECOURSE_OPENED"); },
    completeCureChronology: async () => { stages.push("chronology"); return view("CHRONOLOGY_COMPLETE"); },
    exportProtectionEvidence: async () => { stages.push("export"); return view("COMPLETE"); },
  };
}

async function withWorker(config, orchestrator, run) {
  const worker = createLiveWorker({ configuration: config, createOrchestrator: () => orchestrator });
  worker.server.listen(0, "127.0.0.1");
  await once(worker.server, "listening");
  const { port } = worker.server.address();
  try {
    await run(`http://127.0.0.1:${port}`, worker);
  } finally {
    worker.server.close();
    await once(worker.server, "close");
  }
}

test("the public surface exposes exactly three routes", async () => {
  const config = configuration();
  const orchestrator = mockEngineOrchestrator({});
  await withWorker(config, orchestrator, async (base) => {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    for (const path of ["/", "/v1", "/admin", "/v1/custom-cases/../etc", "/api/protection/conflicting-pledge"]) {
      const response = await fetch(`${base}${path}`);
      assert.equal(response.status, 404, `${path} must not be routable`);
    }
  });
});

test("creation requires the exact origin, content type and a valid token", async () => {
  const config = configuration();
  const orchestrator = mockEngineOrchestrator({});
  await withWorker(config, orchestrator, async (base) => {
    const good = {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: JSON.stringify(WINDOWS),
    };
    // Wrong origin.
    let response = await fetch(`${base}/v1/custom-cases`, { ...good, headers: { ...good.headers, origin: "https://evil.example" } });
    assert.equal(response.status, 403);
    // Missing origin.
    const { origin: _o, ...noOrigin } = good.headers;
    response = await fetch(`${base}/v1/custom-cases`, { ...good, headers: noOrigin });
    assert.equal(response.status, 403);
    // Wrong content type.
    response = await fetch(`${base}/v1/custom-cases`, { ...good, headers: { ...good.headers, "content-type": "text/plain" } });
    assert.equal(response.status, 415);
    // Missing token.
    const { authorization: _a, ...noToken } = good.headers;
    response = await fetch(`${base}/v1/custom-cases`, { ...good, headers: noToken });
    assert.equal(response.status, 401);
    // Query parameters.
    response = await fetch(`${base}/v1/custom-cases?x=1`, good);
    assert.equal(response.status, 400);
    // Unknown JSON members.
    response = await fetch(`${base}/v1/custom-cases`, {
      ...good,
      headers: { ...good.headers, authorization: `Bearer ${token(Date.now())}` },
      body: JSON.stringify({ ...WINDOWS, extra: 1 }),
    });
    assert.equal(response.status, 400);
  });
});

test("a token is single use across requests, and a replay is refused", async () => {
  const config = configuration();
  const orchestrator = mockEngineOrchestrator({});
  await withWorker(config, orchestrator, async (base) => {
    const reused = token(Date.now());
    const headers = { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${reused}` };
    const first = await fetch(`${base}/v1/custom-cases`, { method: "POST", headers, body: JSON.stringify(WINDOWS) });
    assert.equal(first.status, 201);
    const replay = await fetch(`${base}/v1/custom-cases`, { method: "POST", headers, body: JSON.stringify(WINDOWS) });
    // Either the replay is refused as already consumed, or the single active
    // case guard refuses it first. Both are correct; neither admits a case.
    assert.ok([409, 429].includes(replay.status), `replay returned ${replay.status}`);
  });
});

test("a second concurrent case receives BUSY and no parallel evaluation starts", async () => {
  const config = configuration();
  let releaseGate;
  const gate = new Promise((resolve) => { releaseGate = resolve; });
  const orchestrator = mockEngineOrchestrator({});
  const slowPrepare = orchestrator.preparePrivateMatch;
  orchestrator.preparePrivateMatch = async (runId) => { await gate; return slowPrepare(runId); };
  await withWorker(config, orchestrator, async (base) => {
    const headers = () => ({ origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` });
    const first = await fetch(`${base}/v1/custom-cases`, { method: "POST", headers: headers(), body: JSON.stringify(WINDOWS) });
    assert.equal(first.status, 201);
    const second = await fetch(`${base}/v1/custom-cases`, { method: "POST", headers: headers(), body: JSON.stringify(WINDOWS) });
    assert.equal(second.status, 409);
    assert.equal((await second.json()).code, "BUSY");
    const health = await (await fetch(`${base}/health`)).json();
    assert.equal(health.worker, "BUSY");
    assert.equal(health.acceptingCases, false);
    releaseGate();
  });
});

test("the daily limit and the disk floor both refuse admission", async () => {
  const limited = configuration({ MORDANT_WORKER_DAILY_CASE_LIMIT: "1" });
  const orchestrator = mockEngineOrchestrator({});
  await withWorker(limited, orchestrator, async (base) => {
    const headers = () => ({ origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` });
    assert.equal((await fetch(`${base}/v1/custom-cases`, { method: "POST", headers: headers(), body: JSON.stringify(WINDOWS) })).status, 201);
    await new Promise((resolve) => setTimeout(resolve, 60));
    const second = await fetch(`${base}/v1/custom-cases`, { method: "POST", headers: headers(), body: JSON.stringify(WINDOWS) });
    assert.equal(second.status, 429);
    assert.equal((await second.json()).code, "DAILY_LIMIT");
  });

  const starved = configuration({ MORDANT_WORKER_DISK_FLOOR_BYTES: String(Number.MAX_SAFE_INTEGER) });
  await withWorker(starved, mockEngineOrchestrator({}), async (base) => {
    const response = await fetch(`${base}/v1/custom-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: JSON.stringify(WINDOWS),
    });
    assert.equal(response.status, 507);
    assert.equal((await response.json()).code, "DISK");
  });
});

test("a draining worker admits nothing", async () => {
  const config = configuration();
  await withWorker(config, mockEngineOrchestrator({}), async (base, worker) => {
    worker.drain();
    const response = await fetch(`${base}/v1/custom-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: JSON.stringify(WINDOWS),
    });
    assert.equal(response.status, 503);
    assert.equal((await (await fetch(`${base}/health`)).json()).status, "UNAVAILABLE");
  });
});

// ------------------------------------------------------------------ durability

test("pruning removes reproducible artifacts and preserves the receipt", () => {
  const config = configuration();
  const paths = ensureWorkerLayout(config);
  const runId = "11111111-1111-4111-8111-111111111111";
  const runDir = join(paths.runRoot, runId);
  for (const directory of ["public", "decryptor-private", "participant-private"]) {
    mkdirSync(join(runDir, directory), { recursive: true });
    writeFileSync(join(runDir, directory, "big.bin"), Buffer.alloc(1024));
  }
  writeFileSync(join(runDir, "custom-supervised-receipt.json"), JSON.stringify({ schemaVersion: "mordant.custom-supervised-protection-receipt/1" }));
  writeFileSync(join(runDir, "operation-journal.json"), JSON.stringify({ records: [] }));
  writeFileSync(join(runDir, "execution.json"), JSON.stringify({ stage: "COMPLETE" }));

  writeFileSync(join(runDir, "execution.json"), JSON.stringify({
    stage: "COMPLETE",
    executionVariant: "CUSTOM_SUPERVISED",
    supervisedPledgeWindows: { participantA: { activeFrom: 120, activeUntil: 420 }, participantB: { activeFrom: 220, activeUntil: 520 } },
  }));
  const removed = pruneReproducibleArtifacts(paths.runRoot, runId);
  assert.deepEqual(removed.sort(), ["decryptor-private", "participant-private", "private-input", "public"]);
  // The private operator input must not survive on the volume.
  const persisted = readFileSync(join(runDir, "execution.json"), "utf8");
  for (const forbidden of ["supervisedPledgeWindows", "activeFrom", "activeUntil", "120", "420", "220", "520"]) {
    assert.equal(persisted.includes(forbidden), false, `durable state kept ${forbidden}`);
  }
  assert.equal(JSON.parse(persisted).executionVariant, "CUSTOM_SUPERVISED");
  assert.equal(existsSync(join(runDir, "public")), false);
  // Everything needed to present and verify the terminal result survives.
  for (const kept of ["custom-supervised-receipt.json", "operation-journal.json", "execution.json"]) {
    assert.equal(existsSync(join(runDir, kept)), true, `${kept} must be preserved`);
  }
  assert.equal(JSON.parse(readFileSync(join(runDir, "custom-supervised-receipt.json"), "utf8")).schemaVersion,
    "mordant.custom-supervised-protection-receipt/1");

  const summary = reconcileOnStartup(paths);
  assert.equal(summary.retainedReceipts, 1);
  assert.deepEqual(summary.incomplete, []);
});

test("startup reconciliation reports an incomplete run instead of inventing completion", () => {
  const config = configuration();
  const paths = ensureWorkerLayout(config);
  const runId = "22222222-2222-4222-8222-222222222222";
  mkdirSync(join(paths.runRoot, runId), { recursive: true });
  writeFileSync(join(paths.runRoot, runId, "execution.json"), JSON.stringify({ stage: "EVALUATED" }));
  const summary = reconcileOnStartup(paths);
  assert.equal(summary.retainedReceipts, 0);
  assert.deepEqual(summary.incomplete, [runId]);
});

test("configuration is fail-closed", () => {
  const base = {
    MORDANT_WORKER_TOKEN_SECRET: SECRET,
    MORDANT_WORKER_TOKEN_AUDIENCE: AUDIENCE,
    MORDANT_WORKER_ALLOWED_ORIGIN: ORIGIN,
  };
  for (const [name, broken] of Object.entries({
    "missing secret": { ...base, MORDANT_WORKER_TOKEN_SECRET: undefined },
    "short secret": { ...base, MORDANT_WORKER_TOKEN_SECRET: "tooshort" },
    "missing audience": { ...base, MORDANT_WORKER_TOKEN_AUDIENCE: undefined },
    "missing origin": { ...base, MORDANT_WORKER_ALLOWED_ORIGIN: undefined },
    "non-https origin": { ...base, MORDANT_WORKER_ALLOWED_ORIGIN: "http://example.com" },
    "unparseable origin": { ...base, MORDANT_WORKER_ALLOWED_ORIGIN: "not a url" },
  })) {
    assert.throws(() => readWorkerConfiguration(broken), (error) => error instanceof WorkerError, `${name} must be refused`);
  }
});

test("the browser origin is allowed to read the worker across origins", async () => {
  // A curl-based gate cannot catch this: only a browser enforces CORS, and without these
  // headers the page fails before the origin allowlist is ever consulted.
  await withWorker(configuration(), mockEngineOrchestrator({}), async (base) => {
    const preflight = await fetch(`${base}/v1/custom-cases`, {
      method: "OPTIONS",
      headers: {
        origin: ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), ORIGIN);
    assert.match(preflight.headers.get("access-control-allow-methods") ?? "", /POST/u);
    assert.match(preflight.headers.get("access-control-allow-headers") ?? "", /authorization/iu);

    const health = await fetch(`${base}/health`, { headers: { origin: ORIGIN } });
    assert.equal(health.headers.get("access-control-allow-origin"), ORIGIN);

    // A refusal must stay readable, otherwise the page can only say "network error".
    const refused = await fetch(`${base}/v1/custom-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(refused.status, 401);
    assert.equal(refused.headers.get("access-control-allow-origin"), ORIGIN);
  });
});

test("an unknown origin is never granted cross-origin access", async () => {
  await withWorker(configuration(), mockEngineOrchestrator({}), async (base) => {
    for (const origin of ["https://evil.example", "null"]) {
      const preflight = await fetch(`${base}/v1/custom-cases`, {
        method: "OPTIONS",
        headers: { origin, "access-control-request-method": "POST" },
      });
      assert.equal(preflight.headers.get("access-control-allow-origin"), null);
      const health = await fetch(`${base}/health`, { headers: { origin } });
      assert.equal(health.headers.get("access-control-allow-origin"), null);
      assert.equal(health.headers.get("vary"), "Origin");
    }
  });
});

test("preflight on an unknown route is refused", async () => {
  await withWorker(configuration(), mockEngineOrchestrator({}), async (base) => {
    const preflight = await fetch(`${base}/nope`, {
      method: "OPTIONS",
      headers: { origin: ORIGIN, "access-control-request-method": "POST" },
    });
    assert.equal(preflight.status, 404);
  });
});
