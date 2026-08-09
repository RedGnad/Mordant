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
  recordCaseStart,
  readWorkerConfiguration,
  reconcileOnStartup,
  runFixedJourney,
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
    createManagedGovernedPolicyCase: async (runId) => { behaviour.runId = runId; stages.push("create"); return { runId }; },
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

test("the managed worker advances cure only from the plan-authorized recourse outcome", async () => {
  for (const opened of [true, false]) {
    const stages = [];
    let current = {
      governedResult: { conflict: true },
      recourse: null,
    };
    const orchestrator = {
      readCustomSupervisedCase: async () => current,
      preparePrivateMatch: async () => { stages.push("prepare"); },
      submitParticipantPledge: async () => { stages.push("submit"); },
      evaluatePrivateConflict: async () => { stages.push("evaluate"); },
      releaseGovernedResult: async () => { stages.push("release"); },
      openRecourseCase: async () => {
        stages.push("recourse");
        current = { ...current, recourse: { opened, reason: opened ? null : "SIGNED_RESULT_FALSE" } };
      },
      completeCureChronology: async () => { stages.push("chronology"); },
      exportProtectionEvidence: async () => { stages.push("export"); },
    };
    await runFixedJourney(orchestrator, "11111111-1111-4111-8111-111111111111", async () => {});
    assert.equal(stages.includes("chronology"), opened);
  }
});

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

test("pruning preserves the direct-participant bridge evidence and still removes private artifacts", () => {
  const config = configuration();
  const paths = ensureWorkerLayout(config);
  const runId = "22222222-2222-4222-8222-222222222222";
  const runDir = join(paths.runRoot, runId);
  for (const directory of ["public", "decryptor-private", "participant-private"]) {
    mkdirSync(join(runDir, directory), { recursive: true });
    writeFileSync(join(runDir, directory, "big.bin"), Buffer.alloc(1024));
  }
  // The signed governed result lives under public/ and is expendable precisely
  // because the bridge evidence carries a complete copy of it.
  writeFileSync(join(runDir, "public", "governed-conflict-result.json"), JSON.stringify({ conflict: true }));
  writeFileSync(join(runDir, "custom-supervised-receipt.json"), JSON.stringify({ schemaVersion: "mordant.custom-supervised-protection-receipt/1" }));
  writeFileSync(join(runDir, "operation-journal.json"), JSON.stringify({ records: [] }));
  const bridgeEvidence = {
    schemaVersion: "mordant.direct-participant-bridge-evidence/1",
    runId,
    governedResult: { conflict: true, signature: "signed" },
  };
  writeFileSync(join(runDir, "direct-participant-bridge-evidence.json"), JSON.stringify(bridgeEvidence));
  mkdirSync(join(runDir, "admissions"), { recursive: true });
  writeFileSync(join(runDir, "admissions", "participant_a.json"), JSON.stringify({
    role: "PARTICIPANT_A", claimCommitment: "0x01", eligibilityBlock: 51_507_855,
  }));
  writeFileSync(join(runDir, "execution.json"), JSON.stringify({
    stage: "COMPLETE",
    executionVariant: "CUSTOM_SUPERVISED",
    admittedClaims: {
      PARTICIPANT_A: { participantWallet: "0xa", claim: { activeFrom: 777, activeUntil: 888 } },
      PARTICIPANT_B: { participantWallet: "0xb", claim: { activeFrom: 999, activeUntil: 1111 } },
    },
  }));

  const removed = pruneReproducibleArtifacts(paths.runRoot, runId);
  assert.deepEqual(removed.sort(), ["decryptor-private", "participant-private", "private-input", "public"]);

  // The bridge authorization survives, byte for byte.
  const retained = join(runDir, "direct-participant-bridge-evidence.json");
  assert.equal(existsSync(retained), true, "bridge evidence must survive pruning");
  assert.deepEqual(JSON.parse(readFileSync(retained, "utf8")), bridgeEvidence);
  // The durable admission ledger survives; the admitted intervals do not.
  assert.equal(existsSync(join(runDir, "admissions", "participant_a.json")), true);
  const persisted = readFileSync(join(runDir, "execution.json"), "utf8");
  for (const forbidden of ["activeFrom", "activeUntil", "777", "888", "999", "1111"]) {
    assert.equal(persisted.includes(forbidden), false, `durable state kept ${forbidden}`);
  }
  assert.equal(JSON.parse(persisted).admittedClaims.PARTICIPANT_A.participantWallet, "0xa");
  // Reproducible and private material is gone, including the raw signed result.
  assert.equal(existsSync(join(runDir, "public")), false);
  assert.equal(existsSync(join(runDir, "decryptor-private")), false);
  assert.equal(existsSync(join(runDir, "participant-private")), false);
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

// ------------------------------------------------------------------ participant admission

/**
 * The two-wallet surface.
 *
 * These tests drive the real HTTP routes against a stubbed admission service, so
 * what is under test is the worker's own contract: which routes exist, what they
 * refuse, and that a case is never carried forward on one participant.
 */

const WALLET_A = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02";
const WALLET_B = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0";
const CASE_CODE = "ABCDEFGH23456789";

function participantView(stage) {
  return {
    schemaVersion: "mordant.custom-supervised-protection-view/1",
    runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    executionVariant: "CUSTOM_SUPERVISED",
    stage, nextOperation: null, terminalScenario: null,
    protectionCase: {
      cleanverseAssetDigest: `sha256:${"a".repeat(64)}`, fheCaseId: `sha256:${"b".repeat(64)}`,
      incidentState: "PRIVATE_MATCH_OPEN", recourseState: "NOT_OPEN", cureDeadline: null,
    },
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null, governedResult: null, recourse: null, receipt: null,
  };
}

function projection(a, b) {
  return {
    schemaVersion: "mordant.participant-case/1",
    caseCode: CASE_CODE,
    runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    lifecycle: b ? "PARTICIPANT_B_ADMITTED" : a ? "PARTICIPANT_A_ADMITTED" : "MATCH_PREPARED",
    participantA: { admitted: a, wallet: a ? WALLET_A : null },
    participantB: { admitted: b, wallet: b ? WALLET_B : null },
    bothAdmitted: a && b,
    abandoned: false,
  };
}

function mockAdmission(overrides = {}) {
  const admitted = { a: false, b: false };
  const calls = { created: 0, admitted: [], challenges: 0 };
  return {
    calls,
    admittedState: admitted,
    resolveCaseCode: () => "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    verifyApass: async (wallet) => ({ eligible: true, holderAddress: wallet, observedBlock: 1 }),
    verifyTypedData: async () => true,
    admissionFailure: (error) => (
      error?.name === "ParticipantAdmissionError"
        ? { status: error.status, code: error.code, message: error.message }
        : { status: 500, code: "ADMISSION", message: "Participant admission failed" }
    ),
    assertAdmissionRequest: (body) => body,
    createParticipantCase: async (dependencies) => {
      calls.created += 1;
      const created = {
        runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        caseCode: CASE_CODE,
        view: participantView("MATCH_PREPARED"),
        admission: projection(false, false),
      };
      await dependencies.onParticipantCaseCreated?.({ runId: created.runId, caseCode: created.caseCode });
      return created;
    },
    readParticipantCase: async () => ({
      runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", caseCode: CASE_CODE,
      view: participantView("MATCH_PREPARED"), admission: projection(admitted.a, admitted.b),
    }),
    participantAdmissionChallenge: async () => {
      calls.challenges += 1;
      return { schemaVersion: "mordant.participant-admission-challenge/1", domain: {}, primaryType: "ParticipantAdmissionV1", types: {}, message: {} };
    },
    admitParticipant: async (_deps, request) => {
      calls.admitted.push(request.role);
      if (request.role === "PARTICIPANT_A") admitted.a = true; else admitted.b = true;
      return {
        runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", caseCode: CASE_CODE, role: request.role,
        participantWallet: request.role === "PARTICIPANT_A" ? WALLET_A : WALLET_B,
        eligibilityBlock: 1, newlyAdmitted: true,
        view: participantView(request.role === "PARTICIPANT_A" ? "PARTICIPANT_A_SUBMITTED" : "PARTICIPANT_B_SUBMITTED"),
        admission: projection(admitted.a, admitted.b),
      };
    },
    ...overrides,
  };
}

async function withParticipantWorker(config, orchestrator, admission, run) {
  const worker = createLiveWorker({ configuration: config, createOrchestrator: () => orchestrator, admission });
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

function participantConfiguration(overrides = {}) {
  return configuration({
    MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION: "enabled",
    MORDANT_WORKER_DIRECT_PARTICIPANT_ADMISSION_ACK: "MORDANT_PARTICIPANT_ADMISSION_V1",
    ...overrides,
  });
}

function admissionBody(role) {
  return JSON.stringify({
    role,
    authorization: { role },
    signature: `0x${"ab".repeat(65)}`,
    claim: { activeFrom: 120, activeUntil: 420 },
  });
}

test("a neutral case is created with an empty body and no windows", async () => {
  const config = participantConfiguration();
  const admission = mockAdmission();
  await withParticipantWorker(config, mockEngineOrchestrator({}), admission, async (base) => {
    const response = await fetch(`${base}/v1/participant-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: "{}",
    });
    assert.equal(response.status, 201);
    const body = await response.json();
    assert.equal(body.admission.bothAdmitted, false);
    assert.equal(admission.calls.created, 1);
    // No interval reaches this route at all.
    assert.equal(JSON.stringify(body).includes("activeFrom"), false);
  });
});

test("a neutral case refuses any body member", async () => {
  const config = participantConfiguration();
  await withParticipantWorker(config, mockEngineOrchestrator({}), mockAdmission(), async (base) => {
    const response = await fetch(`${base}/v1/participant-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: JSON.stringify(WINDOWS),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, "BODY_MEMBERS");
  });
});

test("participant routes require the exact origin and content type", async () => {
  const config = participantConfiguration();
  await withParticipantWorker(config, mockEngineOrchestrator({}), mockAdmission(), async (base) => {
    const url = `${base}/v1/participant-cases/${CASE_CODE}/admissions`;
    let response = await fetch(url, {
      method: "POST",
      headers: { origin: "https://evil.example", "content-type": "application/json" },
      body: admissionBody("PARTICIPANT_A"),
    });
    assert.equal(response.status, 403);
    response = await fetch(url, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "text/plain" },
      body: admissionBody("PARTICIPANT_A"),
    });
    assert.equal(response.status, 415);
  });
});

test("two wallets admit independently and the journey starts only after both", async () => {
  const config = participantConfiguration();
  const admission = mockAdmission();
  const orchestrator = mockEngineOrchestrator({});
  await withParticipantWorker(config, orchestrator, admission, async (base) => {
    const post = (role) => fetch(`${base}/v1/participant-cases/${CASE_CODE}/admissions`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: admissionBody(role),
    });

    const first = await post("PARTICIPANT_A");
    assert.equal(first.status, 201);
    assert.equal((await first.json()).admission.bothAdmitted, false);
    // Nothing downstream of admission has run on one participant.
    assert.equal(orchestrator.stages.includes("evaluate"), false);

    const second = await post("PARTICIPANT_B");
    assert.equal(second.status, 201);
    assert.equal((await second.json()).admission.bothAdmitted, true);
    assert.deepEqual(admission.calls.admitted, ["PARTICIPANT_A", "PARTICIPANT_B"]);

    // The remainder of the journey is reachable now, and each role's artifact was
    // already published at its own admission, so no submission step reappears.
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(orchestrator.stages.includes("evaluate"), true);
    assert.equal(orchestrator.stages.filter((s) => s === "submit").length, 0);
  });
});

test("a challenge is issued without any signature prompt state on the worker", async () => {
  const config = participantConfiguration();
  const admission = mockAdmission();
  await withParticipantWorker(config, mockEngineOrchestrator({}), admission, async (base) => {
    const response = await fetch(`${base}/v1/participant-cases/${CASE_CODE}/challenge`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ role: "PARTICIPANT_A", participantWallet: WALLET_A, claim: { activeFrom: 1, activeUntil: 2 } }),
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).challenge.primaryType, "ParticipantAdmissionV1");
    assert.equal(admission.calls.challenges, 1);
  });
});

test("a challenge refuses an inexact body", async () => {
  const config = participantConfiguration();
  await withParticipantWorker(config, mockEngineOrchestrator({}), mockAdmission(), async (base) => {
    const response = await fetch(`${base}/v1/participant-cases/${CASE_CODE}/challenge`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ role: "PARTICIPANT_A", participantWallet: WALLET_A }),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, "BODY_MEMBERS");
  });
});

test("a typed admission refusal keeps its status and code", async () => {
  const config = participantConfiguration();
  const refusing = mockAdmission({
    admitParticipant: async () => {
      const error = new Error("That wallet already holds the other role in this case");
      error.name = "ParticipantAdmissionError";
      error.status = 409;
      error.code = "DUPLICATE_SIGNER";
      throw error;
    },
  });
  await withParticipantWorker(config, mockEngineOrchestrator({}), refusing, async (base) => {
    const response = await fetch(`${base}/v1/participant-cases/${CASE_CODE}/admissions`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: admissionBody("PARTICIPANT_B"),
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).code, "DUPLICATE_SIGNER");
  });
});

test("an internal admission failure never leaks its message", async () => {
  const config = participantConfiguration();
  const broken = mockAdmission({
    admitParticipant: async () => { throw new Error("postgres://user:secret@host/db is unreachable"); },
  });
  await withParticipantWorker(config, mockEngineOrchestrator({}), broken, async (base) => {
    const response = await fetch(`${base}/v1/participant-cases/${CASE_CODE}/admissions`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: admissionBody("PARTICIPANT_A"),
    });
    assert.equal(response.status, 500);
    const body = await response.text();
    assert.equal(body.includes("secret"), false);
    assert.equal(body.includes("postgres"), false);
  });
});

test("an oversized admission body is refused", async () => {
  const config = participantConfiguration();
  await withParticipantWorker(config, mockEngineOrchestrator({}), mockAdmission(), async (base) => {
    const response = await fetch(`${base}/v1/participant-cases/${CASE_CODE}/admissions`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ role: "PARTICIPANT_A", authorization: {}, signature: `0x${"ab".repeat(20_000)}`, claim: {} }),
    });
    assert.equal(response.status, 413);
  });
});

test("participant routes are absent when admission is not configured", async () => {
  const config = configuration();
  await withWorker(config, mockEngineOrchestrator({}), async (base) => {
    const response = await fetch(`${base}/v1/participant-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: "{}",
    });
    assert.equal(response.status, 404);
  });
});

test("direct participant routes stay disabled unless both explicit worker gates are present", async () => {
  const config = configuration();
  assert.equal(config.directParticipantAdmission, false);
  await withParticipantWorker(config, mockEngineOrchestrator({}), mockAdmission(), async (base) => {
    const response = await fetch(`${base}/v1/participant-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: "{}",
    });
    assert.equal(response.status, 404);
    assert.equal((await response.json()).code, "ROUTE");
  });
  assert.throws(() => configuration({ MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION: "enabled" }),
    (error) => error instanceof WorkerError && error.code === "CONFIG");
  assert.throws(() => participantConfiguration({ MORDANT_WORKER_MAX_ACTIVE_CASES: "2" }),
    (error) => error instanceof WorkerError && error.code === "CONFIG");
});

test("the direct-admission profile closes managed creation but preserves historical reads", async () => {
  const engine = mockEngineOrchestrator({});
  await withParticipantWorker(participantConfiguration(), engine, mockAdmission(), async (base) => {
    const blocked = await fetch(`${base}/v1/custom-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` },
      body: JSON.stringify(WINDOWS),
    });
    assert.equal(blocked.status, 404);
    assert.equal((await blocked.json()).code, "ROUTE");
    assert.deepEqual(engine.stages, []);

    const historical = await fetch(`${base}/v1/custom-cases/3f2504e0-4f89-11d3-9a0c-0305e82c3301`);
    assert.equal(historical.status, 200);
  });
});

test("participant capacity is reserved before preparation, and a failed prepared case retains its slot", async () => {
  const config = participantConfiguration();
  let allowPreparation;
  let beganPreparation;
  const preparationGate = new Promise((resolve) => { allowPreparation = resolve; });
  const began = new Promise((resolve) => { beganPreparation = resolve; });
  const admission = mockAdmission();
  const originalCreate = admission.createParticipantCase;
  admission.createParticipantCase = async (...args) => {
    beganPreparation();
    await preparationGate;
    return originalCreate(...args);
  };
  await withParticipantWorker(config, mockEngineOrchestrator({}), admission, async (base) => {
    const headers = () => ({ origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` });
    const first = fetch(`${base}/v1/participant-cases`, { method: "POST", headers: headers(), body: "{}" });
    await began;
    const blocked = await fetch(`${base}/v1/participant-cases`, { method: "POST", headers: headers(), body: "{}" });
    assert.equal(blocked.status, 409);
    assert.equal((await blocked.json()).code, "BUSY");
    allowPreparation();
    assert.equal((await first).status, 201);
  });

  const failing = mockAdmission({
    createParticipantCase: async (dependencies) => {
      await dependencies.onParticipantCaseCreated?.({
        runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        caseCode: CASE_CODE,
      });
      throw new Error("preparation failed");
    },
  });
  await withParticipantWorker(participantConfiguration(), mockEngineOrchestrator({}), failing, async (base, worker) => {
    const headers = () => ({ origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(Date.now())}` });
    const failed = await fetch(`${base}/v1/participant-cases`, { method: "POST", headers: headers(), body: "{}" });
    assert.equal(failed.status, 500);
    // The reservation itself is released, but the durable neutral case exists
    // and remains counted until expiry even though preparation failed.
    assert.equal(worker.isBusy(), false);
    assert.equal(worker.state.openCases.size, 1);
    const retry = await fetch(`${base}/v1/participant-cases`, { method: "POST", headers: headers(), body: "{}" });
    assert.equal(retry.status, 409);
    assert.equal((await retry.json()).code, "OPEN_CASE");
  });
});

test("an unexpired participant clock restores capacity and expires it for a later case", async () => {
  let nowMs = 1_800_000_000_000;
  const config = participantConfiguration({
    MORDANT_WORKER_MAX_ACTIVE_CASES: "1",
    MORDANT_WORKER_PARTICIPANT_CASE_LIFETIME_MS: "1000",
  });
  const paths = ensureWorkerLayout(config);
  const priorRunId = "8f2504e0-4f89-11d3-9a0c-0305e82c3301";
  recordCaseStart(paths, priorRunId, nowMs);

  // This is a fresh process after the first participant case was created. The
  // durable clock must still consume the one configured waiting-case slot.
  const worker = createLiveWorker({
    configuration: config,
    createOrchestrator: () => mockEngineOrchestrator({}),
    admission: mockAdmission(),
    now: () => nowMs,
  });
  assert.equal(worker.state.openCases.has(priorRunId), true);
  worker.server.listen(0, "127.0.0.1");
  await once(worker.server, "listening");
  const { port } = worker.server.address();
  const base = `http://127.0.0.1:${port}`;
  try {
    let health = await (await fetch(`${base}/health`)).json();
    assert.equal(health.acceptingCases, false);

    nowMs += 1_000;
    health = await (await fetch(`${base}/health`)).json();
    assert.equal(health.acceptingCases, true);
    assert.equal(worker.state.openCases.has(priorRunId), false);

    const response = await fetch(`${base}/v1/participant-cases`, {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json", authorization: `Bearer ${token(nowMs)}` },
      body: "{}",
    });
    assert.equal(response.status, 201);
  } finally {
    worker.server.close();
    await once(worker.server, "close");
  }
});

test("pruning removes an admitted claim while leaving the admission provable", () => {
  const root = mkdtempSync(join(tmpdir(), "mordant-prune-"));
  const runId = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
  mkdirSync(join(root, runId), { recursive: true });
  writeFileSync(join(root, runId, "execution.json"), JSON.stringify({
    runId,
    admittedClaims: {
      PARTICIPANT_A: { participantWallet: WALLET_A, claimCommitment: `0x${"2".repeat(64)}`, claim: { activeFrom: 120, activeUntil: 420 } },
    },
  }));
  const removed = pruneReproducibleArtifacts(root, runId);
  assert.ok(removed.includes("private-input"));
  const after = JSON.parse(readFileSync(join(root, runId, "execution.json"), "utf8"));
  assert.equal(after.admittedClaims.PARTICIPANT_A.claim, undefined);
  // The commitment survives, so the admission stays checkable without the interval.
  assert.equal(after.admittedClaims.PARTICIPANT_A.claimCommitment, `0x${"2".repeat(64)}`);
  assert.equal(after.admittedClaims.PARTICIPANT_A.participantWallet, WALLET_A);
});
