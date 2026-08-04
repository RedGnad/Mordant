#!/usr/bin/env node
/**
 * Container smoke driver for the live worker.
 *
 * Runs one real custom V2 BGV conflict journey against an already-running
 * container and asserts every property that matters, rather than inferring
 * success from an HTTP status. It reuses the production launch-token signing
 * code so no second token format can drift into existence.
 *
 * It prints a sanitized JSON summary. It never prints the secret, the token or
 * the submitted pledge windows.
 */

import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";

import { signLaunchToken } from "./mordant-live-worker.mjs";

const BASE = process.env.SMOKE_BASE_URL ?? "http://127.0.0.1:8080";
const ORIGIN = process.env.SMOKE_ORIGIN ?? "https://preview.example";
const SECRET = process.env.MORDANT_WORKER_TOKEN_SECRET ?? "";
const AUDIENCE = process.env.MORDANT_WORKER_TOKEN_AUDIENCE ?? "MORDANT_RAILWAY_WORKER";
const SUMMARY_PATH = process.env.SMOKE_SUMMARY_PATH ?? "smoke-summary.json";

// The bounds the gate submits. Kept here only so the leak check knows what to
// look for; they are never written to the summary.
const WINDOWS = {
  participantA: { activeFrom: 120, activeUntil: 420 },
  participantB: { activeFrom: 220, activeUntil: 520 },
};
const SECRET_BOUNDS = [120, 420, 220, 520];

const failures = [];
function check(condition, label) {
  if (!condition) failures.push(label);
  process.stdout.write(`  ${condition ? "ok  " : "FAIL"} ${label}\n`);
  return condition;
}

function mintToken(overrides = {}) {
  const now = Date.now();
  return signLaunchToken({
    tokenId: randomUUID(),
    issuedAt: now,
    expiresAt: now + 60_000,
    audience: AUDIENCE,
    action: "CREATE_CUSTOM_CASE",
    ...overrides,
  }, overrides.secret ?? SECRET);
}

function createHeaders(token, origin = ORIGIN) {
  return { "content-type": "application/json", authorization: `Bearer ${token}`, origin };
}

async function json(response) {
  try { return await response.json(); } catch { return null; }
}

/** Recursively collects every scalar leaf so a leak check cannot be fooled. */
function* leaves(node, path = "$") {
  if (node !== null && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) yield* leaves(value, `${path}.${key}`);
  } else {
    yield [path, node];
  }
}

function assertNoRawInput(label, payload) {
  const encoded = JSON.stringify(payload ?? {});
  const numeric = [...leaves(payload ?? {})].filter(([, v]) => typeof v === "number" && SECRET_BOUNDS.includes(v));
  const named = [...leaves(payload ?? {})].filter(([p]) => /activeFrom|activeUntil|supervisedPledgeWindows|pledges/u.test(p));
  check(numeric.length === 0, `${label} carries no submitted bound`);
  check(named.length === 0, `${label} carries no private window field`);
  check(!encoded.includes("productScenario"), `${label} carries no productScenario`);
}

async function main() {
  const summary = { schemaVersion: "mordant.container-smoke/1", sourceCommit: process.env.MORDANT_PROTECTION_SOURCE_COMMIT ?? "unknown" };

  process.stdout.write("health\n");
  const health = await json(await fetch(`${BASE}/health`));
  check(health?.status === "READY", "health is READY");
  check(health?.worker === "IDLE", "worker is IDLE");
  check(health?.diskSufficient === true, "disk is sufficient");
  check(!/\/data|\/app|secret|token/iu.test(JSON.stringify(health)), "health exposes no path or secret");
  summary.health = health;

  process.stdout.write("security gates\n");
  check((await fetch(`${BASE}/nope`)).status === 404, "unknown route is 404");
  check((await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: JSON.stringify(WINDOWS),
  })).status === 401, "unsigned create is rejected");
  check((await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(mintToken()), body: "{not json",
  })).status === 400, "malformed JSON is rejected");
  check((await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(mintToken(), "https://evil.example"), body: JSON.stringify(WINDOWS),
  })).status === 403, "wrong Origin is rejected");
  check((await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(mintToken({ expiresAt: Date.now() - 1 })), body: JSON.stringify(WINDOWS),
  })).status === 401, "expired token is rejected");
  check((await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(mintToken()), body: JSON.stringify({ ...WINDOWS, extra: 1 }),
  })).status === 400, "unknown JSON members are rejected");

  process.stdout.write("admission\n");
  const admissionToken = mintToken();
  const created = await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(admissionToken), body: JSON.stringify(WINDOWS),
  });
  check(created.status === 201, "one case is admitted");
  const first = await json(created);
  const runId = first?.view?.runId;
  check(typeof runId === "string", "a run identifier is returned");
  check(first?.view?.terminalScenario === null, "terminalScenario is null at admission");
  check(first?.view?.governedResult === null, "governedResult is null at admission");
  assertNoRawInput("admission response", first);

  const replay = await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(admissionToken), body: JSON.stringify(WINDOWS),
  });
  check([409, 429].includes(replay.status), `token replay or second case is refused (${replay.status})`);

  const second = await fetch(`${BASE}/v1/custom-cases`, {
    method: "POST", headers: createHeaders(mintToken()), body: JSON.stringify(WINDOWS),
  });
  check(second.status === 409 && (await json(second))?.code === "BUSY", "a second active case receives BUSY");

  process.stdout.write("journey\n");
  const timeline = [];
  let last = null;
  let releasedAtSeconds = null;
  let sawResultBeforeRelease = false;
  const startedAt = Date.now();
  for (let attempt = 0; attempt < 400; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    const body = await json(await fetch(`${BASE}/v1/custom-cases/${runId}`));
    if (body === null) continue;
    last = body;
    const seconds = Math.round((Date.now() - startedAt) / 1_000);
    if (timeline.at(-1)?.stage !== body.view.stage) {
      timeline.push({ atSeconds: seconds, stage: body.view.stage, progress: body.progress });
      process.stdout.write(`  [${String(seconds).padStart(3)}s] ${body.view.stage}\n`);
    }
    // Before RELEASED there must be no result and no terminal scenario.
    if (["CASE_CREATED", "MATCH_PREPARED", "PARTICIPANT_A_SUBMITTED", "PARTICIPANT_B_PUBLISHED", "PARTICIPANT_B_SUBMITTED", "EVALUATED"].includes(body.view.stage)) {
      if (body.view.governedResult !== null || body.view.terminalScenario !== null) sawResultBeforeRelease = true;
      assertNoRawInput(`status at ${body.view.stage}`, body);
    }
    if (body.view.governedResult !== null && releasedAtSeconds === null) releasedAtSeconds = seconds;
    if (body.view.stage === "COMPLETE" && body.view.receipt !== null) break;
  }

  check(!sawResultBeforeRelease, "no result and no terminalScenario before governed release");
  check(last?.view?.stage === "COMPLETE", "the journey reached COMPLETE");
  check(last?.view?.governedResult?.conflict === true, "the governed Boolean is true");
  check(last?.view?.terminalScenario === "conflict", "terminalScenario derives conflict");
  check(last?.view?.recourse?.opened === true, "recourse is opened");
  check(last?.view?.receipt?.schemaVersion === "mordant.custom-supervised-protection-receipt/1", "a custom receipt is present");
  check(last?.view?.receipt?.terminal?.incidentState === "CONFLICT_CONFIRMED", "terminal incident state is CONFLICT_CONFIRMED");
  check(last?.view?.receipt?.terminal?.originalReceivableState === "OUTSTANDING_INTACT", "the original receivable is intact");
  assertNoRawInput("terminal response", last);

  summary.runId = runId;
  summary.timeline = timeline;
  summary.releasedAtSeconds = releasedAtSeconds;
  summary.governedResultDigest = last?.view?.governedResult?.digest ?? null;
  summary.receiptDigest = last?.view?.receipt?.receiptDigest ?? null;
  summary.terminal = last?.view?.receipt?.terminal ?? null;
  summary.durationSeconds = Math.round((Date.now() - startedAt) / 1_000);

  summary.failures = failures;
  summary.result = failures.length === 0 ? "PASS" : "FAIL";
  writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 1));
  process.stdout.write(`\n${summary.result}: ${failures.length} failure(s)\n`);
  if (failures.length > 0) {
    for (const failure of failures) process.stdout.write(`  - ${failure}\n`);
    process.exitCode = 1;
  }
}

await main();
