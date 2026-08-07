#!/usr/bin/env node
/**
 * Drives one real two-wallet direct-admission journey against the live worker.
 *
 * This is a client, not a shortcut. It speaks only the worker's public HTTP
 * surface, and every value that decides anything is produced by the server:
 * the case, the shareable code, the admission challenge nonce and its window,
 * the FHE preparation, the BGV evaluation and the governed Ed25519 release.
 *
 * The only things supplied here are what a real participant supplies: which
 * wallet signs, and that wallet's own private pledge window. Each role signs
 * the exact ParticipantAdmissionV1 struct the server issued, with its own key.
 * No key is printed, serialized or written.
 *
 *   node scripts/activation-fresh-journey.mjs --worker http://127.0.0.1:8791 --out <path>
 */
import { randomUUID, createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG_PATH = join(ROOT, "docs", "evidence", "recourse-v2-demo-config-2026-08-06.json");

/** Each role signs with its own committed key name. Values are never read here except to sign. */
const ROLE_KEY_NAME = Object.freeze({
  PARTICIPANT_A: "MORDANT_KEY_RECOURSE_HOLDER_A",
  PARTICIPANT_B: "MORDANT_KEY_RECOURSE_HOLDER_B",
});

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function launchToken(secret, audience) {
  const issuedAt = Date.now();
  const claims = {
    tokenId: randomUUID(),
    issuedAt,
    // The worker caps a launch token at five minutes; stay inside it.
    expiresAt: issuedAt + 4 * 60 * 1_000,
    audience,
    action: "CREATE_CUSTOM_CASE",
  };
  // Member order must match the worker's canonicalTokenPayload exactly.
  const payload = JSON.stringify({
    tokenId: claims.tokenId,
    issuedAt: claims.issuedAt,
    expiresAt: claims.expiresAt,
    audience: claims.audience,
    action: claims.action,
  });
  const signature = createHmac("sha256", secret).update(payload).digest();
  return `${base64url(payload)}.${base64url(signature)}`;
}

async function call(url, { method = "GET", body, token, origin } = {}) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  if (origin !== undefined) headers.origin = origin;
  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${method} ${url} -> ${response.status} (non-JSON: ${text.slice(0, 200)})`);
  }
  if (!response.ok) {
    throw new Error(`${method} ${url} -> ${response.status} ${parsed.code ?? ""} ${parsed.error ?? ""}`);
  }
  return parsed;
}

function required(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${name} is required`);
  return value.trim();
}

async function admit(base, origin, caseCode, role, wallet, claim) {
  const { challenge } = await call(`${base}/v1/participant-cases/${caseCode}/challenge`, {
    method: "POST", origin, body: { role, participantWallet: wallet, claim },
  });
  if (challenge.message.participantWallet.toLowerCase() !== wallet.toLowerCase()) {
    throw new Error(`${role}: the server issued a challenge for a different wallet`);
  }
  if (challenge.message.role !== role) throw new Error(`${role}: the server issued a challenge for a different role`);

  // The key is used here and nowhere else. It is not stored, logged or returned.
  const account = privateKeyToAccount(required(ROLE_KEY_NAME[role]));
  if (account.address.toLowerCase() !== wallet.toLowerCase()) {
    throw new Error(`${role}: ${ROLE_KEY_NAME[role]} does not derive to the canonical participant wallet`);
  }
  const signature = await account.signTypedData({
    domain: challenge.domain,
    types: challenge.types,
    primaryType: challenge.primaryType,
    message: challenge.message,
  });

  const admitted = await call(`${base}/v1/participant-cases/${caseCode}/admissions`, {
    method: "POST",
    origin,
    body: { role, authorization: challenge.message, signature, claim },
  });
  process.stdout.write(
    `admitted ${role} wallet=${admitted.participantWallet} eligibilityBlock=${admitted.eligibilityBlock}`
    + ` newly=${admitted.newlyAdmitted} stage=${admitted.view.stage}\n`,
  );
  return {
    role,
    participantWallet: admitted.participantWallet,
    eligibilityBlock: admitted.eligibilityBlock,
    authorizationNonce: challenge.message.authorizationNonce,
    issuedAt: challenge.message.issuedAt,
    expiresAt: challenge.message.expiresAt,
    activeFrom: challenge.message.activeFrom,
    activeUntil: challenge.message.activeUntil,
    stageAfter: admitted.view.stage,
  };
}

async function main() {
  const argument = (name, fallback = null) => {
    const index = process.argv.indexOf(name);
    return index >= 0 ? process.argv[index + 1] : fallback;
  };
  const base = (argument("--worker") ?? "http://127.0.0.1:8791").replace(/\/$/u, "");
  const outPath = argument("--out");
  const origin = required("MORDANT_WORKER_ALLOWED_ORIGIN");

  const config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  const holderA = config.participants.holderA.address;
  const holderB = config.participants.holderB.address;

  const health = await call(`${base}/health`);
  process.stdout.write(`worker health: accepting=${health.acceptingCases} version=${health.version ?? "unknown"}\n`);

  const token = launchToken(required("MORDANT_WORKER_TOKEN_SECRET"), required("MORDANT_WORKER_TOKEN_AUDIENCE"));
  const created = await call(`${base}/v1/participant-cases`, { method: "POST", origin, token, body: {} });
  const caseCode = created.admission.caseCode;
  const runId = created.view.runId;
  process.stdout.write(`case runId=${runId} caseCode=${caseCode} stage=${created.view.stage}\n`);

  // Two private windows that genuinely overlap on the same receivable. The
  // circuit decides; nothing here asserts the outcome.
  const base_ = Math.floor(Date.now() / 1_000);
  const claimA = { activeFrom: base_, activeUntil: base_ + 30 * 24 * 3_600 };
  const claimB = { activeFrom: base_ + 10 * 24 * 3_600, activeUntil: base_ + 40 * 24 * 3_600 };

  const admissionA = await admit(base, origin, caseCode, "PARTICIPANT_A", holderA, claimA);
  const admissionB = await admit(base, origin, caseCode, "PARTICIPANT_B", holderB, claimB);

  process.stdout.write("both admitted; the worker is running the private journey\n");
  let view = null;
  const deadline = Date.now() + 30 * 60 * 1_000;
  let lastStage = null;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5_000));
    let body;
    try {
      body = await call(`${base}/v1/custom-cases/${runId}`);
    } catch (error) {
      process.stdout.write(`  (poll: ${error.message})\n`);
      continue;
    }
    view = body.view ?? body;
    if (view.stage !== lastStage) {
      lastStage = view.stage;
      process.stdout.write(`  stage=${view.stage}\n`);
    }
    if (view.stage === "COMPLETE" || view.stage === "EXECUTION_ABORTED") break;
  }
  if (view === null || view.stage !== "COMPLETE") {
    throw new Error(`the journey did not complete (last stage ${view?.stage ?? "unknown"})`);
  }

  const summary = {
    schemaVersion: "mordant.activation-fresh-journey/1",
    completedAtIso: new Date().toISOString(),
    runId,
    caseCode,
    admissions: [admissionA, admissionB],
    view,
  };
  process.stdout.write(`\nrunId ${runId}\n`);
  if (outPath) {
    writeFileSync(outPath, `${JSON.stringify(summary, null, 2)}\n`);
    process.stdout.write(`wrote ${outPath}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`activation-fresh-journey: ${error.message}\n`);
  process.exitCode = 1;
});
