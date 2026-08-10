#!/usr/bin/env node
/**
 * A fresh governed case whose settlement profile is committed before anything
 * about the outcome can exist.
 *
 * The order is the property, so the order is enforced rather than described:
 *
 *   create case
 *     -> wait for the durable case binding (authority and binding digests)
 *     -> COMMIT the settlement profile, refused if any result artifact exists
 *     -> only then admit participants and let the evaluation run
 *
 * Admissions are deliberately started after the commitment returns, in the same
 * process, so there is no window in which a result could be forming while the
 * profile is still being written.
 */
import { randomUUID, createHmac } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, statSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, http, getContractAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROLE_KEY_NAME = Object.freeze({
  PARTICIPANT_A: "MORDANT_FRESH_KEY_HOLDER_A",
  PARTICIPANT_B: "MORDANT_FRESH_KEY_HOLDER_B",
});

const argument = (name, fallback = null) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
};

function required(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${name} is required`);
  return value.trim();
}

const b64url = (buffer) => Buffer.from(buffer).toString("base64")
  .replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");

function launchToken(secret, audience) {
  const issuedAt = Date.now();
  const payload = JSON.stringify({
    tokenId: randomUUID(), issuedAt, expiresAt: issuedAt + 4 * 60 * 1_000,
    audience, action: "CREATE_CUSTOM_CASE",
  });
  return `${b64url(payload)}.${b64url(createHmac("sha256", secret).update(payload).digest())}`;
}

async function call(url, { method = "GET", body, token, origin } = {}) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (origin !== undefined) headers.origin = origin;
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  const response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw new Error(`${method} ${url} -> ${response.status}: ${text.slice(0, 200)}`); }
  if (!response.ok) throw new Error(`${method} ${url} failed ${response.status}: ${text.slice(0, 300)}`);
  return parsed;
}

async function admit(base, origin, caseCode, role, wallet, claim) {
  const { challenge } = await call(`${base}/v1/participant-cases/${caseCode}/challenge`, {
    method: "POST", origin, body: { role, participantWallet: wallet, claim },
  });
  const account = privateKeyToAccount(required(ROLE_KEY_NAME[role]));
  if (account.address.toLowerCase() !== wallet.toLowerCase()) throw new Error(`${role}: key does not derive to ${wallet}`);
  const signature = await account.signTypedData({
    domain: challenge.domain, types: challenge.types,
    primaryType: challenge.primaryType, message: challenge.message,
  });
  const admitted = await call(`${base}/v1/participant-cases/${caseCode}/admissions`, {
    method: "POST", origin, body: { role, authorization: challenge.message, signature, claim },
  });
  process.stdout.write(`admitted ${role} ${admitted.participantWallet} eligibilityBlock=${admitted.eligibilityBlock}\n`);
  return { role, participantWallet: admitted.participantWallet, eligibilityBlock: admitted.eligibilityBlock };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  const base = (argument("--worker") ?? "http://127.0.0.1:8791").replace(/\/$/u, "");
  const dataRoot = required("MORDANT_WORKER_DATA_ROOT");
  const runRoot = join(dataRoot, "runs");
  const origin = required("MORDANT_WORKER_ALLOWED_ORIGIN");
  const outPath = argument("--out");

  const store = await import("../.product-test-dist/src/lib/protection/settlement-profile-store.js");
  const compat = await import("../.product-test-dist/src/lib/protection/adapter-compatibility.js");

  const selection = compat.readParticipantConfigSelection(process.env);
  const pinned = compat.PINNED_PARTICIPANT_CONFIGS[selection];
  const cfg = compat.loadCanonicalRecourseConfiguration(ROOT, selection);
  process.stdout.write(`participant configuration: ${selection} (${pinned.path})\n  sha256 ${pinned.sha256}\n`);

  const resume = argument("--case-code");
  const health = await call(`${base}/health`);
  // Only creation needs an accepting worker; resuming an open case does not.
  if (resume === null && !health.acceptingCases) {
    throw new Error(`the worker is not accepting cases (${health.worker})`);
  }

  let created = null;
  let caseCode;
  let runId;
  if (resume !== null) {
    const existing = await call(`${base}/v1/participant-cases/${resume}`);
    caseCode = resume;
    runId = existing.runId ?? existing.admission?.runId ?? existing.view?.runId;
  } else {
    const token = launchToken(required("MORDANT_WORKER_TOKEN_SECRET"), required("MORDANT_WORKER_TOKEN_AUDIENCE"));
    created = await call(`${base}/v1/participant-cases`, { method: "POST", origin, token, body: {} });
    caseCode = created.admission.caseCode;
    runId = created.view.runId;
  }
  const createdAtIso = new Date().toISOString();
  process.stdout.write(`case runId=${runId} caseCode=${caseCode}\n`);

  // --- wait only for the durable pre-result case binding ---
  const bindingPath = join(runRoot, runId, "public", "case-binding.json");
  const deadline = Date.now() + 10 * 60 * 1_000;
  while (!existsSync(bindingPath)) {
    if (Date.now() > deadline) throw new Error("the case binding never appeared");
    await sleep(1_000);
  }
  const binding = JSON.parse(readFileSync(bindingPath, "utf8"));
  const bindingWrittenIso = new Date(statSync(bindingPath).mtimeMs).toISOString();
  process.stdout.write(`case binding durable at ${bindingWrittenIso}\n  releaseAuthorityId ${binding.releaseAuthorityId}\n`);

  const exposed = store.existingResultArtifact(runRoot, runId);
  if (exposed !== null) throw new Error(`a result artifact already exists (${exposed}); refusing to commit`);

  // --- commit, before any admission is sent ---
  const pub = createPublicClient({ transport: http(required("MONAD_RPC_URL")) });
  const owner = privateKeyToAccount(required("DEPLOYER_PRIVATE_KEY"));
  const nonce = await pub.getTransactionCount({ address: owner.address });
  const futureAdapter = getContractAddress({ from: owner.address, nonce: BigInt(nonce) });
  const attestor = privateKeyToAccount(required("MORDANT_FRESH_KEY_ATTESTOR")).address;

  // The binding's own digest is recorded by keygen, and is exactly the value the
  // governed result later carries as caseBindingDigest.
  const executionPath = join(runRoot, runId, "execution.json");
  const execution = JSON.parse(readFileSync(executionPath, "utf8"));
  const caseBindingDigest = execution.keygen?.bindingDigest;
  const protectionBindingDigest = execution.keygen?.protectionBindingDigest;
  if (typeof caseBindingDigest !== "string" || typeof protectionBindingDigest !== "string") {
    throw new Error("the durable keygen binding digests are not available yet");
  }

  const profile = Object.freeze({
    schemaVersion: "mordant.settlement-profile/2",
    profileId: "mordant.post-deadline-settlement.minimal",
    profileVersion: 1,
    caseBinding: {
      runId,
      caseId: binding.caseId,
      caseBindingDigest,
      protectionBindingDigest,
      releaseMode: binding.releaseMode,
    },
    participantConfig: { path: pinned.path, sha256: pinned.sha256 },
    committedAtUnix: Math.floor(Date.now() / 1_000),
    chainId: cfg.adapter.chainId,
    adapter: futureAdapter,
    settlementToken: cfg.adapter.settlementToken,
    cviVerifier: cfg.adapter.verifier,
    facility: cfg.adapter.facility,
    attestor,
    holderA: cfg.participants.holderA,
    holderB: cfg.participants.holderB,
    payoutA: "1",
    payoutB: "1",
    cureWindowSeconds: Number(cfg.cureWindowSeconds ?? 600),
    releaseAuthorityId: binding.releaseAuthorityId,
    settlementAuthorization: "AUTHORIZED",
  });

  // Resuming a run whose commitment already exists must never rewrite it: the
  // stored commitment is read back and verified instead.
  let committed;
  if (existsSync(store.settlementProfilePath(runRoot, runId))) {
    committed = store.readCommittedSettlementProfile(runRoot, runId);
    process.stdout.write("existing commitment verified, not rewritten\n");
  } else {
    committed = store.commitSettlementProfile(runRoot, runId, profile);
  }
  const commitmentPath = store.settlementProfilePath(runRoot, runId);
  const commitmentWrittenIso = new Date(statSync(commitmentPath).mtimeMs).toISOString();
  process.stdout.write(
    `COMMITTED at ${commitmentWrittenIso}\n`
    + `  settlementProfileDigest ${committed.committedDigest}\n`
    + `  adapter (CREATE nonce ${nonce}) ${futureAdapter}\n`
    + `  holderA ${profile.holderA}\n  holderB ${profile.holderB}\n`
    + `  payoutA/payoutB ${profile.payoutA}/${profile.payoutB}, cure ${profile.cureWindowSeconds}s\n`
    + `  releaseAuthorityId (precommitted) ${profile.releaseAuthorityId}\n`,
  );

  // --- only now do participants enter ---
  const start = Math.floor(Date.now() / 1_000);
  const admissionA = await admit(base, origin, caseCode, "PARTICIPANT_A", cfg.participants.holderA,
    { activeFrom: start, activeUntil: start + 30 * 24 * 3_600 });
  const admissionB = await admit(base, origin, caseCode, "PARTICIPANT_B", cfg.participants.holderB,
    { activeFrom: start + 10 * 24 * 3_600, activeUntil: start + 40 * 24 * 3_600 });

  let view = null;
  let lastStage = null;
  const runDeadline = Date.now() + 30 * 60 * 1_000;
  while (Date.now() < runDeadline) {
    await sleep(5_000);
    let body;
    try { body = await call(`${base}/v1/custom-cases/${runId}`); } catch { continue; }
    view = body.view ?? body;
    if (view.stage !== lastStage) { lastStage = view.stage; process.stdout.write(`  stage=${view.stage}\n`); }
    if (view.stage === "COMPLETE" || view.stage === "EXECUTION_ABORTED") break;
  }
  if (view?.stage !== "COMPLETE") throw new Error(`the journey did not complete (${view?.stage ?? "unknown"})`);

  const resultPath = join(runRoot, runId, "public", "governed-conflict-result.json");
  const governed = JSON.parse(readFileSync(resultPath, "utf8"));
  const resultWrittenIso = new Date(statSync(resultPath).mtimeMs).toISOString();

  const timeline = {
    caseBindingWrittenIso: bindingWrittenIso,
    settlementCommitmentWrittenIso: commitmentWrittenIso,
    governedResultWrittenIso: resultWrittenIso,
    strictOrder: bindingWrittenIso < commitmentWrittenIso && commitmentWrittenIso < resultWrittenIso,
  };
  const authorityMatch = binding.releaseAuthorityId === governed.releaseAuthorityId;

  process.stdout.write(
    `\nTIMELINE\n  case binding   ${timeline.caseBindingWrittenIso}\n`
    + `  commitment     ${timeline.settlementCommitmentWrittenIso}\n`
    + `  governed result ${timeline.governedResultWrittenIso}\n`
    + `  strict order   ${timeline.strictOrder}\n`
    + `  precommitted authority == released authority: ${authorityMatch}\n`,
  );
  if (!timeline.strictOrder) throw new Error("the commitment did not strictly precede the result");
  if (!authorityMatch) throw new Error("the released authority does not equal the precommitted authority");

  const summary = {
    schemaVersion: "mordant.fresh-settlement-commit-first/1",
    runId, caseCode, createdAtIso,
    participantConfig: { selection, ...pinned },
    settlementProfileDigest: committed.committedDigest,
    profile,
    admissions: [admissionA, admissionB],
    governedResult: {
      caseId: governed.caseId,
      caseBindingDigest: governed.caseBindingDigest,
      releaseAuthorityId: governed.releaseAuthorityId,
      conflict: governed.conflict,
    },
    timeline,
    authorityMatch,
    view,
  };
  if (outPath) {
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, `${JSON.stringify(summary, null, 2)}\n`);
    process.stdout.write(`wrote ${outPath}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
