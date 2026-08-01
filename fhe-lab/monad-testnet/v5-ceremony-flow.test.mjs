import assert from "node:assert/strict";
import {
  createHash, generateKeyPairSync, sign,
} from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

import { Journal, STAGES } from "./v5-journal.mjs";
import {
  CEREMONY_STAGES, inspectCeremonyPublic, runCeremonyPipeline,
} from "./v5-ceremony-flow.mjs";
import { POLICY_ID } from "./v5-rehearsal-support.mjs";

const hash = (value) => createHash("sha256").update(value).digest();
const hex = (value) => value.toString("hex");
const contextDomain = Buffer.from("mordant.ceremony.context/v1\0");
const rosterDomain = Buffer.from("mordant.ceremony.roster/v4");
const statusDomain = Buffer.from("mordant.ceremony.operator-statement/v4");
const auditDomain = Buffer.from("mordant.ceremony.operator-secret-audit/v1");
const manifestDomain = Buffer.from("mordant.ceremony.key-manifest/v4");

function uint(value, bytes) {
  const out = Buffer.alloc(bytes);
  let current = BigInt(value);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    out[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return out;
}

function publicRaw(key) {
  const der = key.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32);
}

function digestRoster(roster) {
  const chunks = [
    rosterDomain, Buffer.from(roster.parameterFingerprint, "hex"), uint(2, 2),
    Buffer.from(roster.ceremonyId, "hex"), uint(1, 8), uint(3, 2),
  ];
  roster.points.forEach((point, index) => chunks.push(
    uint(point, 8), Buffer.from(roster.signingPublicKeys[index], "hex"),
  ));
  return hash(Buffer.concat(chunks));
}

async function completedPublicFixture() {
  const root = await mkdtemp(join(tmpdir(), "mordant-ceremony-public-"));
  const publicRoot = join(root, "public");
  await mkdir(publicRoot, { recursive: true });
  const keys = Array.from({ length: 3 }, () => generateKeyPairSync("ed25519"));
  const signingKeys = keys.map(({ publicKey }) => hex(publicRaw(publicKey)));
  const runtimeBinarySha256 = Object.fromEntries([
    "ceremony-client", "ceremony-coordinator", "ceremony-evaluator", "ceremony-operator",
  ].map((name) => [name, hex(hash(Buffer.from(name)))]));
  const context = {
    schemaVersion: "mordant.ceremony-context/1",
    ceremonyProtocol: "mordant.ceremony.network-request/v4",
    manifestSchema: "mordant.collective-key-manifest/4",
    keyScheme: "Lattigo BGV dealerless multiparty 2-of-3",
    lattigoVersion: "github.com/tuneinsight/lattigo/v6 v6.2.0",
    goRuntimeVersion: "go-test",
    threshold: 2,
    operatorPoints: [1, 2, 3],
    operatorSigningKeys: signingKeys,
    parameterFingerprint: hex(hash(Buffer.from("parameters"))),
    circuitVersion: 5,
    circuitHash: hex(hash(Buffer.from("circuit"))),
    releaseLayoutVersion: 1,
    serializationVersion: 1,
    runtimeBinarySha256,
    chainId: 10143,
    policyId: POLICY_ID.slice(2),
    policyVersion: 1,
    sessionCommitment: hex(hash(Buffer.from("session"))),
    contextNonce: hex(hash(Buffer.from("nonce"))),
    oneHostCustodyWarning: "process separation on one host is not independent organizational custody",
    ceremonyId: "",
  };
  context.ceremonyId = hex(hash(Buffer.concat([contextDomain, Buffer.from(JSON.stringify(context))])));
  const roster = {
    parameterFingerprint: context.parameterFingerprint,
    threshold: 2,
    ceremonyId: context.ceremonyId,
    keyEpoch: 1,
    points: [1, 2, 3],
    signingPublicKeys: signingKeys,
  };
  const rosterDigest = digestRoster(roster);
  const digests = ["crs", "pk", "relin", "galois", "policy"].map((name) => hash(Buffer.from(name)));
  const statement = Buffer.concat([manifestDomain, rosterDigest, ...digests]);
  const manifestDigest = hash(statement);
  const evaluationDigest = hash(Buffer.concat([
    Buffer.from("mordant.ceremony.evaluation-key-summary/v4"), digests[2], digests[3],
  ]));
  const steps = [1, 2, 3, 4, 5, 6, 7, ...Array(9).fill(8), 9]
    .map((operation, index) => ({ operation, name: `step-${operation}`, at: `2026-08-01T00:00:${String(index).padStart(2, "0")}Z` }));
  const manifestAttestations = [];
  for (let index = 0; index < keys.length; index += 1) {
    const point = index + 1;
    const signature = sign(null, manifestDigest, keys[index].privateKey);
    manifestAttestations.push(`${point}:${hex(signature)}`);
    await writeFile(join(publicRoot, `manifest-attestation-${point}.bin`), signature);
    const operatorStatement = {
      point,
      rosterDigest: hex(rosterDigest),
      crsCommitment: hex(digests[0]),
      sealed: true,
      holdsLocalSecretKey: false,
      holdsOwnShareOnly: true,
      publicKeyDigest: hex(digests[1]),
      evaluationKeyDigest: hex(evaluationDigest),
      manifestDigest: hex(manifestDigest),
      steps,
      observedAt: "2026-08-01T00:01:00Z",
    };
    const statusDigest = hash(Buffer.concat([statusDomain, Buffer.from(JSON.stringify(operatorStatement))]));
    await writeFile(join(publicRoot, `operator-status-${point}.json`), `${JSON.stringify({
      statement: operatorStatement,
      point,
      signature: hex(sign(null, statusDigest, keys[index].privateKey)),
    }, null, 2)}\n`);
    const report = {
      schemaVersion: "mordant.ceremony-operator-secret-audit/1",
      point,
      roots: [publicRoot],
      leakHits: [],
      positiveControlDetected: true,
      positiveControlRemoved: true,
      noLeaks: true,
    };
    const auditDigest = hash(Buffer.concat([auditDomain, Buffer.from(JSON.stringify(report))]));
    await writeFile(join(publicRoot, `operator-secret-audit-${point}.json`), `${JSON.stringify({
      report,
      point,
      signature: hex(sign(null, auditDigest, keys[index].privateKey)),
    }, null, 2)}\n`);
  }
  await writeFile(join(publicRoot, "ceremony-context.json"), `${JSON.stringify(context, null, 2)}\n`);
  await writeFile(join(publicRoot, "roster.json"), `${JSON.stringify(roster, null, 2)}\n`);
  await writeFile(join(publicRoot, "ceremony-manifest-statement.bin"), statement);
  await writeFile(join(publicRoot, "collective-public-material.bin"), "public-only");
  await writeFile(join(publicRoot, "collective-evaluation-keys.bin"), "evaluation-only");
  await writeFile(join(publicRoot, "ceremony-evidence.json"), "{}\n");
  await writeFile(join(publicRoot, "key-manifest.json"), `${JSON.stringify({
    threshold: 2,
    ceremonyId: context.ceremonyId,
    publicKeyCommitment: hex(digests[1]),
    attestations: manifestAttestations,
  }, null, 2)}\n`);
  await writeFile(join(publicRoot, "operator-filesystem-audit.json"), `${JSON.stringify({
    passed: true,
    checks: [1, 2, 3].flatMap((point) => [
      { path: `operators/${point}/identity.key`, restricted: true },
      { path: `operators/${point}/operator.bin`, restricted: true },
    ]),
  }, null, 2)}\n`);
  await writeFile(join(publicRoot, "process-snapshot.json"), `${JSON.stringify({
    parentPid: 100,
    processes: [1, 2, 3].map((point) => ({
      role: `threshold-operator-${point}`, pid: 100 + point, parentPid: 100,
      environmentKeys: ["GOMAXPROCS", "PATH", "TMPDIR"],
      temporaryDirectory: join(root, `operators/${point}/tmp`),
      workingDirectory: root,
    })),
  }, null, 2)}\n`);
  await writeFile(join(publicRoot, "ceremony-resources.json"), `${JSON.stringify({
    operatorDiskBytes: { 1: 100, 2: 100, 3: 100 },
    publicBundleBytes: 100,
    combinedDiskBytesAtSnapshot: 400,
    ceremonyWallMillis: 1,
    freeDiskBytes: 1000,
  }, null, 2)}\n`);
  return { root, context, keys };
}

test("public ceremony inspection verifies all three digests and signatures", async () => {
  const fixture = await completedPublicFixture();
  const observed = await inspectCeremonyPublic(fixture.root);
  assert.equal(observed.progress, 13);
  assert.equal(observed.attestations.length, 3);
  assert.equal(observed.statuses.length, 3);
  assert.ok(observed.manifestDigest.startsWith("0x"));
});

test("public ceremony inspection fails closed on context, status, and manifest drift", async (t) => {
  await t.test("context byte", async () => {
    const fixture = await completedPublicFixture();
    const path = join(fixture.root, "public", "ceremony-context.json");
    const context = JSON.parse(await readFile(path, "utf8"));
    context.circuitHash = `${context.circuitHash.slice(0, -1)}0`;
    await writeFile(path, `${JSON.stringify(context, null, 2)}\n`);
    await assert.rejects(() => inspectCeremonyPublic(fixture.root), { code: "CEREMONY_CONTEXT_DRIFT" });
  });
  await t.test("operator status signature", async () => {
    const fixture = await completedPublicFixture();
    const path = join(fixture.root, "public", "operator-status-2.json");
    const status = JSON.parse(await readFile(path, "utf8"));
    status.signature = `${status.signature.slice(0, -2)}00`;
    await writeFile(path, `${JSON.stringify(status, null, 2)}\n`);
    await assert.rejects(() => inspectCeremonyPublic(fixture.root), { code: "CEREMONY_STATUS_SIGNATURE_INVALID" });
  });
  await t.test("canonical manifest byte", async () => {
    const fixture = await completedPublicFixture();
    const path = join(fixture.root, "public", "ceremony-manifest-statement.bin");
    const statement = await readFile(path);
    statement[statement.length - 1] ^= 1;
    await writeFile(path, statement);
    await assert.rejects(() => inspectCeremonyPublic(fixture.root), { code: "CEREMONY_MANIFEST_SIGNATURE_INVALID" });
  });
  await t.test("signed repeated operator step", async () => {
    const fixture = await completedPublicFixture();
    const path = join(fixture.root, "public", "operator-status-1.json");
    const status = JSON.parse(await readFile(path, "utf8"));
    status.statement.steps.push({
      operation: 3,
      name: "repeated-private-reshare",
      at: "2026-08-01T00:02:00Z",
    });
    const statusDigest = hash(Buffer.concat([statusDomain, Buffer.from(JSON.stringify(status.statement))]));
    status.signature = hex(sign(null, statusDigest, fixture.keys[0].privateKey));
    await writeFile(path, `${JSON.stringify(status, null, 2)}\n`);
    await assert.rejects(() => inspectCeremonyPublic(fixture.root), {
      code: "CEREMONY_OPERATOR_STATE_INCONSISTENT",
    });
  });
});

async function confirmedSessionJournal(path) {
  const journal = await Journal.open(path, { sourceCommit: "test-source", chainId: 10143 });
  for (const name of STAGES) {
    if (name === "CEREMONY_CONTEXT_PREPARED") break;
    const values = name === "SESSION_COMMITTED"
      ? { sessionCommitment: `0x${"44".repeat(32)}` }
      : {};
    await journal.prepare(name, values);
    await journal.recordOffChain(name, {});
  }
  return journal;
}

class DurableFakeCeremony {
  constructor(path, context) {
    this.path = path;
    this.context = context;
  }

  async state() {
    try { return JSON.parse(await readFile(this.path, "utf8")); } catch (error) {
      if (error.code !== "ENOENT") throw error;
      return { progress: 0, readyCount: 0, calls: {}, reconciliations: 0 };
    }
  }

  async save(value) { await writeFile(this.path, `${JSON.stringify(value, null, 2)}\n`); }

  async prepareContext() {
    const state = await this.state();
    state.progress = Math.max(state.progress, 1);
    await this.save(state);
    return this.context;
  }

  async inspect() {
    const state = await this.state();
    if (state.progress === 0) {
      const error = new Error("missing");
      error.code = "ENOENT";
      throw error;
    }
    return {
      context: this.context,
      progress: state.progress,
      readyCount: state.readyCount,
      stepDigest: `0x${String(state.progress).padStart(64, "0")}`,
      manifestDigest: state.progress >= 8 ? `0x${"55".repeat(32)}` : null,
      coreDigests: state.progress >= 13 ? { bundle: `0x${"66".repeat(32)}` } : {},
    };
  }

  async runCheckpoint(checkpoint) {
    const ranks = {
      "ready-1": 2, "ready-2": 2, "ready-3": 2, contributions: 3, "crs-sealed": 4, "public-key": 5,
      "relin-complete": 6, "galois-complete": 7, "evaluation-key-complete": 7,
      "manifest-constructed": 8, "signature-1": 9, "signature-2": 10,
      "signature-3": 11, confirmed: 13,
    };
    const state = await this.state();
    state.calls[checkpoint] = (state.calls[checkpoint] ?? 0) + 1;
    state.progress = Math.max(state.progress, ranks[checkpoint]);
    const readyMatch = /^ready-(1|2|3)$/.exec(checkpoint);
    if (readyMatch) state.readyCount = Math.max(state.readyCount, Number(readyMatch[1]));
    await this.save(state);
    return this.inspect();
  }

  async reconcileCompleted() {
    const state = await this.state();
    state.reconciliations += 1;
    await this.save(state);
    const observed = await this.inspect();
    return { beforeStepDigest: observed.stepDigest, afterStepDigest: observed.stepDigest, coreDigests: observed.coreDigests };
  }
}

test("every durable ceremony boundary survives journal reopen without repeating a checkpoint", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-ceremony-runner-"));
  const journalPath = join(root, "journal.json");
  const statePath = join(root, "ceremony-state.json");
  const context = {
    ceremonyId: "77".repeat(32),
    chainId: 10143,
    policyId: POLICY_ID.slice(2),
    sessionCommitment: "44".repeat(32),
  };
  await confirmedSessionJournal(journalPath);
  for (const stage of CEREMONY_STAGES) {
    const journal = await Journal.open(journalPath, { sourceCommit: "test-source", chainId: 10143 });
    const ceremony = new DurableFakeCeremony(statePath, context);
    await runCeremonyPipeline({ journal, ceremony, chainId: 10143, stopAfter: stage });
    assert.equal(journal.state(stage), "CONFIRMED", stage);
  }
  const before = JSON.parse(await readFile(statePath, "utf8"));
  const journal = await Journal.open(journalPath, { sourceCommit: "test-source", chainId: 10143 });
  await runCeremonyPipeline({ journal, ceremony: new DurableFakeCeremony(statePath, context), chainId: 10143 });
  const after = JSON.parse(await readFile(statePath, "utf8"));
  assert.deepEqual(after.calls, before.calls);
  for (const [checkpoint, count] of Object.entries(after.calls)) assert.equal(count, 1, checkpoint);
  assert.equal(after.progress, 13);
  assert.equal(after.reconciliations, 1);
});
