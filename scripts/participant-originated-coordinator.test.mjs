import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { tmpdir } from "node:os";
import { afterEach, test } from "node:test";

import {
  PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE,
  PARTICIPANT_ORIGINATED_IMPORT_SCHEMA,
  PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE,
  PARTICIPANT_ORIGINATED_TICKET_HEADER,
  ParticipantOriginatedCoordinatorError,
  createParticipantOriginatedCoordinator,
  createParticipantOriginatedCoordinatorServer,
  participantFilenames,
  participantOriginatedRoutes,
} from "./participant-originated-coordinator.mjs";

const NOW_MS = 2_000_000_000_000;
const NOW = Math.floor(NOW_MS / 1000);
const RUN_A = "11111111-1111-4111-8111-111111111111";
const RUN_B = "22222222-2222-4222-8222-222222222222";
const AUTHORIZATION = "Bearer participant-wallet-auth";
const activeServers = new Set();

afterEach(async () => {
  await Promise.all([...activeServers].map((server) => new Promise((resolve) => server.close(resolve))));
  activeServers.clear();
});

function digest(value) {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function bytes32(byte) { return `0x${byte.repeat(64)}`; }

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function fixture(overrides = {}) {
  const role = overrides.role ?? "PARTICIPANT_A";
  const names = participantFilenames(role);
  const ciphertext = overrides.ciphertext ?? Buffer.from("bounded encrypted ciphertext");
  const ciphertextDigest = digest(ciphertext);
  const manifestValue = overrides.manifestValue ?? {
    schemaVersion: "mordant.encrypted-participant-artifact/5",
    caseBindingDigest: "sha256:" + "1".repeat(64),
    caseId: "sha256:" + "2".repeat(64),
    assetIdentity: "sha256:" + "3".repeat(64),
    participantId: "sha256:" + "4".repeat(64),
    participantRole: role,
    publicKeyDigest: "sha256:" + "5".repeat(64),
    parameterProfile: "mordant.bgv.identity-full-fhe-256.n15/v1",
    parameterFingerprint: "sha256:" + "6".repeat(64),
    circuitDigest: "sha256:" + "7".repeat(64),
    inputSchema: "mordant.private-pledge/5",
    ciphertextObject: { path: names.ciphertext, sha256: `sha256:${ciphertextDigest.slice(2)}`, length: ciphertext.length },
    components: [],
    submissionNonce: "sha256:" + "8".repeat(64),
    expiresAtUnix: NOW + 300,
    signature: "AA==",
  };
  // Mirrors Go marshalCanonical framing: retained struct order plus one LF.
  const semanticManifest = Buffer.from(JSON.stringify(manifestValue));
  const manifest = overrides.manifest ?? Buffer.from(`${JSON.stringify(manifestValue)}\n`);
  const runId = overrides.runId ?? RUN_A;
  const fheCaseId = overrides.fheCaseId ?? bytes32("1");
  const participantWallet = overrides.participantWallet ?? "0x1111111111111111111111111111111111111111";
  const values = {
    runId,
    fheCaseId,
    role,
    participantWallet,
    participantSigningKeyDigest: overrides.participantSigningKeyDigest ?? bytes32("2"),
    registrationDigest: overrides.registrationDigest ?? bytes32("3"),
    encryptionIntentDigest: overrides.encryptionIntentDigest ?? bytes32("4"),
    finalAdmissionDigest: overrides.finalAdmissionDigest ?? bytes32("5"),
    claimCommitment: overrides.claimCommitment ?? bytes32("6"),
    clientBundleDigest: overrides.clientBundleDigest ?? bytes32("7"),
    encryptedArtifactDigest: overrides.encryptedArtifactDigest ?? digest(semanticManifest),
    artifactObjectDigest: overrides.artifactObjectDigest ?? digest(manifest),
    artifactObjectLength: overrides.artifactObjectLength ?? manifest.length,
    ciphertextObjectDigest: overrides.ciphertextObjectDigest ?? ciphertextDigest,
    ciphertextObjectLength: overrides.ciphertextObjectLength ?? ciphertext.length,
    registrationNonce: overrides.registrationNonce ?? bytes32("8"),
    intentNonce: overrides.intentNonce ?? bytes32("9"),
    submissionNonce: overrides.submissionNonce ?? bytes32("a"),
    issuedAt: overrides.issuedAt ?? NOW - 10,
    expiresAt: overrides.expiresAt ?? NOW + 300,
  };
  const signed = (schemaVersion, message, signatureByte) => ({
    schemaVersion,
    message,
    signature: `0x${signatureByte.repeat(65)}`,
  });
  const metadata = {
    schemaVersion: PARTICIPANT_ORIGINATED_IMPORT_SCHEMA,
    runId: values.runId,
    fheCaseId: values.fheCaseId,
    role: values.role,
    participantWallet: values.participantWallet,
    chainId: 10_143,
    participantSigningKeyDigest: values.participantSigningKeyDigest,
    registrationDigest: values.registrationDigest,
    encryptionIntentDigest: values.encryptionIntentDigest,
    finalAdmissionDigest: values.finalAdmissionDigest,
    claimCommitment: values.claimCommitment,
    clientBundleDigest: values.clientBundleDigest,
    encryptedArtifactDigest: values.encryptedArtifactDigest,
    artifactObjectDigest: values.artifactObjectDigest,
    artifactObjectLength: values.artifactObjectLength,
    ciphertextObjectDigest: values.ciphertextObjectDigest,
    ciphertextObjectLength: values.ciphertextObjectLength,
    registrationNonce: values.registrationNonce,
    intentNonce: values.intentNonce,
    submissionNonce: values.submissionNonce,
    issuedAt: values.issuedAt,
    expiresAt: values.expiresAt,
    walletAuthorizationChain: {
      registration: signed("registration/1", {
        runId: values.runId, fheCaseId: values.fheCaseId, role: values.role,
        participantWallet: values.participantWallet, registrationDigest: values.registrationDigest,
        registrationNonce: values.registrationNonce,
      }, "11"),
      encryptionIntent: signed("intent/1", {
        runId: values.runId, role: values.role, registrationDigest: values.registrationDigest,
        encryptionIntentDigest: values.encryptionIntentDigest, claimCommitment: values.claimCommitment,
        intentNonce: values.intentNonce,
      }, "22"),
      finalAdmission: signed("admission/1", {
        runId: values.runId, role: values.role, encryptionIntentDigest: values.encryptionIntentDigest,
        finalAdmissionDigest: values.finalAdmissionDigest, encryptedArtifactDigest: values.encryptedArtifactDigest,
        ciphertextObjectDigest: values.ciphertextObjectDigest, ciphertextObjectLength: values.ciphertextObjectLength,
        submissionNonce: values.submissionNonce,
      }, "33"),
    },
  };
  return { metadata, ciphertext, manifest, manifestValue, names };
}

function assertAuthorizationBindings(metadata) {
  const chain = metadata.walletAuthorizationChain;
  assert.equal(chain.registration.message.registrationDigest, metadata.registrationDigest);
  assert.equal(chain.encryptionIntent.message.encryptionIntentDigest, metadata.encryptionIntentDigest);
  assert.equal(chain.finalAdmission.message.finalAdmissionDigest, metadata.finalAdmissionDigest);
  assert.equal(chain.finalAdmission.message.encryptedArtifactDigest, metadata.encryptedArtifactDigest);
  assert.equal(chain.finalAdmission.message.ciphertextObjectDigest, metadata.ciphertextObjectDigest);
  assert.equal(chain.finalAdmission.message.ciphertextObjectLength, metadata.ciphertextObjectLength);
}

async function coordinatorFixture(overrides = {}) {
  const root = overrides.root ?? await mkdtemp(join(tmpdir(), "mordant-participant-transport-"));
  const calls = overrides.calls ?? [];
  let ticketByte = overrides.ticketByte ?? 1;
  const coordinator = await createParticipantOriginatedCoordinator({
    root,
    now: overrides.now ?? (() => NOW_MS),
    recover: overrides.recover,
    newTicket: overrides.newTicket ?? (() => Buffer.alloc(32, ticketByte++).toString("base64url")),
    authenticate: overrides.authenticate ?? (async ({ operation, request, metadata }) => {
      calls.push(`auth:${operation}`);
      if (request?.headers?.authorization !== AUTHORIZATION) return false;
      assertAuthorizationBindings(metadata);
      return { authorizationReference: metadata.finalAdmissionDigest };
    }),
    verifyArtifact: overrides.verifyArtifact ?? (async ({ filenames, staged, manifest }) => {
      calls.push("verify");
      assert.equal(staged.ciphertext.filename, filenames.ciphertext);
      assert.equal(staged.artifactManifest.filename, filenames.artifactManifest);
      assert.equal(manifest.ciphertextObject.path, filenames.ciphertext);
      return { verificationReference: digest(Buffer.from(canonical(manifest))) };
    }),
    publishArtifact: overrides.publishArtifact ?? (async ({ filenames, staged, publicationContract }) => {
      calls.push("publish");
      assert.deepEqual(publicationContract, { createOnly: true, ciphertextFirst: true, artifactManifestLast: true });
      const published = join(root, "governed-public");
      mkdirSync(published, { recursive: true });
      copyFileSync(staged.ciphertext.path, join(published, filenames.ciphertext), 1);
      calls.push("publish:ciphertext");
      copyFileSync(staged.artifactManifest.path, join(published, filenames.artifactManifest), 1);
      calls.push("publish:manifest-last");
      return { publicationReference: digest(Buffer.from(filenames.artifactManifest)) };
    }),
    reconcilePublication: overrides.reconcilePublication,
    stageObject: overrides.stageObject,
    allowUnsafeTestStaging: overrides.allowUnsafeTestStaging ?? true,
    streamIdleTimeoutMs: overrides.streamIdleTimeoutMs,
    streamAbsoluteTimeoutMs: overrides.streamAbsoluteTimeoutMs,
    unsafeTestHooks: overrides.unsafeTestHooks,
  });
  return { coordinator, root, calls };
}

async function listen(coordinator) {
  const server = createParticipantOriginatedCoordinatorServer(coordinator);
  activeServers.add(server);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function expectContinueAttempt(base, path, ticket, contentLength) {
  const target = new URL(path, base);
  return await new Promise((resolve, reject) => {
    let continued = false;
    let settled = false;
    const request = httpRequest({
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: "PUT",
      headers: {
        authorization: AUTHORIZATION,
        [PARTICIPANT_ORIGINATED_TICKET_HEADER]: ticket,
        "content-type": PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE,
        "content-length": String(contentLength),
        expect: "100-continue",
      },
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      request.destroy();
      reject(new Error("Expect rejection timed out"));
    }, 1000);
    request.on("continue", () => { continued = true; });
    request.on("response", (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        request.destroy();
        resolve({ status: response.statusCode, continued, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    request.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    request.flushHeaders();
  });
}

async function beginHttp(base, metadata, headers = {}) {
  const body = canonical(metadata);
  return fetch(`${base}${participantOriginatedRoutes.beginImport}`, {
    method: "POST",
    headers: { authorization: AUTHORIZATION, "content-type": PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, ...headers },
    body,
  });
}

async function uploadHttp(base, route, ticket, body, contentType, headers = {}) {
  return fetch(`${base}${route}`, {
    method: "PUT",
    headers: { authorization: AUTHORIZATION, [PARTICIPANT_ORIGINATED_TICKET_HEADER]: ticket, "content-type": contentType, ...headers },
    body,
  });
}

async function errorCode(response) {
  const body = await response.json();
  return body.error?.code;
}

function directDescription(length, contentType, request = { headers: { authorization: AUTHORIZATION } }) {
  return { request, contentLength: length, contentType };
}

async function expectCoordinatorError(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof ParticipantOriginatedCoordinatorError, String(error));
    assert.equal(error.code, code);
    return true;
  });
}

test("the four-route happy path authenticates before streaming and publishes the manifest last", async () => {
  const fx = fixture();
  const setup = await coordinatorFixture();
  const base = await listen(setup.coordinator);
  const begun = await beginHttp(base, fx.metadata);
  assert.equal(begun.status, 201);
  const reservation = await begun.json();
  assert.equal(reservation.state, "RESERVED");
  assert.deepEqual(reservation.filenames, fx.names);

  const ciphertext = await uploadHttp(base, participantOriginatedRoutes.ciphertext, reservation.ticket, fx.ciphertext, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE);
  const ciphertextBody = await ciphertext.json();
  assert.equal(ciphertext.status, 201, JSON.stringify(ciphertextBody));
  assert.equal(ciphertextBody.state, "CIPHERTEXT_STAGED");
  const manifest = await uploadHttp(base, participantOriginatedRoutes.artifactManifest, reservation.ticket, fx.manifest, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE);
  const manifestBody = await manifest.json();
  assert.equal(manifest.status, 201, JSON.stringify(manifestBody));
  assert.equal(manifestBody.state, "PUBLISHED");

  const status = await fetch(`${base}${participantOriginatedRoutes.status}`, {
    headers: { authorization: AUTHORIZATION, [PARTICIPANT_ORIGINATED_TICKET_HEADER]: reservation.ticket },
  });
  assert.equal(status.status, 200);
  assert.equal((await status.json()).state, "PUBLISHED");
  assert.deepEqual(setup.calls, [
    "auth:BEGIN_IMPORT", "auth:UPLOAD_CIPHERTEXT", "auth:UPLOAD_ARTIFACT_MANIFEST",
    "verify", "publish", "publish:ciphertext", "publish:manifest-last", "auth:STATUS",
  ]);
  assert.deepEqual(readdirSync(join(setup.root, "governed-public")).sort(), [fx.names.ciphertext, fx.names.artifactManifest].sort());
  const journal = readFileSync(setup.coordinator.paths.journal, "utf8");
  assert.ok(journal.endsWith("\n"));
  assert.match(journal, /IMPORT_RESERVED/u);
  assert.match(journal, /CIPHERTEXT_STAGED/u);
  assert.match(journal, /MANIFEST_STAGED/u);
  assert.match(journal, /IMPORT_PUBLISHED/u);
});

test("wallet authentication happens before a raw body is consumed", async () => {
  const fx = fixture();
  let iterated = false;
  const setup = await coordinatorFixture({
    authenticate: async ({ operation }) => operation === "BEGIN_IMPORT",
  });
  const reservation = await setup.coordinator.beginImport(fx.metadata, { headers: {} });
  const body = {
    async *[Symbol.asyncIterator]() {
      iterated = true;
      yield fx.ciphertext;
    },
  };
  await expectCoordinatorError(
    setup.coordinator.uploadCiphertext(
      reservation.ticket,
      body,
      directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE),
    ),
    "AUTHENTICATION",
  );
  assert.equal(iterated, false);
  assert.deepEqual(readdirSync(join(setup.root, "quarantine", reservation.ticketRef)), []);
});

test("secure coordinator configuration requires the pinned external stager", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-participant-stage-config-"));
  await expectCoordinatorError(
    createParticipantOriginatedCoordinator({
      root,
      authenticate: async () => true,
      verifyArtifact: async () => true,
      publishArtifact: async () => true,
      recover: false,
    }),
    "CONFIG",
  );
});

test("an authenticated stalled stream times out without blocking another ticket", async () => {
  const fxA = fixture();
  const fxB = fixture({
    runId: RUN_B,
    fheCaseId: bytes32("b"),
    role: "PARTICIPANT_B",
    registrationNonce: bytes32("c"),
    intentNonce: bytes32("d"),
    submissionNonce: bytes32("e"),
  });
  const stageObject = async ({ readable, quarantineRoot, expected }) => {
    const chunks = [];
    for await (const chunk of readable) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    assert.equal(body.length, expected.length);
    assert.equal(digest(body), expected.digest);
    writeFileSync(join(quarantineRoot, expected.filename), body, { flag: "wx", mode: 0o600 });
    return { path: expected.filename, digest: expected.digest, length: expected.length };
  };
  const setup = await coordinatorFixture({
    authenticate: async () => true,
    stageObject,
    streamIdleTimeoutMs: 40,
    streamAbsoluteTimeoutMs: 250,
  });
  const first = await setup.coordinator.beginImport(fxA.metadata, {});
  const stalled = new PassThrough();
  const stalledUpload = setup.coordinator.uploadCiphertext(
    first.ticket,
    stalled,
    directDescription(fxA.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}),
  );
  const second = await setup.coordinator.beginImport(fxB.metadata, {});
  const stagedSecond = await setup.coordinator.uploadCiphertext(
    second.ticket,
    Readable.from(fxB.ciphertext),
    directDescription(fxB.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}),
  );
  assert.equal(stagedSecond.state, "CIPHERTEXT_STAGED");
  await expectCoordinatorError(stalledUpload, "CIPHERTEXT_STREAM_TIMEOUT");
  assert.equal((await setup.coordinator.status(first.ticket, {})).state, "FAILED");
});

test("HTTP Expect 100-continue is rejected before raw upload bytes are requested", async () => {
  const fx = fixture();
  const setup = await coordinatorFixture();
  const base = await listen(setup.coordinator);
  const begun = await beginHttp(base, fx.metadata);
  const reservation = await begun.json();
  const result = await expectContinueAttempt(base, participantOriginatedRoutes.ciphertext, reservation.ticket, fx.ciphertext.length);
  assert.equal(result.status, 417);
  assert.equal(result.continued, false);
  assert.equal(JSON.parse(result.body).error.code, "EXPECTATION");
  assert.deepEqual(readdirSync(join(setup.root, "quarantine", reservation.ticketRef)), []);
});

test("trusted external stageObject owns both raw streams and wrong returned refs burn the ticket", async (t) => {
  await t.test("exact authenticated ciphertext then manifest", async () => {
    const fx = fixture();
    const calls = [];
    const stageObject = async ({ kind, readable, quarantineRoot, filenames, expected }) => {
      calls.push(`stage:${kind}`);
      const chunks = [];
      for await (const chunk of readable) chunks.push(Buffer.from(chunk));
      const body = Buffer.concat(chunks);
      assert.equal(expected.filename, kind === "ciphertext" ? filenames.ciphertext : filenames.artifactManifest);
      assert.equal(expected.digest, digest(body));
      assert.equal(expected.length, body.length);
      writeFileSync(join(quarantineRoot, expected.filename), body, { flag: "wx", mode: 0o600 });
      return { path: expected.filename, digest: expected.digest, length: expected.length };
    };
    const setup = await coordinatorFixture({ calls, stageObject });
    const request = { headers: { authorization: AUTHORIZATION } };
    const reservation = await setup.coordinator.beginImport(fx.metadata, request);
    await setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, request));
    await setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, request));
    assert.deepEqual(calls.slice(0, 5), ["auth:BEGIN_IMPORT", "auth:UPLOAD_CIPHERTEXT", "stage:ciphertext", "auth:UPLOAD_ARTIFACT_MANIFEST", "stage:artifact-manifest"]);
    assert.equal((await setup.coordinator.status(reservation.ticket, request)).state, "PUBLISHED");
  });
  await t.test("wrong callback reference", async () => {
    const fx = fixture();
    const setup = await coordinatorFixture({
      authenticate: async () => true,
      stageObject: async () => ({ path: "../replacement.bin", digest: fx.metadata.ciphertextObjectDigest, length: fx.ciphertext.length }),
    });
    const reservation = await setup.coordinator.beginImport(fx.metadata, {});
    await expectCoordinatorError(
      setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {})),
      "CIPHERTEXT_STAGE_REFERENCE",
    );
    assert.equal((await setup.coordinator.status(reservation.ticket, {})).state, "FAILED");
  });
});

test("role, nonce, ticket, ciphertext and final admission replays are create-only refusals", async () => {
  const fx = fixture();
  const setup = await coordinatorFixture({ authenticate: async () => ({ verified: true }) });
  const first = await setup.coordinator.beginImport(fx.metadata, {});
  await expectCoordinatorError(setup.coordinator.beginImport(fx.metadata, {}), "ROLE_OCCUPIED");

  const nonceReplay = fixture({
    runId: RUN_B,
    fheCaseId: bytes32("b"),
    role: "PARTICIPANT_B",
    registrationNonce: fx.metadata.registrationNonce,
    intentNonce: bytes32("c"),
    submissionNonce: bytes32("d"),
  });
  await expectCoordinatorError(setup.coordinator.beginImport(nonceReplay.metadata, {}), "NONCE_REPLAY");

  await setup.coordinator.uploadCiphertext(first.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
  await expectCoordinatorError(
    setup.coordinator.uploadCiphertext(first.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {})),
    "CIPHERTEXT_REPLAY",
  );
  await setup.coordinator.uploadArtifactManifest(first.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {}));
  await expectCoordinatorError(setup.coordinator.status("A".repeat(43), {}), "TICKET");
  await expectCoordinatorError(
    setup.coordinator.uploadArtifactManifest(first.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
    "TICKET_REPLAY",
  );
});

test("reservation WAL rolls back an uncommitted crash and rolls forward a committed crash", async (t) => {
  await t.test("partial role claim is removed deterministically", async () => {
    const root = await mkdtemp(join(tmpdir(), "mordant-participant-reservation-rollback-"));
    const fx = fixture();
    const crash = new Error("simulated process crash after role claim");
    crash.code = "TEST_SIMULATED_CRASH";
    const first = await coordinatorFixture({
      root,
      authenticate: async () => true,
      recover: false,
      unsafeTestHooks: {
        afterReservationStep(step) { if (step === "ROLE") throw crash; },
      },
    });
    await assert.rejects(first.coordinator.beginImport(fx.metadata, {}), (error) => error === crash);

    const restarted = await coordinatorFixture({ root, authenticate: async () => true, recover: false });
    assert.deepEqual(restarted.coordinator.recoveredReservations.map(({ state }) => state), ["ROLLED_BACK"]);
    const reservation = await restarted.coordinator.beginImport(fx.metadata, {});
    assert.equal(reservation.state, "RESERVED");
  });

  await t.test("commit marker repairs and preserves every owned claim", async () => {
    const root = await mkdtemp(join(tmpdir(), "mordant-participant-reservation-commit-"));
    const fx = fixture();
    const ticket = Buffer.alloc(32, 7).toString("base64url");
    const crash = new Error("simulated process crash after commit");
    crash.code = "TEST_SIMULATED_CRASH";
    const first = await coordinatorFixture({
      root,
      authenticate: async () => true,
      recover: false,
      newTicket: () => ticket,
      unsafeTestHooks: {
        afterReservationStep(step) { if (step === "COMMIT") throw crash; },
      },
    });
    await assert.rejects(first.coordinator.beginImport(fx.metadata, {}), (error) => error === crash);

    const restarted = await coordinatorFixture({ root, authenticate: async () => true, recover: false });
    assert.deepEqual(restarted.coordinator.recoveredReservations.map(({ state }) => state), ["COMMITTED"]);
    assert.equal((await restarted.coordinator.status(ticket, {})).state, "RESERVED");
    await expectCoordinatorError(restarted.coordinator.beginImport(fx.metadata, {}), "ROLE_OCCUPIED");
  });
});

test("two coordinator instances cannot split ownership of one role and nonce set", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-participant-two-coordinators-"));
  const fx = fixture();
  const first = await coordinatorFixture({ root, authenticate: async () => true, recover: false, ticketByte: 1 });
  const second = await coordinatorFixture({ root, authenticate: async () => true, recover: false, ticketByte: 2 });
  const outcomes = await Promise.allSettled([
    first.coordinator.beginImport(fx.metadata, {}),
    second.coordinator.beginImport(fx.metadata, {}),
  ]);
  const admitted = outcomes.filter(({ status }) => status === "fulfilled");
  const rejected = outcomes.filter(({ status }) => status === "rejected");
  assert.equal(admitted.length, 1);
  assert.equal(rejected.length, 1);
  assert.ok(rejected[0].reason instanceof ParticipantOriginatedCoordinatorError);
  assert.ok(["ROLE_OCCUPIED", "NONCE_REPLAY"].includes(rejected[0].reason.code));
  const winner = admitted[0].value;
  const owner = winner.ticket === Buffer.alloc(32, 1).toString("base64url") ? first.coordinator : second.coordinator;
  assert.equal((await owner.status(winner.ticket, {})).ticketRef, winner.ticketRef);
  assert.equal(readdirSync(join(root, "roles")).length, 1);
  assert.equal(readdirSync(join(root, "nonces")).length, 3);
});

test("wrong ciphertext length or digest terminally burns the authenticated ticket", async (t) => {
  await t.test("declared length", async () => {
    const fx = fixture();
    const setup = await coordinatorFixture({ authenticate: async () => true });
    const reservation = await setup.coordinator.beginImport(fx.metadata, {});
    await expectCoordinatorError(
      setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length - 1, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {})),
      "CIPHERTEXT_LENGTH",
    );
    assert.equal((await setup.coordinator.status(reservation.ticket, {})).state, "FAILED");
    await expectCoordinatorError(
      setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {})),
      "IMPORT_TERMINAL",
    );
  });
  await t.test("stream digest", async () => {
    const fx = fixture({ ciphertextObjectDigest: bytes32("f") });
    const setup = await coordinatorFixture({ authenticate: async () => true });
    const reservation = await setup.coordinator.beginImport(fx.metadata, {});
    await expectCoordinatorError(
      setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {})),
      "CIPHERTEXT_DIGEST",
    );
    assert.deepEqual(readdirSync(join(setup.root, "quarantine", reservation.ticketRef)), []);
    assert.equal((await setup.coordinator.status(reservation.ticket, {})).state, "FAILED");
  });
});

test("expired, noncanonical, forbidden and non-exact metadata is rejected before reservation", async () => {
  const setup = await coordinatorFixture({ authenticate: async () => true });
  const expired = fixture({ issuedAt: NOW - 600, expiresAt: NOW - 1 });
  await expectCoordinatorError(setup.coordinator.beginImport(expired.metadata, {}), "EXPIRED");
  const forbidden = fixture();
  forbidden.metadata.walletAuthorizationChain.encryptionIntent.message.activeFrom = 123;
  await expectCoordinatorError(setup.coordinator.beginImport(forbidden.metadata, {}), "PLAINTEXT_FIELD");
  const privateKey = fixture({ runId: RUN_B, fheCaseId: bytes32("d") });
  privateKey.metadata.walletAuthorizationChain.registration.message.private_key = bytes32("e");
  await expectCoordinatorError(setup.coordinator.beginImport(privateKey.metadata, {}), "PLAINTEXT_FIELD");
  const extra = fixture({ runId: RUN_B, fheCaseId: bytes32("e") });
  extra.metadata.filename = "../submission-a.bin";
  await expectCoordinatorError(setup.coordinator.beginImport(extra.metadata, {}), "METADATA_SHAPE");

  const base = await listen(setup.coordinator);
  const raw = JSON.stringify(fixture({ runId: RUN_B, fheCaseId: bytes32("f") }).metadata);
  const response = await fetch(`${base}${participantOriginatedRoutes.beginImport}`, {
    method: "POST",
    headers: { authorization: AUTHORIZATION, "content-type": PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE },
    body: raw,
  });
  assert.equal(response.status, 400);
  assert.equal(await errorCode(response), "METADATA_CANONICAL");
});

test("manifest-last rejects out-of-order, malformed, truncated and replacement attempts", async (t) => {
  await t.test("out of order", async () => {
    const fx = fixture();
    const setup = await coordinatorFixture({ authenticate: async () => true });
    const reservation = await setup.coordinator.beginImport(fx.metadata, {});
    await expectCoordinatorError(
      setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
      "MANIFEST_ORDER",
    );
  });
  await t.test("malformed canonical JSON", async () => {
    const malformed = Buffer.from("{not-json}\n");
    const fx = fixture({ manifest: malformed, encryptedArtifactDigest: digest(malformed) });
    const setup = await coordinatorFixture({ authenticate: async () => true });
    const reservation = await setup.coordinator.beginImport(fx.metadata, {});
    await setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
    await expectCoordinatorError(
      setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(malformed), directDescription(malformed.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
      "MANIFEST_JSON",
    );
    await expectCoordinatorError(
      setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
      "IMPORT_TERMINAL",
    );
  });
  await t.test("truncated", async () => {
    const fx = fixture();
    const setup = await coordinatorFixture({ authenticate: async () => true });
    const reservation = await setup.coordinator.beginImport(fx.metadata, {});
    await setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
    await expectCoordinatorError(
      setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(fx.manifest.subarray(0, -1)), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
      "MANIFEST_TRUNCATED",
    );
  });
  await t.test("missing or extra canonical newline", async () => {
    for (const suffix of ["", "\n\n"]) {
      const value = { ciphertextObject: { path: "submission-a.bin" }, schemaVersion: "artifact/1" };
      const raw = Buffer.from(`${JSON.stringify(value)}${suffix}`);
      const fx = fixture({
        manifest: raw,
        manifestValue: value,
        artifactObjectDigest: digest(raw),
        artifactObjectLength: raw.length,
      });
      const setup = await coordinatorFixture({ authenticate: async () => true });
      const reservation = await setup.coordinator.beginImport(fx.metadata, {});
      await setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
      await expectCoordinatorError(
        setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(raw), directDescription(raw.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
        "MANIFEST_CANONICAL",
      );
    }
  });
});

test("arbitrary methods, paths, query filenames, filename headers, and archive types are unavailable", async () => {
  const fx = fixture();
  const setup = await coordinatorFixture();
  const base = await listen(setup.coordinator);
  let response = await fetch(`${base}/experimental/participant-originated/import/ciphertext/../../outside`, { method: "PUT" });
  assert.equal(response.status, 404);
  response = await fetch(`${base}${participantOriginatedRoutes.status}`, { method: "POST" });
  assert.equal(response.status, 405);
  response = await fetch(`${base}${participantOriginatedRoutes.beginImport}?filename=../claim.json`, { method: "POST" });
  assert.equal(response.status, 400);

  const begun = await beginHttp(base, fx.metadata);
  const reservation = await begun.json();
  response = await uploadHttp(base, participantOriginatedRoutes.ciphertext, reservation.ticket, fx.ciphertext, "application/zip", { "content-disposition": "attachment; filename=../../claim.zip" });
  assert.equal(response.status, 415);
  assert.equal(await errorCode(response), "CIPHERTEXT_CONTENT_TYPE");
});

function allFiles(root) {
  const result = [];
  const visit = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile()) result.push(child);
    }
  };
  visit(root);
  return result;
}

test("durable coordinator state contains encrypted/public material only", async () => {
  const fx = fixture();
  const setup = await coordinatorFixture({ authenticate: async () => true });
  const reservation = await setup.coordinator.beginImport(fx.metadata, {});
  await setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
  await setup.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {}));
  const encoded = allFiles(setup.root).map((path) => `${path}\n${readFileSync(path).toString("utf8")}`).join("\n");
  for (const forbidden of ["activeFrom", "activeUntil", '"claim"', '"salt"', "privateKey", "private_key", "claimPreimage"]) {
    assert.equal(encoded.includes(forbidden), false, `coordinator state leaked ${forbidden}`);
  }
});

test("a symlink in place of a server-selected quarantine object is rejected without replacement", async () => {
  const fx = fixture();
  const setup = await coordinatorFixture({ authenticate: async () => true });
  const reservation = await setup.coordinator.beginImport(fx.metadata, {});
  const target = join(setup.root, "outside.txt");
  writeFileSync(target, "do-not-overwrite");
  symlinkSync(target, join(setup.root, "quarantine", reservation.ticketRef, fx.names.ciphertext));
  await expectCoordinatorError(
    setup.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {})),
    "CIPHERTEXT_REPLAY",
  );
  assert.equal(readFileSync(target, "utf8"), "do-not-overwrite");
});

test("restart recovery verifies and publishes a fully staged manifest", async () => {
  const fx = fixture();
  const root = await mkdtemp(join(tmpdir(), "mordant-participant-recovery-"));
  const first = await coordinatorFixture({ root, authenticate: async () => true, recover: false });
  const reservation = await first.coordinator.beginImport(fx.metadata, {});
  await first.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
  writeFileSync(join(root, "quarantine", reservation.ticketRef, fx.names.artifactManifest), fx.manifest, { flag: "wx", mode: 0o600 });

  const calls = [];
  const restarted = await coordinatorFixture({ root, calls, authenticate: async () => true });
  const recovered = await restarted.coordinator.status(reservation.ticket, {});
  assert.equal(recovered.state, "PUBLISHED");
  assert.deepEqual(calls, ["verify", "publish", "publish:ciphertext", "publish:manifest-last"]);
  assert.match(readFileSync(restarted.coordinator.paths.journal, "utf8"), /IMPORT_RECOVERED_AND_PUBLISHED/u);
});

test("restart reconciles a crash after the publish callback without replaying publication", async () => {
  const fx = fixture();
  const root = await mkdtemp(join(tmpdir(), "mordant-participant-post-publish-crash-"));
  const first = await coordinatorFixture({ root, authenticate: async () => true, recover: false });
  const reservation = await first.coordinator.beginImport(fx.metadata, {});
  await first.coordinator.uploadCiphertext(reservation.ticket, Readable.from(fx.ciphertext), directDescription(fx.ciphertext.length, PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, {}));
  const quarantineManifest = join(root, "quarantine", reservation.ticketRef, fx.names.artifactManifest);
  writeFileSync(quarantineManifest, fx.manifest, { flag: "wx", mode: 0o600 });
  const governedPublic = join(root, "governed-public");
  mkdirSync(governedPublic, { recursive: true });
  copyFileSync(join(root, "quarantine", reservation.ticketRef, fx.names.ciphertext), join(governedPublic, fx.names.ciphertext), 1);
  copyFileSync(quarantineManifest, join(governedPublic, fx.names.artifactManifest), 1);
  writeFileSync(join(governedPublic, "participant-import-completion.json"), canonical({
    artifactManifest: fx.names.artifactManifest,
    artifactManifestDigest: fx.metadata.artifactObjectDigest,
    ciphertext: fx.names.ciphertext,
    ciphertextDigest: fx.metadata.ciphertextObjectDigest,
  }));

  const calls = [];
  const restarted = await coordinatorFixture({
    root,
    calls,
    authenticate: async () => true,
    reconcilePublication: async ({ filenames, metadata }) => {
      calls.push("reconcile");
      const completion = JSON.parse(readFileSync(join(governedPublic, "participant-import-completion.json"), "utf8"));
      assert.equal(completion.ciphertext, filenames.ciphertext);
      assert.equal(completion.artifactManifest, filenames.artifactManifest);
      assert.equal(completion.ciphertextDigest, metadata.ciphertextObjectDigest);
      assert.equal(completion.artifactManifestDigest, metadata.artifactObjectDigest);
      return { completionDigest: digest(Buffer.from(canonical(completion))) };
    },
    publishArtifact: async () => {
      assert.fail("create-only publication must not be replayed after exact completion readback");
    },
  });
  assert.equal((await restarted.coordinator.status(reservation.ticket, {})).state, "PUBLISHED");
  assert.deepEqual(calls, ["verify", "reconcile"]);
  assert.match(readFileSync(restarted.coordinator.paths.journal, "utf8"), /IMPORT_RECOVERED_FROM_PUBLICATION/u);
  await expectCoordinatorError(
    restarted.coordinator.uploadArtifactManifest(reservation.ticket, Readable.from(fx.manifest), directDescription(fx.manifest.length, PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE, {})),
    "TICKET_REPLAY",
  );
});

test("a truncated durable journal is rejected on restart", async () => {
  const root = await mkdtemp(join(tmpdir(), "mordant-participant-journal-"));
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "import-journal.ndjson"), '{"schemaVersion":"mordant.participant-originated-import-journal/1"}');
  await expectCoordinatorError(
    createParticipantOriginatedCoordinator({ root, authenticate: async () => true, verifyArtifact: async () => true, publishArtifact: async () => true, allowUnsafeTestStaging: true }),
    "JOURNAL_INTEGRITY",
  );
});
