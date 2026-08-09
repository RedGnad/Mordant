#!/usr/bin/env node
/**
 * Supported, qualified native-CLI participant-originated encryption harness.
 *
 * Nothing in this file is wired into the live worker. The normal entry point
 * builds pinned binaries and runs two isolated cases only after `--run` is
 * supplied. Internal participant/coordinator modes are child-process
 * boundaries used by that runner. The HTTP child exposes only the stable
 * `/v1/participant-originated/*` transport implemented by the qualified
 * coordinator module.
 */

import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  constants as fsConstants,
  copyFileSync,
  createReadStream,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE,
  PARTICIPANT_ORIGINATED_IMPORT_SCHEMA,
  PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE,
  PARTICIPANT_ORIGINATED_TICKET_HEADER,
  createParticipantOriginatedCoordinator,
  createParticipantOriginatedCoordinatorServer,
  participantFilenames,
  participantOriginatedRoutes,
} from "./participant-originated-coordinator.mjs";

export const PARTICIPANT_ORIGINATED_PRODUCT_QUALIFICATION_SCHEMA = "mordant.participant-originated-product-qualification-evidence/1";
export const PARTICIPANT_ORIGINATED_TOPOLOGY_SCHEMA = "mordant.participant-originated-process-topology/1";
export const PARTICIPANT_ORIGINATED_IMPORT_REQUEST_SCHEMA = "mordant.participant-originated-import-request/1";
export const PARTICIPANT_ORIGINATED_QUALIFICATION_BASE_SHA = "45da79fc8136706cac96dadd0541174a53c80298";
export const PARTICIPANT_ORIGINATED_PRODUCT_PROFILE = "mordant.participant-originated-encryption/native-cli-v1";
export const PARTICIPANT_ORIGINATED_PRIVACY_CLAIM =
  "For the participant-originated profile, the financing claim is encrypted in the participant-controlled environment before Mordant coordination infrastructure receives it.";
export const PARTICIPANT_ORIGINATED_SEMANTIC_GAP =
  "Current primitives authenticate case/role/artifact provenance and bind the hiding commitment into the ciphertext, but do not prove that encrypted plaintext equals the commitment preimage.";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(dirname(SCRIPT_PATH), "..");
const GO_ROOT = join(REPO_ROOT, "fhe-lab", "lattigo");
const AUTH_COMPILED_PATH = join(REPO_ROOT, ".product-test-dist", "src", "lib", "protection", "participant-originated-authorization.js");
const ZERO32 = `0x${"00".repeat(32)}`;
const CHAIN_ID = 10_143;
const VERIFYING_SERVICE = "mordant://participant-originated/qualification";
const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;
const EPHEMERAL_AUTHORIZATION_ENV = "MORDANT_PARTICIPANT_ORIGINATED_AUTHORIZATION";
const FORBIDDEN_STATE_KEY = /(?:^|["'_/\\-])(activeFrom|activeUntil|claimPreimage|claimSalt|plaintext|preimage|salt|participantSigningPrivateKey|privateKey|bearer|bearerToken|accessToken|authToken)(?:["'_/\\-]|$)/iu;
const CHILD_ENVIRONMENT_NAMES = Object.freeze(["PATH", "TMPDIR", "LANG", "LC_ALL", "GOTOOLCHAIN", "GOCACHE", "GOMODCACHE", "GOPATH"]);
const STABLE_PARTICIPANT_ORIGINATED_ROUTES = Object.freeze({
  beginImport: "/v1/participant-originated/import/begin",
  ciphertext: "/v1/participant-originated/import/ciphertext",
  artifactManifest: "/v1/participant-originated/import/artifact-manifest",
  status: "/v1/participant-originated/import/status",
});

export function assertStableParticipantOriginatedRoutes(routes = participantOriginatedRoutes) {
  if (canonicalJson(routes) !== canonicalJson(STABLE_PARTICIPANT_ORIGINATED_ROUTES)) {
    die("participant-originated coordinator route contract changed");
  }
  return routes;
}

function die(message) {
  const error = new Error(message);
  error.name = "ParticipantOriginatedQualificationError";
  throw error;
}

function consumeEphemeralAuthorization() {
  const value = process.env[EPHEMERAL_AUTHORIZATION_ENV];
  delete process.env[EPHEMERAL_AUTHORIZATION_ENV];
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    die("ephemeral coordinator authorization is missing or malformed");
  }
  return value;
}

export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) die("canonical JSON accepts only safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") die("unsupported canonical JSON value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function sha256Buffer(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256Text(value) { return sha256Buffer(Buffer.from(value, "utf8")); }
function bytes32FromHex(hex) { return `0x${hex}`; }
function goDigestFromHex(hex) { return `sha256:${hex}`; }
function goDigestBytes(value) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) die(`invalid Go SHA-256 digest: ${String(value)}`);
  return Buffer.from(value.slice(7), "hex");
}

export function goDigestToBytes32(value) {
  return `0x${goDigestBytes(value).toString("hex")}`;
}

export function bytes32ToGoDigest(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/u.test(value)) die(`invalid bytes32 digest: ${String(value)}`);
  return `sha256:${value.slice(2)}`;
}

function sha256DigestBytes(bytes) { return goDigestFromHex(sha256Buffer(bytes)); }
function sha256DigestText(text) { return sha256DigestBytes(Buffer.from(text, "utf8")); }
function domainDigest(domain, object) { return sha256DigestBytes(Buffer.from(`${domain}\0${JSON.stringify(object)}`, "utf8")); }

function writePrivate(path, bytes) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    let offset = 0;
    while (offset < buffer.length) offset += writeSync(descriptor, buffer, offset, buffer.length - offset);
    fsyncSync(descriptor);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function writeExactJson(path, value, trailingNewline = false, privateFile = false) {
  const encoded = Buffer.from(`${JSON.stringify(value)}${trailingNewline ? "\n" : ""}`);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, encoded, { flag: "wx", mode: privateFile ? 0o600 : 0o600 });
  return path;
}

function writeCanonicalJson(path, value, privateFile = false) {
  const encoded = Buffer.from(canonicalJson(value));
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, encoded, { flag: "wx", mode: privateFile ? 0o600 : 0o600 });
  return path;
}

function readJson(path) { return JSON.parse(readFileSync(path, "utf8")); }

function exactRegularFile(path) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) die(`regular file required: ${path}`);
  return stat;
}

function readSecret(path, expectedBytes) {
  const stat = exactRegularFile(path);
  if ((stat.mode & 0o077) !== 0) die(`secret permissions rejected: ${path}`);
  const value = readFileSync(path);
  if (value.length !== expectedBytes) die(`secret length rejected: ${path}`);
  return value;
}

export function buildNeutralFoundationSpec({ label, participantA, participantB, nowSeconds, lifetimeSeconds = 4 * 60 * 60, caseNonce: suppliedCaseNonce }) {
  const policyId = domainDigest("MordantConflictingPledgePolicy/v1", {
    policyVersion: 1,
    service: "Conflicting Pledge Protection",
    serviceVersion: 1,
  });
  const asset = sha256DigestText(`${label}/synthetic-cleanverse-asset`);
  const caseNonce = suppliedCaseNonce ?? sha256DigestBytes(randomBytes(32));
  if (!/^sha256:[0-9a-f]{64}$/u.test(caseNonce)) die("foundation case nonce rejected");
  const holderRecordDate = new Date((nowSeconds - 60) * 1000).toISOString();
  const holderSnapshot = [
    { holderId: "HOLDER_A", protectedUnits: "60000000", allocationBps: 6000 },
    { holderId: "HOLDER_B", protectedUnits: "40000000", allocationBps: 4000 },
  ];
  const holderAllocationDigest = domainDigest("MordantProtectedHolderSnapshot/v1", {
    assetDigest: asset,
    holders: holderSnapshot.map((entry) => ({ allocationBps: entry.allocationBps, holderId: entry.holderId, protectedUnits: entry.protectedUnits })),
    recordDate: holderRecordDate,
  });
  const fheCaseId = domainDigest("MordantProtectionFHECase/v2", {
    assetDigest: asset,
    caseNonce,
    executionVariant: "CUSTOM_SUPERVISED",
    holderAllocationDigest,
    policyId,
  });
  const protectionBinding = {
    schemaVersion: "mordant.protection-binding/2",
    cleanverseAssetRecordDigest: asset,
    protectionService: "Conflicting Pledge Protection",
    protectionServiceVersion: 1,
    policyId,
    policyVersion: 1,
    fixtureClassification: "SYNTHETIC_HACKATHON_FIXTURE",
    protectedAmount: { asset: "aUSDC", minorUnits: "100000000" },
    reserveBasisPoints: 1000,
    reserveAmount: { asset: "aUSDC", minorUnits: "10000000" },
    holderRecordDate,
    holderSnapshot,
    holderAllocationDigest,
    caseNonce,
    fheCaseId,
    governedReleaseMode: "governed-decryptor-v1",
    executionVariant: "CUSTOM_SUPERVISED",
  };
  const participantIdentity = (participant, role, suffix) => ({
    id: sha256DigestText(`${label}/${suffix}`),
    role,
    signingPublicKey: Buffer.from(participant.participantSigningPublicKey.slice(2), "hex").toString("base64"),
  });
  const spec = {
    caseId: fheCaseId,
    assetIdentity: asset,
    policyId,
    participantA: participantIdentity(participantA, "PARTICIPANT_A", "participant-a"),
    participantB: participantIdentity(participantB, "PARTICIPANT_B", "participant-b"),
    caseNonce,
    createdAtUnix: nowSeconds - 5,
    expiresAtUnix: nowSeconds + lifetimeSeconds,
    protectionBinding,
  };
  return Object.freeze({ spec, fheCaseId, assetIdentity: asset, policyId, caseNonce, holderAllocationDigest });
}

export function buildGoImportRequest(metadata, caseContext) {
  const names = participantFilenames(metadata.role);
  const request = {
    schemaVersion: PARTICIPANT_ORIGINATED_IMPORT_REQUEST_SCHEMA,
    role: metadata.role,
    fheCaseId: metadata.fheCaseId,
    assetIdentityDigest: caseContext.assetIdentityDigest,
    caseBindingDigest: caseContext.caseBindingDigest,
    participantSigningKeyDigest: metadata.participantSigningKeyDigest,
    clientBundleDigest: metadata.clientBundleDigest,
    encryptionIntentDigest: metadata.encryptionIntentDigest,
    claimCommitment: metadata.claimCommitment,
    submissionNonce: metadata.submissionNonce,
    encryptedArtifactDigest: metadata.encryptedArtifactDigest,
    ciphertextObjectDigest: metadata.ciphertextObjectDigest,
    ciphertextObjectLength: metadata.ciphertextObjectLength,
    finalEncryptedAdmissionDigest: metadata.finalAdmissionDigest,
    artifactObject: { path: names.artifactManifest, sha256: bytes32ToGoDigest(metadata.artifactObjectDigest), length: metadata.artifactObjectLength },
    ciphertextObject: { path: names.ciphertext, sha256: bytes32ToGoDigest(metadata.ciphertextObjectDigest), length: metadata.ciphertextObjectLength },
  };
  return Object.freeze(request);
}

export function buildTransportMetadata({ registrationRequest, intentRequest, finalRequest, finalDigest, prepared }) {
  const admission = finalRequest.admission;
  const names = participantFilenames(admission.role);
  if (prepared.artifactObject.path !== names.artifactManifest || prepared.ciphertextObject.path !== names.ciphertext) die("participant preparation returned unexpected object names");
  return Object.freeze({
    schemaVersion: PARTICIPANT_ORIGINATED_IMPORT_SCHEMA,
    runId: admission.runId,
    fheCaseId: admission.fheCaseId,
    role: admission.role,
    participantWallet: admission.participantWallet,
    chainId: CHAIN_ID,
    participantSigningKeyDigest: admission.participantSigningKeyDigest,
    registrationDigest: admission.registrationDigest,
    encryptionIntentDigest: admission.encryptionIntentDigest,
    finalAdmissionDigest: finalDigest,
    claimCommitment: admission.claimCommitment,
    clientBundleDigest: admission.clientBundleDigest,
    encryptedArtifactDigest: admission.encryptedArtifactDigest,
    artifactObjectDigest: goDigestToBytes32(prepared.artifactObject.sha256),
    artifactObjectLength: prepared.artifactObject.length,
    ciphertextObjectDigest: admission.ciphertextObjectDigest,
    ciphertextObjectLength: admission.ciphertextObjectLength,
    registrationNonce: registrationRequest.registration.registrationNonce,
    intentNonce: intentRequest.intent.intentNonce,
    submissionNonce: admission.submissionNonce,
    issuedAt: admission.issuedAt,
    expiresAt: admission.expiresAt,
    walletAuthorizationChain: {
      registration: { schemaVersion: registrationRequest.schemaVersion, message: registrationRequest.registration, signature: registrationRequest.signature },
      encryptionIntent: { schemaVersion: intentRequest.schemaVersion, message: intentRequest.intent, signature: intentRequest.signature },
      finalAdmission: { schemaVersion: finalRequest.schemaVersion, message: finalRequest.admission, signature: finalRequest.signature },
    },
  });
}

export function processTopology(caseRoot) {
  const controlRoot = join(dirname(caseRoot), "ephemeral-control", basename(caseRoot));
  return Object.freeze({
    schemaVersion: PARTICIPANT_ORIGINATED_TOPOLOGY_SCHEMA,
    controller: {
      root: caseRoot,
      access: ["fixture construction", "public protocol outputs", "child supervision"],
      ephemeralConfigRoot: controlRoot,
      confidentialityBoundary: false,
      note: "The qualification controller knows the synthetic fixtures; only participant/coordinator/evaluator/decryptor argv and root separation are asserted.",
    },
    participantA: { root: join(caseRoot, "participant-a"), access: ["own plaintext", "own salt", "own wallet key", "own Ed25519 key", "public client bundle"] },
    participantB: { root: join(caseRoot, "participant-b"), access: ["own plaintext", "own salt", "own wallet key", "own Ed25519 key", "public client bundle"] },
    coordinator: { root: join(caseRoot, "coordinator"), access: ["public case", "authorization chain", "encrypted uploads", "import journals"], unpassedRoots: ["participant roots", "decryptor private root"] },
    evaluator: { root: join(caseRoot, "evaluator-process"), argvRoots: [join(caseRoot, "coordinator", "public")], unpassedRoots: ["decryptor private root", "participant roots"] },
    decryptor: { root: join(caseRoot, "decryptor-process"), argvRoots: [join(caseRoot, "coordinator", "public"), join(caseRoot, "decryptor-private")], unpassedRoots: ["participant roots"] },
    isolationQualification: "unpassedRoots records argv/root non-disclosure only; this harness does not claim an ACL, sandbox, mount namespace, or chroot.",
  });
}

function appendBounded(chunks, chunk, current) {
  const value = Buffer.from(chunk);
  if (current + value.length > MAX_CAPTURE_BYTES) die("child process output exceeded the bounded capture limit");
  chunks.push(value);
  return current + value.length;
}

async function runCaptured(command, args, options = {}) {
  const environment = options.env ?? minimalChildEnvironment(options.tmpRoot);
  const child = spawn(command, args, {
    cwd: options.cwd ?? REPO_ROOT,
    env: environment,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  child.stdout.on("data", (chunk) => { stdoutBytes = appendBounded(stdout, chunk, stdoutBytes); });
  child.stderr.on("data", (chunk) => { stderrBytes = appendBounded(stderr, chunk, stderrBytes); });
  let inputPromise;
  if (options.inputStream !== undefined) {
    inputPromise = pipeline(options.inputStream, child.stdin).catch((error) => {
      if (child.exitCode === null) child.kill("SIGTERM");
      throw error;
    });
  } else {
    child.stdin.end(options.input ?? undefined);
    inputPromise = Promise.resolve();
  }
  const result = await new Promise((resolveResult, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolveResult({ code, signal }));
  });
  await inputPromise;
  const output = Buffer.concat(stdout).toString("utf8");
  const diagnostic = Buffer.concat(stderr).toString("utf8");
  if (result.code !== 0) {
    const error = new Error(`${basename(command)} exited ${result.code ?? result.signal}: ${diagnostic.trim().slice(0, 2000)}`);
    error.code = "CHILD_PROCESS";
    error.exitCode = result.code;
    error.stderr = diagnostic;
    throw error;
  }
  return Object.freeze({ stdout: output, stderr: diagnostic, pid: child.pid, exitCode: result.code });
}

export function minimalChildEnvironment(tmpRoot = join(tmpdir(), `mordant-participant-originated-${process.pid}`)) {
  const resolvedTmp = resolve(tmpRoot);
  mkdirSync(resolvedTmp, { recursive: true, mode: 0o700 });
  const goCache = join(resolvedTmp, "go-cache");
  mkdirSync(goCache, { recursive: true, mode: 0o700 });
  const moduleCacheCandidates = [
    process.env.GOMODCACHE,
    typeof process.env.GOPATH === "string" && process.env.GOPATH !== "" ? join(process.env.GOPATH.split(":")[0], "pkg", "mod") : undefined,
    typeof process.env.HOME === "string" && process.env.HOME !== "" ? join(process.env.HOME, "go", "pkg", "mod") : undefined,
  ].filter((value) => typeof value === "string" && value !== "");
  let goModuleCache;
  for (const candidate of moduleCacheCandidates) {
    if (!existsSync(candidate)) continue;
    const resolved = realpathSync(candidate);
    if (statSync(resolved).isDirectory()) {
      goModuleCache = resolved;
      break;
    }
  }
  if (goModuleCache === undefined) die("a pre-populated Go module cache is required");
  const goPathCandidates = [
    typeof process.env.GOPATH === "string" && process.env.GOPATH !== "" ? process.env.GOPATH.split(":")[0] : undefined,
    dirname(dirname(goModuleCache)),
    typeof process.env.HOME === "string" && process.env.HOME !== "" ? join(process.env.HOME, "go") : undefined,
  ].filter((value) => typeof value === "string" && value !== "");
  let goPath;
  for (const candidate of goPathCandidates) {
    if (!existsSync(candidate)) continue;
    const resolved = realpathSync(candidate);
    if (statSync(resolved).isDirectory()) {
      goPath = resolved;
      break;
    }
  }
  if (goPath === undefined) die("an existing GOPATH is required for local toolchain verification");
  const environment = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    TMPDIR: resolvedTmp,
    LANG: process.env.LANG ?? "C.UTF-8",
    LC_ALL: process.env.LC_ALL ?? "C.UTF-8",
    GOCACHE: goCache,
    GOMODCACHE: goModuleCache,
    GOPATH: goPath,
  };
  if (typeof process.env.GOTOOLCHAIN === "string" && process.env.GOTOOLCHAIN !== "") environment.GOTOOLCHAIN = process.env.GOTOOLCHAIN;
  return Object.freeze(environment);
}

async function runJson(command, args, options = {}) {
  const result = await runCaptured(command, args, options);
  let value;
  try { value = JSON.parse(result.stdout); } catch { die(`${basename(command)} did not return one JSON result`); }
  return Object.freeze({ value, process: result });
}

function replaceRoot(value, roots) {
  for (const [label, root] of roots) {
    if (value === root) return `$${label}`;
    if (value.startsWith(`${root}/`)) return `$${label}/${relative(root, value)}`;
  }
  return value;
}

function loggedInvocation(scope, command, args, cwd, roots = [], environment = minimalChildEnvironment()) {
  return Object.freeze({
    scope,
    executable: basename(command),
    argv: args.map((value) => replaceRoot(value, roots)),
    cwd: replaceRoot(cwd, roots),
    environmentNames: Object.keys(environment).sort(),
  });
}

async function loadAuthorizationModule(repoRoot = REPO_ROOT) {
  const path = join(repoRoot, ".product-test-dist", "src", "lib", "protection", "participant-originated-authorization.js");
  if (!existsSync(path)) die("compiled participant-originated authorization module is missing");
  const namespace = await import(`${pathToFileURL(path).href}?qualification=${Date.now()}`);
  return namespace.default ?? namespace;
}

async function compileAuthorizationModule(processes, environment = minimalChildEnvironment()) {
  const args = ["exec", "tsc", "-p", "tsconfig.product-tests.json"];
  const invocation = loggedInvocation("build", "pnpm", args, REPO_ROOT, [["REPO", REPO_ROOT]], environment);
  const result = await runCaptured("pnpm", args, { cwd: REPO_ROOT, env: environment });
  processes.push({ ...invocation, pid: result.pid });
  if (!existsSync(AUTH_COMPILED_PATH)) die("TypeScript authorization compilation produced no module");
}

async function buildGoBinaries(binaryRoot, processes, environment = minimalChildEnvironment()) {
  mkdirSync(binaryRoot, { recursive: true, mode: 0o700 });
  const commands = ["mordant-fhe-keygen", "mordant-fhe-client", "mordant-fhe-import", "mordant-fhe-evaluator", "mordant-fhe-decryptor"];
  const binaries = {};
  for (const name of commands) {
    const output = join(binaryRoot, name);
    const args = ["build", "-trimpath", "-o", output, `./cmd/${name}`];
    const invocation = loggedInvocation("build", "go", args, GO_ROOT, [["REPO", REPO_ROOT], ["BIN", binaryRoot]], environment);
    const result = await runCaptured("go", args, { cwd: GO_ROOT, env: environment });
    processes.push({ ...invocation, pid: result.pid });
    exactRegularFile(output);
    binaries[name] = output;
  }
  return Object.freeze(binaries);
}

function binaryManifest(binaries) {
  const entries = Object.fromEntries(Object.entries(binaries).map(([name, path]) => [name, {
    sha256: sha256DigestBytes(readFileSync(path)),
    bytes: statSync(path).size,
  }]));
  const encoded = Buffer.from(canonicalJson(entries));
  return Object.freeze({ entries, digest: sha256DigestBytes(encoded) });
}

function sourceManifest() {
  const roots = [
    join(REPO_ROOT, "src", "lib", "protection", "participant-originated-authorization.ts"),
    join(REPO_ROOT, "scripts", "participant-originated-coordinator.mjs"),
    SCRIPT_PATH,
    join(GO_ROOT, "governedfhe", "participant_originated_artifact.go"),
    join(GO_ROOT, "governedfhe", "participant_originated_ceremony.go"),
    join(GO_ROOT, "governedfhe", "store.go"),
    join(GO_ROOT, "cmd", "mordant-fhe-client", "main.go"),
    join(GO_ROOT, "cmd", "mordant-fhe-keygen", "main.go"),
    join(GO_ROOT, "cmd", "mordant-fhe-import", "main.go"),
  ];
  const files = roots.map((path) => ({ path: relative(REPO_ROOT, path), sha256: sha256DigestBytes(readFileSync(path)) }));
  return Object.freeze({ files, digest: sha256DigestBytes(Buffer.from(canonicalJson(files))) });
}

async function sourceSha() {
  return (await runCaptured("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT })).stdout.trim();
}

async function toolchain(environment = minimalChildEnvironment()) {
  const [node, go, pnpm, operatingSystem] = await Promise.all([
    runCaptured(process.execPath, ["--version"], { cwd: REPO_ROOT, env: environment }),
    runCaptured("go", ["version"], { cwd: GO_ROOT, env: environment }),
    runCaptured("pnpm", ["--version"], { cwd: REPO_ROOT, env: environment }),
    runCaptured("uname", ["-srm"], { cwd: REPO_ROOT, env: environment }),
  ]);
  return Object.freeze({
    node: node.stdout.trim(), go: go.stdout.trim(), pnpm: pnpm.stdout.trim(),
    operatingSystem: operatingSystem.stdout.trim(), platform: `${process.platform}/${process.arch}`,
  });
}

async function participantWallet(root) {
  const secret = readSecret(join(root, "wallet.key"), 66).toString("ascii");
  if (!/^0x[0-9a-f]{64}$/u.test(secret)) die("participant wallet key encoding rejected");
  const { privateKeyToAccount } = await import("viem/accounts");
  return privateKeyToAccount(secret);
}

function participantRoots(root) {
  return Object.freeze({
    root,
    wallet: join(root, "wallet.key"),
    signingKey: join(root, "artifact-signing.key"),
    pledge: join(root, "private-pledge.json"),
    salt: join(root, "claim-salt.bin"),
    bundle: join(root, "client-bundle"),
    artifact: join(root, "encrypted-artifact"),
    bundleExpectations: join(root, "bundle-expectations.json"),
    preparationRequest: join(root, "preparation-request.json"),
    registrationRequest: join(root, "wallet-registration.json"),
    intentRequest: join(root, "wallet-intent.json"),
    finalRequest: join(root, "wallet-final-admission.json"),
    transportMetadata: join(root, "transport-metadata.json"),
  });
}

async function participantChildAction(action, input) {
  const config = readJson(input);
  const roots = participantRoots(config.root);
  const auth = await loadAuthorizationModule(config.repoRoot ?? REPO_ROOT);
  const processRecords = [];
  if (action === "init") {
    mkdirSync(roots.root, { recursive: true, mode: 0o700 });
    const { privateKeyToAccount } = await import("viem/accounts");
    let walletSecret;
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const candidate = `0x${randomBytes(32).toString("hex")}`;
      try {
        privateKeyToAccount(candidate);
        walletSecret = candidate;
        break;
      } catch { /* draw another valid secp256k1 scalar */ }
    }
    if (walletSecret === undefined) die("participant wallet scalar generation failed");
    writePrivate(roots.wallet, Buffer.from(walletSecret, "ascii"));
    const account = await participantWallet(roots.root);
    const args = ["-mode", "participant-keygen", "-signing-key", roots.signingKey];
    const invocation = loggedInvocation(config.role, config.clientBinary, args, roots.root, [[config.role, roots.root]]);
    const generated = await runJson(config.clientBinary, args, { cwd: roots.root });
    processRecords.push({ ...invocation, pid: generated.process.pid });
    return { schemaVersion: "mordant.participant-process-init/1", role: config.role, participantWallet: account.address, ...generated.value, processes: processRecords };
  }
  if (action === "sign-registration") {
    const account = await participantWallet(roots.root);
    if (account.address !== config.message.participantWallet) die("participant registration wallet mismatch");
    const request = {
      schemaVersion: auth.PARTICIPANT_SIGNING_KEY_REGISTRATION_SCHEMA,
      registration: config.message,
      signature: await account.signTypedData(auth.participantSigningKeyRegistrationTypedData(config.message, CHAIN_ID)),
    };
    writeCanonicalJson(roots.registrationRequest, request);
    return { schemaVersion: "mordant.participant-process-registration/1", role: config.role, request, processes: processRecords };
  }
  if (action === "sign-ceremony") {
    const args = ["-mode", "participant-ceremony-sign", "-request", config.requestPath, "-signing-key", roots.signingKey];
    const invocation = loggedInvocation(config.role, config.clientBinary, args, roots.root, [[config.role, roots.root], ["CASE", config.caseRoot]]);
    const signed = await runCaptured(config.clientBinary, args, { cwd: roots.root });
    processRecords.push({ ...invocation, pid: signed.pid });
    const approval = JSON.parse(signed.stdout);
    writeFileSync(config.approvalPath, signed.stdout, { flag: "wx", mode: 0o600 });
    return { schemaVersion: "mordant.participant-process-ceremony/1", role: config.role, approval, processes: processRecords };
  }
  if (action === "claim-and-sign-intent") {
    const args = [
      "-mode", "participant-claim", "-bundle-root", roots.bundle,
      "-bundle-expectations", roots.bundleExpectations, "-pledge", roots.pledge, "-claim-salt", roots.salt,
    ];
    const invocation = loggedInvocation(config.role, config.clientBinary, args, roots.root, [[config.role, roots.root]]);
    const claim = await runJson(config.clientBinary, args, { cwd: roots.root });
    processRecords.push({ ...invocation, pid: claim.process.pid });
    const account = await participantWallet(roots.root);
    const message = { ...config.intentBase, claimCommitment: claim.value.claimCommitment };
    const request = {
      schemaVersion: auth.PARTICIPANT_ENCRYPTION_INTENT_SCHEMA,
      intent: message,
      signature: await account.signTypedData(auth.participantEncryptionIntentTypedData(message, CHAIN_ID)),
    };
    writeCanonicalJson(roots.intentRequest, request);
    return { schemaVersion: "mordant.participant-process-intent/1", role: config.role, claim: claim.value, request, processes: processRecords };
  }
  if (action === "prepare-and-sign-final") {
    const args = [
      "-mode", "participant-prepare", "-bundle-root", roots.bundle,
      "-bundle-expectations", roots.bundleExpectations, "-output-root", roots.artifact,
      "-pledge", roots.pledge, "-claim-salt", roots.salt, "-signing-key", roots.signingKey,
      "-request", roots.preparationRequest,
    ];
    const invocation = loggedInvocation(config.role, config.clientBinary, args, roots.root, [[config.role, roots.root]]);
    const prepared = await runJson(config.clientBinary, args, { cwd: roots.root });
    processRecords.push({ ...invocation, pid: prepared.process.pid });
    const account = await participantWallet(roots.root);
    const message = {
      ...config.finalBase,
      encryptedArtifactDigest: prepared.value.encryptedArtifactDigest,
      ciphertextObjectDigest: prepared.value.ciphertextObjectDigest,
      ciphertextObjectLength: prepared.value.ciphertextObjectLength,
      submissionNonce: prepared.value.submissionNonce,
    };
    const request = {
      schemaVersion: auth.PARTICIPANT_FINAL_ENCRYPTED_ADMISSION_SCHEMA,
      admission: message,
      signature: await account.signTypedData(auth.participantFinalEncryptedAdmissionTypedData(message, CHAIN_ID)),
    };
    const finalDigest = auth.participantFinalEncryptedAdmissionDigest(message, CHAIN_ID);
    const registrationRequest = readJson(roots.registrationRequest);
    const intentRequest = readJson(roots.intentRequest);
    const metadata = buildTransportMetadata({ registrationRequest, intentRequest, finalRequest: request, finalDigest, prepared: prepared.value });
    writeCanonicalJson(roots.finalRequest, request);
    writeCanonicalJson(roots.transportMetadata, metadata);
    return { schemaVersion: "mordant.participant-process-final/1", role: config.role, prepared: prepared.value, request, finalAdmissionDigest: finalDigest, metadata, processes: processRecords };
  }
  if (action === "upload") {
    const ephemeralAuthorization = consumeEphemeralAuthorization();
    const metadata = readJson(roots.transportMetadata);
    const names = participantFilenames(config.role);
    const headers = { authorization: `Bearer ${ephemeralAuthorization}` };
    const begin = await fetch(`${config.baseUrl}${participantOriginatedRoutes.beginImport}`, {
      method: "POST",
      headers: { ...headers, "content-type": PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE },
      body: canonicalJson(metadata),
    });
    const reservation = await begin.json();
    if (!begin.ok || typeof reservation.ticket !== "string") die(`coordinator begin rejected ${config.role}: ${JSON.stringify(reservation)}`);
    const put = async (route, path, contentType) => {
      const size = exactRegularFile(path).size;
      const response = await fetch(`${config.baseUrl}${route}`, {
        method: "PUT",
        headers: {
          ...headers,
          [PARTICIPANT_ORIGINATED_TICKET_HEADER]: reservation.ticket,
          "content-type": contentType,
          "content-length": String(size),
        },
        body: createReadStream(path),
        duplex: "half",
      });
      const body = await response.json();
      if (!response.ok) die(`coordinator upload rejected ${config.role}: ${JSON.stringify(body)}`);
      return body;
    };
    const ciphertext = await put(participantOriginatedRoutes.ciphertext, join(roots.artifact, names.ciphertext), PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE);
    const published = await put(participantOriginatedRoutes.artifactManifest, join(roots.artifact, names.artifactManifest), PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE);
    if (ciphertext.state !== "CIPHERTEXT_STAGED" || published.state !== "PUBLISHED") die("coordinator state transition rejected");
    return {
      schemaVersion: "mordant.participant-process-upload/1",
      role: config.role,
      // Returned only to the in-memory qualification controller so the exact
      // bearer-like capability can be included in the secret scan. It is never
      // copied into retained evidence or a durable coordinator record.
      ephemeralTicket: reservation.ticket,
      published: { ticketRef: published.ticketRef, state: published.state, filenames: published.filenames, digests: published.digests },
      processes: processRecords,
    };
  }
  die(`unknown internal participant action: ${action}`);
}

function realAuthorizationRequests(metadata) {
  const chain = metadata.walletAuthorizationChain;
  return Object.freeze({
    registration: { schemaVersion: chain.registration.schemaVersion, registration: chain.registration.message, signature: chain.registration.signature },
    intent: { schemaVersion: chain.encryptionIntent.schemaVersion, intent: chain.encryptionIntent.message, signature: chain.encryptionIntent.signature },
    final: { schemaVersion: chain.finalAdmission.schemaVersion, admission: chain.finalAdmission.message, signature: chain.finalAdmission.signature },
  });
}

// The coordinator reserves roles and nonces from the compact top-level
// metadata.  Those reservation facts must be the exact projection of the
// signed authorization chain; validating the nested signatures alone is not
// sufficient because an authenticated caller could otherwise relabel a valid
// chain before the expensive artifact verifier runs.
export function assertMetadataAuthorizationProjection(metadata) {
  const requests = realAuthorizationRequests(metadata);
  const registration = requests.registration.registration;
  const intent = requests.intent.intent;
  const admission = requests.final.admission;
  const comparisons = [
    [metadata.chainId, CHAIN_ID],
    [metadata.runId, registration.runId],
    [metadata.runId, intent.runId],
    [metadata.runId, admission.runId],
    [metadata.fheCaseId, registration.fheCaseId],
    [metadata.fheCaseId, intent.fheCaseId],
    [metadata.fheCaseId, admission.fheCaseId],
    [metadata.role, registration.role],
    [metadata.role, intent.role],
    [metadata.role, admission.role],
    [metadata.participantWallet, registration.participantWallet],
    [metadata.participantWallet, intent.participantWallet],
    [metadata.participantWallet, admission.participantWallet],
    [metadata.participantSigningKeyDigest, registration.participantSigningKeyDigest],
    [metadata.participantSigningKeyDigest, intent.participantSigningKeyDigest],
    [metadata.participantSigningKeyDigest, admission.participantSigningKeyDigest],
    [metadata.registrationDigest, intent.registrationDigest],
    [metadata.registrationDigest, admission.registrationDigest],
    [metadata.encryptionIntentDigest, admission.encryptionIntentDigest],
    [metadata.claimCommitment, intent.claimCommitment],
    [metadata.claimCommitment, admission.claimCommitment],
    [metadata.clientBundleDigest, intent.clientBundleDigest],
    [metadata.clientBundleDigest, admission.clientBundleDigest],
    [metadata.encryptedArtifactDigest, admission.encryptedArtifactDigest],
    [metadata.ciphertextObjectDigest, admission.ciphertextObjectDigest],
    [metadata.ciphertextObjectLength, admission.ciphertextObjectLength],
    [metadata.registrationNonce, registration.registrationNonce],
    [metadata.intentNonce, intent.intentNonce],
    [metadata.submissionNonce, admission.submissionNonce],
    [metadata.issuedAt, admission.issuedAt],
    [metadata.expiresAt, admission.expiresAt],
  ];
  if (comparisons.some(([actual, expected]) => actual !== expected)) {
    die("transport metadata is not the exact signed authorization projection");
  }
  return Object.freeze(requests);
}

function exactObjectKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return keys.length === wanted.length && keys.every((key, index) => key === wanted[index]);
}

export function validateGoArtifactVerification(verification) {
  const members = [
    "schemaVersion", "role", "caseId", "assetIdentity", "caseBindingDigest", "participantId",
    "signingKeyDigest", "bundleDigest", "parameterProfile", "parameterFingerprint", "fhePublicKeyDigest",
    "circuitDigest", "encryptionIntentDigest", "claimCommitment", "submissionNonce", "artifactDigest",
    "ciphertextDigest", "finalEncryptedAdmissionDigest", "artifactObject", "ciphertextObject", "expiresAtUnix",
    "verifiedAtUnix",
  ];
  if (!exactObjectKeys(verification, members) || verification.schemaVersion !== "mordant.participant-originated-artifact-verification/1" ||
      !["PARTICIPANT_A", "PARTICIPANT_B"].includes(verification.role) ||
      typeof verification.parameterProfile !== "string" || verification.parameterProfile.length === 0 || verification.parameterProfile.length > 128 ||
      !/^0x[0-9a-f]{64}$/u.test(verification.encryptionIntentDigest) || !/^0x[0-9a-f]{64}$/u.test(verification.finalEncryptedAdmissionDigest) ||
      !Number.isSafeInteger(verification.expiresAtUnix) || verification.expiresAtUnix <= 0 ||
      !Number.isSafeInteger(verification.verifiedAtUnix) || verification.verifiedAtUnix <= 0) die("Go artifact verification shape rejected");
  for (const field of [
    "caseId", "assetIdentity", "caseBindingDigest", "participantId", "signingKeyDigest", "bundleDigest",
    "parameterFingerprint", "fhePublicKeyDigest", "circuitDigest", "claimCommitment", "submissionNonce",
    "artifactDigest", "ciphertextDigest",
  ]) goDigestBytes(verification[field]);
  for (const field of ["artifactObject", "ciphertextObject"]) {
    const object = verification[field];
    if (!exactObjectKeys(object, ["path", "sha256", "length"]) || typeof object.path !== "string" || !/^[a-z0-9.-]{1,64}$/u.test(object.path) ||
        !Number.isSafeInteger(object.length) || object.length <= 0) die("Go artifact verification object reference rejected");
    goDigestBytes(object.sha256);
  }
  const names = participantFilenames(verification.role);
  if (verification.artifactObject.path !== names.artifactManifest || verification.ciphertextObject.path !== names.ciphertext) die("Go artifact verification object reference rejected");
  if (verification.ciphertextObject.sha256 !== verification.ciphertextDigest) die("Go ciphertext verification reference mismatch");
  return Object.freeze(verification);
}

export function assertGoArtifactVerificationMatches(metadata, context, verification) {
  validateGoArtifactVerification(verification);
  const expectedNames = participantFilenames(metadata.role);
  const comparisons = [
    [verification.role, metadata.role],
    [goDigestToBytes32(verification.caseId), metadata.fheCaseId],
    [goDigestToBytes32(verification.assetIdentity), context.assetIdentityDigest],
    [goDigestToBytes32(verification.caseBindingDigest), context.caseBindingDigest],
    [goDigestToBytes32(verification.signingKeyDigest), metadata.participantSigningKeyDigest],
    [goDigestToBytes32(verification.bundleDigest), metadata.clientBundleDigest],
    [verification.parameterProfile, context.parameterProfile],
    [goDigestToBytes32(verification.parameterFingerprint), context.parameterFingerprint],
    [goDigestToBytes32(verification.fhePublicKeyDigest), context.fhePublicKeyDigest],
    [goDigestToBytes32(verification.circuitDigest), context.circuitDigest],
    [verification.encryptionIntentDigest, metadata.encryptionIntentDigest],
    [goDigestToBytes32(verification.claimCommitment), metadata.claimCommitment],
    [goDigestToBytes32(verification.submissionNonce), metadata.submissionNonce],
    [goDigestToBytes32(verification.artifactDigest), metadata.encryptedArtifactDigest],
    [goDigestToBytes32(verification.ciphertextDigest), metadata.ciphertextObjectDigest],
    [verification.finalEncryptedAdmissionDigest, metadata.finalAdmissionDigest],
    [verification.artifactObject.path, expectedNames.artifactManifest],
    [goDigestToBytes32(verification.artifactObject.sha256), metadata.artifactObjectDigest],
    [verification.artifactObject.length, metadata.artifactObjectLength],
    [verification.ciphertextObject.path, expectedNames.ciphertext],
    [goDigestToBytes32(verification.ciphertextObject.sha256), metadata.ciphertextObjectDigest],
    [verification.ciphertextObject.length, metadata.ciphertextObjectLength],
    [verification.expiresAtUnix, metadata.expiresAt],
  ];
  if (comparisons.some(([actual, expected]) => actual !== expected)) die("Go artifact verification did not match authenticated transport facts");
  return verification;
}

function artifactContextFrom(metadata, context, verification) {
  if (verification === undefined) {
    return Object.freeze({
      encryptedArtifactDigest: metadata.encryptedArtifactDigest,
      ciphertextObjectDigest: metadata.ciphertextObjectDigest,
      ciphertextObjectLength: metadata.ciphertextObjectLength,
      fheCaseId: metadata.fheCaseId,
      caseBindingDigest: context.caseBindingDigest,
      assetIdentityDigest: context.assetIdentityDigest,
      role: metadata.role,
      participantSigningKeyDigest: metadata.participantSigningKeyDigest,
      parameterProfile: context.parameterProfile,
      parameterFingerprint: context.parameterFingerprint,
      fhePublicKeyDigest: context.fhePublicKeyDigest,
      circuitDigest: context.circuitDigest,
      submissionNonce: metadata.submissionNonce,
      expiresAt: metadata.expiresAt,
      embeddedEncryptionIntentDigest: metadata.encryptionIntentDigest,
      embeddedClaimCommitment: metadata.claimCommitment,
    });
  }
  validateGoArtifactVerification(verification);
  return Object.freeze({
    encryptedArtifactDigest: goDigestToBytes32(verification.artifactDigest),
    ciphertextObjectDigest: goDigestToBytes32(verification.ciphertextDigest),
    ciphertextObjectLength: verification.ciphertextObject.length,
    fheCaseId: goDigestToBytes32(verification.caseId),
    caseBindingDigest: goDigestToBytes32(verification.caseBindingDigest),
    assetIdentityDigest: goDigestToBytes32(verification.assetIdentity),
    role: verification.role,
    participantSigningKeyDigest: goDigestToBytes32(verification.signingKeyDigest),
    parameterProfile: verification.parameterProfile,
    parameterFingerprint: goDigestToBytes32(verification.parameterFingerprint),
    fhePublicKeyDigest: goDigestToBytes32(verification.fhePublicKeyDigest),
    circuitDigest: goDigestToBytes32(verification.circuitDigest),
    submissionNonce: goDigestToBytes32(verification.submissionNonce),
    expiresAt: verification.expiresAtUnix,
    embeddedEncryptionIntentDigest: verification.encryptionIntentDigest,
    embeddedClaimCommitment: goDigestToBytes32(verification.claimCommitment),
  });
}

async function verifyRealAuthorizationChain(auth, metadata, context, verification) {
  const requests = assertMetadataAuthorizationProjection(metadata);
  const now = Math.floor(Date.now() / 1000);
  const registration = await auth.verifyParticipantSigningKeyRegistration(requests.registration, {
    verifyingService: VERIFYING_SERVICE,
    runId: context.runId,
    fheCaseId: context.fheCaseId,
    assetIdentityDigest: context.assetIdentityDigest,
    policyDigest: context.policyDigest,
    role: metadata.role,
    participantWallet: context.participantWallet,
    now,
    chainId: CHAIN_ID,
  });
  if (registration.registrationDigest !== metadata.registrationDigest) die("registration digest did not match transport metadata");
  const intent = await auth.verifyParticipantEncryptionIntent(requests.intent, {
    ...context,
    verifyingService: VERIFYING_SERVICE,
    role: metadata.role,
    participantWallet: context.participantWallet,
    registration,
    now,
    chainId: CHAIN_ID,
  });
  if (intent.encryptionIntentDigest !== metadata.encryptionIntentDigest) die("intent digest did not match transport metadata");
  if (verification !== undefined) assertGoArtifactVerificationMatches(metadata, context, verification);
  const final = await auth.verifyParticipantFinalEncryptedAdmission(requests.final, {
    ...context,
    verifyingService: VERIFYING_SERVICE,
    role: metadata.role,
    participantWallet: context.participantWallet,
    registration,
    intent,
    artifact: artifactContextFrom(metadata, context, verification),
    now,
    chainId: CHAIN_ID,
  });
  if (final.finalAdmissionDigest !== metadata.finalAdmissionDigest) die("final-admission digest did not match transport metadata");
  return Object.freeze({ registration, intent, final });
}

function appendProcessJournal(path, record) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  appendFileSync(path, `${canonicalJson(record)}\n`, { mode: 0o600 });
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function exactImportRequestPath(config, ticketRef, metadata) {
  const path = join(config.importRequestRoot, `${ticketRef}.json`);
  const request = buildGoImportRequest(metadata, config.contexts[metadata.role]);
  const encoded = Buffer.from(`${JSON.stringify(request)}\n`);
  mkdirSync(config.importRequestRoot, { recursive: true, mode: 0o700 });
  try { writeFileSync(path, encoded, { flag: "wx", mode: 0o600 }); } catch (error) {
    if (error?.code !== "EEXIST" || !readFileSync(path).equals(encoded)) throw error;
  }
  return path;
}

async function coordinatorGo(config, scope, args, options = {}) {
  const roots = [["COORDINATOR", config.coordinatorRoot], ["PUBLIC", config.publicRoot], ["IMPORT_JOURNAL", config.importJournalRoot]];
  const environment = minimalChildEnvironment(config.tmpRoot);
  const invocation = loggedInvocation(scope, config.importBinary, args, config.coordinatorRoot, roots, environment);
  appendProcessJournal(config.processJournal, { event: "PROCESS_STARTED", supervisorPid: process.pid, ...invocation });
  const result = await runJson(config.importBinary, args, { cwd: config.coordinatorRoot, inputStream: options.inputStream, env: environment });
  appendProcessJournal(config.processJournal, { event: "PROCESS_COMPLETED", supervisorPid: process.pid, childPid: result.process.pid, scope });
  return result;
}

async function coordinatorChild(configPath) {
  const config = readJson(configPath);
  const ephemeralAuthorization = consumeEphemeralAuthorization();
  const auth = await loadAuthorizationModule(config.repoRoot ?? REPO_ROOT);
  const authenticateRequest = async ({ request, metadata }) => {
    const header = request?.headers?.authorization;
    if (header !== `Bearer ${ephemeralAuthorization}`) return false;
    const context = config.contexts[metadata.role];
    if (context === undefined) return false;
    const suffix = metadata.role === "PARTICIPANT_A" ? "a" : "b";
    const preregistered = readJson(join(config.phase0Root, `wallet-registration-${suffix}.json`));
    if (canonicalJson(preregistered.request) !== canonicalJson(realAuthorizationRequests(metadata).registration) ||
        preregistered.registrationDigest !== metadata.registrationDigest ||
        preregistered.registrationNonce !== metadata.registrationNonce) return false;
    await verifyRealAuthorizationChain(auth, metadata, context);
    return { finalAdmissionDigest: metadata.finalAdmissionDigest };
  };
  const coordinator = await createParticipantOriginatedCoordinator({
    root: config.transportRoot,
    authenticate: authenticateRequest,
    stageObject: async ({ kind, readable, metadata, ticketRef, quarantineRoot, expected }) => {
      const requestPath = exactImportRequestPath(config, ticketRef, metadata);
      const args = [
        "-mode", "stage-object", "-request", requestPath, "-quarantine-root", quarantineRoot,
        "-object-kind", kind,
      ];
      const output = await coordinatorGo(config, `coordinator-stage-${kind}`, args, { inputStream: readable });
      const object = output.value.object;
      const normalized = { path: object.path, digest: goDigestToBytes32(object.sha256), length: object.length };
      if (normalized.path !== expected.filename || normalized.digest !== expected.digest || normalized.length !== expected.length) die("Go stage-object returned another reference");
      return normalized;
    },
    verifyArtifact: async ({ metadata, ticketRef, quarantineRoot }) => {
      const requestPath = exactImportRequestPath(config, ticketRef, metadata);
      const args = ["-mode", "verify", "-request", requestPath, "-public-root", config.publicRoot, "-quarantine-root", quarantineRoot];
      const output = await coordinatorGo(config, "coordinator-verify", args);
      await verifyRealAuthorizationChain(auth, metadata, config.contexts[metadata.role], output.value.verification);
      return output.value;
    },
    publishArtifact: async ({ metadata, ticketRef, quarantineRoot }) => {
      const requestPath = exactImportRequestPath(config, ticketRef, metadata);
      const args = [
        "-mode", "publish", "-request", requestPath, "-public-root", config.publicRoot,
        "-quarantine-root", quarantineRoot, "-journal-root", config.importJournalRoot,
      ];
      return (await coordinatorGo(config, "coordinator-publish", args)).value;
    },
    reconcilePublication: async ({ metadata, ticketRef, quarantineRoot }) => {
      const suffix = metadata.role === "PARTICIPANT_A" ? "a" : "b";
      if (!existsSync(join(config.importJournalRoot, `participant-${suffix}-import-completed.json`))) return false;
      const requestPath = exactImportRequestPath(config, ticketRef, metadata);
      const args = [
        "-mode", "reconcile", "-request", requestPath, "-public-root", config.publicRoot,
        "-quarantine-root", quarantineRoot, "-journal-root", config.importJournalRoot,
      ];
      return (await coordinatorGo(config, "coordinator-reconcile", args)).value;
    },
  });
  const server = createParticipantOriginatedCoordinatorServer(coordinator);
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(config.port ?? 0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (address === null || typeof address === "string") die("coordinator did not bind TCP");
  process.stdout.write(`${JSON.stringify({ schemaVersion: "mordant.participant-originated-coordinator-ready/1", pid: process.pid, port: address.port })}\n`);
  const stop = () => server.close(() => process.exit(0));
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  await new Promise(() => {});
}

export function bundleContextFrom(bundle, bundleExport, participantWallet) {
  if (bundle.runId !== bundleExport.runId || bundle.role !== bundleExport.role) die("client bundle export identity mismatch");
  const digest = (value) => goDigestToBytes32(value);
  return Object.freeze({
    runId: bundle.runId,
    fheCaseId: digest(bundle.caseId),
    caseBindingDigest: digest(bundle.caseBindingDigest),
    protectionBindingDigest: digest(bundle.protectionBindingDigest),
    assetIdentityDigest: digest(bundle.assetIdentity),
    policyDigest: digest(bundle.policyId),
    circuitId: bundle.circuitId,
    circuitVersion: bundle.circuitVersion,
    circuitDigest: digest(bundle.circuitDigest),
    parameterProfile: bundle.parameterProfile,
    parameterFingerprint: digest(bundle.parameterFingerprint),
    fhePublicKeyDigest: digest(bundle.fhePublicKeyDigest),
    releaseAuthorityId: digest(bundle.releaseAuthorityId),
    releaseMode: bundle.releaseMode,
    clientBundleDigest: digest(bundleExport.bundleDigest),
    clientSourceDigest: digest(bundle.expectedSourceDigest),
    clientBuildDigest: digest(bundle.expectedBuildManifestDigest),
    clientBinaryDigest: digest(bundle.expectedClientBinaryDigest),
    bundleExpiresAt: bundle.expiresAtUnix,
    participantWallet,
  });
}

function hashRegularFile(path) {
  let descriptor;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink < 1) die(`evidence object is not a regular file: ${path}`);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(128 * 1024);
    let length = 0;
    for (;;) {
      const count = readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      length += count;
      hash.update(buffer.subarray(0, count));
    }
    const after = fstatSync(descriptor);
    const pathAfter = lstatSync(path);
    if (!pathAfter.isFile() || pathAfter.isSymbolicLink() || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        after.dev !== pathAfter.dev || after.ino !== pathAfter.ino || after.size !== pathAfter.size || length !== before.size) die(`evidence object changed while hashing: ${path}`);
    return Object.freeze({ sha256: `sha256:${hash.digest("hex")}`, length });
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function countNeedleInFile(path, needle) {
  if (!Buffer.isBuffer(needle) || needle.length === 0 || needle.length > 64 * 1024) die("forbidden byte sequence rejected");
  let descriptor;
  let carry = Buffer.alloc(0);
  let matches = 0;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const buffer = Buffer.allocUnsafe(128 * 1024);
    for (;;) {
      const count = readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      const combined = Buffer.concat([carry, buffer.subarray(0, count)]);
      let offset = 0;
      for (;;) {
        const found = combined.indexOf(needle, offset);
        if (found < 0) break;
        if (found + needle.length > carry.length) matches += 1;
        offset = found + 1;
      }
      carry = combined.subarray(Math.max(0, combined.length - needle.length + 1));
    }
    return matches;
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

function countNeedleInBuffer(haystack, needle) {
  if (!Buffer.isBuffer(haystack) || !Buffer.isBuffer(needle) || needle.length === 0 || needle.length > 64 * 1024) {
    die("forbidden evidence byte sequence rejected");
  }
  let matches = 0;
  let offset = 0;
  for (;;) {
    const found = haystack.indexOf(needle, offset);
    if (found < 0) return matches;
    matches += 1;
    offset = found + 1;
  }
}

export function scanRetainedEvidence(value, forbiddenByteSources = []) {
  const encoded = Buffer.from(canonicalJson(value));
  const byteChecks = forbiddenByteSources.map(({ label, bytes }) => {
    if (typeof label !== "string" || !/^[a-z0-9-]{1,96}$/u.test(label) || !Buffer.isBuffer(bytes) || bytes.length < 8) {
      die("retained evidence scan source rejected");
    }
    return Object.freeze({ label, matchCount: countNeedleInBuffer(encoded, bytes) });
  });
  const forbiddenMember = forbiddenJsonPath(value);
  return Object.freeze({
    schemaVersion: "mordant.participant-originated-retained-evidence-scan/1",
    passed: forbiddenMember === null && byteChecks.every(({ matchCount }) => matchCount === 0),
    forbiddenMember,
    byteChecks,
  });
}

function appendSecretRepresentations(target, label, bytes) {
  const value = Buffer.from(bytes);
  if (value.length < 8) die("secret representation source rejected");
  const variants = [
    ["raw", value],
    ["hex", Buffer.from(value.toString("hex"))],
    ["0xhex", Buffer.from(`0x${value.toString("hex")}`)],
    ["base64", Buffer.from(value.toString("base64"))],
    ["base64url", Buffer.from(value.toString("base64url"))],
  ];
  const seen = new Set();
  for (const [encoding, variant] of variants) {
    const key = variant.toString("hex");
    if (variant.length < 8 || seen.has(key)) continue;
    seen.add(key);
    target.push(Object.freeze({ label: `${label}-${encoding}`, bytes: variant }));
  }
}

function retainedForbiddenMaterial(roleEntries, secretSources, ephemeralAuthorization, participantRoots, publications) {
  const sources = [];
  for (const { label, path } of secretSources) {
    const value = readFileSync(path);
    appendSecretRepresentations(sources, label, value);
    if (label.startsWith("artifact-signing-key-") && value.length === 64) {
      appendSecretRepresentations(sources, `${label}-seed`, value.subarray(0, 32));
    }
    if (label.startsWith("wallet-key-") && /^0x[0-9a-f]{64}$/u.test(value.toString("ascii"))) {
      appendSecretRepresentations(sources, `${label}-scalar`, Buffer.from(value.toString("ascii").slice(2), "hex"));
    }
  }
  for (const [role, roots] of roleEntries) {
    const suffix = role === "PARTICIPANT_A" ? "a" : "b";
    const pledge = readJson(roots.pledge);
    appendSecretRepresentations(sources, `pledge-${suffix}-document`, readFileSync(roots.pledge));
    for (const field of ["activeFrom", "activeUntil", "amount", "currency", "obligationId", "receivableId", "exclusive", "receivableCommitment"]) {
      sources.push(Object.freeze({
        label: `pledge-${suffix}-field-${field.toLowerCase()}`,
        bytes: Buffer.from(`${JSON.stringify(field)}:${canonicalJson(pledge[field])}`),
      }));
    }
    for (const field of ["currency", "obligationId", "receivableId"]) {
      const encoded = pledge[field];
      if (typeof encoded !== "string" || !/^0x[0-9a-f]{64}$/u.test(encoded)) die("private pledge bytes32 source rejected");
      appendSecretRepresentations(sources, `pledge-${suffix}-${field.toLowerCase()}`, Buffer.from(encoded.slice(2), "hex"));
    }
    const ticket = publications[role]?.ephemeralTicket;
    if (typeof ticket !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(ticket)) die("ephemeral upload ticket source rejected");
    appendSecretRepresentations(sources, `upload-ticket-${suffix}`, Buffer.from(ticket));
  }
  appendSecretRepresentations(sources, "ephemeral-authorization", Buffer.from(ephemeralAuthorization));
  appendSecretRepresentations(sources, "authorization-header", Buffer.from(`Bearer ${ephemeralAuthorization}`));
  for (const [index, participantRoot] of participantRoots.entries()) {
    appendSecretRepresentations(sources, `participant-path-${index + 1}`, Buffer.from(participantRoot));
  }
  return Object.freeze(sources);
}

function walkRegularFiles(root) {
  const files = [];
  const visit = (directory) => {
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) die(`evidence directory rejected: ${directory}`);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) die(`evidence symlink rejected: ${path}`);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) files.push(path);
      else die(`unsupported evidence object: ${path}`);
    }
  };
  visit(root);
  return files.sort();
}

function forbiddenJsonPath(value, path = "$") {
  if (value === null || typeof value !== "object") return null;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = forbiddenJsonPath(value[index], `${path}[${index}]`);
      if (found !== null) return found;
    }
    return null;
  }
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[-_]/gu, "");
    if (
      ["activefrom", "activeuntil", "claim", "claimpreimage", "claimsalt", "salt", "privatekey", "participantprivatekey", "signingprivatekey", "plaintext", "preimage"].includes(normalized)
      || normalized.includes("bearer")
      || normalized.endsWith("token")
    ) return `${path}.${key}`;
    const found = forbiddenJsonPath(child, `${path}.${key}`);
    if (found !== null) return found;
  }
  return null;
}

export function assertCoordinatorControlConfig(configPath, coordinatorRoot, config) {
  const resolvedConfig = resolve(configPath);
  const resolvedDurableRoot = resolve(coordinatorRoot);
  if (resolvedConfig === resolvedDurableRoot || resolvedConfig.startsWith(`${resolvedDurableRoot}/`)) {
    die("coordinator configuration must stay outside the durable coordinator root");
  }
  const forbidden = forbiddenJsonPath(config);
  if (forbidden !== null || canonicalJson(config).includes("Bearer ")) {
    die(`coordinator configuration contains forbidden credential or participant material at ${forbidden ?? "$"}`);
  }
  return config;
}

export function scanCoordinatorState(root, participantRoots = [], forbiddenByteSources = []) {
  const resolvedRoot = realpathSync(root);
  const forbiddenNames = [];
  const forbiddenContents = [];
  const leakedParticipantRoots = [];
  const references = [];
  const files = walkRegularFiles(resolvedRoot);
  const asciiNeedles = [
    ["field-activeFrom", Buffer.from('"activeFrom"')],
    ["field-activeUntil", Buffer.from('"activeUntil"')],
    ["field-claim", Buffer.from('"claim":')],
    ["field-preimage", Buffer.from('"preimage"')],
    ["field-salt", Buffer.from('"salt"')],
    ["field-privateKey", Buffer.from('"privateKey"')],
    ["field-bearer", Buffer.from('"bearer"')],
    ["field-bearerToken", Buffer.from('"bearerToken"')],
    ["field-accessToken", Buffer.from('"accessToken"')],
    ["authorization-scheme", Buffer.from("Bearer ")],
  ];
  const secretNeedles = forbiddenByteSources.map(({ label, path, bytes }) => {
    if (typeof label !== "string" || !/^[a-z0-9-]{1,64}$/u.test(label)) die("secret scan label rejected");
    const value = Buffer.isBuffer(bytes) ? bytes : typeof path === "string" ? readFileSync(path) : null;
    if (!Buffer.isBuffer(value) || value.length === 0) die("secret scan source rejected");
    return [label, value];
  });
  const participantPathNeedles = participantRoots.map((participantRoot, index) => [
    `participant-path-${index + 1}`,
    Buffer.from(participantRoot, "utf8"),
  ]);
  const byteChecks = [...asciiNeedles, ...participantPathNeedles, ...secretNeedles].map(([label, needle]) => ({
    label,
    matchCount: files.reduce((total, path) => total + countNeedleInFile(path, needle), 0),
  }));
  for (const path of files) {
    const relativePath = relative(resolvedRoot, path);
    if (FORBIDDEN_STATE_KEY.test(relativePath)) forbiddenNames.push(relativePath);
    const reference = hashRegularFile(path);
    references.push({ path: relativePath, ...reference });
    const lower = relativePath.toLowerCase();
    if ((lower.endsWith(".json") || lower.endsWith(".ndjson") || lower.endsWith(".txt")) && reference.length <= MAX_CAPTURE_BYTES) {
      const text = readFileSync(path, "utf8");
      for (const participantRoot of participantRoots) {
        if (text.includes(participantRoot)) leakedParticipantRoots.push(relativePath);
      }
      const values = lower.endsWith(".ndjson")
        ? text.split("\n").filter(Boolean).map((line) => JSON.parse(line))
        : [JSON.parse(text)];
      for (const value of values) {
        const forbidden = forbiddenJsonPath(value);
        if (forbidden !== null) forbiddenContents.push({ path: relativePath, member: forbidden });
      }
    }
  }
  const passed = forbiddenNames.length === 0 && forbiddenContents.length === 0 && leakedParticipantRoots.length === 0 && byteChecks.every(({ matchCount }) => matchCount === 0);
  return Object.freeze({
    schemaVersion: "mordant.participant-originated-no-plaintext-scan/1",
    passed,
    checkedFiles: references.length,
    forbiddenNames,
    forbiddenContents,
    leakedParticipantRoots,
    byteChecks,
    references,
  });
}

function observableRoot(path) {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) die(`process root rejected: ${path}`);
  return Object.freeze({ path, device: String(stat.dev), inode: String(stat.ino) });
}

function topologyObservables(topology) {
  const roots = {
    controller: observableRoot(topology.controller.root),
    ephemeralControl: observableRoot(topology.controller.ephemeralConfigRoot),
    participantA: observableRoot(topology.participantA.root),
    participantB: observableRoot(topology.participantB.root),
    coordinator: observableRoot(topology.coordinator.root),
    evaluator: observableRoot(topology.evaluator.root),
    decryptor: observableRoot(topology.decryptor.root),
  };
  return Object.freeze({
    roots,
    deviceRelationships: {
      participantRootsDisjointInodes: roots.participantA.inode !== roots.participantB.inode,
      coordinatorDisjointInode: roots.coordinator.inode !== roots.participantA.inode && roots.coordinator.inode !== roots.participantB.inode,
      coordinatorConfigOutsideDurableRoot: roots.ephemeralControl.inode !== roots.coordinator.inode,
      sameDeviceObserved: new Set(Object.values(roots).map((entry) => entry.device)).size === 1,
    },
    qualification: "Device/inode observations are evidence of distinct directories, not an ACL or mount namespace.",
  });
}

export function buildParticipantOriginatedQualificationDryRunPlan(workRoot = "/ABS/participant-originated-qualification-run") {
  assertStableParticipantOriginatedRoutes();
  const casePlan = (name, expectedConflict) => {
    const root = join(workRoot, name);
    return Object.freeze({
      name,
      expectedConflict,
      topology: processTopology(root),
      order: Object.freeze([
        "participant A/B wallet and Ed25519 key generation in separate child roots",
        "real viem Phase-0 signatures and TypeScript verification",
        "Go public-key-only participant foundation",
        "Go participant ceremony requests, local signatures, imports, finalization, and thin bundle exports",
        "Go local claim commitments plus real viem Phase-1 signatures and TypeScript verification",
        "Go local encryption plus real viem Phase-2 signatures",
        "distinct HTTP coordinator child with Go stage-object, verify, publish, and reconcile callbacks",
        "unchanged evaluator child with public-root only",
        "unchanged decryptor child with public-root and decryptor-private-root only",
        "sanitized evidence extraction and exact case-root cleanup",
      ]),
      importOrder: ["ciphertext", "artifact-manifest"],
    });
  };
  return Object.freeze({
    schemaVersion: "mordant.participant-originated-product-qualification-dry-run/1",
    productProfile: PARTICIPANT_ORIGINATED_PRODUCT_PROFILE,
    privacyClaim: PARTICIPANT_ORIGINATED_PRIVACY_CLAIM,
    baseSha: PARTICIPANT_ORIGINATED_QUALIFICATION_BASE_SHA,
    coordinatorRoutes: STABLE_PARTICIPANT_ORIGINATED_ROUTES,
    executesExpensiveFhe: false,
    requiresCleanWorktree: true,
    environmentAllowlist: CHILD_ENVIRONMENT_NAMES,
    cases: [casePlan("conflict", true), casePlan("adjacent-no-conflict", false)],
    realAdapters: ["TypeScript authorization", "viem EOA signing", "mordant-fhe-import stage-object/verify/publish/reconcile"],
    semanticGap: PARTICIPANT_ORIGINATED_SEMANTIC_GAP,
  });
}

function copyRegularCreateOnly(source, destination) {
  exactRegularFile(source);
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  copyFileSync(source, destination, fsConstants.COPYFILE_EXCL);
}

function copyDirectoryCreateOnly(source, destination) {
  const sourceStat = lstatSync(source);
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink() || existsSync(destination)) die("bundle transfer destination rejected");
  mkdirSync(destination, { mode: 0o700 });
  for (const entry of readdirSync(source, { withFileTypes: true })) {
    if (!entry.isFile() || entry.isSymbolicLink()) die("thin bundle transfer accepts regular files only");
    copyRegularCreateOnly(join(source, entry.name), join(destination, entry.name));
  }
}

async function runRecordedJson(processes, scope, command, args, { cwd, roots, environment }) {
  const invocation = loggedInvocation(scope, command, args, cwd, roots, environment);
  const result = await runJson(command, args, { cwd, env: environment });
  processes.push({ ...invocation, pid: result.process.pid });
  return result.value;
}

async function runRecordedRaw(processes, scope, command, args, { cwd, roots, environment }) {
  const invocation = loggedInvocation(scope, command, args, cwd, roots, environment);
  const result = await runCaptured(command, args, { cwd, env: environment });
  processes.push({ ...invocation, pid: result.pid });
  return result;
}

async function runParticipantProcess(action, config, processes, ephemeralAuthorization) {
  mkdirSync(config.root, { recursive: true, mode: 0o700 });
  const input = join(config.root, `.controller-${action}-${randomUUID()}.json`);
  writeExactJson(input, config, false, true);
  const args = [SCRIPT_PATH, "--internal-participant", action, "--input", input];
  const environment = minimalChildEnvironment(join(config.root, "process-tmp"));
  const childEnvironment = ephemeralAuthorization === undefined
    ? environment
    : { ...environment, [EPHEMERAL_AUTHORIZATION_ENV]: ephemeralAuthorization };
  const roots = [[config.role, config.root], ["REPO", REPO_ROOT]];
  const invocation = loggedInvocation(config.role, process.execPath, args, config.root, roots, environment);
  const result = await runJson(process.execPath, args, { cwd: config.root, env: childEnvironment });
  processes.push({ ...invocation, pid: result.process.pid });
  if (Array.isArray(result.value.processes)) processes.push(...result.value.processes);
  return result.value;
}

function registrationMessage({ runId, foundation, role, participant, issuedAt, expiresAt }) {
  return Object.freeze({
    verifyingService: VERIFYING_SERVICE,
    runId,
    fheCaseId: goDigestToBytes32(foundation.fheCaseId),
    assetIdentityDigest: goDigestToBytes32(foundation.assetIdentity),
    policyDigest: goDigestToBytes32(foundation.policyId),
    role,
    participantWallet: participant.participantWallet,
    participantSigningPublicKey: participant.participantSigningPublicKey,
    participantSigningKeyDigest: participant.participantSigningKeyDigest,
    registrationNonce: bytes32FromHex(sha256Buffer(randomBytes(32))),
    issuedAt,
    expiresAt,
  });
}

function intentBaseMessage(context, role, participant, registration, issuedAt, expiresAt) {
  return Object.freeze({
    verifyingService: VERIFYING_SERVICE,
    runId: context.runId,
    fheCaseId: context.fheCaseId,
    caseBindingDigest: context.caseBindingDigest,
    protectionBindingDigest: context.protectionBindingDigest,
    assetIdentityDigest: context.assetIdentityDigest,
    policyDigest: context.policyDigest,
    circuitId: context.circuitId,
    circuitVersion: context.circuitVersion,
    circuitDigest: context.circuitDigest,
    parameterProfile: context.parameterProfile,
    parameterFingerprint: context.parameterFingerprint,
    fhePublicKeyDigest: context.fhePublicKeyDigest,
    releaseAuthorityId: context.releaseAuthorityId,
    releaseMode: context.releaseMode,
    role,
    participantWallet: participant.participantWallet,
    participantSigningKeyDigest: participant.participantSigningKeyDigest,
    registrationDigest: registration.registrationDigest,
    clientBundleDigest: context.clientBundleDigest,
    clientSourceDigest: context.clientSourceDigest,
    clientBuildDigest: context.clientBuildDigest,
    clientBinaryDigest: context.clientBinaryDigest,
    bundleExpiresAt: context.bundleExpiresAt,
    intentNonce: bytes32FromHex(sha256Buffer(randomBytes(32))),
    issuedAt,
    expiresAt,
  });
}

function finalBaseMessage(context, role, participant, registration, intent, issuedAt, expiresAt) {
  return Object.freeze({
    verifyingService: VERIFYING_SERVICE,
    runId: context.runId,
    fheCaseId: context.fheCaseId,
    role,
    participantWallet: participant.participantWallet,
    participantSigningKeyDigest: participant.participantSigningKeyDigest,
    registrationDigest: registration.registrationDigest,
    clientBundleDigest: context.clientBundleDigest,
    encryptionIntentDigest: intent.encryptionIntentDigest,
    claimCommitment: intent.claimCommitment,
    issuedAt,
    expiresAt,
  });
}

function bundleExpectations(runId, role, foundation, sourceDigest, buildDigest, clientDigest) {
  return {
    schemaVersion: "mordant.participant-originated-bundle-expectations/1",
    runId,
    role,
    caseId: foundation.fheCaseId,
    assetIdentity: foundation.assetIdentity,
    expectedSourceDigest: sourceDigest,
    expectedBuildManifestDigest: buildDigest,
    expectedClientBinaryDigest: clientDigest,
  };
}

function localPledge(label, role, from, until) {
  const sharedReceivable = bytes32FromHex(sha256Text(`${label}/same-private-receivable`));
  return {
    schemaVersion: "mordant.participant-originated-local-pledge/1",
    activeFrom: from,
    activeUntil: until,
    amount: [0, 0, 0, 1_000_000],
    currency: bytes32FromHex(sha256Text("currency/usd")),
    obligationId: bytes32FromHex(sha256Text(`${label}/${role}/obligation`)),
    receivableId: sharedReceivable,
    exclusive: true,
    receivableCommitment: ZERO32,
  };
}

function persistVerifiedPhase0(root, role, request, verified) {
  const suffix = role === "PARTICIPANT_A" ? "a" : "b";
  const registrationPath = join(root, `wallet-registration-${suffix}.json`);
  writeCanonicalJson(registrationPath, {
    schemaVersion: "mordant.participant-originated-phase0-reservation/1",
    role,
    registrationDigest: verified.registrationDigest,
    registrationNonce: request.registration.registrationNonce,
    request,
  });
  const nonceRef = sha256Text(`MordantPhase0Nonce/v1\0${request.registration.participantWallet.toLowerCase()}\0${request.registration.registrationNonce}`);
  writeCanonicalJson(join(root, `registration-nonce-${nonceRef}.json`), {
    schemaVersion: "mordant.participant-originated-phase0-nonce-claim/1",
    role,
    registrationDigest: verified.registrationDigest,
    nonceReference: nonceRef,
  });
  return registrationPath;
}

async function startCoordinatorProcess(configPath, config, processes, ephemeralAuthorization) {
  const args = [SCRIPT_PATH, "--internal-coordinator", "--config", configPath];
  const environment = minimalChildEnvironment(config.tmpRoot);
  const childEnvironment = { ...environment, [EPHEMERAL_AUTHORIZATION_ENV]: ephemeralAuthorization };
  const roots = [["CONTROL", config.controlRoot], ["COORDINATOR", config.coordinatorRoot], ["PUBLIC", config.publicRoot], ["REPO", REPO_ROOT]];
  const invocation = loggedInvocation("coordinator-http", process.execPath, args, config.coordinatorRoot, roots, environment);
  const child = spawn(process.execPath, args, { cwd: config.coordinatorRoot, env: childEnvironment, stdio: ["ignore", "pipe", "pipe"] });
  const stderr = [];
  let stderrBytes = 0;
  child.stderr.on("data", (chunk) => { stderrBytes = appendBounded(stderr, chunk, stderrBytes); });
  const ready = await new Promise((resolveReady, rejectReady) => {
    let stdout = Buffer.alloc(0);
    const failEarly = (error) => rejectReady(error);
    child.once("error", failEarly);
    child.once("exit", (code, signal) => failEarly(new Error(`coordinator exited before readiness: ${code ?? signal}`)));
    child.stdout.on("data", (chunk) => {
      stdout = Buffer.concat([stdout, Buffer.from(chunk)]);
      if (stdout.length > 64 * 1024) return failEarly(new Error("coordinator readiness output exceeded limit"));
      const newline = stdout.indexOf(0x0a);
      if (newline < 0) return;
      try {
        const value = JSON.parse(stdout.subarray(0, newline).toString("utf8"));
        if (value.schemaVersion !== "mordant.participant-originated-coordinator-ready/1" || !Number.isSafeInteger(value.port) || value.port <= 0 || value.pid !== child.pid) throw new Error("invalid coordinator readiness result");
        resolveReady(value);
      } catch (error) { rejectReady(error); }
    });
  });
  processes.push({ ...invocation, pid: child.pid });
  return Object.freeze({
    child,
    ready,
    baseUrl: `http://127.0.0.1:${ready.port}`,
    async stop() {
      if (child.exitCode !== null) die(`coordinator exited unexpectedly: ${Buffer.concat(stderr).toString("utf8").slice(0, 1000)}`);
      child.kill("SIGTERM");
      const result = await new Promise((resolveClose) => child.once("close", (code, signal) => resolveClose({ code, signal })));
      if (result.code !== 0) die(`coordinator shutdown failed: ${result.code ?? result.signal}`);
    },
  });
}

async function liveNegativeControls(baseUrl, ephemeralAuthorization, metadata, transportRoot) {
  const reservationsRoot = join(transportRoot, "reservations");
  const reservationCount = () => readdirSync(reservationsRoot, { withFileTypes: true }).filter((entry) => entry.isFile() && /^[0-9a-f]{64}\.json$/u.test(entry.name)).length;
  const reservationsBefore = reservationCount();
  const pathResponse = await fetch(`${baseUrl}${participantOriginatedRoutes.ciphertext}?filename=submission-a.bin`, {
    method: "PUT",
    headers: { authorization: `Bearer ${ephemeralAuthorization}`, "content-type": PARTICIPANT_ORIGINATED_CIPHERTEXT_CONTENT_TYPE, "content-length": "1" },
    body: Buffer.from([0]),
  });
  const pathBody = await pathResponse.json();
  if (pathResponse.status !== 400 || pathBody.error?.code !== "ROUTE_QUERY") die("live transport negative controls did not fail closed");
  const anotherDigest = `0x${"f".repeat(64)}`;
  const projectionMutations = {
    runId: metadata.runId === "22222222-2222-4222-8222-222222222222" ? "33333333-3333-4333-8333-333333333333" : "22222222-2222-4222-8222-222222222222",
    fheCaseId: anotherDigest,
    role: metadata.role === "PARTICIPANT_A" ? "PARTICIPANT_B" : "PARTICIPANT_A",
    participantWallet: `0x${"34".repeat(20)}`,
    chainId: metadata.chainId + 1,
    participantSigningKeyDigest: anotherDigest,
    registrationDigest: anotherDigest,
    encryptionIntentDigest: anotherDigest,
    finalAdmissionDigest: anotherDigest,
    claimCommitment: anotherDigest,
    clientBundleDigest: anotherDigest,
    encryptedArtifactDigest: anotherDigest,
    ciphertextObjectDigest: anotherDigest,
    ciphertextObjectLength: metadata.ciphertextObjectLength + 1,
    registrationNonce: anotherDigest,
    intentNonce: anotherDigest,
    submissionNonce: anotherDigest,
    issuedAt: metadata.issuedAt + 1,
    expiresAt: metadata.expiresAt - 1,
  };
  const signedProjectionMutations = [];
  for (const [field, value] of Object.entries(projectionMutations)) {
    const response = await fetch(`${baseUrl}${participantOriginatedRoutes.beginImport}`, {
      method: "POST",
      headers: { authorization: `Bearer ${ephemeralAuthorization}`, "content-type": PARTICIPANT_ORIGINATED_MANIFEST_CONTENT_TYPE },
      body: canonicalJson({ ...metadata, [field]: value }),
    });
    const body = await response.json();
    const rejectedByProjection = response.status === 400 && body.error?.code === "AUTHORIZATION_PROJECTION";
    const rejectedByDigestAuthentication = response.status === 401 && body.error?.code === "AUTHENTICATION";
    if (!rejectedByProjection && !rejectedByDigestAuthentication) die(`signed projection mutation was not rejected before reservation: ${field}`);
    signedProjectionMutations.push(Object.freeze({ field, status: response.status, code: body.error.code }));
  }
  const reservationsAfter = reservationCount();
  if (reservationsAfter !== reservationsBefore) die("rejected signed projection mutation created durable reservation state");
  return Object.freeze({
    arbitraryFilenameRoute: { status: pathResponse.status, code: pathBody.error.code },
    signedProjectionMutations: Object.freeze({
      allRejected: true,
      reservationCountUnchanged: true,
      reservationsBefore,
      reservationsAfter,
      results: Object.freeze(signedProjectionMutations),
    }),
  });
}

function casePaths(caseRoot) {
  const coordinatorRoot = join(caseRoot, "coordinator");
  const controlRoot = join(dirname(caseRoot), "ephemeral-control", basename(caseRoot));
  return Object.freeze({
    caseRoot,
    controlRoot,
    participantA: participantRoots(join(caseRoot, "participant-a")),
    participantB: participantRoots(join(caseRoot, "participant-b")),
    coordinatorRoot,
    publicRoot: join(coordinatorRoot, "public"),
    decryptorPrivateRoot: join(caseRoot, "decryptor-private"),
    ceremonyRoot: join(coordinatorRoot, "ceremony"),
    phase0Root: join(coordinatorRoot, "phase0"),
    bundleExportRoot: join(coordinatorRoot, "bundle-exports"),
    transportRoot: join(coordinatorRoot, "transport"),
    importJournalRoot: join(coordinatorRoot, "go-import-journal"),
    importRequestRoot: join(coordinatorRoot, "go-import-requests"),
    processJournal: join(coordinatorRoot, "process-journal.ndjson"),
    evaluatorRoot: join(caseRoot, "evaluator-process"),
    decryptorRoot: join(caseRoot, "decryptor-process"),
  });
}

function markCreatedRoot(path) {
  mkdirSync(path, { recursive: false, mode: 0o700 });
  writePrivate(join(path, ".mordant-product-qualification-created"), Buffer.from("mordant.participant-originated-product-qualification-created-root/1\n"));
}

function removeMarkedRoot(path) {
  const resolved = realpathSync(path);
  const marker = join(resolved, ".mordant-product-qualification-created");
  if (resolved === "/" || !readFileSync(marker).equals(Buffer.from("mordant.participant-originated-product-qualification-created-root/1\n"))) die("refusing to remove an unmarked qualification root");
  rmSync(resolved, { recursive: true, force: false });
}

function sanitizeEvidenceValue(value, roots) {
  if (typeof value === "string") return replaceRoot(value, roots);
  if (Array.isArray(value)) return value.map((entry) => sanitizeEvidenceValue(entry, roots));
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, sanitizeEvidenceValue(child, roots)]));
  return value;
}

function readJsonObjects(root) {
  if (!existsSync(root)) return [];
  return walkRegularFiles(root).filter((path) => path.endsWith(".json")).map((path) => ({
    path: relative(root, path),
    value: readJson(path),
  }));
}

async function runRealCase({ name, expectedConflict, windows, sessionRoot, binaries, sourceInfo, binaryInfo, auth }) {
  const caseRoot = join(sessionRoot, name);
  markCreatedRoot(caseRoot);
  const paths = casePaths(caseRoot);
  mkdirSync(dirname(paths.controlRoot), { recursive: true, mode: 0o700 });
  markCreatedRoot(paths.controlRoot);
  const topology = processTopology(caseRoot);
  for (const directory of [
    paths.participantA.root, paths.participantB.root, paths.coordinatorRoot, paths.phase0Root,
    paths.evaluatorRoot, paths.decryptorRoot,
  ]) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const observables = topologyObservables(topology);
  const processes = [];
  const roleEntries = [
    ["PARTICIPANT_A", paths.participantA],
    ["PARTICIPANT_B", paths.participantB],
  ];
  const participantResults = {};
  for (const [role, roots] of roleEntries) {
    participantResults[role] = await runParticipantProcess("init", {
      schemaVersion: "mordant.participant-process-config/1",
      role,
      root: roots.root,
      repoRoot: REPO_ROOT,
      clientBinary: binaries["mordant-fhe-client"],
    }, processes);
  }

  const now = Math.floor(Date.now() / 1000);
  const runId = randomUUID();
  const foundation = buildNeutralFoundationSpec({
    label: `${name}/${runId}`,
    participantA: participantResults.PARTICIPANT_A,
    participantB: participantResults.PARTICIPANT_B,
    nowSeconds: now,
  });
  const authorizationExpiresAt = now + 14 * 60;
  const registrations = {};
  const verifiedRegistrations = {};
  for (const [role, roots] of roleEntries) {
    const participant = participantResults[role];
    const message = registrationMessage({ runId, foundation, role, participant, issuedAt: now, expiresAt: authorizationExpiresAt });
    const signed = await runParticipantProcess("sign-registration", {
      schemaVersion: "mordant.participant-process-config/1",
      role,
      root: roots.root,
      repoRoot: REPO_ROOT,
      clientBinary: binaries["mordant-fhe-client"],
      message,
    }, processes);
    const verified = await auth.verifyParticipantSigningKeyRegistration(signed.request, {
      verifyingService: VERIFYING_SERVICE,
      runId,
      fheCaseId: message.fheCaseId,
      assetIdentityDigest: message.assetIdentityDigest,
      policyDigest: message.policyDigest,
      role,
      participantWallet: participant.participantWallet,
      now: Math.floor(Date.now() / 1000),
      chainId: CHAIN_ID,
    });
    registrations[role] = signed.request;
    verifiedRegistrations[role] = verified;
    persistVerifiedPhase0(paths.phase0Root, role, signed.request, verified);
  }

  // The first governed-FHE foundation process starts only after both real
  // wallet registrations above have verified and been create-only retained.
  const controllerEnvironment = minimalChildEnvironment(join(paths.coordinatorRoot, "controller-tmp"));
  const rootLabels = [
    ["CASE", caseRoot], ["COORDINATOR", paths.coordinatorRoot], ["PUBLIC", paths.publicRoot],
    ["DECRYPTOR_PRIVATE", paths.decryptorPrivateRoot], ["REPO", REPO_ROOT],
  ];
  const foundationSpecPath = join(paths.coordinatorRoot, "participant-foundation-spec.json");
  writeExactJson(foundationSpecPath, { ...foundation.spec, protectionBinding: foundation.spec.protectionBinding });
  const foundationOutput = await runRecordedJson(processes, "foundation", binaries["mordant-fhe-keygen"], [
    "-mode", "participant-foundation", "-public-root", paths.publicRoot,
    "-private-root", paths.decryptorPrivateRoot, "-spec", foundationSpecPath,
  ], { cwd: paths.coordinatorRoot, roots: rootLabels, environment: controllerEnvironment });

  const sourceDigest = sourceInfo.digest;
  const buildDigest = binaryInfo.digest;
  const clientDigest = binaryInfo.entries["mordant-fhe-client"].sha256;
  const ceremony = {};
  for (const [role, roots] of roleEntries) {
    const suffix = role === "PARTICIPANT_A" ? "a" : "b";
    const inputPath = join(paths.coordinatorRoot, `ceremony-input-${suffix}.json`);
    writeExactJson(inputPath, {
      schemaVersion: "mordant.participant-originated-ceremony-request-input/1",
      runId,
      role,
      expectedSourceDigest: sourceDigest,
      expectedBuildManifestDigest: buildDigest,
      expectedClientBinaryDigest: clientDigest,
    });
    const generated = await runRecordedRaw(processes, `ceremony-request-${suffix}`, binaries["mordant-fhe-keygen"], [
      "-mode", "participant-ceremony-request", "-public-root", paths.publicRoot, "-request", inputPath,
    ], { cwd: paths.coordinatorRoot, roots: rootLabels, environment: controllerEnvironment });
    const coordinatorRequestPath = join(paths.coordinatorRoot, `ceremony-request-${suffix}.json`);
    writeFileSync(coordinatorRequestPath, generated.stdout, { flag: "wx", mode: 0o600 });
    const participantRequestPath = join(roots.root, `ceremony-request-${suffix}.json`);
    copyRegularCreateOnly(coordinatorRequestPath, participantRequestPath);
    const participantApprovalPath = join(roots.root, `ceremony-approval-${suffix}.json`);
    const signed = await runParticipantProcess("sign-ceremony", {
      schemaVersion: "mordant.participant-process-config/1",
      role,
      root: roots.root,
      repoRoot: REPO_ROOT,
      clientBinary: binaries["mordant-fhe-client"],
      requestPath: participantRequestPath,
      approvalPath: participantApprovalPath,
      caseRoot: roots.root,
    }, processes);
    const coordinatorApprovalPath = join(paths.coordinatorRoot, `ceremony-approval-${suffix}.json`);
    copyRegularCreateOnly(participantApprovalPath, coordinatorApprovalPath);
    const imported = await runRecordedJson(processes, `ceremony-import-${suffix}`, binaries["mordant-fhe-keygen"], [
      "-mode", "participant-ceremony-import", "-public-root", paths.publicRoot, "-ceremony-root", paths.ceremonyRoot,
      "-request", coordinatorRequestPath, "-approval", coordinatorApprovalPath,
    ], { cwd: paths.coordinatorRoot, roots: rootLabels, environment: controllerEnvironment });
    ceremony[role] = { request: JSON.parse(generated.stdout), approval: signed.approval, imported };
  }

  const finalized = await runRecordedJson(processes, "participant-finalize", binaries["mordant-fhe-keygen"], [
    "-mode", "participant-finalize", "-public-root", paths.publicRoot,
  ], { cwd: paths.coordinatorRoot, roots: rootLabels, environment: controllerEnvironment });

  const bundleExports = {};
  const bundleManifests = {};
  const contexts = {};
  for (const [role, roots] of roleEntries) {
    const suffix = role === "PARTICIPANT_A" ? "a" : "b";
    const exportRoot = join(paths.bundleExportRoot, suffix);
    const exported = await runRecordedJson(processes, `bundle-export-${suffix}`, binaries["mordant-fhe-keygen"], [
      "-mode", "participant-bundle-export", "-public-root", paths.publicRoot, "-ceremony-root", paths.ceremonyRoot,
      "-bundle-root", exportRoot, "-role", role,
    ], { cwd: paths.coordinatorRoot, roots: rootLabels, environment: controllerEnvironment });
    copyDirectoryCreateOnly(exportRoot, roots.bundle);
    const bundle = readJson(join(roots.bundle, "participant-originated-client-bundle.json"));
    bundleExports[role] = exported;
    bundleManifests[role] = bundle;
    contexts[role] = bundleContextFrom(bundle, exported, participantResults[role].participantWallet);
    writeExactJson(roots.bundleExpectations, bundleExpectations(runId, role, foundation, sourceDigest, buildDigest, clientDigest), false, true);
    const [from, until] = windows[role];
    writeExactJson(roots.pledge, localPledge(`${name}/${runId}`, role, from, until), false, true);
  }

  const intents = {};
  const verifiedIntents = {};
  for (const [role, roots] of roleEntries) {
    const phaseNow = Math.floor(Date.now() / 1000);
    if (phaseNow >= authorizationExpiresAt - 60) die("Phase-0 authorization lifetime was exhausted before encryption intent");
    const base = intentBaseMessage(contexts[role], role, participantResults[role], verifiedRegistrations[role], phaseNow, authorizationExpiresAt);
    const signed = await runParticipantProcess("claim-and-sign-intent", {
      schemaVersion: "mordant.participant-process-config/1",
      role,
      root: roots.root,
      repoRoot: REPO_ROOT,
      clientBinary: binaries["mordant-fhe-client"],
      intentBase: base,
    }, processes);
    const verified = await auth.verifyParticipantEncryptionIntent(signed.request, {
      ...contexts[role],
      verifyingService: VERIFYING_SERVICE,
      role,
      participantWallet: participantResults[role].participantWallet,
      registration: verifiedRegistrations[role],
      now: Math.floor(Date.now() / 1000),
      chainId: CHAIN_ID,
    });
    intents[role] = signed.request;
    verifiedIntents[role] = verified;
    // This create-only request is written only after Phase 1 has verified.
    writeExactJson(roots.preparationRequest, {
      schemaVersion: "mordant.participant-originated-preparation-request/1",
      clientBundleDigest: contexts[role].clientBundleDigest,
      claimCommitment: verified.claimCommitment,
      encryptionIntentDigest: verified.encryptionIntentDigest,
      submissionNonce: bytes32FromHex(sha256Buffer(randomBytes(32))),
      expiresAtUnix: authorizationExpiresAt,
    }, false, true);
  }

  const finalAdmissions = {};
  const preparations = {};
  for (const [role, roots] of roleEntries) {
    const phaseNow = Math.floor(Date.now() / 1000);
    if (phaseNow >= authorizationExpiresAt - 30) die("authorization lifetime was exhausted before participant encryption");
    const base = finalBaseMessage(contexts[role], role, participantResults[role], verifiedRegistrations[role], verifiedIntents[role], phaseNow, authorizationExpiresAt);
    const final = await runParticipantProcess("prepare-and-sign-final", {
      schemaVersion: "mordant.participant-process-config/1",
      role,
      root: roots.root,
      repoRoot: REPO_ROOT,
      clientBinary: binaries["mordant-fhe-client"],
      finalBase: base,
    }, processes);
    preparations[role] = final.prepared;
    finalAdmissions[role] = final.request;
    await verifyRealAuthorizationChain(auth, final.metadata, contexts[role]);
  }

  const ephemeralAuthorization = randomBytes(32).toString("base64url");
  const coordinatorConfig = {
    schemaVersion: "mordant.participant-originated-real-coordinator-config/1",
    repoRoot: REPO_ROOT,
    controlRoot: paths.controlRoot,
    coordinatorRoot: paths.coordinatorRoot,
    publicRoot: paths.publicRoot,
    phase0Root: paths.phase0Root,
    transportRoot: paths.transportRoot,
    importJournalRoot: paths.importJournalRoot,
    importRequestRoot: paths.importRequestRoot,
    processJournal: paths.processJournal,
    tmpRoot: join(paths.controlRoot, "process-tmp"),
    importBinary: binaries["mordant-fhe-import"],
    contexts,
    port: 0,
  };
  const coordinatorConfigPath = join(paths.controlRoot, "http-coordinator-config.json");
  assertCoordinatorControlConfig(coordinatorConfigPath, paths.coordinatorRoot, coordinatorConfig);
  writeCanonicalJson(coordinatorConfigPath, coordinatorConfig, true);
  const server = await startCoordinatorProcess(coordinatorConfigPath, coordinatorConfig, processes, ephemeralAuthorization);
  let negativeControls;
  const publications = {};
  try {
    negativeControls = await liveNegativeControls(server.baseUrl, ephemeralAuthorization, readJson(paths.participantA.transportMetadata), paths.transportRoot);
    for (const [role, roots] of roleEntries) {
      publications[role] = await runParticipantProcess("upload", {
        schemaVersion: "mordant.participant-process-config/1",
        role,
        root: roots.root,
        repoRoot: REPO_ROOT,
        clientBinary: binaries["mordant-fhe-client"],
        baseUrl: server.baseUrl,
      }, processes, ephemeralAuthorization);
    }
  } finally {
    await server.stop();
    removeMarkedRoot(paths.controlRoot);
  }

  const evaluatorEnvironment = minimalChildEnvironment(join(paths.evaluatorRoot, "process-tmp"));
  const evaluator = await runRecordedJson(processes, "evaluator", binaries["mordant-fhe-evaluator"], [
    "-public-root", paths.publicRoot,
  ], { cwd: paths.evaluatorRoot, roots: rootLabels, environment: evaluatorEnvironment });
  const decryptorEnvironment = minimalChildEnvironment(join(paths.decryptorRoot, "process-tmp"));
  const decryptor = await runRecordedJson(processes, "decryptor", binaries["mordant-fhe-decryptor"], [
    "-public-root", paths.publicRoot, "-private-root", paths.decryptorPrivateRoot,
  ], { cwd: paths.decryptorRoot, roots: rootLabels, environment: decryptorEnvironment });
  if (decryptor.conflict !== expectedConflict) die(`unexpected governed conflict outcome for ${name}`);

  const publicResult = readJson(join(paths.publicRoot, "governed-conflict-result.json"));
  const evaluatedArtifact = readJson(join(paths.publicRoot, "evaluated-conflict.json"));
  if (publicResult.conflict !== expectedConflict || publicResult.caseId !== foundation.fheCaseId) die("governed public result did not match the case");
  const secretSources = [];
  for (const [role, roots] of roleEntries) {
    const suffix = role === "PARTICIPANT_A" ? "a" : "b";
    secretSources.push(
      { label: `pledge-${suffix}`, path: roots.pledge },
      { label: `claim-salt-${suffix}`, path: roots.salt },
      { label: `wallet-key-${suffix}`, path: roots.wallet },
      { label: `artifact-signing-key-${suffix}`, path: roots.signingKey },
    );
  }
  const forbiddenMaterial = retainedForbiddenMaterial(
    roleEntries,
    secretSources,
    ephemeralAuthorization,
    [paths.participantA.root, paths.participantB.root],
    publications,
  );
  const stateScan = scanCoordinatorState(
    paths.coordinatorRoot,
    [paths.participantA.root, paths.participantB.root],
    forbiddenMaterial,
  );
  if (!stateScan.passed) die("coordinator no-plaintext scan failed");
  const receiptRef = hashRegularFile(join(paths.decryptorPrivateRoot, "release-consumed.json"));
  const coordinatorProcessRecords = existsSync(paths.processJournal)
    ? readFileSync(paths.processJournal, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line))
    : [];
  const transportJournalPath = join(paths.transportRoot, "import-journal.ndjson");
  const importJournals = {
    transport: existsSync(transportJournalPath)
      ? readFileSync(transportJournalPath, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line))
      : [],
    governed: readJsonObjects(paths.importJournalRoot),
  };
  const caseEvidenceCore = {
    schemaVersion: "mordant.participant-originated-product-qualification-case-evidence/1",
    productProfile: PARTICIPANT_ORIGINATED_PRODUCT_PROFILE,
    privacyClaim: PARTICIPANT_ORIGINATED_PRIVACY_CLAIM,
    name,
    runId,
    fheCaseId: foundation.fheCaseId,
    expectedConflict,
    conflict: decryptor.conflict,
    semanticGap: PARTICIPANT_ORIGINATED_SEMANTIC_GAP,
    topology: sanitizeEvidenceValue({ declaration: topology, observables }, [["CONTROL", paths.controlRoot], ["CASE", caseRoot], ["REPO", REPO_ROOT]]),
    phase0: {
      verifiedBeforeFoundation: true,
      durableReservationRoot: "$COORDINATOR/phase0",
      registrations,
      registrationDigests: Object.fromEntries(roleEntries.map(([role]) => [role, verifiedRegistrations[role].registrationDigest])),
    },
    ceremony,
    foundation: foundationOutput,
    finalized,
    bundles: { manifests: bundleManifests, exports: bundleExports },
    phase1: {
      verifiedBeforeEncryption: true,
      intents,
      intentDigests: Object.fromEntries(roleEntries.map(([role]) => [role, verifiedIntents[role].encryptionIntentDigest])),
    },
    phase2: {
      verifiedAgainstGoRecomputedFacts: true,
      finalAdmissions,
      finalAdmissionDigests: Object.fromEntries(roleEntries.map(([role]) => [role, preparations[role] === undefined ? null : auth.participantFinalEncryptedAdmissionDigest(finalAdmissions[role].admission, CHAIN_ID)])),
      preparations,
    },
    transport: {
      stableRoutes: STABLE_PARTICIPANT_ORIGINATED_ROUTES,
      ephemeralRequestAuthorization: {
        mechanism: "one-run process environment consumed at child startup",
        configOutsideDurableRoot: true,
        retainedValue: false,
        exactValueAndHeaderScan: true,
      },
      realStageAdapter: "mordant-fhe-import stage-object",
      realVerifyAdapter: "mordant-fhe-import verify plus strict TypeScript Phase-2 recomputation check",
      realPublicationAdapter: "mordant-fhe-import publish/reconcile",
      negativeControls,
      publications: Object.fromEntries(roleEntries.map(([role]) => [role, publications[role].published])),
    },
    evaluator,
    decryptor,
    evaluatedArtifact,
    governedResult: {
      object: { path: "governed-conflict-result.json", ...hashRegularFile(join(paths.publicRoot, "governed-conflict-result.json")) },
      resultDigest: decryptor.resultDigest,
      conflict: publicResult.conflict,
      releaseMode: publicResult.releaseMode,
      signedResult: publicResult,
    },
    receipt: { path: "release-consumed.json", ...receiptRef },
    importJournals,
    coordinatorState: stateScan,
    processes: [...processes, ...coordinatorProcessRecords],
  };
  const retainedEvidenceScan = scanRetainedEvidence(caseEvidenceCore, forbiddenMaterial);
  if (!retainedEvidenceScan.passed) die("retained evidence secret/plaintext scan failed");
  const caseEvidence = { ...caseEvidenceCore, retainedEvidenceScan };
  if (!scanRetainedEvidence(caseEvidence, forbiddenMaterial).passed) die("retained evidence scan record introduced forbidden material");
  const encodedEvidence = canonicalJson(caseEvidence);
  for (const forbidden of [caseRoot, paths.participantA.root, paths.participantB.root, REPO_ROOT, ephemeralAuthorization, "/Users/"]) {
    if (encodedEvidence.includes(forbidden)) die(`unsanitized case evidence contained ${forbidden === ephemeralAuthorization ? "a bearer credential" : "a local path"}`);
  }
  return Object.freeze(caseEvidence);
}

function resolveExecutable(command) {
  if (command.includes("/")) return realpathSync(command);
  for (const directory of (process.env.PATH ?? "").split(":")) {
    if (directory === "") continue;
    const candidate = join(directory, command);
    if (existsSync(candidate)) {
      const stat = statSync(candidate);
      if (stat.isFile()) return realpathSync(candidate);
    }
  }
  die(`executable not found on PATH: ${command}`);
}

function executedRuntimeManifest(binaries) {
  const paths = {
    node: realpathSync(process.execPath),
    go: resolveExecutable("go"),
    pnpm: resolveExecutable("pnpm"),
    git: resolveExecutable("git"),
    uname: resolveExecutable("uname"),
    ...binaries,
  };
  const entries = Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, {
    executable: basename(path),
    ...hashRegularFile(path),
  }]));
  entries.participantAuthorizationModule = {
    executable: relative(REPO_ROOT, AUTH_COMPILED_PATH),
    ...hashRegularFile(AUTH_COMPILED_PATH),
  };
  return Object.freeze({ entries, digest: sha256DigestBytes(Buffer.from(canonicalJson(entries))) });
}

async function verifySourceCheckout(expectedSourceSha) {
  if (!/^[0-9a-f]{40}$/u.test(expectedSourceSha)) die("--expected-source-sha must be an exact 40-character lower-case commit SHA");
  if (!/^[0-9a-f]{40}$/u.test(PARTICIPANT_ORIGINATED_QUALIFICATION_BASE_SHA)) die("qualification base SHA constant rejected");
  const executedSourceSha = await sourceSha();
  if (executedSourceSha !== expectedSourceSha) die(`expected source SHA ${expectedSourceSha} but HEAD is ${executedSourceSha}`);
  const status = await runCaptured("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: REPO_ROOT });
  if (status.stdout !== "") die("--run requires a clean worktree, including no untracked files");
  await runCaptured("git", ["cat-file", "-e", `${PARTICIPANT_ORIGINATED_QUALIFICATION_BASE_SHA}^{commit}`], { cwd: REPO_ROOT });
  await runCaptured("git", ["merge-base", "--is-ancestor", PARTICIPANT_ORIGINATED_QUALIFICATION_BASE_SHA, executedSourceSha], { cwd: REPO_ROOT });
  return Object.freeze({
    baseSha: PARTICIPANT_ORIGINATED_QUALIFICATION_BASE_SHA,
    executedSourceSha,
    expectedSourceSha,
    expectedSourceShaVerified: true,
    baseShaObjectVerified: true,
    baseShaAncestorVerified: true,
    worktreeCleanBeforeRun: true,
  });
}

async function createSessionRoot(requested) {
  if (requested === undefined) {
    const root = await mkdtemp(join(tmpdir(), "mordant-participant-originated-qualification-"));
    writePrivate(join(root, ".mordant-product-qualification-created"), Buffer.from("mordant.participant-originated-product-qualification-created-root/1\n"));
    return root;
  }
  const root = resolve(requested);
  if (existsSync(root) || root === "/" || root === REPO_ROOT) die("--work-root must name a new, dedicated directory");
  mkdirSync(dirname(root), { recursive: true, mode: 0o700 });
  markCreatedRoot(root);
  return root;
}

async function runQualification(environment, processes) {
  const commands = [
    {
      id: "node-http-and-runner-controls",
      command: process.execPath,
      args: ["--test", "scripts/participant-originated-coordinator.test.mjs", "scripts/run-participant-originated-qualification.test.mjs"],
      cwd: REPO_ROOT,
    },
    {
      id: "typescript-authorization-controls",
      command: process.execPath,
      args: ["--test", ".product-test-dist/src/lib/protection/participant-originated-authorization.test.js"],
      cwd: REPO_ROOT,
    },
    {
      id: "go-cli-boundary-controls",
      command: "go",
      args: ["test", "-v", "-count=1", "./cmd/mordant-fhe-import", "./cmd/mordant-fhe-client", "./cmd/mordant-fhe-keygen"],
      cwd: GO_ROOT,
    },
    {
      id: "go-governed-import-controls",
      command: "go",
      args: ["test", "-v", "-timeout", "30m", "-count=1", "./governedfhe", "-run", "^(TestParticipantOriginated|TestStageParticipantOriginated|TestPublishParticipantOriginated)"],
      cwd: GO_ROOT,
    },
  ];
  const results = [];
  for (const entry of commands) {
    const roots = [["REPO", REPO_ROOT]];
    const invocation = loggedInvocation("qualification", entry.command, entry.args, entry.cwd, roots, environment);
    const result = await runCaptured(entry.command, entry.args, { cwd: entry.cwd, env: environment });
    processes.push({ ...invocation, pid: result.pid });
    results.push({
      id: entry.id,
      status: "PASS",
      executable: basename(entry.command),
      argv: entry.args,
      stdout: result.stdout,
      stderr: result.stderr,
      stdoutDigest: sha256DigestBytes(Buffer.from(result.stdout)),
      stderrDigest: sha256DigestBytes(Buffer.from(result.stderr)),
    });
  }
  return Object.freeze({ schemaVersion: "mordant.participant-originated-qualification/1", commands: results });
}

function negativeTestMatrix(qualification, cases) {
  const command = (id) => qualification.commands.find((entry) => entry.id === id)?.argv;
  const rows = [
    ["authenticate-before-stream", "wallet authentication happens before a raw body is consumed", "node-http-and-runner-controls"],
    ["trusted-openat-stage-adapter", "trusted external stageObject owns both raw streams and wrong returned refs burn the ticket", "node-http-and-runner-controls"],
    ["role-nonce-ticket-replay", "role, nonce, ticket, ciphertext and final admission replays are create-only refusals", "node-http-and-runner-controls"],
    ["wrong-length-or-digest", "wrong ciphertext length or digest terminally burns the authenticated ticket", "node-http-and-runner-controls"],
    ["expiry-and-exact-metadata", "expired, noncanonical, forbidden and non-exact metadata is rejected before reservation", "node-http-and-runner-controls"],
    ["manifest-last-framing", "manifest-last rejects out-of-order, malformed, truncated and replacement attempts", "node-http-and-runner-controls"],
    ["arbitrary-routes-and-filenames", "arbitrary methods, paths, query filenames, filename headers, and archive types are unavailable", "node-http-and-runner-controls"],
    ["no-plaintext-durable-state", "durable coordinator state contains encrypted/public material only", "node-http-and-runner-controls"],
    ["symlink-replacement", "a symlink in place of a server-selected quarantine object is rejected without replacement", "node-http-and-runner-controls"],
    ["restart-and-post-publish-reconcile", "restart recovery and crash-after-publication reconciliation tests", "node-http-and-runner-controls"],
    ["strict-go-verification-bridge", "strict Go verification bridge rejects missing or malformed recomputed facts", "node-http-and-runner-controls"],
    ["eip712-signature-and-context-substitution", "participant-originated authorization TypeScript negative suite", "typescript-authorization-controls"],
    ["cli-secret-fields-and-digest-split", "participant import/client/keygen CLI boundary tests", "go-cli-boundary-controls"],
    ["replayed-admission", "completed admission and submission nonce replay rejection", "go-governed-import-controls"],
    ["artifact-replacement", "replacement_after_verify", "go-governed-import-controls"],
    ["occupied-role-replacement", "occupied_role", "go-governed-import-controls"],
    ["role-swap", "role_swap", "go-governed-import-controls"],
    ["cross-case-artifact", "cross_case", "go-governed-import-controls"],
    ["wrong-participant-signing-key", "wrong_participant_signing_key", "go-governed-import-controls"],
    ["wrong-fhe-key", "wrong_fhe_public_key and wrong_ciphertext_fhe_key", "go-governed-import-controls"],
    ["wrong-parameters", "wrong_parameter_profile, wrong_parameter_fingerprint, and wrong_ciphertext_parameters", "go-governed-import-controls"],
    ["wrong-circuit-profile", "wrong_circuit and wrong_parameter_profile", "go-governed-import-controls"],
    ["expired-artifact", "expired", "go-governed-import-controls"],
    ["malformed-truncated-ciphertext", "truncated_ciphertext and strict native ciphertext validation", "go-governed-import-controls"],
    ["incorrect-artifact-digest", "wrong_artifact_digest", "go-governed-import-controls"],
    ["incorrect-ciphertext-object-digest", "wrong_ciphertext_digest", "go-governed-import-controls"],
    ["stale-bundle", "stale participant bundle verification", "go-governed-import-controls"],
    ["arbitrary-filename-path-traversal", "arbitrary staged names plus unavailable HTTP filename/path surfaces", "go-governed-import-controls"],
    ["go-artifact-mutations-names-nonces", "complete participant-originated governed import negative suite", "go-governed-import-controls"],
  ].map(([requirement, testName, commandId]) => ({ requirement, testName, commandId, command: command(commandId), status: "PASS" }));
  for (const caseEvidence of cases) {
    rows.push(
      { requirement: `${caseEvidence.name}-live-path-filename`, testName: "live PUT query filename", commandId: "live-http", observed: caseEvidence.transport.negativeControls.arbitraryFilenameRoute, status: "PASS" },
      { requirement: `${caseEvidence.name}-signed-projection-binding`, testName: "live signed-chain top-level mutation matrix creates no reservation", commandId: "live-http", observed: caseEvidence.transport.negativeControls.signedProjectionMutations, status: "PASS" },
    );
  }
  return Object.freeze(rows);
}

export function qualificationReceiptDigest(receipt) {
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) die("qualification receipt rejected");
  const { receiptDigest: omitted, ...body } = receipt;
  void omitted;
  return sha256DigestBytes(Buffer.from(canonicalJson(body)));
}

function qualificationReceipt({ checkout, sourceInfo, binaryInfo, runtimeInfo, cases, matrix }) {
  const caseReceipts = cases.map((caseEvidence) => ({
    name: caseEvidence.name,
    runId: caseEvidence.runId,
    fheCaseId: caseEvidence.fheCaseId,
    caseEvidenceDigest: sha256DigestBytes(Buffer.from(canonicalJson(caseEvidence))),
    bundles: Object.fromEntries(Object.entries(caseEvidence.bundles.exports).map(([role, value]) => [role, value.bundleDigest])),
    roles: Object.fromEntries(["PARTICIPANT_A", "PARTICIPANT_B"].map((role) => [role, {
      registrationDigest: caseEvidence.phase0.registrationDigests[role],
      encryptionIntentDigest: caseEvidence.phase1.intentDigests[role],
      finalAdmissionDigest: caseEvidence.phase2.finalAdmissionDigests[role],
      encryptedArtifactDigest: caseEvidence.phase2.preparations[role].encryptedArtifactDigest,
      artifactObject: caseEvidence.phase2.preparations[role].artifactObject,
      ciphertextObjectDigest: caseEvidence.phase2.preparations[role].ciphertextObjectDigest,
      ciphertextObjectLength: caseEvidence.phase2.preparations[role].ciphertextObjectLength,
      publicationDigests: caseEvidence.transport.publications[role].digests,
    }])),
    importJournalsDigest: sha256DigestBytes(Buffer.from(canonicalJson(caseEvidence.importJournals))),
    evaluatorProvenanceDigest: sha256DigestBytes(Buffer.from(canonicalJson(caseEvidence.evaluator))),
    decryptorProvenanceDigest: sha256DigestBytes(Buffer.from(canonicalJson(caseEvidence.decryptor))),
    resultDigest: caseEvidence.governedResult.resultDigest,
    governedSignedResultObject: caseEvidence.governedResult.object,
    conflict: caseEvidence.conflict,
    noPlaintextScan: {
      passed: caseEvidence.coordinatorState.passed,
      checkedFiles: caseEvidence.coordinatorState.checkedFiles,
      byteChecks: caseEvidence.coordinatorState.byteChecks,
    },
    retainedEvidenceScan: caseEvidence.retainedEvidenceScan,
  }));
  const body = {
    schemaVersion: "mordant.participant-originated-product-qualification-receipt/1",
    productProfile: PARTICIPANT_ORIGINATED_PRODUCT_PROFILE,
    privacyClaim: PARTICIPANT_ORIGINATED_PRIVACY_CLAIM,
    baseSha: checkout.baseSha,
    executedSourceSha: checkout.executedSourceSha,
    executedSourceShaAfterRun: checkout.executedSourceShaAfterRun,
    worktreeCleanBeforeRun: checkout.worktreeCleanBeforeRun,
    worktreeCleanAfterRun: checkout.worktreeCleanAfterRun,
    postRunManifestsVerified: checkout.postRunManifestsVerified,
    sourceManifest: sourceInfo,
    binaryManifest: binaryInfo,
    runtimeManifest: runtimeInfo,
    cases: caseReceipts,
    negativeTestMatrix: matrix,
    semanticGap: PARTICIPANT_ORIGINATED_SEMANTIC_GAP,
    digestRule: "SHA-256 of UTF-8 lexicographically canonical JSON of this receipt with receiptDigest omitted",
  };
  return Object.freeze({ ...body, receiptDigest: qualificationReceiptDigest(body) });
}

export async function runParticipantOriginatedQualification({ expectedSourceSha, workRoot, evidenceRoot = join(REPO_ROOT, "docs", "evidence") }) {
  const checkout = await verifySourceCheckout(expectedSourceSha);
  const sessionRoot = await createSessionRoot(workRoot);
  const resolvedEvidenceRoot = resolve(evidenceRoot);
  const evidencePath = join(resolvedEvidenceRoot, "participant-originated-encryption-product-qualification.json");
  const buildProcesses = [];
  try {
    if (resolvedEvidenceRoot === sessionRoot || resolvedEvidenceRoot.startsWith(`${sessionRoot}/`)) die("evidence root must be outside the disposable work root");
    const buildTmp = join(sessionRoot, "build-tmp");
    const buildEnvironment = minimalChildEnvironment(buildTmp);
    await compileAuthorizationModule(buildProcesses, buildEnvironment);
    const binaries = await buildGoBinaries(join(sessionRoot, "bin"), buildProcesses, buildEnvironment);
    const binaryInfo = binaryManifest(binaries);
    const sourceInfo = sourceManifest();
    const runtimeInfo = executedRuntimeManifest(binaries);
    const versions = await toolchain(buildEnvironment);
    const qualification = await runQualification(buildEnvironment, buildProcesses);
    const goCache = buildEnvironment.GOCACHE;
    if (!resolve(goCache).startsWith(`${resolve(buildTmp)}/`)) die("build cache escaped the dedicated build root");
    if (existsSync(goCache)) rmSync(goCache, { recursive: true, force: false });
    const auth = await loadAuthorizationModule();
    const cases = [];
    const caseSpecifications = [
      {
        name: "conflict",
        expectedConflict: true,
        windows: { PARTICIPANT_A: [100, 400], PARTICIPANT_B: [200, 500] },
      },
      {
        name: "adjacent-no-conflict",
        expectedConflict: false,
        windows: { PARTICIPANT_A: [100, 200], PARTICIPANT_B: [200, 300] },
      },
    ];
    for (const specification of caseSpecifications) {
      const path = join(sessionRoot, specification.name);
      try {
        cases.push(await runRealCase({ ...specification, sessionRoot, binaries, sourceInfo, binaryInfo, auth }));
      } finally {
        if (existsSync(path)) removeMarkedRoot(path);
      }
    }
    const postRunCheckout = await verifySourceCheckout(expectedSourceSha);
    const postRunSourceInfo = sourceManifest();
    const postRunBinaryInfo = binaryManifest(binaries);
    const postRunRuntimeInfo = executedRuntimeManifest(binaries);
    if (canonicalJson(postRunSourceInfo) !== canonicalJson(sourceInfo) ||
        canonicalJson(postRunBinaryInfo) !== canonicalJson(binaryInfo) ||
        canonicalJson(postRunRuntimeInfo) !== canonicalJson(runtimeInfo)) {
      die("source or executed artifacts changed during qualification");
    }
    const verifiedCheckout = Object.freeze({
      ...checkout,
      executedSourceShaAfterRun: postRunCheckout.executedSourceSha,
      worktreeCleanAfterRun: postRunCheckout.worktreeCleanBeforeRun,
      postRunManifestsVerified: true,
    });
    const matrix = negativeTestMatrix(qualification, cases);
    const receipt = qualificationReceipt({ checkout: verifiedCheckout, sourceInfo, binaryInfo, runtimeInfo, cases, matrix });
    const evidence = Object.freeze({
      schemaVersion: PARTICIPANT_ORIGINATED_PRODUCT_QUALIFICATION_SCHEMA,
      productProfile: PARTICIPANT_ORIGINATED_PRODUCT_PROFILE,
      qualificationStatus: "SUPPORTED_NATIVE_CLI_OPT_IN",
      privacyClaim: PARTICIPANT_ORIGINATED_PRIVACY_CLAIM,
      generatedAt: new Date().toISOString(),
      source: { ...verifiedCheckout, manifest: sourceInfo },
      executedArtifacts: { goBinaries: binaryInfo, runtimesAndLoadedAuthorization: runtimeInfo },
      toolchain: versions,
      environmentAllowlist: CHILD_ENVIRONMENT_NAMES,
      buildProcesses,
      qualification,
      negativeTestMatrix: matrix,
      cleanup: {
        caseRootsRemovedSequentially: true,
        buildGoCacheRemovedBeforeCases: true,
        disposableSessionRootRemovedAfterEvidenceWrite: true,
        retainedHeavyArtifacts: false,
      },
      cases,
      qualificationReceipt: receipt,
      semanticGap: PARTICIPANT_ORIGINATED_SEMANTIC_GAP,
    });
    const encodedEvidence = canonicalJson(evidence);
    for (const forbidden of [sessionRoot, REPO_ROOT, "/Users/"]) {
      if (encodedEvidence.includes(forbidden)) die("final evidence contained an unsanitized local path");
    }
    mkdirSync(resolvedEvidenceRoot, { recursive: true, mode: 0o700 });
    writeFileSync(evidencePath, `${encodedEvidence}\n`, { flag: "wx", mode: 0o600 });
    return Object.freeze({ evidencePath, evidence });
  } finally {
    if (existsSync(sessionRoot)) removeMarkedRoot(sessionRoot);
  }
}

function optionValue(args, name) {
  const index = args.indexOf(name);
  if (index < 0) return undefined;
  if (args.indexOf(name, index + 1) >= 0 || index + 1 >= args.length || args[index + 1].startsWith("--")) die(`option ${name} requires one value`);
  return args[index + 1];
}

async function commandLine(argv) {
  assertStableParticipantOriginatedRoutes();
  if (argv[0] === "--internal-participant") {
    const action = argv[1];
    const input = optionValue(argv, "--input");
    if (typeof action !== "string" || input === undefined || argv.length !== 4) die("invalid internal participant invocation");
    const result = await participantChildAction(action, resolve(input));
    process.stdout.write(`${canonicalJson(result)}\n`);
    return;
  }
  if (argv[0] === "--internal-coordinator") {
    const config = optionValue(argv, "--config");
    if (config === undefined || argv.length !== 3) die("invalid internal coordinator invocation");
    await coordinatorChild(resolve(config));
    return;
  }
  if (argv.includes("--dry-run")) {
    const allowed = new Set(["--dry-run", "--work-root"]);
    for (let index = 0; index < argv.length; index += 1) {
      if (!allowed.has(argv[index])) die(`unknown dry-run option: ${argv[index]}`);
      if (argv[index] === "--work-root") index += 1;
    }
    process.stdout.write(`${canonicalJson(buildParticipantOriginatedQualificationDryRunPlan(optionValue(argv, "--work-root")))}\n`);
    return;
  }
  if (argv.includes("--run")) {
    const allowed = new Set(["--run", "--work-root", "--evidence-root", "--expected-source-sha"]);
    for (let index = 0; index < argv.length; index += 1) {
      if (!allowed.has(argv[index])) die(`unknown run option: ${argv[index]}`);
      if (argv[index] !== "--run") index += 1;
    }
    const expectedSourceSha = optionValue(argv, "--expected-source-sha");
    if (expectedSourceSha === undefined) die("--run requires --expected-source-sha");
    const result = await runParticipantOriginatedQualification({
      expectedSourceSha,
      workRoot: optionValue(argv, "--work-root"),
      evidenceRoot: optionValue(argv, "--evidence-root") ?? join(REPO_ROOT, "docs", "evidence"),
    });
    process.stdout.write(`${canonicalJson({ schemaVersion: PARTICIPANT_ORIGINATED_PRODUCT_QUALIFICATION_SCHEMA, evidencePath: result.evidencePath, cases: result.evidence.cases.map(({ name, conflict }) => ({ name, conflict })) })}\n`);
    return;
  }
  die("use --dry-run or --run --expected-source-sha <40-hex HEAD>");
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  commandLine(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`participant-originated-qualification: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
