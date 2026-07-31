#!/usr/bin/env node

// Six-process controlled privacy laboratory. The Node parent orchestrates
// lifecycles only: it never reads the two client-private canary manifests.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { auditCanaries, scanPublicEvidence } from "./leak-scan.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const LAB = resolve(HERE, "..");
const LATTIGO = resolve(LAB, "lattigo");
const DEFAULT_POLICY = "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540";
let activeRoot = null;
export function lastProcessRunRoot() { return activeRoot; }

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function parse(argv) {
  const value = { root: null, chainId: "10143", vault: "0x1111111111111111111111111111111111111111", policyId: DEFAULT_POLICY, consumer: "0x2222222222222222222222222222222222222222", nonce: null, validUntil: null };
  const keys = { "--root": "root", "--chain-id": "chainId", "--vault": "vault", "--policy-id": "policyId", "--consumer": "consumer", "--nonce": "nonce", "--valid-until": "validUntil" };
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!Object.hasOwn(keys, key) || i + 1 >= argv.length) fail("PROCESS_RUN_ARGUMENT");
    value[keys[key]] = argv[++i];
  }
  if (value.root === null) value.root = null;
  if (!/^0x[0-9a-fA-F]{40}$/.test(value.vault) || !/^0x[0-9a-fA-F]{64}$/.test(value.policyId) || !/^0x[0-9a-fA-F]{40}$/.test(value.consumer)) fail("PROCESS_RUN_PUBLIC_CONTEXT");
  return value;
}
async function exists(path) { try { await access(path, constants.F_OK); return true; } catch { return false; } }
async function waitFor(path, timeoutMs) { const deadline = Date.now() + timeoutMs; while (Date.now() < deadline) { if (await exists(path)) return; await new Promise((resolveDelay) => setTimeout(resolveDelay, 25)); } fail("PROCESS_RUN_TIMEOUT"); }
function child(role, executable, args, logRoot, lifecycle) {
  const childProcess = spawn(executable, args, { cwd: LATTIGO, stdio: ["ignore", "pipe", "pipe"], env: process.env });
  let redactNext = false;
  const redacted = args.map((arg) => {
    if (redactNext) { redactNext = false; return "[redacted]"; }
    if (arg === "--issuer-key" || arg === "--issuer-public" || arg === "--private-manifest") { redactNext = true; return "[redacted]"; }
    return arg;
  });
  const record = { role, pid: childProcess.pid, startTime: new Date().toISOString(), command: [executable, ...redacted] };
  lifecycle.push(record);
  const stdout = resolve(logRoot, `${role}.stdout`), stderr = resolve(logRoot, `${role}.stderr`);
  childProcess.stdout.pipe(requireWriteStream(stdout)); childProcess.stderr.pipe(requireWriteStream(stderr));
  record.wait = new Promise((resolveExit) => childProcess.once("exit", (code, signal) => { record.exitTime = new Date().toISOString(); record.exit = code === 0 ? "0" : `code:${code ?? "null"};signal:${signal ?? "none"}`; resolveExit({ code, signal }); }));
  return { process: childProcess, record };
}
function requireWriteStream(path) { return (awaitableCreateWriteStream)(path); }
import { createWriteStream as awaitableCreateWriteStream } from "node:fs";
async function goBuild(out, pkg) { const run = spawn("go", ["build", "-o", out, pkg], { cwd: LATTIGO, stdio: "ignore" }); const [code] = await new Promise((resolveExit) => run.once("exit", (...args) => resolveExit(args))); if (code !== 0) fail("PROCESS_RUN_BUILD"); }

export async function runProcessSeparatedV3(options = parse(process.argv.slice(2))) {
  const root = options.root ? resolve(options.root) : await mkdtemp(resolve(tmpdir(), "mordant-privacy-v3-"));
  activeRoot = root;
  const publicRoot = resolve(root, "public"), privateRoot = resolve(root, "private"), binRoot = resolve(root, "bin"), logRoot = resolve(publicRoot, "logs");
  await Promise.all([mkdir(publicRoot, { recursive: true, mode: 0o700 }), mkdir(privateRoot, { recursive: true, mode: 0o700 }), mkdir(binRoot, { recursive: true, mode: 0o700 }), mkdir(logRoot, { recursive: true, mode: 0o700 })]);
  const clientBin = resolve(binRoot, "privacy-client"), coordinatorBin = resolve(binRoot, "privacy-coordinator"), nodeBin = resolve(binRoot, "threshold-node");
  await goBuild(clientBin, "./cmd/privacy-client"); await goBuild(coordinatorBin, "./cmd/privacy-coordinator"); await goBuild(nodeBin, "./cmd/threshold-node");
  const issuer = generateKeyPairSync("ed25519");
  const issuerDir = resolve(root, "issuer"); await mkdir(issuerDir, { recursive: true, mode: 0o700 });
  await writeFile(resolve(issuerDir, "private.pem"), issuer.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  await writeFile(resolve(issuerDir, "public.pem"), issuer.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  const sessionId = `0x${randomBytes(32).toString("hex")}`, nonce = options.nonce ?? BigInt(`0x${randomBytes(8).toString("hex")}`).toString();
  const validUntil = options.validUntil ?? String(Math.floor(Date.now() / 1000) + 900);
  const lifecycle = [];
  const coordinator = child("evaluator-coordinator", coordinatorBin, ["--root", root, "--threshold-node", nodeBin, "--issuer-public", resolve(issuerDir, "public.pem"), "--out", resolve(publicRoot, "provider-result.json"), "--session-id", sessionId, "--chain-id", options.chainId, "--vault", options.vault, "--policy-id", options.policyId, "--policy-version", "1", "--consumer", options.consumer, "--input-a", resolve(publicRoot, "envelopes", "a.bin"), "--input-b", resolve(publicRoot, "envelopes", "b.bin"), "--nonce", nonce, "--valid-until", validUntil], logRoot, lifecycle);
  await waitFor(resolve(publicRoot, "encryption-material.bin"), 120_000);
  const common = ["--public-material", resolve(publicRoot, "encryption-material.bin"), "--issuer-key", resolve(issuerDir, "private.pem"), "--chain-id", options.chainId, "--vault", options.vault, "--policy-id", options.policyId, "--policy-version", "1", "--nonce", nonce, "--valid-until", validUntil, "--session-id", sessionId];
  const clientA = child("client-a", clientBin, ["--party", "a", ...common, "--out", resolve(publicRoot, "envelopes", "a.bin"), "--private-manifest", resolve(privateRoot, "client-a", "canaries.json")], logRoot, lifecycle);
  const clientB = child("client-b", clientBin, ["--party", "b", ...common, "--out", resolve(publicRoot, "envelopes", "b.bin"), "--private-manifest", resolve(privateRoot, "client-b", "canaries.json")], logRoot, lifecycle);
  const [aExit, bExit, coordinatorExit] = await Promise.all([clientA.record.wait, clientB.record.wait, coordinator.record.wait]);
  if (aExit.code !== 0 || bExit.code !== 0 || coordinatorExit.code !== 0) fail("PROCESS_RUN_CHILD_FAILURE");
  await writeFile(resolve(publicRoot, "lifecycle.json"), `${JSON.stringify({ sourceCommit: process.env.GIT_COMMIT ?? "working-tree", classification: "PROCESS-SEPARATED CONTROLLED LAB", roles: lifecycle.map(({ wait, ...record }) => record), sixApplicationProcesses: ["client-a", "client-b", "evaluator-coordinator", "threshold-node-1", "threshold-node-2", "threshold-node-3"], selectedCoalition: ["threshold-node-1", "threshold-node-2"], unselectedAuthenticatedNode: "threshold-node-3" }, null, 2)}\n`);
  // The first sweep runs while the private manifests still exist. Deletion is
  // deferred so the caller can fold its own later public artifacts (Monad
  // journal, receipt, calldata, readbacks) into one final canary sweep.
  const generic = await scanPublicEvidence(publicRoot);
  const canaries = await auditCanaries({ publicRoot, privateRoot, deleteManifests: false });
  const scan = { ok: generic.violations.length === 0 && canaries.leaks.length === 0, generic, canaries };
  await writeFile(resolve(publicRoot, "leak-scan.json"), `${JSON.stringify(scan, null, 2)}\n`);
  if (!scan.ok) { await sealCanaries({ publicRoot, privateRoot }); fail("PROCESS_RUN_LEAK_SCAN"); }
  const providerResult = JSON.parse(await readFile(resolve(publicRoot, "provider-result.json"), "utf8"));
  return {
    root, publicRoot, privateRoot, result: providerResult,
    lifecycle: lifecycle.map(({ wait, ...record }) => record), leakScan: scan,
    sealEvidence: (extraRoots = []) => sealCanaries({ publicRoot, privateRoot, extraRoots }),
  };
}

// Final sweep over every captured public artifact, then removal of the private
// canary manifests. Safe to call more than once: after deletion there are no
// manifests left to read and the sweep reports zero canaries.
export async function sealCanaries({ publicRoot, privateRoot, extraRoots = [] }) {
  const generic = await scanPublicEvidence(publicRoot);
  const extraGeneric = [];
  for (const extra of extraRoots) extraGeneric.push(await scanPublicEvidence(extra));
  const canaries = await auditCanaries({ publicRoot, privateRoot, extraRoots, deleteManifests: true });
  const violations = [generic, ...extraGeneric].flatMap((report) => report.violations);
  const sealed = {
    ok: violations.length === 0 && canaries.leaks.length === 0,
    generic: { scannedFiles: generic.scannedFiles + extraGeneric.reduce((total, r) => total + r.scannedFiles, 0), violations },
    canaries,
  };
  await writeFile(resolve(publicRoot, "leak-scan-final.json"), `${JSON.stringify(sealed, null, 2)}\n`);
  return sealed;
}

async function main() { try { const report = await runProcessSeparatedV3(); const sealed = await report.sealEvidence(); process.stdout.write(`${JSON.stringify({ ok: sealed.ok, root: report.root, result: report.result })}\n`); if (!sealed.ok) process.exitCode = 1; } catch (error) { process.stdout.write(`${JSON.stringify({ ok: false, root: activeRoot, code: error.code ?? error.message ?? "PROCESS_RUN_FAILED" })}\n`); process.exitCode = 1; } }
if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) await main();
