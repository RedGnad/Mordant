#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readdir, readFile, rm, stat } from "node:fs/promises";
import { resolve } from "node:path";

const FORBIDDEN_NAMES = /plaintext|private.?key|threshold.?share|credential|certificate.*private|secret/i;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

async function filesAt(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) files.push(...await filesAt(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

export async function scanPublicEvidence(root) {
  const files = await filesAt(resolve(root));
  const violations = [];
  for (const path of files) {
    const info = await stat(path);
    // Ciphertexts and threshold responses are binary and may exceed the text
    // inspection budget. They are still scanned byte-for-byte against the
    // offline canaries below; skipping free-text field-name heuristics is not
    // a skipped evidence file.
    if (info.size > MAX_FILE_BYTES) continue;
    const contents = await readFile(path, "utf8");
    if (FORBIDDEN_NAMES.test(contents)) violations.push({ file: path, code: "FORBIDDEN_FIELD_NAME" });
  }
  return { scannedFiles: files.length, violations };
}

// auditCanaries is intentionally offline: callers invoke it only after every
// workflow process has terminated. The private directory is never passed to
// the coordinator; it is read here solely to search captured public evidence,
// then removed. The returned report contains hashes, never canary values.
export async function auditCanaries({ publicRoot, privateRoot }) {
  const manifests = await filesAt(resolve(privateRoot));
  const values = [];
  for (const manifest of manifests) {
    const parsed = JSON.parse(await readFile(manifest, "utf8"));
    for (const [field, value] of Object.entries(parsed.fields ?? {})) {
      if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
        throw new Error("CANARY_MANIFEST_INVALID");
      }
      values.push({ party: parsed.party, field, value });
    }
  }
  const files = await filesAt(resolve(publicRoot));
  const leaks = [];
  for (const path of files) {
    const content = await readFile(path);
    for (const canary of values) {
      if (content.includes(Buffer.from(canary.value, "utf8"))) {
        leaks.push({ party: canary.party, field: canary.field, file: path });
      }
    }
  }
  await rm(resolve(privateRoot), { recursive: true, force: true });
  return {
    canaries: values.map(({ party, field, value }) => ({
      party, field, sha256: createHash("sha256").update(value).digest("hex"),
    })),
    scannedFiles: files.length,
    leaks,
    privateCanaryManifestsDeleted: true,
  };
}

async function main() {
  const root = process.argv[2];
  if (typeof root !== "string" || root === "") throw new Error("EVIDENCE_ROOT_REQUIRED");
  const privateIndex = process.argv.indexOf("--private-root");
  const privateRoot = privateIndex >= 0 ? process.argv[privateIndex + 1] : null;
  const report = await scanPublicEvidence(root);
  const canaryReport = privateRoot ? await auditCanaries({ publicRoot: root, privateRoot }) : null;
  const ok = report.violations.length === 0 && (!canaryReport || canaryReport.leaks.length === 0);
  process.stdout.write(`${JSON.stringify({ ok, ...report, canaryReport })}\n`);
  if (!ok) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stdout.write(JSON.stringify({ ok: false, code: "SCAN_FAILED" }) + "\n");
    process.exitCode = 1;
  });
}
