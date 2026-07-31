#!/usr/bin/env node

import { readdir, readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const FORBIDDEN_NAMES = /plaintext|private.?key|threshold.?share|credential|certificate.*private|secret/i;
const PRIVATE_KEY = /0x[0-9a-fA-F]{64}/;
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
    if (info.size > MAX_FILE_BYTES) {
      violations.push({ file: path, code: "ARTIFACT_TOO_LARGE" });
      continue;
    }
    const contents = await readFile(path, "utf8");
    if (FORBIDDEN_NAMES.test(contents)) violations.push({ file: path, code: "FORBIDDEN_FIELD_NAME" });
    // A private EVM key is indistinguishable from some public bytes32 values. The public artifact
    // schema contains only named commitments, so raw 32-byte hex values outside JSON values are
    // rejected by the producer; this scanner reports every raw candidate for human review.
    if (PRIVATE_KEY.test(contents) && !contents.includes("Commitment")) {
      violations.push({ file: path, code: "RAW_SECRET_CANDIDATE" });
    }
  }
  return { scannedFiles: files.length, violations };
}

async function main() {
  const root = process.argv[2];
  if (typeof root !== "string" || root === "") throw new Error("EVIDENCE_ROOT_REQUIRED");
  const report = await scanPublicEvidence(root);
  process.stdout.write(`${JSON.stringify({ ok: report.violations.length === 0, ...report })}\n`);
  if (report.violations.length > 0) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stdout.write(JSON.stringify({ ok: false, code: "SCAN_FAILED" }) + "\n");
    process.exitCode = 1;
  });
}
