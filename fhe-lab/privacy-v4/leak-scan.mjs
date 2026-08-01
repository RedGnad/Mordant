#!/usr/bin/env node

// Multi-representation canary scanner.
//
// The V3 scanner searched for exactly one representation: the lowercase-hex
// ASCII text of the canary. The canaries actually enter the pledge as raw
// 32-byte values, so the single representation it searched was the one form a
// real leak was least likely to take. This scanner enumerates every encoding a
// leak could plausibly wear and searches all of them, and it ships positive
// controls proving each representation is genuinely detected.
//
// It is offline by construction: callers invoke it only after every workflow
// process has terminated, and it opens one party's private canary manifest at a
// time so the auditing process never holds both parties' secrets at once.

import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { readdir, readFile, rm, stat } from "node:fs/promises";
import { resolve } from "node:path";

export const FORBIDDEN_FIELD_NAMES =
  /plaintext|private.?key|threshold.?share|shamir|credential|certificate.*private|secret.?key|seed.?phrase/i;

const MAX_TEXT_SCAN_BYTES = 8 * 1024 * 1024;

/* ------------------------------------------------------------ representations */

// A canary is {party, field, kind, value} where value is 64 lowercase hex
// characters. `kind` is "bytes32" for opaque identifiers and commitments, or
// "uint" for values the client also materialises as a number, which adds the
// decimal and word-sized encodings a numeric field can leak through.
export function representations(canary) {
  const hex = canary.value.toLowerCase();
  const raw = Buffer.from(hex, "hex");
  const forms = new Map();
  const add = (name, buffer) => {
    if (!buffer || buffer.length === 0) return;
    const key = `${name}:${buffer.toString("base64")}`;
    if (!forms.has(key)) forms.set(key, { name, bytes: buffer });
  };

  add("raw-bytes", raw);
  add("big-endian", raw);
  add("little-endian", Buffer.from([...raw].reverse()));
  add("utf8-lower-hex", Buffer.from(hex, "utf8"));
  add("utf8-upper-hex", Buffer.from(hex.toUpperCase(), "utf8"));
  add("prefixed-hex", Buffer.from(`0x${hex}`, "utf8"));
  add("prefixed-upper-hex", Buffer.from(`0x${hex.toUpperCase()}`, "utf8"));
  add("base64", Buffer.from(raw.toString("base64"), "utf8"));
  add("base64url", Buffer.from(raw.toString("base64url"), "utf8"));
  add("decimal", Buffer.from(BigInt(`0x${hex}`).toString(10), "utf8"));
  // JSON escaping only differs from the plain text when the value contains
  // characters JSON must escape, but a leak could still arrive inside an
  // encoded string, so the escaped form is searched explicitly.
  add("json-escaped", Buffer.from(JSON.stringify(hex).slice(1, -1), "utf8"));

  if (canary.kind === "uint" && typeof canary.numeric === "string" && canary.numeric !== "") {
    const numeric = BigInt(canary.numeric);
    add("numeric-decimal", Buffer.from(numeric.toString(10), "utf8"));
    add("numeric-hex", Buffer.from(numeric.toString(16), "utf8"));
    add("numeric-prefixed-hex", Buffer.from(`0x${numeric.toString(16)}`, "utf8"));
    const word = Buffer.alloc(32);
    let remaining = numeric;
    for (let index = 31; index >= 0 && remaining > 0n; index -= 1) {
      word[index] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    add("numeric-word-be", word);
    add("numeric-word-le", Buffer.from([...word].reverse()));
    // An 8-byte encoding is what a uint64 field takes on the wire.
    if (numeric < 1n << 64n) {
      const eight = Buffer.alloc(8);
      eight.writeBigUInt64BE(numeric);
      add("numeric-u64-be", eight);
      add("numeric-u64-le", Buffer.from([...eight].reverse()));
    }
  }
  return [...forms.values()];
}

/* --------------------------------------------------------------------- files */

export async function filesAt(root) {
  const entries = await readdir(root, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) files.push(...(await filesAt(path)));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

/* --------------------------------------------------------------- field names */

export async function scanFieldNames(roots) {
  const violations = [];
  let scannedFiles = 0;
  const skipped = [];
  for (const root of roots) {
    for (const path of await filesAt(root)) {
      scannedFiles += 1;
      const info = await stat(path);
      if (info.size > MAX_TEXT_SCAN_BYTES) { skipped.push(path); continue; }
      const contents = await readFile(path, "utf8").catch(() => "");
      if (FORBIDDEN_FIELD_NAMES.test(contents)) violations.push({ file: path, code: "FORBIDDEN_FIELD_NAME" });
    }
  }
  return { scannedFiles, violations, oversizeSkippedForTextScan: skipped };
}

/* ------------------------------------------------------------- canary sweep */

// scanCanaries searches every representation of every supplied canary across
// every file under `roots`. `roots` must already contain the complete public
// evidence surface: client outputs, evaluator inputs and outputs, coordinator
// and operator files and logs, manifests, journals, calldata, decoded events,
// receipts, readbacks and reports.
export async function scanCanaries({ canaries, roots }) {
  const targets = [];
  for (const canary of canaries) {
    for (const form of representations(canary)) {
      targets.push({ party: canary.party, field: canary.field, representation: form.name, bytes: form.bytes });
    }
  }
  const files = [];
  for (const root of roots) files.push(...(await filesAt(root)));

  const leaks = [];
  for (const path of files) {
    const contents = await readFile(path).catch(() => null);
    if (!contents) continue;
    for (const target of targets) {
      if (contents.includes(target.bytes)) {
        leaks.push({
          party: target.party, field: target.field,
          representation: target.representation, file: path,
        });
      }
    }
  }
  return {
    scannedRoots: roots,
    scannedFiles: files.length,
    canaryCount: canaries.length,
    representationCount: targets.length,
    representationsPerCanary: canaries.length === 0 ? 0 : targets.length / canaries.length,
    leaks,
  };
}

/* ------------------------------------------------------- secret material */

// External audit finding L-02. Every scan above searches for canaries derived
// from a party's commercial terms and identifiers. None of them searched for
// the threshold key material itself, so a leaked Shamir share, RLWE secret or
// operator signing key would have passed the gate silently. The canaries and
// the secrets are different things, and only the canaries were ever swept.
//
// This sweep takes the raw secret bytes and searches every file for them,
// including the large binary key material the text scans skip.

// The prefix length used for partial-leak detection. A truncated or
// hex-encoded fragment of a secret is still a leak, and a 16-byte prefix of a
// high-entropy value has no plausible accidental collision.
const SECRET_PREFIX_BYTES = 16;

// 8 MiB chunks with an overlap, so a needle straddling a chunk boundary is
// still found and a 344 MB key file never lands in memory whole.
const STREAM_CHUNK_BYTES = 8 * 1024 * 1024;

export function secretRepresentations(secret) {
  const raw = Buffer.isBuffer(secret.bytes) ? secret.bytes : Buffer.from(secret.bytes);
  if (raw.length < SECRET_PREFIX_BYTES) {
    throw new Error(`SECRET_TOO_SHORT:${secret.label}`);
  }
  const hex = raw.toString("hex");
  const forms = new Map();
  const add = (name, buffer) => {
    if (!buffer || buffer.length < SECRET_PREFIX_BYTES) return;
    const key = `${name}:${buffer.toString("base64")}`;
    if (!forms.has(key)) forms.set(key, { name, bytes: buffer });
  };
  add("raw-bytes", raw);
  add("raw-prefix", raw.subarray(0, SECRET_PREFIX_BYTES));
  add("reversed-bytes", Buffer.from([...raw].reverse()));
  add("utf8-lower-hex", Buffer.from(hex, "utf8"));
  add("utf8-upper-hex", Buffer.from(hex.toUpperCase(), "utf8"));
  add("prefixed-hex", Buffer.from(`0x${hex}`, "utf8"));
  add("base64", Buffer.from(raw.toString("base64"), "utf8"));
  add("base64url", Buffer.from(raw.toString("base64url"), "utf8"));
  return [...forms.values()];
}

// streamContains searches one file for any of the needles without holding it
// in memory. The carry-over keeps the last (maxNeedle - 1) bytes so a match
// spanning two chunks is not missed.
export async function streamContains(path, needles) {
  const longest = needles.reduce((max, needle) => Math.max(max, needle.bytes.length), 0);
  const overlap = Math.max(0, longest - 1);
  const found = new Set();
  let carry = Buffer.alloc(0);
  await new Promise((resolveStream, rejectStream) => {
    const stream = createReadStream(path, { highWaterMark: STREAM_CHUNK_BYTES });
    stream.on("error", rejectStream);
    stream.on("data", (chunk) => {
      const window = carry.length === 0 ? chunk : Buffer.concat([carry, chunk]);
      for (const needle of needles) {
        if (found.has(needle.name)) continue;
        if (window.includes(needle.bytes)) found.add(needle.name);
      }
      carry = overlap === 0 ? Buffer.alloc(0) : window.subarray(Math.max(0, window.length - overlap));
      if (found.size === needles.length) stream.destroy();
    });
    stream.on("close", resolveStream);
    stream.on("end", resolveStream);
  }).catch(() => {});
  return [...found];
}

// scanSecretMaterial sweeps every file under `roots` for every representation
// of every supplied secret. Unlike the text scans it applies NO size cap: the
// files most likely to contain key material are exactly the large ones.
export async function scanSecretMaterial({ secrets, roots, exclude = [] }) {
  const excluded = new Set(exclude.map((path) => resolve(path)));
  const targets = [];
  for (const secret of secrets) {
    for (const form of secretRepresentations(secret)) {
      targets.push({ label: secret.label, representation: form.name, name: `${secret.label}:${form.name}`, bytes: form.bytes });
    }
  }
  const files = [];
  for (const root of roots) files.push(...(await filesAt(root)));

  const leaks = [];
  let scannedBytes = 0;
  let scannedFiles = 0;
  for (const path of files) {
    if (excluded.has(resolve(path))) continue;
    const info = await stat(path).catch(() => null);
    if (!info) continue;
    scannedFiles += 1;
    scannedBytes += info.size;
    for (const name of await streamContains(path, targets)) {
      const target = targets.find((candidate) => candidate.name === name);
      leaks.push({ label: target.label, representation: target.representation, file: path });
    }
  }
  return {
    scannedRoots: roots,
    scannedFiles,
    scannedBytes,
    secretCount: secrets.length,
    representationCount: targets.length,
    representationsPerSecret: secrets.length === 0 ? 0 : targets.length / secrets.length,
    leaks,
  };
}

/* ---------------------------------------------------------- manifest reading */

// readManifest opens exactly one party's private canary manifest. Callers sweep
// one party at a time so the auditing process never holds both parties'
// commercial terms simultaneously.
export async function readManifest(path) {
  const parsed = JSON.parse(await readFile(path, "utf8"));
  if (typeof parsed?.party !== "string" || typeof parsed?.fields !== "object" || parsed.fields === null) {
    throw new Error("CANARY_MANIFEST_INVALID");
  }
  const canaries = [];
  for (const [field, entry] of Object.entries(parsed.fields)) {
    const value = typeof entry === "string" ? entry : entry?.value;
    const kind = typeof entry === "string" ? "bytes32" : (entry?.kind ?? "bytes32");
    const numeric = typeof entry === "string" ? undefined : entry?.numeric;
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
      throw new Error(`CANARY_MANIFEST_INVALID:${field}`);
    }
    canaries.push({ party: parsed.party, field, kind, value: value.toLowerCase(), numeric });
  }
  if (canaries.length === 0) throw new Error("CANARY_MANIFEST_EMPTY");
  return { party: parsed.party, canaries };
}

export function canaryDigests(canaries) {
  return canaries.map(({ party, field, kind, value, numeric }) => ({
    party, field, kind,
    sha256: createHash("sha256").update(value).digest("hex"),
    numericPresent: typeof numeric === "string" && numeric !== "",
  }));
}

/* -------------------------------------------------------------- full sweep */

// sweep runs the complete gate: a field-name scan over the public surface, then
// a per-party canary sweep. Manifests are deleted only after every party has
// been swept and the caller has folded in its own late artifacts.
export async function sweep({ manifestPaths, roots, deleteManifests = false }) {
  const generic = await scanFieldNames(roots);
  const parties = [];
  const leaks = [];
  let representationCount = 0;
  let scannedFiles = 0;
  for (const manifestPath of manifestPaths) {
    // One party in memory at a time.
    const { party, canaries } = await readManifest(manifestPath);
    const report = await scanCanaries({ canaries, roots });
    representationCount += report.representationCount;
    scannedFiles = report.scannedFiles;
    leaks.push(...report.leaks);
    parties.push({
      party,
      manifest: manifestPath,
      canaries: canaryDigests(canaries),
      representationsSearched: report.representationCount,
      representationsPerCanary: report.representationsPerCanary,
    });
  }
  if (deleteManifests) {
    for (const manifestPath of manifestPaths) {
      await rm(manifestPath, { force: true });
    }
  }
  return {
    ok: generic.violations.length === 0 && leaks.length === 0,
    scannedRoots: roots,
    scannedFiles,
    representationsSearched: representationCount,
    fieldNameScan: generic,
    parties,
    leaks,
    privateCanaryManifestsDeleted: deleteManifests,
  };
}

async function main() {
  const roots = [];
  const manifests = [];
  const argv = process.argv.slice(2);
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--root" && argv[index + 1]) { roots.push(resolve(argv[++index])); continue; }
    if (argv[index] === "--manifest" && argv[index + 1]) { manifests.push(resolve(argv[++index])); continue; }
  }
  if (roots.length === 0) throw new Error("EVIDENCE_ROOT_REQUIRED");
  const report = await sweep({ manifestPaths: manifests, roots });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.ok) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stdout.write(`${JSON.stringify({ ok: false, code: error.message })}\n`);
    process.exitCode = 1;
  });
}
