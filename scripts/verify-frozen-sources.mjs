#!/usr/bin/env node

// Verifies every frozen V4 contract source against the approved af5baad manifest.
//
// The comparison is on the git blob SHA-1 of the working-tree file, which is
// what git itself would store, so a change in whitespace, line endings or a
// single character fails. It does not require the af5baad commit to be present
// locally: the manifest carries the approved hashes, so a shallow CI clone can
// still verify.
//
// This is the check that keeps "the architecture is frozen" a fact rather than a
// convention.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = resolve(REPO, "docs/provenance/frozen-sources-af5baad.txt");

/// Git's blob object hash: "blob <bytelength>\0" followed by the raw content.
function gitBlobSha1(contents) {
  return createHash("sha1")
    .update(`blob ${contents.length}\0`)
    .update(contents)
    .digest("hex");
}

export async function verify(manifestPath = MANIFEST, root = REPO) {
  const manifest = await readFile(manifestPath, "utf8");
  const entries = manifest
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) => {
      const [expected, ...rest] = line.split(/\s+/);
      return { expected, path: rest.join(" ") };
    });

  if (entries.length === 0) throw new Error("FROZEN_MANIFEST_EMPTY");

  const results = [];
  for (const entry of entries) {
    let actual = null;
    let error = null;
    try {
      actual = gitBlobSha1(await readFile(resolve(root, entry.path)));
    } catch (cause) {
      error = cause.code === "ENOENT" ? "MISSING" : String(cause.message);
    }
    results.push({ ...entry, actual, error, ok: error === null && actual === entry.expected });
  }
  return { manifestPath, count: results.length, results, drift: results.filter((entry) => !entry.ok) };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const report = await verify();
  for (const entry of report.results) {
    process.stdout.write(`${entry.ok ? "ok  " : "DRIFT"}  ${entry.path}\n`);
    if (!entry.ok) {
      process.stdout.write(`        expected ${entry.expected}\n`);
      process.stdout.write(`        actual   ${entry.error ?? entry.actual}\n`);
    }
  }
  process.stdout.write(`\n${report.count - report.drift.length}/${report.count} frozen sources match af5baad\n`);
  if (report.drift.length > 0) {
    process.stderr.write("FROZEN_SOURCE_DRIFT\n");
    process.exitCode = 1;
  }
}
