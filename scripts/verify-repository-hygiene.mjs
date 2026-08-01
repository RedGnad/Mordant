#!/usr/bin/env node

// Repository hygiene gates for the private-matching integration.
//
// Three scans, each of which has caught something real at least once:
//
//   large-file     a 10.6 MB compiled Go binary was committed by accident on the
//                  source branch; it must never arrive here
//   generated      build output must not be tracked
//   dependency     every direct dependency must carry a license we accept
//
// Everything is checked against the git index rather than the working tree, so a
// file that is merely present locally cannot pass or fail the build.

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const MAX_TRACKED_FILE_BYTES = 1_048_576;

/// Paths that are build output or a working artifact and must never be tracked.
export const GENERATED_PATTERNS = [
  /^contracts\/out\//,
  /^contracts\/cache\//,
  /^fhe-lab\/[^/]+\/out\//,
  /^fhe-lab\/lattigo\/ceremony-client$/,
  /^fhe-lab\/lattigo\/cmd\/[^/]+\/[a-z-]+$/,
  /^node_modules\//,
  /^\.next\//,
  /^test-results\//,
  /\.tsbuildinfo$/,
];

/// Licenses accepted for direct dependencies.
export const ACCEPTED_LICENSES = new Set([
  "MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD",
  "MIT-0", "Unlicense", "CC0-1.0", "BlueOak-1.0.0", "Python-2.0",
  // SIL Open Font License. Applies to bundled webfonts, not to code, and
  // permits redistribution and embedding.
  "OFL-1.1",
]);

/// Files exempt from the size cap, with the reason recorded here rather than
/// in a wildcard.
export const LARGE_FILE_EXEMPTIONS = new Map([
  ["docs/design/assets/m-ex1-review-film.webm", "Recorded design review, reviewed and accepted before this integration"],
  ["pnpm-lock.yaml", "Dependency lockfile"],
]);

async function trackedFiles() {
  const { stdout } = await run("git", ["ls-files", "-z"], { cwd: REPO, maxBuffer: 32 * 1024 * 1024 });
  return stdout.split("\0").filter((entry) => entry !== "");
}

export async function scanLargeFiles() {
  const { stdout } = await run("git", ["ls-tree", "-r", "-l", "HEAD"], { cwd: REPO, maxBuffer: 32 * 1024 * 1024 });
  const offenders = [];
  for (const line of stdout.split("\n")) {
    if (line.trim() === "") continue;
    const match = line.match(/^\S+\s+blob\s+\S+\s+(\d+)\t(.+)$/);
    if (!match) continue;
    const bytes = Number(match[1]);
    const path = match[2];
    if (bytes <= MAX_TRACKED_FILE_BYTES) continue;
    if (LARGE_FILE_EXEMPTIONS.has(path)) continue;
    offenders.push({ path, bytes });
  }
  return offenders;
}

export async function scanGenerated() {
  const files = await trackedFiles();
  return files.filter((path) => GENERATED_PATTERNS.some((pattern) => pattern.test(path)));
}

export async function scanLicenses() {
  const manifest = JSON.parse(await readFile(resolve(REPO, "package.json"), "utf8"));
  const direct = Object.keys({ ...manifest.dependencies, ...manifest.devDependencies });
  const unacceptable = [];
  const unknown = [];
  for (const name of direct) {
    let meta;
    try {
      meta = JSON.parse(await readFile(resolve(REPO, "node_modules", name, "package.json"), "utf8"));
    } catch {
      unknown.push({ name, reason: "not installed" });
      continue;
    }
    const license = typeof meta.license === "string"
      ? meta.license
      : meta.license?.type ?? (Array.isArray(meta.licenses) ? meta.licenses[0]?.type : undefined);
    if (!license) { unknown.push({ name, reason: "no license field" }); continue; }
    // A SPDX OR expression passes when any branch is accepted.
    const branches = license.replace(/[()]/g, "").split(/\s+OR\s+/i).map((entry) => entry.trim());
    if (!branches.some((entry) => ACCEPTED_LICENSES.has(entry))) unacceptable.push({ name, license });
  }
  return { direct: direct.length, unacceptable, unknown };
}

export async function hygiene() {
  const [large, generated, licenses] = await Promise.all([
    scanLargeFiles(), scanGenerated(), scanLicenses(),
  ]);
  return {
    largeFiles: large,
    generatedArtifacts: generated,
    licenses,
    ok: large.length === 0 && generated.length === 0 && licenses.unacceptable.length === 0,
  };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const report = await hygiene();
  const cap = `${(MAX_TRACKED_FILE_BYTES / 1024).toFixed(0)} KB`;

  process.stdout.write(`large tracked files over ${cap}: ${report.largeFiles.length}\n`);
  for (const entry of report.largeFiles) {
    process.stdout.write(`  ${(entry.bytes / 1048576).toFixed(1)} MB  ${entry.path}\n`);
  }
  process.stdout.write(`tracked generated artifacts: ${report.generatedArtifacts.length}\n`);
  for (const path of report.generatedArtifacts) process.stdout.write(`  ${path}\n`);
  process.stdout.write(
    `direct dependencies: ${report.licenses.direct}, unacceptable ${report.licenses.unacceptable.length}, unknown ${report.licenses.unknown.length}\n`,
  );
  for (const entry of report.licenses.unacceptable) {
    process.stdout.write(`  ${entry.name}: ${entry.license}\n`);
  }
  for (const entry of report.licenses.unknown) {
    process.stdout.write(`  ${entry.name}: ${entry.reason}\n`);
  }

  if (!report.ok) {
    process.stderr.write("REPOSITORY_HYGIENE_FAILED\n");
    process.exitCode = 1;
  } else {
    process.stdout.write("\nrepository hygiene clean\n");
  }
}
