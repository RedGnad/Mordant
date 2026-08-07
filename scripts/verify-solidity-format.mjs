#!/usr/bin/env node

// Runs `forge fmt --check` over every Solidity file EXCEPT the frozen set.
//
// The two requirements collide directly: the repository formats its Solidity,
// and the sixteen frozen sources must stay byte-identical to af5baad. `forge fmt`
// would reformat thirteen of them. Formatting wins everywhere it is allowed to,
// and the freeze wins where it is not.
//
// The exclusion is not a blanket skip. It is exactly the manifest that
// `verify-frozen-sources.mjs` enforces, so a file can only escape the formatter
// by being pinned to a hash — and a file that is pinned cannot drift.
//
// Pass --write to format the non-frozen files in place.

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = resolve(REPO, "docs/provenance/frozen-sources-af5baad.txt");
// Pinned for a different reason than the af5baad freeze: this source is what a
// live deployment's artifact was compiled from, and Solidity folds a hash of the
// source bytes into the runtime code, so formatting it would change the very
// artifact the retained deployment proofs assert.
const DEPLOYED_MANIFEST = resolve(REPO, "docs/provenance/deployed-recourse-sources.txt");

async function pinnedPaths(manifestPath) {
  const manifest = await readFile(manifestPath, "utf8");
  return manifest
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) => line.split(/\s+/).slice(1).join(" "));
}

/** Every source the formatter must not touch, each one pinned to a hash elsewhere. */
export async function frozenPaths() {
  return new Set([...await pinnedPaths(MANIFEST), ...await pinnedPaths(DEPLOYED_MANIFEST)]);
}

export async function formattablePaths() {
  const frozen = await frozenPaths();
  const { stdout } = await run("git", ["ls-files", "-z", "contracts"], { cwd: REPO });
  return stdout
    .split("\0")
    .filter((path) => path.endsWith(".sol"))
    .filter((path) => !frozen.has(path));
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const paths = await formattablePaths();
  const frozen = await frozenPaths();
  const write = process.argv.includes("--write");
  const solidityFrozen = [...frozen].filter((path) => path.endsWith(".sol"));

  if (paths.length === 0) {
    process.stdout.write("no formattable Solidity outside the frozen set\n");
  } else {
    // forge does not rebase file arguments onto --root, so the command runs
    // from inside contracts/ with paths relative to it.
    const args = [...(write ? [] : ["--check"]), ...paths.map((path) => relative("contracts", path))];
    try {
      const { stdout } = await run("forge", ["fmt", ...args], {
        cwd: resolve(REPO, "contracts"), maxBuffer: 16 * 1024 * 1024,
      });
      if (stdout.trim() !== "") process.stdout.write(stdout);
      process.stdout.write(
        `${write ? "formatted" : "format check passed for"} ${paths.length} Solidity file(s)\n`,
      );
    } catch (error) {
      process.stdout.write(String(error.stdout ?? ""));
      process.stderr.write("SOLIDITY_FORMAT_DRIFT\n");
      process.exitCode = 1;
    }
  }
  process.stdout.write(
    `${solidityFrozen.length} frozen Solidity file(s) excluded and pinned by hash instead\n`,
  );
}
