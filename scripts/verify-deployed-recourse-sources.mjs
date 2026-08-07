#!/usr/bin/env node

// Verifies the deployed recourse contract source against its approved manifest.
//
// This is the counterpart to excluding that source from `forge fmt`. The
// formatter gate lets a file escape formatting only when it is pinned to a hash,
// and this check is what makes the pin real: without it, "excluded from the
// formatter" would quietly mean "free to change".
//
// The pin matters because Solidity embeds a metadata hash derived from the
// source bytes into the runtime code, so even a cosmetic reformat produces a
// different artifact than the one the retained deployment proofs assert.

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verify } from "./verify-frozen-v5-sources.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEPLOYED_RECOURSE_MANIFEST = resolve(REPO, "docs/provenance/deployed-recourse-sources.txt");

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  const report = await verify(DEPLOYED_RECOURSE_MANIFEST, REPO);
  for (const entry of report.results) {
    process.stdout.write(`${entry.ok ? "ok  " : "DRIFT"}  ${entry.path}\n`);
    if (!entry.ok) {
      process.stdout.write(`        expected ${entry.expected}\n`);
      process.stdout.write(`        actual   ${entry.error ?? entry.actual}\n`);
    }
  }
  process.stdout.write(
    `\n${report.count - report.drift.length}/${report.count} deployed recourse sources match their compiled artifact\n`,
  );
  if (report.drift.length > 0) {
    process.stderr.write("DEPLOYED_SOURCE_DRIFT\n");
    process.exitCode = 1;
  }
}
