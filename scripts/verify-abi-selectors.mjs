#!/usr/bin/env node

// Guards the frozen V4 contracts' external surface against silent drift.
//
// A frozen source can be byte-identical and still expose a different ABI if the
// compiler version or settings change, and a downstream client can break on a
// selector it never sees named. So the manifest records every function, event
// and error selector, and CI recomputes them from the freshly compiled
// artifacts.
//
// Selectors are derived from the ABI, not read from a build field, so a change
// in a parameter type produces a new selector and fails here.
//
// Run with --write to regenerate the manifest after an authorized change.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256, toBytes } from "viem";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = resolve(REPO, "docs/provenance/v4-abi-selectors.json");

/// The frozen V4 external surface. Mocks and test doubles are deliberately out
/// of scope: nothing downstream depends on them.
export const GUARDED = [
  ["MordantScopeGovernanceRegistry", "MordantScopeGovernanceRegistry.sol"],
  ["ECDSAQuorumMatchVerifierV4", "ECDSAQuorumMatchVerifierV4.sol"],
  ["PrivateMatchBinder", "PrivateMatchBinder.sol"],
  ["MordantInvoiceVaultV2", "MordantInvoiceVaultV2.sol"],
  ["MordantFactoryV2", "MordantFactoryV2.sol"],
  ["MordantIssuerRegistry", "MordantIssuerRegistry.sol"],
  ["MordantSourceIdentityRegistry", "MordantSourceIdentityRegistry.sol"],
  ["IAnchoredReceivable", "IAnchoredReceivable.sol"],
  ["IIdentityAnchor", "IIdentityAnchor.sol"],
];

/// Canonical ABI type string, expanding tuples so a struct change is visible.
function canonicalType(input) {
  if (!input.type.startsWith("tuple")) return input.type;
  const inner = (input.components ?? []).map(canonicalType).join(",");
  return `(${inner})${input.type.slice("tuple".length)}`;
}

export function signatureOf(entry) {
  return `${entry.name}(${(entry.inputs ?? []).map(canonicalType).join(",")})`;
}

export function selectorOf(entry) {
  const digest = keccak256(toBytes(signatureOf(entry)));
  // Events are identified by the full 32-byte topic; everything else by 4 bytes.
  return entry.type === "event" ? digest : digest.slice(0, 10);
}

export async function surfaceOf(name, file) {
  const artifact = JSON.parse(
    await readFile(resolve(REPO, `contracts/out/${file}/${name}.json`), "utf8"),
  );
  const surface = {};
  for (const entry of artifact.abi) {
    if (!["function", "event", "error"].includes(entry.type)) continue;
    surface[`${entry.type} ${signatureOf(entry)}`] = selectorOf(entry);
  }
  return Object.fromEntries(Object.entries(surface).sort(([a], [b]) => a.localeCompare(b)));
}

export async function currentSurfaces() {
  const surfaces = {};
  for (const [name, file] of GUARDED) surfaces[name] = await surfaceOf(name, file);
  return surfaces;
}

export async function verify() {
  const current = await currentSurfaces();
  let approved;
  try {
    approved = JSON.parse(await readFile(MANIFEST, "utf8")).surfaces;
  } catch {
    return { missingManifest: true, current, drift: [] };
  }
  const drift = [];
  for (const [contract, surface] of Object.entries(current)) {
    const before = approved[contract];
    if (!before) { drift.push({ contract, change: "contract not in manifest" }); continue; }
    for (const [signature, selector] of Object.entries(surface)) {
      if (!(signature in before)) drift.push({ contract, change: "added", signature, selector });
      else if (before[signature] !== selector) {
        drift.push({ contract, change: "selector changed", signature, from: before[signature], to: selector });
      }
    }
    for (const signature of Object.keys(before)) {
      if (!(signature in surface)) drift.push({ contract, change: "removed", signature });
    }
  }
  for (const contract of Object.keys(approved)) {
    if (!(contract in current)) drift.push({ contract, change: "contract removed" });
  }
  return { missingManifest: false, current, drift };
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--write")) {
    const surfaces = await currentSurfaces();
    const total = Object.values(surfaces).reduce((sum, entry) => sum + Object.keys(entry).length, 0);
    await writeFile(MANIFEST, `${JSON.stringify({
      comment: "Approved external surface of the frozen V4 contracts. Regenerate with scripts/verify-abi-selectors.mjs --write only after an authorized change.",
      frozenContracts: "af5baad",
      entries: total,
      surfaces,
    }, null, 2)}\n`);
    process.stdout.write(`wrote ${total} selectors across ${Object.keys(surfaces).length} contracts\n`);
  } else {
    const report = await verify();
    if (report.missingManifest) {
      process.stderr.write("ABI_MANIFEST_MISSING: run with --write to create it\n");
      process.exitCode = 1;
    } else if (report.drift.length > 0) {
      for (const entry of report.drift) process.stdout.write(`  ${JSON.stringify(entry)}\n`);
      process.stderr.write(`ABI_SELECTOR_DRIFT: ${report.drift.length} change(s)\n`);
      process.exitCode = 1;
    } else {
      const total = Object.values(report.current).reduce((sum, entry) => sum + Object.keys(entry).length, 0);
      process.stdout.write(`${total} selectors across ${Object.keys(report.current).length} contracts match the approved manifest\n`);
    }
  }
}
