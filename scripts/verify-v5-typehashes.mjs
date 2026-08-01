#!/usr/bin/env node
// Freeze gate for the V5 EIP-712 types and transcript schemas.
//
// The type strings are read out of the Solidity sources, hashed, and compared
// against the pinned manifest below. Changing a field, reordering two fields or
// renaming a type all change the hash, so a schema cannot drift after the
// freeze without this failing.
//
// A frozen type is not "a type we agreed on". It is a hash that off-chain
// producers, the verifier, the binder and every archived signature all depend
// on. Editing one silently invalidates evidence that was already produced.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { keccak256, toBytes } from "viem";

const REPO = resolve(import.meta.dirname, "..");

// name -> [source file, pinned keccak256 of the type string]
const FROZEN = {
  ConfidentialMatchResultV5Core: [
    "contracts/src/v5/MordantResultCoreV5.sol",
    "0x3428619310f11cb249a9c673fbcee9eeb9cfed9f2c515ff2a8cdfb1fee0a4bf5",
  ],
  ConfidentialMatchAttestationV5: [
    "contracts/src/v5/MordantMatchVerifierV5.sol",
    "0x8ef0fc17e2de7e62e4ec12daed5f608451fde3bf304eaaa3133354222cb05361",
  ],
  DisclosureConsentV5: [
    "contracts/src/v5/PrivateMatchBinderV5.sol",
    "0xcf8cd9a622d5692702a48f51306c1681b66caae31a75943b9f2bb681296c70a5",
  ],
  BilateralSessionIntentV5: [
    "contracts/src/v5/MordantScopeGovernanceRegistryV5.sol",
    "0x46b6113037776856ab1103a6b21ce3fa94d39940bddd0f59b0f3c4ea69cb898d",
  ],
};

/** Extracts the quoted EIP-712 type string for `name` from a Solidity source. */
function typeStringFor(file, name) {
  const source = readFileSync(resolve(REPO, file), "utf8");
  // The type string is the only string literal that starts with `<name>(`.
  const match = source.match(new RegExp(`"(${name}\\([^"]*\\))"`));
  if (!match) throw new Error(`no EIP-712 type string for ${name} in ${file}`);
  return match[1];
}

const rewrite = process.argv.includes("--write");
const computed = {};
let drift = 0;

for (const [name, [file, pinned]] of Object.entries(FROZEN)) {
  const text = typeStringFor(file, name);
  const hash = keccak256(toBytes(text));
  computed[name] = hash;
  const status = hash === pinned ? "ok  " : "DRIFT";
  if (hash !== pinned) drift += 1;
  console.log(`${status} ${name}`);
  console.log(`     ${hash}`);
  if (hash !== pinned && !rewrite) console.log(`     pinned ${pinned}`);
}

if (rewrite) {
  console.log("\nPinned values for the manifest:");
  for (const [name, hash] of Object.entries(computed)) {
    console.log(`  ${name}: "${hash}",`);
  }
  process.exit(0);
}

if (drift > 0) {
  console.error(
    `\n${drift} V5 type(s) drifted from the freeze. ` +
      "Every archived signature and every off-chain producer depends on these hashes. " +
      "Re-pin only as a deliberate, versioned schema change.",
  );
  process.exit(1);
}
console.log(`\nall ${Object.keys(FROZEN).length} V5 EIP-712 types match the freeze`);
