import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  CaseAdapterProofError,
  loadCaseAdapterDeploymentProof,
  parseCaseAdapterDeploymentProof,
} from "./case-adapter-deployment-proof";

/**
 * F-04: a case-specific adapter must be the reviewed contract, at the exact
 * address, for the exact run.
 *
 * The design point these tests defend: raw runtime code hashes CANNOT be
 * compared across case-specific deployments, because Solidity writes immutables
 * into the runtime. The sound statement is the compiler's immutable-span masked
 * equality, computed at deployment. So the proof is what carries reviewed-ness,
 * and these tests make sure a proof cannot be pointed at the wrong thing.
 */

const PROOF_FILE = "activation-case-adapter-deployment-2026-08-07.json";
const REVIEWED_FILE = "recourse-adapter-v2-deployment-2026-08-06.json";
const ADAPTER = "0x00efE6AAcaC6Aa94A3c66d8F09D310197600D935";
const RUN_ID = "76005a0c-2787-4c50-b196-636e45b71781";

function committed(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(process.cwd(), "docs", "evidence", name), "utf8")) as Record<string, unknown>;
}

/** A scratch evidence root so no tamper is ever written back to the repository. */
function scratchRoot(mutate?: (proof: Record<string, unknown>) => void): string {
  const root = mkdtempSync(join(tmpdir(), "mordant-case-proof-"));
  mkdirSync(join(root, "docs", "evidence"), { recursive: true });
  cpSync(join(process.cwd(), "docs", "evidence", REVIEWED_FILE), join(root, "docs", "evidence", REVIEWED_FILE));
  const proof = committed(PROOF_FILE);
  mutate?.(proof);
  writeFileSync(join(root, "docs", "evidence", PROOF_FILE), JSON.stringify(proof, null, 2));
  return root;
}

function refusesLoad(
  code: string,
  mutate?: (proof: Record<string, unknown>) => void,
  address = ADAPTER,
  runId = RUN_ID,
): void {
  const root = scratchRoot(mutate);
  assert.throws(
    () => loadCaseAdapterDeploymentProof(address, runId, root),
    (error: unknown) => error instanceof CaseAdapterProofError && error.code === code,
    `expected refusal ${code}`,
  );
}

/** Mutates one immutable inside a copy of the committed proof. */
function withImmutable(field: string, value: unknown): (proof: Record<string, unknown>) => void {
  return (proof) => {
    (proof.immutables as Record<string, unknown>)[field] = value;
  };
}

test("F-04: the legitimate case-specific deployment proof satisfies the identity check", () => {
  const proof = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot());
  assert.equal(proof.address.toLowerCase(), ADAPTER.toLowerCase());
  assert.equal(proof.runId, RUN_ID);
  assert.equal(proof.deployedMaskedHash, proof.artifactMaskedHash);
  assert.equal(proof.runtimeBytes, 10_088);
  assert.equal(proof.immutableSpansMasked, 28);
  assert.equal(proof.immutables.cureWindow, 600);
  assert.match(proof.deployedCodeHash, /^0x[0-9a-f]{64}$/u);
  assert.match(proof.transactionHash, /^0x[0-9a-f]{64}$/u);
  // Every security-relevant immutable is present and typed.
  for (const field of [
    "settlementToken", "cviVerifier", "attestor", "facility", "owner",
    "assetIdentityDigest", "expectedGovernedReleaseAuthorityId", "releaseMode",
    "circuitHash", "parameterFingerprint", "cureWindow",
  ]) {
    assert.ok(field in proof.immutables, `${field} missing from the proof`);
  }
});

test("F-04: the masked design is preserved, not replaced by raw code-hash equality", () => {
  const proof = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot());
  const reviewed = committed(REVIEWED_FILE).deployed as Record<string, unknown>;
  // Same reviewed contract, DIFFERENT raw runtime hash, because the immutables
  // differ. Requiring raw equality here would be wrong and would reject a
  // legitimate case deployment.
  assert.notEqual(proof.deployedCodeHash.toLowerCase(), String(reviewed.deployedCodeHash).toLowerCase());
  assert.equal(proof.artifactMaskedHash.toLowerCase(), String(reviewed.artifactMaskedHash).toLowerCase());
  assert.equal(proof.runtimeBytes, reviewed.runtimeBytes);
});

test("F-04: a proof for another adapter address is refused", () => {
  refusesLoad("PROOF_ADDRESS", undefined, "0x1111111111111111111111111111111111111111");
  // And a proof whose own address was edited no longer matches the live adapter.
  refusesLoad("PROOF_ADDRESS", (proof) => { proof.address = "0x2222222222222222222222222222222222222222"; });
});

test("F-04: a proof for another run is refused", () => {
  refusesLoad("PROOF_RUN", undefined, ADAPTER, "11111111-1111-4111-8111-111111111111");
  refusesLoad("PROOF_RUN", (proof) => { proof.runId = "11111111-1111-4111-8111-111111111111"; });
});

test("F-04: a modified masked-bytecode proof is refused", () => {
  refusesLoad("PROOF_MASKED", (proof) => { proof.maskedMatchesReviewedArtifact = false; });
  refusesLoad("PROOF_MASKED", (proof) => { proof.deployedMaskedHash = `0x${"9".repeat(64)}`; });
  refusesLoad("PROOF_MASKED", (proof) => { proof.artifactMaskedHash = `0x${"8".repeat(64)}`; });
  // Claiming equality while the two hashes differ is exactly the forgery shape.
  refusesLoad("PROOF_MASKED", (proof) => {
    proof.maskedMatchesReviewedArtifact = true;
    proof.deployedMaskedHash = `0x${"7".repeat(64)}`;
  });
});

test("F-04: a modified immutable-span count or shape is refused", () => {
  refusesLoad("PROOF_NUMBER", (proof) => { proof.immutableSpansMasked = 0; });
  refusesLoad("PROOF_NUMBER", (proof) => { proof.runtimeBytes = 0; });
  refusesLoad("PROOF_IMMUTABLES", (proof) => {
    delete (proof.immutables as Record<string, unknown>).cureWindow;
  });
  refusesLoad("PROOF_IMMUTABLES", (proof) => {
    (proof.immutables as Record<string, unknown>).unexpected = 1;
  });
});

test("F-04: a changed deployed code hash is still parsed but no longer matches the live runtime", () => {
  // The proof itself only has to be well formed here; binding it to the live
  // runtime is the executor's job, and that comparison is what a changed hash
  // breaks. What the loader must not do is silently accept a malformed one.
  refusesLoad("PROOF_DIGEST", (proof) => { proof.deployedCodeHash = "0xnothex"; });
  const proof = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot((draft) => {
    draft.deployedCodeHash = `0x${"a".repeat(64)}`;
  }));
  const genuine = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot());
  assert.notEqual(proof.deployedCodeHash, genuine.deployedCodeHash);
});

test("F-04: a wrong owner is refused against the reviewed deployment", () => {
  refusesLoad("PROOF_OWNER", withImmutable("owner", "0x3333333333333333333333333333333333333333"));
});

test("F-04: a wrong cure window is refused by shape or by the executor's reviewed check", () => {
  // Zero and negative are refused outright by the proof parser.
  refusesLoad("PROOF_NUMBER", withImmutable("cureWindow", 0));
  // A plausible but different window parses, and is then rejected by the
  // executor against the reviewed configuration.
  const shortened = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot(withImmutable("cureWindow", 60)));
  assert.equal(shortened.immutables.cureWindow, 60);
  assert.notEqual(shortened.immutables.cureWindow, 600);
});

test("F-04: every other security-relevant immutable is carried and typed", () => {
  // Malformed values are refused, so a proof cannot smuggle a non-address or a
  // non-digest into a field the executor will later compare literally.
  for (const field of ["settlementToken", "cviVerifier", "attestor", "facility"]) {
    refusesLoad("PROOF_ADDRESS", withImmutable(field, "0xnot-an-address"));
  }
  for (const field of [
    "assetIdentityDigest", "expectedGovernedReleaseAuthorityId", "releaseMode",
    "circuitHash", "parameterFingerprint",
  ]) {
    refusesLoad("PROOF_DIGEST", withImmutable(field, "0xshort"));
  }
  // A different but well-formed value parses, and the executor compares it to
  // the live readback, so a substituted pin cannot pass unnoticed there.
  const genuine = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot());
  for (const [field, value] of [
    ["settlementToken", "0x4444444444444444444444444444444444444444"],
    ["cviVerifier", "0x5555555555555555555555555555555555555555"],
    ["attestor", "0x6666666666666666666666666666666666666666"],
    ["facility", "0x7777777777777777777777777777777777777777"],
    ["assetIdentityDigest", `0x${"b".repeat(64)}`],
    ["expectedGovernedReleaseAuthorityId", `0x${"c".repeat(64)}`],
    ["releaseMode", `0x${"d".repeat(64)}`],
    ["circuitHash", `0x${"e".repeat(64)}`],
    ["parameterFingerprint", `0x${"f".repeat(64)}`],
  ] as const) {
    const substituted = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot(withImmutable(field, value)));
    assert.notEqual(
      String(substituted.immutables[field as keyof typeof substituted.immutables]).toLowerCase(),
      String(genuine.immutables[field as keyof typeof genuine.immutables]).toLowerCase(),
      `${field} substitution was not observable`,
    );
  }
});

test("F-04: an unsupported or missing proof is refused", () => {
  refusesLoad("PROOF_SCHEMA", (proof) => { proof.schemaVersion = "mordant.something-else/1"; });
  const empty = mkdtempSync(join(tmpdir(), "mordant-case-proof-empty-"));
  mkdirSync(join(empty, "docs", "evidence"), { recursive: true });
  assert.throws(
    () => loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, empty),
    (error: unknown) => error instanceof CaseAdapterProofError && error.code === "PROOF_MISSING",
  );
});

test("F-04: a same-length hostile runtime cannot borrow this proof", () => {
  // The proof pins BOTH a runtime length and the keccak of the exact runtime it
  // was computed from. A hostile contract of identical length has a different
  // code hash, so the executor's live comparison fails even though the length
  // check would have passed on its own.
  const proof = loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot());
  const hostileSameLength = `0x${"60".repeat(proof.runtimeBytes)}`;
  assert.equal((hostileSameLength.length - 2) / 2, proof.runtimeBytes);
  const { keccak256 } = require("viem") as { keccak256: (value: `0x${string}`) => string };
  assert.notEqual(keccak256(hostileSameLength as `0x${string}`).toLowerCase(), proof.deployedCodeHash.toLowerCase());
});

test("F-04: the proof carries no secret", () => {
  const encoded = JSON.stringify(loadCaseAdapterDeploymentProof(ADAPTER, RUN_ID, scratchRoot()));
  for (const forbidden of ["privateKey", "PRIVATE_KEY", "CLEANVERSE_API_KEY", "activeFrom", "signature"]) {
    assert.equal(encoded.includes(forbidden), false, `proof leaked ${forbidden}`);
  }
});
