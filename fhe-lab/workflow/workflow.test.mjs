import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access } from "node:fs/promises";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  PROVIDER_OUTPUT_SCHEMA_VERSION,
  PROVIDER_PROOF_SCHEMA_VERSION,
  WORKFLOW_METRICS_SCHEMA_VERSION,
  loadFixtureProviderOutput,
  normalizeProviderOutput,
  readPublicJson,
  runWorkflow,
} from "./workflow.mjs";

const ARTIFACT = new URL(
  "../monad-adapter/out/ECDSAQuorumConfidentialPolicyVerifier.sol/" +
    "ECDSAQuorumConfidentialPolicyVerifier.json",
  import.meta.url,
);
const RUNNER = fileURLToPath(new URL("./run.mjs", import.meta.url));

async function fixtureOutput() {
  return structuredClone(await loadFixtureProviderOutput());
}

test("accepts only a complete canonical provider success envelope", async () => {
  const supplied = await fixtureOutput();
  const normalized = normalizeProviderOutput(supplied);

  assert.equal(supplied.schemaVersion, PROVIDER_OUTPUT_SCHEMA_VERSION);
  assert.equal(normalized.result.inputCommitmentA, supplied.result.inputCommitmentA);
  assert.equal(normalized.result.inputCommitmentB, supplied.result.inputCommitmentB);
  assert.equal(normalized.result.conflictConfirmed, true);
  assert.equal(normalized.providerProof, undefined);
});

test("rejects a provider failure instead of substituting fixture values", () => {
  assert.throws(
    () => normalizeProviderOutput({
      schemaVersion: PROVIDER_OUTPUT_SCHEMA_VERSION,
      ok: false,
      errorCode: "DECRYPT_FAILED",
    }),
    (error) => error.code === "INPUT_PROVIDER_FAILED" && error.message === "INPUT_PROVIDER_FAILED",
  );
});

test("rejects missing result fields and a mismatched result commitment", async () => {
  const missing = await fixtureOutput();
  delete missing.result.nonce;
  assert.throws(
    () => normalizeProviderOutput(missing),
    (error) => error.code === "INPUT_RESULT_FIELDS",
  );

  const mismatched = await fixtureOutput();
  mismatched.result.resultCommitment = `0x${"99".repeat(32)}`;
  assert.throws(
    () => normalizeProviderOutput(mismatched),
    (error) => error.code === "INPUT_RESULT_COMMITMENT_MISMATCH",
  );
});

test("rejects unknown, plaintext, and ciphertext fields without echoing values", async () => {
  for (const forbiddenField of ["unknown", "plaintext", "ciphertext"]) {
    const supplied = await fixtureOutput();
    supplied[forbiddenField] = "commercial-secret-value";
    assert.throws(
      () => normalizeProviderOutput(supplied),
      (error) => {
        assert.equal(error.code, "INPUT_FIELDS");
        assert.equal(error.message, "INPUT_FIELDS");
        assert.equal(error.message.includes("commercial-secret-value"), false);
        return true;
      },
    );
  }

  const nested = await fixtureOutput();
  nested.result.amount = "1488000";
  assert.throws(
    () => normalizeProviderOutput(nested),
    (error) => error.code === "INPUT_RESULT_FIELDS" && !error.message.includes("1488000"),
  );
});

test("validates the optional provisional provider proof strictly", async () => {
  const supplied = await fixtureOutput();
  supplied.providerProof = {
    schemaVersion: PROVIDER_PROOF_SCHEMA_VERSION,
    transcriptCommitment: `0x${"56".repeat(32)}`,
  };
  const normalized = normalizeProviderOutput(supplied);
  assert.equal(
    normalized.providerProof.transcriptCommitment,
    supplied.providerProof.transcriptCommitment,
  );

  supplied.providerProof.debugTranscript = "must-not-cross-boundary";
  assert.throws(
    () => normalizeProviderOutput(supplied),
    (error) => error.code === "INPUT_PROVIDER_PROOF_FIELDS",
  );
});

test("rejects empty provider input", async () => {
  await assert.rejects(
    readPublicJson(Readable.from([])),
    (error) => error.code === "INPUT_EMPTY" && error.message === "INPUT_EMPTY",
  );
});

test("reads one bounded public JSON object from stdin", async () => {
  const supplied = await fixtureOutput();
  const parsed = await readPublicJson(Readable.from([JSON.stringify(supplied)]));
  assert.equal(parsed.ok, true);
  assert.equal(parsed.result.conflictConfirmed, true);
});

test("CLI failure output contains only a stable code", () => {
  const secret = "plaintext-invoice-1488000";
  const child = spawnSync(process.execPath, [RUNNER, "--stdin"], {
    input: JSON.stringify({
      schemaVersion: PROVIDER_OUTPUT_SCHEMA_VERSION,
      ok: true,
      result: {},
      plaintext: secret,
    }),
    encoding: "utf8",
  });
  assert.equal(child.status, 1);
  assert.equal(child.stderr, "");
  assert.equal(child.stdout.includes(secret), false);
  assert.deepEqual(JSON.parse(child.stdout), {
    schemaVersion: WORKFLOW_METRICS_SCHEMA_VERSION,
    ok: false,
    errorCode: "INPUT_FIELDS",
  });
});

test("requires an explicit provider input or fixture mode", async () => {
  await assert.rejects(
    runWorkflow(),
    (error) => error.code === "INPUT_REQUIRED",
  );
  await assert.rejects(
    runWorkflow({ input: await fixtureOutput(), fixture: true }),
    (error) => error.code === "INPUT_SOURCE_CONFLICT",
  );
});

test("accepts once, rejects replay on the same chain, and emits a public receipt", {
  timeout: 30_000,
}, async (context) => {
  if (spawnSync("anvil", ["--version"], { stdio: "ignore" }).status !== 0) {
    context.skip("anvil is unavailable");
    return;
  }
  try {
    await access(ARTIFACT);
  } catch {
    context.skip("build the monad-adapter Foundry artifact first");
    return;
  }

  const output = await runWorkflow({ fixture: true });

  assert.equal(output.ok, true);
  assert.equal(output.environment, "controlled-local-anvil");
  assert.equal(output.quorum.validatorCount, 3);
  assert.equal(output.quorum.signatures, 2);
  assert.equal(output.quorum.syntheticTestKeys, true);
  assert.equal(output.verification.viewVerified, true);
  assert.equal(output.verification.acceptanceEventObserved, true);
  assert.equal(output.verification.replayStateConsumed, true);
  assert.equal(output.verification.decisionStateConsumed, true);
  assert.equal(output.verification.secondAcceptanceRejected, true);
  assert.equal(output.verification.providerProofRequired, false);
  assert.equal(output.verification.providerProofBoundToAttestation, false);
  assert.match(output.receipt.verifier, /^0x[0-9a-fA-F]{40}$/);
  assert.match(output.receipt.transactionHash, /^0x[0-9a-fA-F]{64}$/);
  assert.match(output.receipt.replayKey, /^0x[0-9a-fA-F]{64}$/);
  assert.match(output.receipt.decisionKey, /^0x[0-9a-fA-F]{64}$/);
  assert.match(output.receipt.attestationDigest, /^0x[0-9a-fA-F]{64}$/);
  assert.equal(BigInt(output.receipt.blockNumber) > 0n, true);
  assert.equal(output.metrics.calldataBytes > 0, true);
  assert.equal(BigInt(output.metrics.gasUsed.resultAcceptance) > 0n, true);
  assert.equal(output.metrics.latencyMs.resultToAccept >= 0, true);

  const serialized = JSON.stringify(output);
  for (const forbidden of [
    "privateKey", "mnemonic", "plaintext", "ciphertext", "activeFrom", "activeUntil", "amount",
  ]) {
    assert.equal(serialized.includes(forbidden), false, `output contains ${forbidden}`);
  }
});
