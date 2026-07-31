import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ROLE,
  ZERO_BYTES32,
  computeAttestationDigest,
  computeResultCommitment,
  computeResultDigest,
  validateAttestation,
  validateResult,
} from "./canonical.mjs";
import { validateBenchmarkSummary } from "../benchmark/validate-benchmark-summary.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const shared = join(here, "..");

function check(condition, code) {
  if (!condition) throw new Error(code);
}

async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

const resultSchema = await json(join(shared, "result-schema", "confidential-policy-result.schema.json"));
const attestationSchema = await json(join(shared, "result-schema", "attestation-envelope.schema.json"));
const benchmarkSchema = await json(join(shared, "benchmark", "benchmark-result.schema.json"));
const benchmarkSummarySchema = await json(join(shared, "benchmark", "benchmark-summary.schema.json"));
const manifest = await json(join(shared, "test-vectors", "manifest.json"));

for (const [name, schema] of Object.entries({
  resultSchema,
  attestationSchema,
  benchmarkSchema,
  benchmarkSummarySchema,
})) {
  check(schema.$schema === "https://json-schema.org/draft/2020-12/schema", `${name}:draft`);
  check(schema.type === "object" && schema.additionalProperties === false, `${name}:strict-root`);
}

check(manifest.schemaVersion === "mordant.fhe-test-manifest/1", "manifest:version");
check(manifest.policy.combine === "AND", "manifest:combine");
check(manifest.policy.responsibleRoleOnConflict === ROLE.facility, "manifest:role");
check(manifest.privacy.fixtureMaterialization === "client-process-memory-only", "manifest:privacy");
check(manifest.privacy.forbidDebugInputEcho === true, "manifest:no-debug-echo");

const requiredExpressions = [
  "same receivable",
  "same currency",
  "a.activeFrom < b.activeUntil",
  "b.activeFrom < a.activeUntil",
  "pledge A is exclusive",
  "pledge B is exclusive",
  "submitter A is authorized",
  "submitter B is authorized",
];
check(JSON.stringify(manifest.policy.expression) === JSON.stringify(requiredExpressions), "manifest:policy");

const mandatoryCases = new Set([
  "conflict-true",
  "different-receivable",
  "periods-separated",
  "periods-adjacent-no-overlap",
  "different-currency",
  "exclusivity-false",
  "unauthorized-submitter",
  "malformed-ciphertext",
  "wrong-key-id",
  "wrong-policy-version",
  "result-replay",
  "result-expired",
]);
const ids = new Set();
for (const testCase of manifest.cases) {
  check(/^[a-z0-9][a-z0-9-]*$/.test(testCase.id), `case:${testCase.id}:id`);
  check(!ids.has(testCase.id), `case:${testCase.id}:duplicate`);
  ids.add(testCase.id);
  check(Object.keys(testCase.inputs).sort().join(",") === "a,b", `case:${testCase.id}:inputs`);
  check(
    Object.values(testCase.inputs).every((value) =>
      typeof value === "string" && value.startsWith("client-runtime://mordant/fhe/v1/")),
    `case:${testCase.id}:runtime-ref`,
  );
  check(typeof testCase.mutation === "string", `case:${testCase.id}:mutation`);
  const expected = testCase.expected;
  if (expected.conflictConfirmed === false) {
    check(expected.responsibleRole === ZERO_BYTES32, `case:${testCase.id}:false-role`);
    check(expected.cureDeadline === "0", `case:${testCase.id}:false-deadline`);
  }
  if (expected.conflictConfirmed === true) {
    check(expected.responsibleRole === ROLE.facility, `case:${testCase.id}:true-role`);
    check(expected.cureDeadline === "evaluation-time-plus-cure-period", `case:${testCase.id}:true-deadline`);
  }
  if (expected.stage === "ingress-rejected") {
    check(expected.conflictConfirmed === null, `case:${testCase.id}:rejected-result`);
    check(typeof expected.errorCode === "string", `case:${testCase.id}:error-code`);
  }
}
for (const id of mandatoryCases) check(ids.has(id), `manifest:missing:${id}`);

const manifestText = await readFile(join(shared, "test-vectors", "manifest.json"), "utf8");
for (const forbiddenKey of [
  "\"pledge\"", "\"plaintext\"", "\"cleartext\"", "\"invoiceRoot\"",
  "\"originatorSigner\"", "\"facility\"", "\"obligationId\"", "\"amount\"",
  "\"currency\"", "\"activeFrom\"", "\"activeUntil\"", "\"exclusive\"",
  "\"signature\"",
]) check(!manifestText.includes(forbiddenKey), `manifest:forbidden-input-key:${forbiddenKey}`);

const vector = manifest.canonicalEncodingVector;
const expectedCommitment = computeResultCommitment(vector.result);
check(expectedCommitment === vector.result.resultCommitment, "encoding-vector:result-commitment");
validateResult(vector.result, manifest.publicHarness.verifier);
const resultDigest = computeResultDigest(vector.result, manifest.publicHarness.verifier);
check(resultDigest === vector.resultDigest, "encoding-vector:result-digest");
const attestationDigest = computeAttestationDigest(
  vector.result,
  manifest.publicHarness.verifier,
  manifest.publicHarness.validatorSetId,
  resultDigest,
);
check(attestationDigest === vector.attestationDigest, "encoding-vector:attestation-digest");

const structuralAttestation = {
  schemaVersion: "mordant.confidential-policy-attestation/1",
  attestationScheme: "eip712-secp256k1-quorum/1",
  resultDigest,
  validatorSetId: manifest.publicHarness.validatorSetId,
  attestationDigest,
  quorum: 2,
  signatures: [
    { validator: "0x3333333333333333333333333333333333333333", signature: `0x${"11".repeat(65)}` },
    { validator: "0x4444444444444444444444444444444444444444", signature: `0x${"22".repeat(65)}` },
  ],
};
validateAttestation(structuralAttestation, vector.result, manifest.publicHarness.verifier);
let rejectedUnordered = false;
try {
  validateAttestation(
    { ...structuralAttestation, signatures: [...structuralAttestation.signatures].reverse() },
    vector.result,
    manifest.publicHarness.verifier,
  );
} catch (error) {
  rejectedUnordered = error instanceof Error && error.message === "ATTESTATION_VALIDATOR_ORDER";
}
check(rejectedUnordered, "attestation:unordered-negative");

let rejectedCommitmentMutation = false;
try {
  validateResult(
    { ...vector.result, nonce: "8" },
    manifest.publicHarness.verifier,
  );
} catch (error) {
  rejectedCommitmentMutation = error instanceof Error && error.message === "RESULT_COMMITMENT";
}
check(rejectedCommitmentMutation, "result:commitment-negative");

const sharedFiles = await readdir(shared);
check(sharedFiles.includes("README.md"), "shared:readme");
check(sharedFiles.includes("threat-model"), "shared:threat-model");

const benchmarkSummary = await validateBenchmarkSummary();

process.stdout.write(
  `Shared FHE spec OK: ${manifest.cases.length} cases; canonical digests verified; `
  + `${benchmarkSummary.modes} benchmark modes validated.\n`,
);
