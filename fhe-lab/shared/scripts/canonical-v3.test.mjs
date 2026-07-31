import assert from "node:assert/strict";
import test from "node:test";
import { computeV3ResultCommitment, validateV3Result, V3_RESULT_SCHEMA_VERSION } from "./canonical-v3.mjs";

const result = {
  schemaVersion: V3_RESULT_SCHEMA_VERSION, chainId: "10143", consumer: "0x2222222222222222222222222222222222222222",
  vault: "0x1111111111111111111111111111111111111111", policyId: `0x${"33".repeat(32)}`,
  policyVersion: "1", inputCommitmentA: `0x${"44".repeat(32)}`, inputCommitmentB: `0x${"55".repeat(32)}`,
  conflictConfirmed: true, nonce: "9", validUntil: "2000000000", providerProofCommitment: `0x${"66".repeat(32)}`,
  resultCommitment: `0x${"00".repeat(32)}`,
};
result.resultCommitment = computeV3ResultCommitment(result);

test("V3 binds the intended consumer into the commitment and EIP-712 result", () => {
  assert.equal(validateV3Result(result, "0x3333333333333333333333333333333333333333"), true);
  const moved = { ...result, consumer: "0x4444444444444444444444444444444444444444" };
  moved.resultCommitment = computeV3ResultCommitment(moved);
  assert.notEqual(moved.resultCommitment, result.resultCommitment);
});

test("V3 rejects V2 consequence fields", () => {
  assert.throws(() => validateV3Result({ ...result, responsibleRole: `0x${"00".repeat(32)}` }, "0x3333333333333333333333333333333333333333"));
});
