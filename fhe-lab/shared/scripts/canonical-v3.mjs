import { encodeAbiParameters, hashTypedData, keccak256, stringToHex } from "viem";

export const V3_RESULT_SCHEMA_VERSION = "mordant.confidential-policy-result/3-lab";
export const V3_EIP712_NAME = "Mordant Confidential Policy";
export const V3_EIP712_VERSION = "3";
export const V3_RESULT_CORE_TYPE =
  "ConfidentialPolicyResultV3Core(uint256 chainId,address consumer,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)";
export const V3_RESULT_TYPES = Object.freeze({
  ConfidentialPolicyResultV3: [
    { name: "chainId", type: "uint256" }, { name: "consumer", type: "address" },
    { name: "vault", type: "address" }, { name: "policyId", type: "bytes32" },
    { name: "policyVersion", type: "uint32" }, { name: "inputCommitmentA", type: "bytes32" },
    { name: "inputCommitmentB", type: "bytes32" }, { name: "conflictConfirmed", type: "bool" },
    { name: "nonce", type: "uint256" }, { name: "validUntil", type: "uint64" },
    { name: "providerProofCommitment", type: "bytes32" }, { name: "resultCommitment", type: "bytes32" },
  ],
});
export const V3_ATTESTATION_TYPES = Object.freeze({
  ConfidentialPolicyAttestation: [
    { name: "validatorSetId", type: "bytes32" }, { name: "resultDigest", type: "bytes32" },
  ],
});

const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const UINT = /^(0|[1-9][0-9]*)$/;
const UINT32_MAX = (1n << 32n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;

function fail(code) { throw new Error(code); }
function exactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("V3_RESULT_OBJECT");
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail("V3_RESULT_FIELDS");
}
function uint(value, max, code) {
  if (typeof value !== "string" || !UINT.test(value) || BigInt(value) > max) fail(code);
  return BigInt(value);
}
function address(value, code) { if (typeof value !== "string" || !ADDRESS.test(value)) fail(code); return value; }
function bytes32(value, code) { if (typeof value !== "string" || !BYTES32.test(value)) fail(code); return value; }

export function v3Message(result) {
  return {
    chainId: uint(result.chainId, UINT256_MAX, "V3_CHAIN_ID"),
    consumer: address(result.consumer, "V3_CONSUMER"), vault: address(result.vault, "V3_VAULT"),
    policyId: bytes32(result.policyId, "V3_POLICY_ID"),
    policyVersion: Number(uint(result.policyVersion, UINT32_MAX, "V3_POLICY_VERSION")),
    inputCommitmentA: bytes32(result.inputCommitmentA, "V3_INPUT_A"),
    inputCommitmentB: bytes32(result.inputCommitmentB, "V3_INPUT_B"),
    conflictConfirmed: result.conflictConfirmed,
    nonce: uint(result.nonce, UINT256_MAX, "V3_NONCE"),
    validUntil: uint(result.validUntil, UINT64_MAX, "V3_VALID_UNTIL"),
    providerProofCommitment: bytes32(result.providerProofCommitment, "V3_PROVIDER_PROOF"),
    resultCommitment: bytes32(result.resultCommitment, "V3_RESULT_COMMITMENT"),
  };
}

export function computeV3ResultCommitment(result) {
  const value = v3Message(result);
  return keccak256(encodeAbiParameters(
    [
      { type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" },
      { type: "bytes32" }, { type: "uint32" }, { type: "bytes32" }, { type: "bytes32" },
      { type: "bool" }, { type: "uint256" }, { type: "uint64" }, { type: "bytes32" },
    ],
    [
      keccak256(stringToHex(V3_RESULT_CORE_TYPE)), value.chainId, value.consumer, value.vault,
      value.policyId, value.policyVersion, value.inputCommitmentA, value.inputCommitmentB,
      value.conflictConfirmed, value.nonce, value.validUntil, value.providerProofCommitment,
    ],
  ));
}

export function computeV3ResultDigest(result, verifier) {
  const message = v3Message(result);
  const chainId = Number(message.chainId);
  if (!Number.isSafeInteger(chainId)) fail("V3_CHAIN_ID_RANGE");
  return hashTypedData({
    domain: { name: V3_EIP712_NAME, version: V3_EIP712_VERSION, chainId, verifyingContract: address(verifier, "V3_VERIFIER") },
    types: V3_RESULT_TYPES, primaryType: "ConfidentialPolicyResultV3", message,
  });
}

export function validateV3Result(result, verifier) {
  exactKeys(result, [
    "schemaVersion", "chainId", "consumer", "vault", "policyId", "policyVersion", "inputCommitmentA",
    "inputCommitmentB", "conflictConfirmed", "nonce", "validUntil", "providerProofCommitment", "resultCommitment",
  ]);
  if (result.schemaVersion !== V3_RESULT_SCHEMA_VERSION || typeof result.conflictConfirmed !== "boolean") fail("V3_RESULT_SCHEMA");
  const message = v3Message(result);
  if (message.providerProofCommitment === `0x${"00".repeat(32)}`) fail("V3_PROVIDER_PROOF_ZERO");
  if (computeV3ResultCommitment(result) !== result.resultCommitment) fail("V3_RESULT_COMMITMENT");
  computeV3ResultDigest(result, verifier);
  return true;
}
