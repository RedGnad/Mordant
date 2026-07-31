import {
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  stringToHex,
} from "viem";

export const RESULT_SCHEMA_VERSION = "mordant.confidential-policy-result/1";
export const ATTESTATION_SCHEMA_VERSION = "mordant.confidential-policy-attestation/1";
export const ATTESTATION_SCHEME = "eip712-secp256k1-quorum/1";
export const EIP712_NAME = "Mordant Confidential Policy";
export const EIP712_VERSION = "1";
export const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

export const ROLE = Object.freeze({
  none: ZERO_BYTES32,
  buyer: keccak256(stringToHex("mordant.role.buyer.v1")),
  originator: keccak256(stringToHex("mordant.role.originator.v1")),
  facility: keccak256(stringToHex("mordant.role.facility.v1")),
  holder: keccak256(stringToHex("mordant.role.holder.v1")),
});

export const RESULT_CORE_TYPE =
  "ConfidentialPolicyResultCore(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,bytes32 responsibleRole,uint64 cureDeadline,uint256 nonce,uint64 validUntil)";

export const RESULT_TYPES = Object.freeze({
  ConfidentialPolicyResult: [
    { name: "chainId", type: "uint256" },
    { name: "vault", type: "address" },
    { name: "policyId", type: "bytes32" },
    { name: "policyVersion", type: "uint32" },
    { name: "inputCommitmentA", type: "bytes32" },
    { name: "inputCommitmentB", type: "bytes32" },
    { name: "conflictConfirmed", type: "bool" },
    { name: "responsibleRole", type: "bytes32" },
    { name: "cureDeadline", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "validUntil", type: "uint64" },
    { name: "resultCommitment", type: "bytes32" },
  ],
});

export const ATTESTATION_TYPES = Object.freeze({
  ConfidentialPolicyAttestation: [
    { name: "validatorSetId", type: "bytes32" },
    { name: "resultDigest", type: "bytes32" },
  ],
});

const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const CANONICAL_UINT = /^(0|[1-9][0-9]*)$/;
const UINT32_MAX = (1n << 32n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;

function fail(code) {
  throw new Error(code);
}
function exactKeys(value, expected, code) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(code);
  }
}

function parseUint(value, max, code) {
  if (typeof value !== "string" || !CANONICAL_UINT.test(value)) fail(code);
  const parsed = BigInt(value);
  if (parsed > max) fail(code);
  return parsed;
}

function assertBytes32(value, code) {
  if (typeof value !== "string" || !BYTES32.test(value)) fail(code);
}

function assertAddress(value, code) {
  if (typeof value !== "string" || !ADDRESS.test(value)) fail(code);
}

export function resultMessage(result) {
  return {
    chainId: parseUint(result.chainId, UINT256_MAX, "RESULT_CHAIN_ID"),
    vault: result.vault,
    policyId: result.policyId,
    policyVersion: Number(parseUint(result.policyVersion, UINT32_MAX, "RESULT_POLICY_VERSION")),
    inputCommitmentA: result.inputCommitmentA,
    inputCommitmentB: result.inputCommitmentB,
    conflictConfirmed: result.conflictConfirmed,
    responsibleRole: result.responsibleRole,
    cureDeadline: parseUint(result.cureDeadline, UINT64_MAX, "RESULT_CURE_DEADLINE"),
    nonce: parseUint(result.nonce, UINT256_MAX, "RESULT_NONCE"),
    validUntil: parseUint(result.validUntil, UINT64_MAX, "RESULT_VALID_UNTIL"),
    resultCommitment: result.resultCommitment,
  };
}

export function computeResultCommitment(result) {
  const message = resultMessage({ ...result, resultCommitment: ZERO_BYTES32 });
  return keccak256(encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "uint256" },
      { type: "address" },
      { type: "bytes32" },
      { type: "uint32" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "bool" },
      { type: "bytes32" },
      { type: "uint64" },
      { type: "uint256" },
      { type: "uint64" },
    ],
    [
      keccak256(stringToHex(RESULT_CORE_TYPE)),
      message.chainId,
      message.vault,
      message.policyId,
      message.policyVersion,
      message.inputCommitmentA,
      message.inputCommitmentB,
      message.conflictConfirmed,
      message.responsibleRole,
      message.cureDeadline,
      message.nonce,
      message.validUntil,
    ],
  ));
}

function eip712Domain(result, verifyingContract) {
  const chainId = parseUint(result.chainId, UINT256_MAX, "RESULT_CHAIN_ID");
  if (chainId > BigInt(Number.MAX_SAFE_INTEGER)) fail("EIP712_CHAIN_ID_JS_RANGE");
  assertAddress(verifyingContract, "VERIFIER_ADDRESS");
  return {
    name: EIP712_NAME,
    version: EIP712_VERSION,
    chainId: Number(chainId),
    verifyingContract,
  };
}

export function computeResultDigest(result, verifyingContract) {
  return hashTypedData({
    domain: eip712Domain(result, verifyingContract),
    types: RESULT_TYPES,
    primaryType: "ConfidentialPolicyResult",
    message: resultMessage(result),
  });
}

export function computeAttestationDigest(result, verifyingContract, validatorSetId, resultDigest) {
  assertBytes32(validatorSetId, "ATTESTATION_VALIDATOR_SET_ID");
  assertBytes32(resultDigest, "ATTESTATION_RESULT_DIGEST");
  return hashTypedData({
    domain: eip712Domain(result, verifyingContract),
    types: ATTESTATION_TYPES,
    primaryType: "ConfidentialPolicyAttestation",
    message: { validatorSetId, resultDigest },
  });
}

export function validateResult(result, verifyingContract) {
  if (result === null || typeof result !== "object" || Array.isArray(result)) fail("RESULT_OBJECT");
  exactKeys(result, [
    "schemaVersion", "chainId", "vault", "policyId", "policyVersion", "inputCommitmentA",
    "inputCommitmentB", "conflictConfirmed", "responsibleRole", "cureDeadline", "nonce",
    "validUntil", "resultCommitment",
  ], "RESULT_FIELDS");
  if (result.schemaVersion !== RESULT_SCHEMA_VERSION) fail("RESULT_SCHEMA_VERSION");
  assertAddress(result.vault, "RESULT_VAULT");
  for (const field of [
    "policyId", "inputCommitmentA", "inputCommitmentB", "responsibleRole", "resultCommitment",
  ]) assertBytes32(result[field], `RESULT_${field.toUpperCase()}`);
  if (typeof result.conflictConfirmed !== "boolean") fail("RESULT_CONFLICT_BOOL");
  resultMessage(result);
  if (!result.conflictConfirmed && (result.responsibleRole !== ZERO_BYTES32 || result.cureDeadline !== "0")) {
    fail("RESULT_FALSE_OUTPUTS");
  }
  if (result.conflictConfirmed && (result.responsibleRole === ZERO_BYTES32 || result.cureDeadline === "0")) {
    fail("RESULT_TRUE_OUTPUTS");
  }
  if (computeResultCommitment(result) !== result.resultCommitment) fail("RESULT_COMMITMENT");
  computeResultDigest(result, verifyingContract);
  return true;
}

export function validateAttestation(envelope, result, verifyingContract) {
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    fail("ATTESTATION_OBJECT");
  }
  exactKeys(envelope, [
    "schemaVersion", "attestationScheme", "resultDigest", "validatorSetId",
    "attestationDigest", "quorum", "signatures",
  ], "ATTESTATION_FIELDS");
  if (envelope.schemaVersion !== ATTESTATION_SCHEMA_VERSION) fail("ATTESTATION_SCHEMA_VERSION");
  if (envelope.attestationScheme !== ATTESTATION_SCHEME) fail("ATTESTATION_SCHEME");
  for (const field of ["resultDigest", "validatorSetId", "attestationDigest"]) {
    assertBytes32(envelope[field], `ATTESTATION_${field.toUpperCase()}`);
  }
  if (!Number.isInteger(envelope.quorum) || envelope.quorum < 1 || envelope.quorum > 255) {
    fail("ATTESTATION_QUORUM");
  }
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length < envelope.quorum) {
    fail("ATTESTATION_SIGNATURE_COUNT");
  }
  let previous = "";
  for (const item of envelope.signatures) {
    exactKeys(item, ["validator", "signature"], "ATTESTATION_SIGNATURE_FIELDS");
    assertAddress(item.validator, "ATTESTATION_VALIDATOR");
    if (!SIGNATURE.test(item.signature)) fail("ATTESTATION_SIGNATURE");
    if (previous !== "" && previous >= item.validator) fail("ATTESTATION_VALIDATOR_ORDER");
    previous = item.validator;
  }
  const resultDigest = computeResultDigest(result, verifyingContract);
  if (resultDigest !== envelope.resultDigest) fail("ATTESTATION_RESULT_DIGEST");
  const attestationDigest = computeAttestationDigest(
    result,
    verifyingContract,
    envelope.validatorSetId,
    resultDigest,
  );
  if (attestationDigest !== envelope.attestationDigest) fail("ATTESTATION_DIGEST");
  return true;
}
