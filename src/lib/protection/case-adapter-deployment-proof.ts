/**
 * The deployment-time proof that a case-specific adapter is the reviewed contract.
 *
 * Solidity writes immutables INTO the runtime code, so two deployments of the
 * same source have different code hashes and comparing them is meaningless. The
 * only sound cross-deployment statement is the compiler's: mask the known
 * immutable spans and the remaining bytes are identical to the reviewed artifact.
 * That masking needs the compiler's span table, which no RPC exposes, so it is
 * computed once at deployment and retained here.
 *
 * A proof on its own proves nothing about a live address, which is the gap this
 * module closes: the proof is bound to the exact deployed address AND deployment
 * transaction, and the caller must additionally confirm that the live runtime
 * code hashes to `deployedCodeHash`. Without that last step a same-length hostile
 * contract at a different address would satisfy every getter check.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

type Address = `0x${string}`;
type Bytes32 = `0x${string}`;

export const CASE_ADAPTER_DEPLOYMENT_PROOF_SCHEMA =
  "mordant.activation-case-adapter-deployment/1" as const;

export class CaseAdapterProofError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "CaseAdapterProofError";
  }
}

function fail(code: string, message: string): never {
  throw new CaseAdapterProofError(code, message);
}

export type CaseAdapterImmutables = Readonly<{
  settlementToken: Address;
  cviVerifier: Address;
  attestor: Address;
  facility: Address;
  owner: Address;
  assetIdentityDigest: Bytes32;
  expectedGovernedReleaseAuthorityId: Bytes32;
  releaseMode: Bytes32;
  circuitHash: Bytes32;
  parameterFingerprint: Bytes32;
  cureWindow: number;
}>;

export type CaseAdapterDeploymentProof = Readonly<{
  schemaVersion: typeof CASE_ADAPTER_DEPLOYMENT_PROOF_SCHEMA;
  runId: string;
  address: Address;
  transactionHash: Bytes32;
  blockNumber: number;
  runtimeBytes: number;
  /** keccak of the exact runtime code this proof was computed from. */
  deployedCodeHash: Bytes32;
  deployedMaskedHash: Bytes32;
  artifactMaskedHash: Bytes32;
  immutableSpansMasked: number;
  immutables: CaseAdapterImmutables;
}>;

const IMMUTABLE_FIELDS = Object.freeze([
  "settlementToken", "cviVerifier", "attestor", "facility", "owner",
  "assetIdentityDigest", "expectedGovernedReleaseAuthorityId", "releaseMode",
  "circuitHash", "parameterFingerprint", "cureWindow",
]);

function object(value: unknown, code: string, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code, `${label} is required`);
  return value as Record<string, unknown>;
}

function address(value: unknown, label: string): Address {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(value)) fail("PROOF_ADDRESS", `${label} must be an address`);
  return value as Address;
}

function bytes32(value: unknown, label: string): Bytes32 {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(value)) fail("PROOF_DIGEST", `${label} must be a 32-byte hex value`);
  return value.toLowerCase() as Bytes32;
}

function whole(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) fail("PROOF_NUMBER", `${label} must be positive`);
  return value;
}

export function parseCaseAdapterDeploymentProof(value: unknown): CaseAdapterDeploymentProof {
  const raw = object(value, "PROOF_SHAPE", "deployment proof");
  if (raw.schemaVersion !== CASE_ADAPTER_DEPLOYMENT_PROOF_SCHEMA) {
    fail("PROOF_SCHEMA", "Unsupported case adapter deployment proof schema");
  }
  // The masked equality must be asserted AND recomputed-consistent: a proof that
  // merely claims it, or whose masked hash is not the reviewed one, is refused.
  if (raw.maskedMatchesReviewedArtifact !== true) {
    fail("PROOF_MASKED", "The deployment proof does not assert reviewed-artifact equality");
  }
  const deployedMaskedHash = bytes32(raw.deployedMaskedHash, "deployedMaskedHash");
  const artifactMaskedHash = bytes32(raw.artifactMaskedHash, "artifactMaskedHash");
  if (deployedMaskedHash !== artifactMaskedHash) {
    fail("PROOF_MASKED", "The deployed masked bytecode is not the reviewed artifact");
  }
  const immutables = object(raw.immutables, "PROOF_IMMUTABLES", "deployment proof immutables");
  const actual = Object.keys(immutables).sort();
  const wanted = [...IMMUTABLE_FIELDS].sort();
  if (actual.length !== wanted.length || !actual.every((key, index) => key === wanted[index])) {
    fail("PROOF_IMMUTABLES", "The deployment proof immutables are not exact");
  }
  if (typeof raw.runId !== "string" || raw.runId === "") fail("PROOF_RUN", "The deployment proof names no run");

  return Object.freeze({
    schemaVersion: CASE_ADAPTER_DEPLOYMENT_PROOF_SCHEMA,
    runId: raw.runId,
    address: address(raw.address, "address"),
    transactionHash: bytes32(raw.transactionHash, "transactionHash"),
    blockNumber: whole(raw.blockNumber, "blockNumber"),
    runtimeBytes: whole(raw.runtimeBytes, "runtimeBytes"),
    deployedCodeHash: bytes32(raw.deployedCodeHash, "deployedCodeHash"),
    deployedMaskedHash,
    artifactMaskedHash,
    immutableSpansMasked: whole(raw.immutableSpansMasked, "immutableSpansMasked"),
    immutables: Object.freeze({
      settlementToken: address(immutables.settlementToken, "immutables.settlementToken"),
      cviVerifier: address(immutables.cviVerifier, "immutables.cviVerifier"),
      attestor: address(immutables.attestor, "immutables.attestor"),
      facility: address(immutables.facility, "immutables.facility"),
      owner: address(immutables.owner, "immutables.owner"),
      assetIdentityDigest: bytes32(immutables.assetIdentityDigest, "immutables.assetIdentityDigest"),
      expectedGovernedReleaseAuthorityId: bytes32(
        immutables.expectedGovernedReleaseAuthorityId, "immutables.expectedGovernedReleaseAuthorityId",
      ),
      releaseMode: bytes32(immutables.releaseMode, "immutables.releaseMode"),
      circuitHash: bytes32(immutables.circuitHash, "immutables.circuitHash"),
      parameterFingerprint: bytes32(immutables.parameterFingerprint, "immutables.parameterFingerprint"),
      cureWindow: whole(immutables.cureWindow, "immutables.cureWindow"),
    }),
  });
}

/** Where a case-specific deployment proof is retained, per adapter address. */
export const CASE_ADAPTER_PROOF_DIRECTORY = join("docs", "evidence");

/**
 * Loads the retained deployment proof for exactly this adapter and run.
 *
 * A proof for another adapter is not a weaker proof, it is the wrong proof, so a
 * mismatched address or run is refused by name rather than falling through to a
 * digest comparison that would happen to differ.
 */
export function loadCaseAdapterDeploymentProof(
  adapterAddress: string,
  runId: string,
  root: string = process.cwd(),
  fileName = "activation-case-adapter-deployment-2026-08-07.json",
): CaseAdapterDeploymentProof {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(root, CASE_ADAPTER_PROOF_DIRECTORY, fileName), "utf8")) as unknown;
  } catch {
    fail("PROOF_MISSING", "No retained deployment proof was found for this case adapter");
  }
  const proof = parseCaseAdapterDeploymentProof(raw);
  if (proof.address.toLowerCase() !== adapterAddress.toLowerCase()) {
    fail("PROOF_ADDRESS", "The retained deployment proof is for a different adapter address");
  }
  if (proof.runId !== runId) fail("PROOF_RUN", "The retained deployment proof is for a different run");
  // Ownership can still withdraw unreserved reserve, so the case deployment must
  // name the same owner the reviewed V2 deployment did. A proof is committed
  // material, but it may not introduce a new privileged account.
  let reviewed: unknown;
  try {
    reviewed = JSON.parse(readFileSync(
      join(root, CASE_ADAPTER_PROOF_DIRECTORY, "recourse-adapter-v2-deployment-2026-08-06.json"), "utf8",
    )) as unknown;
  } catch {
    fail("REVIEWED_MISSING", "The reviewed V2 deployment evidence could not be read");
  }
  const reviewedOwner = address(
    object(object(reviewed, "REVIEWED_SHAPE", "reviewed deployment").immutables, "REVIEWED_SHAPE", "reviewed immutables").owner,
    "reviewed immutables.owner",
  );
  if (proof.immutables.owner.toLowerCase() !== reviewedOwner.toLowerCase()) {
    fail("PROOF_OWNER", "The case adapter names an owner the reviewed deployment does not");
  }
  return proof;
}
