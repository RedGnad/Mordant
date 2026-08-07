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

import { readFileSync, readdirSync } from "node:fs";
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

/**
 * The identity a retained file CLAIMS, read from its parsed contents.
 *
 * Claiming is decided BEFORE strict parsing, and that ordering is the whole
 * point: a file that names the requested adapter and run is a claimant even when
 * it is otherwise malformed, so a broken proof can never be quietly stepped over
 * in favour of some other file. Nothing here judges validity; the strict parser
 * keeps that job.
 */
function claimedIdentity(raw: unknown): Readonly<{ address: string; runId: string }> | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  if (record.schemaVersion !== CASE_ADAPTER_DEPLOYMENT_PROOF_SCHEMA) return null;
  if (typeof record.address !== "string" || typeof record.runId !== "string") return null;
  return Object.freeze({ address: record.address, runId: record.runId });
}

/**
 * Names the ONE retained file whose contents claim exactly this adapter address
 * and this run.
 *
 * Selection is by claimed CONTENT alone. There is deliberately no fixed name, no
 * newest-file or mtime tie-break, and no reading of the file name's text: each of
 * those would let a file that is merely present, merely recent, or merely
 * well-named stand in for the proof of the deployment actually being settled,
 * which is the substitution this resolver exists to refuse.
 *
 * Zero claimants and more than one claimant are both refusals. The first has no
 * proof at all; the second has no unambiguous one, and picking between them is
 * precisely the judgement that must not be made here.
 */
export function resolveCaseAdapterDeploymentProofFile(
  adapterAddress: string,
  runId: string,
  root: string = process.cwd(),
): string {
  if (typeof adapterAddress !== "string" || !/^0x[0-9a-fA-F]{40}$/u.test(adapterAddress)) {
    fail("PROOF_ADDRESS", "A deployment proof can only be resolved for a well-formed adapter address");
  }
  if (typeof runId !== "string" || runId === "") {
    fail("PROOF_RUN", "A deployment proof can only be resolved for a named run");
  }
  const directory = join(root, CASE_ADAPTER_PROOF_DIRECTORY);
  let entries: readonly string[];
  try {
    // Regular files only, so a symlink cannot point the resolver outside the
    // retained evidence directory. Sorted for a stable refusal message, never as
    // a way to prefer one claimant over another.
    entries = readdirSync(directory, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
      .map((entry) => entry.name)
      .sort();
  } catch {
    fail("PROOF_DIRECTORY", "The retained deployment proof directory could not be read");
  }
  const wantedAddress = adapterAddress.toLowerCase();
  const claimants: string[] = [];
  for (const name of entries) {
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(join(directory, name), "utf8")) as unknown;
    } catch {
      // Unreadable or non-JSON evidence claims nothing. It cannot be this proof,
      // and it cannot suppress the real one either.
      continue;
    }
    const claimed = claimedIdentity(raw);
    if (claimed === null) continue;
    if (claimed.address.toLowerCase() !== wantedAddress || claimed.runId !== runId) continue;
    claimants.push(name);
  }
  if (claimants.length === 0) {
    fail("PROOF_UNRESOLVED", "No retained deployment proof names this adapter address and this run");
  }
  if (claimants.length > 1) {
    fail(
      "PROOF_AMBIGUOUS",
      `More than one retained deployment proof names this adapter address and this run: ${claimants.join(", ")}`,
    );
  }
  return claimants[0];
}

/**
 * Loads the retained deployment proof for this adapter and run without being
 * told which file holds it.
 *
 * Resolution only chooses the file. Everything that decides whether a proof is
 * acceptable stays in `loadCaseAdapterDeploymentProof`, which re-reads and
 * re-checks the resolved file, so the strict parser and every F-04 check remain
 * the authority over what is returned here.
 */
export function loadCaseAdapterDeploymentProofForRun(
  adapterAddress: string,
  runId: string,
  root: string = process.cwd(),
): CaseAdapterDeploymentProof {
  return loadCaseAdapterDeploymentProof(
    adapterAddress,
    runId,
    root,
    resolveCaseAdapterDeploymentProofFile(adapterAddress, runId, root),
  );
}
