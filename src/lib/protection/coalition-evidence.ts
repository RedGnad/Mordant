import { createHash } from "node:crypto";
import { verify } from "node:crypto";

import type { GovernedResultFacts } from "./settlement-authority";

/**
 * The settlement authority's view of a coalition release.
 *
 * A governed case is settled against one Ed25519 release authority, and
 * `verifyGovernedResultSignature` checks that one signature. A coalition case has
 * no such key: its release identity is the digest of the threshold manifest that
 * publishes the operator set and the quorum, and its evidence is a quorum of
 * operator statements rather than a single signature.
 *
 * This module turns that evidence into the same {@link GovernedResultFacts} the
 * governed path produces, so `deriveSettlementPlan` is unchanged and economics
 * still come only from the pre-committed profile.
 *
 * What this verifier establishes, and what it does not, is stated in
 * {@link verifyCoalitionEvidence}.
 */

const COALITION_RESULT_SCHEMA = "mordant.coalition-conflict-result/1" as const;
const COALITION_MANIFEST_SCHEMA = "mordant.fhe-coalition-threshold-manifest/1" as const;
const MINIMUM_QUORUM = 2;

const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const BYTES32_HEX = /^0x[0-9a-f]{64}$/u;
const SIGNATURE_HEX = /^0x[0-9a-f]{128}$/u;

export class CoalitionEvidenceError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CoalitionEvidenceError";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new CoalitionEvidenceError(code, message);
}

export type ThresholdOperatorRecord = Readonly<{
  operatorId: string;
  point: number;
  signingPublicKey: string;
}>;

export type CoalitionThresholdManifest = Readonly<{
  schemaVersion: typeof COALITION_MANIFEST_SCHEMA;
  caseId: string;
  keyId: string;
  parameterFingerprint: string;
  threshold: number;
  operators: readonly ThresholdOperatorRecord[];
  operatorTopology: string;
}>;

export type CoalitionOperatorStatement = Readonly<{
  point: number;
  slot: number;
  statementDigest: string;
  signature: string;
}>;

export type CoalitionConflictResult = Readonly<{
  schemaVersion: typeof COALITION_RESULT_SCHEMA;
  caseId: string;
  caseBindingDigest: string;
  assetIdentity: string;
  sameEconomicAsset: boolean;
  policyConflict: boolean;
  releaseMode: string;
  releaseAuthorityId: string;
  threshold: number;
  coalition: readonly number[];
  operatorTopology: string;
  operatorStatements: readonly CoalitionOperatorStatement[];
  releaseTranscript: string;
  [field: string]: unknown;
}>;

export type VerifiedCoalitionEvidence = Readonly<{
  facts: GovernedResultFacts;
  /** The digest of the threshold manifest. This is the release identity. */
  coalitionAuthorityId: string;
  servingQuorum: number;
  operatorTopology: string;
  /** Reported as released, never combined into a single decision here. */
  sameEconomicAsset: boolean;
  policyConflict: boolean;
}>;

/**
 * Recomputes the manifest digest exactly as Go does: sha256 over the canonical
 * JSON of the struct, fields in declaration order.
 */
function thresholdManifestDigest(manifest: CoalitionThresholdManifest): string {
  const canonical = JSON.stringify({
    schemaVersion: manifest.schemaVersion,
    caseId: manifest.caseId,
    keyId: manifest.keyId,
    parameterFingerprint: manifest.parameterFingerprint,
    threshold: manifest.threshold,
    operators: manifest.operators.map((operator) => ({
      operatorId: operator.operatorId,
      point: operator.point,
      signingPublicKey: operator.signingPublicKey,
    })),
    operatorTopology: manifest.operatorTopology,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function ed25519PublicKey(base64: string) {
  const raw = Buffer.from(base64, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== base64) {
    fail("OPERATOR_KEY", "an operator signing key is not a canonical Ed25519 public key");
  }
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return { key: der, format: "der" as const, type: "spki" as const };
}

function assertManifest(manifest: CoalitionThresholdManifest): void {
  if (manifest.schemaVersion !== COALITION_MANIFEST_SCHEMA) {
    fail("MANIFEST_SCHEMA", "unsupported threshold manifest schema");
  }
  if (!SHA256_DIGEST.test(manifest.caseId) || !SHA256_DIGEST.test(manifest.keyId)) {
    fail("MANIFEST_FIELDS", "the threshold manifest carries a malformed case or key digest");
  }
  if (!Number.isInteger(manifest.threshold) || manifest.threshold < MINIMUM_QUORUM) {
    fail("MANIFEST_THRESHOLD", "a coalition whose quorum is below two is not a coalition");
  }
  if (!Array.isArray(manifest.operators) || manifest.operators.length < manifest.threshold) {
    fail("MANIFEST_OPERATORS", "the manifest publishes fewer operators than its own quorum");
  }
  const points = new Set<number>();
  for (const operator of manifest.operators) {
    if (!Number.isInteger(operator.point) || operator.point <= 0) {
      fail("MANIFEST_OPERATORS", "an operator record carries a malformed point");
    }
    if (points.has(operator.point)) fail("MANIFEST_OPERATORS", "two operator records share a point");
    points.add(operator.point);
    ed25519PublicKey(operator.signingPublicKey);
  }
}

/**
 * Verifies a coalition release and returns the facts the settlement plan reads.
 *
 * **What this establishes.** The release identity is recomputed from the
 * published threshold manifest rather than taken from the result, so a result
 * naming an authority no manifest digests to is refused. The serving coalition
 * is the manifest's own operator set, at or above the manifest's quorum, with no
 * repeated point. Every operator statement carries an Ed25519 signature that
 * verifies against the key the manifest publishes for that operator's point, so
 * a statement attributed to an operator that did not sign it is refused. The two
 * released bits are present, and the combination the circuit cannot produce is
 * refused.
 *
 * **What this does not establish.** The binding of each operator statement to
 * *this* release is not re-derived here. An operator signs the digest of a
 * statement built from the threshold descriptor it recomputed, and that binding
 * is checked in the release path, by the combiner, before any result exists.
 * Re-deriving it in TypeScript would mean reimplementing the threshold
 * encoding in a second language, and a second implementation that drifts is
 * worse than one that is trusted for a stated reason. So this verifier proves
 * the quorum is authentic and the identity is the manifest's; it relies on the
 * release path for the statements being about this release.
 */
export function verifyCoalitionEvidence(
  result: CoalitionConflictResult,
  manifest: CoalitionThresholdManifest,
  resultDigest: string,
  runId: string,
): VerifiedCoalitionEvidence {
  if (result.schemaVersion !== COALITION_RESULT_SCHEMA) {
    fail("RESULT_SCHEMA", "unsupported coalition result schema");
  }
  assertManifest(manifest);

  // The identity is derived, never read. A result claiming an authority that no
  // published manifest digests to settles nothing.
  const authority = thresholdManifestDigest(manifest);
  if (authority !== result.releaseAuthorityId) {
    fail(
      "AUTHORITY_NOT_DERIVED",
      "the coalition result names a release authority that is not this threshold manifest's digest",
    );
  }
  if (manifest.caseId !== result.caseId) {
    fail("MANIFEST_CASE", "the threshold manifest describes a different case than the result");
  }

  if (result.threshold !== manifest.threshold) {
    fail("QUORUM_MISMATCH", "the result claims a quorum the manifest does not require");
  }
  if (!Array.isArray(result.coalition) || result.coalition.length !== result.threshold) {
    fail("QUORUM_SIZE", "the serving coalition is not the size the quorum requires");
  }
  const serving = new Set<number>();
  const keyByPoint = new Map(manifest.operators.map((operator) => [operator.point, operator.signingPublicKey]));
  for (const point of result.coalition) {
    if (!keyByPoint.has(point)) fail("QUORUM_MEMBERSHIP", "an operator served that the manifest does not publish");
    if (serving.has(point)) fail("QUORUM_MEMBERSHIP", "one operator was counted twice toward the quorum");
    serving.add(point);
  }

  // Every released bit must be attested by every serving operator, and every
  // attestation must verify against that operator's published key.
  const attested = new Map<number, Set<number>>();
  for (const statement of result.operatorStatements) {
    if (!BYTES32_HEX.test(statement.statementDigest) || !SIGNATURE_HEX.test(statement.signature)) {
      fail("STATEMENT_ENCODING", "an operator statement is malformed");
    }
    if (!serving.has(statement.point)) {
      fail("STATEMENT_ATTRIBUTION", "a statement is attributed to an operator outside the serving coalition");
    }
    const publicKey = keyByPoint.get(statement.point);
    if (publicKey === undefined) fail("STATEMENT_ATTRIBUTION", "a statement names an unpublished operator");
    const digest = Buffer.from(statement.statementDigest.slice(2), "hex");
    const signature = Buffer.from(statement.signature.slice(2), "hex");
    if (!verify(null, digest, ed25519PublicKey(publicKey), signature)) {
      fail("STATEMENT_SIGNATURE", `operator ${statement.point} did not sign the statement attributed to it`);
    }
    const slots = attested.get(statement.point) ?? new Set<number>();
    if (slots.has(statement.slot)) fail("STATEMENT_REPLAY", "one operator attested the same released bit twice");
    slots.add(statement.slot);
    attested.set(statement.point, slots);
  }
  for (const point of serving) {
    const slots = attested.get(point);
    if (slots === undefined || !slots.has(0) || !slots.has(1)) {
      fail("STATEMENT_COVERAGE", `operator ${point} did not attest both released bits`);
    }
  }

  // H-02. The policy conjunction has identity equality as a factor, so this
  // combination cannot have come from the circuit. The asset bit is an integrity
  // constraint here, and it never becomes an economic input.
  if (result.policyConflict && !result.sameEconomicAsset) {
    fail("NON_CANONICAL_DECISION", "a policy conflict without an asset match cannot have come from the circuit");
  }

  return Object.freeze({
    facts: Object.freeze({
      governedResultDigest: resultDigest as GovernedResultFacts["governedResultDigest"],
      runId: runId as GovernedResultFacts["runId"],
      releaseAuthorityId: authority,
      // Only the policy decision reaches the plan. The asset bit stays evidence.
      conflict: result.policyConflict,
      caseId: result.caseId,
      caseBindingDigest: result.caseBindingDigest,
    }),
    coalitionAuthorityId: authority,
    servingQuorum: result.threshold,
    operatorTopology: result.operatorTopology,
    sameEconomicAsset: result.sameEconomicAsset,
    policyConflict: result.policyConflict,
  });
}
