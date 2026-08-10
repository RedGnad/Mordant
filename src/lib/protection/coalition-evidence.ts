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

/** One operator's signature over the statement it verified for itself. */
export type CoalitionSettlementAttestation = Readonly<{
  point: number;
  signature: string;
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
  settlementAttestations: readonly CoalitionSettlementAttestation[];
  policyId: string;
  serviceId: string;
  [field: string]: unknown;
}>;

const SETTLEMENT_STATEMENT_SCHEMA = "mordant.coalition-settlement-statement/1" as const;
const SETTLEMENT_STATEMENT_DOMAIN = "MordantCoalitionSettlementStatement/v1" as const;

/**
 * Rebuilds the exact statement one operator signed, in Go's field order.
 *
 * Every field is read from the result, so editing any of them here moves the
 * message and breaks every signature over it. That is the whole binding: an
 * operator's release share is generated before the bits exist and cannot attest
 * them, so this statement is the only thing tying a published key to a value.
 */
function settlementStatementMessage(result: CoalitionConflictResult, point: number): Buffer {
  const statement = {
    schemaVersion: SETTLEMENT_STATEMENT_SCHEMA,
    caseId: result.caseId,
    caseBindingDigest: result.caseBindingDigest,
    assetIdentity: result.assetIdentity,
    releaseAuthorityId: result.releaseAuthorityId,
    releaseMode: result.releaseMode,
    releaseTranscript: result.releaseTranscript,
    coalition: [...result.coalition],
    threshold: result.threshold,
    sameEconomicAsset: result.sameEconomicAsset,
    policyConflict: result.policyConflict,
    point,
  };
  return Buffer.concat([
    Buffer.from(SETTLEMENT_STATEMENT_DOMAIN),
    Buffer.of(0),
    Buffer.from(JSON.stringify(statement)),
  ]);
}

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
 * **The binding to this release.** A release share is generated before any bit
 * exists, so nothing signed during the release can attest what the bits turned
 * out to be. Each serving operator therefore recombines both bits for itself
 * after the release and signs a settlement statement naming this case, this
 * release identity, this transcript and those two bits. This verifier rebuilds
 * that statement from the result and checks a quorum of those signatures, so a
 * result edited after production fails here even when every signature it carries
 * is authentic.
 *
 * **What this still does not establish.** The threshold statement digests are
 * not recomputed here, which would mean reimplementing the threshold encoding in
 * a second language. They are checked by the combiner in the release path. The
 * settlement statements above are what carry the binding downstream.
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

  // The binding. Each serving operator signed a statement naming this case, this
  // release and these two bits, and it signed only after recombining the bits
  // itself. Rebuilding that statement here and checking the signatures is what
  // makes an edited result detectable: change a bit, the case, the release
  // identity or the transcript and every signature over it fails, however
  // authentic the signatures themselves are.
  const confirmed = new Set<number>();
  for (const attestation of result.settlementAttestations ?? []) {
    if (!serving.has(attestation.point)) {
      fail("SETTLEMENT_ATTRIBUTION", "a settlement attestation names an operator outside the serving coalition");
    }
    if (confirmed.has(attestation.point)) {
      fail("SETTLEMENT_REPLAY", "one operator confirmed the release twice");
    }
    const publicKey = keyByPoint.get(attestation.point);
    if (publicKey === undefined) fail("SETTLEMENT_ATTRIBUTION", "a settlement attestation names an unpublished operator");
    const signature = Buffer.from(attestation.signature, "base64");
    if (signature.length !== 64 || signature.toString("base64") !== attestation.signature) {
      fail("SETTLEMENT_ENCODING", "a settlement attestation signature is not canonical");
    }
    if (!verify(null, settlementStatementMessage(result, attestation.point), ed25519PublicKey(publicKey), signature)) {
      fail(
        "SETTLEMENT_SIGNATURE",
        `operator ${attestation.point} did not confirm this case, this release and these released bits`,
      );
    }
    confirmed.add(attestation.point);
  }
  if (confirmed.size < result.threshold) {
    fail(
      "SETTLEMENT_QUORUM",
      `only ${confirmed.size} of the required ${result.threshold} operators confirmed the released bits`,
    );
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
