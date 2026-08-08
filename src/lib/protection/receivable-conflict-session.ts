import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";

import {
  CANONICAL_CLEANVERSE_ASSET_DIGEST,
  type Sha256Digest,
} from "./cleanverse-asset";
import {
  EXPECTED_GOVERNED_FHE_COMMIT,
  assertReleaseAuthorityIdentity,
  governedResultDigest,
  verifyGovernedResultSignature,
  type FheCaseBinding,
  type GovernedSignedResult,
} from "./protection-evidence";
import {
  FHE_CIRCUIT,
  FHE_PARAMETER_PROFILE,
  GOVERNED_RELEASE_MODE,
  protectionPolicyId,
} from "./protection-case";

export const GRAPH_CLAIM_AUTHORIZATION_SCHEMA = "mordant.graph-claim-authorization/1" as const;
export const GRAPH_PRIVATE_CLAIM_SCHEMA = "mordant.graph-private-claim/1" as const;
export const GRAPH_RETAINED_PRIVATE_CLAIM_SCHEMA = "mordant.graph-private-claim-retained/1" as const;
export const GRAPH_PAIR_INTENT_SCHEMA = "mordant.graph-pair-intent/1" as const;
export const GRAPH_PAIR_BINDING_SCHEMA = "mordant.graph-pair-binding/1" as const;
export const GRAPH_PAIR_EVIDENCE_SCHEMA = "mordant.graph-pair-evidence/1" as const;
export const GRAPH_AGGREGATE_SCHEMA = "mordant.receivable-conflict-aggregate/1" as const;
export const GRAPH_CHRONOLOGY_SCHEMA = "mordant.receivable-conflict-chronology/1" as const;
export const GRAPH_PROJECTIONS_SCHEMA = "mordant.receivable-conflict-projections/1" as const;

export const N3_EXPECTED_CLAIM_COUNT = 3 as const;
export const N3_EXPECTED_PAIR_COUNT = 3 as const;
export const N3_STARTING_COMMIT = "9ea6652dbf61c6227e3a21183e628a7356b6df18" as const;
export const EXPECTED_CIRCUIT_DIGEST =
  "sha256:2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e" as const;
export const EXPECTED_PARAMETER_FINGERPRINT =
  "sha256:d0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6" as const;

const CLAIM_COMMITMENT_DOMAIN = "MordantGraphClaimCommitment/v1";
const CLAIM_AUTHORIZATION_DOMAIN = "MordantGraphClaimAuthorization/v1";
const CLAIM_NODE_DIGEST_DOMAIN = "MordantGraphClaimNode/v1";
const PAIR_ID_DOMAIN = "MordantGraphClaimPair/v1";
const PAIR_INTENT_AUTHORIZATION_DOMAIN = "MordantGraphPairIntentAuthorization/v1";
const PAIR_INTENT_DIGEST_DOMAIN = "MordantGraphPairIntent/v1";
const PAIR_BINDING_AUTHORIZATION_DOMAIN = "MordantGraphPairBindingAuthorization/v1";
const PAIR_BINDING_DIGEST_DOMAIN = "MordantGraphPairBinding/v1";
const PAIR_EVIDENCE_DIGEST_DOMAIN = "MordantGraphPairEvidence/v1";
const PAIR_INSPECTION_DIGEST_DOMAIN = "MordantGraphPairPublicInspection/v1";
const PAIR_INSPECTION_REPORT_DIGEST_DOMAIN = "MordantGraphPairPublicInspectionReport/v1";
const CHRONOLOGY_DIGEST_DOMAIN = "MordantGraphChronology/v1";
const AGGREGATE_ROOT_DOMAIN = "MordantReceivableConflictAggregate/v1";

export type GraphClaimId = Sha256Digest;
export type PairRole = "PARTICIPANT_A" | "PARTICIPANT_B";
export type PairExecutionState =
  | "CONFLICT"
  | "NO_CONFLICT_UNDER_POLICY"
  | "PENDING"
  | "FAILED"
  | "EXPIRED";
export type GraphCompleteness = "COMPLETE" | "PARTIAL";
export type GraphReviewState = "REVIEW_READY" | "AWAITING_EVIDENCE";

export class ConflictGraphError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = "ConflictGraphError";
  }
}

function fail(code: string, message: string): never {
  throw new ConflictGraphError(code, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function assertExactKeys(value: unknown, expected: readonly string[], code: string): asserts value is Record<string, unknown> {
  if (!isRecord(value)) fail(code, "Plain JSON object required");
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    fail(code, "Unexpected or missing fields");
  }
}

function assertExactArray(value: unknown, length: number, code: string): asserts value is unknown[] {
  if (!Array.isArray(value) || value.length !== length) fail(code, `Exactly ${length} entries required`);
}

function assertCanonicalPair(value: unknown, code: string): asserts value is CanonicalClaimPair {
  assertExactKeys(value, ["leftClaimId", "rightClaimId", "pairId"], code);
  const pair = value as CanonicalClaimPair;
  const expected = canonicalClaimPair(pair.leftClaimId, pair.rightClaimId);
  if (canonicalGraphJson(pair) !== canonicalGraphJson(expected)) fail(code, "Canonical pair mismatch");
}

function assertCanonicalBase64(value: unknown, code: string, exactBytes?: number): Buffer {
  if (typeof value !== "string" || value.length === 0) fail(code, "Canonical base64 required");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (exactBytes !== undefined && bytes.length !== exactBytes)) {
    fail(code, "Canonical base64 length mismatch");
  }
  return bytes;
}

function assertIsoTime(value: unknown, code: string): number {
  if (typeof value !== "string") fail(code, "Canonical UTC timestamp required");
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) fail(code, "Canonical UTC timestamp required");
  return parsed;
}

function assertNoUnpairedSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) fail("CANONICAL_STRING", "Unpaired surrogate rejected");
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail("CANONICAL_STRING", "Unpaired surrogate rejected");
    }
  }
}

/** Deterministic JSON for the deliberately small, plain acyclic graph schemas. */
export function canonicalGraphJson(value: unknown): string {
  return canonicalGraphJsonInner(value, new Set<object>());
}

function canonicalGraphJsonInner(value: unknown, ancestors: Set<object>): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string") assertNoUnpairedSurrogates(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("CANONICAL_NUMBER", "Non-finite number rejected");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) fail("CANONICAL_CYCLE", "Cyclic value rejected");
    ancestors.add(value);
    const rendered = `[${value.map((entry) => canonicalGraphJsonInner(entry, ancestors)).join(",")}]`;
    ancestors.delete(value);
    return rendered;
  }
  if (isRecord(value)) {
    if (ancestors.has(value)) fail("CANONICAL_CYCLE", "Cyclic value rejected");
    ancestors.add(value);
    const rendered = `{${Object.keys(value).sort().map((key) => {
      assertNoUnpairedSurrogates(key);
      const entry = value[key];
      if (entry === undefined) fail("CANONICAL_UNDEFINED", `Undefined field ${key}`);
      return `${JSON.stringify(key)}:${canonicalGraphJsonInner(entry, ancestors)}`;
    }).join(",")}}`;
    ancestors.delete(value);
    return rendered;
  }
  fail("CANONICAL_TYPE", `Unsupported canonical value ${typeof value}`);
}

export function sha256Bytes(value: string | Buffer): Sha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}` as Sha256Digest;
}

export function graphDigest(domain: string, value: unknown): Sha256Digest {
  if (domain.length === 0) fail("DIGEST_DOMAIN", "Digest domain is required");
  return sha256Bytes(Buffer.concat([
    Buffer.from(domain, "utf8"),
    Buffer.of(0),
    Buffer.from(canonicalGraphJson(value), "utf8"),
  ]));
}

function isSha256(value: unknown): value is Sha256Digest {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
}

function assertSha256(value: unknown, code: string): asserts value is Sha256Digest {
  if (!isSha256(value) || /^sha256:0{64}$/u.test(value)) fail(code, "Non-zero SHA-256 digest required");
}

function assertGitCommit(value: string, code: string): void {
  if (!/^[0-9a-f]{40}$/u.test(value) || /^0{40}$/u.test(value)) fail(code, "Full non-zero Git commit required");
}

function signingMessage(domain: string, value: unknown): Buffer {
  return Buffer.concat([
    Buffer.from(domain, "utf8"),
    Buffer.of(0),
    Buffer.from(canonicalGraphJson(value), "utf8"),
  ]);
}

function signGraphValue(privateKeyPkcs8: string, domain: string, value: unknown): string {
  const keyBytes = assertCanonicalBase64(privateKeyPkcs8, "GRAPH_PRIVATE_KEY", 48);
  const key = createPrivateKey({ key: keyBytes, format: "der", type: "pkcs8" });
  if (key.asymmetricKeyType !== "ed25519"
    || !Buffer.from(key.export({ format: "der", type: "pkcs8" })).equals(keyBytes)) {
    fail("GRAPH_PRIVATE_KEY", "Canonical Ed25519 private key required");
  }
  return sign(null, signingMessage(domain, value), key).toString("base64");
}

function verifyGraphValue(publicKeySpki: string, domain: string, value: unknown, signature: string, code: string): void {
  let keyBytes: Buffer;
  let signatureBytes: Buffer;
  try {
    keyBytes = assertCanonicalBase64(publicKeySpki, code, 44);
    signatureBytes = assertCanonicalBase64(signature, code, 64);
    const key = createPublicKey({ key: keyBytes, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519"
      || !Buffer.from(key.export({ format: "der", type: "spki" })).equals(keyBytes)) {
      fail(code, "Canonical Ed25519 authorization key required");
    }
    if (!verify(null, signingMessage(domain, value), key, signatureBytes)) {
      fail(code, "Signature verification failed");
    }
  } catch (error) {
    if (error instanceof ConflictGraphError) throw error;
    fail(code, "Invalid Ed25519 authorization key or signature");
  }
}

export type GraphPrivateClaimOpening = Readonly<{
  activeFrom: number;
  activeUntil: number;
  currency: "aUSDC";
  exclusive: true;
  salt: string;
}>;

export type GraphClaimAuthorization = Readonly<{
  schemaVersion: typeof GRAPH_CLAIM_AUTHORIZATION_SCHEMA;
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  claimId: GraphClaimId;
  claimVersion: number;
  participantRef: Sha256Digest;
  claimCommitment: Sha256Digest;
  authorizationPublicKey: string;
  issuedAtUnix: number;
  expiresAtUnix: number;
  authorizationDigest: Sha256Digest;
  signature: string;
}>;

export type GraphPrivateClaimRecord = Readonly<{
  schemaVersion: typeof GRAPH_PRIVATE_CLAIM_SCHEMA;
  authorization: GraphClaimAuthorization;
  opening: GraphPrivateClaimOpening;
  authorizationPrivateKey: string;
  retention: Readonly<{
    scope: "OPERATOR_PRIVATE";
    exactIntervalsRetained: true;
    saltRetained: true;
    authorizationPrivateKeyRetained: false;
    authorizationPrivateKeyLifetime: "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED";
    authorizationPrivateKeyZeroizationClaimed: false;
    authorizationPrivateKeyGarbageCollectionTimingClaimed: false;
    automaticTerminalDeletion: false;
    secureErasureClaimed: false;
    deletionTrigger: "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY";
  }>;
}>;

export type RetainedGraphPrivateClaimRecord = Readonly<{
  schemaVersion: typeof GRAPH_RETAINED_PRIVATE_CLAIM_SCHEMA;
  authorization: GraphClaimAuthorization;
  opening: GraphPrivateClaimOpening;
  retention: GraphPrivateClaimRecord["retention"];
}>;

export type CreateGraphClaimOptions = Readonly<{
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  participantRef: Sha256Digest;
  activeFrom: number;
  activeUntil: number;
  issuedAtUnix: number;
  expiresAtUnix: number;
  claimVersion?: number;
}>;

function claimCommitmentValue(
  authorization: Pick<GraphClaimAuthorization,
    "graphSessionId" | "receivableIdentity" | "claimId" | "claimVersion" | "participantRef" |
    "issuedAtUnix" | "expiresAtUnix">,
  opening: GraphPrivateClaimOpening,
): object {
  return {
    graphSessionId: authorization.graphSessionId,
    receivableIdentity: authorization.receivableIdentity,
    claimId: authorization.claimId,
    claimVersion: authorization.claimVersion,
    participantRef: authorization.participantRef,
    activeFrom: opening.activeFrom,
    activeUntil: opening.activeUntil,
    currency: opening.currency,
    exclusive: opening.exclusive,
    salt: opening.salt,
    issuedAtUnix: authorization.issuedAtUnix,
    expiresAtUnix: authorization.expiresAtUnix,
  };
}

function claimAuthorizationValue(authorization: Omit<GraphClaimAuthorization, "authorizationDigest" | "signature">): object {
  return { ...authorization };
}

export function createGraphClaimAuthorization(options: CreateGraphClaimOptions): GraphPrivateClaimRecord {
  assertSha256(options.graphSessionId, "CLAIM_SESSION");
  assertSha256(options.receivableIdentity, "CLAIM_RECEIVABLE");
  assertSha256(options.participantRef, "CLAIM_PARTICIPANT");
  const claimVersion = options.claimVersion ?? 1;
  if (!Number.isSafeInteger(claimVersion) || claimVersion <= 0) fail("CLAIM_VERSION", "Positive claim version required");
  if (!Number.isSafeInteger(options.activeFrom) || !Number.isSafeInteger(options.activeUntil)
    || options.activeFrom < 0 || options.activeUntil <= options.activeFrom) {
    fail("CLAIM_INTERVAL", "A forward integer half-open interval is required");
  }
  if (!Number.isSafeInteger(options.issuedAtUnix) || !Number.isSafeInteger(options.expiresAtUnix)
    || options.issuedAtUnix <= 0 || options.expiresAtUnix <= options.issuedAtUnix) {
    fail("CLAIM_TIME", "Forward issue/expiry interval required");
  }
  const claimId = sha256Bytes(randomBytes(32));
  const salt = randomBytes(32).toString("base64");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const authorizationPrivateKey = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  const authorizationPublicKey = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const opening: GraphPrivateClaimOpening = {
    activeFrom: options.activeFrom,
    activeUntil: options.activeUntil,
    currency: "aUSDC",
    exclusive: true,
    salt,
  };
  const base = {
    schemaVersion: GRAPH_CLAIM_AUTHORIZATION_SCHEMA,
    graphSessionId: options.graphSessionId,
    receivableIdentity: options.receivableIdentity,
    claimId,
    claimVersion,
    participantRef: options.participantRef,
    authorizationPublicKey,
    issuedAtUnix: options.issuedAtUnix,
    expiresAtUnix: options.expiresAtUnix,
  } as const;
  const claimCommitment = graphDigest(CLAIM_COMMITMENT_DOMAIN, claimCommitmentValue(base, opening));
  const unsigned = { ...base, claimCommitment };
  const authorizationDigest = graphDigest(CLAIM_AUTHORIZATION_DOMAIN, claimAuthorizationValue(unsigned));
  const authorization: GraphClaimAuthorization = {
    ...unsigned,
    authorizationDigest,
    signature: signGraphValue(authorizationPrivateKey, CLAIM_AUTHORIZATION_DOMAIN, claimAuthorizationValue(unsigned)),
  };
  return {
    schemaVersion: GRAPH_PRIVATE_CLAIM_SCHEMA,
    authorization,
    opening,
    authorizationPrivateKey,
    retention: {
      scope: "OPERATOR_PRIVATE",
      exactIntervalsRetained: true,
      saltRetained: true,
      authorizationPrivateKeyRetained: false,
      authorizationPrivateKeyLifetime: "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
      authorizationPrivateKeyZeroizationClaimed: false,
      authorizationPrivateKeyGarbageCollectionTimingClaimed: false,
      automaticTerminalDeletion: false,
      secureErasureClaimed: false,
      deletionTrigger: "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY",
    },
  };
}

export function graphClaimNodeDigest(node: GraphClaimAuthorization): Sha256Digest {
  verifyGraphClaimAuthorization(node);
  return graphDigest(CLAIM_NODE_DIGEST_DOMAIN, node);
}

export function verifyGraphClaimAuthorization(node: GraphClaimAuthorization): void {
  assertExactKeys(node, [
    "schemaVersion", "graphSessionId", "receivableIdentity", "claimId", "claimVersion", "participantRef",
    "claimCommitment", "authorizationPublicKey", "issuedAtUnix", "expiresAtUnix", "authorizationDigest", "signature",
  ], "CLAIM_FIELDS");
  if (node.schemaVersion !== GRAPH_CLAIM_AUTHORIZATION_SCHEMA) fail("CLAIM_SCHEMA", "Unknown graph claim schema");
  assertSha256(node.graphSessionId, "CLAIM_SESSION");
  assertSha256(node.receivableIdentity, "CLAIM_RECEIVABLE");
  assertSha256(node.claimId, "CLAIM_ID");
  assertSha256(node.participantRef, "CLAIM_PARTICIPANT");
  assertSha256(node.claimCommitment, "CLAIM_COMMITMENT");
  if (!Number.isSafeInteger(node.claimVersion) || node.claimVersion <= 0) fail("CLAIM_VERSION", "Invalid claim version");
  if (!Number.isSafeInteger(node.issuedAtUnix) || !Number.isSafeInteger(node.expiresAtUnix)
    || node.issuedAtUnix <= 0 || node.expiresAtUnix <= node.issuedAtUnix) fail("CLAIM_TIME", "Invalid claim lifetime");
  const unsigned = {
    schemaVersion: node.schemaVersion,
    graphSessionId: node.graphSessionId,
    receivableIdentity: node.receivableIdentity,
    claimId: node.claimId,
    claimVersion: node.claimVersion,
    participantRef: node.participantRef,
    claimCommitment: node.claimCommitment,
    authorizationPublicKey: node.authorizationPublicKey,
    issuedAtUnix: node.issuedAtUnix,
    expiresAtUnix: node.expiresAtUnix,
  } as const;
  const digest = graphDigest(CLAIM_AUTHORIZATION_DOMAIN, claimAuthorizationValue(unsigned));
  if (digest !== node.authorizationDigest) fail("CLAIM_AUTHORIZATION_DIGEST", "Claim authorization digest mismatch");
  verifyGraphValue(node.authorizationPublicKey, CLAIM_AUTHORIZATION_DOMAIN, claimAuthorizationValue(unsigned), node.signature, "CLAIM_AUTHORIZATION_SIGNATURE");
}

export function verifyGraphPrivateClaimRecord(record: GraphPrivateClaimRecord): void {
  assertExactKeys(record, ["schemaVersion", "authorization", "opening", "authorizationPrivateKey", "retention"], "PRIVATE_CLAIM_FIELDS");
  assertExactKeys(record.opening, ["activeFrom", "activeUntil", "currency", "exclusive", "salt"], "PRIVATE_CLAIM_OPENING_FIELDS");
  assertExactKeys(record.retention, [
    "scope", "exactIntervalsRetained", "saltRetained", "authorizationPrivateKeyRetained",
    "authorizationPrivateKeyLifetime", "authorizationPrivateKeyZeroizationClaimed",
    "authorizationPrivateKeyGarbageCollectionTimingClaimed", "automaticTerminalDeletion", "secureErasureClaimed",
    "deletionTrigger",
  ], "PRIVATE_CLAIM_RETENTION_FIELDS");
  if (record.schemaVersion !== GRAPH_PRIVATE_CLAIM_SCHEMA) fail("PRIVATE_CLAIM_SCHEMA", "Unknown private claim schema");
  verifyGraphClaimAuthorization(record.authorization);
  const salt = Buffer.from(record.opening.salt, "base64");
  if (salt.length !== 32 || salt.toString("base64") !== record.opening.salt || salt.every((value) => value === 0)) {
    fail("CLAIM_SALT", "A canonical non-zero 32-byte salt is required");
  }
  if (!Number.isSafeInteger(record.opening.activeFrom) || !Number.isSafeInteger(record.opening.activeUntil)
    || record.opening.activeFrom < 0 || record.opening.activeUntil <= record.opening.activeFrom
    || record.opening.currency !== "aUSDC" || record.opening.exclusive !== true) {
    fail("CLAIM_OPENING", "Private claim opening rejected");
  }
  const commitment = graphDigest(
    CLAIM_COMMITMENT_DOMAIN,
    claimCommitmentValue(record.authorization, record.opening),
  );
  if (commitment !== record.authorization.claimCommitment) fail("CLAIM_OPENING", "Claim opening does not match commitment");
  try {
    const privateKeyBytes = assertCanonicalBase64(record.authorizationPrivateKey, "CLAIM_PRIVATE_KEY", 48);
    const privateKey = createPrivateKey({
      key: privateKeyBytes,
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "ed25519"
      || !Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).equals(privateKeyBytes)) {
      fail("CLAIM_PRIVATE_KEY", "Canonical Ed25519 private key required");
    }
    const derivedPublic = createPublicKey(privateKey).export({ format: "der", type: "spki" }).toString("base64");
    if (derivedPublic !== record.authorization.authorizationPublicKey) fail("CLAIM_PRIVATE_KEY", "Claim authorization key mismatch");
  } catch (error) {
    if (error instanceof ConflictGraphError) throw error;
    fail("CLAIM_PRIVATE_KEY", "Invalid Ed25519 private key");
  }
  if (record.retention.scope !== "OPERATOR_PRIVATE" || !record.retention.exactIntervalsRetained
    || !record.retention.saltRetained || record.retention.authorizationPrivateKeyRetained
    || record.retention.authorizationPrivateKeyLifetime !== "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED"
    || record.retention.authorizationPrivateKeyZeroizationClaimed
    || record.retention.authorizationPrivateKeyGarbageCollectionTimingClaimed
    || record.retention.automaticTerminalDeletion
    || record.retention.secureErasureClaimed
    || record.retention.deletionTrigger !== "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY") {
    fail("CLAIM_RETENTION", "Private retention declaration changed");
  }
}

/** Persist the exact opening but deliberately discard the graph authorization private key. */
export function retainedGraphPrivateClaimRecord(record: GraphPrivateClaimRecord): RetainedGraphPrivateClaimRecord {
  verifyGraphPrivateClaimRecord(record);
  const retained = Object.freeze({
    schemaVersion: GRAPH_RETAINED_PRIVATE_CLAIM_SCHEMA,
    authorization: record.authorization,
    opening: record.opening,
    retention: record.retention,
  });
  verifyRetainedGraphPrivateClaimRecord(retained);
  return retained;
}

export function verifyRetainedGraphPrivateClaimRecord(record: RetainedGraphPrivateClaimRecord): void {
  assertExactKeys(record, ["schemaVersion", "authorization", "opening", "retention"], "RETAINED_PRIVATE_CLAIM_FIELDS");
  if (record.schemaVersion !== GRAPH_RETAINED_PRIVATE_CLAIM_SCHEMA) {
    fail("RETAINED_PRIVATE_CLAIM_SCHEMA", "Unknown retained private claim schema");
  }
  verifyGraphClaimAuthorization(record.authorization);
  assertExactKeys(record.opening, ["activeFrom", "activeUntil", "currency", "exclusive", "salt"], "RETAINED_PRIVATE_OPENING_FIELDS");
  assertExactKeys(record.retention, [
    "scope", "exactIntervalsRetained", "saltRetained", "authorizationPrivateKeyRetained",
    "authorizationPrivateKeyLifetime", "authorizationPrivateKeyZeroizationClaimed",
    "authorizationPrivateKeyGarbageCollectionTimingClaimed", "automaticTerminalDeletion", "secureErasureClaimed",
    "deletionTrigger",
  ], "RETAINED_PRIVATE_RETENTION_FIELDS");
  const salt = assertCanonicalBase64(record.opening.salt, "RETAINED_PRIVATE_SALT", 32);
  if (salt.every((value) => value === 0)
    || record.opening.currency !== "aUSDC" || record.opening.exclusive !== true
    || !Number.isSafeInteger(record.opening.activeFrom) || record.opening.activeFrom < 0
    || !Number.isSafeInteger(record.opening.activeUntil) || record.opening.activeUntil <= record.opening.activeFrom
    || graphDigest(CLAIM_COMMITMENT_DOMAIN, claimCommitmentValue(record.authorization, record.opening))
      !== record.authorization.claimCommitment
    || record.retention.scope !== "OPERATOR_PRIVATE" || !record.retention.exactIntervalsRetained
    || !record.retention.saltRetained || record.retention.authorizationPrivateKeyRetained
    || record.retention.authorizationPrivateKeyLifetime !== "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED"
    || record.retention.authorizationPrivateKeyZeroizationClaimed
    || record.retention.authorizationPrivateKeyGarbageCollectionTimingClaimed
    || record.retention.automaticTerminalDeletion || record.retention.secureErasureClaimed
    || record.retention.deletionTrigger !== "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY") {
    fail("RETAINED_PRIVATE_CLAIM", "Retained private claim opening or disposition rejected");
  }
}

export type CanonicalClaimPair = Readonly<{
  leftClaimId: GraphClaimId;
  rightClaimId: GraphClaimId;
  pairId: Sha256Digest;
}>;

export function canonicalClaimPair(first: GraphClaimId, second: GraphClaimId): CanonicalClaimPair {
  assertSha256(first, "PAIR_CLAIM");
  assertSha256(second, "PAIR_CLAIM");
  if (first === second) fail("PAIR_SELF", "A claim cannot be paired with itself");
  const [leftClaimId, rightClaimId] = first < second ? [first, second] : [second, first];
  return {
    leftClaimId,
    rightClaimId,
    pairId: graphDigest(PAIR_ID_DOMAIN, { leftClaimId, rightClaimId }),
  };
}

export function enumerateCanonicalPairs(nodes: readonly Pick<GraphClaimAuthorization, "claimId">[]): readonly CanonicalClaimPair[] {
  const ids = [...new Set(nodes.map((node) => node.claimId))].sort();
  if (ids.length !== nodes.length) fail("PAIR_NODE_DUPLICATE", "Duplicate graph claim node");
  const pairs: CanonicalClaimPair[] = [];
  for (let left = 0; left < ids.length; left += 1) {
    for (let right = left + 1; right < ids.length; right += 1) {
      pairs.push(canonicalClaimPair(ids[left], ids[right]));
    }
  }
  return pairs;
}

export type PairClaimBinding = Readonly<{
  role: PairRole;
  claimId: GraphClaimId;
  claimVersion: number;
  claimNodeDigest: Sha256Digest;
  claimCommitment: Sha256Digest;
  claimAuthorizationDigest: Sha256Digest;
}>;

export type GraphPairIntent = Readonly<{
  schemaVersion: typeof GRAPH_PAIR_INTENT_SCHEMA;
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  claimPair: CanonicalClaimPair;
  roleMapping: Readonly<{
    participantAClaimId: GraphClaimId;
    participantBClaimId: GraphClaimId;
  }>;
  claimBindings: readonly [PairClaimBinding, PairClaimBinding];
  pairRunId: string;
  createdAtUnix: number;
  authorizations: readonly [Readonly<{ claimId: GraphClaimId; signature: string }>, Readonly<{ claimId: GraphClaimId; signature: string }>];
  intentDigest: Sha256Digest;
}>;

function pairIntentBody(intent: Omit<GraphPairIntent, "authorizations" | "intentDigest">): object {
  return {
    schemaVersion: intent.schemaVersion,
    graphSessionId: intent.graphSessionId,
    receivableIdentity: intent.receivableIdentity,
    claimPair: intent.claimPair,
    roleMapping: intent.roleMapping,
    claimBindings: intent.claimBindings,
    pairRunId: intent.pairRunId,
    createdAtUnix: intent.createdAtUnix,
  };
}

function privateClaimMap(records: readonly GraphPrivateClaimRecord[]): Map<GraphClaimId, GraphPrivateClaimRecord> {
  const map = new Map<GraphClaimId, GraphPrivateClaimRecord>();
  for (const record of records) {
    verifyGraphPrivateClaimRecord(record);
    if (map.has(record.authorization.claimId)) fail("CLAIM_DUPLICATE", "Duplicate private claim");
    map.set(record.authorization.claimId, record);
  }
  return map;
}

export function createGraphPairIntent(options: Readonly<{
  first: GraphPrivateClaimRecord;
  second: GraphPrivateClaimRecord;
  pairRunId: string;
  createdAtUnix: number;
}>): GraphPairIntent {
  const records = privateClaimMap([options.first, options.second]);
  const pair = canonicalClaimPair(options.first.authorization.claimId, options.second.authorization.claimId);
  const participantA = records.get(pair.leftClaimId);
  const participantB = records.get(pair.rightClaimId);
  if (participantA === undefined || participantB === undefined) fail("PAIR_CLAIM", "Pair claim lookup failed");
  if (participantA.authorization.graphSessionId !== participantB.authorization.graphSessionId
    || participantA.authorization.receivableIdentity !== participantB.authorization.receivableIdentity) {
    fail("PAIR_SESSION", "Claims do not share graph and receivable");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(options.pairRunId)) {
    fail("PAIR_RUN", "Canonical UUID pair run id required");
  }
  if (!Number.isSafeInteger(options.createdAtUnix) || options.createdAtUnix <= 0) fail("PAIR_TIME", "Pair intent time rejected");
  const bindingFor = (record: GraphPrivateClaimRecord, role: PairRole): PairClaimBinding => ({
    role,
    claimId: record.authorization.claimId,
    claimVersion: record.authorization.claimVersion,
    claimNodeDigest: graphClaimNodeDigest(record.authorization),
    claimCommitment: record.authorization.claimCommitment,
    claimAuthorizationDigest: record.authorization.authorizationDigest,
  });
  const unsigned = {
    schemaVersion: GRAPH_PAIR_INTENT_SCHEMA,
    graphSessionId: participantA.authorization.graphSessionId,
    receivableIdentity: participantA.authorization.receivableIdentity,
    claimPair: pair,
    roleMapping: { participantAClaimId: pair.leftClaimId, participantBClaimId: pair.rightClaimId },
    claimBindings: [
      bindingFor(participantA, "PARTICIPANT_A"),
      bindingFor(participantB, "PARTICIPANT_B"),
    ] as const,
    pairRunId: options.pairRunId,
    createdAtUnix: options.createdAtUnix,
  } as const;
  const body = pairIntentBody(unsigned);
  const authorizations = [
    { claimId: pair.leftClaimId, signature: signGraphValue(participantA.authorizationPrivateKey, PAIR_INTENT_AUTHORIZATION_DOMAIN, body) },
    { claimId: pair.rightClaimId, signature: signGraphValue(participantB.authorizationPrivateKey, PAIR_INTENT_AUTHORIZATION_DOMAIN, body) },
  ] as const;
  return {
    ...unsigned,
    authorizations,
    intentDigest: graphDigest(PAIR_INTENT_DIGEST_DOMAIN, { ...body, authorizations }),
  };
}

function nodeMap(nodes: readonly GraphClaimAuthorization[]): Map<GraphClaimId, GraphClaimAuthorization> {
  const map = new Map<GraphClaimId, GraphClaimAuthorization>();
  for (const node of nodes) {
    verifyGraphClaimAuthorization(node);
    if (map.has(node.claimId)) fail("CLAIM_DUPLICATE", "Duplicate public claim node");
    map.set(node.claimId, node);
  }
  return map;
}

export function verifyGraphPairIntent(intent: GraphPairIntent, nodes: readonly GraphClaimAuthorization[]): void {
  assertExactKeys(intent, [
    "schemaVersion", "graphSessionId", "receivableIdentity", "claimPair", "roleMapping", "claimBindings",
    "pairRunId", "createdAtUnix", "authorizations", "intentDigest",
  ], "PAIR_INTENT_FIELDS");
  assertCanonicalPair(intent.claimPair, "PAIR_INTENT_PAIR");
  assertExactKeys(intent.roleMapping, ["participantAClaimId", "participantBClaimId"], "PAIR_ROLE_FIELDS");
  assertExactArray(intent.claimBindings, 2, "PAIR_CLAIM_BINDINGS");
  assertExactArray(intent.authorizations, 2, "PAIR_INTENT_AUTHORIZATIONS");
  for (const binding of intent.claimBindings) {
    assertExactKeys(binding, ["role", "claimId", "claimVersion", "claimNodeDigest", "claimCommitment", "claimAuthorizationDigest"], "PAIR_CLAIM_BINDING_FIELDS");
  }
  for (const authorization of intent.authorizations) {
    assertExactKeys(authorization, ["claimId", "signature"], "PAIR_INTENT_AUTHORIZATION_FIELDS");
  }
  if (intent.schemaVersion !== GRAPH_PAIR_INTENT_SCHEMA) fail("PAIR_INTENT_SCHEMA", "Unknown pair intent schema");
  assertSha256(intent.graphSessionId, "PAIR_INTENT_SESSION");
  assertSha256(intent.receivableIdentity, "PAIR_INTENT_RECEIVABLE");
  assertSha256(intent.intentDigest, "PAIR_INTENT_DIGEST");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(intent.pairRunId)
    || !Number.isSafeInteger(intent.createdAtUnix) || intent.createdAtUnix <= 0) {
    fail("PAIR_INTENT_HEADER", "Pair intent run/time rejected");
  }
  const canonical = canonicalClaimPair(intent.claimPair.leftClaimId, intent.claimPair.rightClaimId);
  if (canonical.pairId !== intent.claimPair.pairId
    || intent.roleMapping.participantAClaimId !== canonical.leftClaimId
    || intent.roleMapping.participantBClaimId !== canonical.rightClaimId) {
    fail("PAIR_ROLE_MAPPING", "Pair mapping is not deterministic");
  }
  const nodesById = nodeMap(nodes);
  const expectedRoles: readonly PairRole[] = ["PARTICIPANT_A", "PARTICIPANT_B"];
  const expectedIds: readonly GraphClaimId[] = [canonical.leftClaimId, canonical.rightClaimId];
  const body = pairIntentBody({
    schemaVersion: intent.schemaVersion,
    graphSessionId: intent.graphSessionId,
    receivableIdentity: intent.receivableIdentity,
    claimPair: intent.claimPair,
    roleMapping: intent.roleMapping,
    claimBindings: intent.claimBindings,
    pairRunId: intent.pairRunId,
    createdAtUnix: intent.createdAtUnix,
  });
  if (intent.claimBindings.length !== 2 || intent.authorizations.length !== 2) fail("PAIR_INTENT_SHAPE", "Two claim bindings required");
  for (let index = 0; index < 2; index += 1) {
    const binding = intent.claimBindings[index];
    const authorization = intent.authorizations[index];
    const node = nodesById.get(expectedIds[index]);
    if (node === undefined || node.graphSessionId !== intent.graphSessionId || node.receivableIdentity !== intent.receivableIdentity
      || intent.createdAtUnix < node.issuedAtUnix || intent.createdAtUnix > node.expiresAtUnix
      || binding.role !== expectedRoles[index] || binding.claimId !== expectedIds[index]
      || binding.claimVersion !== node.claimVersion || binding.claimNodeDigest !== graphClaimNodeDigest(node)
      || binding.claimCommitment !== node.claimCommitment || binding.claimAuthorizationDigest !== node.authorizationDigest
      || authorization.claimId !== node.claimId) {
      fail("PAIR_INTENT_BINDING", "Pair intent claim binding mismatch");
    }
    verifyGraphValue(node.authorizationPublicKey, PAIR_INTENT_AUTHORIZATION_DOMAIN, body, authorization.signature, "PAIR_INTENT_SIGNATURE");
  }
  const digest = graphDigest(PAIR_INTENT_DIGEST_DOMAIN, { ...body, authorizations: intent.authorizations });
  if (digest !== intent.intentDigest) fail("PAIR_INTENT_DIGEST", "Pair intent digest mismatch");
}

export type GraphPins = Readonly<{
  startingCommit: string;
  executionSourceCommit: string;
  executionSourceTree: string;
  governedFheSourceCommit: string;
  assetIdentity: Sha256Digest;
  policyId: Sha256Digest;
  policyVersion: 1;
  serviceId: "mordant.private-pledge-matching";
  serviceVersion: 1;
  circuitId: typeof FHE_CIRCUIT;
  circuitVersion: 5;
  circuitDigest: Sha256Digest;
  parameterProfile: typeof FHE_PARAMETER_PROFILE;
  parameterFingerprint: Sha256Digest;
  releaseMode: typeof GOVERNED_RELEASE_MODE;
  nativeBinaries: Readonly<{
    keygen: Sha256Digest;
    client: Sha256Digest;
    evaluator: Sha256Digest;
    decryptor: Sha256Digest;
    inspect: Sha256Digest;
  }>;
}>;

export function assertGraphPins(pins: GraphPins): void {
  assertExactKeys(pins, [
    "startingCommit", "executionSourceCommit", "executionSourceTree", "governedFheSourceCommit", "assetIdentity",
    "policyId", "policyVersion", "serviceId", "serviceVersion", "circuitId", "circuitVersion", "circuitDigest",
    "parameterProfile", "parameterFingerprint", "releaseMode", "nativeBinaries",
  ], "GRAPH_PIN_FIELDS");
  assertExactKeys(pins.nativeBinaries, ["keygen", "client", "evaluator", "decryptor", "inspect"], "GRAPH_BINARY_PIN_FIELDS");
  assertGitCommit(pins.startingCommit, "PIN_STARTING_COMMIT");
  assertGitCommit(pins.executionSourceCommit, "PIN_SOURCE_COMMIT");
  assertGitCommit(pins.executionSourceTree, "PIN_SOURCE_TREE");
  assertGitCommit(pins.governedFheSourceCommit, "PIN_GOVERNED_SOURCE");
  if (pins.startingCommit !== N3_STARTING_COMMIT || pins.governedFheSourceCommit !== EXPECTED_GOVERNED_FHE_COMMIT
    || pins.assetIdentity !== CANONICAL_CLEANVERSE_ASSET_DIGEST || pins.policyId !== protectionPolicyId()
    || pins.policyVersion !== 1 || pins.serviceId !== "mordant.private-pledge-matching" || pins.serviceVersion !== 1
    || pins.circuitId !== FHE_CIRCUIT || pins.circuitVersion !== 5 || pins.circuitDigest !== EXPECTED_CIRCUIT_DIGEST
    || pins.parameterProfile !== FHE_PARAMETER_PROFILE || pins.parameterFingerprint !== EXPECTED_PARAMETER_FINGERPRINT
    || pins.releaseMode !== GOVERNED_RELEASE_MODE) {
    fail("GRAPH_PINS", "Graph policy/circuit/profile/source pins changed");
  }
  for (const [name, digest] of Object.entries(pins.nativeBinaries)) assertSha256(digest, `PIN_BINARY_${name.toUpperCase()}`);
}

export function verifyFheCaseBindingShape(caseBinding: FheCaseBinding): void {
  assertExactKeys(caseBinding, [
    "schemaVersion", "caseId", "assetIdentity", "serviceId", "serviceVersion", "policyId", "policyVersion",
    "circuitId", "circuitVersion", "circuitDigest", "parameterProfile", "parameterFingerprint", "publicKeyDigest",
    "evaluationKeyManifestDigest", "participantA", "participantB", "participantOrder", "inputSchema", "resultSchema",
    "releaseMode", "releaseAuthorityId", "releaseAuthorityPublicKey", "caseNonce", "createdAtUnix", "expiresAtUnix",
  ], "FHE_CASE_BINDING_FIELDS");
  assertExactKeys(caseBinding.participantA, ["id", "role", "signingPublicKey"], "FHE_PARTICIPANT_A_FIELDS");
  assertExactKeys(caseBinding.participantB, ["id", "role", "signingPublicKey"], "FHE_PARTICIPANT_B_FIELDS");
  assertExactArray(caseBinding.participantOrder, 2, "FHE_PARTICIPANT_ORDER");
  for (const [name, digest] of Object.entries({
    caseId: caseBinding.caseId,
    assetIdentity: caseBinding.assetIdentity,
    policyId: caseBinding.policyId,
    circuitDigest: caseBinding.circuitDigest,
    parameterFingerprint: caseBinding.parameterFingerprint,
    publicKeyDigest: caseBinding.publicKeyDigest,
    evaluationKeyManifestDigest: caseBinding.evaluationKeyManifestDigest,
    participantAId: caseBinding.participantA.id,
    participantBId: caseBinding.participantB.id,
    releaseAuthorityId: caseBinding.releaseAuthorityId,
    caseNonce: caseBinding.caseNonce,
  })) assertSha256(digest, `FHE_${name.toUpperCase()}`);
  assertCanonicalBase64(caseBinding.participantA.signingPublicKey, "FHE_PARTICIPANT_A_KEY", 32);
  assertCanonicalBase64(caseBinding.participantB.signingPublicKey, "FHE_PARTICIPANT_B_KEY", 32);
  assertCanonicalBase64(caseBinding.releaseAuthorityPublicKey, "FHE_RELEASE_KEY", 32);
  if (caseBinding.participantA.role !== "PARTICIPANT_A" || caseBinding.participantB.role !== "PARTICIPANT_B"
    || caseBinding.participantA.id === caseBinding.participantB.id
    || caseBinding.participantA.signingPublicKey === caseBinding.participantB.signingPublicKey
    || caseBinding.participantOrder[0] !== caseBinding.participantA.id
    || caseBinding.participantOrder[1] !== caseBinding.participantB.id
    || !Number.isSafeInteger(caseBinding.createdAtUnix) || caseBinding.createdAtUnix <= 0
    || !Number.isSafeInteger(caseBinding.expiresAtUnix) || caseBinding.expiresAtUnix <= caseBinding.createdAtUnix) {
    fail("FHE_CASE_BINDING_SHAPE", "Governed FHE case binding rejected");
  }
}

function fheCaseBindingValue(binding: FheCaseBinding): object {
  return {
    schemaVersion: binding.schemaVersion,
    caseId: binding.caseId,
    assetIdentity: binding.assetIdentity,
    serviceId: binding.serviceId,
    serviceVersion: binding.serviceVersion,
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    circuitId: binding.circuitId,
    circuitVersion: binding.circuitVersion,
    circuitDigest: binding.circuitDigest,
    parameterProfile: binding.parameterProfile,
    parameterFingerprint: binding.parameterFingerprint,
    publicKeyDigest: binding.publicKeyDigest,
    evaluationKeyManifestDigest: binding.evaluationKeyManifestDigest,
    participantA: {
      id: binding.participantA.id,
      role: binding.participantA.role,
      signingPublicKey: binding.participantA.signingPublicKey,
    },
    participantB: {
      id: binding.participantB.id,
      role: binding.participantB.role,
      signingPublicKey: binding.participantB.signingPublicKey,
    },
    participantOrder: [...binding.participantOrder],
    inputSchema: binding.inputSchema,
    resultSchema: binding.resultSchema,
    releaseMode: binding.releaseMode,
    releaseAuthorityId: binding.releaseAuthorityId,
    releaseAuthorityPublicKey: binding.releaseAuthorityPublicKey,
    caseNonce: binding.caseNonce,
    createdAtUnix: binding.createdAtUnix,
    expiresAtUnix: binding.expiresAtUnix,
  };
}

export function fheCaseBindingDigest(binding: FheCaseBinding): Sha256Digest {
  return sha256Bytes(JSON.stringify(fheCaseBindingValue(binding)));
}

export type PairLocalRoleBinding = Readonly<{
  role: PairRole;
  claimId: GraphClaimId;
  claimNodeDigest: Sha256Digest;
  pairParticipantId: Sha256Digest;
  pairParticipantSigningPublicKey: string;
}>;

export type GraphPairBindingRecord = Readonly<{
  schemaVersion: typeof GRAPH_PAIR_BINDING_SCHEMA;
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  claimPair: CanonicalClaimPair;
  pairRunId: string;
  pairIntentDigest: Sha256Digest;
  caseId: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  caseBinding: FheCaseBinding;
  roleBindings: readonly [PairLocalRoleBinding, PairLocalRoleBinding];
  boundAtUnix: number;
  authorizations: readonly [Readonly<{ claimId: GraphClaimId; signature: string }>, Readonly<{ claimId: GraphClaimId; signature: string }>];
  bindingDigest: Sha256Digest;
}>;

function pairBindingBody(binding: Omit<GraphPairBindingRecord, "authorizations" | "bindingDigest">): object {
  return {
    schemaVersion: binding.schemaVersion,
    graphSessionId: binding.graphSessionId,
    receivableIdentity: binding.receivableIdentity,
    claimPair: binding.claimPair,
    pairRunId: binding.pairRunId,
    pairIntentDigest: binding.pairIntentDigest,
    caseId: binding.caseId,
    caseBindingDigest: binding.caseBindingDigest,
    caseBinding: fheCaseBindingValue(binding.caseBinding),
    roleBindings: binding.roleBindings,
    boundAtUnix: binding.boundAtUnix,
  };
}

export function createGraphPairBinding(options: Readonly<{
  intent: GraphPairIntent;
  claims: readonly [GraphPrivateClaimRecord, GraphPrivateClaimRecord];
  caseBinding: FheCaseBinding;
  boundAtUnix: number;
  pins: GraphPins;
}>): GraphPairBindingRecord {
  const claims = privateClaimMap(options.claims);
  const nodes = [...claims.values()].map((record) => record.authorization);
  verifyGraphPairIntent(options.intent, nodes);
  assertGraphPins(options.pins);
  const ids = [options.intent.claimPair.leftClaimId, options.intent.claimPair.rightClaimId] as const;
  const identities = [options.caseBinding.participantA, options.caseBinding.participantB] as const;
  const roles = ["PARTICIPANT_A", "PARTICIPANT_B"] as const;
  const roleBindings = roles.map((role, index): PairLocalRoleBinding => {
    const claim = claims.get(ids[index]);
    if (claim === undefined) fail("PAIR_BINDING_CLAIM", "Pair binding claim missing");
    return {
      role,
      claimId: claim.authorization.claimId,
      claimNodeDigest: graphClaimNodeDigest(claim.authorization),
      pairParticipantId: identities[index].id,
      pairParticipantSigningPublicKey: identities[index].signingPublicKey,
    };
  }) as [PairLocalRoleBinding, PairLocalRoleBinding];
  const unsigned = {
    schemaVersion: GRAPH_PAIR_BINDING_SCHEMA,
    graphSessionId: options.intent.graphSessionId,
    receivableIdentity: options.intent.receivableIdentity,
    claimPair: options.intent.claimPair,
    pairRunId: options.intent.pairRunId,
    pairIntentDigest: options.intent.intentDigest,
    caseId: options.caseBinding.caseId,
    caseBindingDigest: fheCaseBindingDigest(options.caseBinding),
    caseBinding: options.caseBinding,
    roleBindings,
    boundAtUnix: options.boundAtUnix,
  } as const;
  const body = pairBindingBody(unsigned);
  const authorizations = ids.map((claimId) => {
    const claim = claims.get(claimId);
    if (claim === undefined) fail("PAIR_BINDING_CLAIM", "Pair binding claim missing");
    return {
      claimId,
      signature: signGraphValue(claim.authorizationPrivateKey, PAIR_BINDING_AUTHORIZATION_DOMAIN, body),
    };
  }) as [Readonly<{ claimId: GraphClaimId; signature: string }>, Readonly<{ claimId: GraphClaimId; signature: string }>];
  const record: GraphPairBindingRecord = {
    ...unsigned,
    authorizations,
    bindingDigest: graphDigest(PAIR_BINDING_DIGEST_DOMAIN, { ...body, authorizations }),
  };
  verifyGraphPairBinding(record, options.intent, nodes, options.pins);
  return record;
}

export function verifyGraphPairBinding(
  binding: GraphPairBindingRecord,
  intent: GraphPairIntent,
  nodes: readonly GraphClaimAuthorization[],
  pins: GraphPins,
): void {
  assertGraphPins(pins);
  verifyGraphPairIntent(intent, nodes);
  assertExactKeys(binding, [
    "schemaVersion", "graphSessionId", "receivableIdentity", "claimPair", "pairRunId", "pairIntentDigest", "caseId",
    "caseBindingDigest", "caseBinding", "roleBindings", "boundAtUnix", "authorizations", "bindingDigest",
  ], "PAIR_BINDING_FIELDS");
  assertCanonicalPair(binding.claimPair, "PAIR_BINDING_PAIR");
  assertExactArray(binding.roleBindings, 2, "PAIR_ROLE_BINDINGS");
  assertExactArray(binding.authorizations, 2, "PAIR_BINDING_AUTHORIZATIONS");
  for (const roleBinding of binding.roleBindings) {
    assertExactKeys(roleBinding, ["role", "claimId", "claimNodeDigest", "pairParticipantId", "pairParticipantSigningPublicKey"], "PAIR_ROLE_BINDING_FIELDS");
  }
  for (const authorization of binding.authorizations) {
    assertExactKeys(authorization, ["claimId", "signature"], "PAIR_BINDING_AUTHORIZATION_FIELDS");
  }
  verifyFheCaseBindingShape(binding.caseBinding);
  if (binding.schemaVersion !== GRAPH_PAIR_BINDING_SCHEMA || binding.graphSessionId !== intent.graphSessionId
    || binding.receivableIdentity !== intent.receivableIdentity || binding.pairRunId !== intent.pairRunId
    || binding.receivableIdentity !== pins.assetIdentity || intent.receivableIdentity !== pins.assetIdentity
    || binding.pairIntentDigest !== intent.intentDigest
    || canonicalGraphJson(binding.claimPair) !== canonicalGraphJson(intent.claimPair)
    || binding.caseId !== binding.caseBinding.caseId || binding.caseBindingDigest !== fheCaseBindingDigest(binding.caseBinding)
    || !Number.isSafeInteger(binding.boundAtUnix) || binding.boundAtUnix < intent.createdAtUnix
    || binding.boundAtUnix < binding.caseBinding.createdAtUnix || binding.boundAtUnix > binding.caseBinding.expiresAtUnix) {
    fail("PAIR_BINDING", "Pair binding does not extend its pre-result intent");
  }
  const caseBinding = binding.caseBinding;
  if (caseBinding.schemaVersion !== "mordant.fhe-case-binding/1" || caseBinding.assetIdentity !== pins.assetIdentity
    || caseBinding.policyId !== pins.policyId || caseBinding.policyVersion !== pins.policyVersion
    || caseBinding.serviceId !== pins.serviceId || caseBinding.serviceVersion !== pins.serviceVersion
    || caseBinding.circuitId !== pins.circuitId || caseBinding.circuitVersion !== pins.circuitVersion
    || caseBinding.circuitDigest !== pins.circuitDigest || caseBinding.parameterProfile !== pins.parameterProfile
    || caseBinding.parameterFingerprint !== pins.parameterFingerprint || caseBinding.releaseMode !== pins.releaseMode
    || caseBinding.inputSchema !== "mordant.encrypted-pledge/governed-fhe-v1"
    || caseBinding.resultSchema !== "mordant.fixed-conflict-boolean/v1") {
    fail("PAIR_BINDING_PINS", "Pair case asset/policy/circuit/profile pin mismatch");
  }
  try {
    assertReleaseAuthorityIdentity(
      caseBinding.releaseAuthorityPublicKey,
      caseBinding.releaseMode,
      caseBinding.releaseAuthorityId,
      "PAIR_BINDING_AUTHORITY",
    );
  } catch {
    fail("PAIR_BINDING_AUTHORITY", "Pair case release authority identity rejected");
  }
  const nodesById = nodeMap(nodes);
  const identities = [caseBinding.participantA, caseBinding.participantB] as const;
  const ids = [intent.claimPair.leftClaimId, intent.claimPair.rightClaimId] as const;
  const roles = ["PARTICIPANT_A", "PARTICIPANT_B"] as const;
  const body = pairBindingBody({
    schemaVersion: binding.schemaVersion,
    graphSessionId: binding.graphSessionId,
    receivableIdentity: binding.receivableIdentity,
    claimPair: binding.claimPair,
    pairRunId: binding.pairRunId,
    pairIntentDigest: binding.pairIntentDigest,
    caseId: binding.caseId,
    caseBindingDigest: binding.caseBindingDigest,
    caseBinding: binding.caseBinding,
    roleBindings: binding.roleBindings,
    boundAtUnix: binding.boundAtUnix,
  });
  if (binding.roleBindings.length !== 2 || binding.authorizations.length !== 2
    || caseBinding.participantOrder[0] !== caseBinding.participantA.id
    || caseBinding.participantOrder[1] !== caseBinding.participantB.id) {
    fail("PAIR_BINDING_SHAPE", "Pair binding role shape rejected");
  }
  for (let index = 0; index < 2; index += 1) {
    const roleBinding = binding.roleBindings[index];
    const authorization = binding.authorizations[index];
    const node = nodesById.get(ids[index]);
    if (node === undefined || roleBinding.role !== roles[index] || roleBinding.claimId !== ids[index]
      || roleBinding.claimNodeDigest !== graphClaimNodeDigest(node)
      || roleBinding.pairParticipantId !== identities[index].id
      || roleBinding.pairParticipantSigningPublicKey !== identities[index].signingPublicKey
      || identities[index].role !== roles[index] || authorization.claimId !== ids[index]) {
      fail("PAIR_BINDING_ROLE", "Stable graph claim to pair-local participant binding mismatch");
    }
    verifyGraphValue(node.authorizationPublicKey, PAIR_BINDING_AUTHORIZATION_DOMAIN, body, authorization.signature, "PAIR_BINDING_SIGNATURE");
  }
  const digest = graphDigest(PAIR_BINDING_DIGEST_DOMAIN, { ...body, authorizations: binding.authorizations });
  if (digest !== binding.bindingDigest) fail("PAIR_BINDING_DIGEST", "Pair binding digest mismatch");
}

export type PairPublicInspection = Readonly<{
  finalized: true;
  evaluationAdmission: true;
  releaseVerified: true;
  ambiguous: false;
  recoursePresent: false;
  publicEvidencePresent: false;
  resultDigest: Sha256Digest;
  conflict: boolean;
  releaseMode: typeof GOVERNED_RELEASE_MODE;
  participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
  evaluatedArtifactDigest: Sha256Digest;
  inspectBinaryDigest: Sha256Digest;
  inspectionReportDigest: Sha256Digest;
  inspectionDigest: Sha256Digest;
}>;

type PairPublicInspectionBody = Omit<PairPublicInspection, "inspectionDigest">;

export function createPairPublicInspection(value: PairPublicInspectionBody): PairPublicInspection {
  assertSha256(value.inspectBinaryDigest, "PAIR_INSPECT_BINARY");
  assertSha256(value.inspectionReportDigest, "PAIR_INSPECT_REPORT");
  const body: PairPublicInspectionBody = {
    finalized: value.finalized,
    evaluationAdmission: value.evaluationAdmission,
    releaseVerified: value.releaseVerified,
    ambiguous: value.ambiguous,
    recoursePresent: value.recoursePresent,
    publicEvidencePresent: value.publicEvidencePresent,
    resultDigest: value.resultDigest,
    conflict: value.conflict,
    releaseMode: value.releaseMode,
    participantArtifactDigests: value.participantArtifactDigests,
    evaluatedArtifactDigest: value.evaluatedArtifactDigest,
    inspectBinaryDigest: value.inspectBinaryDigest,
    inspectionReportDigest: value.inspectionReportDigest,
  };
  return Object.freeze({ ...body, inspectionDigest: graphDigest(PAIR_INSPECTION_DIGEST_DOMAIN, body) });
}

export function publicInspectionReportDigest(report: unknown): Sha256Digest {
  return graphDigest(PAIR_INSPECTION_REPORT_DIGEST_DOMAIN, report);
}

export const REQUIRED_PAIR_OPERATIONS = Object.freeze([
  "preparePrivateMatch",
  "submitParticipantA",
  "submitParticipantB",
  "finalizeParticipantSubmissions",
  "evaluatePrivateConflict",
  "releaseGovernedResult",
] as const);

export type PairExecutionChronology = Readonly<{
  executionOrdinal: number;
  startedAt: string;
  completedAt: string;
  terminalStage: "RELEASED";
  operations: typeof REQUIRED_PAIR_OPERATIONS;
}>;

export type GraphPairEvidenceLeaf = Readonly<{
  schemaVersion: typeof GRAPH_PAIR_EVIDENCE_SCHEMA;
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  claimPair: CanonicalClaimPair;
  pairRunId: string;
  pairBindingDigest: Sha256Digest;
  caseId: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
  evaluatedArtifactDigest: Sha256Digest;
  evaluatorProvenance: Sha256Digest;
  governedResult: GovernedSignedResult;
  governedResultDigest: Sha256Digest;
  state: "CONFLICT" | "NO_CONFLICT_UNDER_POLICY";
  inspection: PairPublicInspection;
  execution: PairExecutionChronology;
  evidenceDigest: Sha256Digest;
}>;

function pairEvidenceBody(leaf: Omit<GraphPairEvidenceLeaf, "evidenceDigest">): object {
  return { ...leaf, governedResult: { ...leaf.governedResult } };
}

export function createGraphPairEvidenceLeaf(options: Omit<GraphPairEvidenceLeaf, "schemaVersion" | "state" | "evidenceDigest"> & Readonly<{
  binding: GraphPairBindingRecord;
  intent: GraphPairIntent;
  nodes: readonly GraphClaimAuthorization[];
  pins: GraphPins;
}>): GraphPairEvidenceLeaf {
  const state = options.governedResult.conflict ? "CONFLICT" : "NO_CONFLICT_UNDER_POLICY";
  const body = {
    schemaVersion: GRAPH_PAIR_EVIDENCE_SCHEMA,
    graphSessionId: options.graphSessionId,
    receivableIdentity: options.receivableIdentity,
    claimPair: options.claimPair,
    pairRunId: options.pairRunId,
    pairBindingDigest: options.pairBindingDigest,
    caseId: options.caseId,
    caseBindingDigest: options.caseBindingDigest,
    participantArtifactDigests: options.participantArtifactDigests,
    evaluatedArtifactDigest: options.evaluatedArtifactDigest,
    evaluatorProvenance: options.evaluatorProvenance,
    governedResult: options.governedResult,
    governedResultDigest: options.governedResultDigest,
    state,
    inspection: options.inspection,
    execution: options.execution,
  } as const;
  const leaf: GraphPairEvidenceLeaf = {
    ...body,
    evidenceDigest: graphDigest(PAIR_EVIDENCE_DIGEST_DOMAIN, pairEvidenceBody(body)),
  };
  verifyGraphPairEvidenceLeaf(leaf, options.binding, options.intent, options.nodes, options.pins);
  return leaf;
}

export function verifyGraphPairEvidenceLeaf(
  leaf: GraphPairEvidenceLeaf,
  binding: GraphPairBindingRecord,
  intent: GraphPairIntent,
  nodes: readonly GraphClaimAuthorization[],
  pins: GraphPins,
): PairExecutionState {
  assertGraphPins(pins);
  assertExactKeys(leaf, [
    "schemaVersion", "graphSessionId", "receivableIdentity", "claimPair", "pairRunId", "pairBindingDigest", "caseId",
    "caseBindingDigest", "participantArtifactDigests", "evaluatedArtifactDigest", "evaluatorProvenance", "governedResult",
    "governedResultDigest", "state", "inspection", "execution", "evidenceDigest",
  ], "PAIR_EVIDENCE_FIELDS");
  assertCanonicalPair(leaf.claimPair, "PAIR_EVIDENCE_PAIR");
  assertExactArray(leaf.participantArtifactDigests, 2, "PAIR_EVIDENCE_ARTIFACTS");
  assertExactKeys(leaf.inspection, [
    "finalized", "evaluationAdmission", "releaseVerified", "ambiguous", "recoursePresent", "publicEvidencePresent",
    "resultDigest", "conflict", "releaseMode", "participantArtifactDigests", "evaluatedArtifactDigest",
    "inspectBinaryDigest", "inspectionReportDigest", "inspectionDigest",
  ], "PAIR_INSPECTION_FIELDS");
  assertExactArray(leaf.inspection.participantArtifactDigests, 2, "PAIR_INSPECTION_ARTIFACTS");
  assertExactKeys(leaf.execution, ["executionOrdinal", "startedAt", "completedAt", "terminalStage", "operations"], "PAIR_EXECUTION_FIELDS");
  assertExactArray(leaf.execution.operations, REQUIRED_PAIR_OPERATIONS.length, "PAIR_EXECUTION_OPERATIONS");
  if (leaf.graphSessionId !== intent.graphSessionId || leaf.graphSessionId !== binding.graphSessionId) {
    fail("CROSS_SESSION_LEAF", "Pair evidence belongs to another graph session");
  }
  verifyGraphPairBinding(binding, intent, nodes, pins);
  if (leaf.schemaVersion !== GRAPH_PAIR_EVIDENCE_SCHEMA || leaf.receivableIdentity !== pins.assetIdentity
    || leaf.receivableIdentity !== intent.receivableIdentity || leaf.receivableIdentity !== binding.receivableIdentity
    || canonicalGraphJson(leaf.claimPair) !== canonicalGraphJson(intent.claimPair) || leaf.pairRunId !== intent.pairRunId
    || leaf.pairBindingDigest !== binding.bindingDigest || leaf.caseId !== binding.caseId
    || leaf.caseBindingDigest !== binding.caseBindingDigest || leaf.evaluatorProvenance !== pins.nativeBinaries.evaluator) {
    fail("PAIR_EVIDENCE_BINDING", "Pair evidence binding mismatch");
  }
  const result = leaf.governedResult;
  if (!isRecord(result)) fail("PAIR_RESULT_FIELDS", "Governed result must be a plain JSON object");
  assertExactArray(result.participantArtifactDigests, 2, "PAIR_RESULT_ARTIFACTS");
  for (const [name, digest] of Object.entries({
    pairBindingDigest: leaf.pairBindingDigest,
    caseId: leaf.caseId,
    caseBindingDigest: leaf.caseBindingDigest,
    participantArtifactA: leaf.participantArtifactDigests[0],
    participantArtifactB: leaf.participantArtifactDigests[1],
    evaluatedArtifactDigest: leaf.evaluatedArtifactDigest,
    evaluatorProvenance: leaf.evaluatorProvenance,
    governedResultDigest: leaf.governedResultDigest,
    evidenceDigest: leaf.evidenceDigest,
  })) assertSha256(digest, `PAIR_EVIDENCE_${name.toUpperCase()}`);
  // Pin checks precede signature verification so a precise wrong-pin rejection
  // cannot be hidden behind the stale signature of a mutated test candidate.
  if (result.schemaVersion !== "mordant.governed-conflict-result/1" || result.caseId !== binding.caseId
    || result.caseBindingDigest !== binding.caseBindingDigest || result.assetIdentity !== pins.assetIdentity
    || result.policyId !== pins.policyId || result.policyVersion !== pins.policyVersion
    || result.serviceId !== pins.serviceId || result.serviceVersion !== pins.serviceVersion
    || result.circuitId !== pins.circuitId || result.circuitVersion !== pins.circuitVersion
    || result.circuitDigest !== pins.circuitDigest || result.parameterProfile !== pins.parameterProfile
    || result.parameterFingerprint !== pins.parameterFingerprint || result.releaseMode !== pins.releaseMode
    || result.releaseOrdinal !== 1 || result.releaseAuthorityId !== binding.caseBinding.releaseAuthorityId
    || result.releaseAuthorityPublicKey !== binding.caseBinding.releaseAuthorityPublicKey
    || result.sourceProvenance !== pins.nativeBinaries.decryptor) {
    fail("PAIR_RESULT_PINS", "Governed result asset/policy/circuit/profile/source pin mismatch");
  }
  if (leaf.participantArtifactDigests.length !== 2 || result.participantArtifactDigests.length !== 2
    || leaf.participantArtifactDigests[0] !== result.participantArtifactDigests[0]
    || leaf.participantArtifactDigests[1] !== result.participantArtifactDigests[1]
    || leaf.evaluatedArtifactDigest !== result.evaluatedArtifactDigest) {
    fail("PAIR_RESULT_ARTIFACTS", "Governed result artifact binding mismatch");
  }
  try {
    assertReleaseAuthorityIdentity(
      result.releaseAuthorityPublicKey,
      result.releaseMode,
      result.releaseAuthorityId,
      "PAIR_RESULT_AUTHORITY",
    );
  } catch {
    fail("PAIR_RESULT_AUTHORITY", "Governed result release authority identity rejected");
  }
  try {
    verifyGovernedResultSignature(result);
  } catch {
    fail("PAIR_RESULT_SIGNATURE", "Complete governed result signature rejected");
  }
  const resultDigest = governedResultDigest(result);
  const displayedDigest = (result as GovernedSignedResult & Readonly<{ digest?: unknown }>).digest;
  if (displayedDigest !== undefined && displayedDigest !== resultDigest) {
    fail("PAIR_RESULT_DISPLAY_DIGEST", "Governed result carries a contradictory displayed digest");
  }
  if (resultDigest !== leaf.governedResultDigest) fail("PAIR_RESULT_DIGEST", "Governed result digest mismatch");
  const expectedState = result.conflict ? "CONFLICT" : "NO_CONFLICT_UNDER_POLICY";
  if (leaf.state !== expectedState) fail("PAIR_RESULT_STATE", "Relation state is not derived from the signed Boolean");
  const inspection = leaf.inspection;
  if (!inspection.finalized || !inspection.evaluationAdmission || !inspection.releaseVerified || inspection.ambiguous
    || inspection.recoursePresent || inspection.publicEvidencePresent || inspection.resultDigest !== resultDigest
    || inspection.conflict !== result.conflict || inspection.releaseMode !== result.releaseMode
    || inspection.participantArtifactDigests[0] !== leaf.participantArtifactDigests[0]
    || inspection.participantArtifactDigests[1] !== leaf.participantArtifactDigests[1]
    || inspection.evaluatedArtifactDigest !== leaf.evaluatedArtifactDigest
    || inspection.inspectBinaryDigest !== pins.nativeBinaries.inspect) {
    fail("PAIR_INSPECTION", "Independent public pair inspection mismatch");
  }
  const { inspectionDigest, ...inspectionBody } = inspection;
  if (inspectionDigest !== graphDigest(PAIR_INSPECTION_DIGEST_DOMAIN, inspectionBody)) {
    fail("PAIR_INSPECTION_DIGEST", "Independent inspection digest mismatch");
  }
  if (!Number.isSafeInteger(leaf.execution.executionOrdinal) || leaf.execution.executionOrdinal <= 0
    || leaf.execution.terminalStage !== "RELEASED"
    || canonicalGraphJson(leaf.execution.operations) !== canonicalGraphJson(REQUIRED_PAIR_OPERATIONS)
    || assertIsoTime(leaf.execution.completedAt, "PAIR_COMPLETED_TIME") <= assertIsoTime(leaf.execution.startedAt, "PAIR_STARTED_TIME")) {
    fail("PAIR_EXECUTION", "Pair execution chronology rejected");
  }
  const expectedEvidence = graphDigest(PAIR_EVIDENCE_DIGEST_DOMAIN, pairEvidenceBody({
    schemaVersion: leaf.schemaVersion,
    graphSessionId: leaf.graphSessionId,
    receivableIdentity: leaf.receivableIdentity,
    claimPair: leaf.claimPair,
    pairRunId: leaf.pairRunId,
    pairBindingDigest: leaf.pairBindingDigest,
    caseId: leaf.caseId,
    caseBindingDigest: leaf.caseBindingDigest,
    participantArtifactDigests: leaf.participantArtifactDigests,
    evaluatedArtifactDigest: leaf.evaluatedArtifactDigest,
    evaluatorProvenance: leaf.evaluatorProvenance,
    governedResult: leaf.governedResult,
    governedResultDigest: leaf.governedResultDigest,
    state: leaf.state,
    inspection: leaf.inspection,
    execution: leaf.execution,
  }));
  if (expectedEvidence !== leaf.evidenceDigest) fail("PAIR_EVIDENCE_DIGEST", "Pair evidence digest mismatch");
  return leaf.state;
}

export type GraphChronologyEvent = Readonly<{
  ordinal: number;
  kind: "CLAIM_ADMITTED" | "ADMISSIONS_SEALED" | "PAIR_INTENT_FROZEN" | "PAIR_BOUND" | "PAIR_COMPLETED" | "PAIR_FAILED" | "PAIR_EXPIRED";
  occurredAt: string;
  claimId?: GraphClaimId;
  pairId?: Sha256Digest;
  pairRunId?: string;
  evidenceRef?: Sha256Digest;
  newPairIds?: readonly Sha256Digest[];
}>;

export type PairRelationRecord = Readonly<{
  claimPair: CanonicalClaimPair;
  state: PairExecutionState;
  pairRunId: string | null;
  pairIntentDigest: Sha256Digest | null;
  pairBindingDigest: Sha256Digest | null;
  evidenceDigest: Sha256Digest | null;
  governedResultDigest: Sha256Digest | null;
  failureDigest: Sha256Digest | null;
  executionOrdinal: number | null;
  startedAt: string | null;
  completedAt: string | null;
}>;

type MutableRelation = {
  claimPair: CanonicalClaimPair;
  state: PairExecutionState;
  pairRunId: string | null;
  pairIntentDigest: Sha256Digest | null;
  pairBindingDigest: Sha256Digest | null;
  evidenceDigest: Sha256Digest | null;
  governedResultDigest: Sha256Digest | null;
  failureDigest: Sha256Digest | null;
  executionOrdinal: number | null;
  startedAt: string | null;
  completedAt: string | null;
  intent: GraphPairIntent | null;
  binding: GraphPairBindingRecord | null;
  leaf: GraphPairEvidenceLeaf | null;
};

export type AggregateManifest = Readonly<{
  schemaVersion: typeof GRAPH_AGGREGATE_SCHEMA;
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  issuedAtUnix: number;
  expiresAtUnix: number;
  expectedClaimCount: typeof N3_EXPECTED_CLAIM_COUNT;
  nodesSealed: boolean;
  nodes: readonly GraphClaimAuthorization[];
  expectedPairs: readonly CanonicalClaimPair[];
  pairRelations: readonly PairRelationRecord[];
  pins: GraphPins;
  chronologyDigest: Sha256Digest;
  completeness: GraphCompleteness;
  reviewState: GraphReviewState;
  globalAllClear: boolean | null;
  trueConflictEdges: readonly CanonicalClaimPair[];
  execution: Readonly<{
    scheduling: "SEQUENTIAL";
    workerArchitecture: "UNCHANGED_SINGLE_SLOT";
    maxConcurrentPairsObserved: 0 | 1;
    strictlySequential: boolean;
  }>;
  retention: GraphPrivateClaimRecord["retention"] & Readonly<{
    publicEvidenceContainsOpenings: false;
  }>;
  reviewHandoff: Readonly<{
    automaticIncidentCreation: false;
    policyOrHumanReviewRequired: true;
    evidenceReferences: readonly Sha256Digest[];
  }>;
  sideEffects: Readonly<{
    recourseOpened: false;
    adapterDeployed: false;
    cureWindowCreated: false;
    settlementExecuted: false;
    tokensMoved: false;
  }>;
  aggregateRoot: Sha256Digest;
}>;

function relationPublic(relation: MutableRelation): PairRelationRecord {
  return {
    claimPair: relation.claimPair,
    state: relation.state,
    pairRunId: relation.pairRunId,
    pairIntentDigest: relation.pairIntentDigest,
    pairBindingDigest: relation.pairBindingDigest,
    evidenceDigest: relation.evidenceDigest,
    governedResultDigest: relation.governedResultDigest,
    failureDigest: relation.failureDigest,
    executionOrdinal: relation.executionOrdinal,
    startedAt: relation.startedAt,
    completedAt: relation.completedAt,
  };
}

function resolvedState(state: PairExecutionState): boolean {
  return state === "CONFLICT" || state === "NO_CONFLICT_UNDER_POLICY";
}

export function claimGlobalAllClear(
  completeness: GraphCompleteness,
  relations: readonly Pick<PairRelationRecord, "state" | "claimPair">[],
): boolean {
  if (completeness !== "COMPLETE" || relations.length !== N3_EXPECTED_PAIR_COUNT
    || new Set(relations.map((relation) => {
      assertCanonicalPair(relation.claimPair, "ALL_CLEAR_PAIR");
      return relation.claimPair.pairId;
    })).size !== N3_EXPECTED_PAIR_COUNT
    || relations.some((relation) => !resolvedState(relation.state))) {
    fail("ALL_CLEAR_INCOMPLETE", "A global all-clear requires every expected pair to have valid complete evidence");
  }
  return relations.every((relation) => relation.state === "NO_CONFLICT_UNDER_POLICY");
}

export type ConflictGraphSessionOptions = Readonly<{
  graphSessionId: Sha256Digest;
  receivableIdentity: Sha256Digest;
  issuedAtUnix: number;
  expiresAtUnix: number;
  pins: GraphPins;
}>;

export class ReceivableConflictSession {
  readonly graphSessionId: Sha256Digest;
  readonly receivableIdentity: Sha256Digest;
  readonly expectedClaimCount = N3_EXPECTED_CLAIM_COUNT;
  readonly issuedAtUnix: number;
  readonly expiresAtUnix: number;
  readonly pins: GraphPins;

  #nodes: GraphClaimAuthorization[] = [];
  #relations = new Map<Sha256Digest, MutableRelation>();
  #chronology: GraphChronologyEvent[] = [];
  #sealed = false;
  #activePair: Sha256Digest | null = null;
  #pairExecutionOrdinal = 0;
  #activePairs = 0;
  #maxConcurrentPairsObserved: 0 | 1 = 0;
  #pendingPairQueue: Sha256Digest[] = [];
  #lastEventMs: number;

  constructor(options: ConflictGraphSessionOptions) {
    assertSha256(options.graphSessionId, "GRAPH_SESSION");
    assertSha256(options.receivableIdentity, "GRAPH_RECEIVABLE");
    assertGraphPins(options.pins);
    if (options.receivableIdentity !== options.pins.assetIdentity
      || !Number.isSafeInteger(options.issuedAtUnix) || !Number.isSafeInteger(options.expiresAtUnix)
      || options.issuedAtUnix <= 0 || options.expiresAtUnix <= options.issuedAtUnix) {
      fail("GRAPH_HEADER", "Invalid graph session header");
    }
    this.graphSessionId = options.graphSessionId;
    this.receivableIdentity = options.receivableIdentity;
    this.issuedAtUnix = options.issuedAtUnix;
    this.expiresAtUnix = options.expiresAtUnix;
    this.pins = options.pins;
    this.#lastEventMs = options.issuedAtUnix * 1_000;
  }

  #validateEventTime(occurredAt: string, allowAfterExpiry = false): number {
    const milliseconds = assertIsoTime(occurredAt, "GRAPH_TIME");
    if (milliseconds < this.#lastEventMs || (!allowAfterExpiry && Math.floor(milliseconds / 1_000) > this.expiresAtUnix)) {
      fail("GRAPH_TIME", "Graph event is outside the monotonic session lifetime");
    }
    return milliseconds;
  }

  #event(event: Omit<GraphChronologyEvent, "ordinal">, allowAfterExpiry = false): void {
    const milliseconds = this.#validateEventTime(event.occurredAt, allowAfterExpiry);
    this.#chronology.push({ ordinal: this.#chronology.length + 1, ...event });
    this.#lastEventMs = milliseconds;
  }

  #assertFreshPairArtifacts(
    currentPairId: Sha256Digest,
    binding: GraphPairBindingRecord,
    leaf: GraphPairEvidenceLeaf,
  ): void {
    const candidate = {
      pairRunId: binding.pairRunId,
      caseId: binding.caseId,
      caseBindingDigest: binding.caseBindingDigest,
      publicKeyDigest: binding.caseBinding.publicKeyDigest,
      evaluationKeyManifestDigest: binding.caseBinding.evaluationKeyManifestDigest,
      caseNonce: binding.caseBinding.caseNonce,
      releaseAuthorityId: binding.caseBinding.releaseAuthorityId,
      releaseAuthorityPublicKey: binding.caseBinding.releaseAuthorityPublicKey,
      participantAId: binding.caseBinding.participantA.id,
      participantBId: binding.caseBinding.participantB.id,
      participantAKey: binding.caseBinding.participantA.signingPublicKey,
      participantBKey: binding.caseBinding.participantB.signingPublicKey,
      evaluatedArtifactDigest: leaf.evaluatedArtifactDigest,
      resultCiphertextDigest: leaf.governedResult.resultCiphertextDigest,
      resultCiphertextCommitment: leaf.governedResult.resultCiphertextCommitment,
      governedResultDigest: leaf.governedResultDigest,
    } as const;
    for (const [pairId, other] of this.#relations) {
      if (pairId === currentPairId || other.binding === null || other.leaf === null) continue;
      const prior = {
        pairRunId: other.binding.pairRunId,
        caseId: other.binding.caseId,
        caseBindingDigest: other.binding.caseBindingDigest,
        publicKeyDigest: other.binding.caseBinding.publicKeyDigest,
        evaluationKeyManifestDigest: other.binding.caseBinding.evaluationKeyManifestDigest,
        caseNonce: other.binding.caseBinding.caseNonce,
        releaseAuthorityId: other.binding.caseBinding.releaseAuthorityId,
        releaseAuthorityPublicKey: other.binding.caseBinding.releaseAuthorityPublicKey,
        participantAId: other.binding.caseBinding.participantA.id,
        participantBId: other.binding.caseBinding.participantB.id,
        participantAKey: other.binding.caseBinding.participantA.signingPublicKey,
        participantBKey: other.binding.caseBinding.participantB.signingPublicKey,
        evaluatedArtifactDigest: other.leaf.evaluatedArtifactDigest,
        resultCiphertextDigest: other.leaf.governedResult.resultCiphertextDigest,
        resultCiphertextCommitment: other.leaf.governedResult.resultCiphertextCommitment,
        governedResultDigest: other.leaf.governedResultDigest,
      } as const;
      for (const key of Object.keys(candidate) as (keyof typeof candidate)[]) {
        if (candidate[key] === prior[key]) fail("PAIR_FRESHNESS", `Pair-specific ${key} was reused`);
      }
      const participantArtifacts = new Set(leaf.participantArtifactDigests);
      if (other.leaf.participantArtifactDigests.some((digest) => participantArtifacts.has(digest))) {
        fail("PAIR_FRESHNESS", "Pair participant ciphertext artifact was reused");
      }
    }
  }

  admitClaim(node: GraphClaimAuthorization, occurredAt: string): readonly CanonicalClaimPair[] {
    if (this.#sealed) fail("GRAPH_SEALED", "Claim admissions are sealed");
    if (this.#activePair !== null || this.#pendingPairQueue.length !== 0) {
      fail("GRAPH_ADMISSION_ORDER", "Resolve every pair formed by the prior admission before admitting another claim");
    }
    verifyGraphClaimAuthorization(node);
    const at = this.#validateEventTime(occurredAt);
    const atUnix = Math.floor(at / 1_000);
    if (node.graphSessionId !== this.graphSessionId || node.receivableIdentity !== this.receivableIdentity
      || atUnix < node.issuedAtUnix || atUnix > node.expiresAtUnix || atUnix > this.expiresAtUnix
      || this.#nodes.some((existing) => existing.claimId === node.claimId)
      || this.#nodes.some((existing) => existing.participantRef === node.participantRef)) {
      fail("GRAPH_CLAIM_ADMISSION", "Graph claim admission rejected");
    }
    if (this.#nodes.length >= this.expectedClaimCount) fail("GRAPH_CAPACITY", "N=3 experiment accepts exactly three claims");
    const newPairs = this.#nodes.map((existing) => canonicalClaimPair(existing.claimId, node.claimId));
    this.#nodes.push(node);
    for (const pair of newPairs) {
      this.#relations.set(pair.pairId, {
        claimPair: pair,
        state: "PENDING",
        pairRunId: null,
        pairIntentDigest: null,
        pairBindingDigest: null,
        evidenceDigest: null,
        governedResultDigest: null,
        failureDigest: null,
        executionOrdinal: null,
        startedAt: null,
        completedAt: null,
        intent: null,
        binding: null,
        leaf: null,
      });
      this.#pendingPairQueue.push(pair.pairId);
    }
    this.#event({ kind: "CLAIM_ADMITTED", occurredAt, claimId: node.claimId, newPairIds: newPairs.map((pair) => pair.pairId) });
    return newPairs;
  }

  sealAdmissions(occurredAt: string): void {
    if (this.#sealed) return;
    if (this.#nodes.length !== this.expectedClaimCount || this.#relations.size !== N3_EXPECTED_PAIR_COUNT) {
      fail("GRAPH_INCOMPLETE_NODES", "Exactly three admitted claims are required before sealing");
    }
    this.#validateEventTime(occurredAt);
    this.#sealed = true;
    this.#event({ kind: "ADMISSIONS_SEALED", occurredAt });
  }

  beginPair(intent: GraphPairIntent, occurredAt: string): void {
    if (intent.graphSessionId !== this.graphSessionId) fail("CROSS_SESSION_INTENT", "Pair intent belongs to another session");
    verifyGraphPairIntent(intent, this.#nodes);
    const startedMs = this.#validateEventTime(occurredAt);
    const relation = this.#relations.get(intent.claimPair.pairId);
    if (relation === undefined || relation.state !== "PENDING" || relation.intent !== null || this.#activePair !== null) {
      fail("PAIR_SEQUENTIAL", "Only one pending pair may execute at a time");
    }
    if (this.#pendingPairQueue[0] !== intent.claimPair.pairId
      || intent.createdAtUnix !== Math.floor(startedMs / 1_000)) {
      fail("PAIR_ADMISSION_SEQUENCE", "Pair execution is not the next admission-created pair");
    }
    this.#pairExecutionOrdinal += 1;
    this.#activePair = intent.claimPair.pairId;
    this.#activePairs += 1;
    if (this.#activePairs > 1) fail("PAIR_CONCURRENCY", "N=3 pair execution must be sequential");
    this.#maxConcurrentPairsObserved = 1;
    relation.intent = intent;
    relation.pairRunId = intent.pairRunId;
    relation.pairIntentDigest = intent.intentDigest;
    relation.executionOrdinal = this.#pairExecutionOrdinal;
    relation.startedAt = occurredAt;
    this.#event({
      kind: "PAIR_INTENT_FROZEN",
      occurredAt,
      pairId: intent.claimPair.pairId,
      pairRunId: intent.pairRunId,
      evidenceRef: intent.intentDigest,
    });
  }

  bindPair(binding: GraphPairBindingRecord, occurredAt: string): void {
    const boundMs = this.#validateEventTime(occurredAt);
    const relation = this.#relations.get(binding.claimPair.pairId);
    if (relation === undefined || this.#activePair !== binding.claimPair.pairId || relation.intent === null
      || relation.binding !== null) fail("PAIR_BINDING_ORDER", "Pair binding must freeze before submission");
    verifyGraphPairBinding(binding, relation.intent, this.#nodes, this.pins);
    if (binding.boundAtUnix !== Math.floor(boundMs / 1_000)) fail("PAIR_BINDING_TIME", "Pair binding time mismatch");
    relation.binding = binding;
    relation.pairBindingDigest = binding.bindingDigest;
    this.#event({
      kind: "PAIR_BOUND",
      occurredAt,
      pairId: binding.claimPair.pairId,
      pairRunId: binding.pairRunId,
      evidenceRef: binding.bindingDigest,
    });
  }

  validateActivePairEvidence(leaf: GraphPairEvidenceLeaf, occurredAt: string): PairExecutionState {
    if (leaf.graphSessionId !== this.graphSessionId) fail("CROSS_SESSION_LEAF", "Pair leaf belongs to another session");
    const completedMs = this.#validateEventTime(occurredAt);
    const relation = this.#activePair === null ? undefined : this.#relations.get(this.#activePair);
    if (relation === undefined || relation.intent === null || relation.binding === null) {
      fail("PAIR_COMPLETION_ORDER", "Pair evidence is not for the active bound pair");
    }
    if (canonicalGraphJson(leaf.claimPair) !== canonicalGraphJson(relation.claimPair)
      || leaf.execution.executionOrdinal !== relation.executionOrdinal
      || leaf.execution.startedAt !== relation.startedAt
      || leaf.execution.completedAt !== occurredAt
      || assertIsoTime(leaf.execution.completedAt, "PAIR_COMPLETED_TIME") !== completedMs) {
      fail("PAIR_EXECUTION_BINDING", "Leaf chronology does not match the trusted active relation");
    }
    const state = verifyGraphPairEvidenceLeaf(leaf, relation.binding, relation.intent, this.#nodes, this.pins);
    this.#assertFreshPairArtifacts(relation.claimPair.pairId, relation.binding, leaf);
    return state;
  }

  completePair(leaf: GraphPairEvidenceLeaf, occurredAt: string): void {
    const activePair = this.#activePair;
    const relation = activePair === null ? undefined : this.#relations.get(activePair);
    if (relation === undefined || relation.intent === null || relation.binding === null) {
      fail("PAIR_COMPLETION_ORDER", "Pair evidence is not for the active bound pair");
    }
    try {
      const state = this.validateActivePairEvidence(leaf, occurredAt);
      relation.state = state;
      relation.leaf = leaf;
      relation.evidenceDigest = leaf.evidenceDigest;
      relation.governedResultDigest = leaf.governedResultDigest;
      relation.failureDigest = null;
      relation.completedAt = occurredAt;
      this.#event({
        kind: "PAIR_COMPLETED",
        occurredAt,
        pairId: relation.claimPair.pairId,
        pairRunId: relation.pairRunId ?? undefined,
        evidenceRef: leaf.evidenceDigest,
      });
    } catch (error) {
      relation.state = "FAILED";
      relation.leaf = null;
      relation.evidenceDigest = null;
      relation.governedResultDigest = null;
      relation.failureDigest = graphDigest("MordantGraphPairFailure/v1", {
        pairId: relation.claimPair.pairId,
        code: error instanceof ConflictGraphError ? error.code : "UNKNOWN",
      });
      relation.completedAt = occurredAt;
      this.#event({
        kind: "PAIR_FAILED",
        occurredAt,
        pairId: relation.claimPair.pairId,
        pairRunId: relation.pairRunId ?? undefined,
        evidenceRef: relation.failureDigest,
      });
      throw error;
    } finally {
      if (this.#pendingPairQueue[0] === relation.claimPair.pairId) this.#pendingPairQueue.shift();
      this.#activePair = null;
      this.#activePairs = 0;
    }
  }

  /** Independent replay/assembly path used to prove that one bad leaf is isolated. */
  ingestPairEvidence(
    leaf: GraphPairEvidenceLeaf,
    binding: GraphPairBindingRecord,
    intent: GraphPairIntent,
    occurredAt: string,
  ): void {
    if (leaf.graphSessionId !== this.graphSessionId || binding.graphSessionId !== this.graphSessionId
      || intent.graphSessionId !== this.graphSessionId) {
      fail("CROSS_SESSION_LEAF", "Pair evidence belongs to another graph session");
    }
    const replayOccurredMs = this.#validateEventTime(occurredAt);
    // Establish the trusted mutation target from an independently authenticated
    // pre-result intent. Never select a relation from an unverified leaf.
    verifyGraphPairIntent(intent, this.#nodes);
    const relation = this.#relations.get(intent.claimPair.pairId);
    if (relation === undefined) fail("PAIR_UNEXPECTED", "Pair is not in the complete expected set");
    if (canonicalGraphJson(intent.claimPair) !== canonicalGraphJson(relation.claimPair)) {
      fail("PAIR_UNEXPECTED", "Authenticated pair intent does not match the expected relation");
    }
    if (resolvedState(relation.state) || relation.state === "FAILED" || relation.state === "EXPIRED") {
      if (relation.intent !== null && relation.binding !== null && relation.leaf !== null
        && canonicalGraphJson(relation.intent) === canonicalGraphJson(intent)
        && canonicalGraphJson(relation.binding) === canonicalGraphJson(binding)
        && canonicalGraphJson(relation.leaf) === canonicalGraphJson(leaf)) return;
      fail("PAIR_REPLAY_IMMUTABLE", "Resolved pair evidence is create-only");
    }
    if (this.#pendingPairQueue[0] !== relation.claimPair.pairId) {
      fail("PAIR_ADMISSION_SEQUENCE", "Replay evidence is not for the next admission-created pair");
    }
    const expectedExecutionOrdinal = this.#pairExecutionOrdinal + 1;
    try {
      verifyGraphPairBinding(binding, intent, this.#nodes, this.pins);
      if (canonicalGraphJson(binding.claimPair) !== canonicalGraphJson(relation.claimPair)
        || canonicalGraphJson(leaf.claimPair) !== canonicalGraphJson(relation.claimPair)) {
        fail("PAIR_REPLAY_BINDING", "Replay binding or leaf relabelled the authenticated claim pair");
      }
      const state = verifyGraphPairEvidenceLeaf(leaf, binding, intent, this.#nodes, this.pins);
      if (leaf.execution.executionOrdinal !== expectedExecutionOrdinal
        || leaf.execution.completedAt !== occurredAt) {
        fail("PAIR_REPLAY_CHRONOLOGY", "Replay leaf chronology is not contiguous");
      }
      this.#assertFreshPairArtifacts(relation.claimPair.pairId, binding, leaf);
      const candidate: MutableRelation = {
        claimPair: relation.claimPair,
        state,
        intent,
        binding,
        leaf,
        pairRunId: leaf.pairRunId,
        pairIntentDigest: intent.intentDigest,
        pairBindingDigest: binding.bindingDigest,
        evidenceDigest: leaf.evidenceDigest,
        governedResultDigest: leaf.governedResultDigest,
        failureDigest: null,
        executionOrdinal: leaf.execution.executionOrdinal,
        startedAt: leaf.execution.startedAt,
        completedAt: leaf.execution.completedAt,
      };
      this.#relations.set(relation.claimPair.pairId, candidate);
      this.#pairExecutionOrdinal = expectedExecutionOrdinal;
      this.#maxConcurrentPairsObserved = 1;
    } catch (error) {
      relation.state = "FAILED";
      relation.intent = intent;
      relation.binding = null;
      relation.leaf = null;
      relation.pairRunId = intent.pairRunId;
      relation.pairIntentDigest = intent.intentDigest;
      relation.pairBindingDigest = null;
      relation.evidenceDigest = null;
      relation.governedResultDigest = null;
      relation.failureDigest = graphDigest("MordantGraphPairFailure/v1", {
        pairId: relation.claimPair.pairId,
        code: error instanceof ConflictGraphError ? error.code : "UNKNOWN",
      });
      relation.executionOrdinal = expectedExecutionOrdinal;
      relation.startedAt = null;
      relation.completedAt = occurredAt;
      this.#pairExecutionOrdinal = expectedExecutionOrdinal;
      this.#maxConcurrentPairsObserved = 1;
      this.#lastEventMs = replayOccurredMs;
      if (this.#pendingPairQueue[0] === relation.claimPair.pairId) this.#pendingPairQueue.shift();
      throw error;
    }
    this.#lastEventMs = replayOccurredMs;
    if (this.#pendingPairQueue[0] === relation.claimPair.pairId) this.#pendingPairQueue.shift();
  }

  failActivePair(code: string, occurredAt: string): void {
    if (this.#activePair === null) fail("PAIR_ACTIVE", "No active pair to fail");
    const relation = this.#relations.get(this.#activePair);
    if (relation === undefined) fail("PAIR_ACTIVE", "Active pair state missing");
    this.#validateEventTime(occurredAt);
    relation.state = "FAILED";
    relation.failureDigest = graphDigest("MordantGraphPairFailure/v1", { pairId: relation.claimPair.pairId, code });
    relation.completedAt = occurredAt;
    this.#event({ kind: "PAIR_FAILED", occurredAt, pairId: relation.claimPair.pairId, pairRunId: relation.pairRunId ?? undefined, evidenceRef: relation.failureDigest });
    if (this.#pendingPairQueue[0] === relation.claimPair.pairId) this.#pendingPairQueue.shift();
    this.#activePair = null;
    this.#activePairs = 0;
  }

  expirePending(occurredAt: string): void {
    if (this.#activePair !== null) fail("PAIR_ACTIVE", "An active pair must finish or fail before session expiry");
    const atUnix = Math.floor(assertIsoTime(occurredAt, "GRAPH_EXPIRY_TIME") / 1_000);
    if (!Number.isFinite(atUnix) || atUnix <= this.expiresAtUnix) fail("GRAPH_NOT_EXPIRED", "Session has not expired");
    for (const relation of this.#relations.values()) {
      if (relation.state === "PENDING") {
        relation.state = "EXPIRED";
        relation.completedAt = occurredAt;
        this.#event({ kind: "PAIR_EXPIRED", occurredAt, pairId: relation.claimPair.pairId }, true);
      }
    }
    this.#pendingPairQueue = [];
  }

  publicNodes(): readonly GraphClaimAuthorization[] {
    return [...this.#nodes].sort((left, right) => left.claimId.localeCompare(right.claimId));
  }

  chronology(): Readonly<{
    schemaVersion: typeof GRAPH_CHRONOLOGY_SCHEMA;
    graphSessionId: Sha256Digest;
    events: readonly GraphChronologyEvent[];
    digest: Sha256Digest;
  }> {
    const value = {
      schemaVersion: GRAPH_CHRONOLOGY_SCHEMA,
      graphSessionId: this.graphSessionId,
      events: [...this.#chronology],
    } as const;
    return { ...value, digest: graphDigest(CHRONOLOGY_DIGEST_DOMAIN, value) };
  }

  relations(): readonly PairRelationRecord[] {
    const expected = enumerateCanonicalPairs(this.publicNodes());
    return expected.map((pair) => {
      const relation = this.#relations.get(pair.pairId);
      if (relation === undefined) fail("PAIR_LEDGER", "Expected pair relation missing");
      return relationPublic(relation);
    });
  }

  aggregate(): AggregateManifest {
    const nodes = this.publicNodes();
    const expectedPairs = enumerateCanonicalPairs(nodes);
    const pairRelations = this.relations();
    const complete = this.#sealed && nodes.length === N3_EXPECTED_CLAIM_COUNT
      && expectedPairs.length === N3_EXPECTED_PAIR_COUNT && pairRelations.every((relation) => resolvedState(relation.state));
    const completeness: GraphCompleteness = complete ? "COMPLETE" : "PARTIAL";
    const reviewState: GraphReviewState = complete ? "REVIEW_READY" : "AWAITING_EVIDENCE";
    const chronology = this.chronology();
    const completedIntervals = pairRelations.filter((relation) => relation.startedAt !== null && relation.completedAt !== null)
      .sort((left, right) => (left.executionOrdinal ?? 0) - (right.executionOrdinal ?? 0));
    const strictlySequential = completedIntervals.every((relation, index) => index === 0
      || Date.parse(completedIntervals[index - 1].completedAt ?? "") <= Date.parse(relation.startedAt ?? ""));
    if (this.#maxConcurrentPairsObserved > 1 || !strictlySequential) fail("PAIR_SEQUENTIAL", "Pair execution chronology overlapped");
    const globalAllClear = complete ? claimGlobalAllClear(completeness, pairRelations) : null;
    const trueConflictEdges = pairRelations.filter((relation) => relation.state === "CONFLICT").map((relation) => relation.claimPair);
    const body = {
      schemaVersion: GRAPH_AGGREGATE_SCHEMA,
      graphSessionId: this.graphSessionId,
      receivableIdentity: this.receivableIdentity,
      issuedAtUnix: this.issuedAtUnix,
      expiresAtUnix: this.expiresAtUnix,
      expectedClaimCount: N3_EXPECTED_CLAIM_COUNT,
      nodesSealed: this.#sealed,
      nodes,
      expectedPairs,
      pairRelations,
      pins: this.pins,
      chronologyDigest: chronology.digest,
      completeness,
      reviewState,
      globalAllClear,
      trueConflictEdges,
      execution: {
        scheduling: "SEQUENTIAL",
        workerArchitecture: "UNCHANGED_SINGLE_SLOT",
        maxConcurrentPairsObserved: this.#maxConcurrentPairsObserved,
        strictlySequential,
      },
      retention: {
        scope: "OPERATOR_PRIVATE",
        exactIntervalsRetained: true,
        saltRetained: true,
        authorizationPrivateKeyRetained: false,
        authorizationPrivateKeyLifetime: "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED",
        authorizationPrivateKeyZeroizationClaimed: false,
        authorizationPrivateKeyGarbageCollectionTimingClaimed: false,
        automaticTerminalDeletion: false,
        secureErasureClaimed: false,
        deletionTrigger: "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY",
        publicEvidenceContainsOpenings: false,
      },
      reviewHandoff: {
        automaticIncidentCreation: false,
        policyOrHumanReviewRequired: true,
        evidenceReferences: pairRelations.flatMap((relation) => relation.evidenceDigest === null ? [] : [relation.evidenceDigest]),
      },
      sideEffects: {
        recourseOpened: false,
        adapterDeployed: false,
        cureWindowCreated: false,
        settlementExecuted: false,
        tokensMoved: false,
      },
    } as const;
    return { ...body, aggregateRoot: graphDigest(AGGREGATE_ROOT_DOMAIN, body) };
  }
}

export type OperatorGraphProjection = Readonly<{
  scope: "OPERATOR";
  graphSessionId: Sha256Digest;
  aggregateRoot: Sha256Digest;
  completeness: GraphCompleteness;
  reviewState: GraphReviewState;
  relations: readonly PairRelationRecord[];
}>;

export type ClaimantGraphProjection = Readonly<{
  scope: "CLAIMANT";
  graphSessionId: Sha256Digest;
  claimId: GraphClaimId;
  aggregateRoot: Sha256Digest;
  completeness: GraphCompleteness;
  relations: readonly PairRelationRecord[];
}>;

export type PublicGraphProjection = Readonly<{
  scope: "PUBLIC";
  graphSessionId: Sha256Digest;
  aggregateRoot: Sha256Digest;
  completeness: GraphCompleteness;
  reviewState: GraphReviewState;
  nodeCount: number;
  expectedPairCount: number;
  resolvedPairCount: number;
  executionSourceCommit: string;
}>;

export type ConflictGraphProjections = Readonly<{
  schemaVersion: typeof GRAPH_PROJECTIONS_SCHEMA;
  operator: OperatorGraphProjection;
  claimants: readonly ClaimantGraphProjection[];
  public: PublicGraphProjection;
}>;

function assertAggregateRoot(aggregate: AggregateManifest): void {
  const { aggregateRoot, ...body } = aggregate;
  if (aggregateRoot !== graphDigest(AGGREGATE_ROOT_DOMAIN, body)) fail("AGGREGATE_ROOT", "Aggregate root mismatch");
}

export function projectOperatorGraph(aggregate: AggregateManifest): OperatorGraphProjection {
  assertAggregateRoot(aggregate);
  return {
    scope: "OPERATOR",
    graphSessionId: aggregate.graphSessionId,
    aggregateRoot: aggregate.aggregateRoot,
    completeness: aggregate.completeness,
    reviewState: aggregate.reviewState,
    relations: aggregate.pairRelations,
  };
}

export function projectClaimantGraph(
  aggregate: AggregateManifest,
  authenticatedClaimId: GraphClaimId,
): ClaimantGraphProjection {
  assertAggregateRoot(aggregate);
  assertSha256(authenticatedClaimId, "CLAIMANT_ID");
  if (!aggregate.nodes.some((node) => node.claimId === authenticatedClaimId)) {
    fail("CLAIMANT_MEMBERSHIP", "Authenticated claim is not a member of this graph session");
  }
  return {
    scope: "CLAIMANT",
    graphSessionId: aggregate.graphSessionId,
    claimId: authenticatedClaimId,
    aggregateRoot: aggregate.aggregateRoot,
    completeness: aggregate.completeness,
    relations: aggregate.pairRelations.filter((relation) => (
      relation.claimPair.leftClaimId === authenticatedClaimId || relation.claimPair.rightClaimId === authenticatedClaimId
    )),
  };
}

export function projectPublicGraph(aggregate: AggregateManifest): PublicGraphProjection {
  assertAggregateRoot(aggregate);
  return {
    scope: "PUBLIC",
    graphSessionId: aggregate.graphSessionId,
    aggregateRoot: aggregate.aggregateRoot,
    completeness: aggregate.completeness,
    reviewState: aggregate.reviewState,
    nodeCount: aggregate.nodes.length,
    expectedPairCount: aggregate.expectedPairs.length,
    resolvedPairCount: aggregate.pairRelations.filter((relation) => resolvedState(relation.state)).length,
    executionSourceCommit: aggregate.pins.executionSourceCommit,
  };
}

/** Audit bundle only. Deliver claimant views through projectClaimantGraph. */
export function projectConflictGraph(aggregate: AggregateManifest): ConflictGraphProjections {
  return {
    schemaVersion: GRAPH_PROJECTIONS_SCHEMA,
    operator: projectOperatorGraph(aggregate),
    claimants: aggregate.nodes.map((node) => projectClaimantGraph(aggregate, node.claimId)),
    public: projectPublicGraph(aggregate),
  };
}

export function verifyAggregateManifest(
  aggregate: AggregateManifest,
  chronology: ReturnType<ReceivableConflictSession["chronology"]>,
  leaves: readonly GraphPairEvidenceLeaf[],
): void {
  assertExactKeys(aggregate, [
    "schemaVersion", "graphSessionId", "receivableIdentity", "issuedAtUnix", "expiresAtUnix", "expectedClaimCount",
    "nodesSealed", "nodes", "expectedPairs", "pairRelations", "pins", "chronologyDigest", "completeness", "reviewState",
    "globalAllClear", "trueConflictEdges", "execution", "retention", "reviewHandoff", "sideEffects", "aggregateRoot",
  ], "AGGREGATE_FIELDS");
  assertExactKeys(aggregate.execution, [
    "scheduling", "workerArchitecture", "maxConcurrentPairsObserved", "strictlySequential",
  ], "AGGREGATE_EXECUTION_FIELDS");
  assertExactKeys(aggregate.retention, [
    "scope", "exactIntervalsRetained", "saltRetained", "authorizationPrivateKeyRetained",
    "authorizationPrivateKeyLifetime", "authorizationPrivateKeyZeroizationClaimed",
    "authorizationPrivateKeyGarbageCollectionTimingClaimed", "automaticTerminalDeletion", "secureErasureClaimed",
    "deletionTrigger", "publicEvidenceContainsOpenings",
  ], "AGGREGATE_RETENTION_FIELDS");
  assertExactKeys(aggregate.reviewHandoff, [
    "automaticIncidentCreation", "policyOrHumanReviewRequired", "evidenceReferences",
  ], "AGGREGATE_HANDOFF_FIELDS");
  assertExactKeys(aggregate.sideEffects, [
    "recourseOpened", "adapterDeployed", "cureWindowCreated", "settlementExecuted", "tokensMoved",
  ], "AGGREGATE_SIDE_EFFECT_FIELDS");
  if (aggregate.schemaVersion !== GRAPH_AGGREGATE_SCHEMA || aggregate.expectedClaimCount !== N3_EXPECTED_CLAIM_COUNT) {
    fail("AGGREGATE_SCHEMA", "Unexpected aggregate schema or claim cardinality");
  }
  assertGraphPins(aggregate.pins);
  if (aggregate.graphSessionId !== chronology.graphSessionId || aggregate.receivableIdentity !== aggregate.pins.assetIdentity
    || !Number.isSafeInteger(aggregate.issuedAtUnix) || aggregate.issuedAtUnix <= 0
    || !Number.isSafeInteger(aggregate.expiresAtUnix) || aggregate.expiresAtUnix <= aggregate.issuedAtUnix) {
    fail("AGGREGATE_SESSION", "Aggregate session or receivable binding mismatch");
  }
  const nodes = [...aggregate.nodes].sort((left, right) => left.claimId.localeCompare(right.claimId));
  if (canonicalGraphJson(nodes) !== canonicalGraphJson(aggregate.nodes)) {
    fail("AGGREGATE_NODE_ORDER", "Aggregate node set is not canonical");
  }
  const nodesById = nodeMap(nodes);
  if (nodes.length !== N3_EXPECTED_CLAIM_COUNT || nodesById.size !== N3_EXPECTED_CLAIM_COUNT
    || nodes.some((node) => node.graphSessionId !== aggregate.graphSessionId || node.receivableIdentity !== aggregate.receivableIdentity)) {
    fail("AGGREGATE_NODES", "Aggregate does not contain the complete bound node set");
  }
  const expectedPairs = enumerateCanonicalPairs(nodes);
  if (canonicalGraphJson(expectedPairs) !== canonicalGraphJson(aggregate.expectedPairs)
    || aggregate.pairRelations.length !== N3_EXPECTED_PAIR_COUNT) {
    fail("AGGREGATE_PAIRS", "Aggregate expected-pair set is incomplete or non-canonical");
  }
  const leafByPair = new Map(leaves.map((leaf) => [leaf.claimPair.pairId, leaf]));
  const expectedPairIds = new Set(expectedPairs.map((pair) => pair.pairId));
  if (leafByPair.size !== leaves.length || leaves.some((leaf) => !expectedPairIds.has(leaf.claimPair.pairId))) {
    fail("AGGREGATE_LEAVES", "Duplicate or unexpected pair evidence leaf");
  }
  for (let index = 0; index < expectedPairs.length; index += 1) {
    const pair = expectedPairs[index];
    const relation = aggregate.pairRelations[index];
    assertExactKeys(relation, [
      "claimPair", "state", "pairRunId", "pairIntentDigest", "pairBindingDigest", "evidenceDigest",
      "governedResultDigest", "failureDigest", "executionOrdinal", "startedAt", "completedAt",
    ], "AGGREGATE_RELATION_FIELDS");
    assertCanonicalPair(relation.claimPair, "AGGREGATE_RELATION_PAIR");
    if (canonicalGraphJson(relation.claimPair) !== canonicalGraphJson(pair)) fail("AGGREGATE_RELATION_ORDER", "Pair relation order changed");
    const leaf = leafByPair.get(pair.pairId);
    if (resolvedState(relation.state)) {
      if (leaf === undefined || leaf.graphSessionId !== aggregate.graphSessionId || leaf.state !== relation.state
        || leaf.evidenceDigest !== relation.evidenceDigest || leaf.governedResultDigest !== relation.governedResultDigest
        || leaf.pairRunId !== relation.pairRunId || leaf.pairBindingDigest !== relation.pairBindingDigest
        || leaf.execution.executionOrdinal !== relation.executionOrdinal
        || leaf.execution.startedAt !== relation.startedAt || leaf.execution.completedAt !== relation.completedAt
        || relation.failureDigest !== null) {
        fail("AGGREGATE_RELATION_EVIDENCE", "Resolved relation does not bind its independently retained leaf");
      }
    } else if (leaf !== undefined || relation.evidenceDigest !== null || relation.governedResultDigest !== null) {
      fail("AGGREGATE_UNRESOLVED_EVIDENCE", "Unresolved relation cannot claim complete evidence");
    }
  }
  const complete = aggregate.nodesSealed
    && aggregate.nodes.length === N3_EXPECTED_CLAIM_COUNT
    && aggregate.expectedPairs.length === N3_EXPECTED_PAIR_COUNT
    && aggregate.pairRelations.every((relation) => resolvedState(relation.state));
  if (complete && leaves.length !== N3_EXPECTED_PAIR_COUNT) {
    fail("AGGREGATE_LEAVES", "Complete aggregate requires exactly three retained leaves");
  }
  const completeness: GraphCompleteness = complete ? "COMPLETE" : "PARTIAL";
  if (aggregate.completeness !== completeness
    || aggregate.reviewState !== (complete ? "REVIEW_READY" : "AWAITING_EVIDENCE")
    || aggregate.globalAllClear !== (complete ? claimGlobalAllClear(completeness, aggregate.pairRelations) : null)) {
    fail("AGGREGATE_COMPLETENESS", "Aggregate completeness/review/all-clear derivation mismatch");
  }
  const trueEdges = aggregate.pairRelations.filter((relation) => relation.state === "CONFLICT").map((relation) => relation.claimPair);
  if (canonicalGraphJson(trueEdges) !== canonicalGraphJson(aggregate.trueConflictEdges)) {
    fail("AGGREGATE_TRUE_EDGES", "Visual graph contains a false or missing conflict edge");
  }
  const chronologyValue = {
    schemaVersion: chronology.schemaVersion,
    graphSessionId: chronology.graphSessionId,
    events: chronology.events,
  };
  if (chronology.digest !== graphDigest(CHRONOLOGY_DIGEST_DOMAIN, chronologyValue)
    || chronology.digest !== aggregate.chronologyDigest
    || chronology.events.some((event, index) => event.ordinal !== index + 1)) {
    fail("AGGREGATE_CHRONOLOGY", "Aggregate chronology binding mismatch");
  }
  let priorEventMs = aggregate.issuedAtUnix * 1_000;
  for (const event of chronology.events) {
    const eventMs = assertIsoTime(event.occurredAt, "AGGREGATE_EVENT_TIME");
    if (eventMs < priorEventMs || (event.kind !== "PAIR_EXPIRED" && Math.floor(eventMs / 1_000) > aggregate.expiresAtUnix)) {
      fail("AGGREGATE_EVENT_TIME", "Chronology is not monotonic within the graph lifetime");
    }
    priorEventMs = eventMs;
  }
  const executionLeaves = leaves.slice().sort((left, right) => left.execution.executionOrdinal - right.execution.executionOrdinal);
  if (complete) {
    const admissions = chronology.events.filter((event) => event.kind === "CLAIM_ADMITTED");
    if (admissions.length !== 3 || admissions.some((event) => event.claimId === undefined)) {
      fail("AGGREGATE_ADMISSION_SEQUENCE", "Complete graph must retain exactly three admissions");
    }
    const admissionIds = admissions.map((event) => event.claimId as GraphClaimId);
    if (new Set(admissionIds).size !== N3_EXPECTED_CLAIM_COUNT
      || admissionIds.some((claimId) => !nodesById.has(claimId))) {
      fail("AGGREGATE_ADMISSION_SEQUENCE", "Admission chronology does not name the aggregate node set");
    }
    const admissionPairs = [
      canonicalClaimPair(admissionIds[0], admissionIds[1]),
      canonicalClaimPair(admissionIds[0], admissionIds[2]),
      canonicalClaimPair(admissionIds[1], admissionIds[2]),
    ];
    const expectedKinds: readonly GraphChronologyEvent["kind"][] = [
      "CLAIM_ADMITTED", "CLAIM_ADMITTED", "PAIR_INTENT_FROZEN", "PAIR_BOUND", "PAIR_COMPLETED",
      "CLAIM_ADMITTED", "ADMISSIONS_SEALED", "PAIR_INTENT_FROZEN", "PAIR_BOUND", "PAIR_COMPLETED",
      "PAIR_INTENT_FROZEN", "PAIR_BOUND", "PAIR_COMPLETED",
    ];
    if (chronology.events.length !== expectedKinds.length
      || chronology.events.some((event, index) => event.kind !== expectedKinds[index])
      || canonicalGraphJson(admissions.map((event) => event.newPairIds ?? []))
        !== canonicalGraphJson([[], [admissionPairs[0].pairId], [admissionPairs[1].pairId, admissionPairs[2].pairId]])) {
      fail("AGGREGATE_ADMISSION_SEQUENCE", "Required A then B/AB then C/AC/BC chronology changed");
    }
    const pairEventOffsets = [2, 7, 10] as const;
    for (let index = 0; index < pairEventOffsets.length; index += 1) {
      const start = pairEventOffsets[index];
      const leaf = executionLeaves[index];
      const relation = aggregate.pairRelations.find((entry) => entry.claimPair.pairId === leaf.claimPair.pairId);
      if (leaf.claimPair.pairId !== admissionPairs[index].pairId
        || relation === undefined
        || chronology.events[start].pairId !== admissionPairs[index].pairId
        || chronology.events[start + 1].pairId !== admissionPairs[index].pairId
        || chronology.events[start + 2].pairId !== admissionPairs[index].pairId
        || chronology.events[start].pairRunId !== leaf.pairRunId
        || chronology.events[start + 1].pairRunId !== leaf.pairRunId
        || chronology.events[start + 2].pairRunId !== leaf.pairRunId
        || chronology.events[start].evidenceRef !== relation.pairIntentDigest
        || chronology.events[start + 1].evidenceRef !== relation.pairBindingDigest
        || chronology.events[start + 2].evidenceRef !== leaf.evidenceDigest
        || chronology.events[start].occurredAt !== leaf.execution.startedAt
        || chronology.events[start + 2].occurredAt !== leaf.execution.completedAt) {
        fail("AGGREGATE_PAIR_SEQUENCE", "Pair leaf is not bound to the required admission chronology");
      }
    }
  }
  const uniqueLeafFields = [
    executionLeaves.map((leaf) => leaf.pairRunId),
    executionLeaves.map((leaf) => leaf.caseId),
    executionLeaves.map((leaf) => leaf.caseBindingDigest),
    executionLeaves.map((leaf) => leaf.evaluatedArtifactDigest),
    executionLeaves.map((leaf) => leaf.governedResultDigest),
    executionLeaves.map((leaf) => leaf.governedResult.releaseAuthorityId),
    executionLeaves.map((leaf) => leaf.governedResult.releaseAuthorityPublicKey),
    executionLeaves.map((leaf) => leaf.governedResult.resultCiphertextDigest),
    executionLeaves.map((leaf) => leaf.governedResult.resultCiphertextCommitment),
  ];
  const executionOrdinals = executionLeaves.map((leaf) => leaf.execution.executionOrdinal);
  if (uniqueLeafFields.some((values) => new Set(values).size !== values.length)
    || new Set(executionLeaves.flatMap((leaf) => [...leaf.participantArtifactDigests])).size !== executionLeaves.length * 2
    || new Set(executionOrdinals).size !== executionOrdinals.length
    || executionOrdinals.some((ordinal) => !Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > N3_EXPECTED_PAIR_COUNT)
    || (complete && canonicalGraphJson(executionOrdinals) !== canonicalGraphJson([1, 2, 3]))) {
    fail("AGGREGATE_PAIR_FRESHNESS", "Pair run/key/artifact/result freshness or ordinal uniqueness failed");
  }
  const strictlySequential = executionLeaves.every((leaf, index) => index === 0
    || Date.parse(executionLeaves[index - 1].execution.completedAt) <= Date.parse(leaf.execution.startedAt));
  if (aggregate.execution.scheduling !== "SEQUENTIAL"
    || aggregate.execution.workerArchitecture !== "UNCHANGED_SINGLE_SLOT"
    || aggregate.execution.maxConcurrentPairsObserved !== (
      aggregate.pairRelations.some((relation) => relation.executionOrdinal !== null) ? 1 : 0
    )
    || aggregate.execution.strictlySequential !== strictlySequential || !strictlySequential) {
    fail("AGGREGATE_EXECUTION", "Sequential single-slot execution proof mismatch");
  }
  if (aggregate.retention.scope !== "OPERATOR_PRIVATE" || !aggregate.retention.exactIntervalsRetained
    || !aggregate.retention.saltRetained || aggregate.retention.authorizationPrivateKeyRetained
    || aggregate.retention.authorizationPrivateKeyLifetime !== "CALLER_MANAGED_PROCESS_MEMORY_UNTIL_REFERENCES_RELEASED"
    || aggregate.retention.authorizationPrivateKeyZeroizationClaimed
    || aggregate.retention.authorizationPrivateKeyGarbageCollectionTimingClaimed
    || aggregate.retention.automaticTerminalDeletion
    || aggregate.retention.secureErasureClaimed || aggregate.retention.publicEvidenceContainsOpenings
    || aggregate.retention.deletionTrigger !== "EXPLICIT_OPERATOR_ACTION_AFTER_REVIEW_OR_EXPIRY") {
    fail("AGGREGATE_RETENTION", "Aggregate retention disclosure changed");
  }
  const evidenceReferences = aggregate.pairRelations.flatMap((relation) => relation.evidenceDigest === null ? [] : [relation.evidenceDigest]);
  if (aggregate.reviewHandoff.automaticIncidentCreation || !aggregate.reviewHandoff.policyOrHumanReviewRequired
    || canonicalGraphJson(aggregate.reviewHandoff.evidenceReferences) !== canonicalGraphJson(evidenceReferences)
    || aggregate.sideEffects.recourseOpened || aggregate.sideEffects.adapterDeployed
    || aggregate.sideEffects.cureWindowCreated || aggregate.sideEffects.settlementExecuted || aggregate.sideEffects.tokensMoved) {
    fail("AGGREGATE_RECOURSE_BOUNDARY", "Aggregate crossed the review-only boundary");
  }
  assertAggregateRoot(aggregate);
}

export function verifyConflictGraphProjections(
  aggregate: AggregateManifest,
  projections: ConflictGraphProjections,
): void {
  if (projections.schemaVersion !== GRAPH_PROJECTIONS_SCHEMA
    || canonicalGraphJson(projections) !== canonicalGraphJson(projectConflictGraph(aggregate))) {
    fail("GRAPH_PROJECTIONS", "Privacy-scoped projections are not the canonical graph projections");
  }
  const publicText = canonicalGraphJson(projections.public);
  if (/activeFrom|activeUntil|salt|claimCommitment|claimId|pairId|conflict/iu.test(publicText)) {
    fail("PUBLIC_PROJECTION_PRIVACY", "Public graph projection contains claim or pair facts");
  }
  for (const claimant of projections.claimants) {
    if (claimant.relations.some((relation) => relation.claimPair.leftClaimId !== claimant.claimId
      && relation.claimPair.rightClaimId !== claimant.claimId)) {
      fail("CLAIMANT_PROJECTION_SCOPE", "Claimant projection contains an unrelated pair");
    }
  }
}

export function newGraphSessionId(): Sha256Digest {
  return sha256Bytes(randomBytes(32));
}

export function participantReference(): Sha256Digest {
  // This is an unlinkable experiment-local handle, not a wallet ownership proof.
  return graphDigest("MordantGraphParticipantReference/v1", { entropy: randomBytes(32).toString("base64") });
}
