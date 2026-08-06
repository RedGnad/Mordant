/**
 * Typed bridge payload from a verified governed release to MordantRecourseAdapter.
 *
 * The only input that decides anything here is the Ed25519-signed governed result.
 * The terminal Boolean, the digests, the payouts and the holder addresses are all
 * derived from material that has already been verified; nothing is accepted from a
 * browser, and there is no parameter through which a caller could supply a Boolean.
 *
 * No adapter address is hard-coded. The verifying contract is supplied by the
 * caller at the moment a payload is built, so this module cannot bind a payload to
 * a deployment nobody has reviewed.
 *
 * Compatibility is enforced, not assumed. The adapter pins five immutable values,
 * and a payload is emitted only when every one of them reconciles with the
 * verified governed result under a stated interpretation. Where the adapter pins a
 * keccak label hash and the governed result carries a sha256 digest, that is a
 * DIFFERENT VALUE, not a formatting difference, and this module refuses to paper
 * over it. See `docs/governed-recourse-bridge.md`.
 */

import { encodeAbiParameters, keccak256, toHex, type Hex } from "viem";

import type { Sha256Digest } from "./cleanverse-asset";
import { digestToBytes32 } from "./participant-authorization";

export const GOVERNED_BRIDGE_SCHEMA = "mordant.governed-recourse-bridge/1" as const;
export const RECOURSE_ADAPTER_ABI_VERSION = "MordantRecourseAdapter/1" as const;

export const RELEASE_TYPE_STRING =
  "GovernedRelease(bytes32 runId,bytes32 fheCaseId,bytes32 caseBindingDigest,bytes32 assetIdentityDigest,"
  + "bytes32 governedResultDigest,bytes32 resultCiphertextDigest,bytes32 participantArtifactDigestA,"
  + "bytes32 participantArtifactDigestB,address holderA,address holderB,uint256 payoutA,uint256 payoutB,"
  + "bool conflict,bytes32 releaseAuthorityId,bytes32 releaseMode,bytes32 circuitHash,"
  + "bytes32 parameterFingerprint,uint256 nonce,uint64 issuedAt,uint64 expiry)";

export const RELEASE_TYPEHASH = keccak256(toHex(RELEASE_TYPE_STRING));

export const GOVERNED_RELEASE_TYPES = {
  GovernedRelease: [
    { name: "runId", type: "bytes32" },
    { name: "fheCaseId", type: "bytes32" },
    { name: "caseBindingDigest", type: "bytes32" },
    { name: "assetIdentityDigest", type: "bytes32" },
    { name: "governedResultDigest", type: "bytes32" },
    { name: "resultCiphertextDigest", type: "bytes32" },
    { name: "participantArtifactDigestA", type: "bytes32" },
    { name: "participantArtifactDigestB", type: "bytes32" },
    { name: "holderA", type: "address" },
    { name: "holderB", type: "address" },
    { name: "payoutA", type: "uint256" },
    { name: "payoutB", type: "uint256" },
    { name: "conflict", type: "bool" },
    { name: "releaseAuthorityId", type: "bytes32" },
    { name: "releaseMode", type: "bytes32" },
    { name: "circuitHash", type: "bytes32" },
    { name: "parameterFingerprint", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiry", type: "uint64" },
  ],
} as const;

export class GovernedBridgeError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "GovernedBridgeError";
  }
}

function fail(code: string, message: string): never {
  throw new GovernedBridgeError(code, message);
}

/** The five immutables the deployed adapter checks a payload against. */
export type AdapterPins = Readonly<{
  address: `0x${string}`;
  chainId: number;
  assetIdentityDigest: Hex;
  releaseAuthorityId: Hex;
  releaseMode: Hex;
  circuitHash: Hex;
  parameterFingerprint: Hex;
}>;

/**
 * How the adapter's pinned authority identity relates to the real governed one.
 *
 * Adapter V2 pins `expectedGovernedReleaseAuthorityId` to the real Ed25519
 * governed authority, so `PINS_GOVERNED_AUTHORITY` is the production
 * interpretation and the only one the executor will sign under.
 *
 * `PINS_SEPARATE_BRIDGE_ATTESTOR` survives only to describe the superseded V1
 * deployment, whose authority pin was `keccak256` of an invented label string. It
 * is retained so the superseded deployment can still be described accurately, and
 * is refused by `assertProductionInterpretation`.
 */
export const AUTHORITY_INTERPRETATIONS = [
  "PINS_GOVERNED_AUTHORITY",
  "PINS_SEPARATE_BRIDGE_ATTESTOR",
] as const;
export type AuthorityInterpretation = (typeof AUTHORITY_INTERPRETATIONS)[number];

/**
 * The superseded V1 deployment. Recorded so a configuration pointing at it is
 * refused by name rather than merely failing a digest comparison later.
 */
export const SUPERSEDED_ADAPTER_ADDRESS = "0x27677c837287b060D285d5C90096f06fBe675938" as const;

export function assertProductionInterpretation(interpretation: AuthorityInterpretation): void {
  if (interpretation !== "PINS_GOVERNED_AUTHORITY") {
    fail(
      "SUPERSEDED_INTERPRETATION",
      "Only an adapter pinning the governed Ed25519 release authority may be used in production",
    );
  }
}

export type VerifiedGovernedRelease = Readonly<{
  runId: string;
  fheCaseId: Sha256Digest;
  caseBindingDigest: Sha256Digest;
  assetIdentity: Sha256Digest;
  governedResultDigest: Sha256Digest;
  resultCiphertextDigest: Sha256Digest;
  participantArtifactDigests: readonly [Sha256Digest, Sha256Digest];
  circuitDigest: Sha256Digest;
  parameterFingerprint: Sha256Digest;
  releaseAuthorityId: Sha256Digest;
  releaseMode: "governed-decryptor-v1";
  /** The signed Boolean. The only source of a terminal outcome. */
  conflict: boolean;
}>;

export type BridgeParticipants = Readonly<{
  holderA: `0x${string}`;
  holderB: `0x${string}`;
  payoutA: bigint;
  payoutB: bigint;
}>;

export type GovernedBridgePayload = Readonly<{
  schemaVersion: typeof GOVERNED_BRIDGE_SCHEMA;
  abiVersion: typeof RECOURSE_ADAPTER_ABI_VERSION;
  authorityInterpretation: AuthorityInterpretation;
  domain: Readonly<{ name: string; version: string; chainId: number; verifyingContract: `0x${string}` }>;
  primaryType: "GovernedRelease";
  types: typeof GOVERNED_RELEASE_TYPES;
  message: Readonly<{
    runId: Hex; fheCaseId: Hex; caseBindingDigest: Hex; assetIdentityDigest: Hex;
    governedResultDigest: Hex; resultCiphertextDigest: Hex;
    participantArtifactDigestA: Hex; participantArtifactDigestB: Hex;
    holderA: `0x${string}`; holderB: `0x${string}`;
    payoutA: bigint; payoutB: bigint; conflict: boolean;
    releaseAuthorityId: Hex; releaseMode: Hex; circuitHash: Hex; parameterFingerprint: Hex;
    nonce: bigint; issuedAt: bigint; expiry: bigint;
  }>;
}>;

/** The adapter's own run identity: the case run id, hashed into bytes32. */
export function bridgeRunId(runId: string): Hex {
  return keccak256(toHex(runId));
}

/**
 * Reconciles the verified governed result against what the adapter actually pins.
 *
 * Every mismatch is returned rather than thrown one at a time, so a reviewer sees
 * the whole picture instead of fixing them one deployment at a time.
 */
export function reconcileAdapter(
  release: VerifiedGovernedRelease,
  pins: AdapterPins,
  interpretation: AuthorityInterpretation,
): readonly string[] {
  const problems: string[] = [];
  if (pins.assetIdentityDigest.toLowerCase() !== digestToBytes32(release.assetIdentity)) {
    problems.push("assetIdentityDigest: the adapter is pinned to a different receivable");
  }
  // `releaseMode` keeps its documented label convention: the governed result names
  // it as a string and the adapter pins keccak of that string.
  if (pins.releaseMode.toLowerCase() !== keccak256(toHex(release.releaseMode))) {
    problems.push("releaseMode: the adapter pin is not keccak of the governed release mode");
  }
  // Circuit and parameters are content-derived and nothing else. A keccak of the
  // circuit id or the profile id names the circuit without committing to it, and
  // Adapter V2 pins the governed digests, so the label form is not accepted here.
  if (pins.circuitHash.toLowerCase() !== digestToBytes32(release.circuitDigest)) {
    problems.push("circuitHash: the adapter pin is not the governed content-derived circuit digest");
  }
  if (pins.parameterFingerprint.toLowerCase() !== digestToBytes32(release.parameterFingerprint)) {
    problems.push("parameterFingerprint: the adapter pin is not the governed content-derived fingerprint");
  }
  if (interpretation === "PINS_GOVERNED_AUTHORITY"
    && pins.releaseAuthorityId.toLowerCase() !== digestToBytes32(release.releaseAuthorityId)) {
    problems.push("releaseAuthorityId: the adapter does not pin the governed Ed25519 release authority");
  }
  if (pins.address.toLowerCase() === SUPERSEDED_ADAPTER_ADDRESS.toLowerCase()) {
    problems.push("address: this is the superseded adapter and must not be used");
  }
  return Object.freeze(problems);
}

export type BridgeInput = Readonly<{
  release: VerifiedGovernedRelease;
  participants: BridgeParticipants;
  pins: AdapterPins;
  interpretation: AuthorityInterpretation;
  nonce: bigint;
  issuedAt: number;
  expiry: number;
}>;

/**
 * Builds the typed payload.
 *
 * This is deliberately a pure encoding function. A TypeScript literal such as
 * `{ governedSignatureVerified: true }` is not proof of an Ed25519 verification,
 * so proof ownership belongs at the server-side authorization boundary rather
 * than in a forgeable input flag. The bridge executor only calls this function
 * after it has loaded and reconciled the committed handoff itself.
 */
export function buildGovernedBridgePayload(input: BridgeInput): GovernedBridgePayload {
  const { release, participants, pins, interpretation } = input;
  if (typeof release.conflict !== "boolean") fail("BOOLEAN", "The terminal Boolean must come from the governed result");

  const problems = reconcileAdapter(release, pins, interpretation);
  if (problems.length > 0) {
    fail("ADAPTER_INCOMPATIBLE", `The deployed adapter cannot consume this governed release: ${problems.join("; ")}`);
  }
  if (!Number.isSafeInteger(input.issuedAt) || !Number.isSafeInteger(input.expiry) || input.expiry <= input.issuedAt) {
    fail("WINDOW", "The bridge window must be a forward interval");
  }
  // A refused case pays nothing. The adapter enforces this too; refusing here
  // means a bad payload is never signed in the first place.
  if (!release.conflict && (participants.payoutA !== 0n || participants.payoutB !== 0n)) {
    fail("PAYOUT_ON_NO_CONFLICT", "A signed false Boolean cannot carry a payout");
  }
  if (release.conflict && participants.payoutA + participants.payoutB === 0n) {
    fail("PAYOUT_MISSING", "A signed true Boolean must carry a payout");
  }

  return Object.freeze({
    schemaVersion: GOVERNED_BRIDGE_SCHEMA,
    abiVersion: RECOURSE_ADAPTER_ABI_VERSION,
    authorityInterpretation: interpretation,
    domain: Object.freeze({
      name: "MordantRecourseAdapter",
      version: "1",
      chainId: pins.chainId,
      verifyingContract: pins.address,
    }),
    primaryType: "GovernedRelease" as const,
    types: GOVERNED_RELEASE_TYPES,
    message: Object.freeze({
      runId: bridgeRunId(release.runId),
      fheCaseId: digestToBytes32(release.fheCaseId),
      caseBindingDigest: digestToBytes32(release.caseBindingDigest),
      assetIdentityDigest: digestToBytes32(release.assetIdentity),
      governedResultDigest: digestToBytes32(release.governedResultDigest),
      resultCiphertextDigest: digestToBytes32(release.resultCiphertextDigest),
      participantArtifactDigestA: digestToBytes32(release.participantArtifactDigests[0]),
      participantArtifactDigestB: digestToBytes32(release.participantArtifactDigests[1]),
      holderA: participants.holderA,
      holderB: participants.holderB,
      payoutA: participants.payoutA,
      payoutB: participants.payoutB,
      // Straight from the verified governed result, and from nowhere else.
      conflict: release.conflict,
      releaseAuthorityId: pins.releaseAuthorityId,
      releaseMode: pins.releaseMode,
      circuitHash: pins.circuitHash,
      parameterFingerprint: pins.parameterFingerprint,
      nonce: input.nonce,
      issuedAt: BigInt(input.issuedAt),
      expiry: BigInt(input.expiry),
    }),
  });
}

/**
 * The EIP-712 struct hash, computed exactly as the adapter's `_hashRelease` does:
 * the type hash followed by the twenty encoded fields. Kept here so the parity
 * check against the deployed `hashRelease` view has an independent implementation
 * to compare with, rather than trusting one library on both sides.
 */
export function governedReleaseStructHash(payload: GovernedBridgePayload): Hex {
  const m = payload.message;
  return keccak256(encodeAbiParameters(
    [
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" },
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "address" },
      { type: "address" }, { type: "uint256" }, { type: "uint256" }, { type: "bool" }, { type: "bytes32" },
      { type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "uint64" },
      { type: "uint64" },
    ],
    [
      RELEASE_TYPEHASH, m.runId, m.fheCaseId, m.caseBindingDigest, m.assetIdentityDigest,
      m.governedResultDigest, m.resultCiphertextDigest, m.participantArtifactDigestA, m.participantArtifactDigestB,
      m.holderA, m.holderB, m.payoutA, m.payoutB, m.conflict, m.releaseAuthorityId,
      m.releaseMode, m.circuitHash, m.parameterFingerprint, m.nonce, m.issuedAt, m.expiry,
    ],
  ));
}
