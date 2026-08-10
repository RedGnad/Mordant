import { keccak256, type Hex } from "viem";

/**
 * The Adapter V2 runtime artifacts this build will deploy, each reviewed
 * explicitly and pinned by its exact masked runtime hash.
 *
 * Two artifacts are listed because the same source, compiled in two different
 * environments, produces two runtimes that differ only inside the Solidity CBOR
 * metadata trailer. That was measured rather than assumed: against the deployed
 * historical adapter, 32 bytes differ, all of them inside the metadata region,
 * and the 10,035 executable bytes are byte-identical.
 *
 * The registry is an ALLOWLIST, not a rule. There is deliberately no "ignore
 * metadata differences" behaviour: a third build, with a third metadata blob,
 * is refused until somebody reviews it and pins it here. What the executable
 * hash buys is evidence for that review, never an automatic pass.
 */

export type ReviewedAdapterArtifact = Readonly<{
  name: string;
  /** keccak of the runtime with every immutable span zeroed. The identity key. */
  maskedRuntimeHash: Hex;
  runtimeBytes: number;
  /** Inclusive byte range of the Solidity CBOR metadata trailer. */
  metadataRegion: Readonly<{ start: number; end: number }>;
  /** keccak of everything before the metadata region, after masking immutables. */
  executableRegionHash: Hex;
  solcVersion: string;
  optimizerRuns: number;
  provenance: string;
}>;

export const REVIEWED_ADAPTER_ARTIFACTS: readonly ReviewedAdapterArtifact[] = Object.freeze([
  Object.freeze({
    name: "recourse-adapter-v2-2026-08-06",
    maskedRuntimeHash: "0x29b610f1fa6592d70e7171b98dcaaa7ee48a7bf0896efa1f3bbe7a1f773e722e",
    runtimeBytes: 10_088,
    metadataRegion: Object.freeze({ start: 10_035, end: 10_087 }),
    executableRegionHash: "0xcb38de62ecb3c4d27a88c5b535cea3bd1dc8933c6d7fd465134640e8374af77d",
    solcVersion: "0.8.28",
    optimizerRuns: 10_000,
    provenance: "docs/evidence/recourse-adapter-v2-deployment-2026-08-06.json; deployed runtime read back from"
      + " 0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1 on Monad testnet",
  }),
  Object.freeze({
    name: "recourse-adapter-v2-metadata-variant-a",
    maskedRuntimeHash: "0x0d1cd7dd147bfd6e07d375542fed725a40469919d837e6a9662f7cab68d2e9c2",
    runtimeBytes: 10_088,
    metadataRegion: Object.freeze({ start: 10_035, end: 10_087 }),
    executableRegionHash: "0xcb38de62ecb3c4d27a88c5b535cea3bd1dc8933c6d7fd465134640e8374af77d",
    solcVersion: "0.8.28",
    optimizerRuns: 10_000,
    provenance: "Built from this repository with the pinned foundry profile and the pinned OpenZeppelin submodule"
      + " 5fd1781b1454fd1ef8e722282f86f9293cacf256. Differs from recourse-adapter-v2-2026-08-06 in exactly 32 bytes,"
      + " all within the CBOR metadata trailer at 10045-10076; the 10,035 executable bytes are byte-identical.",
  }),
]);

export class ReviewedAdapterArtifactError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "ReviewedAdapterArtifactError";
  }
}

function fail(code: string, message: string): never {
  throw new ReviewedAdapterArtifactError(code, message);
}

export type ImmutableReferences = Readonly<Record<string, readonly Readonly<{ start: number; length: number }>[]>>;

/** Zeroes every immutable span, so two deployments of one artifact compare equal. */
export function maskImmutables(runtime: Buffer, immutableReferences: ImmutableReferences): Buffer {
  const masked = Buffer.from(runtime);
  for (const spans of Object.values(immutableReferences ?? {})) {
    for (const { start, length } of spans) {
      if (start < 0 || start + length > masked.length) {
        fail("IMMUTABLE_SPAN", "An immutable span falls outside the runtime");
      }
      masked.fill(0, start, start + length);
    }
  }
  return masked;
}

/**
 * Accepts a runtime only when it is one of the explicitly reviewed artifacts.
 *
 * The masked hash alone decides acceptance. Length, metadata boundary and
 * executable hash are then re-verified against the same entry, so a collision
 * in one field cannot carry the rest.
 */
export function assertReviewedAdapterArtifact(
  runtime: Buffer,
  immutableReferences: ImmutableReferences,
): ReviewedAdapterArtifact {
  const masked = maskImmutables(runtime, immutableReferences);
  const maskedRuntimeHash = keccak256(`0x${masked.toString("hex")}`);
  const reviewed = REVIEWED_ADAPTER_ARTIFACTS.find((entry) => entry.maskedRuntimeHash === maskedRuntimeHash);
  if (reviewed === undefined) {
    fail(
      "UNREVIEWED_ARTIFACT",
      `This runtime is not an explicitly reviewed Adapter V2 artifact (masked hash ${maskedRuntimeHash})`,
    );
  }
  if (masked.length !== reviewed.runtimeBytes) {
    fail("RUNTIME_LENGTH", `The runtime is ${masked.length} bytes where ${reviewed.name} is ${reviewed.runtimeBytes}`);
  }
  const executable = masked.subarray(0, reviewed.metadataRegion.start);
  const executableRegionHash = keccak256(`0x${executable.toString("hex")}`);
  if (executableRegionHash !== reviewed.executableRegionHash) {
    fail("EXECUTABLE_REGION", `The executable region does not match ${reviewed.name}`);
  }
  return reviewed;
}

/**
 * Evidence for a review: where two accepted artifacts differ, and the proof that
 * the difference is confined to metadata. This reports, it never decides.
 */
export function compareReviewedRuntimes(
  left: Buffer,
  right: Buffer,
  immutableReferences: ImmutableReferences,
  metadataStart: number,
): Readonly<{
  lengths: readonly [number, number];
  differingByteOffsets: readonly number[];
  allDifferencesInsideMetadata: boolean;
  executableRegionIdentical: boolean;
}> {
  const a = maskImmutables(left, immutableReferences);
  const b = maskImmutables(right, immutableReferences);
  const differing: number[] = [];
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) differing.push(index);
  }
  return Object.freeze({
    lengths: [a.length, b.length] as const,
    differingByteOffsets: Object.freeze(differing),
    allDifferencesInsideMetadata: differing.every((index) => index >= metadataStart),
    executableRegionIdentical: a.subarray(0, metadataStart).equals(b.subarray(0, metadataStart)),
  });
}
