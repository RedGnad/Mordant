import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { keccak256 } from "viem";

import {
  REVIEWED_ADAPTER_ARTIFACTS,
  ReviewedAdapterArtifactError,
  assertReviewedAdapterArtifact,
  compareReviewedRuntimes,
  maskImmutables,
} from "./reviewed-adapter-artifacts";

const ARTIFACT = "contracts/out/MordantRecourseAdapter.sol/MordantRecourseAdapter.json";

function built(): { runtime: Buffer; immutableReferences: Record<string, { start: number; length: number }[]> } | null {
  try {
    const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8")) as {
      deployedBytecode: { object: string; immutableReferences?: Record<string, { start: number; length: number }[]> };
    };
    return {
      runtime: Buffer.from(artifact.deployedBytecode.object.replace(/^0x/u, ""), "hex"),
      immutableReferences: artifact.deployedBytecode.immutableReferences ?? {},
    };
  } catch {
    return null;
  }
}

const build = built();

function code(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    assert.ok(error instanceof ReviewedAdapterArtifactError, `expected a reviewed-artifact error, got ${String(error)}`);
    return error.code;
  }
  return assert.fail("expected a refusal, the call succeeded");
}

test("the registry pins each artifact separately and shares no identity", () => {
  const hashes = new Set(REVIEWED_ADAPTER_ARTIFACTS.map((entry) => entry.maskedRuntimeHash));
  assert.equal(hashes.size, REVIEWED_ADAPTER_ARTIFACTS.length, "two entries must never share a masked hash");
  // Both reviewed artifacts are the same contract: same executable region.
  const executables = new Set(REVIEWED_ADAPTER_ARTIFACTS.map((entry) => entry.executableRegionHash));
  assert.equal(executables.size, 1);
});

test("the historical artifact is still accepted exactly as before", () => {
  const historical = REVIEWED_ADAPTER_ARTIFACTS.find((entry) => entry.name === "recourse-adapter-v2-2026-08-06");
  assert.ok(historical !== undefined);
  assert.equal(historical.maskedRuntimeHash, "0x29b610f1fa6592d70e7171b98dcaaa7ee48a7bf0896efa1f3bbe7a1f773e722e");
  assert.equal(historical.runtimeBytes, 10_088);
});

test("the freshly built artifact is accepted", { skip: build === null }, () => {
  const reviewed = assertReviewedAdapterArtifact(build!.runtime, build!.immutableReferences);
  assert.equal(reviewed.runtimeBytes, build!.runtime.length);
  assert.equal(reviewed.executableRegionHash, "0xcb38de62ecb3c4d27a88c5b535cea3bd1dc8933c6d7fd465134640e8374af77d");
});

// ------------------------------------------------------------ negative controls

test("mutating one executable opcode is refused", { skip: build === null }, () => {
  const mutated = Buffer.from(build!.runtime);
  // Byte 64 is well inside the executable region and outside every immutable span.
  mutated[64] = mutated[64] ^ 0xff;
  assert.equal(code(() => assertReviewedAdapterArtifact(mutated, build!.immutableReferences)), "UNREVIEWED_ARTIFACT");
});

test("mutating a byte outside the permitted immutable mask is refused", { skip: build === null }, () => {
  const spans = Object.values(build!.immutableReferences).flat();
  assert.ok(spans.length > 0, "the artifact must declare immutable spans");
  const span = spans[0];
  const justOutside = span.start + span.length;
  const mutated = Buffer.from(build!.runtime);
  mutated[justOutside] = mutated[justOutside] ^ 0xff;
  assert.equal(code(() => assertReviewedAdapterArtifact(mutated, build!.immutableReferences)), "UNREVIEWED_ARTIFACT");
});

test("a byte inside a declared immutable span is masked and therefore tolerated", { skip: build === null }, () => {
  const spans = Object.values(build!.immutableReferences).flat();
  const mutated = Buffer.from(build!.runtime);
  mutated[spans[0].start] = mutated[spans[0].start] ^ 0xff;
  // This is the whole point of masking: a deployment differs here by construction.
  assert.doesNotThrow(() => assertReviewedAdapterArtifact(mutated, build!.immutableReferences));
});

test("an unpinned metadata variant is refused rather than tolerated", { skip: build === null }, () => {
  const reviewed = assertReviewedAdapterArtifact(build!.runtime, build!.immutableReferences);
  const mutated = Buffer.from(build!.runtime);
  // A third build would differ only here. It must not pass on the strength of a
  // matching executable region: it has to be reviewed and pinned first.
  mutated[reviewed.metadataRegion.start + 12] = mutated[reviewed.metadataRegion.start + 12] ^ 0xff;
  const masked = maskImmutables(mutated, build!.immutableReferences);
  const executable = masked.subarray(0, reviewed.metadataRegion.start);
  assert.equal(
    keccak256(`0x${executable.toString("hex")}`),
    reviewed.executableRegionHash,
    "the executable region is untouched, so only the allowlist can refuse this",
  );
  assert.equal(code(() => assertReviewedAdapterArtifact(mutated, build!.immutableReferences)), "UNREVIEWED_ARTIFACT");
});

test("the metadata-only difference between the two reviewed artifacts is measured, not assumed", { skip: build === null }, () => {
  const reviewed = REVIEWED_ADAPTER_ARTIFACTS[0];
  // A synthetic stand-in for the historical runtime: identical everywhere except
  // inside metadata, which is exactly the relationship the registry records.
  const other = Buffer.from(build!.runtime);
  for (let index = 10_045; index <= 10_076; index += 1) other[index] = other[index] ^ 0x5a;
  const report = compareReviewedRuntimes(build!.runtime, other, build!.immutableReferences, reviewed.metadataRegion.start);
  assert.equal(report.differingByteOffsets.length, 32);
  assert.ok(report.allDifferencesInsideMetadata);
  assert.ok(report.executableRegionIdentical);
});
