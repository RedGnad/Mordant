/**
 * Neutral custom-supervised authorization, V2.
 *
 * This is a separate model from the V1 product. The V1 binding, the V1 product
 * case, the V4 imported evidence and every A8 verifier stay untouched: nothing
 * here widens them.
 *
 * The point of V2 is that a custom supervised case is authorized and signed
 * BEFORE the FHE evaluation without binding anything about the expected result.
 * Where V1 binds `productScenario`, V2 binds only a neutral
 * `executionVariant: "CUSTOM_SUPERVISED"`. No pledge window, no overlap, and no
 * prediction of the circuit output takes part in any derivation below.
 *
 * The canonical shapes mirror the Go structs in
 * `fhe-lab/lattigo/governedfhe/product_proof.go` exactly, including field order,
 * because Go derives its digests from `json.Marshal` over the struct. The
 * cross-language golden vectors in `custom-supervised-v2.test.ts` pin that
 * agreement.
 */

import { createHash } from "node:crypto";

import { sha256Digest, type Sha256Digest } from "./cleanverse-asset";
import type { HolderAllocation } from "./protection-case";

export const CUSTOM_SUPERVISED_BINDING_SCHEMA = "mordant.protection-binding/2" as const;
export const CUSTOM_SUPERVISED_EXECUTION_VARIANT = "CUSTOM_SUPERVISED" as const;

export type MordantCustomSupervisedBindingV2 = Readonly<{
  schemaVersion: typeof CUSTOM_SUPERVISED_BINDING_SCHEMA;
  cleanverseAssetRecordDigest: Sha256Digest;
  protectionService: string;
  protectionServiceVersion: number;
  policyId: Sha256Digest;
  policyVersion: number;
  fixtureClassification: string;
  protectedAmount: Readonly<{ asset: "aUSDC"; minorUnits: string }>;
  reserveBasisPoints: number;
  reserveAmount: Readonly<{ asset: "aUSDC"; minorUnits: string }>;
  holderRecordDate: string;
  holderSnapshot: readonly [HolderAllocation, HolderAllocation];
  holderAllocationDigest: Sha256Digest;
  caseNonce: Sha256Digest;
  fheCaseId: Sha256Digest;
  governedReleaseMode: string;
  executionVariant: typeof CUSTOM_SUPERVISED_EXECUTION_VARIANT;
}>;

/**
 * The V2 FHE case identity. Domain-separated from V1 and derived from neutral
 * case material plus the execution variant. `productScenario` is structurally
 * absent, so no expected Boolean can enter the case identity.
 *
 * Key order matches the Go struct, and is also the sorted order the TypeScript
 * canonicaliser produces, so both languages agree.
 */
export function customSupervisedFheCaseIdV2(options: Readonly<{
  assetDigest: Sha256Digest;
  caseNonce: Sha256Digest;
  holderAllocationDigest: Sha256Digest;
  policyId: Sha256Digest;
}>): Sha256Digest {
  return sha256Digest("MordantProtectionFHECase/v2", {
    assetDigest: options.assetDigest,
    caseNonce: options.caseNonce,
    executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT,
    holderAllocationDigest: options.holderAllocationDigest,
    policyId: options.policyId,
  });
}

/**
 * Field order mirrors the Go struct declaration order exactly, with
 * `productScenario` absent and `executionVariant` last, because Go digests the
 * marshalled struct rather than a sorted object.
 */
function customSupervisedBindingValue(binding: MordantCustomSupervisedBindingV2): object {
  return {
    schemaVersion: binding.schemaVersion,
    cleanverseAssetRecordDigest: binding.cleanverseAssetRecordDigest,
    protectionService: binding.protectionService,
    protectionServiceVersion: binding.protectionServiceVersion,
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    fixtureClassification: binding.fixtureClassification,
    protectedAmount: { asset: binding.protectedAmount.asset, minorUnits: binding.protectedAmount.minorUnits },
    reserveBasisPoints: binding.reserveBasisPoints,
    reserveAmount: { asset: binding.reserveAmount.asset, minorUnits: binding.reserveAmount.minorUnits },
    holderRecordDate: binding.holderRecordDate,
    holderSnapshot: binding.holderSnapshot.map((holder) => ({
      holderId: holder.holderId,
      protectedUnits: holder.protectedUnits,
      allocationBps: holder.allocationBps,
    })),
    holderAllocationDigest: binding.holderAllocationDigest,
    caseNonce: binding.caseNonce,
    fheCaseId: binding.fheCaseId,
    governedReleaseMode: binding.governedReleaseMode,
    executionVariant: binding.executionVariant,
  };
}

export function customSupervisedBindingBytesV2(binding: MordantCustomSupervisedBindingV2): string {
  return JSON.stringify(customSupervisedBindingValue(binding));
}

export function customSupervisedBindingDigestV2(binding: MordantCustomSupervisedBindingV2): Sha256Digest {
  return `sha256:${createHash("sha256").update(customSupervisedBindingBytesV2(binding)).digest("hex")}`;
}

/**
 * Structural guard used by tests and by the product path: a V2 binding must
 * never carry a product scenario or any conflict wording.
 */
export function assertNeutralCustomBinding(binding: MordantCustomSupervisedBindingV2): void {
  const encoded = customSupervisedBindingBytesV2(binding);
  if (Object.hasOwn(binding as object, "productScenario")) {
    throw new Error("A custom V2 binding must not carry productScenario");
  }
  if (binding.executionVariant !== CUSTOM_SUPERVISED_EXECUTION_VARIANT) {
    throw new Error("A custom V2 binding must carry the neutral execution variant");
  }
  for (const forbidden of ['"conflict"', '"no-conflict"']) {
    if (encoded.includes(forbidden)) {
      throw new Error(`A custom V2 binding must not contain ${forbidden}`);
    }
  }
}
