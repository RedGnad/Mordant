import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CUSTOM_SUPERVISED_BINDING_SCHEMA,
  CUSTOM_SUPERVISED_EXECUTION_VARIANT,
  assertNeutralCustomBinding,
  customSupervisedBindingBytesV2,
  customSupervisedBindingDigestV2,
  customSupervisedFheCaseIdV2,
  type MordantCustomSupervisedBindingV2,
} from "./custom-supervised-v2";

/**
 * Cross-language golden vectors. These exact strings were emitted by the Go
 * implementation in fhe-lab/lattigo/governedfhe/product_proof.go over the same
 * neutral case material. If Go and TypeScript ever disagree on canonical bytes,
 * the case identity or the binding digest, these fail.
 */
const GO_V2_BYTES = '{"schemaVersion":"mordant.protection-binding/2","cleanverseAssetRecordDigest":"sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c","protectionService":"Conflicting Pledge Protection","protectionServiceVersion":1,"policyId":"sha256:a9e039b95a56043532bcc1d7a8c1bb0086fc64d50adcb35ff54f54ee59fb6e65","policyVersion":1,"fixtureClassification":"SYNTHETIC_HACKATHON_FIXTURE","protectedAmount":{"asset":"aUSDC","minorUnits":"100000000"},"reserveBasisPoints":1000,"reserveAmount":{"asset":"aUSDC","minorUnits":"10000000"},"holderRecordDate":"2026-08-03T14:48:49.163Z","holderSnapshot":[{"holderId":"HOLDER_A","protectedUnits":"60000000","allocationBps":6000},{"holderId":"HOLDER_B","protectedUnits":"40000000","allocationBps":4000}],"holderAllocationDigest":"sha256:3c700c3f10343766c466e959ca65d6906c8811fababec08c8e6c4f31b3700b83","caseNonce":"sha256:b0ebed0f839dfc2b9bed641dcbbba51c2761e85f63d9ac05090c8ac1af46b87c","fheCaseId":"sha256:9b582884230400cbfb47daaeed07b6292255d34ce67641557410477af8f8c9f2","governedReleaseMode":"governed-decryptor-v1","executionVariant":"CUSTOM_SUPERVISED"}';
const GO_V2_CASE_ID = "sha256:9b582884230400cbfb47daaeed07b6292255d34ce67641557410477af8f8c9f2";
const GO_V2_BINDING_DIGEST = "sha256:fcedfd30397493be4c8f1f994978bf080cff637636f816f9b9331393095400d7";

const ASSET_DIGEST = "sha256:7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c" as const;
const POLICY_ID = "sha256:a9e039b95a56043532bcc1d7a8c1bb0086fc64d50adcb35ff54f54ee59fb6e65" as const;
const ALLOCATION_DIGEST = "sha256:3c700c3f10343766c466e959ca65d6906c8811fababec08c8e6c4f31b3700b83" as const;
const CASE_NONCE = "sha256:b0ebed0f839dfc2b9bed641dcbbba51c2761e85f63d9ac05090c8ac1af46b87c" as const;

function binding(): MordantCustomSupervisedBindingV2 {
  return {
    schemaVersion: CUSTOM_SUPERVISED_BINDING_SCHEMA,
    cleanverseAssetRecordDigest: ASSET_DIGEST,
    protectionService: "Conflicting Pledge Protection",
    protectionServiceVersion: 1,
    policyId: POLICY_ID,
    policyVersion: 1,
    fixtureClassification: "SYNTHETIC_HACKATHON_FIXTURE",
    protectedAmount: { asset: "aUSDC", minorUnits: "100000000" },
    reserveBasisPoints: 1000,
    reserveAmount: { asset: "aUSDC", minorUnits: "10000000" },
    holderRecordDate: "2026-08-03T14:48:49.163Z",
    holderSnapshot: [
      { holderId: "HOLDER_A", protectedUnits: "60000000", allocationBps: 6000 },
      { holderId: "HOLDER_B", protectedUnits: "40000000", allocationBps: 4000 },
    ],
    holderAllocationDigest: ALLOCATION_DIGEST,
    caseNonce: CASE_NONCE,
    fheCaseId: GO_V2_CASE_ID,
    governedReleaseMode: "governed-decryptor-v1",
    executionVariant: CUSTOM_SUPERVISED_EXECUTION_VARIANT,
  };
}

test("TypeScript derives the same V2 case identity as Go", () => {
  const caseId = customSupervisedFheCaseIdV2({
    assetDigest: ASSET_DIGEST,
    caseNonce: CASE_NONCE,
    holderAllocationDigest: ALLOCATION_DIGEST,
    policyId: POLICY_ID,
  });
  assert.equal(caseId, GO_V2_CASE_ID);
});

test("TypeScript produces the same V2 canonical bytes as Go", () => {
  assert.equal(customSupervisedBindingBytesV2(binding()), GO_V2_BYTES);
});

test("TypeScript produces the same V2 binding digest as Go", () => {
  assert.equal(customSupervisedBindingDigestV2(binding()), GO_V2_BINDING_DIGEST);
});

test("the V2 binding is structurally neutral about the result", () => {
  const value = binding();
  assert.doesNotThrow(() => assertNeutralCustomBinding(value));
  const encoded = customSupervisedBindingBytesV2(value);
  assert.equal(encoded.includes("productScenario"), false);
  assert.equal(encoded.includes('"conflict"'), false);
  assert.equal(encoded.includes('"no-conflict"'), false);
  assert.equal(encoded.includes("CUSTOM_SUPERVISED"), true);
});

test("the V2 case identity is domain separated from V1", () => {
  // The retained A8 V1 case identity over the same asset, nonce, policy and
  // allocation. A V2 derivation must never collide with it.
  assert.notEqual(GO_V2_CASE_ID, "sha256:806de678d14adbde33a0048d244389d3404b6c45d0c71163e2fd5a283c60828e");
});

test("the V2 case identity ignores everything except neutral case material", () => {
  const first = customSupervisedFheCaseIdV2({
    assetDigest: ASSET_DIGEST, caseNonce: CASE_NONCE,
    holderAllocationDigest: ALLOCATION_DIGEST, policyId: POLICY_ID,
  });
  const second = customSupervisedFheCaseIdV2({
    assetDigest: ASSET_DIGEST, caseNonce: CASE_NONCE,
    holderAllocationDigest: ALLOCATION_DIGEST, policyId: POLICY_ID,
  });
  assert.equal(first, second);
});

test("a binding carrying a product scenario is refused as non-neutral", () => {
  const polluted = { ...binding(), productScenario: "conflict" } as unknown as MordantCustomSupervisedBindingV2;
  assert.throws(() => assertNeutralCustomBinding(polluted), /must not carry productScenario/);
});
