import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { encodeAbiParameters, hashTypedData, keccak256, toHex } from "viem";

import {
  GovernedBridgeError,
  RELEASE_TYPEHASH,
  SUPERSEDED_ADAPTER_ADDRESS,
  assertProductionInterpretation,
  buildGovernedBridgePayload,
  governedReleaseStructHash,
  reconcileAdapter,
  type AdapterPins,
  type BridgeInput,
  type VerifiedGovernedRelease,
} from "./governed-recourse-bridge";

/**
 * The bridge carries a governed result that has already been verified, to the
 * adapter that actually pins it, and refuses everything else.
 *
 * The canonical regression is bound to Adapter V2. The superseded V1 deployment
 * survives here only as a negative case: its domain, its address and its
 * label-derived pins must all be rejected, and a test proves each.
 */

const HANDOFF_PATH = "docs/evidence/runtime-contract-handoff-2026-08-06.json";
const HANDOFF = JSON.parse(readFileSync(HANDOFF_PATH, "utf8")) as {
  adapter: Record<string, string | number>;
  supersededAdapter: Record<string, unknown>;
  governedResult: Record<string, string | boolean>;
  eip712: { typeHash: string; primaryType: string; typeString: string; fields: { index: number; name: string; type: string }[]; domain: Record<string, unknown> };
  encodingVector: { payload: Record<string, string | boolean>; expectedDigests: Record<string, string | boolean> };
  participantEligibility: Record<string, { address: string; eligible: boolean } | string | number>;
  submissionPayload: Record<string, unknown>;
};

const V2_ADDRESS = HANDOFF.adapter.address as `0x${string}`;
const V2_CHAIN = HANDOFF.adapter.chainId as number;
const governed = HANDOFF.governedResult as Record<string, string>;

function release(overrides: Partial<VerifiedGovernedRelease> = {}): VerifiedGovernedRelease {
  return {
    runId: governed.runId,
    fheCaseId: governed.fheCaseId as `sha256:${string}`,
    caseBindingDigest: governed.caseBindingDigest as `sha256:${string}`,
    assetIdentity: governed.assetIdentityDigest as `sha256:${string}`,
    governedResultDigest: governed.governedResultDigest as `sha256:${string}`,
    resultCiphertextDigest: governed.resultCiphertextDigest as `sha256:${string}`,
    participantArtifactDigests: [
      governed.participantArtifactDigestA as `sha256:${string}`,
      governed.participantArtifactDigestB as `sha256:${string}`,
    ],
    circuitDigest: governed.circuitDigest as `sha256:${string}`,
    parameterFingerprint: governed.parameterFingerprint as `sha256:${string}`,
    releaseAuthorityId: governed.releaseAuthorityId as `sha256:${string}`,
    releaseMode: "governed-decryptor-v1",
    conflict: HANDOFF.governedResult.conflict as boolean,
    ...overrides,
  };
}

/** The live Adapter V2 pins, as recorded by eth_call in the fixture. */
const V2_PINS: AdapterPins = Object.freeze({
  address: V2_ADDRESS,
  chainId: V2_CHAIN,
  assetIdentityDigest: HANDOFF.adapter.assetIdentityDigest as `0x${string}`,
  releaseAuthorityId: HANDOFF.adapter.expectedGovernedReleaseAuthorityId as `0x${string}`,
  releaseMode: HANDOFF.adapter.releaseMode as `0x${string}`,
  circuitHash: HANDOFF.adapter.circuitHash as `0x${string}`,
  parameterFingerprint: HANDOFF.adapter.parameterFingerprint as `0x${string}`,
});

/** The superseded V1 deployment, retained only to be refused. */
const SUPERSEDED_PINS: AdapterPins = Object.freeze({
  address: SUPERSEDED_ADAPTER_ADDRESS,
  chainId: V2_CHAIN,
  assetIdentityDigest: HANDOFF.adapter.assetIdentityDigest as `0x${string}`,
  releaseAuthorityId: "0x130d619731ab2a03a81de297e058ef57a6a85656d0ddf76d26e7a20cfa2d3651",
  releaseMode: HANDOFF.adapter.releaseMode as `0x${string}`,
  circuitHash: keccak256(toHex("mordant.identity-full-fhe-256")),
  parameterFingerprint: keccak256(toHex("mordant.bgv.identity-full-fhe-256.n15/v1")),
});

const vector = HANDOFF.encodingVector.payload;

function input(overrides: Partial<BridgeInput> = {}): BridgeInput {
  return {
    release: release(),
    participants: {
      holderA: vector.holderA as `0x${string}`,
      holderB: vector.holderB as `0x${string}`,
      payoutA: BigInt(vector.payoutA as string),
      payoutB: BigInt(vector.payoutB as string),
    },
    pins: V2_PINS,
    interpretation: "PINS_GOVERNED_AUTHORITY",
    nonce: BigInt(vector.nonce as string),
    issuedAt: Number(vector.issuedAt),
    expiry: Number(vector.expiry),
    governedSignatureVerified: true,
    crossReferencesVerified: true,
    ...overrides,
  };
}

function digestOf(payload: ReturnType<typeof buildGovernedBridgePayload>) {
  return hashTypedData({
    domain: payload.domain, types: payload.types,
    primaryType: payload.primaryType, message: payload.message,
  });
}

// ------------------------------------------------------------------ V2 canonical regression

test("the canonical regression is bound to Adapter V2", () => {
  assert.equal(HANDOFF.adapter.generation, "V2");
  assert.notEqual(V2_ADDRESS.toLowerCase(), SUPERSEDED_ADAPTER_ADDRESS.toLowerCase());
  assert.equal((HANDOFF.eip712.domain.verifyingContract as string), V2_ADDRESS);
});

test("the V2 encoding vector reproduces the digest the deployed view returned", () => {
  const payload = buildGovernedBridgePayload(input());
  assert.equal(digestOf(payload), HANDOFF.encodingVector.expectedDigests.viemTypedDataDigest);
  // The published viem digest and the published eth_call result are one value.
  assert.equal(
    HANDOFF.encodingVector.expectedDigests.soliditySolidityHashReleaseResult,
    HANDOFF.encodingVector.expectedDigests.viemTypedDataDigest,
  );
  assert.equal(HANDOFF.encodingVector.expectedDigests.byteIdentical, true);
});

test("the local domain separator equals the one the adapter reports", () => {
  const separator = keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
    [
      keccak256(toHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
      keccak256(toHex("MordantRecourseAdapter")), keccak256(toHex("1")),
      BigInt(V2_CHAIN), V2_ADDRESS,
    ],
  ));
  assert.equal(separator, HANDOFF.adapter.domainSeparator);
  assert.equal(separator, HANDOFF.encodingVector.expectedDigests.viemDomainSeparator);
});

test("the independent struct hash agrees with the typed-data path", () => {
  const payload = buildGovernedBridgePayload(input());
  assert.equal(governedReleaseStructHash(payload), HANDOFF.encodingVector.expectedDigests.viemStructHash);
  assert.equal(
    digestOf(payload),
    keccak256(`0x1901${(HANDOFF.adapter.domainSeparator as string).slice(2)}${governedReleaseStructHash(payload).slice(2)}` as `0x${string}`),
  );
});

test("the release type hash is the twenty-field GovernedRelease struct", () => {
  assert.equal(RELEASE_TYPEHASH, "0x5e5f1a6c601ddff4a7d452bf8cf5c106c0efb68a0d0e17832da59c95a6ac0a8d");
  assert.equal(HANDOFF.eip712.typeHash, RELEASE_TYPEHASH);
  assert.equal(HANDOFF.eip712.fields.length, 20);
  HANDOFF.eip712.fields.forEach((field, index) => assert.equal(field.index, index));
});

test("mutating any single field changes the digest", () => {
  const base = digestOf(buildGovernedBridgePayload(input()));
  const p = { holderA: vector.holderA as `0x${string}`, holderB: vector.holderB as `0x${string}`, payoutA: 600n, payoutB: 400n };
  const mutations: ReadonlyArray<readonly [string, BridgeInput]> = [
    ["runId", input({ release: release({ runId: "5fac6616-1a89-4234-a1fa-1e1046782fb4" }) })],
    ["fheCaseId", input({ release: release({ fheCaseId: `sha256:${"9".repeat(64)}` }) })],
    ["caseBindingDigest", input({ release: release({ caseBindingDigest: `sha256:${"9".repeat(64)}` }) })],
    ["governedResultDigest", input({ release: release({ governedResultDigest: `sha256:${"9".repeat(64)}` }) })],
    ["resultCiphertextDigest", input({ release: release({ resultCiphertextDigest: `sha256:${"9".repeat(64)}` }) })],
    ["participantArtifactA", input({ release: release({ participantArtifactDigests: [`sha256:${"9".repeat(64)}`, governed.participantArtifactDigestB as `sha256:${string}`] }) })],
    ["participantArtifactB", input({ release: release({ participantArtifactDigests: [governed.participantArtifactDigestA as `sha256:${string}`, `sha256:${"9".repeat(64)}`] }) })],
    ["holderA", input({ participants: { ...p, holderA: p.holderB } })],
    ["holderB", input({ participants: { ...p, holderB: p.holderA } })],
    ["payoutA", input({ participants: { ...p, payoutA: 601n } })],
    ["payoutB", input({ participants: { ...p, payoutB: 401n } })],
    ["nonce", input({ nonce: 2n })],
    ["issuedAt", input({ issuedAt: Number(vector.issuedAt) + 1 })],
    ["expiry", input({ expiry: Number(vector.expiry) + 1 })],
  ];
  for (const [label, mutated] of mutations) {
    assert.notEqual(digestOf(buildGovernedBridgePayload(mutated)), base, `${label} must change the digest`);
  }
});

// ------------------------------------------------------------------ superseded deployment

test("the superseded adapter address is refused by name", () => {
  const problems = reconcileAdapter(release(), SUPERSEDED_PINS, "PINS_GOVERNED_AUTHORITY");
  assert.ok(problems.some((problem) => problem.startsWith("address:")), "the superseded address must be named");
  assert.throws(
    () => buildGovernedBridgePayload(input({ pins: SUPERSEDED_PINS })),
    (error: unknown) => {
      assert.ok(error instanceof GovernedBridgeError);
      assert.equal(error.code, "ADAPTER_INCOMPATIBLE");
      return true;
    },
  );
});

test("the former domain produces a different digest and cannot be reused", () => {
  const v2 = digestOf(buildGovernedBridgePayload(input()));
  // Same twenty fields, former verifying contract: a distinct signing domain.
  const formerDomain = hashTypedData({
    domain: { name: "MordantRecourseAdapter", version: "1", chainId: V2_CHAIN, verifyingContract: SUPERSEDED_ADAPTER_ADDRESS },
    types: buildGovernedBridgePayload(input()).types,
    primaryType: "GovernedRelease",
    message: buildGovernedBridgePayload(input()).message,
  });
  assert.notEqual(formerDomain, v2, "a signature for the former adapter must not verify for V2");
});

test("label-derived circuit and parameter pins are rejected", () => {
  const labelled: AdapterPins = {
    ...V2_PINS,
    circuitHash: keccak256(toHex("mordant.identity-full-fhe-256")),
    parameterFingerprint: keccak256(toHex("mordant.bgv.identity-full-fhe-256.n15/v1")),
  };
  const problems = reconcileAdapter(release(), labelled, "PINS_GOVERNED_AUTHORITY");
  assert.ok(problems.some((p) => p.startsWith("circuitHash:")));
  assert.ok(problems.some((p) => p.startsWith("parameterFingerprint:")));
  assert.throws(() => buildGovernedBridgePayload(input({ pins: labelled })), /ADAPTER_INCOMPATIBLE|content-derived/u);
});

test("the releaseMode label convention is unchanged", () => {
  assert.equal(V2_PINS.releaseMode, keccak256(toHex("governed-decryptor-v1")));
  assert.equal(reconcileAdapter(release(), V2_PINS, "PINS_GOVERNED_AUTHORITY").length, 0);
});

test("only the governed-authority interpretation may be used in production", () => {
  assert.doesNotThrow(() => assertProductionInterpretation("PINS_GOVERNED_AUTHORITY"));
  assert.throws(() => assertProductionInterpretation("PINS_SEPARATE_BRIDGE_ATTESTOR"), /SUPERSEDED_INTERPRETATION|production/u);
});

test("an adapter pinned to another receivable is refused", () => {
  assert.throws(
    () => buildGovernedBridgePayload(input({ pins: { ...V2_PINS, assetIdentityDigest: `0x${"9".repeat(64)}` } })),
    /assetIdentityDigest/u,
  );
});

test("an adapter that does not pin the governed authority is refused", () => {
  assert.throws(
    () => buildGovernedBridgePayload(input({ pins: { ...V2_PINS, releaseAuthorityId: `0x${"9".repeat(64)}` } })),
    /releaseAuthorityId/u,
  );
});

// ------------------------------------------------------------------ the Boolean and payouts

test("the terminal Boolean is carried from the governed result and nowhere else", () => {
  const p = { holderA: vector.holderA as `0x${string}`, holderB: vector.holderB as `0x${string}`, payoutA: 0n, payoutB: 0n };
  const refused = buildGovernedBridgePayload(input({ release: release({ conflict: false }), participants: p }));
  assert.equal(refused.message.conflict, false);
  const confirmed = buildGovernedBridgePayload(input());
  assert.equal(confirmed.message.conflict, true);
  assert.notEqual(digestOf(refused), digestOf(confirmed));
});

test("a false Boolean cannot carry a payout and a true one cannot omit it", () => {
  assert.throws(
    () => buildGovernedBridgePayload(input({ release: release({ conflict: false }) })),
    /PAYOUT_ON_NO_CONFLICT|false Boolean/u,
  );
  assert.throws(
    () => buildGovernedBridgePayload(input({
      participants: { holderA: vector.holderA as `0x${string}`, holderB: vector.holderB as `0x${string}`, payoutA: 0n, payoutB: 0n },
    })),
    /PAYOUT_MISSING|must carry a payout/u,
  );
});

test("a payload cannot be built before the governed signature is verified", () => {
  assert.throws(() => buildGovernedBridgePayload({ ...input(), governedSignatureVerified: false as never }), /governed signature must be verified/u);
  assert.throws(() => buildGovernedBridgePayload({ ...input(), crossReferencesVerified: false as never }), /cross-references must be verified/u);
});

test("an inverted bridge window is refused", () => {
  assert.throws(() => buildGovernedBridgePayload(input({ issuedAt: 1_785_003_600, expiry: 1_785_000_000 })), /forward interval/u);
});

// ------------------------------------------------------------------ fixture hygiene

test("the module hard-codes no adapter target, only the superseded deny-list entry", () => {
  const source = readFileSync("src/lib/protection/governed-recourse-bridge.ts", "utf8");
  const addresses = source.match(/0x[0-9a-fA-F]{40}/gu) ?? [];
  // Exactly one address may appear, and only as the thing that is refused.
  assert.deepEqual([...new Set(addresses)], [SUPERSEDED_ADAPTER_ADDRESS]);
});

test("the handoff fixture records participant eligibility as measured", () => {
  const holderA = HANDOFF.participantEligibility.holderA as { address: string; eligible: boolean };
  const holderB = HANDOFF.participantEligibility.holderB as { address: string; eligible: boolean };
  // Whatever the verifier said is what is written down, including a refusal.
  assert.equal(typeof holderA.eligible, "boolean");
  assert.equal(typeof holderB.eligible, "boolean");
  assert.match(holderA.address, /^0x[0-9a-fA-F]{40}$/u);
  assert.match(holderB.address, /^0x[0-9a-fA-F]{40}$/u);
  assert.notEqual(holderA.address.toLowerCase(), holderB.address.toLowerCase());
  // A submission may be READY only when both participants actually passed.
  if (HANDOFF.submissionPayload.status === "READY") {
    assert.equal(holderA.eligible, true);
    assert.equal(holderB.eligible, true);
  }
});

test("a pending submission names exactly what is missing", () => {
  if (HANDOFF.submissionPayload.status === "PENDING") {
    const blocked = HANDOFF.submissionPayload.blockedOn as string[];
    assert.ok(Array.isArray(blocked) && blocked.length > 0, "a pending submission must say why");
  }
});

test("the handoff fixture carries no secret material", () => {
  const raw = readFileSync(HANDOFF_PATH, "utf8");
  for (const forbidden of ["PRIVATE KEY", "privateKey", "apiKey", "API_KEY", "mnemonic", "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY\":"]) {
    assert.equal(raw.includes(forbidden), false, `${forbidden} must not appear in a public fixture`);
  }
});
