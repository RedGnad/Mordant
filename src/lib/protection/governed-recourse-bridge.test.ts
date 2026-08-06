import assert from "node:assert/strict";
import { test } from "node:test";

import { readFileSync } from "node:fs";

import { encodeAbiParameters, hashTypedData, keccak256, toHex } from "viem";

import {
  GovernedBridgeError,
  RELEASE_TYPEHASH,
  buildGovernedBridgePayload,
  governedReleaseStructHash,
  reconcileAdapter,
  type AdapterPins,
  type BridgeInput,
  type VerifiedGovernedRelease,
} from "./governed-recourse-bridge";

/**
 * The bridge's job is to carry a governed result that has already been verified,
 * and to refuse everything else. So the properties under test are: the Boolean can
 * only come from the governed result, the deployed adapter's own pins decide
 * whether a payload may exist at all, and the EIP-712 digest agrees byte for byte
 * with the deployed Solidity view.
 *
 * The vector below is retained as a regression fixture. Its digest was compared
 * against the deployed adapter's `hashRelease` view on Monad testnet
 * (0x27677c837287b060D285d5C90096f06fBe675938, chain 10143) and matched exactly.
 */

const ADAPTER = "0x27677c837287b060D285d5C90096f06fBe675938" as const;
const HOLDER_A = "0x911F99f424D47F08a15fcC771e94dcc2f7252B02" as const;
const HOLDER_B = "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0" as const;

const digest = (hex: string) => `sha256:${hex}` as const;

/** The real values carried by the retained A8 governed result. */
const GOVERNED_ASSET = "7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c";
const GOVERNED_CIRCUIT = "2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e";
const GOVERNED_PARAMETERS = "d0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6";
const GOVERNED_AUTHORITY = "c21276405a249b7c178914508d99e9f0286ce29e5e3bb085ad3697f0cc665c3d";

function release(overrides: Partial<VerifiedGovernedRelease> = {}): VerifiedGovernedRelease {
  return {
    runId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    fheCaseId: digest("b".repeat(64)),
    caseBindingDigest: digest("c".repeat(64)),
    assetIdentity: digest(GOVERNED_ASSET),
    governedResultDigest: digest("d".repeat(64)),
    resultCiphertextDigest: digest("e".repeat(64)),
    participantArtifactDigests: [digest("1".repeat(64)), digest("2".repeat(64))],
    circuitDigest: digest(GOVERNED_CIRCUIT),
    parameterFingerprint: digest(GOVERNED_PARAMETERS),
    releaseAuthorityId: digest(GOVERNED_AUTHORITY),
    releaseMode: "governed-decryptor-v1",
    conflict: true,
    ...overrides,
  };
}

/** The values actually read from the deployed adapter on 2026-08-06. */
const DEPLOYED_PINS: AdapterPins = Object.freeze({
  address: ADAPTER,
  chainId: 10_143,
  assetIdentityDigest: `0x${GOVERNED_ASSET}`,
  releaseAuthorityId: "0x130d619731ab2a03a81de297e058ef57a6a85656d0ddf76d26e7a20cfa2d3651",
  releaseMode: "0x29d74d033f25761ba7e8fbb0e872d7420cb42498951e9a85e3993b7ef59600fa",
  circuitHash: "0xed716235e5b273fef1afcd500823af52e729e8f82106145b7fe6429f0f1b4f5b",
  parameterFingerprint: "0x7cf76ba57a3793d251d621e3faa6037b0364e20625f1a2e1dea6dedac6811060",
});

function input(overrides: Partial<BridgeInput> = {}): BridgeInput {
  return {
    release: release(),
    participants: { holderA: HOLDER_A, holderB: HOLDER_B, payoutA: 600n, payoutB: 400n },
    pins: DEPLOYED_PINS,
    interpretation: "PINS_SEPARATE_BRIDGE_ATTESTOR",
    nonce: 1n,
    issuedAt: 1_785_000_000,
    expiry: 1_785_003_600,
    governedSignatureVerified: true,
    crossReferencesVerified: true,
    ...overrides,
  };
}

function digestOf(payload: ReturnType<typeof buildGovernedBridgePayload>) {
  return hashTypedData({
    domain: payload.domain,
    types: payload.types,
    primaryType: payload.primaryType,
    message: payload.message,
  });
}

// ------------------------------------------------------------------ deployed adapter

test("the deployed adapter does not pin the governed Ed25519 release authority", () => {
  const problems = reconcileAdapter(release(), DEPLOYED_PINS, "PINS_GOVERNED_AUTHORITY");
  assert.equal(problems.length, 1);
  assert.match(problems[0], /releaseAuthorityId/u);
  // The deployed value is not the governed authority in any encoding.
  assert.notEqual(DEPLOYED_PINS.releaseAuthorityId, `0x${GOVERNED_AUTHORITY}`);
});

test("the deployed adapter pins keccak label hashes for mode, circuit and parameters", () => {
  assert.equal(DEPLOYED_PINS.releaseMode, keccak256(toHex("governed-decryptor-v1")));
  assert.equal(DEPLOYED_PINS.circuitHash, keccak256(toHex("mordant.identity-full-fhe-256")));
  assert.equal(DEPLOYED_PINS.parameterFingerprint, keccak256(toHex("mordant.bgv.identity-full-fhe-256.n15/v1")));
  // Which is a different value from the governed sha256 digests, not a format of them.
  assert.notEqual(DEPLOYED_PINS.circuitHash, `0x${GOVERNED_CIRCUIT}`);
  assert.notEqual(DEPLOYED_PINS.parameterFingerprint, `0x${GOVERNED_PARAMETERS}`);
});

test("a payload is refused outright under the interpretation that does not hold", () => {
  assert.throws(
    () => buildGovernedBridgePayload(input({ interpretation: "PINS_GOVERNED_AUTHORITY" })),
    (error: unknown) => {
      assert.ok(error instanceof GovernedBridgeError);
      assert.equal(error.code, "ADAPTER_INCOMPATIBLE");
      return true;
    },
  );
});

test("an adapter pinned to another receivable is refused", () => {
  assert.throws(
    () => buildGovernedBridgePayload(input({
      pins: { ...DEPLOYED_PINS, assetIdentityDigest: `0x${"9".repeat(64)}` },
    })),
    /assetIdentityDigest/u,
  );
});

// ------------------------------------------------------------------ EIP-712 parity

test("the retained vector reproduces the digest the deployed view returned", () => {
  const payload = buildGovernedBridgePayload(input());
  // Byte-identical to MordantRecourseAdapter.hashRelease on Monad testnet.
  assert.equal(digestOf(payload), "0xcaadf3c23d8237f77804d7f9dc4ba2bb490d36a319d54c523dcb24b50e086f3b");
});

test("the independent struct hash agrees with the typed-data path", () => {
  const payload = buildGovernedBridgePayload(input());
  // The adapter's own domain separator, rebuilt field by field the way
  // `_buildDomainSeparator` does.
  const domainSeparator = keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
    [
      keccak256(toHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
      keccak256(toHex(payload.domain.name)),
      keccak256(toHex(payload.domain.version)),
      BigInt(payload.domain.chainId),
      payload.domain.verifyingContract,
    ],
  ));
  // Two implementations, one answer: a library change on either side would show.
  assert.equal(
    digestOf(payload),
    keccak256(`0x1901${domainSeparator.slice(2)}${governedReleaseStructHash(payload).slice(2)}` as `0x${string}`),
  );
});

test("the release type hash is the twenty-field GovernedRelease struct", () => {
  assert.equal(RELEASE_TYPEHASH, "0x5e5f1a6c601ddff4a7d452bf8cf5c106c0efb68a0d0e17832da59c95a6ac0a8d");
});

test("mutating any single field changes the digest", () => {
  const base = digestOf(buildGovernedBridgePayload(input()));
  const mutations: ReadonlyArray<readonly [string, BridgeInput]> = [
    ["runId", input({ release: release({ runId: "5fac6616-1a89-4234-a1fa-1e1046782fb4" }) })],
    ["fheCaseId", input({ release: release({ fheCaseId: digest("9".repeat(64)) }) })],
    ["caseBindingDigest", input({ release: release({ caseBindingDigest: digest("9".repeat(64)) }) })],
    ["governedResultDigest", input({ release: release({ governedResultDigest: digest("9".repeat(64)) }) })],
    ["resultCiphertextDigest", input({ release: release({ resultCiphertextDigest: digest("9".repeat(64)) }) })],
    ["participantArtifactA", input({ release: release({ participantArtifactDigests: [digest("9".repeat(64)), digest("2".repeat(64))] }) })],
    ["participantArtifactB", input({ release: release({ participantArtifactDigests: [digest("1".repeat(64)), digest("9".repeat(64))] }) })],
    ["holderA", input({ participants: { holderA: HOLDER_B, holderB: HOLDER_B, payoutA: 600n, payoutB: 400n } })],
    ["holderB", input({ participants: { holderA: HOLDER_A, holderB: HOLDER_A, payoutA: 600n, payoutB: 400n } })],
    ["payoutA", input({ participants: { holderA: HOLDER_A, holderB: HOLDER_B, payoutA: 601n, payoutB: 400n } })],
    ["payoutB", input({ participants: { holderA: HOLDER_A, holderB: HOLDER_B, payoutA: 600n, payoutB: 401n } })],
    ["nonce", input({ nonce: 2n })],
    ["issuedAt", input({ issuedAt: 1_785_000_001 })],
    ["expiry", input({ expiry: 1_785_003_601 })],
  ];
  for (const [label, mutated] of mutations) {
    assert.notEqual(digestOf(buildGovernedBridgePayload(mutated)), base, `${label} must change the digest`);
  }
});

test("the verifying contract and chain are part of the digest", () => {
  const base = digestOf(buildGovernedBridgePayload(input()));
  assert.notEqual(
    digestOf(buildGovernedBridgePayload(input({ pins: { ...DEPLOYED_PINS, chainId: 1 } }))),
    base,
  );
  assert.notEqual(
    digestOf(buildGovernedBridgePayload(input({
      pins: { ...DEPLOYED_PINS, address: "0x0000000000000000000000000000000000000001" },
    }))),
    base,
  );
});

// ------------------------------------------------------------------ contract handoff

/**
 * The fixture handed to the contract developer.
 *
 * It is derived from the retained governed result whose Ed25519 signature and
 * cross-references were verified before it was written, and it is built under the
 * corrected semantics: `releaseAuthorityId` carries the governed Ed25519 release
 * authority, not the value the currently deployed adapter pins. These tests are
 * what keep the published fixture and this module from drifting apart.
 */
const HANDOFF = JSON.parse(
  readFileSync("docs/evidence/runtime-contract-handoff-2026-08-06.json", "utf8"),
) as {
  runtimeCandidateCommit: string;
  governedResult: Record<string, string | boolean>;
  eip712: { typeHash: string; primaryType: string; fields: { index: number; name: string; type: string }[]; domain: Record<string, unknown> };
  canonicalPayload: Record<string, string | boolean>;
  expectedDigests: Record<string, string | boolean>;
  expectedBridgeSigner: { address: string };
};

function handoffPayload() {
  const p = HANDOFF.canonicalPayload;
  const strip = (d: string) => d.slice("sha256:".length);
  const governed = HANDOFF.governedResult as Record<string, string>;
  return buildGovernedBridgePayload({
    release: {
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
    },
    participants: {
      holderA: p.holderA as `0x${string}`,
      holderB: p.holderB as `0x${string}`,
      payoutA: BigInt(p.payoutA as string),
      payoutB: BigInt(p.payoutB as string),
    },
    pins: {
      address: (HANDOFF.eip712.domain.verifyingContract as string) as `0x${string}`,
      chainId: HANDOFF.eip712.domain.chainId as number,
      assetIdentityDigest: `0x${strip(governed.assetIdentityDigest)}`,
      releaseAuthorityId: `0x${strip(governed.releaseAuthorityId)}`,
      releaseMode: p.releaseMode as `0x${string}`,
      circuitHash: `0x${strip(governed.circuitDigest)}`,
      parameterFingerprint: `0x${strip(governed.parameterFingerprint)}`,
    },
    interpretation: "PINS_GOVERNED_AUTHORITY",
    nonce: BigInt(p.nonce as string),
    issuedAt: Number(p.issuedAt),
    expiry: Number(p.expiry),
    governedSignatureVerified: true,
    crossReferencesVerified: true,
  });
}

test("the handoff fixture pins this runtime candidate", () => {
  assert.equal(HANDOFF.runtimeCandidateCommit, "5ca3382c90c37935b685853cecf96e1c74294e4c");
});

test("the handoff fixture declares the twenty fields in contract order", () => {
  assert.equal(HANDOFF.eip712.primaryType, "GovernedRelease");
  assert.equal(HANDOFF.eip712.typeHash, RELEASE_TYPEHASH);
  const declared = HANDOFF.eip712.fields;
  assert.equal(declared.length, 20);
  declared.forEach((field, index) => {
    assert.equal(field.index, index, "field indices must be contiguous and ordered");
  });
});

test("the handoff fixture reproduces its own published digests", () => {
  const payload = handoffPayload();
  assert.equal(digestOf(payload), HANDOFF.expectedDigests.viemTypedDataDigest);
  assert.equal(governedReleaseStructHash(payload), HANDOFF.expectedDigests.viemStructHash);
  // The published Solidity result and the published viem digest are the same value.
  assert.equal(
    HANDOFF.expectedDigests.soliditySolidityHashReleaseResult,
    HANDOFF.expectedDigests.viemTypedDataDigest,
  );
});

test("the handoff fixture is deterministic", () => {
  assert.equal(digestOf(handoffPayload()), digestOf(handoffPayload()));
});

test("the handoff fixture carries the governed Ed25519 authority, not the deployed pin", () => {
  const payload = handoffPayload();
  assert.equal(payload.message.releaseAuthorityId, `0x${GOVERNED_AUTHORITY}`);
  assert.notEqual(payload.message.releaseAuthorityId, DEPLOYED_PINS.releaseAuthorityId);
  assert.equal(payload.authorityInterpretation, "PINS_GOVERNED_AUTHORITY");
});

test("the handoff fixture carries no secret material", () => {
  const raw = readFileSync("docs/evidence/runtime-contract-handoff-2026-08-06.json", "utf8");
  for (const forbidden of ["PRIVATE KEY", "privateKey", "apiKey", "API_KEY", "secret:", "mnemonic"]) {
    assert.equal(raw.includes(forbidden), false, `${forbidden} must not appear in a public fixture`);
  }
  // No 64-hex-character 0x literal that is not one of the declared digests.
  assert.equal(/0x[0-9a-fA-F]{64}/u.test(raw), true);
});

test("no adapter address is hard-coded anywhere in the module", () => {
  const source = readFileSync("src/lib/protection/governed-recourse-bridge.ts", "utf8");
  // A deployment address in the module would bind every payload to one contract,
  // including one nobody has reviewed. The address arrives as an argument instead.
  assert.equal(/0x[0-9a-fA-F]{40}/u.test(source), false, "the module must not carry a deployment address");
});

// ------------------------------------------------------------------ the Boolean

test("the terminal Boolean is carried from the governed result and nowhere else", () => {
  const refused = buildGovernedBridgePayload(input({
    release: release({ conflict: false }),
    participants: { holderA: HOLDER_A, holderB: HOLDER_B, payoutA: 0n, payoutB: 0n },
  }));
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
      participants: { holderA: HOLDER_A, holderB: HOLDER_B, payoutA: 0n, payoutB: 0n },
    })),
    /PAYOUT_MISSING|must carry a payout/u,
  );
});

test("a payload cannot be built before the governed signature is verified", () => {
  assert.throws(
    () => buildGovernedBridgePayload({ ...input(), governedSignatureVerified: false as never }),
    /governed signature must be verified/u,
  );
  assert.throws(
    () => buildGovernedBridgePayload({ ...input(), crossReferencesVerified: false as never }),
    /cross-references must be verified/u,
  );
});

test("an inverted bridge window is refused", () => {
  assert.throws(
    () => buildGovernedBridgePayload(input({ issuedAt: 1_785_003_600, expiry: 1_785_000_000 })),
    /forward interval/u,
  );
});
