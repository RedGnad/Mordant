// Three-way agreement for the source-attestation EIP-712 digest.
//
// `MordantSourceAttestation` is a library with `internal` functions and
// `MordantFactoryV2` exposes no `attestationDigest` view, so the digest an
// issuer signs before a vault exists cannot be read from any deployed contract.
// A runner must derive it. This file makes that derivation safe by requiring
// three independent producers to agree, byte for byte:
//
//   1. the runner implementation      - `sourceAttestationDigest` in v4-digests.mjs
//   2. an independent reference       - `referenceDigest` below, which builds the
//                                       preimage by explicit 32-byte word
//                                       concatenation and shares no encoder with (1)
//   3. pinned Solidity vectors        - emitted by the frozen library itself in
//                                       contracts/test/SourceAttestationVectors.t.sol
//
// If any two disagree the runner must refuse to sign. A wrong digest would also
// revert on chain, but reverting after broadcast is a worse way to learn it.
import assert from "node:assert/strict";
import test from "node:test";
import { keccak256, stringToBytes, concatHex, pad, toHex, getAddress } from "viem";

import { sourceAttestationDigest, SOURCE_ATTESTATION_TYPEHASH, SOURCE_DOMAIN, domainSeparator }
  from "./v4-digests.mjs";
import { agreedSourceAttestationDigest, referenceDigest, referenceDomainSeparator, referenceStructHash }
  from "./source-attestation-digest.mjs";

/* -------------------------------------------------- the pinned Solidity vector */

const CHAIN_ID = 10_143;
const FACTORY = "0x1111111111111111111111111111111111111111";
const SOURCE_REGISTRY = "0x2222222222222222222222222222222222222222";

// Emitted by SourceAttestationVectorsTest against the frozen library.
const PINNED = {
  typehash: "0x5c84efcfafc8e9d8293daaf7fbc1b3023887538bb27651c6c46e8af3551b3397",
  structHash: "0xce83de9e69a87c459c4770633f5d47f240404196deae25bf492c9ca695bae497",
  digestFactory: "0x49b44a18bf3a9641c23c074ce802b681777f472ddbdf4e7bb38d1d39ff880824",
  digestSourceRegistry: "0x1d5598ee5e3236baff60335fc551898c0a2cf25f3c06994dddd5c2c4ee3e2ede",
  domainSeparatorFactory: "0x684163e2fbeb7d80a14c2603076b625a13a8015737f9e51e8a4d17688e12141e",
};

const VECTOR = {
  chainId: CHAIN_ID,
  factory: FACTORY,
  creationDigest: keccak256(stringToBytes("vector.creationDigest")),
  assetCommitment: keccak256(stringToBytes("vector.assetCommitment")),
  initialTermsCommitment: keccak256(stringToBytes("vector.initialTermsCommitment")),
  identitySchemeVersion: 3,
  termsSchemeVersion: 1,
  identityEpoch: 7,
  issuerKeyId: keccak256(stringToBytes("vector.issuerKeyId")),
  invoiceRoot: keccak256(stringToBytes("vector.invoiceRoot")),
  controller: "0x3333333333333333333333333333333333333333",
  validUntil: 1_800_000_000,
  nonce: 42,
};

/* ------------------------------------------------------------------- tests */

test("the typehash matches the frozen library", () => {
  assert.equal(SOURCE_ATTESTATION_TYPEHASH, PINNED.typehash);
});

test("the domain separator matches the frozen library", () => {
  assert.equal(domainSeparator(SOURCE_DOMAIN, CHAIN_ID, FACTORY), PINNED.domainSeparatorFactory);
  assert.equal(referenceDomainSeparator(CHAIN_ID, FACTORY), PINNED.domainSeparatorFactory);
});

test("the independent reference reproduces the pinned struct hash", () => {
  assert.equal(referenceStructHash(VECTOR), PINNED.structHash);
});

test("all three producers agree on the factory digest", () => {
  const runner = sourceAttestationDigest(VECTOR, CHAIN_ID, FACTORY);
  const reference = referenceDigest(VECTOR, CHAIN_ID, FACTORY);
  assert.equal(runner, PINNED.digestFactory, "runner vs pinned Solidity");
  assert.equal(reference, PINNED.digestFactory, "reference vs pinned Solidity");
  assert.equal(runner, reference, "runner vs reference");
});

test("all three producers agree on the source-registry digest", () => {
  const runner = sourceAttestationDigest(VECTOR, CHAIN_ID, SOURCE_REGISTRY);
  const reference = referenceDigest(VECTOR, CHAIN_ID, SOURCE_REGISTRY);
  assert.equal(runner, PINNED.digestSourceRegistry);
  assert.equal(reference, PINNED.digestSourceRegistry);
  assert.equal(runner, reference);
});

// The same attestation is signed once for the factory and once for the source
// registry. Confusing the two is a realistic mistake, so the separation is
// asserted rather than assumed.
test("the verifying contract separates the two digests", () => {
  assert.notEqual(PINNED.digestFactory, PINNED.digestSourceRegistry);
});

test("the agreement gate returns the digest when producers agree", () => {
  assert.equal(agreedSourceAttestationDigest(VECTOR, CHAIN_ID, FACTORY), PINNED.digestFactory);
});

// Every field must be covered: a transposition or a dropped field has to change
// the digest, or the gate is checking nothing.
test("every attestation field is covered by the digest", () => {
  const baseline = referenceDigest(VECTOR, CHAIN_ID, FACTORY);
  const mutations = {
    chainId: { ...VECTOR, chainId: CHAIN_ID + 1 },
    factory: { ...VECTOR, factory: SOURCE_REGISTRY },
    creationDigest: { ...VECTOR, creationDigest: keccak256(stringToBytes("x")) },
    assetCommitment: { ...VECTOR, assetCommitment: keccak256(stringToBytes("x")) },
    initialTermsCommitment: { ...VECTOR, initialTermsCommitment: keccak256(stringToBytes("x")) },
    identitySchemeVersion: { ...VECTOR, identitySchemeVersion: 4 },
    termsSchemeVersion: { ...VECTOR, termsSchemeVersion: 2 },
    identityEpoch: { ...VECTOR, identityEpoch: 8 },
    issuerKeyId: { ...VECTOR, issuerKeyId: keccak256(stringToBytes("x")) },
    invoiceRoot: { ...VECTOR, invoiceRoot: keccak256(stringToBytes("x")) },
    controller: { ...VECTOR, controller: SOURCE_REGISTRY },
    validUntil: { ...VECTOR, validUntil: 1_800_000_001 },
    nonce: { ...VECTOR, nonce: 43 },
  };
  for (const [field, mutated] of Object.entries(mutations)) {
    assert.notEqual(
      referenceDigest(mutated, CHAIN_ID, FACTORY), baseline,
      `${field} is not covered by the digest`,
    );
  }
});

// Transposing two same-width fields must also change the digest, which proves
// field ORDER is covered and not just field values.
test("transposing two fields changes the digest", () => {
  const swapped = {
    ...VECTOR,
    assetCommitment: VECTOR.initialTermsCommitment,
    initialTermsCommitment: VECTOR.assetCommitment,
  };
  assert.notEqual(referenceDigest(swapped, CHAIN_ID, FACTORY), PINNED.digestFactory);
});
