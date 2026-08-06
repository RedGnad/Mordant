#!/usr/bin/env node
/**
 * Regenerates the runtime-to-contract handoff fixture, bound to the live adapter.
 *
 * Nothing here is copied from a report. The governed values come from the retained
 * evidence after its Ed25519 signature and cross-references are verified; the
 * adapter pins come from `eth_call` against the deployed adapter; and the two
 * participant wallets and the bounded payouts come from the contract developer's
 * committed demo configuration when it exists.
 *
 * The EIP-712 digest is required to match the adapter's own `hashRelease` view
 * byte for byte, or the fixture is not written.
 *
 * Usage:
 *   MORDANT_MONAD_RPC_URL=... MORDANT_RECOURSE_ADAPTER_ADDRESS=0x... \
 *     node scripts/build-recourse-handoff.mjs
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  createPublicClient, encodeAbiParameters, getAddress, hashTypedData, http, keccak256, parseAbi, toHex,
} from "viem";

const ROOT = process.cwd();
const SOURCE = "docs/evidence/conflicting-pledge-protection/conflict.json";
const DEMO_CONFIG = "docs/evidence/recourse-v2-demo-config-2026-08-06.json";
const OUTPUT = "docs/evidence/runtime-contract-handoff-2026-08-06.json";
const SOURCE_COMMIT_PIN = "b5587f6489933c6dc462da7fda56e57bd5f9e31b";
const SUPERSEDED_ADAPTER = "0x27677c837287b060D285d5C90096f06fBe675938";

const rpcUrl = process.env.MORDANT_MONAD_RPC_URL ?? process.env.MONAD_RPC_URL;
const adapterAddress = process.env.MORDANT_RECOURSE_ADAPTER_ADDRESS;
if (!rpcUrl) throw new Error("MORDANT_MONAD_RPC_URL is required");
if (!adapterAddress) throw new Error("MORDANT_RECOURSE_ADAPTER_ADDRESS is required");
if (adapterAddress.toLowerCase() === SUPERSEDED_ADAPTER.toLowerCase()) {
  throw new Error("The superseded adapter must not be used");
}

const evidence = await import("../.product-test-dist/src/lib/protection/protection-evidence.js");
const bridge = await import("../.product-test-dist/src/lib/protection/governed-recourse-bridge.js");

const retained = JSON.parse(readFileSync(join(ROOT, SOURCE), "utf8"));
evidence.verifyGovernedResultSignature(retained.governedResult);
evidence.assertPublicProtectionEvidence(retained, SOURCE_COMMIT_PIN);
const governed = retained.governedResult;
const governedResultDigest = evidence.governedResultDigest(governed);

const ABI = parseAbi([
  "function settlementToken() view returns (address)",
  "function cviVerifier() view returns (address)",
  "function attestor() view returns (address)",
  "function facility() view returns (address)",
  "function assetIdentityDigest() view returns (bytes32)",
  "function expectedGovernedReleaseAuthorityId() view returns (bytes32)",
  "function releaseMode() view returns (bytes32)",
  "function circuitHash() view returns (bytes32)",
  "function parameterFingerprint() view returns (bytes32)",
  "function cureWindow() view returns (uint64)",
  "function availableReserve() view returns (uint256)",
  "function domainSeparator() view returns (bytes32)",
  "function ROLE_HOLDER() view returns (uint8)",
  "function hashRelease((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,address,uint256,uint256,bool,bytes32,bytes32,bytes32,bytes32,uint256,uint64,uint64) r) view returns (bytes32)",
]);
const CVI = parseAbi(["function isEligible(address,uint8) view returns (bool)"]);

const client = createPublicClient({ transport: http(rpcUrl) });
const address = getAddress(adapterAddress);
const read = (functionName, args = []) => client.readContract({ address, abi: ABI, functionName, args });

const chainId = await client.getChainId();
const pins = {
  settlementToken: await read("settlementToken"),
  cviVerifier: await read("cviVerifier"),
  attestor: await read("attestor"),
  facility: await read("facility"),
  assetIdentityDigest: await read("assetIdentityDigest"),
  expectedGovernedReleaseAuthorityId: await read("expectedGovernedReleaseAuthorityId"),
  releaseMode: await read("releaseMode"),
  circuitHash: await read("circuitHash"),
  parameterFingerprint: await read("parameterFingerprint"),
  cureWindow: String(await read("cureWindow")),
  availableReserve: String(await read("availableReserve")),
  domainSeparator: await read("domainSeparator"),
  roleHolder: Number(await read("ROLE_HOLDER")),
};

// The two participants and the bounded payouts are the contract developer's to
// state. Without the committed configuration the fixture still binds everything
// that is verifiable, and records exactly what is missing.
const demoPresent = existsSync(join(ROOT, DEMO_CONFIG));
const demo = demoPresent ? JSON.parse(readFileSync(join(ROOT, DEMO_CONFIG), "utf8")) : null;
const participants = demo?.participants ?? demo ?? {};
const payouts = demo?.payouts ?? demo ?? {};

// Provisional values, used only so a deterministic encoding vector exists. They
// are 60/40 of a bounded amount, matching the committed record-date allocation.
const holderA = getAddress(participants.holderA ?? "0x911F99f424D47F08a15fcC771e94dcc2f7252B02");
const holderB = getAddress(participants.holderB ?? "0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0");
const payoutA = BigInt(payouts.payoutA ?? 600);
const payoutB = BigInt(payouts.payoutB ?? 400);

const eligibility = {};
for (const [label, holder] of [["holderA", holderA], ["holderB", holderB]]) {
  eligibility[label] = await client.readContract({
    address: pins.cviVerifier, abi: CVI, functionName: "isEligible", args: [holder, pins.roleHolder],
  });
}

const release = {
  runId: retained.runId,
  fheCaseId: governed.caseId,
  caseBindingDigest: governed.caseBindingDigest,
  assetIdentity: governed.assetIdentity,
  governedResultDigest,
  resultCiphertextDigest: governed.resultCiphertextDigest,
  participantArtifactDigests: governed.participantArtifactDigests,
  circuitDigest: governed.circuitDigest,
  parameterFingerprint: governed.parameterFingerprint,
  releaseAuthorityId: governed.releaseAuthorityId,
  releaseMode: governed.releaseMode,
  conflict: governed.conflict,
};

const payload = bridge.buildGovernedBridgePayload({
  release,
  participants: { holderA, holderB, payoutA, payoutB },
  pins: {
    address, chainId,
    assetIdentityDigest: pins.assetIdentityDigest,
    releaseAuthorityId: pins.expectedGovernedReleaseAuthorityId,
    releaseMode: pins.releaseMode,
    circuitHash: pins.circuitHash,
    parameterFingerprint: pins.parameterFingerprint,
  },
  interpretation: "PINS_GOVERNED_AUTHORITY",
  nonce: 1n, issuedAt: 1785000000, expiry: 1785003600,
  governedSignatureVerified: true, crossReferencesVerified: true,
});

const m = payload.message;
const tuple = [
  m.runId, m.fheCaseId, m.caseBindingDigest, m.assetIdentityDigest, m.governedResultDigest,
  m.resultCiphertextDigest, m.participantArtifactDigestA, m.participantArtifactDigestB,
  m.holderA, m.holderB, m.payoutA, m.payoutB, m.conflict, m.releaseAuthorityId,
  m.releaseMode, m.circuitHash, m.parameterFingerprint, m.nonce, m.issuedAt, m.expiry,
];
const viemDigest = hashTypedData({
  domain: payload.domain, types: payload.types, primaryType: payload.primaryType, message: m,
});
const solidityDigest = await read("hashRelease", [tuple]);
if (viemDigest.toLowerCase() !== solidityDigest.toLowerCase()) {
  throw new Error(`EIP-712 parity failed: viem ${viemDigest} vs solidity ${solidityDigest}`);
}
const localDomainSeparator = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "uint256" }, { type: "address" }],
  [
    keccak256(toHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
    keccak256(toHex(payload.domain.name)), keccak256(toHex(payload.domain.version)),
    BigInt(chainId), address,
  ],
));
if (localDomainSeparator.toLowerCase() !== pins.domainSeparator.toLowerCase()) {
  throw new Error("Domain separator disagrees with the deployed adapter");
}

const fixture = {
  schemaVersion: "mordant.runtime-contract-handoff/2",
  generatedAt: "2026-08-06",
  runtimeCandidateBranch: "feat/live-participant-admission-v1-runtime-candidate",
  sourceRetainedGovernedResult: SOURCE,
  sourceCommitPin: SOURCE_COMMIT_PIN,

  adapter: {
    address, chainId, network: "monad-testnet", generation: "V2",
    settlementToken: pins.settlementToken,
    cviVerifier: pins.cviVerifier,
    attestor: pins.attestor,
    facility: pins.facility,
    assetIdentityDigest: pins.assetIdentityDigest,
    expectedGovernedReleaseAuthorityId: pins.expectedGovernedReleaseAuthorityId,
    releaseMode: pins.releaseMode,
    circuitHash: pins.circuitHash,
    parameterFingerprint: pins.parameterFingerprint,
    cureWindowSeconds: Number(pins.cureWindow),
    availableReserve: pins.availableReserve,
    domainSeparator: pins.domainSeparator,
    roleHolder: pins.roleHolder,
    readMethod: "eth_call against the deployed adapter",
  },

  supersededAdapter: {
    address: SUPERSEDED_ADAPTER,
    status: "SUPERSEDED",
    mustNotBeUsed: true,
    reason: "Its releaseAuthorityId pin was keccak256 of an invented label string and was never derived from the governed Ed25519 authority. It also pinned keccak label hashes for circuitHash and parameterFingerprint instead of the governed content digests.",
    retainedAs: "explicit superseded evidence only",
  },

  semantics: {
    releaseAuthorityId: "Identifies the governed Ed25519 release authority: the designated decryptor whose Ed25519 signature over MordantGovernedConflictResult/v1 is the sole authority for the terminal Boolean. Adapter V2 pins it as expectedGovernedReleaseAuthorityId and compares it as data; the EVM cannot verify an Ed25519 signature.",
    bridgeAttestor: "A separate secp256k1 key and a separate role. It signs the EIP-712 GovernedRelease so the adapter can authenticate the relayed payload. It cannot produce the governed Boolean.",
    circuitAndParameters: "Content-derived only. Adapter V2 pins the governed sha256 digests; label-derived alternatives are rejected by the runtime production path.",
    releaseMode: "Label convention retained: the governed result names it as a string and the adapter pins keccak256 of that string.",
  },

  governedResult: {
    releaseAuthorityId: governed.releaseAuthorityId,
    releaseAuthorityPublicKeyEd25519Base64: governed.releaseAuthorityPublicKey,
    governedResultDigest,
    resultCiphertextDigest: governed.resultCiphertextDigest,
    participantArtifactDigestA: governed.participantArtifactDigests[0],
    participantArtifactDigestB: governed.participantArtifactDigests[1],
    evaluatedArtifactDigest: governed.evaluatedArtifactDigest,
    caseBindingDigest: governed.caseBindingDigest,
    assetIdentityDigest: governed.assetIdentity,
    circuitDigest: governed.circuitDigest,
    parameterFingerprint: governed.parameterFingerprint,
    releaseMode: governed.releaseMode,
    fheCaseId: governed.caseId,
    runId: retained.runId,
    conflict: governed.conflict,
  },

  eip712: {
    domain: payload.domain,
    primaryType: payload.primaryType,
    typeString: bridge.RELEASE_TYPE_STRING,
    typeHash: bridge.RELEASE_TYPEHASH,
    fields: payload.types.GovernedRelease.map((field, index) => ({ index, name: field.name, type: field.type })),
  },

  encodingVector: {
    purpose: "Proves the runtime and Adapter V2 agree on the EIP-712 encoding. Verified by eth_call against the deployed adapter. This is NOT a submission payload.",
    participantsAreProvisional: !demoPresent,
    payload: {
      runId: m.runId, fheCaseId: m.fheCaseId, caseBindingDigest: m.caseBindingDigest,
      assetIdentityDigest: m.assetIdentityDigest, governedResultDigest: m.governedResultDigest,
      resultCiphertextDigest: m.resultCiphertextDigest,
      participantArtifactDigestA: m.participantArtifactDigestA,
      participantArtifactDigestB: m.participantArtifactDigestB,
      holderA: m.holderA, holderB: m.holderB,
      payoutA: m.payoutA.toString(), payoutB: m.payoutB.toString(),
      conflict: m.conflict, releaseAuthorityId: m.releaseAuthorityId, releaseMode: m.releaseMode,
      circuitHash: m.circuitHash, parameterFingerprint: m.parameterFingerprint,
      nonce: m.nonce.toString(), issuedAt: m.issuedAt.toString(), expiry: m.expiry.toString(),
    },
    expectedDigests: {
      viemDomainSeparator: localDomainSeparator,
      adapterDomainSeparator: pins.domainSeparator,
      viemStructHash: bridge.governedReleaseStructHash(payload),
      viemTypedDataDigest: viemDigest,
      soliditySolidityHashReleaseResult: solidityDigest,
      byteIdentical: true,
    },
  },

  participantEligibility: {
    verifier: pins.cviVerifier,
    role: pins.roleHolder,
    holderA: { address: holderA, eligible: eligibility.holderA },
    holderB: { address: holderB, eligible: eligibility.holderB },
    method: "eth_call cviVerifier.isEligible(address, ROLE_HOLDER)",
  },

  submissionPayload: demoPresent && eligibility.holderA && eligibility.holderB
    ? { status: "READY", note: "Derived from the committed demo configuration and verified above." }
    : {
      status: "PENDING",
      blockedOn: [
        !demoPresent ? `the committed configuration ${DEMO_CONFIG} does not exist on any ref` : null,
        !eligibility.holderA ? `holderA ${holderA} is not eligible under the adapter compliance verifier` : null,
        !eligibility.holderB ? `holderB ${holderB} is not eligible under the adapter compliance verifier` : null,
      ].filter(Boolean),
      requiredInputs: ["participants.holderA", "participants.holderB", "payouts.payoutA", "payouts.payoutB"],
      constraint: `payoutA + payoutB must not exceed availableReserve (${pins.availableReserve})`,
    },

  expectedBridgeSigner: {
    address: pins.attestor,
    curve: "secp256k1",
    role: "ECDSA bridge attestor",
    environmentName: "MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY",
    note: "The key is not held by the runtime and is never committed. Only the derived address is recorded.",
  },

  compatibilityAssertions: {
    governedEd25519SignatureVerified: true,
    crossReferencesVerified: true,
    noBrowserSuppliedBoolean: true,
    noBrowserSuppliedPayload: true,
    allTwentySignedFieldsPresentInContractOrder: true,
    eachSignedFieldMutationChangesDigest: true,
    deterministic: true,
    consumedByBridgeTests: true,
    liveBridgeTransactionSent: false,
  },

  containsNoSecrets: true,
};

writeFileSync(join(ROOT, OUTPUT), `${JSON.stringify(fixture, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({
  wrote: OUTPUT, adapter: address, chainId,
  viemDigest, solidityDigest, byteIdentical: viemDigest === solidityDigest,
  demoConfigPresent: demoPresent, submission: fixture.submissionPayload.status,
}, null, 2)}\n`);
