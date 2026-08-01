// The V5 call matrix, as executable data rather than prose.
//
// The governing rule for this mission is that no API may be inferred from
// naming or from a prior version. This file states every call the runner makes
// and, at load time, verifies each declaration against the freshly compiled
// ABI: the function must exist, its full signature must match, its selector
// must match, and its mutability must match.
//
// A renamed function, a reordered tuple, an added parameter or a view that
// silently became non-payable all fail here, before the runner touches a chain.
// The previous session found two real defects this way; this makes that check
// permanent rather than a thing someone remembered to do.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { toFunctionSelector, toFunctionSignature } from "viem";

import { REPO } from "./priv8-chain.mjs";

/// contract key -> compiled artifact path, relative to the repository.
export const ARTIFACTS = Object.freeze({
  eligibility: "contracts/out/MockEligibility.sol/MockEligibility.json",
  erc20: "contracts/out/MockERC20.sol/MockERC20.json",
  adapter: "contracts/out/MockCvaAdapter.sol/MockCvaAdapter.json",
  issuerRegistry: "contracts/out/MordantIssuerRegistry.sol/MordantIssuerRegistry.json",
  factory: "contracts/out/MordantFactoryV2.sol/MordantFactoryV2.json",
  vault: "contracts/out/MordantInvoiceVaultV2.sol/MordantInvoiceVaultV2.json",
  governance:
    "contracts/out/MordantScopeGovernanceRegistryV5.sol/MordantScopeGovernanceRegistryV5.json",
  sources:
    "contracts/out/MordantSourceCommitmentRegistry.sol/MordantSourceCommitmentRegistry.json",
  verifier: "contracts/out/MordantMatchVerifierV5.sol/MordantMatchVerifierV5.json",
  binder: "contracts/out/PrivateMatchBinderV5.sol/PrivateMatchBinderV5.json",
});

/// Every call the runner makes, with the selector it must resolve to.
///
/// `caller` is normative: several of these revert for the wrong sender by
/// design, and recording it here is what stops the runner sending a relayer
/// call from the deployer.
export const CALLS = Object.freeze([
  // ---- configuration, deployer as governor
  { key: "issuerRegistry", fn: "registerIssuer", selector: "0x64c6f49d", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "issuer authorized from the given epoch" },
  { key: "issuerRegistry", fn: "issuerKeyIdFor", selector: "0x43e33383", caller: "any", mutability: "pure",
    consumes: null, effect: "reads the issuer key id" },
  { key: "eligibility", fn: "setEligible", selector: "0x1301c0c9", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "role eligibility granted" },
  { key: "factory", fn: "setFacility", selector: "0x1fc53b5f", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "facility approved" },
  { key: "factory", fn: "setCvaAdapter", selector: "0xb3ebdb61", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "adapter approved" },
  { key: "factory", fn: "setSettlementToken", selector: "0x9b28cca9", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "settlement token approved" },

  // ---- vault
  { key: "factory", fn: "creationDigest", selector: "0xecb00e17", caller: "any", mutability: "view",
    consumes: null, effect: "the digest the attestation must name" },
  { key: "factory", fn: "createIdentityAnchoredVault", selector: "0x2f714234", caller: "buyer", mutability: "nonpayable",
    consumes: "issuer nonce", effect: "CREATE2 vault deployed and recorded under its attestation digest" },
  { key: "factory", fn: "vaultForRoot", selector: "0x144618ba", caller: "any", mutability: "view",
    consumes: null, effect: "readback of the created vault" },
  { key: "factory", fn: "vaultForAttestation", selector: "0xccccd48a", caller: "any", mutability: "view",
    consumes: null, effect: "the binder's anchor-provenance oracle" },

  // ---- opaque source admission
  { key: "sources", fn: "setAuthorizedSubmitter", selector: "0x5197a0d3", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "submitter allowed to publish opaque commitments" },
  { key: "sources", fn: "setAuthorizedRevealer", selector: "0x3ed7f066", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "binder allowed to open a commitment at binding" },
  { key: "sources", fn: "sourceCommitmentOf", selector: "0xe88a5629", caller: "any", mutability: "view",
    consumes: null, effect: "the opaque commitment, computed on chain so the runner derives nothing" },
  { key: "sources", fn: "commitSource", selector: "0xdec99436", caller: "submitter", mutability: "nonpayable",
    consumes: null, effect: "one 32-byte commitment published, nothing else" },
  { key: "sources", fn: "commitment", selector: "0x9fcb0985", caller: "any", mutability: "view",
    consumes: null, effect: "readback: committedAt, committedInBlock, submitter, exists, revealed" },

  // ---- governance and session
  { key: "governance", fn: "setAuthorizedRelayer", selector: "0x9011e5f9", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "relayer allowed to admit sessions" },
  { key: "governance", fn: "setAuthorizedBinder", selector: "0xd2206eea", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "binder allowed to resolve a session" },
  { key: "governance", fn: "authorize", selector: "0xdfcb2371", caller: "deployer", mutability: "nonpayable",
    consumes: "scope nonce", effect: "appends an authorization record valid from this block" },
  { key: "governance", fn: "intentDigest", selector: "0xa1b83fba", caller: "any", mutability: "view",
    consumes: null, effect: "the digest both controllers and the issuer sign" },
  { key: "governance", fn: "sessionNullifierOf", selector: "0x7cf180dd", caller: "any", mutability: "view",
    consumes: null, effect: "salt-independent one-shot identity of the signed intent" },
  { key: "governance", fn: "sessionCommitmentOf", selector: "0xd406f1dc", caller: "any", mutability: "view",
    consumes: null, effect: "the opaque session commitment" },
  { key: "governance", fn: "commitSession", selector: "0x4484e8ce", caller: "relayer", mutability: "nonpayable",
    consumes: "session nullifier", effect: "session admitted; nullifier consumed at admission" },
  { key: "governance", fn: "commitment", selector: "0x9fcb0985", caller: "any", mutability: "view",
    consumes: null, effect: "readback: nullifier, committedAt, committedInBlock, submitter, exists, consumed" },

  // ---- verifier, producer-side canonical digests
  { key: "verifier", fn: "setPolicyVersion", selector: "0x0f71a101", caller: "deployer", mutability: "nonpayable",
    consumes: null, effect: "policy version configured" },
  { key: "verifier", fn: "resultStructHash", selector: "0xa2538a0c", caller: "any", mutability: "pure",
    consumes: null, effect: "canonical EIP-712 struct hash; the runner must match it" },
  { key: "verifier", fn: "resultCommitmentOf", selector: "0xf417e039", caller: "any", mutability: "pure",
    consumes: null, effect: "canonical result commitment; the runner must match it" },
  { key: "verifier", fn: "resultDigest", selector: "0x3d6c354f", caller: "any", mutability: "view",
    consumes: null, effect: "EIP-712 digest over the result core" },
  { key: "verifier", fn: "attestationDigest", selector: "0x30488427", caller: "any", mutability: "view",
    consumes: null, effect: "what each validator signs" },
  { key: "verifier", fn: "recomputationContext", selector: "0x514c1bd3", caller: "any", mutability: "pure",
    consumes: null, effect: "context recomputed from the core, never read from the transcript" },
  { key: "verifier", fn: "replayKey", selector: "0xbb2bc62f", caller: "any", mutability: "pure",
    consumes: null, effect: "one of the six one-time identities" },
  { key: "verifier", fn: "decisionKey", selector: "0x1ce74e5a", caller: "any", mutability: "pure",
    consumes: null, effect: "one of the six one-time identities" },
  { key: "verifier", fn: "acceptMatch", selector: "0x6316be9b", caller: "binder-contract", mutability: "nonpayable",
    consumes: "replay, decision, session, nullifier, output, provider proof",
    effect: "INTERNAL ONLY: reverts unless msg.sender == core.binder" },

  // ---- binder, the single external transaction
  { key: "binder", fn: "consentDigest", selector: "0x814c1ad7", caller: "any", mutability: "view",
    consumes: null, effect: "the digest a controller signs; corrected in c709df2" },
  { key: "binder", fn: "bindRecourse", selector: "0x99d32920", caller: "any", mutability: "nonpayable",
    consumes: "result, decision, both sources, both consent nonces",
    effect: "THE atomic transaction: verify, reveal, consent, one recourse record" },
  { key: "binder", fn: "recourseOf", selector: "0xff503bf3", caller: "any", mutability: "view",
    consumes: null, effect: "readback of the opened recourse record" },
]);

const cache = new Map();

async function abiFor(key) {
  if (!cache.has(key)) {
    const path = ARTIFACTS[key];
    if (!path) throw new Error(`CALL_MATRIX_UNKNOWN_CONTRACT: ${key}`);
    cache.set(key, JSON.parse(await readFile(resolve(REPO, path), "utf8")).abi);
  }
  return cache.get(key);
}

/// Resolves one declared call against the compiled ABI.
export async function resolveCall(entry) {
  const abi = await abiFor(entry.key);
  const candidates = abi.filter((item) => item.type === "function" && item.name === entry.fn);
  if (candidates.length === 0) {
    throw new Error(`CALL_MATRIX_MISSING_FUNCTION: ${entry.key}.${entry.fn}`);
  }
  if (candidates.length > 1) {
    throw new Error(`CALL_MATRIX_OVERLOADED: ${entry.key}.${entry.fn} has ${candidates.length} overloads`);
  }
  const item = candidates[0];
  const signature = toFunctionSignature(item);
  return {
    ...entry,
    signature,
    resolvedSelector: toFunctionSelector(signature),
    resolvedMutability: item.stateMutability,
    inputs: item.inputs,
    outputs: item.outputs,
  };
}

/// Verifies the entire matrix. Returns the resolved calls; throws on the first
/// disagreement so a drifted ABI cannot reach a broadcast.
export async function verifyCallMatrix({ requireSelectors = true } = {}) {
  const resolved = [];
  const drift = [];
  for (const entry of CALLS) {
    const call = await resolveCall(entry);
    if (call.resolvedMutability !== entry.mutability) {
      drift.push(
        `${entry.key}.${entry.fn} mutability is ${call.resolvedMutability}, matrix says ${entry.mutability}`,
      );
    }
    const declared = entry.selector;
    const isPinned = declared && declared !== "0x00000000";
    if (requireSelectors && isPinned && declared !== call.resolvedSelector) {
      drift.push(
        `${entry.key}.${entry.fn} selector is ${call.resolvedSelector}, matrix pins ${declared}`,
      );
    }
    resolved.push(call);
  }
  if (drift.length > 0) throw new Error(`CALL_MATRIX_DRIFT:\n  ${drift.join("\n  ")}`);
  return resolved;
}

/// Emits the matrix with every selector resolved, for the evidence bundle and
/// for re-pinning after a deliberate schema change.
export async function renderCallMatrix() {
  const resolved = await verifyCallMatrix({ requireSelectors: false });
  return resolved.map((call) => ({
    contract: call.key,
    signature: call.signature,
    selector: call.resolvedSelector,
    caller: call.caller,
    mutability: call.resolvedMutability,
    consumes: call.consumes,
    effect: call.effect,
  }));
}
