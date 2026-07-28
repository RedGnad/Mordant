/**
 * M-13 shared internals: fork hygiene, calldata substitution and the assumption register.
 *
 * The rehearsal writes to a local fork and must never be able to reach the public network, so the
 * hygiene checks below are gates rather than logging: a run that cannot prove it is talking to a
 * loopback Anvil refuses to send anything.
 */
import { ControlError } from "./runner-controls.mjs";

export const MONAD_CHAIN_ID = 10_143;

/** The A-Pass registry and the wallet observed issuing into it. Neither is guessed. */
export const APASS_REGISTRY = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
export const OBSERVED_ISSUER = "0xbd8428761efb5384c4945d16de56817caa6903df";

/**
 * The issuance transaction M-08 caused, and the block before it.
 *
 * `0xb8dd3664` is deliberately NOT called `issue`. Cleanverse publishes no ABI for it; all we have
 * is one observed, successful call. It is referred to throughout as the observed issuance call
 * selector, and nothing here claims to know its name or its full signature.
 */
export const OBSERVED_ISSUANCE = Object.freeze({
  txHash: "0x4693a9afbcf4ce3401de6ce7f095afe309e8de33836a8d0443d96bf1dca16fd8",
  blockNumber: 48_889_105n,
  parentBlockNumber: 48_889_104n,
  selector: "0xb8dd3664",
  subject: "0x0f8b9a0c064306f938912658c96c681d8655140b",
  calldata:
    "0xb8dd3664"
    + "0000000000000000000000000f8b9a0c064306f938912658c96c681d8655140b"
    + "0000000000000000000000000000000000000000000000000000000000000032"
    + "0000000000000000000000000000000000000000000000000000000000000000"
    + "0000000000000000000000000000000000000000000000000000000000000000"
    + "0000000000000000000000000000000000000000000000000000000000000000"
    + "000000000000000000000000000000000000000000000000000000006c4a2686"
    + "854d0f1a7fd0ef2ee7815a823bb7e95207222aa0abd1cb4294c93b4a27eeb699"
    + "0000000000000000000000000000000000000000000000000000000000000000",
});

const fail = (message) => {
  throw new ControlError(`STOP — ${message}`);
};

/** Only a loopback host may receive a write. Anything else could be the public network. */
export function assertLoopbackRpc(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail(`the write RPC "${url}" is not a URL.`);
  }
  if (!["127.0.0.1", "localhost", "[::1]", "::1"].includes(parsed.hostname)) {
    fail(`the write RPC host is ${parsed.hostname}, which is not loopback. A rehearsal must not be`
      + " able to reach the public network.");
  }
  return parsed.hostname;
}

/** The upstream is a fork source only, and must be a different endpoint from the write RPC. */
export function assertUpstreamSeparate(upstreamUrl, writeUrl) {
  if (String(upstreamUrl) === String(writeUrl)) {
    fail("the upstream and the write RPC are the same endpoint. The upstream is a fork source only.");
  }
  let upstream;
  try {
    upstream = new URL(upstreamUrl);
  } catch {
    fail(`the upstream "${upstreamUrl}" is not a URL.`);
  }
  if (["127.0.0.1", "localhost", "[::1]", "::1"].includes(upstream.hostname)) {
    fail("the upstream is loopback, so it is not a fork source. Point it at the Monad endpoint.");
  }
  return true;
}

/** The write endpoint must actually be Anvil, not something that merely answers on a local port. */
export function assertAnvilClient(clientVersion) {
  if (!/anvil/i.test(String(clientVersion ?? ""))) {
    fail(`web3_clientVersion reports "${clientVersion}", which does not identify Anvil.`
      + " Refusing to send writes to an unidentified client.");
  }
  return clientVersion;
}

/** The fork must present the chain the rehearsal targets. */
export function assertForkChain(chainId) {
  if (Number(chainId) !== MONAD_CHAIN_ID) {
    fail(`the fork reports chain ${chainId}, expected ${MONAD_CHAIN_ID}.`);
  }
  return Number(chainId);
}

/**
 * Substitutes only the address encoded in the first argument word, leaving every other byte alone.
 *
 * The bound is the point. This is an inference from one observed call, so the change is made as
 * narrow as it can be, and `diffCalldata` below proves afterwards that nothing else moved.
 */
export function substituteSubjectAddress(calldata, newAddress) {
  if (typeof calldata !== "string" || !calldata.startsWith("0x")) {
    fail("the observed calldata is not a hex string.");
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(newAddress))) {
    fail(`"${newAddress}" is not a 20-byte address.`);
  }
  const body = calldata.slice(10);
  if (body.length % 64 !== 0 || body.length === 0) {
    fail("the observed calldata does not divide into whole 32-byte words.");
  }
  const word0 = body.slice(0, 64);
  if (!/^0{24}[0-9a-fA-F]{40}$/.test(word0)) {
    fail("the first argument word is not a left-padded address, so it must not be substituted.");
  }
  const replaced = `${"0".repeat(24)}${String(newAddress).slice(2).toLowerCase()}`;
  return `${calldata.slice(0, 10)}${replaced}${body.slice(64)}`;
}

/**
 * Proves the substitution changed only what it claimed to.
 *
 * Reported as data rather than asserted quietly, so the artifact can be checked by someone who does
 * not trust the substitution function.
 */
export function diffCalldata(original, substituted) {
  const words = (data) => {
    const body = data.slice(10);
    return Array.from({ length: body.length / 64 }, (_, index) => body.slice(index * 64, (index + 1) * 64));
  };
  const originalWords = words(original);
  const substitutedWords = words(substituted);
  const differing = [];
  for (let index = 0; index < Math.max(originalWords.length, substitutedWords.length); index += 1) {
    if (originalWords[index] !== substitutedWords[index]) differing.push(index);
  }
  return {
    sameSelector: original.slice(0, 10) === substituted.slice(0, 10),
    sameLength: original.length === substituted.length,
    wordCount: originalWords.length,
    differingWords: differing,
    // The only acceptable difference is the low 20 bytes of word 0.
    onlySubjectAddressChanged: differing.length === 1 && differing[0] === 0
      && originalWords[0].slice(0, 24) === substitutedWords[0].slice(0, 24),
    originalWord0: originalWords[0] ?? null,
    substitutedWord0: substitutedWords[0] ?? null,
    unchangedWords: originalWords.slice(1),
  };
}

/** Refuses to send a substituted calldata that changed anything beyond the subject address. */
export function assertSubstitutionBounded(diff) {
  if (!diff.sameSelector) fail("the substituted calldata has a different selector.");
  if (!diff.sameLength) fail("the substituted calldata has a different length.");
  if (!diff.onlySubjectAddressChanged) {
    fail(`the substitution changed words ${diff.differingWords.join(", ")}; only the address in`
      + " word 0 may differ.");
  }
  return true;
}

export const EVIDENCE_GRADES = Object.freeze([
  "REPOSITORY-PROVEN", "ON-CHAIN OBSERVED", "FORK-PROVEN", "INFERRED", "NOT PROVEN",
]);

/**
 * The assumption register.
 *
 * Every premise this rehearsal rests on, graded. It exists because the previous brief assumed a
 * fork proof that had never been written, and that was only caught by looking. Grading each premise
 * makes the same mistake visible before it costs anything.
 */
export function assumptionRegister(overrides = {}) {
  const entries = [
    { premise: "The A-Pass issuer address",
      value: OBSERVED_ISSUER,
      grade: "ON-CHAIN OBSERVED",
      basis: `sender of ${OBSERVED_ISSUANCE.txHash}, a successful call into the registry` },
    { premise: "The issuance calldata shape",
      value: `${OBSERVED_ISSUANCE.selector}, 8 argument words`,
      grade: "ON-CHAIN OBSERVED",
      basis: "the exact bytes of that transaction. No ABI is published and none is claimed" },
    { premise: "Word 0 of the calldata is the subject address",
      value: OBSERVED_ISSUANCE.subject,
      grade: "INFERRED",
      basis: "word 0 equals the address whose A-Pass that call created. One observation, so the"
        + " substitution is bounded to this word and diffed before sending" },
    { premise: "Replaying the observed call on a fork issues an A-Pass",
      value: "control A",
      grade: overrides.controlA ?? "NOT PROVEN",
      basis: "exact byte-for-byte replay at the parent block, verified by readback" },
    { premise: "The same shape issues to a new contract address",
      value: "step B",
      grade: overrides.stepB ?? "NOT PROVEN",
      basis: "the bounded substitution, verified by readback and by the policy" },
    { premise: "MINV01 authorities: admin holds DEFAULT_ADMIN_ROLE, not MINTER_ROLE",
      value: "admin cannot mint",
      grade: "ON-CHAIN OBSERVED",
      basis: "hasRole is false and a read-only mint simulation reverts, recorded in M-12" },
    { premise: "No unexpected active minter on MINV01",
      value: overrides.minterExclusivity ?? "unestablished",
      grade: overrides.minterExclusivityGrade ?? "NOT PROVEN",
      basis: "requires reconstructing RoleGranted and RoleRevoked since issuance" },
    { premise: "The nine policy tuples pass for the real participants",
      value: overrides.tuples ?? "unestablished",
      grade: overrides.tuplesGrade ?? "NOT PROVEN",
      basis: "read from the policy on the fork once every address exists" },
    { premise: "The production adapter is the contract the vault binds",
      value: "CleanverseCvaAdapter",
      grade: "REPOSITORY-PROVEN",
      basis: "21 passing tests; the mock is referenced only from tests" },
    { premise: "Deployment ordering: adapter, A-Pass, roles, supply, vault, bind",
      value: "bindVault is the only one-shot step",
      grade: "REPOSITORY-PROVEN",
      basis: "read from bindVault's own require set in the adapter source" },
    { premise: "Cleanverse API can read a fork-local A-Pass",
      value: "no",
      grade: "NOT PROVEN",
      basis: "fork-local state never reaches Cleanverse; classified NOT APPLICABLE rather than failed" },
  ];
  for (const entry of entries) {
    if (!EVIDENCE_GRADES.includes(entry.grade)) {
      fail(`assumption "${entry.premise}" has grade "${entry.grade}", which is not a known grade.`);
    }
  }
  return entries;
}
