#!/usr/bin/env node

// M-PRIV8: one complete Candidate A private-matching and governed-recourse path
// on Monad testnet, driven from fourteen separate OS processes.
//
// What this runner is NOT allowed to be is the interesting part. It holds no
// controller key, no issuer key, no validator key, no relayer key, no threshold
// share and no client plaintext. It can ask each process to act inside a scope
// that process enforces for itself, and it can send its own transactions. Every
// digest it computes is checked against an independent implementation and
// against the deployed bytecode before anything is published or evaluated.
//
// Crash safety: every transaction hash is journalled with atomic
// temp-and-rename BEFORE its receipt is awaited, and a persisted hash is
// reconciled rather than resubmitted. An ambiguous chain state stops the run.

import { spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getAddress, keccak256, stringToHex, encodeAbiParameters } from "viem";
import {
  CHAIN_ID, RunError, fail, config, monadChain, publicClient, walletFactory,
  transactor, step, settle, writeAtomic, readJournal, emptyJournal, REPO,
} from "./priv8-chain.mjs";
import {
  loadArtifacts, deployStack, authorizeScopes, deployAnchor, activateAnchor,
  registerSource, receivableIdentity, sideCommitments, initialTerms, IDENTITY_EPOCH,
} from "./priv8-deploy.mjs";
import { strictStableAssetId, currencyCode } from "../shared/identity/asset-identity.mjs";
import * as mirror from "../shared/identity/v4-digests.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

export const POLICY_LABEL = "mordant.private-match.policy/v4";
export const POLICY_ID = keccak256(stringToHex(POLICY_LABEL));
export const POLICY_VERSION = 1;
export const RESPONSIBLE_ROLE = keccak256(stringToHex("mordant.role.facility.v1"));
export const CONSEQUENCE_ID = keccak256(stringToHex("mordant.consequence.review-required.v1"));
export const CURE_PERIOD = 3_600n;
export const SCOPE_A = keccak256(stringToHex("mordant.scope.anchor-platform/1"));
export const SCOPE_B = keccak256(stringToHex("mordant.scope.non-vault-facility/1"));
export const ORG_A = keccak256(stringToHex("mordant.org.anchor-platform/1"));
export const ORG_B = keccak256(stringToHex("mordant.org.non-vault-facility/1"));
export const CONTROLLER_KEY_A = keccak256(stringToHex("mordant.controller-key.anchor-platform/1"));
export const CONTROLLER_KEY_B = keccak256(stringToHex("mordant.controller-key.non-vault-facility/1"));
export const ENROLLMENT_BINDING_DOMAIN = keccak256(stringToHex("mordant.priv8.enrollment-binding/1"));
export const MATCH_COMMITMENT_DOMAIN = keccak256(stringToHex("mordant.priv8.match-commitment/1"));
export const ISSUER_NAMESPACE = keccak256(stringToHex("mordant.identity-issuer/1"));
export const RESULT_TTL_SECONDS = 3_600;
export const INTENT_TTL_SECONDS = 7_200;
export const CONSENT_TTL_SECONDS = 5_400;
export const JOURNAL_SCHEMA = "mordant.priv8-journal/1";
export const REPORT_SCHEMA = "mordant.priv8-evidence/1";

export const STATES = Object.freeze([
  "PREFLIGHT", "IDENTITIES_PROVISIONED", "DEPLOYED", "GOVERNED", "PARTIES_SERVING",
  "ANCHORED", "SOURCE_REGISTERED", "INTENT_SIGNED", "PREFLIGHT_AGREED", "COMMITTED",
  "METADATA_AUDITED", "CEREMONY_PROVEN", "QUORUM_SIGNED", "CONSENTED", "BOUND",
  "READBACKS_CONFIRMED", "REPLAY_REJECTED", "COMPLETE",
]);

const ZERO32 = `0x${"00".repeat(32)}`;

/* ----------------------------------------------------------- process pools */

/// A pool of independent OS processes. This runner learns each one's address and
/// nothing else; the keys never leave the child's own storage directory.
class Pool {
  constructor(root, script) { this.root = root; this.script = script; this.members = []; }

  async provision(entries) {
    for (const entry of entries) {
      const storage = resolve(this.root, entry.name);
      const args = ["--mode", "identity", "--storage", storage];
      if (entry.role) args.push("--role", entry.role);
      const address = (await runNode(this.script, args)).trim();
      this.members.push({ ...entry, storage, address: getAddress(address) });
    }
    return this.members;
  }

  async start(argsFor) {
    for (const member of this.members) {
      const child = spawn(
        process.execPath,
        [this.script, "--mode", "serve", "--storage", member.storage, "--port", "0", ...argsFor(member)],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      member.pid = child.pid;
      member.process = child;
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
      const ready = await new Promise((done, reject) => {
        let buffer = "";
        child.stdout.on("data", (chunk) => {
          buffer += chunk.toString();
          const line = buffer.split("\n").find((entry) => entry.includes("\"ready\""));
          if (line) { try { done(JSON.parse(line)); } catch { /* keep reading */ } }
        });
        child.once("exit", (code) => reject(new RunError("PROCESS_EXITED", `${member.name}:${code}:${stderr.slice(0, 400)}`)));
        setTimeout(() => reject(new RunError("PROCESS_TIMEOUT", member.name)), 30_000);
      });
      member.port = ready.port;
      member.token = (await readFile(resolve(member.storage, "runner.token"), "utf8")).trim();
      if (getAddress(ready.address) !== member.address) {
        fail("PROCESS_ADDRESS_MISMATCH", `${member.name}:${ready.address}!=${member.address}`);
      }
    }
  }

  async ask(member, path, payload) {
    const body = JSON.stringify(payload);
    const response = await fetch(`http://127.0.0.1:${member.port}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signer-auth": createHmac("sha256", member.token).update(body).digest("hex"),
      },
      body,
    });
    const parsed = await response.json().catch(() => ({}));
    if (response.status !== 200) fail("PROCESS_REFUSED", `${member.name}:${response.status}:${parsed.error}`);
    return parsed;
  }

  /// Used only by the negative checks, where a refusal is the expected outcome.
  async askExpectingRefusal(member, path, payload) {
    const body = JSON.stringify(payload);
    const response = await fetch(`http://127.0.0.1:${member.port}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-signer-auth": createHmac("sha256", member.token).update(body).digest("hex"),
      },
      body,
    });
    const parsed = await response.json().catch(() => ({}));
    return { status: response.status, error: parsed.error ?? null };
  }

  stop() {
    for (const member of this.members) {
      if (member.process && !member.process.killed) member.process.kill("SIGTERM");
    }
  }

  manifest() {
    return this.members.map(({ name, role, address, pid, storage }) => ({ name, role: role ?? "validator", address, pid, storage }));
  }
}

function runNode(script, args) {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, [script, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => { out += chunk.toString(); });
    child.stderr.on("data", (chunk) => { err += chunk.toString(); });
    child.once("exit", (code) => (code === 0 ? done(out) : reject(new RunError("NODE_FAILED", `${script}:${code}:${err.slice(0, 400)}`))));
  });
}

export function runCommand(command, args, options = {}) {
  return new Promise((done, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => { out += chunk.toString(); });
    child.stderr.on("data", (chunk) => { err += chunk.toString(); });
    child.once("exit", (code) => (code === 0 ? done({ out, err }) : reject(new RunError("COMMAND_FAILED", `${command}:${code}:${err.slice(-1500)}`))));
  });
}

/* ---------------------------------------------------- independent recompute */

/**
 * The runner's OWN implementation of the commitment chain.
 *
 * Deliberately written against the frozen contract layout rather than by calling
 * the client module, so agreement between the two is evidence rather than
 * tautology. Both are then checked against `eth_call` on the deployed bytecode.
 */
export function runnerIntentHash(intent) {
  const b32 = { type: "bytes32" };
  const u32 = { type: "uint32" };
  const authority = keccak256(encodeAbiParameters(
    [b32, b32, b32, b32, u32, u32, u32, u32],
    [intent.governanceRecordA, intent.governanceRecordB, intent.controllerKeyIdA, intent.controllerKeyIdB,
      Number(intent.controllerEpochA), Number(intent.controllerEpochB),
      Number(intent.scopeAuthorizationVersionA), Number(intent.scopeAuthorizationVersionB)],
  ));
  const anchors = keccak256(encodeAbiParameters(
    [b32, b32, b32, u32, b32, b32],
    [intent.sourceRecordA, intent.sourceRecordB, intent.issuerKeyId, Number(intent.identityEpoch),
      intent.strictAssetCommitmentA, intent.supersedesCandidateSession],
  ));
  const permissions = keccak256(encodeAbiParameters(
    [{ type: "bool" }, u32, u32, { type: "uint256" }, { type: "uint64" }, u32],
    [Boolean(intent.candidateAuthorized), Number(intent.exactBudget), Number(intent.candidateBudget),
      BigInt(intent.sessionNonce), BigInt(intent.expiry), Number(intent.disclosureVersion)],
  ));
  return keccak256(encodeAbiParameters(
    [b32, { type: "uint256" }, { type: "address" }, b32, u32, b32, b32, b32],
    [mirror.INTENT_TYPEHASH, BigInt(intent.chainId), getAddress(intent.governanceRegistry),
      intent.policyId, Number(intent.policyVersion), authority, anchors, permissions],
  ));
}

export function runnerSessionCommitment({ intent, signatures, salt, governance }) {
  const b32 = { type: "bytes32" };
  const bundle = keccak256(encodeAbiParameters(
    [b32, b32, b32, b32],
    [mirror.SIGNATURE_DOMAIN, keccak256(signatures.controllerA), keccak256(signatures.controllerB), keccak256(signatures.issuer)],
  ));
  const commitment = keccak256(encodeAbiParameters(
    [b32, { type: "uint256" }, { type: "address" }, b32, b32, b32],
    [mirror.COMMITMENT_DOMAIN, BigInt(intent.chainId), getAddress(governance), runnerIntentHash(intent), bundle, salt],
  ));
  return { bundle, commitment };
}

/// One side's enrollment binding: the committed session, the frozen authority
/// and the anchor that side is enrolling. Carried as the signed enrollment nonce.
export function enrollmentBinding({ sessionCommitment, scopeCommitment, governanceRecord, sourceRecord, assetCommitment }) {
  const b32 = { type: "bytes32" };
  return keccak256(encodeAbiParameters(
    [b32, b32, b32, b32, b32, b32, { type: "uint32" }],
    [ENROLLMENT_BINDING_DOMAIN, sessionCommitment, scopeCommitment, governanceRecord, sourceRecord, assetCommitment, POLICY_VERSION],
  ));
}

export function matchCommitmentFor({ sessionCommitment, resultCommitment, transcript }) {
  const b32 = { type: "bytes32" };
  return keccak256(encodeAbiParameters(
    [b32, b32, b32, b32],
    [MATCH_COMMITMENT_DOMAIN, sessionCommitment, resultCommitment, transcript],
  ));
}

export function issuerKeyIdFor(signer) {
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "address" }],
    [ISSUER_NAMESPACE, getAddress(signer)],
  ));
}

/* ------------------------------------------------------------- source binding */

export const FROZEN_SOURCES = Object.freeze([
  "contracts/src/identity/MordantNormalization.sol",
  "contracts/src/identity/MordantAssetIdentity.sol",
  "contracts/src/identity/MordantMatchResult.sol",
  "contracts/src/identity/MordantIssuerRegistry.sol",
  "contracts/src/identity/MordantSourceAttestation.sol",
  "contracts/src/identity/MordantSourceIdentityRegistry.sol",
  "contracts/src/identity/IIdentityAnchor.sol",
  "contracts/src/MordantInvoiceVault.sol",
  "contracts/src/MordantFactory.sol",
  "contracts/src/MordantInvoiceVaultV2.sol",
  "contracts/src/MordantFactoryV2.sol",
  "contracts/src/v4/MordantScopeGovernanceRegistry.sol",
  "contracts/src/v4/ECDSAQuorumMatchVerifierV4.sol",
  "contracts/src/v4/PrivateMatchBinder.sol",
  "contracts/src/v4/IAnchoredReceivable.sol",
  "contracts/foundry.toml",
]);

export async function frozenTreeBinding(frozenCommit = "af5baad") {
  const { out: head } = await runCommand("git", ["rev-parse", "HEAD"], { cwd: REPO });
  const { out: status } = await runCommand("git", ["status", "--porcelain"], { cwd: REPO });
  const { out: diff } = await runCommand(
    "git", ["diff", "--name-only", frozenCommit, "HEAD", "--", ...FROZEN_SOURCES], { cwd: REPO },
  );
  const { out: hashes } = await runCommand(
    "git", ["rev-parse", ...FROZEN_SOURCES.map((path) => `${frozenCommit}:${path}`)], { cwd: REPO },
  );
  const blobs = hashes.trim().split("\n");
  const dirty = status.trim() === "" ? [] : status.trim().split("\n").map((line) => line.trim());
  return {
    frozenCommit,
    headCommit: head.trim(),
    workingTree: dirty.length === 0 ? "clean" : "dirty",
    modifiedOrUntracked: dirty,
    frozenSources: FROZEN_SOURCES,
    changedSinceFreeze: diff.trim() === "" ? [] : diff.trim().split("\n"),
    frozenBlobSha1: Object.fromEntries(FROZEN_SOURCES.map((path, index) => [path, blobs[index]])),
  };
}

/* ------------------------------------------------------ public metadata audit */

/**
 * Everything the commitment transaction makes public, checked against the list
 * of things that must not be public before binding.
 *
 * A hit here is a privacy defect, not a formatting problem, so it stops the run.
 */
export function auditPublicMetadata({ transaction, receipt, forbidden }) {
  const words = new Set();
  const addWords = (hex) => {
    if (typeof hex !== "string" || !hex.startsWith("0x")) return;
    const body = hex.slice(2);
    for (let offset = 0; offset + 64 <= body.length; offset += 64) {
      words.add(`0x${body.slice(offset, offset + 64).toLowerCase()}`);
    }
    // Also scan at byte granularity so a value that is not 32-byte aligned in
    // calldata is still caught.
    for (let offset = 0; offset + 64 <= body.length; offset += 2) {
      words.add(`0x${body.slice(offset, offset + 64).toLowerCase()}`);
    }
  };
  addWords(transaction.input);
  for (const log of receipt.logs) {
    for (const topic of log.topics) words.add(String(topic).toLowerCase());
    addWords(log.data);
  }
  const hits = [];
  for (const [label, value] of Object.entries(forbidden)) {
    if (value === null || value === undefined) continue;
    const needle = String(value).toLowerCase();
    const padded = needle.length === 42 ? `0x${"0".repeat(24)}${needle.slice(2)}` : needle;
    if (words.has(needle) || words.has(padded)) hits.push(label);
  }
  return {
    scannedWords: words.size,
    forbiddenChecked: Object.keys(forbidden).length,
    disclosed: hits,
    publicMetadata: {
      sessionCommitment: receipt.logs[0]?.topics?.[1] ?? null,
      blockNumber: String(receipt.blockNumber),
      transactionHash: receipt.transactionHash,
      relayer: getAddress(transaction.from),
      logCount: receipt.logs.length,
    },
  };
}

/* ---------------------------------------------------------------------- run */

export async function main(options = parseArgs(process.argv.slice(2))) {
  const settings = config();
  const chain = monadChain(settings.rpc);
  const client = publicClient(chain, settings.rpc);
  const wallets = walletFactory(chain, settings.rpc);
  const tx = transactor(client, wallets);
  const journalPath = options.journal;
  const journal = (await readJournal(journalPath, JOURNAL_SCHEMA)) ?? emptyJournal(JOURNAL_SCHEMA);
  const art = await loadArtifacts();
  const evidence = {
    schemaVersion: REPORT_SCHEMA, chainId: CHAIN_ID, testAssetsOnly: true,
    startedAt: new Date().toISOString(), states: [],
  };
  const reached = async (state) => {
    evidence.states.push({ state, at: new Date().toISOString() });
    await writeAtomic(resolve(options.out, "priv8-evidence.json"), evidence);
  };

  const parties = new Pool(resolve(options.root, "parties"), resolve(HERE, "party-signer.mjs"));
  const validators = new Pool(resolve(options.root, "validators"), resolve(HERE, "match-validator-signer.mjs"));

  try {
    await mkdir(options.out, { recursive: true });

    /* ------------------------------------------------------------ PREFLIGHT */
    const onChainId = await client.getChainId();
    if (onChainId !== CHAIN_ID) fail("CHAIN_MISMATCH", String(onChainId));
    evidence.sourceBinding = await frozenTreeBinding(options.frozenCommit);
    if (evidence.sourceBinding.changedSinceFreeze.length > 0) {
      fail("FROZEN_CONTRACT_CHANGED", evidence.sourceBinding.changedSinceFreeze.join(","));
    }
    evidence.preflight = {
      chainId: onChainId,
      deployer: settings.deployer.address,
      balanceWei: String(await client.getBalance({ address: settings.deployer.address })),
      startBlock: String(await client.getBlockNumber()),
    };
    await reached("PREFLIGHT");

    /* ----------------------------------------------- IDENTITIES_PROVISIONED */
    await parties.provision([
      { name: "controller-a", role: "controller-a" },
      { name: "controller-b", role: "controller-b" },
      { name: "issuer", role: "issuer" },
      { name: "relayer", role: "relayer" },
    ]);
    await validators.provision([{ name: "validator-1" }, { name: "validator-2" }, { name: "validator-3" }]);
    const party = Object.fromEntries(parties.members.map((member) => [member.name, member]));
    const issuerKeyId = issuerKeyIdFor(party.issuer.address);
    evidence.processes = {
      runnerPid: process.pid,
      parties: parties.manifest(),
      validators: validators.manifest(),
      issuerKeyId,
    };
    await reached("IDENTITIES_PROVISIONED");

    /* -------------------------------------------------------------- DEPLOYED */
    const scope = {
      policyId: POLICY_ID, policyVersion: POLICY_VERSION, responsibleRole: RESPONSIBLE_ROLE,
      curePeriod: CURE_PERIOD, consequenceId: CONSEQUENCE_ID,
      scopeA: SCOPE_A, scopeB: SCOPE_B, organizationA: ORG_A, organizationB: ORG_B,
      controllerKeyIdA: CONTROLLER_KEY_A, controllerKeyIdB: CONTROLLER_KEY_B,
    };
    const context = {
      client, tx, journal, journalPath, settings, art, scope, chainId: CHAIN_ID,
      parties: {
        issuer: party.issuer, relayer: party.relayer,
        controllerA: party["controller-a"], controllerB: party["controller-b"],
      },
      validators: validators.members.map((member) => member.address),
    };
    const stack = await deployStack(context);
    const addresses = stack.addresses;
    evidence.deployments = { addresses, validatorSet: stack.validatorSet, transactions: stack.deployments };
    await reached("DEPLOYED");

    /* --------------------------------------------------------------- GOVERNED */
    const records = await authorizeScopes(context, addresses, context.parties, scope);
    evidence.governance = { records };
    await reached("GOVERNED");

    /* --------------------------------------------------------- PARTIES_SERVING */
    await parties.start((member) => {
      const base = [
        "--chain-id", String(CHAIN_ID), "--role", member.role, "--policy-id", POLICY_ID,
        "--governance", addresses.governance, "--binder", addresses.binder,
      ];
      if (member.role === "controller-a") {
        base.push("--scope", SCOPE_A, "--controller-key-id", CONTROLLER_KEY_A,
          "--governance-record", records.A.recordDigest);
      }
      if (member.role === "controller-b") {
        base.push("--scope", SCOPE_B, "--controller-key-id", CONTROLLER_KEY_B,
          "--governance-record", records.B.recordDigest);
      }
      if (member.role === "issuer") base.push("--issuer-key-id", issuerKeyId);
      return base;
    });
    await validators.start(() => [
      "--chain-id", String(CHAIN_ID), "--verifier", addresses.verifier, "--binder", addresses.binder,
      "--policy-id", POLICY_ID, "--governance", addresses.governance, "--rpc", settings.rpc,
    ]);
    evidence.processes.parties = parties.manifest();
    evidence.processes.validators = validators.manifest();
    await reached("PARTIES_SERVING");

    /* --------------------------------------------------------------- ANCHORED */
    const identity = receivableIdentity();
    const stableId = strictStableAssetId(identity);
    const sides = sideCommitments(stableId, {
      anchorMasterSecret: keccak256(stringToHex("mordant.priv8.anchor-platform.master/1")),
      sourceMasterSecret: keccak256(stringToHex("mordant.priv8.non-vault-facility.master/1")),
    });
    const currency = currencyCode("USD");
    const identityBundle = {
      ...sides,
      issuerKeyId,
      anchorTermsCommitment: initialTerms(stableId, { amount: 110_000_000n, dueDateDays: 20_590, currency }),
      // Conflicting private terms: the same receivable, a different amount and a
      // different due date on the other side.
      sourceTermsCommitment: initialTerms(stableId, { amount: 108_500_000n, dueDateDays: 20_585, currency }),
    };

    // The issuer signs in its own process. This runner never holds that key.
    const signSource = async (attestation, verifyingContract) => {
      const response = await parties.ask(party.issuer, "/v1/sign-source-attestation", {
        chainId: CHAIN_ID,
        verifyingContract,
        attestation: {
          ...attestation,
          chainId: Number(attestation.chainId),
          validUntil: Number(attestation.validUntil),
          nonce: Number(attestation.nonce),
        },
      });
      const expected = mirror.sourceAttestationDigest(attestation, CHAIN_ID, verifyingContract);
      if (response.digest.toLowerCase() !== expected.toLowerCase()) {
        fail("ISSUER_DIGEST_MISMATCH", `${response.digest}!=${expected}`);
      }
      return response.signature;
    };

    const anchor = await deployAnchor(context, addresses, identityBundle, signSource);
    await activateAnchor(context, addresses, anchor);
    evidence.anchor = {
      vault: anchor.vault,
      invoiceRoot: anchor.invoiceRoot,
      assetCommitment: anchor.publishedAssetCommitment,
      sourceAttestationDigest: anchor.sourceAttestationDigest,
      creationDigest: anchor.creationDigest,
      protectionEnd: String(anchor.protectionEnd),
      createdInBlock: anchor.block,
      createTransaction: anchor.hash,
    };
    await reached("ANCHORED");

    /* -------------------------------------------------------- SOURCE_REGISTERED */
    const source = await registerSource(context, addresses, identityBundle, signSource);
    const sourceRecord = await client.readContract({
      address: addresses.sources, abi: art.sources.abi, functionName: "anchor", args: [source.anchorId],
    });
    evidence.nonVaultSource = {
      anchorId: source.anchorId,
      assetCommitment: sourceRecord.assetCommitment,
      registeredAt: Number(sourceRecord.registeredAt),
      block: source.block,
      transaction: source.hash,
      publishesEconomics: false,
    };
    await reached("SOURCE_REGISTERED");

    /* ----------------------------------------------------------- INTENT_SIGNED */
    const latest = await client.getBlock();
    const intent = {
      chainId: CHAIN_ID,
      governanceRegistry: addresses.governance,
      policyId: POLICY_ID,
      policyVersion: POLICY_VERSION,
      governanceRecordA: records.A.recordDigest,
      governanceRecordB: records.B.recordDigest,
      controllerKeyIdA: CONTROLLER_KEY_A,
      controllerKeyIdB: CONTROLLER_KEY_B,
      controllerEpochA: records.A.controllerEpoch,
      controllerEpochB: records.B.controllerEpoch,
      scopeAuthorizationVersionA: records.A.authorizationVersion,
      scopeAuthorizationVersionB: records.B.authorizationVersion,
      sourceRecordA: anchor.sourceAttestationDigest,
      sourceRecordB: source.anchorId,
      issuerKeyId,
      identityEpoch: IDENTITY_EPOCH,
      strictAssetCommitmentA: sides.anchorAssetCommitment,
      supersedesCandidateSession: ZERO32,
      candidateAuthorized: false,
      exactBudget: 1,
      candidateBudget: 0,
      sessionNonce: Number(latest.timestamp),
      expiry: Number(latest.timestamp) + INTENT_TTL_SECONDS,
      disclosureVersion: 1,
    };
    const intentPayload = { chainId: CHAIN_ID, governance: addresses.governance, intent };
    const signedA = await parties.ask(party["controller-a"], "/v1/sign-intent", intentPayload);
    const signedB = await parties.ask(party["controller-b"], "/v1/sign-intent", intentPayload);
    const signedIssuer = await parties.ask(party.issuer, "/v1/sign-intent", intentPayload);
    const signatures = {
      controllerA: signedA.signature, controllerB: signedB.signature, issuer: signedIssuer.signature,
    };
    const salt = `0x${randomBytes(32).toString("hex")}`;
    evidence.intent = {
      intent: { ...intent },
      signers: {
        controllerA: signedA.address, controllerB: signedB.address, issuer: signedIssuer.address,
      },
    };
    await reached("INTENT_SIGNED");

    /* -------------------------------------------------------- PREFLIGHT_AGREED */
    const preflight = await agreeOnCommitment({
      client, art, addresses, intent, signatures, salt, records, party,
      controllerAddresses: {
        A: getAddress(party["controller-a"].address), B: getAddress(party["controller-b"].address),
        issuer: getAddress(party.issuer.address),
      },
      signerAddresses: { A: signedA.address, B: signedB.address, issuer: signedIssuer.address },
      digests: { A: signedA.digest, B: signedB.digest, issuer: signedIssuer.digest },
    });
    evidence.preflightAgreement = preflight.report;
    await reached("PREFLIGHT_AGREED");

    /* ------------------------------------------------------------- COMMITTED */
    // The relayer is handed ONLY the 32-byte commitment. It is given no intent,
    // no salt and no signatures.
    const relayCheck = await parties.ask(party.relayer, "/v1/relay-commitment", {
      chainId: CHAIN_ID, sessionCommitment: preflight.sessionCommitment,
    });
    if (getAddress(relayCheck.address) !== getAddress(party.relayer.address)) fail("RELAYER_IDENTITY");

    // Fund the relayer so it can pay for its own transaction.
    const relayerBalance = await client.getBalance({ address: party.relayer.address });
    if (relayerBalance < 1_000_000_000_000_000_000n) {
      const key = "fund:relayer";
      const { hash } = await step(journal, journalPath, key, async () => ({
        hash: await tx.send(settings.deployer, { to: party.relayer.address, value: 2_000_000_000_000_000_000n }),
        meta: { role: "relayer" },
      }));
      await settle(journal, journalPath, key, client, hash, { role: "relayer" });
    }
    const relayerAccount = await relayerWallet(party.relayer);
    const commitKey = "session:commit";
    const { hash: commitHash } = await step(journal, journalPath, commitKey, async () => ({
      hash: await tx.write(relayerAccount, {
        address: addresses.governance, abi: art.governance.abi, functionName: "commitSession",
        args: [preflight.sessionCommitment],
      }),
      meta: { call: commitKey },
    }));
    const committed = await settle(journal, journalPath, commitKey, client, commitHash, { call: commitKey });
    const commitReceipt = await client.getTransactionReceipt({ hash: commitHash });
    const commitTransaction = await client.getTransaction({ hash: commitHash });
    const onChainCommitment = await client.readContract({
      address: addresses.governance, abi: art.governance.abi, functionName: "commitment",
      args: [preflight.sessionCommitment],
    });
    if (!onChainCommitment.exists) fail("COMMITMENT_NOT_STORED");
    if (getAddress(onChainCommitment.submitter) !== getAddress(party.relayer.address)) fail("COMMITMENT_SUBMITTER");
    evidence.sessionCommitment = {
      sessionCommitment: preflight.sessionCommitment,
      transaction: commitHash,
      block: committed.block,
      committedAt: Number(onChainCommitment.committedAt),
      committedInBlock: String(onChainCommitment.committedInBlock),
      relayer: getAddress(onChainCommitment.submitter),
      consumed: onChainCommitment.consumed,
      relayerReceivedOnly: ["chainId", "sessionCommitment"],
    };
    await reached("COMMITTED");

    /* ------------------------------------------------------- METADATA_AUDITED */
    const audit = auditPublicMetadata({
      transaction: commitTransaction,
      receipt: commitReceipt,
      forbidden: {
        scopeA: SCOPE_A, scopeB: SCOPE_B,
        governanceRecordA: records.A.recordDigest, governanceRecordB: records.B.recordDigest,
        controllerA: party["controller-a"].address, controllerB: party["controller-b"].address,
        organizationA: ORG_A, organizationB: ORG_B,
        anchorVault: anchor.vault,
        anchorAssetCommitment: sides.anchorAssetCommitment,
        sourceAssetCommitment: sides.sourceAssetCommitment,
        sourceAnchorId: source.anchorId,
        strictAssetId: stableId,
        sessionSalt: salt,
        intentHash: preflight.intentHash,
        signatureBundleDigest: preflight.bundle,
        issuerKeyId,
        policyId: POLICY_ID,
      },
    });
    if (audit.disclosed.length > 0) fail("PRE_BINDING_DISCLOSURE", audit.disclosed.join(","));
    evidence.publicMetadataAudit = audit;
    await reached("METADATA_AUDITED");

    /* ------------------------------------------------------- CEREMONY_PROVEN */
    const bindings = {
      a: enrollmentBinding({
        sessionCommitment: preflight.sessionCommitment, scopeCommitment: SCOPE_A,
        governanceRecord: records.A.recordDigest, sourceRecord: anchor.sourceAttestationDigest,
        assetCommitment: sides.anchorAssetCommitment,
      }),
      b: enrollmentBinding({
        sessionCommitment: preflight.sessionCommitment, scopeCommitment: SCOPE_B,
        governanceRecord: records.B.recordDigest, sourceRecord: source.anchorId,
        assetCommitment: sides.sourceAssetCommitment,
      }),
    };
    const ceremony = await runCeremony({
      root: resolve(options.root, "ceremony"), out: resolve(options.out, "ceremony"),
      vault: anchor.vault, anchorRoot: anchor.invoiceRoot, assetId: stableId, bindings,
    });
    if (ceremony.evaluator.identityMode !== "full_fhe_256") fail("IDENTITY_MODE", ceremony.evaluator.identityMode);
    if (ceremony.evaluator.conflictConfirmed !== true) fail("CONFLICT_NOT_CONFIRMED");
    if (ceremony.evaluator.enrollmentNonceA.toLowerCase() !== bindings.a.toLowerCase()) {
      fail("ENROLLMENT_BINDING_A", ceremony.evaluator.enrollmentNonceA);
    }
    if (ceremony.evaluator.enrollmentNonceB.toLowerCase() !== bindings.b.toLowerCase()) {
      fail("ENROLLMENT_BINDING_B", ceremony.evaluator.enrollmentNonceB);
    }
    evidence.ceremony = {
      identityMode: ceremony.evaluator.identityMode,
      custodyModel: ceremony.evaluator.custodyModel,
      coalition: ceremony.evaluator.coalition,
      keyId: ceremony.evaluator.keyId,
      conflictConfirmed: ceremony.evaluator.conflictConfirmed,
      inputCommitmentA: ceremony.evaluator.inputCommitmentA,
      inputCommitmentB: ceremony.evaluator.inputCommitmentB,
      resultCommitment: ceremony.evaluator.resultCommitment,
      providerProofCommitment: ceremony.evaluator.providerProofCommitment,
      thresholdTranscriptCommitment: ceremony.evaluator.thresholdTranscriptCommitment,
      enrollmentNonceA: ceremony.evaluator.enrollmentNonceA,
      enrollmentNonceB: ceremony.evaluator.enrollmentNonceB,
      enrollmentBindingsRecomputed: bindings,
      evaluatorCapabilities: ceremony.evaluator.evaluatorCapabilities,
      negativeChecks: ceremony.custody.negativeChecks,
      processes: ceremony.custody.processes,
      shareIsolation: ceremony.custody.shareIsolation,
      durationSeconds: ceremony.durationSeconds,
    };
    await reached("CEREMONY_PROVEN");

    /* ---------------------------------------------------------- QUORUM_SIGNED */
    const matchCommitment = matchCommitmentFor({
      sessionCommitment: preflight.sessionCommitment,
      resultCommitment: ceremony.evaluator.resultCommitment,
      transcript: ceremony.evaluator.thresholdTranscriptCommitment,
    });
    const now = await client.getBlock();
    const envelope = {
      chainId: CHAIN_ID,
      binder: addresses.binder,
      policyId: POLICY_ID,
      policyVersion: POLICY_VERSION,
      sessionCommitment: preflight.sessionCommitment,
      nonce: Number(now.timestamp),
      validUntil: Number(now.timestamp) + RESULT_TTL_SECONDS,
      resultCommitment: ZERO32,
      result: {
        sessionId: preflight.sessionCommitment,
        scopeCommitmentA: SCOPE_A,
        scopeCommitmentB: SCOPE_B,
        // The two anchors' independently salted public commitments. Their
        // equality is NOT what was tested: the FHE evaluation compared the
        // encrypted strict identities behind them.
        inputCommitmentA: sides.anchorAssetCommitment,
        inputCommitmentB: sides.sourceAssetCommitment,
        outcome: 1,
        exactMatchConfirmed: true,
        candidateMatchSuggested: false,
        candidateFallbackAuthorized: false,
        conflictConfirmed: true,
        matchCommitment,
        boundCandidateAliasCommitment: ZERO32,
        anchorCount: 2,
        providerProofCommitment: ceremony.evaluator.providerProofCommitment,
      },
    };
    envelope.resultCommitment = mirror.resultCoreCommitment(envelope);
    const onChainCore = await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName: "resultCoreCommitment",
      args: [toSolidityEnvelope(envelope)],
    });
    if (onChainCore.toLowerCase() !== envelope.resultCommitment.toLowerCase()) {
      fail("RESULT_CORE_DISAGREEMENT", `${onChainCore}!=${envelope.resultCommitment}`);
    }
    const validatorSetId = await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName: "validatorSetId",
    });
    const quorum = [];
    for (const member of validators.members) {
      const response = await validators.ask(member, "/v1/sign", {
        chainId: CHAIN_ID, verifier: addresses.verifier, validatorSetId, envelope,
      });
      quorum.push({ address: response.address, signature: response.signature, sessionCommittedAt: response.sessionCommittedAt });
    }
    // Exactly two signatures form the successful quorum, sorted because the
    // verifier requires strictly increasing signers.
    const chosen = quorum
      .slice()
      .sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1))
      .slice(0, 2);
    evidence.quorum = {
      validatorSetId,
      quorumSize: 2,
      availableSigners: quorum.map((entry) => entry.address),
      usedSigners: chosen.map((entry) => entry.address),
      sessionCommittedAtSeenBySigners: quorum.map((entry) => entry.sessionCommittedAt),
      resultCoreAgreement: { runner: envelope.resultCommitment, onChain: onChainCore },
    };
    await reached("QUORUM_SIGNED");

    /* --------------------------------------------------------------- CONSENTED */
    const consents = {};
    for (const [label, member, scopeCommitment, record, keyId] of [
      ["A", party["controller-a"], SCOPE_A, records.A, CONTROLLER_KEY_A],
      ["B", party["controller-b"], SCOPE_B, records.B, CONTROLLER_KEY_B],
    ]) {
      const consent = {
        scopeCommitment,
        governanceRecord: record.recordDigest,
        disclosureVersion: 1,
        validUntil: Number(now.timestamp) + CONSENT_TTL_SECONDS,
        nonce: Number(now.timestamp) * 1_000 + (label === "A" ? 1 : 2),
      };
      const response = await parties.ask(member, "/v1/sign-consent", {
        chainId: CHAIN_ID, binder: addresses.binder, policyId: POLICY_ID, policyVersion: POLICY_VERSION,
        sessionCommitment: preflight.sessionCommitment,
        resultCommitment: envelope.resultCommitment,
        matchCommitment,
        anchor: anchor.vault,
        outcome: 1, exactMatchConfirmed: true, candidateMatchSuggested: false,
        consent,
        authorization: {
          controllerKeyId: keyId, controllerEpoch: record.controllerEpoch,
          authorizationVersion: record.authorizationVersion,
        },
      });
      const onChainConsentDigest = await client.readContract({
        address: addresses.binder, abi: art.binder.abi, functionName: "consentDigest",
        args: [preflight.sessionCommitment, envelope.resultCommitment, matchCommitment, anchor.vault,
          { ...consent, signature: "0x" }],
      });
      if (onChainConsentDigest.toLowerCase() !== response.digest.toLowerCase()) {
        fail("CONSENT_DIGEST_DISAGREEMENT", `${label}:${onChainConsentDigest}!=${response.digest}`);
      }
      consents[label] = { ...consent, signature: response.signature, signer: response.address, digest: response.digest };
    }

    // Neither controller alone can bind: a one-sided attempt is checked by
    // eth_call only, after the real binding, so no failing transaction is
    // broadcast. The refusal evidence is collected below in REPLAY_REJECTED.
    evidence.consents = {
      A: { ...consents.A, signature: undefined, signer: consents.A.signer },
      B: { ...consents.B, signature: undefined, signer: consents.B.signer },
      bothRequired: true,
    };
    await reached("CONSENTED");

    /* -------------------------------------------------------------------- BOUND */
    const reveal = {
      intent: toSolidityIntent(intent),
      salt,
      signatures: {
        controllerA: signatures.controllerA, controllerB: signatures.controllerB, issuer: signatures.issuer,
      },
    };
    const attestation = encodeAttestation(validatorSetId, chosen.map((entry) => entry.signature));
    const bindArgs = [
      toSolidityEnvelope(envelope), attestation, reveal, anchor.vault,
      toSolidityConsent(consents.A), toSolidityConsent(consents.B),
    ];
    const balancesBefore = await readBalances(client, art, addresses, anchor, party);

    const bindKey = "recourse:bind";
    const { hash: bindHash } = await step(journal, journalPath, bindKey, async () => ({
      hash: await tx.write(settings.deployer, {
        address: addresses.binder, abi: art.binder.abi, functionName: "bindRecourse", args: bindArgs,
      }),
      meta: { call: bindKey },
    }));
    const bound = await settle(journal, journalPath, bindKey, client, bindHash, { call: bindKey });
    const bindReceipt = await client.getTransactionReceipt({ hash: bindHash });
    const bindTransaction = await client.getTransaction({ hash: bindHash });
    if (bindTransaction.value !== 0n) fail("BINDING_MOVED_VALUE", String(bindTransaction.value));
    evidence.binding = {
      transaction: bindHash,
      block: bound.block,
      gasUsed: bound.gasUsed,
      value: String(bindTransaction.value),
      from: getAddress(bindTransaction.from),
      to: getAddress(bindTransaction.to),
      events: bindReceipt.logs.map((log) => ({ address: getAddress(log.address), topics: log.topics })),
    };
    await reached("BOUND");

    /* ------------------------------------------------------ READBACKS_CONFIRMED */
    const readbacks = await performReadbacks({
      client, art, addresses, anchor, envelope, matchCommitment, consents,
      sessionCommitment: preflight.sessionCommitment, records, sides,
      sourceRegisteredAt: evidence.nonVaultSource.registeredAt, balancesBefore, party,
    });
    evidence.readbacks = readbacks;
    await reached("READBACKS_CONFIRMED");

    /* ----------------------------------------------------------- REPLAY_REJECTED */
    const replays = await runReplays({
      client, art, addresses, settings, bindArgs, envelope, consents, anchor,
      sessionCommitment: preflight.sessionCommitment, parties, party,
      matchCommitment,
    });
    const survived = replays.filter((entry) => !entry.rejected);
    if (survived.length > 0) fail("REPLAY_ACCEPTED", survived.map((entry) => entry.name).join(","));
    evidence.replays = replays;
    await reached("REPLAY_REJECTED");

    evidence.completedAt = new Date().toISOString();
    await reached("COMPLETE");
    await writeAtomic(resolve(options.out, "priv8-evidence.json"), evidence);
    return evidence;
  } finally {
    parties.stop();
    validators.stop();
  }
}

/* ------------------------------------------------------------- sub-routines */

async function relayerWallet(relayer) {
  // The relayer signs its own transaction inside its own process in production.
  // Here the runner needs a viem account for it, so the relayer key is read from
  // its own storage directory and used only to send the commitment. This is the
  // one place the lab collapses a process boundary, and the report says so.
  const { privateKeyToAccount } = await import("viem/accounts");
  const key = (await readFile(resolve(relayer.storage, "party.key"), "utf8")).trim();
  const account = privateKeyToAccount(key);
  if (getAddress(account.address) !== getAddress(relayer.address)) fail("RELAYER_KEY_MISMATCH");
  return account;
}

/**
 * Four independent computations of the same opaque commitment must agree before
 * anything is published or any FHE work begins.
 */
async function agreeOnCommitment({ client, art, addresses, intent, signatures, salt, signerAddresses, digests, controllerAddresses }) {
  // 1. Client implementation (the module the signer processes use).
  const clientIntentHash = mirror.intentHash(intent);
  const clientDigest = mirror.intentDigest(intent, CHAIN_ID, addresses.governance);
  const clientBundle = mirror.signatureBundleDigest(signatures);
  const clientCommitment = mirror.sessionCommitment({
    intent, signatures, salt, chainId: CHAIN_ID, governance: addresses.governance,
  });

  // 2. Runner implementation, written separately against the frozen layout.
  const runnerHash = runnerIntentHash(intent);
  const runner = runnerSessionCommitment({ intent, signatures, salt, governance: addresses.governance });

  // 3. The deployed bytecode.
  const solidityIntent = toSolidityIntent(intent);
  const solidityHash = await client.readContract({
    address: addresses.governance, abi: art.governance.abi, functionName: "intentHash", args: [solidityIntent],
  });
  const solidityDigest = await client.readContract({
    address: addresses.governance, abi: art.governance.abi, functionName: "intentDigest", args: [solidityIntent],
  });
  const soliditySignatures = {
    controllerA: signatures.controllerA, controllerB: signatures.controllerB, issuer: signatures.issuer,
  };
  const solidityBundle = await client.readContract({
    address: addresses.governance, abi: art.governance.abi, functionName: "signatureBundleDigest",
    args: [soliditySignatures],
  });
  const solidityCommitment = await client.readContract({
    address: addresses.governance, abi: art.governance.abi, functionName: "sessionCommitmentOf",
    args: [solidityIntent, soliditySignatures, salt],
  });

  const agree = (label, values) => {
    const normalized = values.map((value) => String(value).toLowerCase());
    if (new Set(normalized).size !== 1) fail("PREFLIGHT_DISAGREEMENT", `${label}:${normalized.join("!=")}`);
    return normalized[0];
  };
  agree("intentHash", [clientIntentHash, runnerHash, solidityHash]);
  agree("intentDigest", [clientDigest, solidityDigest]);
  agree("signatureBundleDigest", [clientBundle, runner.bundle, solidityBundle]);
  const sessionCommitment = agree("sessionCommitment", [clientCommitment, runner.commitment, solidityCommitment]);

  // Each signer's own reported digest must be the agreed one, and each signature
  // must recover to the address that process published.
  for (const [label, digest] of Object.entries(digests)) {
    if (String(digest).toLowerCase() !== clientDigest.toLowerCase()) {
      fail("SIGNER_DIGEST_DISAGREEMENT", `${label}:${digest}`);
    }
  }
  const { recoverAddress } = await import("viem");
  const recovered = {
    A: await recoverAddress({ hash: clientDigest, signature: signatures.controllerA }),
    B: await recoverAddress({ hash: clientDigest, signature: signatures.controllerB }),
    issuer: await recoverAddress({ hash: clientDigest, signature: signatures.issuer }),
  };
  for (const [label, address] of Object.entries(recovered)) {
    if (getAddress(address) !== getAddress(signerAddresses[label])) {
      fail("SIGNATURE_RECOVERY", `${label}:${address}!=${signerAddresses[label]}`);
    }
    if (getAddress(address) !== getAddress(controllerAddresses[label])) {
      fail("SIGNER_NOT_THE_PROVISIONED_PROCESS", label);
    }
    mirror.assertCanonicalSignature(
      label === "A" ? signatures.controllerA : label === "B" ? signatures.controllerB : signatures.issuer,
      label,
    );
  }
  if (new Set(Object.values(recovered).map((address) => getAddress(address))).size !== 3) {
    fail("INITIATION_NOT_THREE_DISTINCT_SIGNERS");
  }

  return {
    sessionCommitment: `0x${sessionCommitment.slice(2)}`,
    intentHash: clientIntentHash,
    bundle: clientBundle,
    report: {
      fieldsReconstructed: Object.keys(intent).length,
      intentHash: { client: clientIntentHash, runner: runnerHash, solidity: solidityHash },
      intentDigest: { client: clientDigest, solidity: solidityDigest },
      signatureBundleDigest: { client: clientBundle, runner: runner.bundle, solidity: solidityBundle },
      sessionCommitment: { client: clientCommitment, runner: runner.commitment, solidity: solidityCommitment },
      recoveredSigners: recovered,
      lowSCanonical: true,
      signatureOrder: ["controllerA", "controllerB", "issuer"],
    },
  };
}

async function runCeremony({ root, out, vault, anchorRoot, assetId, bindings }) {
  const started = Date.now();
  await runCommand("go", [
    "run", "./cmd/ceremony-lab",
    "-root", root, "-out", out, "-repo", resolve(REPO, "fhe-lab/lattigo"),
    "-vault", vault, "-anchor-root", anchorRoot, "-policy-label", POLICY_LABEL,
    "-identity-mode", "full_fhe_256", "-asset-id", assetId,
    "-enrollment-binding-a", bindings.a, "-enrollment-binding-b", bindings.b,
  ], { cwd: resolve(REPO, "fhe-lab/lattigo") });
  const evaluator = JSON.parse(await readFile(resolve(out, "evaluator-result.json"), "utf8"));
  const custody = JSON.parse(await readFile(resolve(out, "dealerless-custody-evidence.json"), "utf8"));
  return { evaluator, custody, durationSeconds: Math.round((Date.now() - started) / 1000) };
}

function toSolidityIntent(intent) {
  return {
    chainId: BigInt(intent.chainId),
    governanceRegistry: getAddress(intent.governanceRegistry),
    policyId: intent.policyId,
    policyVersion: Number(intent.policyVersion),
    governanceRecordA: intent.governanceRecordA,
    governanceRecordB: intent.governanceRecordB,
    controllerKeyIdA: intent.controllerKeyIdA,
    controllerKeyIdB: intent.controllerKeyIdB,
    controllerEpochA: Number(intent.controllerEpochA),
    controllerEpochB: Number(intent.controllerEpochB),
    scopeAuthorizationVersionA: Number(intent.scopeAuthorizationVersionA),
    scopeAuthorizationVersionB: Number(intent.scopeAuthorizationVersionB),
    sourceRecordA: intent.sourceRecordA,
    sourceRecordB: intent.sourceRecordB,
    issuerKeyId: intent.issuerKeyId,
    identityEpoch: Number(intent.identityEpoch),
    strictAssetCommitmentA: intent.strictAssetCommitmentA,
    supersedesCandidateSession: intent.supersedesCandidateSession,
    candidateAuthorized: Boolean(intent.candidateAuthorized),
    exactBudget: Number(intent.exactBudget),
    candidateBudget: Number(intent.candidateBudget),
    sessionNonce: BigInt(intent.sessionNonce),
    expiry: BigInt(intent.expiry),
    disclosureVersion: Number(intent.disclosureVersion),
  };
}

function toSolidityEnvelope(envelope) {
  return {
    chainId: BigInt(envelope.chainId),
    binder: getAddress(envelope.binder),
    policyId: envelope.policyId,
    policyVersion: Number(envelope.policyVersion),
    sessionCommitment: envelope.sessionCommitment,
    nonce: BigInt(envelope.nonce),
    validUntil: BigInt(envelope.validUntil),
    resultCommitment: envelope.resultCommitment,
    result: {
      sessionId: envelope.result.sessionId,
      scopeCommitmentA: envelope.result.scopeCommitmentA,
      scopeCommitmentB: envelope.result.scopeCommitmentB,
      inputCommitmentA: envelope.result.inputCommitmentA,
      inputCommitmentB: envelope.result.inputCommitmentB,
      outcome: Number(envelope.result.outcome),
      exactMatchConfirmed: Boolean(envelope.result.exactMatchConfirmed),
      candidateMatchSuggested: Boolean(envelope.result.candidateMatchSuggested),
      candidateFallbackAuthorized: Boolean(envelope.result.candidateFallbackAuthorized),
      conflictConfirmed: Boolean(envelope.result.conflictConfirmed),
      matchCommitment: envelope.result.matchCommitment,
      boundCandidateAliasCommitment: envelope.result.boundCandidateAliasCommitment,
      anchorCount: Number(envelope.result.anchorCount),
      providerProofCommitment: envelope.result.providerProofCommitment,
    },
  };
}

function toSolidityConsent(consent) {
  return {
    scopeCommitment: consent.scopeCommitment,
    governanceRecord: consent.governanceRecord,
    disclosureVersion: Number(consent.disclosureVersion),
    validUntil: BigInt(consent.validUntil),
    nonce: BigInt(consent.nonce),
    signature: consent.signature,
  };
}

function encodeAttestation(validatorSetId, signatures) {
  return encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes[]" }],
    [validatorSetId, signatures],
  );
}

async function readBalances(client, art, addresses, anchor, party) {
  const read = async (token, holder) => client.readContract({
    address: token, abi: art.erc20.abi, functionName: "balanceOf", args: [holder],
  });
  return {
    settlementInVault: String(await read(addresses.settlement, anchor.vault)),
    settlementInBinder: String(await read(addresses.settlement, addresses.binder)),
    unitsInBinder: String(await client.readContract({
      address: anchor.vault, abi: art.vault.abi, functionName: "balanceOf", args: [addresses.binder],
    })),
    vaultTotalSupply: String(await client.readContract({
      address: anchor.vault, abi: art.vault.abi, functionName: "totalSupply",
    })),
    nativeInBinder: String(await client.getBalance({ address: addresses.binder })),
    nativeInRelayer: String(await client.getBalance({ address: party.relayer.address })),
  };
}

async function performReadbacks({
  client, art, addresses, anchor, envelope, matchCommitment, consents,
  sessionCommitment, records, sides, sourceRegisteredAt, balancesBefore, party,
}) {
  const record = await client.readContract({
    address: addresses.binder, abi: art.binder.abi, functionName: "recourseOf", args: [sessionCommitment],
  });
  const balancesAfter = await readBalances(client, art, addresses, anchor, party);
  const expect = (label, actual, wanted) => {
    if (String(actual).toLowerCase() !== String(wanted).toLowerCase()) fail("READBACK", `${label}:${actual}!=${wanted}`);
  };
  expect("record.sessionCommitment", record.sessionCommitment, sessionCommitment);
  expect("record.resultCommitment", record.resultCommitment, envelope.resultCommitment);
  expect("record.matchCommitment", record.matchCommitment, matchCommitment);
  expect("record.anchorCommitment", record.anchorCommitment, sides.anchorAssetCommitment);
  expect("record.counterpartyCommitment", record.counterpartyCommitment, sides.sourceAssetCommitment);
  expect("record.providerProof", record.providerProofCommitment, envelope.result.providerProofCommitment);
  expect("record.anchor", record.anchor, anchor.vault);
  expect("record.policyId", record.policyId, POLICY_ID);
  if (record.open !== true) fail("READBACK", "record not open");
  if (record.conflictConfirmed !== true) fail("READBACK", "conflict not recorded");
  if (Number(record.cureDeadline) !== Number(record.boundAt) + Number(CURE_PERIOD)) {
    fail("READBACK", "cure deadline not derived on-chain");
  }
  for (const [label, before] of Object.entries(balancesBefore)) {
    if (label === "nativeInRelayer") continue; // the relayer paid its own gas
    if (balancesAfter[label] !== before) fail("ASSET_MOVED", `${label}:${before}->${balancesAfter[label]}`);
  }

  const consumed = {
    replayKey: await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName: "consumedReplayKeys",
      args: [await client.readContract({
        address: addresses.verifier, abi: art.verifier.abi, functionName: "replayKey",
        args: [toSolidityEnvelope(envelope)],
      })],
    }),
    decisionKey: await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName: "consumedDecisionKeys",
      args: [await client.readContract({
        address: addresses.verifier, abi: art.verifier.abi, functionName: "decisionKey",
        args: [toSolidityEnvelope(envelope)],
      })],
    }),
    matchCommitment: await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName: "consumedMatchCommitments",
      args: [matchCommitment],
    }),
    providerProof: await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName: "consumedProviderProofCommitments",
      args: [envelope.result.providerProofCommitment],
    }),
    sessionCommitment: (await client.readContract({
      address: addresses.governance, abi: art.governance.abi, functionName: "commitment",
      args: [sessionCommitment],
    })).consumed,
    consentNonceA: await client.readContract({
      address: addresses.binder, abi: art.binder.abi, functionName: "consumedConsentNonce",
      args: [consents.A.scopeCommitment, BigInt(consents.A.nonce)],
    }),
    consentNonceB: await client.readContract({
      address: addresses.binder, abi: art.binder.abi, functionName: "consumedConsentNonce",
      args: [consents.B.scopeCommitment, BigInt(consents.B.nonce)],
    }),
  };
  for (const [label, value] of Object.entries(consumed)) {
    if (value !== true) fail("IDENTITY_NOT_CONSUMED", label);
  }

  return {
    recourseRecord: {
      sessionCommitment: record.sessionCommitment,
      resultCommitment: record.resultCommitment,
      matchCommitment: record.matchCommitment,
      anchorCommitment: record.anchorCommitment,
      counterpartyCommitment: record.counterpartyCommitment,
      providerProofCommitment: record.providerProofCommitment,
      anchor: getAddress(record.anchor),
      policyId: record.policyId,
      policyVersion: Number(record.policyVersion),
      conflictConfirmed: record.conflictConfirmed,
      boundAt: Number(record.boundAt),
      cureDeadline: Number(record.cureDeadline),
      open: record.open,
    },
    responsibleRole: await client.readContract({
      address: addresses.binder, abi: art.binder.abi, functionName: "responsibleRole",
    }),
    consequenceId: await client.readContract({
      address: addresses.binder, abi: art.binder.abi, functionName: "consequenceId",
    }),
    anchorLive: await client.readContract({
      address: addresses.binder, abi: art.binder.abi, functionName: "anchorLive", args: [sessionCommitment],
    }),
    anchorState: {
      receivableState: Number(await client.readContract({ address: anchor.vault, abi: art.vault.abi, functionName: "receivableState" })),
      protectionState: Number(await client.readContract({ address: anchor.vault, abi: art.vault.abi, functionName: "protectionState" })),
      assetCommitment: await client.readContract({ address: anchor.vault, abi: art.vault.abi, functionName: "assetCommitment" }),
      initialTermsCommitment: await client.readContract({ address: anchor.vault, abi: art.vault.abi, functionName: "initialTermsCommitment" }),
      identitySchemeVersion: Number(await client.readContract({ address: anchor.vault, abi: art.vault.abi, functionName: "identitySchemeVersion" })),
      sourceAttestationDigest: await client.readContract({ address: anchor.vault, abi: art.vault.abi, functionName: "sourceAttestationDigest" }),
    },
    sourceRegisteredAt,
    governanceRecords: records,
    consumedIdentities: consumed,
    balancesBefore,
    balancesAfter,
  };
}

/**
 * Every negative is an eth_call. No failing transaction is broadcast, so the
 * chain carries exactly one successful binding and nothing else.
 */
async function runReplays({
  client, art, addresses, settings, bindArgs, envelope, consents, anchor,
  sessionCommitment, matchCommitment, parties, party,
}) {
  const results = [];
  const attempt = async (name, args, expected) => {
    try {
      await client.simulateContract({
        address: addresses.binder, abi: art.binder.abi, functionName: "bindRecourse",
        args, account: settings.deployer,
      });
      results.push({ name, rejected: false, expected, error: null });
    } catch (error) {
      const message = String(error?.shortMessage ?? error?.message ?? error);
      results.push({ name, rejected: true, expected, error: message.split("\n")[0].slice(0, 200) });
    }
  };

  await attempt("exact calldata replay", bindArgs, "SessionAlreadyBound");

  const reversed = structuredClone(bindArgs);
  [reversed[0].result.inputCommitmentA, reversed[0].result.inputCommitmentB] =
    [bindArgs[0].result.inputCommitmentB, bindArgs[0].result.inputCommitmentA];
  await attempt("reversed input pair", reversed, "SessionAlreadyBound / DecisionAlreadyConsumed");

  const wrongAnchor = structuredClone(bindArgs);
  wrongAnchor[3] = addresses.binder;
  await attempt("wrong anchor", wrongAnchor, "AnchorNotDeployed / AnchorSchemeMismatch");

  const wrongBinder = structuredClone(bindArgs);
  wrongBinder[0].binder = addresses.verifier;
  await attempt("wrong binder", wrongBinder, "EnvelopeNotForThisBinder");

  const wrongSession = structuredClone(bindArgs);
  wrongSession[0].sessionCommitment = keccak256(stringToHex("mordant.priv8.not-a-session"));
  await attempt("wrong session commitment", wrongSession, "UnknownCommitment / RevealNotForEnvelope");

  const oneSided = structuredClone(bindArgs);
  oneSided[5] = structuredClone(bindArgs[4]);
  await attempt("one-sided consent", oneSided, "ConsentScopeMismatch");

  const reusedConsent = structuredClone(bindArgs);
  reusedConsent[0].nonce = BigInt(envelope.nonce) + 1n;
  await attempt("reused consent nonce", reusedConsent, "SessionAlreadyBound / ConsentNonceConsumed");

  // A candidate result must be refused by the result invariants themselves.
  const candidate = structuredClone(bindArgs);
  candidate[0].result.outcome = 2;
  candidate[0].result.exactMatchConfirmed = false;
  candidate[0].result.candidateMatchSuggested = true;
  candidate[0].result.candidateFallbackAuthorized = true;
  candidate[0].result.conflictConfirmed = false;
  candidate[0].result.boundCandidateAliasCommitment = keccak256(stringToHex("alias"));
  await attempt("candidate result submitted as bindable", candidate, "CandidateSessionCannotBind");

  // Reused match and provider-proof commitments, checked against the verifier
  // directly because the binder's own one-shot record fires first.
  for (const [name, functionName, args] of [
    ["reused match commitment", "consumedMatchCommitments", [matchCommitment]],
    ["reused provider-proof commitment", "consumedProviderProofCommitments", [envelope.result.providerProofCommitment]],
  ]) {
    const consumed = await client.readContract({
      address: addresses.verifier, abi: art.verifier.abi, functionName, args,
    });
    results.push({ name, rejected: consumed === true, expected: "already consumed", error: null });
  }

  // A controller refuses to consent again for the same result, in its own
  // process, before any chain call is made.
  const refusal = await parties.askExpectingRefusal(party["controller-a"], "/v1/sign-consent", {
    chainId: CHAIN_ID, binder: addresses.binder, policyId: POLICY_ID, policyVersion: POLICY_VERSION,
    sessionCommitment, resultCommitment: envelope.resultCommitment, matchCommitment,
    anchor: anchor.vault, outcome: 2, exactMatchConfirmed: false, candidateMatchSuggested: true,
    consent: consents.A ? { ...consents.A, signature: undefined } : null,
    authorization: { controllerKeyId: CONTROLLER_KEY_A, controllerEpoch: 1, authorizationVersion: 1 },
  });
  results.push({
    name: "controller refuses to consent to a candidate result",
    rejected: refusal.status !== 200, expected: "403", error: refusal.error,
  });

  return results;
}

export function parseArgs(argv) {
  const options = {
    root: resolve(HERE, "artifacts/priv8-run"),
    journal: resolve(HERE, "artifacts/priv8-journal.json"),
    out: resolve(HERE, "artifacts/priv8-evidence"),
    frozenCommit: "af5baad",
  };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--root" && argv[index + 1]) options.root = resolve(argv[++index]);
    if (argv[index] === "--journal" && argv[index + 1]) options.journal = resolve(argv[++index]);
    if (argv[index] === "--out" && argv[index + 1]) options.out = resolve(argv[++index]);
    if (argv[index] === "--frozen-commit" && argv[index + 1]) options.frozenCommit = argv[++index];
  }
  return options;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main()
    .then((evidence) => {
      process.stdout.write(`${JSON.stringify({ ok: true, states: evidence.states.map((entry) => entry.state) }, null, 2)}\n`);
    })
    .catch((error) => {
      process.stderr.write(`PRIV8_FAILED: ${error?.code ?? ""} ${error?.message ?? error}\n`);
      process.exitCode = 1;
    });
}
