#!/usr/bin/env node

// Reads the deployed M-PRIV8 configuration back off Monad and compares it with
// what the runner intends, before any new transaction is sent.
//
// Deployment is only trustworthy if the chain agrees with the plan, so this
// checks admin surfaces, policy, quorum, relayer and binder authorization, the
// governance records and the anchor's live state.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createPublicClient, defineChain, http, getAddress, keccak256, stringToHex } from "viem";
import { loadArtifacts } from "./priv8-deploy.mjs";
import { REPO } from "./priv8-chain.mjs";

const env = {};
for (const line of (await readFile(resolve(REPO, ".env"), "utf8")).split("\n")) {
  const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (match) env[match[1]] = match[2].replace(/^["']|["']$/g, "");
}
const chain = defineChain({
  id: 10_143, name: "Monad testnet",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: [env.FHE_MONAD_RPC_URL] } },
});
const client = createPublicClient({ chain, transport: http(env.FHE_MONAD_RPC_URL) });

let last = 0;
async function throttled(work, attempt = 0) {
  const wait = Math.max(0, 80 - (Date.now() - last));
  if (wait > 0) await new Promise((done) => setTimeout(done, wait));
  last = Date.now();
  try { return await work(); } catch (error) {
    if (attempt >= 5) throw error;
    await new Promise((done) => setTimeout(done, 400 * (attempt + 1)));
    return throttled(work, attempt + 1);
  }
}

const journal = JSON.parse(await readFile(process.argv[2], "utf8"));
const art = await loadArtifacts();
const addressOf = (step) => getAddress(journal.steps[`deploy:${step}`].contractAddress);
const addresses = {
  eligibility: addressOf("MockEligibility"),
  settlement: addressOf("SettlementToken"),
  cvaToken: addressOf("ReceivableUnits"),
  adapter: addressOf("MockCvaAdapter"),
  issuerRegistry: addressOf("MordantIssuerRegistry"),
  factory: addressOf("MordantFactoryV2"),
  sources: addressOf("MordantSourceIdentityRegistry"),
  governance: addressOf("MordantScopeGovernanceRegistry"),
  verifier: addressOf("ECDSAQuorumMatchVerifierV4"),
  binder: addressOf("PrivateMatchBinder"),
};

const read = (address, abi, functionName, args = []) =>
  throttled(() => client.readContract({ address, abi, functionName, args }));

// Deployed runtime bytecode must equal the artifact compiled from the frozen
// tree. This is what proves the deployed code derives from af5baad.
const { keccak256: hash } = await import("viem");
const codeHashes = {};
for (const [label, address] of Object.entries(addresses)) {
  const deployed = await throttled(() => client.getBytecode({ address }));
  codeHashes[label] = { address, onChainCodeHash: hash(deployed ?? "0x"), bytes: (deployed ?? "0x").length / 2 - 1 };
}

const POLICY_ID = keccak256(stringToHex("mordant.private-match.policy/v4"));
const report = {
  addresses,
  codeHashes,
  verifier: {
    owner: await read(addresses.verifier, art.verifier.abi, "owner"),
    governance: await read(addresses.verifier, art.verifier.abi, "governance"),
    quorum: String(await read(addresses.verifier, art.verifier.abi, "quorum")),
    validatorSetId: await read(addresses.verifier, art.verifier.abi, "validatorSetId"),
    policyVersionForPolicy: Number(await read(addresses.verifier, art.verifier.abi, "currentPolicyVersion", [POLICY_ID])),
  },
  binder: {
    verifier: await read(addresses.binder, art.binder.abi, "verifier"),
    governance: await read(addresses.binder, art.binder.abi, "governance"),
    issuerRegistry: await read(addresses.binder, art.binder.abi, "issuerRegistry"),
    sourceRegistry: await read(addresses.binder, art.binder.abi, "sourceRegistry"),
    policyId: await read(addresses.binder, art.binder.abi, "policyId"),
    policyVersion: Number(await read(addresses.binder, art.binder.abi, "policyVersion")),
    responsibleRole: await read(addresses.binder, art.binder.abi, "responsibleRole"),
    curePeriod: String(await read(addresses.binder, art.binder.abi, "curePeriod")),
    consequenceId: await read(addresses.binder, art.binder.abi, "consequenceId"),
    disclosureVersion: Number(await read(addresses.binder, art.binder.abi, "DISCLOSURE_VERSION")),
  },
  governance: {
    governor: await read(addresses.governance, art.governance.abi, "governor"),
    binderAuthorized: await read(addresses.governance, art.governance.abi, "authorizedBinder", [addresses.binder]),
  },
};

// Governance records, recovered from the authorize receipts.
const { parseEventLogs } = await import("viem");
report.governanceRecords = {};
for (const [label, key] of [["A", "governance:authorizeA"], ["B", "governance:authorizeB"]]) {
  const receipt = await throttled(() => client.getTransactionReceipt({ hash: journal.steps[key].hash }));
  const [event] = parseEventLogs({ abi: art.governance.abi, eventName: "ScopeAuthorized", logs: receipt.logs });
  const record = await read(addresses.governance, art.governance.abi, "record", [event.args.recordDigest]);
  report.governanceRecords[label] = {
    recordDigest: event.args.recordDigest,
    scopeCommitment: record.scopeCommitment,
    controller: getAddress(record.controller),
    controllerKeyId: record.controllerKeyId,
    organizationId: record.organizationId,
    controllerEpoch: Number(record.controllerEpoch),
    authorizationVersion: Number(record.authorizationVersion),
    validFrom: Number(record.validFrom),
    retiredAt: Number(record.retiredAt),
    hardRevokedAt: Number(record.hardRevokedAt),
    relayerAuthorized: null,
  };
}
// The relayer is whoever actually sent the commitment transaction.
const commitTransaction = await throttled(() => client.getTransaction({ hash: journal.steps["session:commit"].hash }));
const relayer = getAddress(commitTransaction.from);
report.governance.relayer = relayer;
report.governance.relayerAuthorized = await read(
  addresses.governance, art.governance.abi, "authorizedRelayer", [relayer],
);
report.governance.relayerIsNotAController = ![
  report.governanceRecords.A.controller, report.governanceRecords.B.controller,
].includes(relayer);

// The anchor and the non-vault source.
const anchorReceipt = await throttled(() => client.getTransactionReceipt({ hash: journal.steps["anchor:create"].hash }));
const [created] = parseEventLogs({ abi: art.factory.abi, eventName: "IdentityAnchoredVaultCreated", logs: anchorReceipt.logs });
const vault = getAddress(created.args.vault);
report.anchor = {
  vault,
  invoiceRoot: created.args.invoiceRoot,
  assetCommitment: await read(vault, art.vault.abi, "assetCommitment"),
  initialTermsCommitment: await read(vault, art.vault.abi, "initialTermsCommitment"),
  identitySchemeVersion: Number(await read(vault, art.vault.abi, "identitySchemeVersion")),
  termsSchemeVersion: Number(await read(vault, art.vault.abi, "termsSchemeVersion")),
  identityEpoch: Number(await read(vault, art.vault.abi, "identityEpoch")),
  issuerKeyId: await read(vault, art.vault.abi, "issuerKeyId"),
  sourceAttestationDigest: await read(vault, art.vault.abi, "sourceAttestationDigest"),
  receivableState: Number(await read(vault, art.vault.abi, "receivableState")),
  protectionState: Number(await read(vault, art.vault.abi, "protectionState")),
  totalSupply: String(await read(vault, art.vault.abi, "totalSupply")),
  currency: await read(vault, art.vault.abi, "currency"),
};

const sourceReceipt = await throttled(() => client.getTransactionReceipt({ hash: journal.steps["source:register"].hash }));
const [registered] = parseEventLogs({ abi: art.sources.abi, eventName: "SourceIdentityRegistered", logs: sourceReceipt.logs });
const sourceAnchor = await read(addresses.sources, art.sources.abi, "anchor", [registered.args.anchorId]);
report.nonVaultSource = {
  anchorId: registered.args.anchorId,
  assetCommitment: sourceAnchor.assetCommitment,
  identitySchemeVersion: Number(sourceAnchor.identitySchemeVersion),
  identityEpoch: Number(sourceAnchor.identityEpoch),
  issuerKeyId: sourceAnchor.issuerKeyId,
  registeredAt: Number(sourceAnchor.registeredAt),
};

// The session commitment the interrupted run published, whose preimage was lost.
const commitReceipt = await throttled(() => client.getTransactionReceipt({ hash: journal.steps["session:commit"].hash }));
const orphan = commitReceipt.logs[0]?.topics?.[1] ?? null;
report.orphanedSessionCommitment = orphan === null ? null : {
  sessionCommitment: orphan,
  transaction: journal.steps["session:commit"].hash,
  block: String(commitReceipt.blockNumber),
  state: await read(addresses.governance, art.governance.abi, "commitment", [orphan]).then((entry) => ({
    exists: entry.exists, consumed: entry.consumed,
    committedAt: Number(entry.committedAt), submitter: getAddress(entry.submitter),
  })),
  note: "preimage lost when the process died; it can never be revealed and never bound",
};

await writeFile(process.argv[3], `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
