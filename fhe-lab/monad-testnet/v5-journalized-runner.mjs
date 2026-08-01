// RC2 Run6: durable admission spine for a V5 private-matching session.
//
// This runner intentionally ends at SESSION_COMMITTED. Ceremony, enrolment,
// evaluation, threshold release, validation, consent and binding are outside
// Run6 and remain unreachable from this module.
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  decodeEventLog, encodeAbiParameters, encodeDeployData, encodeFunctionData,
  encodePacked, keccak256, parseAbiParameters, toBytes, toHex,
} from "viem";

import { JournalError, STATES } from "./v5-journal.mjs";
import { defineStage, runPipeline } from "./v5-stage.mjs";
import { artifact, CURRENCY, POLICY_ID, SCOPE_A, SCOPE_B } from "./v5-rehearsal-support.mjs";
import {
  agreeAndSignAttestation, creationCalldata, deriveInvoiceRoot, invoiceConfig,
  readVaultState, requireActivatedAnchor, requireAddressAgreement, simulateCreation,
  sourceAttestation,
} from "./v5-vault-flow.mjs";
import {
  commitSourceCalldata, freshSourceSalt, requireOpaqueAdmission, signSourceAttestation,
  sourceCommitmentFromChain, sourcePreimage, writeRevealPackage,
} from "./v5-source-flow.mjs";

export const ADMISSION_STAGES = Object.freeze([
  "INITIALIZED",
  "FINAL_STACK_PLANNED",
  "FINAL_STACK_DEPLOYED",
  "BYTECODE_VERIFIED",
  "VAULT_CREATED",
  "AWAITING_VAULT_APASS",
  "VAULT_ACTIVATED",
  "SOURCE_A_COMMITTED",
  "SOURCE_B_COMMITTED",
  "GOVERNANCE_A_CREATED",
  "GOVERNANCE_B_CREATED",
  "SESSION_PREPARED",
  "SESSION_NULLIFIER_RESERVED",
  "SESSION_COMMITTED",
]);

const JOURNAL_META = new Set([
  "state", "preparedAt", "inputDigest", "broadcastAt", "transactionHash", "confirmedAt",
  "receipt", "outputDigest", "verified", "verifiedAt", "verification", "awaitingSince",
]);

const digest = (value) =>
  `0x${createHash("sha256").update(JSON.stringify(normalized(value))).digest("hex")}`;

const normalized = (value) => {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(normalized);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalized(child)]));
  }
  return value;
};

const frozenRecord = (entry) =>
  Object.fromEntries(Object.entries(entry).filter(([key]) => !JOURNAL_META.has(key)));

const b = (value) => BigInt(value);
const n = (value) => Number(value);
const zeroAddress = "0x0000000000000000000000000000000000000000";

function addressPresent(value) {
  return value && value.toLowerCase() !== zeroAddress;
}

function sourceStageName(side) {
  return side === "A" ? "SOURCE_A_COMMITTED" : "SOURCE_B_COMMITTED";
}

function governanceStageName(side) {
  return side === "A" ? "GOVERNANCE_A_CREATED" : "GOVERNANCE_B_CREATED";
}

function sourceFromRecord(record) {
  return {
    attestation: {
      ...record.sourcePreimage.attestation,
      chainId: b(record.sourcePreimage.attestation.chainId),
      identityEpoch: n(record.sourcePreimage.attestation.identityEpoch),
      validUntil: b(record.sourcePreimage.attestation.validUntil),
      nonce: b(record.sourcePreimage.attestation.nonce),
    },
    salt: record.sourcePreimage.salt,
  };
}

function vaultConfigFromRecord(record) {
  const config = record.config;
  return {
    ...config,
    initialUnits: b(config.initialUnits),
    advanceAmount: b(config.advanceAmount),
    faceValue: b(config.faceValue),
    bondBps: n(config.bondBps),
    protectionEnd: b(config.protectionEnd),
    revealPeriod: b(config.revealPeriod),
    curePeriod: b(config.curePeriod),
  };
}

function intentFromRecord(record) {
  const intent = record.canonicalIntent;
  return {
    ...intent,
    chainId: b(intent.chainId),
    policyVersion: n(intent.policyVersion),
    controllerEpochA: n(intent.controllerEpochA),
    controllerEpochB: n(intent.controllerEpochB),
    scopeAuthorizationVersionA: n(intent.scopeAuthorizationVersionA),
    scopeAuthorizationVersionB: n(intent.scopeAuthorizationVersionB),
    identityEpoch: n(intent.identityEpoch),
    exactBudget: n(intent.exactBudget),
    candidateBudget: n(intent.candidateBudget),
    sessionNonce: b(intent.sessionNonce),
    expiry: b(intent.expiry),
    disclosureVersion: n(intent.disclosureVersion),
  };
}

async function privatePackageDigest(path) {
  return `0x${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

async function verifyRevealPackage({ record, context, sourcesAbi }) {
  const observedDigest = await privatePackageDigest(record.revealPackage.path);
  if (observedDigest !== record.revealPackageDigest) {
    throw new JournalError("REVEAL_PACKAGE_DRIFT", `${observedDigest} != ${record.revealPackageDigest}`);
  }
  const parsed = JSON.parse(await readFile(record.revealPackage.path, "utf8"));
  if (parsed.commitment !== record.commitment || parsed.salt !== record.sourceSalt) {
    throw new JournalError("REVEAL_PACKAGE_MISMATCH", record.revealPackage.path);
  }
  const fromChain = await sourceCommitmentFromChain({
    client: context.client,
    sourcesAbi,
    sourceRegistry: context.topology.at.sources,
    attestation: sourceFromRecord(record).attestation,
    signature: record.issuerSignature,
    salt: record.sourceSalt,
  });
  if (fromChain !== record.commitment) throw new JournalError("SOURCE_COMMITMENT_DRIFT", fromChain);
}

async function txNonce(client, address) {
  return Number(await client.getTransactionCount({ address, blockTag: "pending" }));
}

function sourceConfidential(record) {
  const preimage = sourceFromRecord(record);
  return {
    controller: preimage.attestation.controller,
    invoiceRoot: preimage.attestation.invoiceRoot,
    assetCommitment: preimage.attestation.assetCommitment,
    initialTermsCommitment: preimage.attestation.initialTermsCommitment,
    creationDigest: preimage.attestation.creationDigest,
    issuerKeyId: preimage.attestation.issuerKeyId,
    salt: preimage.salt,
    attestationDigest: record.issuerSignatureDigest,
    issuerSignature: record.issuerSignature,
  };
}

async function sourceMetadataAudit({ record, context, sourcesAbi }) {
  if (!record.transactionHash) return { skipped: "reconciled without retained transaction hash" };
  const [transaction, receipt, stored] = await Promise.all([
    context.client.getTransaction({ hash: record.transactionHash }),
    context.client.getTransactionReceipt({ hash: record.transactionHash }),
    context.client.readContract({
      address: context.topology.at.sources, abi: sourcesAbi, functionName: "commitment", args: [record.commitment],
    }),
  ]);
  const surfaces = { calldata: transaction.input };
  receipt.logs.forEach((log, index) => {
    log.topics.forEach((topic, topicIndex) => { surfaces[`log${index}.topic${topicIndex}`] = topic; });
    surfaces[`log${index}.data`] = log.data;
  });
  surfaces.storage = Buffer.from(
    JSON.stringify(stored, (_key, value) => (typeof value === "bigint" ? value.toString() : value)),
    "utf8",
  );
  return requireOpaqueAdmission({ surfaces, confidential: sourceConfidential(record) });
}

function chronologyBlocks(context, sessionRecord) {
  const sourceA = context.journal.stage("SOURCE_A_COMMITTED");
  const sourceB = context.journal.stage("SOURCE_B_COMMITTED");
  const governanceA = context.journal.stage("GOVERNANCE_A_CREATED");
  const governanceB = context.journal.stage("GOVERNANCE_B_CREATED");
  return [
    Number(sourceA.receipt?.blockNumber),
    Number(sourceB.receipt?.blockNumber),
    Number(governanceA.receipt?.blockNumber),
    Number(governanceB.receipt?.blockNumber),
  ].every((block) => Number.isFinite(block) && block < Number(sessionRecord.committedInBlock));
}

function vaultIdentityInit(attestation, attestationDigest) {
  return {
    assetCommitment: attestation.assetCommitment,
    initialTermsCommitment: attestation.initialTermsCommitment,
    identitySchemeVersion: attestation.identitySchemeVersion,
    termsSchemeVersion: attestation.termsSchemeVersion,
    identityEpoch: attestation.identityEpoch,
    issuerKeyId: attestation.issuerKeyId,
    sourceAttestationDigest: attestationDigest,
  };
}

function vaultInit(config, cviVerifier) {
  return {
    factory: undefined, // Filled by the caller because it is the factory address.
    cviVerifier,
    cvaAdapter: config.cvaAdapter,
    settlementToken: config.settlementToken,
    invoiceRoot: config.invoiceRoot,
    currency: config.currency,
    buyer: config.buyer,
    originatorTreasury: config.originatorTreasury,
    initialOriginatorSigner: config.initialOriginatorSigner,
    initialUnits: config.initialUnits,
    advanceAmount: config.advanceAmount,
    faceValue: config.faceValue,
    bondBps: config.bondBps,
    protectionEnd: config.protectionEnd,
    revealPeriod: config.revealPeriod,
    curePeriod: config.curePeriod,
  };
}

function externalAPassRequest(chainId, vault) {
  // This is deliberately the entire request surface. No issuer endpoint, key,
  // policy profile or operator assertion crosses the runner boundary.
  return {
    chainId: Number(chainId),
    vaultAddress: vault,
    requiredIdentityStatus: "valid A-Pass",
    minimumValidity: "isValidAPass(vault) === true",
  };
}

export function createAdmissionStages() {
  return [
    defineStage({
      name: "INITIALIZED",
      prepare: async ({ chainId, existing }) => existing ? frozenRecord(existing) : { chainId: Number(chainId) },
      execute: async () => ({ outputs: {} }),
      verify: async ({ client, chainId }) => ({ ok: Number(await client.getChainId()) === Number(chainId) }),
    }),
    defineStage({
      name: "FINAL_STACK_PLANNED",
      prepare: async ({ topology, existing }) => existing ? frozenRecord(existing) : {
        topologyDigest: digest({ at: topology.at, roles: topology.roles, config: topology.config }),
      },
      execute: async () => ({ outputs: {} }),
      verify: async ({ topology }) => ({ ok: Boolean(topology?.at?.factory && topology?.at?.governance) }),
    }),
    defineStage({
      name: "FINAL_STACK_DEPLOYED",
      prepare: async ({ topology, existing }) => existing ? frozenRecord(existing) : {
        addresses: normalized(topology.at),
      },
      execute: async () => ({ outputs: {} }),
      verify: async ({ client, journal }) => {
        const addresses = journal.stage("FINAL_STACK_DEPLOYED").addresses;
        const code = await Promise.all(Object.values(addresses).map((address) => client.getBytecode({ address })));
        return { ok: code.every((value) => value && value !== "0x") };
      },
    }),
    defineStage({
      name: "BYTECODE_VERIFIED",
      prepare: async ({ journal, existing }) => existing ? frozenRecord(existing) : {
        stackDigest: digest(journal.stage("FINAL_STACK_DEPLOYED").addresses),
      },
      execute: async () => ({ outputs: {} }),
      verify: async ({ client, journal }) => {
        const addresses = journal.stage("FINAL_STACK_DEPLOYED").addresses;
        const checks = await Promise.all(Object.values(addresses).map((address) => client.getBytecode({ address })));
        return { ok: checks.every((code) => code && code !== "0x") };
      },
    }),
    defineStage({
      name: "VAULT_CREATED",
      async prepare(context) {
        if (context.existing) return frozenRecord(context.existing);
        const [factoryAbi, vaultAbi, vaultArtifact, issuerRegistryAbi] = await Promise.all([
          artifact("factory"), artifact("vault"), artifact("vault"), artifact("issuerRegistry"),
        ]);
        const { topology, client, capabilities, chainId, label } = context;
        const now = BigInt((await client.getBlock()).timestamp);
        const invoiceRoot = deriveInvoiceRoot(label);
        const economics = {
          units: 100_000_000n, advance: 100_000_000n, face: 110_000_000n, bondBps: 1_000,
          protectionEnd: now + 30n * 24n * 3600n, revealPeriod: 3600n, curePeriod: 3600n,
        };
        const config = invoiceConfig({
          adapter: topology.at.adapter, settlement: topology.at.settlement, invoiceRoot, currency: CURRENCY,
          roles: topology.roles, economics,
        });
        const [creationDigest, issuerKeyId] = await Promise.all([
          client.readContract({ address: topology.at.factory, abi: factoryAbi.abi, functionName: "creationDigest", args: [config] }),
          client.readContract({
            address: topology.at.issuerRegistry, abi: issuerRegistryAbi.abi,
            functionName: "issuerKeyIdFor", args: [topology.roles.issuer],
          }),
        ]);
        const stableId = keccak256(toBytes(`mordant.run6.asset/${label}`));
        const assetCommitment = keccak256(
          encodeAbiParameters(parseAbiParameters("bytes32,uint256"), [stableId, 1n]),
        );
        const attestation = sourceAttestation({
          chainId, factory: topology.at.factory, creationDigest, assetCommitment,
          initialTermsCommitment: keccak256(toBytes(`mordant.run6.terms/${label}`)),
          issuerKeyId, invoiceRoot, controller: topology.roles.originator,
          identityEpoch: 1, validUntil: now + 7n * 24n * 3600n, nonce: 1n,
        });
        const signed = await agreeAndSignAttestation({
          attestation, chainId, verifyingContract: topology.at.factory, signer: capabilities.issuerSourceSigner,
        });
        const init = vaultInit(config, topology.at.eligibility);
        init.factory = topology.at.factory;
        const initCode = encodeDeployData({
          abi: vaultAbi.abi,
          bytecode: vaultArtifact.bytecode.object ?? vaultArtifact.bytecode,
          args: [init, vaultIdentityInit(attestation, signed.digest)],
        });
        const [predicted, simulated] = await Promise.all([
          client.readContract({
            address: topology.at.factory, abi: factoryAbi.abi, functionName: "predictVaultAddress",
            args: [signed.digest, initCode],
          }),
          simulateCreation({
            client, factoryAbi: factoryAbi.abi, factory: topology.at.factory, buyer: topology.roles.buyer,
            config, attestation, signature: signed.signature,
          }),
        ]);
        requireAddressAgreement({ predicted, simulated, byRoot: null, byAttestation: null });
        return normalized({
          sender: topology.roles.buyer,
          nonce: await txNonce(client, topology.roles.buyer),
          to: topology.at.factory,
          calldata: creationCalldata({ factoryAbi: factoryAbi.abi, config, attestation, signature: signed.signature }),
          config,
          attestation,
          issuerSignatureDigest: signed.digest,
          issuerSignature: signed.signature,
          invoiceRoot,
          assetCommitment,
          issuerKeyId,
          predictedVault: predicted,
          simulatedVault: simulated,
          initCodeDigest: keccak256(initCode),
        });
      },
      execute: async ({ prepared, broadcast, journal, stage, execution }) => ({
        transactionHash: await execution.broadcastPrepared({
          prepared, broadcast, onBroadcast: (hash) => journal.markBroadcast(stage, hash),
        }),
      }),
      reconcile: async (context) => {
        const entry = context.journal.stage("VAULT_CREATED");
        if (!entry.predictedVault) return null;
        const factoryAbi = await artifact("factory");
        const [byRoot, byAttestation] = await Promise.all([
          context.client.readContract({
            address: context.topology.at.factory, abi: factoryAbi.abi, functionName: "vaultForRoot", args: [entry.invoiceRoot],
          }),
          context.client.readContract({
            address: context.topology.at.factory, abi: factoryAbi.abi,
            functionName: "vaultForAttestation", args: [entry.issuerSignatureDigest],
          }),
        ]);
        if (!addressPresent(byRoot) && !addressPresent(byAttestation)) return null;
        requireAddressAgreement({
          predicted: entry.predictedVault, simulated: entry.simulatedVault, byRoot, byAttestation,
        });
        return { alreadyDone: true, outputs: { reconciledVault: byRoot } };
      },
      verify: async (context) => {
        const entry = context.journal.stage("VAULT_CREATED");
        const [factoryAbi, vaultAbi] = await Promise.all([artifact("factory"), artifact("vault")]);
        const [byRoot, byAttestation, code] = await Promise.all([
          context.client.readContract({
            address: context.topology.at.factory, abi: factoryAbi.abi, functionName: "vaultForRoot", args: [entry.invoiceRoot],
          }),
          context.client.readContract({
            address: context.topology.at.factory, abi: factoryAbi.abi,
            functionName: "vaultForAttestation", args: [entry.issuerSignatureDigest],
          }),
          context.client.getBytecode({ address: entry.predictedVault }),
        ]);
        requireAddressAgreement({
          predicted: entry.predictedVault, simulated: entry.simulatedVault, byRoot, byAttestation,
        });
        const state = await readVaultState({
          client: context.client, vaultAbi: vaultAbi.abi, factoryAbi: factoryAbi.abi,
          vault: entry.predictedVault, factory: context.topology.at.factory,
        });
        const ok = Boolean(code && code !== "0x") &&
          state.assetCommitment === entry.assetCommitment &&
          state.initialTermsCommitment === entry.attestation.initialTermsCommitment &&
          state.sourceAttestationDigest === entry.issuerSignatureDigest &&
          state.admittedAs.toLowerCase() === entry.predictedVault.toLowerCase();
        return { ok, evidence: { predicted: entry.predictedVault, byRoot, byAttestation } };
      },
    }),
    defineStage({
      name: "AWAITING_VAULT_APASS",
      prepare: async ({ journal, chainId, existing }) => existing ? frozenRecord(existing) : {
        externalActionRequest: externalAPassRequest(chainId, journal.stage("VAULT_CREATED").predictedVault),
      },
      execute: async ({ prepared }) => ({ awaitingExternal: true, request: prepared.externalActionRequest }),
      reconcile: async (context) => {
        const entry = context.journal.stage("AWAITING_VAULT_APASS");
        if (entry.state === STATES.NOT_STARTED) return null;
        const valid = await context.client.readContract({
          address: context.topology.at.eligibility, abi: (await artifact("eligibility")).abi,
          functionName: "hasValidIdentity", args: [entry.externalActionRequest.vaultAddress],
        });
        if (valid) return { alreadyDone: true, outputs: { reconciledFromChain: true } };
        return { awaitingExternal: true, request: entry.externalActionRequest };
      },
      verify: async (context) => {
        const entry = context.journal.stage("AWAITING_VAULT_APASS");
        const valid = await context.client.readContract({
          address: context.topology.at.eligibility, abi: (await artifact("eligibility")).abi,
          functionName: "hasValidIdentity", args: [entry.externalActionRequest.vaultAddress],
        });
        return { ok: valid === true, evidence: entry.externalActionRequest };
      },
    }),
    defineStage({
      name: "VAULT_ACTIVATED",
      async prepare(context) {
        if (context.existing) return frozenRecord(context.existing);
        const vaultRecord = context.journal.stage("VAULT_CREATED");
        const [vaultAbi, erc20Abi, adapterAbi] = await Promise.all([
          artifact("vault"), artifact("erc20"), artifact("adapter"),
        ]);
        const vault = vaultRecord.predictedVault;
        const config = vaultConfigFromRecord(vaultRecord);
        const now = BigInt((await context.client.getBlock()).timestamp);
        const pledge = {
          invoiceRoot: vaultRecord.invoiceRoot,
          originatorSigner: context.topology.roles.originator,
          facility: context.topology.roles.facility,
          obligationId: keccak256(encodePacked(["string", "address"], ["mordant.run6.obligation", vault])),
          amount: config.faceValue,
          currency: CURRENCY,
          activeFrom: now - 1n,
          activeUntil: config.protectionEnd + 1n,
          nonce: BigInt(vault),
          deadline: now + 2n * 24n * 3600n,
          exclusive: true,
        };
        const signed = await context.capabilities.signPledge({ vault, vaultAbi: vaultAbi.abi, pledge });
        const activationPrerequisites = [
          {
            role: "deployer", to: context.topology.at.cvaToken,
            calldata: encodeFunctionData({
              abi: erc20Abi.abi, functionName: "mint", args: [context.topology.roles.deployer, config.initialUnits],
            }),
          },
          {
            role: "deployer", to: context.topology.at.cvaToken,
            calldata: encodeFunctionData({
              abi: erc20Abi.abi, functionName: "approve", args: [context.topology.at.adapter, config.initialUnits],
            }),
          },
          {
            role: "deployer", to: context.topology.at.adapter,
            calldata: encodeFunctionData({ abi: adapterAbi.abi, functionName: "creditVault", args: [vault, config.initialUnits] }),
          },
          {
            role: "deployer", to: context.topology.at.settlement,
            calldata: encodeFunctionData({
              abi: erc20Abi.abi, functionName: "mint", args: [context.topology.roles.holder, config.advanceAmount],
            }),
          },
          {
            role: "holder", to: context.topology.at.settlement,
            calldata: encodeFunctionData({
              abi: erc20Abi.abi, functionName: "approve", args: [vault, config.advanceAmount * 10n],
            }),
          },
        ];
        return normalized({
          sender: context.topology.roles.facility,
          nonce: await txNonce(context.client, context.topology.roles.facility),
          to: vault,
          calldata: encodeFunctionData({
            abi: vaultAbi.abi, functionName: "activate",
            args: [pledge, signed.signature, context.topology.roles.holder, [context.topology.roles.holder], [config.initialUnits]],
          }),
          activationPrerequisites,
          activationAmounts: {
            units: config.initialUnits,
            advance: config.advanceAmount,
            holderApproval: config.advanceAmount * 10n,
          },
          pledge,
          pledgeDigest: signed.digest,
          pledgeSignature: signed.signature,
        });
      },
      execute: async ({ prepared, broadcast, journal, stage, execution }) => ({
        transactionHash: await execution.activatePrepared({
          prepared,
          broadcast,
          onBroadcast: (hash) => journal.markBroadcast(stage, hash),
        }),
      }),
      reconcile: async (context) => {
        const entry = context.journal.stage("VAULT_ACTIVATED");
        if (!entry.to) return null;
        const state = await context.client.readContract({
          address: entry.to, abi: (await artifact("vault")).abi, functionName: "receivableState",
        });
        return Number(state) === 1 ? { alreadyDone: true, outputs: { reconciledActive: true } } : null;
      },
      verify: async (context) => {
        const vaultRecord = context.journal.stage("VAULT_CREATED");
        const vaultAbi = await artifact("vault");
        const factoryAbi = await artifact("factory");
        const state = await readVaultState({
          client: context.client, vaultAbi: vaultAbi.abi, factoryAbi: factoryAbi.abi,
          vault: vaultRecord.predictedVault, factory: context.topology.at.factory,
        });
        try {
          requireActivatedAnchor(state, {
            assetCommitment: vaultRecord.assetCommitment,
            initialTermsCommitment: vaultRecord.attestation.initialTermsCommitment,
            issuerKeyId: vaultRecord.issuerKeyId,
            invoiceRoot: vaultRecord.invoiceRoot,
            attestationDigest: vaultRecord.issuerSignatureDigest,
            vault: vaultRecord.predictedVault,
          });
          return { ok: true };
        } catch (error) {
          return { ok: false, reason: error.message };
        }
      },
    }),
    ...["A", "B"].map((side) => defineSourceStage(side)),
    ...["A", "B"].map((side) => defineGovernanceStage(side)),
    defineSessionPreparedStage(),
    defineNullifierReservationStage(),
    defineSessionCommittedStage(),
  ];
}

function defineSourceStage(side) {
  const name = sourceStageName(side);
  return defineStage({
    name,
    async prepare(context) {
      if (context.existing) {
        const record = frozenRecord(context.existing);
        await verifyRevealPackage({ record, context, sourcesAbi: (await artifact("sources")).abi });
        return record;
      }
      const sourcesAbi = await artifact("sources");
      const vault = context.journal.stage("VAULT_CREATED");
      const now = BigInt((await context.client.getBlock()).timestamp);
      const sourceSalt = freshSourceSalt();
      const preimage = sourcePreimage({
        chainId: context.chainId,
        sourceRegistry: context.topology.at.sources,
        controller: context.participants[`controller${side}`],
        invoiceRoot: keccak256(toBytes(`mordant.run6.source-root/${context.label}/${side}`)),
        assetCommitment: side === "A"
          ? vault.assetCommitment
          : keccak256(toBytes(`mordant.run6.source-asset/${context.label}/${side}`)),
        initialTermsCommitment: keccak256(toBytes(`mordant.run6.source-terms/${context.label}/${side}`)),
        creationDigest: keccak256(toBytes(`mordant.run6.source-creation/${context.label}/${side}`)),
        issuerKeyId: vault.issuerKeyId,
        identityEpoch: 1,
        validUntil: now + 30n * 24n * 3600n,
        nonce: side === "A" ? 101n : 102n,
        salt: sourceSalt,
      });
      const signed = await signSourceAttestation({
        preimage, chainId: context.chainId, sourceRegistry: context.topology.at.sources,
        signer: context.capabilities.issuerSourceSigner,
      });
      const commitment = await sourceCommitmentFromChain({
        client: context.client, sourcesAbi: sourcesAbi.abi, sourceRegistry: context.topology.at.sources,
        attestation: preimage.attestation, signature: signed.signature, salt: sourceSalt,
      });
      const revealPath = resolve(context.privateRoot, `source-${side.toLowerCase()}.reveal.json`);
      const revealPackage = await writeRevealPackage({
        path: revealPath, preimage, signature: signed.signature, digest: signed.digest, commitment,
      });
      const revealPackageDigest = await privatePackageDigest(revealPath);
      return normalized({
        sender: context.topology.roles.submitter,
        nonce: await txNonce(context.client, context.topology.roles.submitter),
        to: context.topology.at.sources,
        calldata: commitSourceCalldata({ sourcesAbi: sourcesAbi.abi, commitment }),
        side,
        sourceSalt,
        sourceNonce: preimage.attestation.nonce,
        sourcePreimage: preimage,
        commitment,
        issuerSignatureDigest: signed.digest,
        issuerSignature: signed.signature,
        revealPackage,
        revealPackageDigest,
      });
    },
    execute: async ({ prepared, broadcast, journal, stage, execution }) => ({
      transactionHash: await execution.broadcastPrepared({
        prepared, broadcast, onBroadcast: (hash) => journal.markBroadcast(stage, hash),
      }),
    }),
    reconcile: async (context) => {
      const entry = context.journal.stage(name);
      if (!entry.commitment) return null;
      const stored = await context.client.readContract({
        address: context.topology.at.sources, abi: (await artifact("sources")).abi,
        functionName: "commitment", args: [entry.commitment],
      });
      if (!stored.exists) return null;
      if (stored.submitter.toLowerCase() !== entry.sender.toLowerCase()) {
        return { ambiguous: true, reason: `${name} commitment belongs to another submitter` };
      }
      return { alreadyDone: true, outputs: { reconciledSourceBlock: Number(stored.committedInBlock) } };
    },
    verify: async (context) => {
      const entry = context.journal.stage(name);
      const sourcesAbi = await artifact("sources");
      await verifyRevealPackage({ record: entry, context, sourcesAbi: sourcesAbi.abi });
      const stored = await context.client.readContract({
        address: context.topology.at.sources, abi: sourcesAbi.abi, functionName: "commitment", args: [entry.commitment],
      });
      if (!stored.exists || stored.revealed || stored.submitter.toLowerCase() !== entry.sender.toLowerCase()) {
        return { ok: false, reason: "source registry readback mismatch" };
      }
      const metadata = await sourceMetadataAudit({ record: entry, context, sourcesAbi: sourcesAbi.abi });
      await context.journal.recordDerived(name, {
        sourceCommittedInBlock: Number(stored.committedInBlock),
        sourceCommittedAt: Number(stored.committedAt),
      });
      return {
        ok: true,
        evidence: {
          committedInBlock: Number(stored.committedInBlock),
          committedAt: Number(stored.committedAt),
          metadata,
        },
      };
    },
  });
}

function defineGovernanceStage(side) {
  const name = governanceStageName(side);
  return defineStage({
    name,
    async prepare(context) {
      if (context.existing) return frozenRecord(context.existing);
      const governanceAbi = await artifact("governance");
      const request = {
        scopeCommitment: side === "A" ? SCOPE_A : SCOPE_B,
        controller: context.participants[`controller${side}`],
        controllerKeyId: keccak256(toBytes(`mordant.run6.controller-key/${context.label}/${side}`)),
        organizationId: keccak256(toBytes(`mordant.run6.organization/${context.label}/${side}`)),
        controllerEpoch: 1,
        authorizationVersion: 1,
        nonce: side === "A" ? 201n : 202n,
      };
      return normalized({
        sender: context.topology.roles.deployer,
        nonce: await txNonce(context.client, context.topology.roles.deployer),
        to: context.topology.at.governance,
        calldata: encodeFunctionData({ abi: governanceAbi.abi, functionName: "authorize", args: [request] }),
        side,
        scopeCommitment: request.scopeCommitment,
        controller: request.controller,
        controllerKeyId: request.controllerKeyId,
        organizationId: request.organizationId,
        controllerEpoch: request.controllerEpoch,
        authorizationVersion: request.authorizationVersion,
        governanceNonce: request.nonce,
      });
    },
    execute: async ({ prepared, broadcast, journal, stage, execution }) => ({
      transactionHash: await execution.broadcastPrepared({
        prepared, broadcast, onBroadcast: (hash) => journal.markBroadcast(stage, hash),
      }),
    }),
    reconcile: async (context) => {
      const entry = context.journal.stage(name);
      if (!entry.scopeCommitment) return null;
      const governanceAbi = await artifact("governance");
      const recordDigest = entry.recordDigest ?? await context.client.readContract({
        address: context.topology.at.governance, abi: governanceAbi.abi,
        functionName: "versionRecord", args: [entry.scopeCommitment, entry.authorizationVersion],
      });
      if (!recordDigest || /^0x0{64}$/i.test(recordDigest)) return null;
      const record = await context.client.readContract({
        address: context.topology.at.governance, abi: governanceAbi.abi, functionName: "record", args: [recordDigest],
      });
      if (!record.exists) return null;
      if (record.controller.toLowerCase() !== entry.controller.toLowerCase()) {
        return { ambiguous: true, reason: `${name} record controller differs` };
      }
      return {
        alreadyDone: true,
        outputs: { recordDigest, reconciledRecordBlock: Number(record.validFromBlock) },
      };
    },
    verify: async (context) => {
      let entry = context.journal.stage(name);
      const governanceAbi = await artifact("governance");
      if (!entry.recordDigest && entry.transactionHash) {
        const receipt = await context.client.getTransactionReceipt({ hash: entry.transactionHash });
        let recordDigest = null;
        for (const log of receipt.logs) {
          try {
            const decoded = decodeEventLog({ abi: governanceAbi.abi, data: log.data, topics: log.topics });
            if (decoded.eventName === "ScopeAuthorized") recordDigest = decoded.args.recordDigest;
          } catch { /* unrelated event */ }
        }
        if (!recordDigest) return { ok: false, reason: "ScopeAuthorized event missing" };
        const block = await context.client.getBlock({ blockNumber: receipt.blockNumber });
        await context.journal.recordDerived(name, {
          recordDigest,
          recordBlock: Number(receipt.blockNumber),
          recordBlockTimestamp: Number(block.timestamp),
        });
        entry = context.journal.stage(name);
      }
      if (!entry.recordDigest) return { ok: false, reason: "governance record digest unavailable" };
      const record = await context.client.readContract({
        address: context.topology.at.governance, abi: governanceAbi.abi,
        functionName: "record", args: [entry.recordDigest],
      });
      const ok = record.exists && record.scopeCommitment === entry.scopeCommitment &&
        record.controller.toLowerCase() === entry.controller.toLowerCase() &&
        record.controllerKeyId === entry.controllerKeyId && record.organizationId === entry.organizationId &&
        Number(record.controllerEpoch) === Number(entry.controllerEpoch) &&
        Number(record.authorizationVersion) === Number(entry.authorizationVersion) &&
        BigInt(record.nonce) === b(entry.governanceNonce);
      return { ok, evidence: { recordDigest: entry.recordDigest, validFromBlock: Number(record.validFromBlock) } };
    },
  });
}

function defineSessionPreparedStage() {
  return defineStage({
    name: "SESSION_PREPARED",
    async prepare(context) {
      if (context.existing) return frozenRecord(context.existing);
      const [governanceAbi, signers] = await Promise.all([artifact("governance"), context.capabilities.intentSigners()]);
      const a = context.journal.stage("GOVERNANCE_A_CREATED");
      const bRecord = context.journal.stage("GOVERNANCE_B_CREATED");
      const sourceA = context.journal.stage("SOURCE_A_COMMITTED");
      const sourceB = context.journal.stage("SOURCE_B_COMMITTED");
      const vault = context.journal.stage("VAULT_CREATED");
      const now = BigInt((await context.client.getBlock()).timestamp);
      const sessionNonce = BigInt(toHex(randomBytes(32)));
      const sessionSalt = toHex(randomBytes(32));
      const intent = {
        chainId: BigInt(context.chainId),
        governanceRegistry: context.topology.at.governance,
        policyId: POLICY_ID,
        policyVersion: 1,
        governanceRecordA: a.recordDigest,
        governanceRecordB: bRecord.recordDigest,
        controllerKeyIdA: a.controllerKeyId,
        controllerKeyIdB: bRecord.controllerKeyId,
        controllerEpochA: 1,
        controllerEpochB: 1,
        scopeAuthorizationVersionA: 1,
        scopeAuthorizationVersionB: 1,
        sourceRecordCommitmentA: sourceA.commitment,
        sourceRecordCommitmentB: sourceB.commitment,
        scopeCommitmentA: a.scopeCommitment,
        scopeCommitmentB: bRecord.scopeCommitment,
        issuerKeyId: vault.issuerKeyId,
        identityEpoch: 1,
        strictAssetCommitmentA: vault.assetCommitment,
        candidateAuthorized: false,
        exactBudget: 1,
        candidateBudget: 0,
        sessionNonce,
        expiry: now + 7n * 24n * 3600n,
        disclosureVersion: 1,
      };
      const canonicalIntentHash = await context.client.readContract({
        address: context.topology.at.governance, abi: governanceAbi.abi, functionName: "intentDigest", args: [intent],
      });
      const signed = await Promise.all([
        signers.controllerA.signIntent(intent), signers.controllerB.signIntent(intent), signers.issuer.signIntent(intent),
      ]);
      if (signed.some(({ digest: actual }) => actual !== canonicalIntentHash)) {
        throw new JournalError("SIGNER_DIGEST_DISAGREEMENT", "a signer did not reproduce the canonical intent digest");
      }
      const signatures = { controllerA: signed[0].signature, controllerB: signed[1].signature, issuer: signed[2].signature };
      const [sessionNullifier, sessionCommitment, signatureBundleDigest] = await Promise.all([
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi, functionName: "sessionNullifierOf", args: [intent],
        }),
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi,
          functionName: "sessionCommitmentOf", args: [intent, signatures, sessionSalt],
        }),
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi,
          functionName: "signatureBundleDigest", args: [signatures],
        }),
      ]);
      const relayerRequest = { chainId: Number(context.chainId), sessionCommitment, sessionNullifier };
      return normalized({
        canonicalIntent: intent,
        canonicalIntentHash,
        sessionNonce,
        sessionNullifier,
        sessionSalt,
        signatures,
        signatureBundleDigest,
        sessionCommitment,
        relayerRequest,
        relayerRequestDigest: digest(relayerRequest),
      });
    },
    execute: async () => ({ outputs: {} }),
    verify: async (context) => {
      const entry = context.journal.stage("SESSION_PREPARED");
      const intent = intentFromRecord(entry);
      const governanceAbi = await artifact("governance");
      const [intentDigest, nullifier, commitment, signatureBundleDigest] = await Promise.all([
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi, functionName: "intentDigest", args: [intent],
        }),
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi, functionName: "sessionNullifierOf", args: [intent],
        }),
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi,
          functionName: "sessionCommitmentOf", args: [intent, entry.signatures, entry.sessionSalt],
        }),
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi,
          functionName: "signatureBundleDigest", args: [entry.signatures],
        }),
      ]);
      const request = { chainId: Number(context.chainId), sessionCommitment: commitment, sessionNullifier: nullifier };
      return {
        ok: intentDigest === entry.canonicalIntentHash && nullifier === entry.sessionNullifier &&
          commitment === entry.sessionCommitment && signatureBundleDigest === entry.signatureBundleDigest &&
          digest(request) === entry.relayerRequestDigest,
      };
    },
  });
}

function defineNullifierReservationStage() {
  return defineStage({
    name: "SESSION_NULLIFIER_RESERVED",
    prepare: async ({ journal, existing }) => existing ? frozenRecord(existing) : {
      sessionNullifier: journal.stage("SESSION_PREPARED").sessionNullifier,
      sessionCommitment: journal.stage("SESSION_PREPARED").sessionCommitment,
      reservationDigest: digest({
        nullifier: journal.stage("SESSION_PREPARED").sessionNullifier,
        commitment: journal.stage("SESSION_PREPARED").sessionCommitment,
      }),
    },
    execute: async () => ({ outputs: {} }),
    verify: async ({ client, topology, journal }) => {
      const entry = journal.stage("SESSION_NULLIFIER_RESERVED");
      const used = await client.readContract({
        address: topology.at.governance, abi: (await artifact("governance")).abi,
        functionName: "consumedNullifier", args: [entry.sessionNullifier],
      });
      // The reservation is journal-local. If a third party consumed it before
      // publication, the later relayer stage refuses rather than substituting.
      return { ok: used === false };
    },
  });
}

function defineSessionCommittedStage() {
  return defineStage({
    name: "SESSION_COMMITTED",
    async prepare(context) {
      if (context.existing) return frozenRecord(context.existing);
      const session = context.journal.stage("SESSION_PREPARED");
      const relayer = await context.capabilities.relayer.handle();
      const request = session.relayerRequest;
      if (digest(request) !== session.relayerRequestDigest) {
        throw new JournalError("RELAYER_REQUEST_DRIFT", "prepared request digest does not match session record");
      }
      return {
        sender: relayer.address,
        nonce: await txNonce(context.client, relayer.address),
        relayerAddress: relayer.address,
        relayerRequest: request,
        relayerRequestDigest: session.relayerRequestDigest,
        sessionCommitment: session.sessionCommitment,
        sessionNullifier: session.sessionNullifier,
      };
    },
    execute: async ({ prepared, journal, stage, execution }) => ({
      transactionHash: await execution.publishPrepared({
        prepared,
        onBroadcast: ({ transactionHash, sender, nonce }) => {
          if (sender.toLowerCase() !== prepared.sender.toLowerCase() || Number(nonce) !== Number(prepared.nonce)) {
            throw new JournalError("RELAYER_NONCE_DRIFT", `${sender} nonce ${nonce}`);
          }
          return journal.markBroadcast(stage, transactionHash);
        },
      }),
    }),
    reconcile: async (context) => {
      const entry = context.journal.stage("SESSION_COMMITTED");
      if (!entry.sessionCommitment) return null;
      const record = await context.client.readContract({
        address: context.topology.at.governance, abi: (await artifact("governance")).abi,
        functionName: "commitment", args: [entry.sessionCommitment],
      });
      if (!record.exists) return null;
      if (record.sessionNullifier !== entry.sessionNullifier || record.submitter.toLowerCase() !== entry.sender.toLowerCase()) {
        return { ambiguous: true, reason: "session commitment exists with substituted nullifier or relayer" };
      }
      return { alreadyDone: true, outputs: { reconciledSessionBlock: Number(record.committedInBlock) } };
    },
    verify: async (context) => {
      const entry = context.journal.stage("SESSION_COMMITTED");
      const governanceAbi = await artifact("governance");
      const [record, consumed] = await Promise.all([
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi,
          functionName: "commitment", args: [entry.sessionCommitment],
        }),
        context.client.readContract({
          address: context.topology.at.governance, abi: governanceAbi.abi,
          functionName: "consumedNullifier", args: [entry.sessionNullifier],
        }),
      ]);
      if (!record.exists || record.sessionNullifier !== entry.sessionNullifier || !consumed ||
        record.submitter.toLowerCase() !== entry.sender.toLowerCase()) {
        return { ok: false, reason: "registry session/nullifier readback mismatch" };
      }
      const event = governanceAbi.abi.find((item) => item.type === "event" && item.name === "SessionCommitted");
      const admissions = await context.client.getLogs({
        address: context.topology.at.governance, event, args: { sessionNullifier: entry.sessionNullifier },
        fromBlock: 0n, toBlock: "latest",
      });
      const exactAdmissions = admissions.filter((log) => log.args.sessionCommitment === entry.sessionCommitment);
      const ok = exactAdmissions.length === 1 && admissions.length === 1 && chronologyBlocks(context, record);
      return { ok, evidence: { committedInBlock: Number(record.committedInBlock), admissions: admissions.length } };
    },
  });
}

export function executionForAdmissionStage(capabilities, name) {
  if (name === "VAULT_CREATED") return capabilities.transaction.buyer;
  if (name === "VAULT_ACTIVATED") return capabilities.activation;
  if (name === "SOURCE_A_COMMITTED" || name === "SOURCE_B_COMMITTED") return capabilities.transaction.submitter;
  if (name === "GOVERNANCE_A_CREATED" || name === "GOVERNANCE_B_CREATED") return capabilities.transaction.deployer;
  if (name === "SESSION_COMMITTED") {
    return Object.freeze({
      async publishPrepared({ prepared, onBroadcast }) {
        const relayer = await capabilities.relayer.handle();
        if (relayer.address.toLowerCase() !== prepared.sender.toLowerCase()) {
          throw new JournalError("RELAYER_ADDRESS_DRIFT", relayer.address);
        }
        const result = await relayer.publishSessionCommitment(prepared.relayerRequest, { onBroadcast });
        if (result.status !== "success") throw new JournalError("RELAYER_TRANSACTION_REVERTED", result.transactionHash);
        return result.transactionHash;
      },
    });
  }
  return undefined;
}

/// Reconcile durable broadcast records before running any handler, then drive
/// the admission spine. A journal in AMBIGUOUS remains terminal by design.
export async function runAdmissionPipeline(context) {
  await context.journal.reconcile(context.client);
  return runPipeline(createAdmissionStages(), {
    ...context,
    executionForStage: (name) => executionForAdmissionStage(context.capabilities, name),
  });
}
