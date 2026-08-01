#!/usr/bin/env node
// V5 Monad testnet acceptance.
//
// Deploys the V5 stack, publishes both opaque source-record commitments, admits
// one bilateral session through a policy-authorized relayer, runs the real FHE
// session out of process, and submits the result through the V5 verifier and
// binder on chain.
//
// What is deliberately NOT in this file: any private value. The plaintext
// receivable identifiers, the FHE secrets and the threshold shares all live
// inside the `v5-session` process and never cross back. This runner sees only
// commitments, digests and two released Booleans.
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { encodeAbiParameters, keccak256, parseAbiParameters, toBytes, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  CHAIN_ID, REPO, artifact, config, deriveRole, fail, getAddress,
  monadChain, paceRpc, publicClient, transactor, walletFactory,
} from "./priv8-chain.mjs";

const POLICY_ID = keccak256(toBytes("mordant.policy.v5"));
const POLICY_VERSION = 1;
const CURRENCY = keccak256(toBytes("USD"));
const SCOPE_A = keccak256(toBytes("mordant.v5.scope-a"));
const SCOPE_B = keccak256(toBytes("mordant.v5.scope-b"));
const IDENTITY_EPOCH = 1;
const EVALUATION_KEY_EPOCH = 1;
const FACE = 110_000_000n;
const ADVANCE = 100_000_000n;
const UNITS = 100_000_000n;
const CURE_PERIOD = 7n * 24n * 3600n;

const V5_ARTIFACTS = Object.freeze({
  eligibility: ["MockEligibility", "MockEligibility.sol"],
  erc20: ["MockERC20", "MockERC20.sol"],
  adapter: ["MockCvaAdapter", "MockCvaAdapter.sol"],
  issuerRegistry: ["MordantIssuerRegistry", "MordantIssuerRegistry.sol"],
  factory: ["MordantFactoryV2", "MordantFactoryV2.sol"],
  vault: ["MordantInvoiceVaultV2", "MordantInvoiceVaultV2.sol"],
  governance: ["MordantScopeGovernanceRegistryV5", "MordantScopeGovernanceRegistryV5.sol"],
  sources: ["MordantSourceCommitmentRegistry", "MordantSourceCommitmentRegistry.sol"],
  verifier: ["MordantMatchVerifierV5", "MordantMatchVerifierV5.sol"],
  binder: ["PrivateMatchBinderV5", "PrivateMatchBinderV5.sol"],
});

async function loadArtifacts() {
  const loaded = {};
  for (const [key, [name, path]] of Object.entries(V5_ARTIFACTS)) {
    loaded[key] = await artifact(name, path);
  }
  return loaded;
}

const log = (...parts) => process.stdout.write(parts.join(" ") + "\n");

async function main() {
  const outDir = process.env.V5_RUN_DIR ?? resolve(REPO, "fhe-lab/monad-testnet/artifacts/v5-run");
  await mkdir(outDir, { recursive: true });

  const settings = config();
  paceRpc(settings.rpc);
  const chain = monadChain(settings.rpc);
  const client = publicClient(chain, settings.rpc);
  const walletFor = walletFactory(chain, settings.rpc);
  const tx = transactor(client, walletFor);

  const chainId = await client.getChainId();
  if (chainId !== CHAIN_ID) fail("WRONG_CHAIN", String(chainId));

  // Roles. The relayer and the submitter are deliberately NOT the controllers:
  // a session commitment published by a controller would identify that side.
  const deployer = settings.deployer;
  const issuer = deriveRole(settings.deployerKey, "v5-issuer");
  const controllerA = deriveRole(settings.deployerKey, "v5-controller-a");
  const controllerB = deriveRole(settings.deployerKey, "v5-controller-b");
  const relayer = deriveRole(settings.deployerKey, "v5-relayer");
  const submitter = deriveRole(settings.deployerKey, "v5-submitter");
  const validators = ["v5-validator-1", "v5-validator-2", "v5-validator-3"]
    .map((label) => deriveRole(settings.deployerKey, label))
    .sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));

  log("deployer  ", deployer.address);
  log("relayer   ", relayer.address, "(not a controller)");
  log("submitter ", submitter.address, "(not a source controller)");

  const journal = { chainId, startedAt: new Date().toISOString(), addresses: {}, transactions: {} };
  const record = async (name, hash) => {
    const receipt = await client.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") fail("TX_REVERTED", `${name} ${hash}`);
    journal.transactions[name] = { hash, block: Number(receipt.blockNumber), gasUsed: String(receipt.gasUsed) };
    log(`  ${name} ${hash} block ${receipt.blockNumber}`);
    return receipt;
  };

  const art = await loadArtifacts();

  // Fund the roles that must send their own transactions.
  log("\nfunding roles");
  for (const [label, account] of [["relayer", relayer], ["submitter", submitter]]) {
    const balance = await client.getBalance({ address: account.address });
    if (balance < 200_000_000_000_000_000n) {
      const hash = await tx.send(deployer, { to: account.address, value: 300_000_000_000_000_000n });
      await record(`fund-${label}`, hash);
    }
  }

  log("\ndeploying V5 stack");
  const deploy = async (name, key, args) => {
    const hash = await tx.deploy(deployer, art[key], args);
    const receipt = await record(`deploy-${name}`, hash);
    const address = getAddress(receipt.contractAddress);
    journal.addresses[name] = address;
    return address;
  };

  const eligibility = await deploy("eligibility", "eligibility", []);
  const settlement = await deploy("settlement", "erc20", ["Settlement", "aUSD", 6]);
  const cvaToken = await deploy("cvaToken", "erc20", ["Invoice A-Token", "aINV", 6]);
  const adapter = await deploy("adapter", "adapter", [cvaToken]);
  const issuerRegistry = await deploy("issuerRegistry", "issuerRegistry", [deployer.address]);
  const factory = await deploy("factory", "factory", [deployer.address, eligibility, issuerRegistry]);
  const governance = await deploy("governance", "governance", [deployer.address]);
  const sources = await deploy("sources", "sources", [deployer.address, issuerRegistry]);
  const verifier = await deploy("verifier", "verifier", [
    deployer.address, governance, validators.map((v) => v.address), 2n, 2,
  ]);
  const binder = await deploy("binder", "binder", [
    verifier, governance, sources, factory, POLICY_ID, POLICY_VERSION, CURE_PERIOD,
    keccak256(toBytes("mordant.v5.consequence")),
  ]);

  const write = async (name, address, abiKey, functionName, args, account = deployer) => {
    const hash = await tx.write(account, { address, abi: art[abiKey].abi, functionName, args });
    return record(name, hash);
  };

  log("\nconfiguring");
  await write("register-issuer", issuerRegistry, "issuerRegistry", "registerIssuer", [issuer.address, IDENTITY_EPOCH]);
  await write("set-policy-version", verifier, "verifier", "setPolicyVersion", [POLICY_ID, POLICY_VERSION]);
  await write("authorize-relayer", governance, "governance", "setAuthorizedRelayer", [relayer.address, true]);
  await write("authorize-binder", governance, "governance", "setAuthorizedBinder", [binder, true]);
  await write("authorize-submitter", sources, "sources", "setAuthorizedSubmitter", [submitter.address, true]);
  await write("authorize-revealer", sources, "sources", "setAuthorizedRevealer", [binder, true]);
  await write("approve-adapter", factory, "factory", "setCvaAdapter", [adapter, true]);
  await write("approve-settlement", factory, "factory", "setSettlementToken", [settlement, true]);

  await writeFile(resolve(outDir, "journal.json"), JSON.stringify(journal, null, 2) + "\n");
  log("\ndeployment journal written to", resolve(outDir, "journal.json"));
  log("\nV5 stack deployed. Addresses:");
  for (const [name, address] of Object.entries(journal.addresses)) log(`  ${name.padEnd(16)} ${address}`);

  return { journal, outDir };
}

main().then(({ outDir }) => {
  log("\nstage 1 complete:", outDir);
}).catch((error) => {
  process.stderr.write(`\nV5 acceptance failed: ${error.code ?? ""} ${error.message}\n`);
  process.exit(1);
});
