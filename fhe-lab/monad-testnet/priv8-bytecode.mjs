#!/usr/bin/env node

// Proves the deployed runtime bytecode derives, unchanged, from the frozen tree.
//
// A byte-for-byte comparison would fail for every contract that has immutables,
// because the compiler writes constructor-supplied values directly into the
// runtime code. So the artifact's own `immutableReferences` map is used to blank
// exactly those spans on both sides; everything outside them must match
// exactly, and the values inside them are decoded and reported as the deployed
// configuration.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createPublicClient, defineChain, http, getAddress, keccak256 } from "viem";
import { REPO } from "./priv8-chain.mjs";
import { ARTIFACTS } from "./priv8-deploy.mjs";

const [, , journalPath, outPath] = process.argv;

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
const journal = JSON.parse(await readFile(journalPath, "utf8"));

const DEPLOYED = {
  MockEligibility: ["MockEligibility", "MockEligibility.sol"],
  SettlementToken: ["MockERC20", "MockERC20.sol"],
  "ReceivableUnits:3": ["MockERC20", "MockERC20.sol"],
  "MockCvaAdapter:3": ["MockCvaAdapter", "MockCvaAdapter.sol"],
  MordantIssuerRegistry: ["MordantIssuerRegistry", "MordantIssuerRegistry.sol"],
  MordantFactoryV2: ["MordantFactoryV2", "MordantFactoryV2.sol"],
  MordantSourceIdentityRegistry: ["MordantSourceIdentityRegistry", "MordantSourceIdentityRegistry.sol"],
  MordantScopeGovernanceRegistry: ["MordantScopeGovernanceRegistry", "MordantScopeGovernanceRegistry.sol"],
  ECDSAQuorumMatchVerifierV4: ["ECDSAQuorumMatchVerifierV4", "ECDSAQuorumMatchVerifierV4.sol"],
  PrivateMatchBinder: ["PrivateMatchBinder", "PrivateMatchBinder.sol"],
};

const blank = (hex, spans) => {
  const bytes = Buffer.from(hex.slice(2), "hex");
  for (const span of spans) bytes.fill(0, span.start, span.start + span.length);
  return `0x${bytes.toString("hex")}`;
};

const report = { chainId: 10_143, contracts: [] };
for (const [step, [name, path]] of Object.entries(DEPLOYED)) {
  const journalStep = journal.steps[`deploy:${step}`];
  if (!journalStep?.contractAddress) continue;
  const address = getAddress(journalStep.contractAddress);
  const artifact = JSON.parse(await readFile(resolve(REPO, `contracts/out/${path}/${name}.json`), "utf8"));
  const expected = artifact.deployedBytecode.object;
  const references = artifact.deployedBytecode.immutableReferences ?? {};
  const spans = Object.values(references).flat();
  const onChain = await client.getBytecode({ address });

  const maskedExpected = blank(expected, spans);
  const maskedOnChain = blank(onChain, spans);
  const immutables = spans.map((span) => ({
    start: span.start,
    length: span.length,
    value: `0x${Buffer.from(onChain.slice(2), "hex").subarray(span.start, span.start + span.length).toString("hex")}`,
  }));

  report.contracts.push({
    step,
    contract: name,
    address,
    deployTransaction: journalStep.hash,
    sizeBytes: (onChain.length - 2) / 2,
    immutableSpans: spans.length,
    matchesFrozenArtifactOutsideImmutables: maskedExpected === maskedOnChain,
    onChainCodeHash: keccak256(onChain),
    artifactCodeHash: keccak256(expected),
    identicalIncludingImmutables: keccak256(onChain) === keccak256(expected),
    immutables,
  });
}

report.summary = {
  contracts: report.contracts.length,
  allMatchOutsideImmutables: report.contracts.every((entry) => entry.matchesFrozenArtifactOutsideImmutables),
  identicalWithNoImmutables: report.contracts.filter((entry) => entry.identicalIncludingImmutables).map((entry) => entry.step),
  differOnlyInImmutables: report.contracts
    .filter((entry) => !entry.identicalIncludingImmutables && entry.matchesFrozenArtifactOutsideImmutables)
    .map((entry) => entry.step),
  mismatched: report.contracts.filter((entry) => !entry.matchesFrozenArtifactOutsideImmutables).map((entry) => entry.step),
};

await writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report.summary, null, 2));
if (!report.summary.allMatchOutsideImmutables) process.exitCode = 1;
