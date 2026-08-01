// Shared rehearsal scaffolding: one stack builder, used by every group test.
//
// Having one builder matters. If each group test deployed its own variant they
// could drift apart, and a group would pass against a stack the next group
// never sees. The live runner will assemble the same stack from the same plan.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { keccak256, toBytes } from "viem";

import { REPO } from "./priv8-chain.mjs";
import { ARTIFACTS } from "./v5-call-matrix.mjs";
import { DEPLOYMENTS, deploymentOrder, resolveArguments, resolveConfiguration }
  from "./v5-deployment-plan.mjs";
import { localTransactor } from "./v5-local-chain.mjs";

export const CHAIN_ID = 31_337;
export const CURRENCY = keccak256(toBytes("USD"));
export const POLICY_ID = keccak256(toBytes("mordant.policy.v5"));
export const SCOPE_A = keccak256(toBytes("mordant.v5.scope-a"));
export const SCOPE_B = keccak256(toBytes("mordant.v5.scope-b"));

const cache = {};
export async function artifact(key) {
  if (!cache[key]) {
    cache[key] = JSON.parse(await readFile(resolve(REPO, ARTIFACTS[key]), "utf8"));
  }
  return cache[key];
}

/// A bounded signer capability.
///
/// It exposes `signDigest` and nothing else: no key, no `signTransaction`, no
/// way to ask it for arbitrary bytes. The runner holds one of these per signer
/// and can do exactly one thing with it.
export function boundedSigner(account, label) {
  return Object.freeze({
    label,
    address: account.address,
    async signDigest(digest) {
      if (!/^0x[0-9a-f]{64}$/.test(digest)) {
        throw new Error(`${label}: refusing to sign a value that is not a 32-byte digest`);
      }
      return account.sign({ hash: digest });
    },
  });
}

/// Deploys and configures the complete V5 stack from the verified plan.
export async function deployStack(chain) {
  const tx = localTransactor(chain.client, chain.walletFor);
  const [deployer, issuer, buyer, originator, facility, holder, relayer, submitter] = chain.accounts;
  const [v1, v2, v3] = chain.accounts.slice(8, 11);
  const [controllerA, controllerB] = chain.accounts.slice(11, 13);

  const roles = {
    deployer: deployer.address, issuer: issuer.address, buyer: buyer.address,
    originator: originator.address, facility: facility.address, holder: holder.address,
    relayer: relayer.address, submitter: submitter.address,
  };
  const validators = [v1.address, v2.address, v3.address]
    .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
  const config = {
    policyId: POLICY_ID, policyVersion: 1, validators, quorum: 2n, recomputationQuorum: 2,
    curePeriod: 604_800n, consequenceId: keccak256(toBytes("consequence")), identityEpoch: 1,
  };

  const at = {};
  for (const entry of deploymentOrder()) {
    const art = await artifact(entry.artifact);
    const hash = await tx.deploy(deployer, art, resolveArguments(entry, { at, roles, config }));
    const receipt = await chain.client.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error(`deploy ${entry.id} reverted`);
    at[entry.id] = receipt.contractAddress;
  }

  const byAddress = Object.fromEntries(
    DEPLOYMENTS.map((entry) => [at[entry.id].toLowerCase(), entry.artifact]),
  );
  for (const step of [
    "register-issuer", "set-policy-version", "authorize-relayer", "authorize-binder",
    "authorize-submitter", "authorize-revealer", "approve-adapter", "approve-settlement",
    "approve-facility", "eligible-buyer", "eligible-originator", "eligible-facility",
    "eligible-holder",
  ]) {
    const call = resolveConfiguration(step, { at, roles, config });
    const art = await artifact(byAddress[call.at.toLowerCase()]);
    const hash = await tx.write(deployer, {
      address: call.at, abi: art.abi, functionName: call.fn, args: call.args,
    });
    const receipt = await chain.client.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error(`configuration ${step} reverted`);
  }

  const issuerKeyId = await chain.client.readContract({
    address: at.issuerRegistry, abi: (await artifact("issuerRegistry")).abi,
    functionName: "issuerKeyIdFor", args: [issuer.address],
  });

  return {
    at, roles, config, tx, issuerKeyId,
    validatorAccounts: [v1, v2, v3].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1)),
    accounts: {
      deployer, issuer, buyer, originator, facility, holder, relayer, submitter,
      controllerA, controllerB,
    },
    issuerSigner: boundedSigner(issuer, "issuer"),
    controllerASigner: boundedSigner(controllerA, "controller-a"),
    controllerBSigner: boundedSigner(controllerB, "controller-b"),
  };
}
