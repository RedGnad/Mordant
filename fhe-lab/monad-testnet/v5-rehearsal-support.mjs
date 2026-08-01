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
import { TARGETS, guardedBroadcast } from "./v5-live-guard.mjs";
import { createRelayerProcess } from "./v5-relayer-process.mjs";

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

/// A signer that recomputes the V5 intent digest from the complete canonical
/// intent at its configured registry before signing. The runner can compare
/// the returned digest to its own frozen value, but cannot ask this handle to
/// sign a substituted hash.
function localIntentSigner({ account, label, chain, governance, governanceAbi }) {
  return Object.freeze({
    label,
    address: account.address,
    async signIntent(intent) {
      const digest = await chain.client.readContract({
        address: governance, abi: governanceAbi, functionName: "intentDigest", args: [intent],
      });
      return Object.freeze({ digest, signature: await account.sign({ hash: digest }) });
    },
  });
}

/// A one-method transaction capability for the journalized local rehearsal.
///
/// The runner sees the public address and can hand this object only to the
/// relevant execute handler. The account, wallet and RPC client stay closed
/// over here; there is no generic send or signing method for a handler to use.
function preparedTransactionCapability({ account, chain, label }) {
  return Object.freeze({
    address: account.address,
    async broadcastPrepared({ prepared, broadcast, onBroadcast }) {
      if (prepared.sender?.toLowerCase() !== account.address.toLowerCase()) {
        throw new Error(`${label}: prepared sender is outside this capability`);
      }
      if (!prepared.to || !prepared.calldata) throw new Error(`${label}: missing prepared target or calldata`);
      const block = await chain.client.getBlock();
      const priority = 1_000_000_000n;
      const fee = (block.baseFeePerGas ?? priority) * 2n + priority;
      const estimate = await chain.client.estimateGas({
        account: account.address, to: prepared.to, data: prepared.calldata, value: 0n,
      });
      const gas = (estimate * 130n) / 100n;
      const hash = await broadcast(label, async () => chain.walletFor(account).sendTransaction({
        account, to: prepared.to, data: prepared.calldata, value: 0n, gas,
        maxFeePerGas: fee, maxPriorityFeePerGas: priority,
      }));
      if (onBroadcast) await onBroadcast(hash);
      return hash;
    },
  });
}

function preparedActivationCapability({ chain, accounts, topology }) {
  const byRole = Object.freeze({
    deployer: accounts.deployer,
    holder: accounts.holder,
    facility: accounts.facility,
  });
  const erc20Abi = [
    { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "allowance", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "uint256" }] },
  ];
  const adapterAbi = [{
    type: "function", name: "availableBalance", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }],
  }];
  const send = async ({ role, to, calldata }, broadcast, description) => {
    const account = byRole[role];
    if (!account || !to || !calldata) throw new Error(`activation capability: invalid ${description}`);
    const block = await chain.client.getBlock();
    const priority = 1_000_000_000n;
    const fee = (block.baseFeePerGas ?? priority) * 2n + priority;
    const estimate = await chain.client.estimateGas({ account: account.address, to, data: calldata, value: 0n });
    const gas = (estimate * 130n) / 100n;
    return broadcast(description, async () => chain.walletFor(account).sendTransaction({
      account, to, data: calldata, value: 0n, gas, maxFeePerGas: fee, maxPriorityFeePerGas: priority,
    }));
  };
  return Object.freeze({
    async activatePrepared({ prepared, broadcast, onBroadcast }) {
      const config = prepared.activationAmounts;
      const alreadyReady = [
        async () => (await chain.client.readContract({
          address: topology.at.cvaToken, abi: erc20Abi, functionName: "balanceOf", args: [accounts.deployer.address],
        })) >= BigInt(config.units),
        async () => (await chain.client.readContract({
          address: topology.at.cvaToken, abi: erc20Abi, functionName: "allowance",
          args: [accounts.deployer.address, topology.at.adapter],
        })) >= BigInt(config.units),
        async () => (await chain.client.readContract({
          address: topology.at.adapter, abi: adapterAbi, functionName: "availableBalance", args: [prepared.to],
        })) >= BigInt(config.units),
        async () => (await chain.client.readContract({
          address: topology.at.settlement, abi: erc20Abi, functionName: "balanceOf", args: [accounts.holder.address],
        })) >= BigInt(config.advance),
        async () => (await chain.client.readContract({
          address: topology.at.settlement, abi: erc20Abi, functionName: "allowance", args: [accounts.holder.address, prepared.to],
        })) >= BigInt(config.holderApproval),
      ];
      for (const [index, call] of (prepared.activationPrerequisites ?? []).entries()) {
        // Each prerequisite is idempotently reconciled before it is sent. A
        // restart after any individual setup hash therefore never mints or
        // credits the vault a second time.
        if (await alreadyReady[index]()) continue;
        const hash = await send(call, broadcast, `vault activation prerequisite ${index + 1}`);
        const receipt = await chain.client.waitForTransactionReceipt({ hash });
        if (receipt.status !== "success") throw new Error(`activation prerequisite ${index + 1} reverted`);
      }
      const hash = await send({ role: "facility", to: prepared.to, calldata: prepared.calldata }, broadcast, "vault activate");
      if (onBroadcast) await onBroadcast(hash);
      return hash;
    },
  });
}

/// The local-only capability bundle used by the recovery rehearsal. It models
/// the production boundaries: issuer/controllers/relayer are passed as tiny
/// handles, while no runner code receives their private keys.
export function localRunCapabilities(chain, stack) {
  const { accounts } = stack;
  const governanceAbiPromise = artifact("governance");
  const relayer = {
    async handle() {
      const governance = await governanceAbiPromise;
      return createRelayerProcess({
        account: accounts.relayer,
        client: chain.client,
        walletFor: chain.walletFor,
        registry: stack.at.governance,
        chainId: CHAIN_ID,
        governanceAbi: governance.abi,
        broadcast: (description, send) =>
          guardedBroadcast({ target: TARGETS.LOCAL, description, send, env: {} }),
      });
    },
  };
  return Object.freeze({
    // Source attestations retain the bounded digest-only capability because
    // `signSourceAttestation` first reaches three independent digest mirrors.
    issuerSourceSigner: stack.issuerSigner,
    async intentSigners() {
      const governance = await governanceAbiPromise;
      return Object.freeze({
        controllerA: localIntentSigner({
          account: accounts.controllerA, label: "controller-a", chain,
          governance: stack.at.governance, governanceAbi: governance.abi,
        }),
        controllerB: localIntentSigner({
          account: accounts.controllerB, label: "controller-b", chain,
          governance: stack.at.governance, governanceAbi: governance.abi,
        }),
        issuer: localIntentSigner({
          account: accounts.issuer, label: "issuer", chain,
          governance: stack.at.governance, governanceAbi: governance.abi,
        }),
      });
    },
    async signPledge({ vault, vaultAbi, pledge }) {
      const digest = await chain.client.readContract({
        address: vault, abi: vaultAbi, functionName: "hashPledge", args: [pledge],
      });
      return Object.freeze({ digest, signature: await accounts.originator.sign({ hash: digest }) });
    },
    relayer,
    activation: preparedActivationCapability({ chain, accounts, topology: stack }),
    transaction: Object.freeze({
      buyer: preparedTransactionCapability({ account: accounts.buyer, chain, label: "buyer prepared transaction" }),
      submitter: preparedTransactionCapability({ account: accounts.submitter, chain, label: "submitter prepared transaction" }),
      deployer: preparedTransactionCapability({ account: accounts.deployer, chain, label: "deployer prepared transaction" }),
      facility: preparedTransactionCapability({ account: accounts.facility, chain, label: "facility prepared transaction" }),
    }),
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
