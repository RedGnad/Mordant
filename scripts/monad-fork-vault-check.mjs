#!/usr/bin/env node
/**
 * Factory to vault creation, on a disposable Monad fork.
 *
 * The remote RPC cannot simulate this: `createInvoiceVault` needs a deployed factory, and inventing
 * one would fabricate state. A local fork of Monad testnet keeps the real A-Pass and A-Token code in
 * place while letting the deployment sequence actually run.
 *
 * This is FORK evidence. It is never READ-ONLY RPC evidence, and it is never a deployment: nothing
 * is broadcast to Monad, and no Cleanverse endpoint is called.
 *
 *   node scripts/monad-fork-vault-check.mjs [--rpc-url <url>] [--out <prefix>]
 */
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createPublicClient, createTestClient, createWalletClient, http, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FORK_PORT = 8546;
const FORK_URL = `http://127.0.0.1:${FORK_PORT}`;
const MONAD_CHAIN_ID = 10_143;
const MONAD_CODE_SIZE_LIMIT = 131_072;

const MONAD_APASS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9";
const MONAD_ATOKEN = "0x6cbA1135f61BA24867Ef125eFcA46fC7f9FDa835";
/** Addresses observed to hold a valid Monad A-Pass, reused here as fork participants. */
const APASS_HOLDERS = {
  buyer: "0x000000000000000000000000000000000000dEaD",
  originator: "0x1111111111111111111111111111111111111111",
  facility: "0x7f7098632b0258Af07e527015D65e6bc743f4CF5",
};
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const UNIT = 1_000_000n;
const CURRENCY = `0x${Buffer.from("USD").toString("hex").padEnd(64, "0")}`;
const INVOICE_ROOT = `0x${"c3".repeat(32)}`;

function artifact(file, name) {
  const parsed = JSON.parse(readFileSync(join(ROOT, "contracts", "out", file, `${name}.json`), "utf8"));
  return { abi: parsed.abi, bytecode: parsed.bytecode.object };
}

function parseArgs() {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const at = (flag) => { const i = argv.indexOf(flag); return i === -1 ? null : argv[i + 1] ?? null; };
  return {
    rpcUrl: at("--rpc-url") ?? process.env.MONAD_RPC_URL ?? "https://testnet-rpc.monad.xyz",
    out: at("--out"),
  };
}

async function waitReady(client, attempts = 120) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try { await client.getBlockNumber(); return; }
    catch { await new Promise((resolve) => setTimeout(resolve, 500)); }
  }
  throw new Error("the fork did not become ready");
}

async function main() {
  const { rpcUrl, out } = parseArgs();
  const steps = [];
  const record = (step, ok, detail) => {
    steps.push({ step, ok, detail });
    process.stdout.write(`  ${ok ? "ok  " : "FAIL"} ${step.padEnd(38)} ${detail}\n`);
  };

  const fork = spawn("anvil", [
    "--fork-url", rpcUrl, "--port", String(FORK_PORT), "--host", "127.0.0.1",
    "--code-size-limit", String(MONAD_CODE_SIZE_LIMIT), "--silent",
  ], { stdio: ["ignore", "ignore", "inherit"] });
  const stop = () => { if (!fork.killed) fork.kill("SIGTERM"); };
  process.on("SIGINT", () => { stop(); process.exit(0); });

  let status = "NOT PROVEN";
  let vaultAddress = null;
  let forkBlock = null;

  try {
    const chain = { ...anvil, id: MONAD_CHAIN_ID };
    const transport = http(FORK_URL);
    const publicClient = createPublicClient({ chain, transport });
    const testClient = createTestClient({ chain, transport, mode: "anvil" });
    await waitReady(publicClient);

    forkBlock = (await publicClient.getBlockNumber()).toString();
    record("fork ready", true, `forked Monad at block ${forkBlock}`);

    const deployer = privateKeyToAccount(DEPLOYER_KEY);
    const wallet = createWalletClient({ account: deployer, chain, transport });

    const deployFor = async ({ abi, bytecode }, args) => {
      const hash = await wallet.deployContract({ abi, bytecode, args });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error("creation reverted");
      return receipt.contractAddress;
    };
    const send = async (address, abi, functionName, args, account = deployer) => {
      const hash = await createWalletClient({ account, chain, transport })
        .writeContract({ address, abi, functionName, args });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      if (receipt.status !== "success") throw new Error(`${functionName} reverted`);
      return receipt;
    };

    const verifierArtifact = artifact("CleanverseAPassVerifier.sol", "CleanverseAPassVerifier");
    const factoryArtifact = artifact("MordantFactory.sol", "MordantFactory");
    const adapterArtifact = artifact("CleanverseCvaAdapter.sol", "CleanverseCvaAdapter");

    const verifier = await deployFor(verifierArtifact, [deployer.address, MONAD_APASS, 16n]);
    record("CleanverseAPassVerifier deployed", true, verifier);

    const adapter = await deployFor(adapterArtifact, [deployer.address, MONAD_ATOKEN, MONAD_APASS]);
    record("CleanverseCvaAdapter deployed", true, adapter);

    const factory = await deployFor(factoryArtifact, [deployer.address, verifier]);
    record("MordantFactory deployed", true, `${factory} (40382 B runtime accepted)`);

    // Roles, against the live A-Pass credentials preserved by the fork.
    for (const [role, account] of [[1, APASS_HOLDERS.buyer], [2, APASS_HOLDERS.originator],
      [3, APASS_HOLDERS.facility]]) {
      await send(verifier, verifierArtifact.abi, "setRoleEligibility", [account, role, true]);
    }
    record("role eligibility granted", true, "buyer, originator, facility");

    for (const [fn, args] of [
      ["setFacility", [APASS_HOLDERS.facility, true]],
      ["setCvaAdapter", [adapter, true]],
      ["setSettlementToken", [MONAD_ATOKEN, true]],
    ]) {
      await send(factory, factoryArtifact.abi, fn, args);
    }
    record("factory allowlists configured", true, "facility, adapter, settlement token");

    // The buyer creates the vault, so the fork impersonates that A-Pass holder.
    await testClient.impersonateAccount({ address: APASS_HOLDERS.buyer });
    await testClient.setBalance({ address: APASS_HOLDERS.buyer, value: 10n ** 19n });

    const latest = await publicClient.getBlock();
    const receipt = await send(factory, factoryArtifact.abi, "createInvoiceVault", [{
      cvaAdapter: adapter,
      settlementToken: MONAD_ATOKEN,
      invoiceRoot: INVOICE_ROOT,
      currency: CURRENCY,
      buyer: APASS_HOLDERS.buyer,
      originatorTreasury: APASS_HOLDERS.originator,
      initialOriginatorSigner: APASS_HOLDERS.originator,
      initialUnits: 100n * UNIT,
      advanceAmount: 100n * UNIT,
      faceValue: 110n * UNIT,
      bondBps: 1_000,
      protectionEnd: latest.timestamp + 30n * 24n * 3_600n,
      revealPeriod: 3_600n,
      curePeriod: 3_600n,
    }], { address: APASS_HOLDERS.buyer, type: "json-rpc" });

    const [created] = parseEventLogs({
      abi: factoryArtifact.abi, eventName: "InvoiceVaultCreated", logs: receipt.logs,
    });
    vaultAddress = created.args.vault;
    const code = await publicClient.getCode({ address: vaultAddress });
    record("factory created the vault", true,
      `${vaultAddress}, ${(code.length - 2) / 2} B of runtime installed`);
    status = "FORK";
  } catch (error) {
    record("factory to vault creation", false, (error.message ?? String(error)).split("\n")[0].slice(0, 200));
  } finally {
    stop();
  }

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    classification: "FORK",
    warning:
      "Disposable local fork of Monad testnet. Nothing was broadcast to Monad and no Cleanverse"
      + " endpoint was called. FORK evidence is never READ-ONLY RPC evidence and never a deployment.",
    forkedFromBlock: forkBlock,
    vault: vaultAddress,
    status: {
      "MONAD FACTORY → VAULT CREATION": status,
      "MONAD DEPLOYMENT": "NOT PROVEN — NO TRANSACTION BROADCAST",
    },
    steps,
  };

  if (out !== null) {
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(`${out}.json`, `${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(`\nWrote ${out}.json\n`);
  }
  process.stdout.write(`\nMONAD FACTORY → VAULT CREATION: ${status}\n`);
  process.exitCode = status === "FORK" ? 0 : 1;
}

main().catch((error) => {
  process.stderr.write(`fork check failed: ${error.message}\n`);
  process.exitCode = 1;
});
