// A fresh local EVM for the integration rehearsal.
//
// The rehearsal must exercise the REAL stage handlers against REAL compiled
// contracts. A mocked chain would prove the handlers agree with the mock, which
// is the one thing nobody needs to know.
//
// Every instance is ephemeral and gets its own port and its own state, so a
// rehearsal never inherits anything from a previous run. That matters more here
// than usual: several stages are one-shot by design, and a reused chain would
// make a passing test indistinguishable from a stage silently skipping itself.
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { createPublicClient, createWalletClient, defineChain, http } from "viem";
import { mnemonicToAccount, privateKeyToAccount } from "viem/accounts";

/// Foundry's standard test mnemonic. Public by construction.
export const TEST_MNEMONIC = "test test test test test test test test test test test junk";

/// Anvil's deterministic mnemonic accounts, derived from the standard test
/// mnemonic. These are public test keys with no value; they exist in every
/// Foundry installation and are safe to embed.
///
/// Twenty are derived rather than the ten hard-coded here, so the derivation
/// below is used instead of this list when more are needed.
export const LOCAL_KEYS = Object.freeze([
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
  "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
  "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
  "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
]);

const LOCAL_CHAIN_ID = 31_337;

export const localChain = (port) =>
  defineChain({
    id: LOCAL_CHAIN_ID,
    name: "Mordant V5 rehearsal",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [`http://127.0.0.1:${port}`] } },
  });

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/// Starts anvil and waits until it answers. Resolving on the first successful
/// `eth_chainId` rather than on a log line means the harness does not depend on
/// anvil's output format.
export async function startLocalChain({ timeoutMs = 30_000 } = {}) {
  const port = await freePort();
  const child = spawn(
    "anvil",
    [
      "--port", String(port),
      "--host", "127.0.0.1",
      "--chain-id", String(LOCAL_CHAIN_ID),
      "--silent",
      // Large enough for the factory deployment plus a full session.
      // More than the default ten: the V5 topology needs deployer, issuer,
      // buyer, originator, facility, holder, relayer, submitter, three
      // validators and two controllers, all distinct.
      "--accounts", "20",
      "--gas-limit", "120000000",
      "--code-size-limit", "120000",
    ],
    { stdio: ["ignore", "ignore", "pipe"] },
  );

  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += String(chunk); });

  const chain = localChain(port);
  const rpc = `http://127.0.0.1:${port}`;
  const client = createPublicClient({ chain, transport: http(rpc) });

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (child.exitCode !== null) {
      throw new Error(`anvil exited with ${child.exitCode}: ${stderr.slice(0, 400)}`);
    }
    try {
      const id = await client.getChainId();
      if (id === LOCAL_CHAIN_ID) break;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error(`anvil did not become ready within ${timeoutMs}ms: ${stderr.slice(0, 400)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  // Derive the same twenty accounts anvil created, from the standard mnemonic.
  const accounts = Array.from({ length: 20 }, (_, index) =>
    mnemonicToAccount(TEST_MNEMONIC, { addressIndex: index }));
  const wallets = new Map();
  const walletFor = (account) => {
    if (!wallets.has(account.address)) {
      wallets.set(account.address, createWalletClient({ account, chain, transport: http(rpc) }));
    }
    return wallets.get(account.address);
  };

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    child.kill("SIGTERM");
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 3000);
      child.on("exit", () => { clearTimeout(timer); resolve(); });
    });
  };

  return { port, rpc, chain, client, accounts, walletFor, stop, pid: child.pid };
}

/// A transactor with the same shape the Monad runner uses, so a stage handler
/// written against one works unchanged against the other.
///
/// The local chain does not have Monad's `gas_limit * maxFeePerGas` balance
/// rule, but the same explicit-gas discipline is used anyway: a handler that
/// only works because the local chain is lenient would fail on Monad.
export function localTransactor(client, walletFor) {
  const fees = async () => {
    const block = await client.getBlock();
    const base = block.baseFeePerGas ?? 1_000_000_000n;
    return { maxPriorityFeePerGas: 1_000_000_000n, maxFeePerGas: base * 2n + 1_000_000_000n };
  };
  const bounded = (estimate) => (estimate * 130n) / 100n;

  return {
    fees,
    async deploy(account, artifact, args) {
      const wallet = walletFor(account);
      return wallet.deployContract({
        abi: artifact.abi,
        bytecode: artifact.bytecode.object ?? artifact.bytecode,
        args,
        gas: bounded(30_000_000n),
        ...(await fees()),
      });
    },
    async write(account, request) {
      const gas = bounded(await client.estimateContractGas({ ...request, account }));
      return walletFor(account).writeContract({ ...request, account, gas, ...(await fees()) });
    },
    async send(account, request) {
      const gas = bounded(await client.estimateGas({ ...request, account }));
      return walletFor(account).sendTransaction({ ...request, account, gas, ...(await fees()) });
    },
  };
}
