import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { Abi, Address, Hex } from "viem";

import { assertNoSecretLeak, redactSecrets } from "../evidence/redaction";
import {
  EIP170_RUNTIME_LIMIT,
  MONAD_INIT_CODE_LIMIT,
  MONAD_RUNTIME_LIMIT,
  WrongNetworkError,
  assertMonadTestnet,
  createPreflightTransport,
  describeRpcEndpoint,
  pinBlock,
  preflightContract,
  type ArtifactRef,
  type ContractPreflight,
  type LoadedArtifact,
} from "./monad-preflight";

/**
 * `pnpm preflight:monad`
 *
 * Read-only Monad deployment preflight. No key, no signature, no broadcast. A passing estimate
 * means the RPC would accept the creation, not that anything was deployed.
 */

/**
 * Deployed Monad contracts used only as constructor arguments that satisfy a code-length check.
 * They are not a claim that Mordant is wired to them.
 */
const MONAD_APASS = "0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9" as Address;
const MONAD_ATOKEN = "0x6cbA1135f61BA24867Ef125eFcA46fC7f9FDa835" as Address;
/** Simulation caller. No private key exists for it and nothing is signed. */
const SIMULATION_CALLER = "0x000000000000000000000000000000000000d341" as Address;

const OPEN_ROLE_MASK = 16n;

const ARTIFACTS: readonly ArtifactRef[] = Object.freeze([
  {
    key: "verifier",
    file: "CleanverseAPassVerifier.sol",
    name: "CleanverseAPassVerifier",
    args: [SIMULATION_CALLER, MONAD_APASS, OPEN_ROLE_MASK],
    argumentNote:
      "Owner is the simulation caller; the A-Pass argument is the live Monad A-Pass, which the"
      + " constructor requires to carry bytecode.",
  },
  {
    key: "adapter",
    file: "CleanverseCvaAdapter.sol",
    name: "CleanverseCvaAdapter",
    args: [SIMULATION_CALLER, MONAD_ATOKEN, MONAD_APASS],
    argumentNote:
      "The token argument is an existing Monad A-Token used only because the constructor requires a"
      + " code-bearing address. The judged deployment will use the freshly issued invoice A-Token.",
  },
  {
    key: "factory",
    file: "MordantFactory.sol",
    name: "MordantFactory",
    args: [SIMULATION_CALLER, MONAD_APASS],
    argumentNote:
      "The verifier argument is a placeholder that only satisfies the constructor's code-length"
      + " check. The real deployment passes the CleanverseAPassVerifier deployed one step earlier,"
      + " whose address cannot exist before that deployment.",
  },
  {
    key: "vault",
    file: "MordantInvoiceVault.sol",
    name: "MordantInvoiceVault",
    args: null,
    argumentNote:
      "Not directly constructible against a remote RPC: the constructor calls asset() on a CVA"
      + " adapter that is not deployed on Monad, and inventing one would fabricate state. The vault"
      + " is created by the factory, which is covered separately.",
  },
]);

function loadArtifact(root: string, ref: ArtifactRef): LoadedArtifact {
  const path = join(root, "contracts", "out", ref.file, `${ref.name}.json`);
  if (!existsSync(path)) {
    throw new Error(`Missing artifact for ${ref.name}. Run \`pnpm build:contracts\` first.`);
  }
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const compiler = parsed.metadata?.compiler?.version
    ?? parsed.rawMetadata?.match(/"version":"([^"]+)"/)?.[1]
    ?? "unknown";
  return {
    key: ref.key,
    name: ref.name,
    abi: parsed.abi as Abi,
    bytecode: parsed.bytecode.object as Hex,
    deployedBytecode: parsed.deployedBytecode.object as Hex,
    compiler,
  };
}

function repositoryCommit(): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "UNVERSIONED";
  }
}

function table(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  if (rows.length === 0) {
    return "_No entry._\n";
  }
  const escape = (cell: string) => cell.replace(/\|/g, "\\|").replace(/\n/g, " ");
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(escape).join(" | ")} |`),
  ].join("\n") + "\n";
}

function render(report: Record<string, unknown>, results: readonly ContractPreflight[]): string {
  const network = report.network as Record<string, string | number>;
  const statuses = report.statuses as Record<string, string>;

  return [
    "# Monad deployment preflight",
    "",
    "Read-only. No private key was used, nothing was signed and no transaction was broadcast.",
    "A passing gas estimate means the RPC would accept the creation payload; it is not a deployment.",
    "",
    table(["Field", "Value"], [
      ["generatedAt", String(report.generatedAt)],
      ["repositoryCommit", String(report.repositoryCommit)],
      ["compiler", String(report.compiler)],
      ["rpcEndpoint", String(network.rpcEndpoint)],
      ["chainId", String(network.chainId)],
      ["blockNumber", String(network.blockNumber)],
      ["blockHash", String(network.blockHash)],
    ]),
    "## Status",
    "",
    table(["Statement", "Value"], Object.entries(statuses).map(([k, v]) => [k, v])),
    "## Sizes and estimates",
    "",
    table(
      ["Contract", "Init code B", "Runtime B", "Monad limit", "EIP-170", "Estimated gas", "Status"],
      results.map((entry) => [
        entry.contract,
        String(entry.initCodeBytes),
        String(entry.runtimeBytes),
        entry.withinMonadLimit ? "within" : "EXCEEDS",
        entry.withinEip170 ? "within" : "EXCEEDS",
        entry.estimatedGas ?? "n/a",
        entry.status,
      ]),
    ),
    `Monad documented limits: ${MONAD_RUNTIME_LIMIT} bytes of runtime code and`,
    `${MONAD_INIT_CODE_LIMIT} bytes of init code. Ethereum EIP-170: ${EIP170_RUNTIME_LIMIT} bytes.`,
    "",
    "## Probes",
    "",
    table(
      ["Contract", "Method", "Result", "Classification"],
      results.flatMap((entry) => entry.probes.map((probe) => [
        entry.contract, probe.method, probe.result, probe.classification,
      ])),
    ),
    "## Constructor arguments",
    "",
    table(
      ["Contract", "Arguments", "Why"],
      results.map((entry) => [entry.contract, entry.constructorArguments, entry.argumentNote]),
    ),
  ].join("\n");
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2).filter((value) => value !== "--");
  const outIndex = argv.indexOf("--out");
  const outputPrefix = outIndex === -1 ? null : argv[outIndex + 1] ?? null;
  const forkIndex = argv.indexOf("--fork-evidence");
  const forkEvidencePath = forkIndex === -1 ? null : argv[forkIndex + 1] ?? null;
  const urlIndex = argv.indexOf("--rpc-url");
  const rpcUrl = (urlIndex === -1 ? undefined : argv[urlIndex + 1])
    ?? process.env.MONAD_RPC_URL
    ?? process.env.NEXT_PUBLIC_MONAD_RPC_URL
    ?? "https://testnet-rpc.monad.xyz";

  const root = process.cwd();
  const client = createPreflightTransport(rpcUrl);

  const chainId = await assertMonadTestnet(client);
  const block = await pinBlock(client);

  const loaded = ARTIFACTS.map((ref) => ({ ref, artifact: loadArtifact(root, ref) }));
  const results: ContractPreflight[] = [];
  for (const { ref, artifact } of loaded) {
    results.push(await preflightContract(
      client, artifact, ref.args, ref.argumentNote, SIMULATION_CALLER, block.tag,
    ));
  }

  const constructible = results.filter((entry) => entry.estimatedGas !== null
    || entry.status !== "NOT DIRECTLY CONSTRUCTIBLE");
  const preflightStatus = constructible.every((entry) => entry.status === "PASSED")
    ? "PASSED"
    : constructible.some((entry) => entry.status === "FAILED") ? "FAILED" : "RPC METHOD UNSUPPORTED";
  const withinLimits = results.every((entry) => entry.withinMonadLimit);

  // A fork artifact can raise factory-to-vault creation from NOT PROVEN to FORK. It is read here
  // rather than assumed, and FORK is never reported as a read-only RPC observation.
  let vaultCreationStatus = "NOT PROVEN ON REMOTE RPC";
  if (forkEvidencePath !== null && existsSync(forkEvidencePath)) {
    const forkReport = JSON.parse(readFileSync(forkEvidencePath, "utf8"));
    if (forkReport?.status?.["MONAD FACTORY → VAULT CREATION"] === "FORK") {
      vaultCreationStatus = "FORK";
    }
  }

  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    repositoryCommit: repositoryCommit(),
    compiler: loaded[0]?.artifact.compiler ?? "unknown",
    network: {
      rpcEndpoint: describeRpcEndpoint(rpcUrl),
      chainId,
      blockNumber: block.number.toString(),
      blockHash: block.hash,
    },
    statuses: {
      "MONAD SIZE LIMIT": withinLimits
        ? "WITHIN DOCUMENTED LIMIT" : "EXCEEDS DOCUMENTED LIMIT",
      "MONAD RPC PREFLIGHT": preflightStatus,
      "MONAD FACTORY CREATION": results.find((entry) => entry.contract === "MordantFactory")
        ?.status === "PASSED" ? "READ-ONLY RPC SIMULATION" : "NOT PROVEN",
      "MONAD FACTORY → VAULT CREATION": vaultCreationStatus,
      "MONAD DEPLOYMENT": "NOT PROVEN — NO TRANSACTION BROADCAST",
      "STANDARD EVM PORTABILITY": results.every((entry) => entry.withinEip170)
        ? "WITHIN EIP-170" : "BLOCKED BY EIP-170",
    },
    contracts: results,
  };

  const json = redactSecrets(`${JSON.stringify(report, null, 2)}\n`);
  const markdown = redactSecrets(render(report, results));
  assertNoSecretLeak(json);
  assertNoSecretLeak(markdown);

  if (outputPrefix !== null) {
    mkdirSync(dirname(outputPrefix), { recursive: true });
    writeFileSync(`${outputPrefix}.json`, json, "utf8");
    writeFileSync(`${outputPrefix}.md`, markdown, "utf8");
    process.stdout.write(`Wrote ${outputPrefix}.json and ${outputPrefix}.md\n`);
  }

  process.stdout.write([
    "",
    `Endpoint       ${report.network.rpcEndpoint}`,
    `Chain          ${chainId}`,
    `Pinned block   ${block.number} ${block.hash}`,
    ...Object.entries(report.statuses).map(([key, value]) => `${key.padEnd(30)} ${value}`),
    "",
  ].join("\n"));

  for (const entry of results) {
    process.stdout.write(
      `  ${entry.contract.padEnd(24)} init ${String(entry.initCodeBytes).padStart(6)} B`
      + `  runtime ${String(entry.runtimeBytes).padStart(6)} B`
      + `  gas ${(entry.estimatedGas ?? "n/a").padStart(9)}  ${entry.status}\n`,
    );
  }

  return preflightStatus === "FAILED" ? 1 : 0;
}

main().then(
  (code) => { process.exitCode = code; },
  (error: unknown) => {
    if (error instanceof WrongNetworkError) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 3;
      return;
    }
    process.stderr.write(
      `Preflight failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  },
);
