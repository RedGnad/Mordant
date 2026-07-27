import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import {
  DEFAULT_CLEANVERSE_MONAD_TARGETS,
  type CleanverseMonadTargets,
  type DocumentationAvailability,
} from "./cleanverse-monad";
import { createFixtureTransport } from "./fixtures";
import { WrongNetworkError } from "./observe";
import { DOC_DEPLOYMENT_SKEW, renderEvidenceArtifacts } from "./report";
import { createHttpRpcTransport } from "./rpc";
import { runCleanverseMonadEvidence, type EvidenceRunMode } from "./run";

const PROTECTED_DOCS_URL = "https://docs.cleanverse.com/docs/cleanverse";
const CHAIN_CONFIG_URL = "https://uatapi.cleanverse.com/api/skills/query_chain_config";

type CliOptions = Readonly<{
  mode: EvidenceRunMode;
  rpcUrl: string | null;
  outputPrefix: string | null;
  vaultAddress: string | null;
  /** ISO date asserting that an operator read the access-gated documentation. */
  docsConsultedAt: string | null;
}>;

function parseArguments(argv: readonly string[]): CliOptions {
  let mode: EvidenceRunMode = "fixture";
  let rpcUrl: string | null = null;
  let outputPrefix: string | null = null;
  let vaultAddress: string | null = null;
  let docsConsultedAt: string | null = null;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      // pnpm forwards its own separator; ignore it rather than failing the run.
      case "--":
        break;
      case "--live":
        mode = "live-read-only";
        break;
      case "--rpc-url":
        index += 1;
        rpcUrl = argv[index] ?? null;
        break;
      case "--out":
        index += 1;
        outputPrefix = argv[index] ?? null;
        break;
      case "--vault":
        index += 1;
        vaultAddress = argv[index] ?? null;
        break;
      // Asserts a human/agent consultation of the access-gated page. The access code is never
      // read, sent or stored by this process; only the date of the consultation is recorded.
      case "--docs-consulted":
        index += 1;
        docsConsultedAt = argv[index] ?? null;
        break;
      default:
        throw new Error(`Unknown argument: ${argument}`);
    }
  }

  return Object.freeze({ mode, rpcUrl, outputPrefix, vaultAddress, docsConsultedAt });
}

function resolveRepositoryCommit(): string {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "UNVERSIONED (no git repository at run time)";
  }
}

/**
 * Records whether each documentation source could be read. The protected pages are only probed
 * for reachability; no access code is read, sent or stored by this run.
 */
async function probeDocumentation(
  mode: EvidenceRunMode,
  docsConsultedAt: string | null,
): Promise<DocumentationAvailability> {
  const consultedAt = new Date().toISOString();

  if (mode === "fixture") {
    return Object.freeze({
      protectedDocsReachable: false,
      protectedDocsHttpStatus: null,
      chainConfigReachable: false,
      consultedAt,
      protectedDocsConsultedAt: docsConsultedAt,
    });
  }

  let protectedDocsHttpStatus: number | null = null;
  try {
    const response = await fetch(PROTECTED_DOCS_URL, {
      redirect: "follow",
      signal: AbortSignal.timeout(20_000),
    });
    protectedDocsHttpStatus = response.status;
  } catch {
    protectedDocsHttpStatus = null;
  }

  let chainConfigReachable = false;
  try {
    const response = await fetch(CHAIN_CONFIG_URL, { signal: AbortSignal.timeout(20_000) });
    const payload: unknown = await response.json();
    chainConfigReachable = response.ok
      && typeof payload === "object" && payload !== null
      && "code" in payload && String((payload as { code: unknown }).code) === "0000";
  } catch {
    chainConfigReachable = false;
  }

  return Object.freeze({
    protectedDocsReachable: protectedDocsHttpStatus !== null && protectedDocsHttpStatus < 400,
    protectedDocsHttpStatus,
    chainConfigReachable,
    consultedAt,
    protectedDocsConsultedAt: docsConsultedAt,
  });
}

async function main(): Promise<number> {
  const options = parseArguments(process.argv.slice(2));

  const rpcUrl = options.rpcUrl
    ?? process.env.MONAD_RPC_URL
    ?? process.env.NEXT_PUBLIC_MONAD_RPC_URL
    ?? null;

  if (options.mode === "live-read-only" && rpcUrl === null) {
    process.stderr.write(
      "A live read-only run needs --rpc-url or MONAD_RPC_URL.\n",
    );
    return 2;
  }

  const targets: CleanverseMonadTargets = Object.freeze({
    ...DEFAULT_CLEANVERSE_MONAD_TARGETS,
    mordantVault: options.vaultAddress
      ?? process.env.NEXT_PUBLIC_MORDANT_VAULT_ADDRESS
      ?? null,
  });

  const transport = options.mode === "live-read-only"
    ? createHttpRpcTransport({ url: rpcUrl as string })
    : createFixtureTransport();

  const report = await runCleanverseMonadEvidence({
    transport,
    mode: options.mode,
    generatedAt: new Date().toISOString(),
    repositoryCommit: resolveRepositoryCommit(),
    documentation: await probeDocumentation(options.mode, options.docsConsultedAt),
    targets,
  });

  // Secret values are never read into this process; the scan is a fail-closed backstop.
  const artifacts = renderEvidenceArtifacts(report);

  if (options.outputPrefix !== null) {
    mkdirSync(dirname(options.outputPrefix), { recursive: true });
    writeFileSync(`${options.outputPrefix}.json`, artifacts.json, "utf8");
    writeFileSync(`${options.outputPrefix}.md`, artifacts.markdown, "utf8");
    process.stdout.write(
      `Wrote ${options.outputPrefix}.json and ${options.outputPrefix}.md\n`,
    );
  }

  const skew = report.comparisons.filter(
    (comparison) => comparison.comparisonStatus === DOC_DEPLOYMENT_SKEW,
  );
  const blocked = report.comparisons.filter(
    (comparison) => comparison.comparisonStatus === "BLOCKED",
  );

  process.stdout.write([
    ``,
    `Mode           ${report.mode}${options.mode === "fixture" ? "  (recorded chain, NOT a live observation)" : ""}`,
    `Network        ${report.network.name} (chain ${report.network.chainId})`,
    `Pinned block   ${report.network.blockNumber} ${report.network.blockHash}`,
    `Observations   ${report.onchainObservations.length} (all READ-ONLY)`,
    `Comparisons    ${report.comparisons.length}`
      + ` | MATCH ${report.comparisons.filter((c) => c.comparisonStatus === "MATCH").length}`
      + ` | NOT PROVEN ${report.comparisons.filter((c) => c.comparisonStatus === "NOT PROVEN").length}`
      + ` | BLOCKED ${blocked.length}`
      + ` | SKEW ${skew.length}`,
    `Documentation  ${options.docsConsultedAt === null ? "access-gated page NOT read" : `v5.6 recorded, consulted ${options.docsConsultedAt}`}`,
    `Missing        ${report.missingEvidence.length} item(s) of evidence`,
    ``,
  ].join("\n"));

  for (const comparison of skew) {
    process.stdout.write(`${DOC_DEPLOYMENT_SKEW}: ${comparison.topic}\n`);
  }

  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    if (error instanceof WrongNetworkError) {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 3;
      return;
    }
    process.stderr.write(
      `Evidence run failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  },
);
