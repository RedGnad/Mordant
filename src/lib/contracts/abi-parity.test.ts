import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";

import {
  REQUIRED_ACCOUNTING_FUNCTIONS,
  compareReadAbiToCompiledAbi,
  describeAbiParityIssues,
  type AbiFunctionLike,
} from "./abi-parity";
import { mordantInvoiceVaultReadAbi } from "./mordant-invoice-vault-abi";

const ARTIFACT_RELATIVE_PATH = join(
  "contracts",
  "out",
  "MordantInvoiceVault.sol",
  "MordantInvoiceVault.json",
);

/** Walks up from the compiled test toward the repository root so the run stays cwd-independent. */
function locateCompiledArtifact(): string {
  let directory = __dirname;
  for (let depth = 0; depth < 12; depth += 1) {
    const candidate = resolve(directory, ARTIFACT_RELATIVE_PATH);
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = dirname(directory);
    if (parent === directory) {
      break;
    }
    directory = parent;
  }
  throw new Error(
    `Compiled MordantInvoiceVault artifact not found. Run "pnpm build:contracts" first.`,
  );
}

function loadCompiledAbi(): readonly AbiFunctionLike[] {
  const artifact: unknown = JSON.parse(readFileSync(locateCompiledArtifact(), "utf8"));
  if (
    typeof artifact !== "object" || artifact === null || !("abi" in artifact)
    || !Array.isArray((artifact as { abi: unknown }).abi)
  ) {
    throw new Error("Compiled artifact does not expose an ABI array");
  }
  return (artifact as { abi: readonly AbiFunctionLike[] }).abi;
}

const readAbi = mordantInvoiceVaultReadAbi as readonly AbiFunctionLike[];

test("TypeScript read ABI matches the compiled MordantInvoiceVault ABI", () => {
  const issues = compareReadAbiToCompiledAbi(readAbi, loadCompiledAbi());
  assert.equal(
    issues.length,
    0,
    `Read ABI drifted from the compiled contract:\n${describeAbiParityIssues(issues)}`,
  );
});

test("read ABI exposes no state-changing function", () => {
  for (const entry of readAbi) {
    assert.ok(
      entry.stateMutability === "view" || entry.stateMutability === "pure",
      `${entry.name ?? "<anonymous>"} is not read-only`,
    );
  }
});

test("parity check detects a function removed from the contract", () => {
  const compiled = loadCompiledAbi().filter((entry) => entry.name !== "cvaReleasedFace");
  const issues = compareReadAbiToCompiledAbi(readAbi, compiled);
  assert.ok(issues.some((issue) => issue.kind === "missing-function"
    && issue.functionName === "cvaReleasedFace"));
  assert.ok(issues.some((issue) => issue.kind === "missing-required-function"
    && issue.functionName === "cvaReleasedFace"));
});

test("parity check detects an incompatible return type", () => {
  const compiled = loadCompiledAbi().map((entry) => entry.name === "redeemedFace"
    ? { ...entry, outputs: [{ name: "", type: "uint128" }] }
    : entry);
  const issues = compareReadAbiToCompiledAbi(readAbi, compiled);
  const issue = issues.find((candidate) => candidate.kind === "output-mismatch");
  assert.equal(issue?.functionName, "redeemedFace");
  assert.equal(issue?.expected, "(uint256)");
  assert.equal(issue?.actual, "(uint128)");
});

test("parity check detects an incompatible mutability", () => {
  const compiled = loadCompiledAbi().map((entry) => entry.name === "assertAccounting"
    ? { ...entry, stateMutability: "nonpayable" }
    : entry);
  const issues = compareReadAbiToCompiledAbi(readAbi, compiled);
  assert.ok(issues.some((issue) => issue.kind === "mutability-mismatch"
    && issue.functionName === "assertAccounting"
    && issue.actual === "nonpayable"));
});

test("parity check detects a stale function name kept by the reader", () => {
  const staleReadAbi: readonly AbiFunctionLike[] = [
    ...readAbi,
    {
      type: "function",
      name: "remainingFace",
      inputs: [],
      outputs: [{ name: "", type: "uint256" }],
      stateMutability: "view",
    },
  ];
  const issues = compareReadAbiToCompiledAbi(staleReadAbi, loadCompiledAbi());
  assert.ok(issues.some((issue) => issue.kind === "missing-function"
    && issue.functionName === "remainingFace"));
});

test("parity check detects an argument-signature drift", () => {
  const driftedReadAbi: readonly AbiFunctionLike[] = readAbi.map((entry) =>
    entry.name === "balanceAt" || entry.name !== "totalSupply"
      ? entry
      : { ...entry, inputs: [{ name: "atSequence", type: "uint48" }] },
  );
  const issues = compareReadAbiToCompiledAbi(driftedReadAbi, loadCompiledAbi());
  assert.ok(issues.some((issue) => issue.kind === "input-mismatch"
    && issue.functionName === "totalSupply"));
});

test("parity check rejects a state-changing function smuggled into the read surface", () => {
  const writeReadAbi: readonly AbiFunctionLike[] = [
    ...readAbi,
    {
      type: "function",
      name: "claimBond",
      inputs: [],
      outputs: [{ name: "amount", type: "uint256" }],
      stateMutability: "nonpayable",
    },
  ];
  const issues = compareReadAbiToCompiledAbi(writeReadAbi, loadCompiledAbi());
  assert.ok(issues.some((issue) => issue.kind === "not-read-only"
    && issue.functionName === "claimBond"));
});

test("every accounting-critical function is required by name", () => {
  for (const required of ["cvaReleasedFace", "settlementCreditTotal", "redeemedFace", "faceValue"]) {
    assert.ok(REQUIRED_ACCOUNTING_FUNCTIONS.includes(required), `${required} must be required`);
  }
});
