/**
 * Parity between the read-only ABI the TypeScript layer calls and the ABI Foundry actually
 * compiled. A reader that drifts from the deployed contract reports stale accounting silently,
 * so this comparison is a build gate rather than a manual review step.
 */

export type AbiParameterLike = Readonly<{
  name?: string;
  type: string;
}>;

export type AbiFunctionLike = Readonly<{
  type: string;
  name?: string;
  inputs?: readonly AbiParameterLike[];
  outputs?: readonly AbiParameterLike[];
  stateMutability?: string;
}>;

export type AbiParityIssueKind =
  | "missing-function"
  | "input-mismatch"
  | "output-mismatch"
  | "mutability-mismatch"
  | "not-read-only"
  | "missing-required-function";

export type AbiParityIssue = Readonly<{
  kind: AbiParityIssueKind;
  functionName: string;
  expected: string;
  actual: string;
}>;

const READ_ONLY_MUTABILITIES = new Set(["view", "pure"]);

/**
 * Every function the accounting model depends on. Losing one of these does not break a type
 * check, it silently removes a term from a money calculation.
 */
export const REQUIRED_ACCOUNTING_FUNCTIONS: readonly string[] = Object.freeze([
  "faceValue",
  "redeemedFace",
  "cvaReleasedFace",
  "redemptionEscrow",
  "settlementCreditTotal",
  "accountedSettlementBalance",
  "initialBond",
  "bondLocked",
  "bondReturned",
  "entitlementAllocated",
  "entitlementClaimed",
  "totalSupply",
  "cvaAccounted",
  "assertAccounting",
]);

function typeList(parameters: readonly AbiParameterLike[] | undefined): string {
  return (parameters ?? []).map((parameter) => parameter.type).join(",");
}

export function formatAbiFunction(entry: AbiFunctionLike): string {
  return `${entry.name ?? "<anonymous>"}(${typeList(entry.inputs)})`
    + ` ${entry.stateMutability ?? "<unset>"}`
    + ` -> (${typeList(entry.outputs)})`;
}

function isFunction(entry: AbiFunctionLike): boolean {
  return entry.type === "function" && typeof entry.name === "string";
}

/**
 * @param readAbi the ABI shipped in the TypeScript layer
 * @param compiledAbi the ABI emitted by `forge build`
 * @param requiredFunctions names that must survive in both ABIs
 */
export function compareReadAbiToCompiledAbi(
  readAbi: readonly AbiFunctionLike[],
  compiledAbi: readonly AbiFunctionLike[],
  requiredFunctions: readonly string[] = REQUIRED_ACCOUNTING_FUNCTIONS,
): readonly AbiParityIssue[] {
  const issues: AbiParityIssue[] = [];
  const compiledFunctions = compiledAbi.filter(isFunction);

  for (const entry of readAbi) {
    if (!isFunction(entry)) {
      continue;
    }
    const name = entry.name as string;

    if (!READ_ONLY_MUTABILITIES.has(entry.stateMutability ?? "")) {
      issues.push({
        kind: "not-read-only",
        functionName: name,
        expected: "view or pure",
        actual: entry.stateMutability ?? "<unset>",
      });
    }

    const sameName = compiledFunctions.filter((candidate) => candidate.name === name);
    if (sameName.length === 0) {
      issues.push({
        kind: "missing-function",
        functionName: name,
        expected: formatAbiFunction(entry),
        actual: "absent from the compiled ABI",
      });
      continue;
    }

    // Overloads are matched on the input signature; the reader must name a real overload.
    const overload = sameName.find(
      (candidate) => typeList(candidate.inputs) === typeList(entry.inputs),
    );
    if (overload === undefined) {
      issues.push({
        kind: "input-mismatch",
        functionName: name,
        expected: `(${typeList(entry.inputs)})`,
        actual: sameName.map((candidate) => `(${typeList(candidate.inputs)})`).join(" | "),
      });
      continue;
    }

    if (typeList(overload.outputs) !== typeList(entry.outputs)) {
      issues.push({
        kind: "output-mismatch",
        functionName: name,
        expected: `(${typeList(entry.outputs)})`,
        actual: `(${typeList(overload.outputs)})`,
      });
    }

    if ((overload.stateMutability ?? "") !== (entry.stateMutability ?? "")) {
      issues.push({
        kind: "mutability-mismatch",
        functionName: name,
        expected: entry.stateMutability ?? "<unset>",
        actual: overload.stateMutability ?? "<unset>",
      });
    }
  }

  const readNames = new Set(
    readAbi.filter(isFunction).map((entry) => entry.name as string),
  );
  const compiledNames = new Set(compiledFunctions.map((entry) => entry.name as string));
  for (const required of requiredFunctions) {
    const missingFrom = [
      readNames.has(required) ? null : "the TypeScript read ABI",
      compiledNames.has(required) ? null : "the compiled ABI",
    ].filter((value): value is string => value !== null);

    if (missingFrom.length !== 0) {
      issues.push({
        kind: "missing-required-function",
        functionName: required,
        expected: "present in both ABIs",
        actual: `absent from ${missingFrom.join(" and ")}`,
      });
    }
  }

  return Object.freeze(issues);
}

export function describeAbiParityIssues(issues: readonly AbiParityIssue[]): string {
  return issues
    .map((issue) => `- [${issue.kind}] ${issue.functionName}: expected ${issue.expected}, found ${issue.actual}`)
    .join("\n");
}
