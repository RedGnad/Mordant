import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = join(here, "benchmark-summary.schema.json");
const artifactPath = join(here, "..", "..", "lattigo", "benchmark", "arm64-2026-07-31.json");

function fail(path, message) {
  throw new Error(`${path}: ${message}`);
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function dereference(root, reference) {
  if (!reference.startsWith("#/")) fail("schema", `external reference is not supported: ${reference}`);
  return reference.slice(2).split("/").reduce((value, token) => {
    const key = token.replaceAll("~1", "/").replaceAll("~0", "~");
    if (value === null || typeof value !== "object" || !(key in value)) {
      fail("schema", `unresolved reference: ${reference}`);
    }
    return value[key];
  }, root);
}

// This intentionally small validator implements every JSON Schema keyword used
// by benchmark-summary.schema.json. Keeping it local avoids adding a runtime
// dependency solely to validate a checked-in research artifact.
function validate(value, schema, root, path = "$") {
  if (schema === false) fail(path, "value is forbidden by schema");
  if (schema === true) return;
  if (schema.$ref) {
    validate(value, dereference(root, schema.$ref), root, path);
    return;
  }
  if ("const" in schema && !same(value, schema.const)) fail(path, `expected constant ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.some((candidate) => same(value, candidate))) fail(path, "value is not in enum");

  if (schema.type) {
    const validType = {
      object: value !== null && typeof value === "object" && !Array.isArray(value),
      array: Array.isArray(value),
      string: typeof value === "string",
      number: typeof value === "number" && Number.isFinite(value),
      integer: Number.isInteger(value),
      boolean: typeof value === "boolean",
      null: value === null,
    }[schema.type];
    if (!validType) fail(path, `expected ${schema.type}`);
  }

  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) {
    fail(path, `must be >= ${schema.minimum}`);
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) fail(path, "string is too short");
    if (schema.pattern !== undefined && !(new RegExp(schema.pattern)).test(value)) fail(path, "string does not match pattern");
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) fail(path, "array is too short");
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail(path, "array is too long");
    const prefix = schema.prefixItems ?? [];
    prefix.forEach((itemSchema, index) => {
      if (index < value.length) validate(value[index], itemSchema, root, `${path}[${index}]`);
    });
    if (schema.items !== undefined) {
      for (let index = prefix.length; index < value.length; index += 1) {
        validate(value[index], schema.items, root, `${path}[${index}]`);
      }
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const required of schema.required ?? []) {
      if (!(required in value)) fail(path, `missing required property ${required}`);
    }
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (key in value) validate(value[key], child, root, `${path}.${key}`);
    }
    if (schema.additionalProperties === false) {
      const known = new Set(Object.keys(schema.properties ?? {}));
      for (const key of Object.keys(value)) {
        if (!known.has(key)) fail(`${path}.${key}`, "additional property is forbidden");
      }
    }
  }
}

function validateAggregateInvariants(summary) {
  if (summary.method.measuredRunsPerMode === 5 && summary.method.p95 !== "nearest-rank; maximum at n=5") {
    fail("$.method.p95", "does not describe the recorded five-run p95 method");
  }
  for (const [modeIndex, mode] of summary.modes.entries()) {
    for (const [metric, measurement] of Object.entries(mode.latencyMilliseconds)) {
      if (measurement && typeof measurement === "object" && "median" in measurement) {
        if (measurement.p95 < measurement.median) {
          fail(`$.modes[${modeIndex}].latencyMilliseconds.${metric}.p95`, "must be >= median");
        }
      }
    }
    const expectedEnvelopeBytes = mode.sizesBytes.pledgeA
      + mode.sizesBytes.pledgeB
      + mode.sizesBytes.decisionCiphertext;
    if (mode.sizesBytes.fheEnvelopes !== expectedEnvelopeBytes) {
      fail(`$.modes[${modeIndex}].sizesBytes.fheEnvelopes`, "does not equal two pledges plus decision ciphertext");
    }
    if (mode.goHeapBytes.peak < mode.goHeapBytes.before || mode.goHeapBytes.peak < mode.goHeapBytes.after) {
      fail(`$.modes[${modeIndex}].goHeapBytes.peak`, "must cover before and after samples");
    }
  }
}

export async function validateBenchmarkSummary() {
  const [schema, summary] = await Promise.all([
    readFile(schemaPath, "utf8").then(JSON.parse),
    readFile(artifactPath, "utf8").then(JSON.parse),
  ]);
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    fail("schema.$schema", "expected JSON Schema draft 2020-12");
  }
  validate(summary, schema, schema);
  validateAggregateInvariants(summary);
  return {
    artifact: artifactPath,
    modes: summary.modes.length,
    measuredRunsPerMode: summary.method.measuredRunsPerMode,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await validateBenchmarkSummary();
  process.stdout.write(
    `Lattigo benchmark summary OK: ${result.modes} modes; ${result.measuredRunsPerMode} measured runs per mode.\n`,
  );
}
