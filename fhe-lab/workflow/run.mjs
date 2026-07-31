#!/usr/bin/env node

import { createReadStream } from "node:fs";
import { resolve } from "node:path";

import {
  WORKFLOW_METRICS_SCHEMA_VERSION,
  WorkflowError,
  readPublicJson,
  runWorkflow,
} from "./workflow.mjs";

function usage() {
  return [
    "Usage: node fhe-lab/workflow/run.mjs (--fixture | --input PUBLIC.json | --stdin)",
    "",
    "--fixture explicitly uses the shared canonical public test vector.",
    "Provider input must be a strict successful public-output envelope.",
    "A piped stdin stream is read automatically.",
  ].join("\n");
}

function parseArgs(argv) {
  let inputPath;
  let forceStdin = false;
  let fixture = false;
  for (let index = 0; index < argv.length; ++index) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") return { help: true };
    if (argument === "--fixture") {
      if (fixture || forceStdin || inputPath !== undefined) {
        throw new WorkflowError("CLI_INPUT_CONFLICT");
      }
      fixture = true;
      continue;
    }
    if (argument === "--stdin") {
      if (fixture || forceStdin || inputPath !== undefined) {
        throw new WorkflowError("CLI_INPUT_CONFLICT");
      }
      forceStdin = true;
      continue;
    }
    if (argument === "--input") {
      if (fixture || forceStdin || inputPath !== undefined || index + 1 >= argv.length) {
        throw new WorkflowError("CLI_INPUT_CONFLICT");
      }
      inputPath = argv[++index];
      if (inputPath === "-") {
        inputPath = undefined;
        forceStdin = true;
      }
      continue;
    }
    throw new WorkflowError("CLI_ARGUMENT");
  }
  return { help: false, fixture, forceStdin, inputPath };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  let input;
  if (options.fixture) {
    // The fixture is loaded inside runWorkflow so no provider input can be mixed with it.
  } else if (options.forceStdin || (options.inputPath === undefined && !process.stdin.isTTY)) {
    input = await readPublicJson(process.stdin);
  } else if (options.inputPath !== undefined) {
    input = await readPublicJson(createReadStream(resolve(options.inputPath)));
  } else {
    throw new WorkflowError("CLI_INPUT_REQUIRED");
  }

  const output = await runWorkflow({ input, fixture: options.fixture });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

main().catch((error) => {
  const errorCode = error instanceof WorkflowError ? error.code : "WORKFLOW_FAILED";
  process.stdout.write(`${JSON.stringify({
    schemaVersion: WORKFLOW_METRICS_SCHEMA_VERSION,
    ok: false,
    errorCode,
  })}\n`);
  process.exitCode = 1;
});
