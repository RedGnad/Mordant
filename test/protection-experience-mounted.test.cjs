/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const { existsSync, readFileSync } = require("node:fs");
const { join } = require("node:path");
const { test } = require("node:test");
const Module = require("node:module");
const React = require("react");
const { act, create } = require("react-test-renderer");

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
require.extensions[".css"] = (module) => {
  module.exports = new Proxy({}, { get: (_target, property) => String(property) });
};
const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function resolveProductAlias(request, parent, isMain, options) {
  if (request === "next/link") {
    return join(process.cwd(), "test", "stubs", "next", "link.js");
  }
  if (request === "./protection-experience.module.css") {
    return join(process.cwd(), "src", "components", "protection-experience.module.css");
  }
  if (request.startsWith("@/")) {
    return resolveFilename.call(this, join(process.cwd(), ".product-test-dist", "src", request.slice(2)), parent, isMain, options);
  }
  return resolveFilename.call(this, request, parent, isMain, options);
};

const { ProtectionExperience } = require("../.product-test-dist/src/components/protection-experience.js");
const evidencePath = (scenario = "conflict") => join(
  process.cwd(), "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`,
);
const artifactTest = existsSync(evidencePath("conflict")) ? test : test.skip;

function evidence(scenario = "conflict") {
  return JSON.parse(readFileSync(evidencePath(scenario), "utf8"));
}

function text(node) {
  if (typeof node === "string") return node;
  if (node === null || node === undefined) return "";
  if (Array.isArray(node)) return node.map(text).join(" ");
  return text(node.children);
}

function button(root, label) {
  return root.findAllByType("button").find((candidate) => text(candidate).includes(label));
}

function response(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

artifactTest("mounted imported to local loading to local error never renders imported case data", async () => {
  const imported = evidence();
  let rejectRequest;
  global.fetch = () => new Promise((_resolve, reject) => { rejectRequest = reject; });
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, { initialEvidence: imported, localExecutionAvailable: true })); });
  await act(async () => {
    button(renderer.root, "Run this case locally").props.onClick();
    await Promise.resolve();
  });
  const loading = renderer.root.findByProps({ "data-testid": "local-case-status" });
  assert.match(text(loading), /imported case data is withheld/i);
  assert.doesNotMatch(text(renderer.root), new RegExp(imported.protectionCase.fheCaseId.slice(-16)));
  await act(async () => {
    rejectRequest(new Error("LOCAL_CREATE_REJECTED"));
    await Promise.resolve();
  });
  assert.match(text(renderer.root.findByProps({ "data-testid": "local-case-status" })), /LOCAL_CREATE_REJECTED/);
  await act(async () => { renderer.unmount(); });
});

artifactTest("mounted imported to local incomplete to cure window to complete keeps exact local evidence", async () => {
  const imported = evidence();
  const runId = "11111111-1111-4111-8111-111111111111";
  const incompleteCase = { ...imported.protectionCase, recourseState: "NOT_OPEN", cureDeadline: null };
  const cureCase = { ...incompleteCase, recourseState: "CURE_WINDOW", cureDeadline: "2026-08-04T00:00:00.000Z" };
  const completeCase = { ...cureCase, recourseState: "AVAILABLE" };
  const localEvidence = { ...imported, runId, protectionCase: completeCase };
  const queue = [
    {
      runId, stage: "CASE_CREATED", nextOperation: "preparePrivateMatch", protectionCase: incompleteCase,
      governedResult: null, recourse: null, evidence: null,
    },
    {
      runId, stage: "RECOURSE_OPENED", nextOperation: "completeCureChronology", protectionCase: cureCase,
      governedResult: { conflict: true, digest: imported.governedResult.digest, releaseMode: "governed-decryptor-v1" },
      recourse: { opened: true }, evidence: null,
    },
    {
      runId, stage: "COMPLETE", nextOperation: null, protectionCase: completeCase,
      governedResult: { conflict: true, digest: imported.governedResult.digest, releaseMode: "governed-decryptor-v1" },
      recourse: { opened: true }, evidence: localEvidence,
    },
  ];
  global.fetch = async () => response(queue.shift());
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, { initialEvidence: imported, localExecutionAvailable: true })); });
  await act(async () => { button(renderer.root, "Run this case locally").props.onClick(); });
  assert.equal(button(renderer.root, "Evidence").props.disabled, true);
  await act(async () => { button(renderer.root, "Prepare private match").props.onClick(); });
  assert.match(text(renderer.root), /Recourse not opened/);
  assert.equal(button(renderer.root, "Evidence").props.disabled, true);
  await act(async () => { button(renderer.root, "Simulate cure-window completion").props.onClick(); });
  assert.match(text(renderer.root), /Simulated protocol clock/);
  assert.equal(button(renderer.root, "Evidence").props.disabled, false);
  assert.equal(renderer.root.findByProps({ "data-execution": "local" }).props["data-execution"], "local");
  await act(async () => { renderer.unmount(); });
});

artifactTest("mounted chronology ignores forged text and suppresses contradictory duplicate kinds", async () => {
  const imported = evidence();
  const malicious = structuredClone(imported);
  malicious.chronology.events[0].label = "Cleanverse confirmed the conflict on-chain";
  malicious.chronology.events.push({
    ...malicious.chronology.events[0],
    ordinal: 99,
    label: "Cleanverse confirmed the conflict on-chain",
  });
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, { initialEvidence: malicious, localExecutionAvailable: false })); });
  const rendered = text(renderer.root);
  assert.doesNotMatch(rendered, /Cleanverse confirmed the conflict on-chain/);
  assert.equal((rendered.match(/Protected holder snapshot fixed/g) ?? []).length, 1);
  await act(async () => { renderer.unmount(); });
});
