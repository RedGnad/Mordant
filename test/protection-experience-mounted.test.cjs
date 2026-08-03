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
  if (request === "next/link") return join(process.cwd(), "test", "stubs", "next", "link.js");
  if (request === "./protection-experience.module.css") return join(process.cwd(), "src", "components", "protection-experience.module.css");
  if (request.startsWith("@/")) {
    return resolveFilename.call(this, join(process.cwd(), ".product-test-dist", "src", request.slice(2)), parent, isMain, options);
  }
  return resolveFilename.call(this, request, parent, isMain, options);
};

const { ProtectionExperience } = require("../.product-test-dist/src/components/protection-experience.js");
const { verifyAndProjectPublicProtectionEvidence } = require("../.product-test-dist/src/lib/protection/protection-public-view.js");
const evidencePath = (scenario = "conflict") => join(
  process.cwd(), "docs", "evidence", "conflicting-pledge-protection", `${scenario}.json`,
);
const artifactTest = existsSync(evidencePath("conflict")) && existsSync(evidencePath("no-conflict")) ? test : test.skip;

function evidence(scenario = "conflict") {
  const retained = JSON.parse(readFileSync(evidencePath(scenario), "utf8"));
  return verifyAndProjectPublicProtectionEvidence(retained, retained.sourceCommit);
}

function props(initialEvidence, overrides = {}) {
  return {
    initialEvidence,
    initialScenario: initialEvidence?.scenario ?? "conflict",
    initialRunId: null,
    initialUrlError: null,
    localAdapterOrigin: null,
    ...overrides,
  };
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

function view(runId, stage, nextOperation, protectionCase, extra = {}) {
  return {
    schemaVersion: "mordant.protection-product-view/1",
    runId,
    stage,
    nextOperation,
    protectionCase,
    participantArtifactDigests: { participantA: null, participantB: null },
    evaluatedArtifactDigest: null,
    governedResult: null,
    recourse: null,
    evidence: null,
    execution: {
      fhe: "REAL_BGV_FHE", deployment: "LOCAL_SINGLE_HOST",
      webPresentation: "PUBLIC_EVIDENCE_READBACK", recourse: "LOCAL_PROTOCOL_DOUBLE",
    },
    ...extra,
  };
}

artifactTest("mounted imported to local loading to local error never renders imported case data", async () => {
  const imported = evidence();
  let rejectRequest;
  global.fetch = () => new Promise((_resolve, reject) => { rejectRequest = reject; });
  let renderer;
  await act(async () => {
    renderer = create(React.createElement(ProtectionExperience, props(imported, {
      localAdapterOrigin: "http://127.0.0.1:4040/protection",
    })));
  });
  await act(async () => {
    button(renderer.root, "Run this case locally").props.onClick();
    await Promise.resolve();
  });
  const loading = renderer.root.findByProps({ "data-testid": "case-loading-status" });
  assert.match(text(loading), /creating a new durable local case/i);
  assert.doesNotMatch(text(renderer.root), new RegExp(imported.protectionCase.fheCaseId.slice(-16)));
  await act(async () => {
    rejectRequest(new Error("LOCAL_CREATE_REJECTED"));
    await Promise.resolve();
  });
  assert.match(text(renderer.root.findByProps({ "data-testid": "case-loading-status" })), /LOCAL_CREATE_REJECTED/);
  await act(async () => { renderer.unmount(); });
});

artifactTest("mounted local states show admitted cure window provisionally before complete evidence", async () => {
  const imported = evidence();
  const runId = "11111111-1111-4111-8111-111111111111";
  const incompleteCase = { ...imported.protectionCase, incidentState: "AUTHORIZED", recourseState: "NOT_OPEN", cureDeadline: null };
  const cureCase = { ...incompleteCase, incidentState: "CONFLICT_CONFIRMED", recourseState: "CURE_WINDOW", cureDeadline: "2026-08-04T00:00:00.000Z" };
  const completeCase = { ...cureCase, recourseState: "AVAILABLE" };
  const localEvidence = { ...imported, runId };
  const queue = [
    view(runId, "CASE_CREATED", "preparePrivateMatch", incompleteCase),
    view(runId, "RECOURSE_OPENED", "completeCureChronology", cureCase, {
      governedResult: { conflict: true, digest: imported.governedResult.digest, releaseMode: "governed-decryptor-v1" },
      recourse: { opened: true, reason: null },
    }),
    view(runId, "COMPLETE", null, completeCase, {
      governedResult: { conflict: true, digest: imported.governedResult.digest, releaseMode: "governed-decryptor-v1" },
      recourse: { opened: true, reason: null }, evidence: localEvidence,
    }),
  ];
  global.fetch = async () => response(queue.shift());
  let renderer;
  await act(async () => {
    renderer = create(React.createElement(ProtectionExperience, props(imported, {
      localAdapterOrigin: "http://127.0.0.1:4040/protection",
    })));
  });
  await act(async () => { button(renderer.root, "Run this case locally").props.onClick(); });
  assert.equal(button(renderer.root, "Evidence").props.disabled, true);
  await act(async () => { button(renderer.root, "Prepare private match").props.onClick(); });
  assert.match(text(renderer.root), /RECOURSE_OPENED · CURE_WINDOW/);
  assert.match(text(renderer.root), /Cure \/ dispute window open\s+· provisional backend state/);
  assert.doesNotMatch(text(renderer.root), /Recourse not opened/);
  assert.equal(button(renderer.root, "Evidence").props.disabled, true);
  await act(async () => { button(renderer.root, "Simulate cure-window completion").props.onClick(); });
  assert.match(text(renderer.root), /Simulated protocol clock/);
  assert.equal(button(renderer.root, "Evidence").props.disabled, false);
  assert.equal(renderer.root.findByProps({ "data-execution": "local" }).props["data-execution"], "local");
  await act(async () => { renderer.unmount(); });
});

artifactTest("failed imported scenario load clears every previous case authority", async () => {
  const imported = evidence("conflict");
  let rejectRequest;
  global.fetch = () => new Promise((_resolve, reject) => { rejectRequest = reject; });
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(imported))); });
  await act(async () => {
    button(renderer.root, "No conflict").props.onClick();
    await Promise.resolve();
  });
  assert.doesNotMatch(text(renderer.root), new RegExp(imported.protectionCase.fheCaseId.slice(-16)));
  assert.equal(button(renderer.root, "Evidence").props.disabled, true);
  assert.match(text(renderer.root), /Previous case authority is cleared/);
  await act(async () => {
    rejectRequest(new Error("IMPORTED_READ_FAILED"));
    await Promise.resolve();
  });
  assert.match(text(renderer.root), /IMPORTED_READ_FAILED/);
  assert.doesNotMatch(text(renderer.root), new RegExp(imported.protectionCase.fheCaseId.slice(-16)));
  await act(async () => { renderer.unmount(); });
});

artifactTest("mismatched imported response is refused without falling back", async () => {
  const conflict = evidence("conflict");
  global.fetch = async () => response({
    schemaVersion: "mordant.protection-imported-view/1",
    presentation: "IMPORTED_COMPLETED_EVIDENCE",
    evidence: conflict,
  });
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(conflict))); });
  await act(async () => { button(renderer.root, "No conflict").props.onClick(); });
  assert.match(text(renderer.root), /did not match the requested scenario/);
  assert.doesNotMatch(text(renderer.root), new RegExp(conflict.protectionCase.fheCaseId.slice(-16)));
  await act(async () => { renderer.unmount(); });
});

artifactTest("imported wrapper and nested projection extras never enter mounted state", async () => {
  const conflict = evidence("conflict");
  const noConflict = structuredClone(evidence("no-conflict"));
  noConflict.fhe.privatePlaintextSentinel = "PRIVATE_FHE_SENTINEL";
  global.fetch = async () => response({
    schemaVersion: "mordant.protection-imported-view/1",
    presentation: "IMPORTED_COMPLETED_EVIDENCE",
    evidence: noConflict,
    privateWrapperSentinel: "PRIVATE_WRAPPER_SENTINEL",
  });
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(conflict))); });
  await act(async () => { button(renderer.root, "No conflict").props.onClick(); });
  const rendered = text(renderer.root);
  assert.match(rendered, /did not match the requested scenario/);
  assert.doesNotMatch(rendered, /PRIVATE_FHE_SENTINEL|PRIVATE_WRAPPER_SENTINEL/);
  await act(async () => { renderer.unmount(); });
});

artifactTest("local adapter response extras are rejected before mounted state", async () => {
  const imported = evidence("conflict");
  const runId = "11111111-1111-4111-8111-111111111111";
  const localCase = { ...imported.protectionCase, incidentState: "AUTHORIZED", recourseState: "NOT_OPEN", cureDeadline: null };
  global.fetch = async () => response({
    ...view(runId, "CASE_CREATED", "preparePrivateMatch", localCase),
    privatePlaintextSentinel: "LOCAL_PRIVATE_SENTINEL",
  });
  let renderer;
  await act(async () => {
    renderer = create(React.createElement(ProtectionExperience, props(imported, {
      localAdapterOrigin: "http://127.0.0.1:4040/protection",
    })));
  });
  await act(async () => { button(renderer.root, "Run this case locally").props.onClick(); });
  const rendered = text(renderer.root);
  assert.match(rendered, /mismatched public view/);
  assert.doesNotMatch(rendered, /LOCAL_PRIVATE_SENTINEL/);
  await act(async () => { renderer.unmount(); });
});

artifactTest("older imported response cannot win a rapid scenario race", async () => {
  const conflict = evidence("conflict");
  const noConflict = evidence("no-conflict");
  const pending = [];
  global.fetch = (_url, options) => new Promise((resolve) => pending.push({ resolve, signal: options.signal }));
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(conflict))); });
  await act(async () => {
    button(renderer.root, "No conflict").props.onClick();
    await Promise.resolve();
  });
  await act(async () => {
    button(renderer.root, "Conflict").props.onClick();
    await Promise.resolve();
  });
  await act(async () => {
    pending[1].resolve(response({ schemaVersion: "mordant.protection-imported-view/1", presentation: "IMPORTED_COMPLETED_EVIDENCE", evidence: conflict }));
    await Promise.resolve();
  });
  await act(async () => {
    pending[0].resolve(response({ schemaVersion: "mordant.protection-imported-view/1", presentation: "IMPORTED_COMPLETED_EVIDENCE", evidence: noConflict }));
    await Promise.resolve();
  });
  assert.match(text(renderer.root), /Conflict confirmed/);
  assert.doesNotMatch(text(renderer.root), new RegExp(noConflict.protectionCase.fheCaseId.slice(-16)));
  await act(async () => { renderer.unmount(); });
});

artifactTest("drawer renders the actual recourse record digest and full required public values", async () => {
  const imported = evidence("conflict");
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(imported))); });
  await act(async () => {
    button(renderer.root, "Evidence").props.onClick({ currentTarget: { focus() {} } });
  });
  const dialog = renderer.root.findByProps({ role: "dialog" });
  const rendered = text(dialog);
  for (const exact of [
    imported.sourceCommit,
    imported.governedFheCommit,
    imported.fhe.caseId,
    imported.protectionAuthorization.bindingDigest,
    imported.governedResult.digest,
    imported.recourseAttestation.attestation.chronologyDigest,
    imported.recourse.recordDigest,
    imported.recourseAttestation.digest,
    imported.manifestDigest,
  ]) assert.match(rendered, new RegExp(exact.replaceAll(":", "\\:")));
  assert.match(rendered, /Recourse-record digest/);
  assert.notEqual(imported.recourse.recordDigest, imported.recourse.resultDigest);
  await act(async () => { renderer.unmount(); });
});

artifactTest("no-conflict drawer states explicit refusal and absence without a fabricated digest", async () => {
  const imported = evidence("no-conflict");
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(imported))); });
  await act(async () => {
    button(renderer.root, "Evidence").props.onClick({ currentTarget: { focus() {} } });
  });
  const rendered = text(renderer.root.findByProps({ role: "dialog" }));
  assert.match(rendered, /ABSENT — signed false Boolean refused recourse/);
  assert.match(rendered, /No digest exists/);
  assert.equal(imported.recourse.recordDigest, null);
  await act(async () => { renderer.unmount(); });
});

artifactTest("mounted chronology suppresses duplicate canonical kinds without accepting caller labels", async () => {
  const imported = evidence();
  const malicious = structuredClone(imported);
  malicious.chronology.events.push({
    ...malicious.chronology.events[0],
    ordinal: 99,
  });
  let renderer;
  await act(async () => { renderer = create(React.createElement(ProtectionExperience, props(malicious))); });
  const rendered = text(renderer.root);
  assert.equal((rendered.match(/Protected holder snapshot fixed/g) ?? []).length, 1);
  await act(async () => { renderer.unmount(); });
});
