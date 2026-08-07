import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

/**
 * The worker's runtime image must actually contain what the worker imports.
 *
 * This exists because the assumption drifted silently and production paid for
 * it. The Dockerfile's runtime stage shipped no `node_modules` on the stated
 * grounds that "the compiled engine resolves only relative modules plus the
 * `server-only` stub". That was true when it was written. Then the two-wallet
 * admission path pulled in the canonical configuration and the typed-data
 * verifier, both of which resolve `viem`, and the container died on boot with
 * MODULE_NOT_FOUND while every other gate stayed green.
 *
 * Nothing in the normal suite could see it: the failure lives in the gap between
 * the module graph and the image, and only a container build exercises that. So
 * the gap is asserted directly here, cheaply, on every run.
 */

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKER = join(REPO, "scripts", "mordant-live-worker.mjs");
const DIST = join(REPO, ".product-test-dist");

/** Bare specifiers the runtime image answers, and how each one is answered. */
const PROVIDED = Object.freeze({
  "server-only": "NODE_PATH=/app/test/stubs",
  viem: "COPY --from=runtimedeps /deps/node_modules/",
});

function packageOf(specifier) {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

/** Every compiled module the worker can reach, and every bare package it needs. */
function moduleGraph() {
  const worker = readFileSync(WORKER, "utf8");
  const entries = [...worker.matchAll(/await import\("([^"]*\.product-test-dist\/[^"]+)"\)/gu)]
    .map((match) => resolve(dirname(WORKER), match[1]));
  assert.ok(entries.length > 0, "the worker imports no compiled engine module; this test is looking at the wrong file");

  const visited = new Set();
  const bare = new Map();
  const queue = [...entries];
  while (queue.length > 0) {
    const file = queue.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    assert.ok(existsSync(file), `the worker imports ${file}, which the build did not emit`);
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/require\("([^"]+)"\)/gu)) {
      const specifier = match[1];
      if (specifier.startsWith("node:")) continue;
      if (specifier.startsWith(".")) {
        queue.push(resolve(dirname(file), specifier.endsWith(".js") ? specifier : `${specifier}.js`));
        continue;
      }
      const name = packageOf(specifier);
      if (!bare.has(name)) bare.set(name, file.slice(REPO.length + 1));
    }
  }
  return { modules: visited, bare };
}

test("every bare package the worker reaches is one the runtime image ships", () => {
  const { modules, bare } = moduleGraph();
  assert.ok(modules.size > 5, "the traced module graph is implausibly small");
  const missing = [...bare.entries()].filter(([name]) => !(name in PROVIDED));
  assert.deepEqual(
    missing.map(([name, via]) => `${name} (reached from ${via})`),
    [],
    "the worker image does not ship these packages; add them to the runtime stage or stop importing them",
  );
});

test("the runtime image really provides each package the worker needs", () => {
  const dockerfile = readFileSync(join(REPO, "Dockerfile"), "utf8");
  const runtime = dockerfile.slice(dockerfile.indexOf("AS runtime\n"));
  assert.ok(runtime.length > 0, "the Dockerfile has no runtime stage");
  const { bare } = moduleGraph();
  for (const name of bare.keys()) {
    assert.ok(name in PROVIDED, `${name} is reachable but not declared as provided`);
    assert.ok(
      runtime.includes(PROVIDED[name]),
      `the runtime stage no longer contains "${PROVIDED[name]}", so ${name} would not resolve in the container`,
    );
  }
  // viem is shipped at the version the application builds against, never floated.
  assert.match(
    dockerfile,
    /require\('\.\/package\.json'\)\.dependencies\.viem/u,
    "the runtime viem version must be read from package.json so it cannot drift",
  );
});

test("the compiled engine the worker loads was actually built", () => {
  assert.ok(existsSync(DIST), ".product-test-dist is missing; run the protection suite, which builds it");
});
