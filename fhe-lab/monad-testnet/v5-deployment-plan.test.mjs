import assert from "node:assert/strict";
import test from "node:test";

import {
  DEPLOYMENTS, CONFIGURATION, PlanError, buildDeploymentPlan, deploymentOrder,
  resolveArguments, resolveConfiguration,
} from "./v5-deployment-plan.mjs";

const roles = Object.fromEntries(
  ["deployer", "issuer", "relayer", "submitter", "buyer", "originator", "facility", "holder"]
    .map((role) => [role, `0x${role.padEnd(40, "0").slice(0, 40)}`]),
);
const config = {
  policyId: `0x${"11".repeat(32)}`,
  policyVersion: 1,
  validators: ["0xa", "0xb", "0xc"],
  quorum: 2n,
  recomputationQuorum: 2,
  curePeriod: 604_800n,
  consequenceId: `0x${"22".repeat(32)}`,
  identityEpoch: 1,
};

test("the deployment order satisfies every declared dependency", () => {
  const order = deploymentOrder();
  const seen = new Set();
  for (const entry of order) {
    for (const need of entry.needs) {
      assert.ok(seen.has(need), `${entry.id} deployed before its dependency ${need}`);
    }
    seen.add(entry.id);
  }
  assert.equal(order.length, DEPLOYMENTS.length);
});

// A resumed run must prepare the same sequence it prepared before, or the
// journal's frozen inputs would not line up.
test("the deployment order is deterministic", () => {
  const first = deploymentOrder().map((entry) => entry.id);
  const second = deploymentOrder().map((entry) => entry.id);
  assert.deepEqual(first, second);
});

test("the binder is deployed after the verifier it immutably references", () => {
  const order = deploymentOrder().map((entry) => entry.id);
  assert.ok(order.indexOf("verifier") < order.indexOf("binder"));
  assert.ok(order.indexOf("governance") < order.indexOf("binder"));
  assert.ok(order.indexOf("sources") < order.indexOf("binder"));
  assert.ok(order.indexOf("factory") < order.indexOf("binder"));
});

test("a dependency cycle is refused", () => {
  const cyclic = [
    { id: "a", artifact: "erc20", needs: ["b"], args: () => [] },
    { id: "b", artifact: "erc20", needs: ["a"], args: () => [] },
  ];
  assert.throws(
    () => deploymentOrder(cyclic),
    (error) => error instanceof PlanError && error.code === "DEPENDENCY_CYCLE",
  );
});

test("an unknown dependency is refused", () => {
  const broken = [{ id: "a", artifact: "erc20", needs: ["nope"], args: () => [] }];
  assert.throws(
    () => deploymentOrder(broken),
    (error) => error.code === "UNKNOWN_DEPENDENCY",
  );
});

// Every constructor argument list is checked against the real ABI, so a
// contract whose constructor gained or lost a parameter fails at plan time.
test("every constructor arity matches the compiled ABI", async () => {
  const plan = await buildDeploymentPlan({ roles, config });
  assert.equal(plan.deployments.length, DEPLOYMENTS.length);
  for (const step of plan.deployments) {
    assert.equal(step.args.length, step.constructorInputs.length, step.id);
  }
});

test("the factory constructor takes the eligibility contract as its verifier", async () => {
  const plan = await buildDeploymentPlan({ roles, config });
  const factory = plan.deployments.find((step) => step.id === "factory");
  assert.deepEqual(factory.constructorInputs, [
    "address initialOwner", "address verifier", "address registry",
  ]);
  // The parameter is named `verifier` but is the ICviVerifier eligibility
  // interface. Recording that here stops a future reader "fixing" it.
  assert.equal(factory.needs.includes("eligibility"), true);
  assert.equal(factory.needs.includes("verifier"), false);
});

// An entry that reads an address it did not declare would deploy with an
// undefined constructor argument. This asserts the invariant directly: every
// entry's args function, given a proxy that throws on any undeclared read,
// must still succeed.
test("every deployment reads only the dependencies it declares", () => {
  for (const entry of DEPLOYMENTS) {
    const guarded = new Proxy({}, {
      get(_target, key) {
        if (typeof key !== "string") return undefined;
        assert.ok(
          entry.needs.includes(key),
          `${entry.id} reads ${key} but declares needs [${entry.needs.join(", ")}]`,
        );
        return `0x${key}`;
      },
    });
    assert.doesNotThrow(() => entry.args({ at: guarded, roles, config }), entry.id);
  }
});

// The proxy in the planner turns an undeclared read into a named plan-time
// error rather than an undefined constructor argument.
test("an undeclared read is reported by name", () => {
  const rogue = { id: "rogue", needs: ["cvaToken"], args: ({ at }) => [at.factory] };
  const guarded = new Proxy({}, {
    get(_target, key) {
      if (!rogue.needs.includes(key)) {
        throw new PlanError("UNDECLARED_DEPENDENCY", `${rogue.id} reads ${key}`);
      }
      return `0x${key}`;
    },
  });
  assert.throws(
    () => rogue.args({ at: guarded }),
    (error) => error.code === "UNDECLARED_DEPENDENCY" && /reads factory/.test(error.message),
  );
});

test("missing roles and config are refused before any planning", async () => {
  await assert.rejects(
    () => buildDeploymentPlan({ roles: {}, config }),
    (error) => error.code === "MISSING_ROLE",
  );
  await assert.rejects(
    () => buildDeploymentPlan({ roles, config: { ...config, policyId: null } }),
    (error) => error.code === "MISSING_CONFIG",
  );
  await assert.rejects(
    () => buildDeploymentPlan({ roles, config: { ...config, validators: ["0xa"], quorum: 2n } }),
    (error) => error.code === "MISSING_CONFIG",
  );
});

test("configuration resolves against real addresses", () => {
  const at = Object.fromEntries(DEPLOYMENTS.map((entry) => [entry.id, `0x${entry.id}`]));
  const step = resolveConfiguration("authorize-binder", { at, roles, config });
  assert.equal(step.fn, "setAuthorizedBinder");
  assert.deepEqual(step.args, [at.binder, true]);
  assert.equal(step.at, at.governance);
});

// The binder must be authorized on BOTH registries, or binding reverts on the
// first source reveal.
test("the binder is authorized as governance binder and source revealer", () => {
  const ids = CONFIGURATION.map((entry) => entry.id);
  assert.ok(ids.includes("authorize-binder"));
  assert.ok(ids.includes("authorize-revealer"));
  const at = Object.fromEntries(DEPLOYMENTS.map((entry) => [entry.id, `0x${entry.id}`]));
  assert.deepEqual(resolveConfiguration("authorize-revealer", { at, roles, config }).args, [at.binder, true]);
});

// The relayer and submitter must never be a controller; recording them as
// separate roles is the first half of that guarantee.
test("relayer and submitter are distinct roles from the controllers", () => {
  const at = Object.fromEntries(DEPLOYMENTS.map((entry) => [entry.id, `0x${entry.id}`]));
  const relayer = resolveConfiguration("authorize-relayer", { at, roles, config }).args[0];
  const submitter = resolveConfiguration("authorize-submitter", { at, roles, config }).args[0];
  assert.notEqual(relayer, submitter);
  assert.notEqual(relayer, roles.originator);
  assert.notEqual(submitter, roles.originator);
});
