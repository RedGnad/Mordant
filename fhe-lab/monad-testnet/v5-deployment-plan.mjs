// Group 1: the final V5 deployment plan.
//
// The plan is data, derived from a declared dependency graph and topologically
// ordered. Nothing here infers an API from V4 or from the provisional
// deployment: every constructor signature is read from the compiled ABI at plan
// time, and a mismatch between the declared arguments and the real constructor
// fails before a single transaction is prepared.
//
// The provisional deployment is deliberately not consulted. Its addresses are
// not reused, and its ordering is not assumed to have been correct.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { ARTIFACTS } from "./v5-call-matrix.mjs";
import { REPO } from "./priv8-chain.mjs";

export class PlanError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.code = code;
    this.name = "PlanError";
  }
}

/// The contracts to deploy, with what each one needs.
///
/// `needs` names other deployment ids; `args` is a function from the resolved
/// address map (plus roles) to the constructor arguments, in ABI order.
export const DEPLOYMENTS = Object.freeze([
  {
    id: "eligibility", artifact: "eligibility", needs: [],
    args: () => [],
    note: "ICviVerifier implementation; the factory's second constructor argument",
  },
  {
    id: "settlement", artifact: "erc20", needs: [],
    args: () => ["Settlement", "aUSD", 6],
  },
  {
    id: "cvaToken", artifact: "erc20", needs: [],
    args: () => ["Invoice A-Token", "aINV", 6],
  },
  {
    id: "adapter", artifact: "adapter", needs: ["cvaToken"],
    args: ({ at }) => [at.cvaToken],
  },
  {
    id: "issuerRegistry", artifact: "issuerRegistry", needs: [],
    args: ({ roles }) => [roles.deployer],
  },
  {
    id: "factory", artifact: "factory", needs: ["eligibility", "issuerRegistry"],
    args: ({ at, roles }) => [roles.deployer, at.eligibility, at.issuerRegistry],
    note: "constructor is (initialOwner, ICviVerifier, MordantIssuerRegistry)",
  },
  {
    id: "governance", artifact: "governance", needs: [],
    args: ({ roles }) => [roles.deployer],
  },
  {
    id: "sources", artifact: "sources", needs: ["issuerRegistry"],
    args: ({ at, roles }) => [roles.deployer, at.issuerRegistry],
  },
  {
    id: "verifier", artifact: "verifier", needs: ["governance"],
    args: ({ at, roles, config }) => [
      roles.deployer, at.governance, config.validators, config.quorum, config.recomputationQuorum,
    ],
    note: "immutables: owner, governance, quorum, validatorSetId, recomputationQuorum",
  },
  {
    id: "binder", artifact: "binder", needs: ["verifier", "governance", "sources", "factory"],
    args: ({ at, config }) => [
      at.verifier, at.governance, at.sources, at.factory,
      config.policyId, config.policyVersion, config.curePeriod, config.consequenceId,
    ],
    note: "verifier is immutable here, which is why a new verifier forces a new binder",
  },
]);

/// Configuration applied after deployment, in order. Every entry names the
/// call-matrix function it uses, so a renamed setter fails the matrix check
/// rather than this file.
export const CONFIGURATION = Object.freeze([
  { id: "register-issuer", at: "issuerRegistry", fn: "registerIssuer",
    args: ({ roles, config }) => [roles.issuer, config.identityEpoch] },
  { id: "set-policy-version", at: "verifier", fn: "setPolicyVersion",
    args: ({ config }) => [config.policyId, config.policyVersion] },
  { id: "authorize-relayer", at: "governance", fn: "setAuthorizedRelayer",
    args: ({ roles }) => [roles.relayer, true] },
  { id: "authorize-binder", at: "governance", fn: "setAuthorizedBinder",
    args: ({ at }) => [at.binder, true] },
  { id: "authorize-submitter", at: "sources", fn: "setAuthorizedSubmitter",
    args: ({ roles }) => [roles.submitter, true] },
  { id: "authorize-revealer", at: "sources", fn: "setAuthorizedRevealer",
    args: ({ at }) => [at.binder, true] },
  { id: "approve-adapter", at: "factory", fn: "setCvaAdapter",
    args: ({ at }) => [at.adapter, true] },
  { id: "approve-settlement", at: "factory", fn: "setSettlementToken",
    args: ({ at }) => [at.settlement, true] },
  { id: "approve-facility", at: "factory", fn: "setFacility",
    args: ({ roles }) => [roles.facility, true] },
  { id: "eligible-buyer", at: "eligibility", fn: "setEligible",
    args: ({ roles }) => [roles.buyer, 1, true] },
  { id: "eligible-originator", at: "eligibility", fn: "setEligible",
    args: ({ roles }) => [roles.originator, 2, true] },
  { id: "eligible-facility", at: "eligibility", fn: "setEligible",
    args: ({ roles }) => [roles.facility, 3, true] },
  { id: "eligible-holder", at: "eligibility", fn: "setEligible",
    args: ({ roles }) => [roles.holder, 4, true] },
]);

const artifactCache = new Map();

export async function loadArtifact(key) {
  if (!artifactCache.has(key)) {
    const path = ARTIFACTS[key];
    if (!path) throw new PlanError("UNKNOWN_ARTIFACT", key);
    artifactCache.set(key, JSON.parse(await readFile(resolve(REPO, path), "utf8")));
  }
  return artifactCache.get(key);
}

/// Deterministic topological order. Ties break on declaration order, so the
/// plan is byte-identical across runs and a resumed run prepares the same
/// sequence it did before.
export function deploymentOrder(deployments = DEPLOYMENTS) {
  const byId = new Map(deployments.map((entry) => [entry.id, entry]));
  const ordered = [];
  const state = new Map();

  const visit = (id, trail) => {
    if (state.get(id) === "done") return;
    if (state.get(id) === "visiting") {
      throw new PlanError("DEPENDENCY_CYCLE", [...trail, id].join(" -> "));
    }
    const entry = byId.get(id);
    if (!entry) throw new PlanError("UNKNOWN_DEPENDENCY", id);
    state.set(id, "visiting");
    for (const need of entry.needs) visit(need, [...trail, id]);
    state.set(id, "done");
    ordered.push(entry);
  };

  for (const entry of deployments) visit(entry.id, []);
  return ordered;
}

/// Builds the full plan, verifying every constructor against the compiled ABI.
///
/// Returns entries carrying the artifact, the resolved constructor inputs and
/// the arguments, ready for a stage to encode. It performs no I/O against a
/// chain and prepares no transaction.
export async function buildDeploymentPlan({ roles, config }) {
  if (!roles?.deployer) throw new PlanError("MISSING_ROLE", "deployer");
  for (const role of ["issuer", "relayer", "submitter", "buyer", "originator", "facility", "holder"]) {
    if (!roles[role]) throw new PlanError("MISSING_ROLE", role);
  }
  if (!config?.policyId || !config?.policyVersion) throw new PlanError("MISSING_CONFIG", "policy");
  if (!Array.isArray(config.validators) || config.validators.length < Number(config.quorum)) {
    throw new PlanError("MISSING_CONFIG", "validators must be at least the quorum");
  }

  const at = {};
  const steps = [];
  for (const entry of deploymentOrder()) {
    const artifact = await loadArtifact(entry.artifact);
    const constructor = artifact.abi.find((item) => item.type === "constructor");
    const declared = entry.args({ at: proxyAddresses(at, entry), roles, config });
    const expected = constructor?.inputs ?? [];
    if (declared.length !== expected.length) {
      throw new PlanError(
        "CONSTRUCTOR_ARITY",
        `${entry.id} passes ${declared.length} args, ${entry.artifact} constructor takes ${expected.length}`,
      );
    }
    at[entry.id] = `<${entry.id}>`;
    steps.push({
      id: entry.id,
      artifact: entry.artifact,
      needs: entry.needs,
      constructorInputs: expected.map((input) => `${input.type} ${input.name ?? ""}`.trim()),
      args: declared,
      note: entry.note ?? null,
    });
  }
  return { deployments: steps, configuration: CONFIGURATION.map((entry) => entry.id) };
}

/// During planning the addresses are unknown, so dependencies resolve to a
/// placeholder. Reading an address the entry did NOT declare as a dependency
/// throws, which is how an undeclared edge is caught at plan time rather than
/// as an undefined constructor argument at deploy time.
function proxyAddresses(at, entry) {
  return new Proxy(at, {
    get(target, key) {
      if (typeof key !== "string") return target[key];
      if (!entry.needs.includes(key)) {
        throw new PlanError(
          "UNDECLARED_DEPENDENCY",
          `${entry.id} reads ${key} but does not declare it in needs`,
        );
      }
      return target[key];
    },
  });
}

/// Resolves the plan against real addresses once deployment has happened.
export function resolveArguments(entry, { at, roles, config }) {
  const source = DEPLOYMENTS.find((item) => item.id === entry.id);
  if (!source) throw new PlanError("UNKNOWN_DEPLOYMENT", entry.id);
  return source.args({ at: proxyAddresses(at, source), roles, config });
}

export function resolveConfiguration(id, { at, roles, config }) {
  const entry = CONFIGURATION.find((item) => item.id === id);
  if (!entry) throw new PlanError("UNKNOWN_CONFIGURATION", id);
  return { at: at[entry.at], fn: entry.fn, args: entry.args({ at, roles, config }) };
}
