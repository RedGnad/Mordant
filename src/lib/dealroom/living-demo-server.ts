import "server-only";

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { Abi, Hex } from "viem";

import {
  JOURNEY,
  createClients,
  decodeReceiptEvents,
  readDealRoomState,
  type Deployment,
  type JourneyContext,
} from "@/lib/dealroom/journey";
import {
  CONTROLLED_CHAIN_SOURCE,
  roleLabel,
  type LivingActionRecord,
  type LivingNextAction,
  type LivingRunArtifact,
} from "@/lib/dealroom/living-demo";
import type { MordantPledge } from "@/lib/contracts/pledge";

const LOCAL_CHAIN_ID = 31_337;
const RUN_PATH = join(process.cwd(), ".dealroom", "m-ex2-run.json");
const DEPLOYMENT_PATH = join(process.cwd(), ".dealroom", "deployment.json");
// Anvil mines instantly. Retain the real broadcast state briefly so a human can
// perceive the same pending → confirmed transition that a remote chain exposes.
const RECEIPT_OBSERVATION_DELAY_MS = 900;

const ARTIFACTS: readonly (readonly [string, string, string])[] = [
  ["vault", "MordantInvoiceVault.sol", "MordantInvoiceVault"],
  ["factory", "MordantFactory.sol", "MordantFactory"],
  ["erc20", "MockERC20.sol", "MockERC20"],
  ["adapter", "MockCvaAdapter.sol", "MockCvaAdapter"],
  ["eligibility", "MockEligibility.sol", "MockEligibility"],
];

type SerializedConflict = Readonly<{
  pledge: Readonly<{
    invoiceRoot: Hex;
    originatorSigner: `0x${string}`;
    facility: `0x${string}`;
    obligationId: Hex;
    amount: string;
    currency: Hex;
    activeFrom: string;
    activeUntil: string;
    nonce: string;
    deadline: string;
    exclusive: boolean;
  }>;
  signature: Hex;
  salt: Hex;
  digest: Hex;
}>;

type StoredRun = LivingRunArtifact & Readonly<{
  internal: Readonly<{
    deploymentGeneratedAt: string;
    conflict?: SerializedConflict;
  }>;
}>;

let activeActionId: string | null = null;

export class LivingDemoError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "LivingDemoError";
  }
}

function assertControlledEnvironment() {
  if (process.env.NODE_ENV === "production") {
    throw new LivingDemoError(
      "The transaction demo requires the controlled local chain and is unavailable in production.",
      404,
    );
  }
}

function readJson<T>(path: string): T {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown read error";
    throw new LivingDemoError(`The controlled execution artifact is unreadable: ${detail}`, 500);
  }
}

function writeJsonAtomic(path: string, value: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  renameSync(temporary, path);
}

function loadDeployment(): Deployment {
  assertControlledEnvironment();
  if (!existsSync(DEPLOYMENT_PATH)) {
    throw new LivingDemoError("No controlled deployment found. Run `pnpm localnet` first.", 503);
  }

  const raw = readJson<Omit<Deployment, "abis">>(DEPLOYMENT_PATH);
  if (raw.chainId !== LOCAL_CHAIN_ID) {
    throw new LivingDemoError(`Refusing controlled execution on chain ${raw.chainId}.`, 409);
  }

  const rpc = new URL(raw.rpcUrl);
  if (rpc.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(rpc.hostname)) {
    throw new LivingDemoError("The controlled execution RPC must be local.", 409);
  }

  if (!raw.resetSnapshotId) {
    throw new LivingDemoError("The local deployment predates M-EX2. Restart `pnpm localnet`.", 503);
  }

  const abis: Record<string, Abi> = {};
  for (const [key, file, name] of ARTIFACTS) {
    const path = join(process.cwd(), "contracts", "out", file, `${name}.json`);
    if (!existsSync(path)) {
      throw new LivingDemoError("Contract artifacts are missing. Run `pnpm build:contracts`.", 503);
    }
    abis[key] = readJson<{ abi: Abi }>(path).abi;
  }

  return { ...raw, abis } as Deployment;
}

function serializeConflict(conflict: NonNullable<JourneyContext["conflict"]>): SerializedConflict {
  return {
    pledge: {
      ...conflict.pledge,
      amount: conflict.pledge.amount.toString(),
      activeFrom: conflict.pledge.activeFrom.toString(),
      activeUntil: conflict.pledge.activeUntil.toString(),
      nonce: conflict.pledge.nonce.toString(),
      deadline: conflict.pledge.deadline.toString(),
    },
    signature: conflict.signature,
    salt: conflict.salt,
    digest: conflict.digest,
  };
}

function hydrateConflict(conflict: SerializedConflict): NonNullable<JourneyContext["conflict"]> {
  return {
    pledge: {
      ...conflict.pledge,
      amount: BigInt(conflict.pledge.amount),
      activeFrom: BigInt(conflict.pledge.activeFrom),
      activeUntil: BigInt(conflict.pledge.activeUntil),
      nonce: BigInt(conflict.pledge.nonce),
      deadline: BigInt(conflict.pledge.deadline),
    } satisfies MordantPledge,
    signature: conflict.signature,
    salt: conflict.salt,
    digest: conflict.digest,
  };
}

function publicRun(stored: StoredRun): LivingRunArtifact {
  const { internal, ...run } = stored;
  void internal;
  return run;
}

function descriptorFor(index: number): LivingNextAction | null {
  const step = JOURNEY[index];
  if (step === undefined) return null;
  return {
    id: step.id,
    title: step.title,
    detail: step.detail,
    actor: step.role,
    actorLabel: roleLabel(step.role),
    kind: step.kind,
    contract: step.contract,
    method: step.method,
  };
}

function nextActionFor(actions: readonly LivingActionRecord[]): LivingNextAction | null {
  const confirmed = new Set(
    actions.filter((action) => action.status === "confirmed").map((action) => action.id),
  );
  const index = JOURNEY.findIndex((step) => !confirmed.has(step.id));
  return descriptorFor(index === -1 ? JOURNEY.length : index);
}

function withDerivedStatus(stored: StoredRun): StoredRun {
  const nextAction = nextActionFor(stored.actions);
  const currentRecord = nextAction === null
    ? undefined
    : stored.actions.find((action) => action.id === nextAction.id);
  const status = nextAction === null ? "complete"
    : currentRecord?.status === "pending" ? "running"
      : currentRecord?.status === "failed" ? "failed" : "ready";
  return { ...stored, status, nextAction };
}

function writeStored(stored: StoredRun): StoredRun {
  const derived = withDerivedStatus(stored);
  writeJsonAtomic(RUN_PATH, derived);
  return derived;
}

function updateAction(
  stored: StoredRun,
  id: string,
  mutate: (record: LivingActionRecord) => LivingActionRecord,
): StoredRun {
  return {
    ...stored,
    revision: stored.revision + 1,
    updatedAt: new Date().toISOString(),
    actions: stored.actions.map((record) => record.id === id ? mutate(record) : record),
  };
}

async function initializeRun(deployment: Deployment): Promise<StoredRun> {
  const clients = createClients(deployment);
  const current = await readDealRoomState({ deployment, ...clients });
  const protectionAmount = (
    BigInt(deployment.invoice.advanceAmount) * BigInt(deployment.invoice.bondBps) / 10_000n
  ).toString();
  const runId = `m-ex2:${deployment.contracts.vault.toLowerCase()}:${current.blockNumber}`;
  const dealId = `deal:${deployment.contracts.vault.slice(2, 10).toLowerCase()}`;
  const now = new Date().toISOString();

  return writeStored({
    schemaVersion: 1,
    runId,
    revision: 0,
    source: {
      kind: "controlled-demo-chain",
      label: CONTROLLED_CHAIN_SOURCE,
      network: "Anvil",
      chainId: deployment.chainId,
      protocolAssets: "doubles",
      executionDiscipline: "M-15 checkpoint semantics",
    },
    deal: {
      id: dealId,
      invoiceRoot: deployment.invoice.invoiceRoot,
      vault: deployment.contracts.vault,
      settlementToken: deployment.contracts.settlement,
      settlementSymbol: "dSETTLE",
      initialUnits: deployment.invoice.initialUnits,
      advanceAmount: deployment.invoice.advanceAmount,
      faceValue: deployment.invoice.faceValue,
      protectionAmount,
      participants: Object.fromEntries(
        Object.entries(deployment.accounts).map(([role, account]) => [role, account.address]),
      ) as LivingRunArtifact["deal"]["participants"],
    },
    status: "ready",
    current,
    lastSafeState: current,
    actions: [],
    nextAction: descriptorFor(0),
    updatedAt: now,
    internal: { deploymentGeneratedAt: deployment.generatedAt },
  });
}

function receiptAbi(deployment: Deployment, action: LivingActionRecord): Abi {
  return action.contract === "settlement" ? deployment.abis.erc20 : deployment.abis.vault;
}

async function reconcilePending(
  stored: StoredRun,
  deployment: Deployment,
  observeActive = false,
): Promise<StoredRun> {
  const pending = stored.actions.find((action) => action.status === "pending");
  if (pending === undefined) return stored;

  // The executing request owns the terminal observation. Keeping the retained
  // broadcast visible here lets polling clients render the real pending window
  // even when the controlled chain mines immediately.
  if (!observeActive && activeActionId === pending.id) return stored;

  if (pending.transactionHash === undefined) {
    const age = Date.now() - Date.parse(pending.startedAt);
    if (age < 10_000) return stored;
    return writeStored(updateAction(stored, pending.id, (record) => ({
      ...record,
      status: "failed",
      error: "Execution stopped before a transaction hash or terminal observation was retained.",
      completedAt: new Date().toISOString(),
    })));
  }

  const clients = createClients(deployment);
  let receipt;
  try {
    receipt = await clients.publicClient.getTransactionReceipt({ hash: pending.transactionHash });
  } catch {
    return stored;
  }

  const after = await readDealRoomState(
    { deployment, ...clients },
    receipt.blockNumber,
  );
  const receiptRecord = {
    transactionHash: pending.transactionHash,
    blockNumber: receipt.blockNumber.toString(),
    blockHash: receipt.blockHash,
    status: receipt.status,
    gasUsed: receipt.gasUsed.toString(),
    events: decodeReceiptEvents(receiptAbi(deployment, pending), receipt),
  } as const;

  const updated = updateAction(stored, pending.id, (record) => ({
    ...record,
    status: receipt.status === "success" ? "confirmed" : "failed",
    receipt: receiptRecord,
    after,
    error: receipt.status === "success" ? undefined : "The retained receipt reports a revert.",
    completedAt: new Date().toISOString(),
  }));
  return writeStored({
    ...updated,
    current: after,
    lastSafeState: receipt.status === "success" ? after : stored.lastSafeState,
  });
}

async function loadOrInitialize(): Promise<{ deployment: Deployment; stored: StoredRun }> {
  const deployment = loadDeployment();
  if (!existsSync(RUN_PATH)) {
    return { deployment, stored: await initializeRun(deployment) };
  }

  let stored = readJson<StoredRun>(RUN_PATH);
  if (stored.schemaVersion !== 1
    || stored.internal?.deploymentGeneratedAt !== deployment.generatedAt
    || stored.deal.vault.toLowerCase() !== deployment.contracts.vault.toLowerCase()
    || stored.deal.invoiceRoot.toLowerCase() !== deployment.invoice.invoiceRoot.toLowerCase()) {
    stored = await initializeRun(deployment);
  }
  stored = await reconcilePending(stored, deployment);
  return { deployment, stored };
}

export async function getLivingDemoRun(): Promise<LivingRunArtifact> {
  const { stored } = await loadOrInitialize();
  return publicRun(stored);
}

export async function executeLivingDemoAction(actionId: string): Promise<LivingRunArtifact> {
  if (activeActionId !== null) {
    throw new LivingDemoError(`Action ${activeActionId} is already executing.`, 409);
  }

  const { deployment, stored: loaded } = await loadOrInitialize();
  const next = nextActionFor(loaded.actions);
  if (next === null) throw new LivingDemoError("The canonical execution is already complete.", 409);
  if (next.id !== actionId) {
    throw new LivingDemoError(`Expected ${next.id}; received ${actionId}.`, 409);
  }

  const step = JOURNEY.find((candidate) => candidate.id === actionId);
  if (step === undefined) throw new LivingDemoError(`Unknown action ${actionId}.`, 400);

  activeActionId = actionId;
  const clients = createClients(deployment);
  const before = await readDealRoomState({ deployment, ...clients });
  const startedAt = new Date().toISOString();
  const pendingRecord: LivingActionRecord = {
    ...next,
    status: "pending",
    before,
    startedAt,
  };
  const withoutPreviousAttempt = loaded.actions.filter((action) => action.id !== actionId);
  let stored = writeStored({
    ...loaded,
    revision: loaded.revision + 1,
    current: before,
    lastSafeState: before,
    actions: [...withoutPreviousAttempt, pendingRecord],
    updatedAt: startedAt,
  });

  const context: JourneyContext = {
    deployment,
    ...clients,
    conflict: stored.internal.conflict === undefined
      ? undefined : hydrateConflict(stored.internal.conflict),
    receiptObservationDelayMs: RECEIPT_OBSERVATION_DELAY_MS,
    onTransactionBroadcast: async ({ hash }) => {
      const latest = readJson<StoredRun>(RUN_PATH);
      stored = writeStored(updateAction(latest, actionId, (record) => ({
        ...record,
        transactionHash: hash,
      })));
    },
  };

  try {
    const outcome = await step.run(context);
    const after = await readDealRoomState(
      context,
      outcome.blockNumber === undefined ? undefined : BigInt(outcome.blockNumber),
    );
    const latest = readJson<StoredRun>(RUN_PATH);
    const completedAt = new Date().toISOString();
    stored = writeStored({
      ...updateAction(latest, actionId, (record) => ({
        ...record,
        status: "confirmed",
        transactionHash: outcome.hash ?? record.transactionHash,
        receipt: outcome.hash === undefined || outcome.blockNumber === undefined
          || outcome.blockHash === undefined || outcome.status === undefined
          || outcome.gasUsed === undefined
          ? undefined
          : {
              transactionHash: outcome.hash,
              blockNumber: outcome.blockNumber,
              blockHash: outcome.blockHash,
              status: outcome.status,
              gasUsed: outcome.gasUsed,
              events: outcome.events,
            },
        after,
        completedAt,
        error: undefined,
      })),
      current: after,
      lastSafeState: after,
      internal: {
        ...latest.internal,
        conflict: context.conflict === undefined ? latest.internal.conflict : serializeConflict(context.conflict),
      },
    });
  } catch (error) {
    const latest = readJson<StoredRun>(RUN_PATH);
    const retained = latest.actions.find((record) => record.id === actionId);
    if (retained?.transactionHash !== undefined) {
      // A failure after broadcast is not guessed from the thrown error. Observe
      // the retained hash: a mined receipt decides success/revert, while a hash
      // without a receipt remains pending for later reconciliation.
      stored = await reconcilePending(latest, deployment, true);
    } else {
      const message = error instanceof Error
        ? error.message.split("\n")[0].slice(0, 240)
        : "Unknown execution failure";
      stored = writeStored({
        ...updateAction(latest, actionId, (record) => ({
          ...record,
          status: "failed",
          error: message,
          completedAt: new Date().toISOString(),
        })),
        current: before,
        lastSafeState: before,
      });
    }
  } finally {
    activeActionId = null;
  }

  return publicRun(stored);
}

async function localRpc<T>(deployment: Deployment, method: string, params: readonly unknown[]): Promise<T> {
  const response = await fetch(deployment.rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    cache: "no-store",
  });
  if (!response.ok) throw new LivingDemoError(`Local RPC refused ${method}.`, 502);
  const body = await response.json() as { result?: T; error?: { message?: string } };
  if (body.error !== undefined || body.result === undefined) {
    throw new LivingDemoError(body.error?.message ?? `Local RPC did not return ${method}.`, 502);
  }
  return body.result;
}

export async function resetLivingDemoRun(): Promise<LivingRunArtifact> {
  if (activeActionId !== null) {
    throw new LivingDemoError("Wait for the pending transaction before resetting the run.", 409);
  }
  const deployment = loadDeployment();
  const reverted = await localRpc<boolean>(deployment, "evm_revert", [deployment.resetSnapshotId]);
  if (!reverted) {
    throw new LivingDemoError("The canonical reset snapshot is no longer available. Restart `pnpm localnet`.", 409);
  }
  const resetSnapshotId = await localRpc<string>(deployment, "evm_snapshot", []);
  const raw = readJson<Omit<Deployment, "abis">>(DEPLOYMENT_PATH);
  writeJsonAtomic(DEPLOYMENT_PATH, { ...raw, resetSnapshotId });
  return publicRun(await initializeRun({ ...deployment, resetSnapshotId }));
}
