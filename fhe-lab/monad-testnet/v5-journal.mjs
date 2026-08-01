// Durable stage machine for the final V5 Monad execution.
//
// The journal and the chain are the ONLY continuity authorities. Conversational
// memory, in-process variables and the operator's recollection are all
// explicitly not authorities: a run may be interrupted at any point and resumed
// in a different session, and the only safe question to ask is "what does the
// journal say, and does the chain agree".
//
// Two properties matter more than anything else here:
//
//   1. A transaction hash is persisted BEFORE the receipt is awaited. A crash
//      between broadcast and receipt must leave a hash to reconcile, never a
//      silent gap. The opposite order loses money and, worse, loses knowledge
//      of whether a nonce was consumed.
//
//   2. Canonical calldata is frozen at PREPARED and never regenerated. If a
//      resumed run rebuilt the calldata it might differ (timestamps, salts,
//      map ordering) and would then broadcast something the operator never
//      reviewed. Preparation is the review point; broadcast replays bytes.
import { createHash } from "node:crypto";
import { open, mkdir, readFile, rename } from "node:fs/promises";
import { dirname } from "node:path";

/// The durable stages, in order. A stage may only advance forwards.
///
/// The admission spine is deliberately finer grained than its RC1 predecessor:
/// each source, governance record and the A-Pass hand-off has independent
/// continuity.  Collapsing any pair would make a restart unable to distinguish
/// "the first action happened" from "the whole group happened".
export const STAGES = Object.freeze([
  "INITIALIZED",
  "FINAL_STACK_PLANNED",
  "FINAL_STACK_DEPLOYED",
  "BYTECODE_VERIFIED",
  "VAULT_CREATED",
  "AWAITING_VAULT_APASS",
  "VAULT_ACTIVATED",
  "SOURCE_A_COMMITTED",
  "SOURCE_B_COMMITTED",
  "GOVERNANCE_A_CREATED",
  "GOVERNANCE_B_CREATED",
  "SESSION_PREPARED",
  "SESSION_NULLIFIER_RESERVED",
  "SESSION_COMMITTED",
  "CEREMONY_CONTEXT_PREPARED",
  "CEREMONY_IDENTITIES_CONFIRMED",
  "CEREMONY_OPERATOR_1_READY",
  "CEREMONY_OPERATOR_2_READY",
  "CEREMONY_OPERATOR_3_READY",
  "CEREMONY_CONTRIBUTIONS_GENERATED",
  "CEREMONY_CONTRIBUTIONS_EXCHANGED",
  "CEREMONY_COLLECTIVE_PUBLIC_KEY_COMPLETED",
  "CEREMONY_RELINEARIZATION_COMPLETED",
  "CEREMONY_GALOIS_COMPLETED",
  "CEREMONY_EVALUATION_KEY_BUNDLE_COMPLETED",
  "CEREMONY_PUBLIC_MANIFEST_CONSTRUCTED",
  "CEREMONY_MANIFEST_SIGNATURE_1",
  "CEREMONY_MANIFEST_SIGNATURE_2",
  "CEREMONY_MANIFEST_SIGNATURE_3",
  "CEREMONY_PUBLIC_BUNDLE_VERIFIED",
  "CEREMONY_COMPLETED",
  "ENROLLMENTS_ADMITTED",
  "EVALUATION_COMPLETED",
  "OPERATOR_RECOMPUTATION_COMPLETED",
  "THRESHOLD_RELEASE_COMPLETED",
  "VALIDATOR_ATTESTATIONS_COMPLETED",
  "DISCLOSURE_CONSENTS_COMPLETED",
  "BINDING_PREPARED",
  "BINDING_BROADCAST",
  "BINDING_CONFIRMED",
  "READBACKS_COMPLETED",
  "NEGATIVES_COMPLETED",
  "LEAK_AUDIT_COMPLETED",
  "EVIDENCE_FINALIZED",
]);

/// Per-stage lifecycle. AMBIGUOUS is terminal for automation: a human decides.
export const STATES = Object.freeze({
  NOT_STARTED: "NOT_STARTED",
  PREPARED: "PREPARED",
  /// An external, separately-authorized action is required.  Unlike FAILED or
  /// AMBIGUOUS this is resumable: reconciliation is the only way out.
  AWAITING_EXTERNAL: "AWAITING_EXTERNAL",
  BROADCAST: "BROADCAST",
  CONFIRMED: "CONFIRMED",
  FAILED: "FAILED",
  AMBIGUOUS: "AMBIGUOUS",
});

export class JournalError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
    this.name = "JournalError";
  }
}

const digestOf = (value) =>
  "0x" + createHash("sha256").update(JSON.stringify(value)).digest("hex");

/// Atomic replace with fsync of both the file and its directory.
///
/// Without the directory fsync the rename itself can be lost on power failure,
/// which would leave the journal pointing at the pre-rename content while the
/// chain has already moved on. That is precisely the AMBIGUOUS state this
/// machine exists to avoid.
async function writeAtomic(path, text) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp`;
  // Journals contain salts and opaque signing material. They are durable
  // private process artifacts, not evidence-bundle input.
  const handle = await open(temporary, "w", 0o600);
  try {
    await handle.writeFile(text);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } catch {
    // Some platforms refuse to fsync a directory handle. The rename is still
    // atomic; only the durability of the rename itself is weaker.
  } finally {
    await directory.close();
  }
}

export class Journal {
  #path;
  #data;

  constructor(path, data) {
    this.#path = path;
    this.#data = data;
  }

  static empty(sourceCommit, chainId) {
    return {
      schemaVersion: "mordant.v5-run-journal/1",
      sourceCommit,
      chainId,
      createdAt: new Date().toISOString(),
      stages: Object.fromEntries(STAGES.map((name) => [name, { state: STATES.NOT_STARTED }])),
    };
  }

  /// Opens an existing journal or creates one. A journal whose source commit or
  /// chain differs from the current run is refused rather than migrated: those
  /// are different runs and merging them would silently rebind evidence.
  static async open(path, { sourceCommit, chainId }) {
    let data;
    try {
      data = JSON.parse(await readFile(path, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      data = Journal.empty(sourceCommit, chainId);
      await writeAtomic(path, JSON.stringify(data, null, 2) + "\n");
      return new Journal(path, data);
    }
    if (data.sourceCommit !== sourceCommit) {
      throw new JournalError("JOURNAL_SOURCE_COMMIT_MISMATCH", `${data.sourceCommit} != ${sourceCommit}`);
    }
    if (Number(data.chainId) !== Number(chainId)) {
      throw new JournalError("JOURNAL_CHAIN_MISMATCH", `${data.chainId} != ${chainId}`);
    }
    for (const name of STAGES) {
      if (!data.stages[name]) data.stages[name] = { state: STATES.NOT_STARTED };
    }
    return new Journal(path, data);
  }

  get data() {
    return this.#data;
  }

  stage(name) {
    if (!STAGES.includes(name)) throw new JournalError("UNKNOWN_STAGE", name);
    return this.#data.stages[name];
  }

  state(name) {
    return this.stage(name).state;
  }

  async #flush() {
    await writeAtomic(this.#path, JSON.stringify(this.#data, null, 2) + "\n");
  }

  /// The first stage that is not CONFIRMED. Resumption starts here.
  nextStage() {
    for (const name of STAGES) {
      const entry = this.stage(name);
      if (entry.state === STATES.AMBIGUOUS) {
        throw new JournalError("AMBIGUOUS_STAGE", `${name} requires a human decision`);
      }
      if (entry.state !== STATES.CONFIRMED) return name;
    }
    return null;
  }

  /// Every stage before `name` must be CONFIRMED. Stages are not independent:
  /// a session commitment is meaningless without the governance records that
  /// preceded it, so skipping forward is refused rather than warned about.
  #requirePredecessors(name) {
    for (const previous of STAGES) {
      if (previous === name) return;
      if (this.stage(previous).state !== STATES.CONFIRMED) {
        throw new JournalError("STAGE_OUT_OF_ORDER", `${previous} is ${this.state(previous)}, required before ${name}`);
      }
    }
  }

  /// Freezes the canonical inputs for a stage. Idempotent: re-preparing an
  /// already-prepared stage returns the FROZEN record and refuses to overwrite
  /// it, because the prepared bytes are what the operator reviewed.
  async prepare(name, record) {
    const entry = this.stage(name);
    if (entry.state === STATES.CONFIRMED) return entry;
    if (entry.state === STATES.BROADCAST) {
      throw new JournalError("STAGE_ALREADY_BROADCAST", `${name} has hash ${entry.transactionHash}`);
    }
    if (entry.state === STATES.PREPARED) {
      const incoming = digestOf(record);
      if (incoming !== entry.inputDigest) {
        throw new JournalError(
          "PREPARED_INPUT_DRIFT",
          `${name} was prepared with ${entry.inputDigest}, now ${incoming}`,
        );
      }
      return entry;
    }
    this.#requirePredecessors(name);
    this.#data.stages[name] = {
      state: STATES.PREPARED,
      preparedAt: new Date().toISOString(),
      inputDigest: digestOf(record),
      ...record,
    };
    await this.#flush();
    return this.stage(name);
  }

  /// Persists the transaction hash BEFORE the caller awaits the receipt.
  async markBroadcast(name, transactionHash) {
    const entry = this.stage(name);
    if (entry.state === STATES.CONFIRMED) return entry;
    if (entry.state !== STATES.PREPARED && entry.state !== STATES.BROADCAST) {
      throw new JournalError("STAGE_NOT_PREPARED", `${name} is ${entry.state}`);
    }
    if (entry.state === STATES.BROADCAST && entry.transactionHash !== transactionHash) {
      throw new JournalError(
        "DOUBLE_BROADCAST",
        `${name} already broadcast ${entry.transactionHash}, refusing ${transactionHash}`,
      );
    }
    entry.state = STATES.BROADCAST;
    entry.transactionHash = transactionHash;
    entry.broadcastAt = new Date().toISOString();
    await this.#flush();
    return entry;
  }

  async markConfirmed(name, receipt) {
    const entry = this.stage(name);
    if (entry.state === STATES.CONFIRMED) return entry;
    if (entry.state !== STATES.BROADCAST && entry.state !== STATES.PREPARED) {
      throw new JournalError("STAGE_NOT_BROADCAST", `${name} is ${entry.state}`);
    }
    entry.state = STATES.CONFIRMED;
    entry.confirmedAt = new Date().toISOString();
    entry.receipt = receipt;
    await this.#flush();
    return entry;
  }

  /// A stage that produced no transaction, such as the ceremony or the FHE
  /// evaluation. It still records its canonical outputs so a resumed run does
  /// not recompute them and silently obtain different values.
  async recordOffChain(name, outputs) {
    const entry = this.stage(name);
    if (entry.state === STATES.CONFIRMED) return entry;
    if (entry.state !== STATES.PREPARED && entry.state !== STATES.AWAITING_EXTERNAL) {
      this.#requirePredecessors(name);
    }
    // MERGE onto the prepared record rather than replacing it. The frozen
    // inputs (calldata, salts, nonces) are part of the stage's permanent
    // evidence: a later reconcile compares against them, and an evidence
    // bundle that lost them could not show what was actually submitted.
    this.#data.stages[name] = {
      ...entry,
      ...outputs,
      state: STATES.CONFIRMED,
      confirmedAt: new Date().toISOString(),
      outputDigest: digestOf(outputs),
    };
    await this.#flush();
    return this.stage(name);
  }

  /// Persist a bounded external-action request.  Only reconciliation can
  /// confirm this stage later; an operator assertion is intentionally not an
  /// input to this transition.
  async markAwaitingExternal(name, request) {
    const entry = this.stage(name);
    if (entry.state === STATES.CONFIRMED) return entry;
    if (entry.state !== STATES.PREPARED && entry.state !== STATES.AWAITING_EXTERNAL) {
      throw new JournalError("STAGE_NOT_PREPARED", `${name} is ${entry.state}`);
    }
    this.#data.stages[name] = {
      ...entry,
      ...request,
      state: STATES.AWAITING_EXTERNAL,
      awaitingSince: entry.awaitingSince ?? new Date().toISOString(),
    };
    await this.#flush();
    return this.stage(name);
  }

  async markFailed(name, reason) {
    const entry = this.stage(name);
    entry.state = STATES.FAILED;
    entry.failedAt = new Date().toISOString();
    entry.reason = reason;
    await this.#flush();
    return entry;
  }

  async markAmbiguous(name, reason) {
    const entry = this.stage(name);
    entry.state = STATES.AMBIGUOUS;
    entry.ambiguousAt = new Date().toISOString();
    entry.reason = reason;
    await this.#flush();
    return entry;
  }

  /// Reconciles every BROADCAST stage against the chain.
  ///
  /// A broadcast stage has exactly three honest outcomes: the receipt exists and
  /// succeeded (CONFIRMED), the receipt exists and reverted (FAILED), or the
  /// transaction is not found. The third is only safe to call FAILED when the
  /// sender's nonce has NOT advanced past it; otherwise some transaction
  /// consumed that nonce and this one may or may not have been it, which is
  /// AMBIGUOUS and stops the run.
  async reconcile(client) {
    const findings = [];
    for (const name of STAGES) {
      const entry = this.stage(name);
      if (entry.state !== STATES.BROADCAST) continue;
      let receipt = null;
      try {
        receipt = await client.getTransactionReceipt({ hash: entry.transactionHash });
      } catch {
        receipt = null;
      }
      if (receipt && receipt.status === "success") {
        await this.markConfirmed(name, {
          blockNumber: Number(receipt.blockNumber),
          blockHash: receipt.blockHash,
          gasUsed: String(receipt.gasUsed),
        });
        findings.push({ stage: name, resolved: STATES.CONFIRMED });
        continue;
      }
      if (receipt && receipt.status !== "success") {
        await this.markFailed(name, `reverted in block ${receipt.blockNumber}`);
        findings.push({ stage: name, resolved: STATES.FAILED });
        continue;
      }
      const nonce = entry.sender
        ? await client.getTransactionCount({ address: entry.sender })
        : null;
      if (nonce !== null && entry.nonce !== undefined && nonce > Number(entry.nonce)) {
        await this.markAmbiguous(
          name,
          `no receipt for ${entry.transactionHash} but sender nonce advanced to ${nonce} past ${entry.nonce}`,
        );
        findings.push({ stage: name, resolved: STATES.AMBIGUOUS });
        continue;
      }
      findings.push({ stage: name, resolved: "STILL_PENDING" });
    }
    return findings;
  }

  /// Persists the verification flags a stage set on its entry.
  async recordVerification(name) {
    if (!STAGES.includes(name)) throw new JournalError("UNKNOWN_STAGE", name);
    await this.#flush();
    return this.stage(name);
  }

  /// Persist a value that is knowable only after a transaction has executed,
  /// such as a governance record digest containing the mined block number.
  /// Reconciliation may call this after a crash; a different re-derived value
  /// is evidence of a different transaction and is refused.
  async recordDerived(name, values) {
    const entry = this.stage(name);
    for (const [key, value] of Object.entries(values)) {
      if (entry[key] !== undefined && JSON.stringify(entry[key]) !== JSON.stringify(value)) {
        throw new JournalError("DERIVED_OUTPUT_DRIFT", `${name}.${key}`);
      }
    }
    this.#data.stages[name] = { ...entry, ...values };
    await this.#flush();
    return this.stage(name);
  }

  summary() {
    return STAGES.map((name) => ({ stage: name, state: this.state(name) }));
  }
}
