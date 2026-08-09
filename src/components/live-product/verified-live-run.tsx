import Link from "next/link";

import {
  RUN_PROVENANCE_BADGE,
  monadExplorerHref,
  type VerifiedLiveRunReceipt,
} from "@/lib/protection/verified-live-run";

import { formatAusdcExact } from "./live-product-view-model";
import styles from "./verified-live-run.module.css";

/**
 * The completed real Monad journey, told as five chapters.
 *
 * Product language leads and digests are disclosed, not paraded. Everything on
 * screen came from the verified receipt: this component computes no outcome,
 * invents no amount and has no fixture branch. It is badged as a separate
 * verified on-chain execution because that is what the retained hardened
 * receipt proves, and no other provenance can print that badge.
 */

function Explorer({ kind, value, label }: {
  readonly kind: "tx" | "address" | "block";
  readonly value: string | null;
  readonly label?: string;
}) {
  const href = monadExplorerHref(kind, value);
  const shown = label ?? (value ?? "");
  if (href === null) return <span className={styles.factValue}>{shown}</span>;
  return (
    <a className={styles.link} href={href} target="_blank" rel="noreferrer noopener">
      {shown}
    </a>
  );
}

function Fact({ label, children }: { readonly label: string; readonly children: React.ReactNode }) {
  return (
    <div className={styles.fact}>
      <span className={styles.factLabel}>{label}</span>
      <span className={styles.factValue}>{children}</span>
    </div>
  );
}

function ProofDetails({ summary, rows }: {
  readonly summary: string;
  readonly rows: readonly (readonly [string, string])[];
}) {
  return (
    <details className={styles.details}>
      <summary>{summary}</summary>
      <dl className={styles.proofRows}>
        {rows.map(([label, value]) => (
          <div className={styles.proofRow} key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

function shortHash(value: string): string {
  return value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-8)}` : value;
}

function ChapterHead({ index, id, children }: {
  readonly index: string;
  readonly id: string;
  readonly children: React.ReactNode;
}) {
  return (
    <div className={styles.chapterHead}>
      <span className={styles.chapterCheck} aria-hidden="true">✓</span>
      <span className={styles.chapterIndex}>{index}</span>
      <h2 className={styles.chapterTitle} id={id}>{children}</h2>
    </div>
  );
}

export function VerifiedLiveRun({ receipt }: { readonly receipt: VerifiedLiveRunReceipt }) {
  const [a, b] = receipt.authorize.participants;
  const claimA = formatAusdcExact(receipt.prove.claimA.atomic);
  const claimB = formatAusdcExact(receipt.prove.claimB.atomic);
  const entitlement = formatAusdcExact(receipt.act.entitlementOpenedAtomic);

  return (
    <article className={styles.run} data-testid="verified-live-run" data-provenance={receipt.provenance}>
      <header className={styles.header}>
        <span className={styles.badge} data-testid="verified-live-run-badge">
          {RUN_PROVENANCE_BADGE.VERIFIED_LIVE_RUN}
        </span>
        <p className={styles.context}>Separate hardened execution · historical Adapter V2 configuration</p>
        <h1 className={styles.title}>A conflicting pledge, decided privately and settled on Monad</h1>
        <p className={styles.standfirst}>
          This retained run predates the current managed V2 policy-authority chain. Two eligible wallets
          submitted claims against the same tokenized receivable identity. The
          governed result established that their windows conflicted; preconfigured demo recourse policy
          then applied, and the deployment configuration—not the Boolean—determined holders and payout
          amounts. Every transaction below happened on {receipt.network.name} and is linked publicly.
        </p>
        <p className={styles.meta}>
          <span>Run {receipt.runId}</span>
          <span>{receipt.network.name} · chain {receipt.network.chainId}</span>
          <span>Source {receipt.sourceCommit.slice(0, 12)}</span>
        </p>
      </header>

      <section className={styles.verificationSummary} aria-labelledby="verification-summary-title" data-testid="verification-summary">
        <div className={styles.verificationSummaryHead}>
          <p>Completed path</p>
          <h2 id="verification-summary-title">Five verified stages. One reconciled run.</h2>
          <span>Each status below is backed by the retained receipt and public chain readback.</span>
        </div>
        <ol className={styles.verificationRail}>
          <li><span aria-hidden="true">✓</span><div><strong>Provenance observed</strong><small>{receipt.verify.assetLabel}</small></div></li>
          <li><span aria-hidden="true">✓</span><div><strong>Eligibility verified</strong><small>Two distinct wallets</small></div></li>
          <li><span aria-hidden="true">✓</span><div><strong>Private decision verified</strong><small>Signed conflict status</small></div></li>
          <li><span aria-hidden="true">✓</span><div><strong>Recourse finalized</strong><small>Configured path</small></div></li>
          <li><span aria-hidden="true">✓</span><div><strong>Settlement reconciled</strong><small>Reserve cleared</small></div></li>
        </ol>
      </section>

      <section className={styles.chapter} aria-labelledby="chapter-verify">
        <ChapterHead index="01" id="chapter-verify">Verify</ChapterHead>
        <p className={styles.answer}>
          The protected asset is MINV01, whose Cleanverse provenance and identity are verified. That
          evidence does not establish invoice authenticity, legal validity or enforceability. The
          original receivable was never moved or altered by this case.
        </p>
        <div className={styles.facts}>
          <Fact label="Asset">{receipt.verify.assetLabel}</Fact>
          <Fact label="MINV01 contract">
            <Explorer kind="address" value={receipt.verify.minv01} label={shortHash(receipt.verify.minv01)} />
          </Fact>
          <Fact label="Network">{receipt.network.name} · chain {receipt.network.chainId}</Fact>
          <Fact label="Original receivable">Unchanged</Fact>
        </div>
        <ProofDetails summary="Proof detail: asset identity and MINV01 readback" rows={[
          ["Cleanverse asset identity", receipt.verify.assetIdentity],
          ["MINV01 held by adapter, before", receipt.verify.minv01AdapterBalanceBefore],
          ["MINV01 held by adapter, after", receipt.verify.minv01AdapterBalanceAfter],
          ["Original receivable state", "OUTSTANDING_INTACT"],
        ]} />
      </section>

      <section className={styles.chapter} aria-labelledby="chapter-authorize">
        <ChapterHead index="02" id="chapter-authorize">Authorize</ChapterHead>
        <p className={styles.answer}>
          Two distinct wallets participated. Cleanverse verified an A-Pass for each one on Monad
          before it was admitted, and each signed its own role-bound admission.
        </p>
        <div className={styles.facts}>
          {[a, b].map((participant) => (
            <Fact key={participant.role} label={`${participant.label} · A-Pass verified`}>
              <Explorer kind="address" value={participant.wallet} label={shortHash(participant.wallet)} />
            </Fact>
          ))}
          <Fact label="Distinct participants">Yes</Fact>
          <Fact label="Eligibility observed at blocks">
            {a.eligibilityBlock} · {b.eligibilityBlock}
          </Fact>
        </div>
        <ProofDetails summary="Proof detail: admission commitments" rows={[
          ["Participant A wallet", a.wallet],
          ["Participant A authorization digest", a.authorizationDigest],
          ["Participant A claim commitment", a.claimCommitment],
          ["Participant B wallet", b.wallet],
          ["Participant B authorization digest", b.authorizationDigest],
          ["Participant B claim commitment", b.claimCommitment],
          ["Protection binding digest", receipt.authorize.protectionBindingDigest],
        ]} />
      </section>

      <section className={styles.chapter} aria-labelledby="chapter-decide">
        <ChapterHead index="03" id="chapter-decide">Decide privately</ChapterHead>
        <p className={styles.answer}>
          The counterparty-facing workflow did not disclose either pledge window. A fixed BGV circuit
          evaluated them under encryption, and the designated decryptor recomputed the circuit and signed
          exactly one Boolean: <strong>{receipt.decidePrivately.conflict ? "a conflict was confirmed" : "no conflict"}</strong>.
          That Boolean established conflict status only; it did not authorize recourse or settlement and
          established no legal responsibility, priority, ownership, deadline or payout amount.
        </p>
        <div className={styles.facts}>
          <Fact label="Circuit">{receipt.decidePrivately.circuitId}</Fact>
          <Fact label="Parameters">{receipt.decidePrivately.parameterProfile}</Fact>
          <Fact label="Governed result">Ed25519 signature verified</Fact>
          <Fact label="Outcome">{receipt.decidePrivately.conflict ? "Conflict confirmed" : "Cleared"}</Fact>
        </div>
        <ProofDetails summary="Proof detail: encrypted execution and governed release" rows={[
          ["FHE case id", receipt.decidePrivately.fheCaseId],
          ["Case binding digest", receipt.decidePrivately.caseBindingDigest],
          ["Participant artifact A", receipt.decidePrivately.participantArtifactDigestA],
          ["Participant artifact B", receipt.decidePrivately.participantArtifactDigestB],
          ["Evaluated artifact", receipt.decidePrivately.evaluatedArtifactDigest],
          ["Result ciphertext digest", receipt.decidePrivately.resultCiphertextDigest],
          ["Result ciphertext commitment", receipt.decidePrivately.resultCiphertextCommitment],
          ["Governed result digest", receipt.decidePrivately.governedResultDigest],
          ["Governed release authority", receipt.decidePrivately.releaseAuthorityId],
          ["Release authority public key", receipt.decidePrivately.releaseAuthorityPublicKey],
          ["Bridge evidence digest", receipt.decidePrivately.bridgeEvidenceDigest],
        ]} />
      </section>

      <section className={styles.chapter} aria-labelledby="chapter-act">
        <ChapterHead index="04" id="chapter-act">Act</ChapterHead>
        <p className={styles.answer}>
          After the governed result established conflict, the preconfigured demo recourse policy applied.
          Adapter V2 opened the configured case and real {receipt.act.cureWindowSeconds}-second cure
          path. Nobody cured it, so anyone was then able to finalize it.
        </p>
        <div className={styles.facts}>
          <Fact label="Case adapter">
            <Explorer kind="address" value={receipt.act.adapter} label={shortHash(receipt.act.adapter)} />
          </Fact>
          <Fact label="ReleaseConsumed">
            <Explorer kind="tx" value={receipt.act.releaseConsumedTx} label={shortHash(receipt.act.releaseConsumedTx)} />
          </Fact>
          <Fact label="Block">
            <Explorer kind="block" value={String(receipt.act.releaseConsumedBlock)} />
          </Fact>
          <Fact label="Cure window">
            {receipt.act.cureWindowSeconds} seconds, deadline {receipt.act.cureDeadlineIso}
          </Fact>
          <Fact label="Finalize, permissionless">
            <Explorer kind="tx" value={receipt.act.finalizeTx} label={shortHash(receipt.act.finalizeTx)} />
          </Fact>
          <Fact label="Entitlement opened">
            <span className={styles.amount}>{entitlement} aUSDC</span>
          </Fact>
        </div>
        <ProofDetails summary="Proof detail: adapter provenance and on-chain state" rows={[
          ["Adapter address", receipt.act.adapter],
          ["Adapter deployment transaction", receipt.act.adapterDeploymentTx],
          ["Adapter deployment block", String(receipt.act.adapterDeploymentBlock)],
          ["Reviewed bytecode", "Immutable-masked runtime code equals the reviewed artifact"],
          ["Adapter A-Pass", "Valid on chain"],
          ["Case state after release", receipt.act.cureState],
          ["Cure deadline, unix", String(receipt.act.cureDeadlineUnix)],
          ["Finalize block", String(receipt.act.finalizeBlock)],
          ["Entitlement, atomic units", receipt.act.entitlementOpenedAtomic],
        ]} />
      </section>

      <section className={styles.chapter} aria-labelledby="chapter-prove">
        <ChapterHead index="05" id="chapter-prove">Prove</ChapterHead>
        <p className={styles.answer}>
          Deployment configuration determined the two holders and their payout amounts; the Boolean
          carried neither. Both holders claimed those configured amounts on chain. The adapter&rsquo;s reserve
          went to zero, it holds no remaining liability, and MINV01 was never touched.
        </p>
        <div className={styles.ledgerScroll}>
          <table className={styles.ledger}>
            <thead>
              <tr>
                <th scope="col">Account</th>
                <th scope="col">Before</th>
                <th scope="col">After</th>
                <th scope="col">Claim transaction</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Adapter reserve</td>
                <td>{formatAusdcExact(receipt.prove.adapterBalanceBefore)}</td>
                <td>{formatAusdcExact(receipt.prove.adapterBalanceAfter)}</td>
                <td>&mdash;</td>
              </tr>
              <tr>
                <td>Holder A</td>
                <td>{formatAusdcExact(receipt.prove.holderABalanceBefore)}</td>
                <td>{formatAusdcExact(receipt.prove.holderABalanceAfter)}</td>
                <td>
                  <Explorer
                    kind="tx"
                    value={receipt.prove.claimA.transactionHash}
                    label={shortHash(receipt.prove.claimA.transactionHash)}
                  />
                </td>
              </tr>
              <tr>
                <td>Holder B</td>
                <td>{formatAusdcExact(receipt.prove.holderBBalanceBefore)}</td>
                <td>{formatAusdcExact(receipt.prove.holderBBalanceAfter)}</td>
                <td>
                  <Explorer
                    kind="tx"
                    value={receipt.prove.claimB.transactionHash}
                    label={shortHash(receipt.prove.claimB.transactionHash)}
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className={styles.facts}>
          <Fact label="Holder A claimed"><span className={styles.amount}>{claimA} aUSDC</span></Fact>
          <Fact label="Holder B claimed"><span className={styles.amount}>{claimB} aUSDC</span></Fact>
          <Fact label="Reserved liability">{receipt.prove.openReserved} · cleared</Fact>
          <Fact label="Unpaid entitlement">{receipt.prove.entitledUnpaid} · cleared</Fact>
          <Fact label="Adapter solvency">Solvent</Fact>
          <Fact label="MINV01">Unchanged</Fact>
        </div>
        <ProofDetails summary="Proof detail: exact atomic reconciliation" rows={[
          ["Holder A, atomic units", receipt.prove.claimA.atomic],
          ["Holder B, atomic units", receipt.prove.claimB.atomic],
          ["Adapter reserve, atomic before", receipt.prove.adapterBalanceBefore],
          ["Adapter reserve, atomic after", receipt.prove.adapterBalanceAfter],
          ["Open reserved", receipt.prove.openReserved],
          ["Entitled unpaid", receipt.prove.entitledUnpaid],
          ["Terminal case state", receipt.prove.terminalState],
          ["Claim A transaction", receipt.prove.claimA.transactionHash],
          ["Claim B transaction", receipt.prove.claimB.transactionHash],
        ]} />
      </section>

      <div className={styles.transition}>
        <h2 className={styles.transitionTitle}>Run the current managed proof</h2>
        <p className={styles.transitionBody}>
          This page is a separate completed hardened run. The current live proof starts a new managed
          case under the published eligible test context and follows conflict status through its
          precommitted policy and bounded local action.
        </p>
        <Link className={styles.cta} href="/protection/live" data-testid="verified-run-to-live">
          Run live proof
        </Link>
      </div>

      <details className={styles.scopeDisclosure}>
        <summary>Technical scope of this completed run</summary>
        <p>
          Managed Mordant infrastructure prepares each participant&rsquo;s encrypted artifact, so it sees
          that participant&rsquo;s claim during admission and preparation. The evaluator receives encrypted
          participant artifacts only. The internal FHE identities are Mordant&rsquo;s, not the participants&rsquo;
          wallets; encryption is not performed on the participant&rsquo;s device; release is governed by a
          single designated decryptor rather than a threshold or an independent institution. This is a
          hackathon testnet deployment and is not production ready.
        </p>
      </details>
    </article>
  );
}
