# Reviewer access

> ## The public deployment currently runs the managed live proof.
>
> The public submission profile gives every judge access to a fresh real BGV execution without a
> wallet key. It exposes one worker slot, so a second visitor receives an explicit busy state.
>
> This is a deployment profile, not a removal:
>
> - the two-wallet direct-participant rail is implemented, tested and qualified. Separate admission
>   proves wallet authorization; it does not prove participant-local encryption;
> - the authoritative hardened two-wallet run remains publicly verifiable at
>   [`/protection/verified-run`](https://mordant-two.vercel.app/protection/verified-run), with every
>   Monad transaction linked;
> - re-enabling direct admission requires
>   `MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION=enabled` on the worker and Vercel, followed by
>   a worker redeploy.
>
> Participant-originated native-CLI encryption is now a current qualified, opt-in capability. It is
> disabled by default and is not wired into the public managed demo or browser direct admission.

The reviewer wallet addresses are public so the historical run can be checked on chain. Their
private keys stay out of band and are neither distributed nor required for the current public proof.

## What a judge should do today

1. Open <https://mordant-two.vercel.app>.
2. Run the live proof on the landing page. It performs a real BGV evaluation and releases
   conflict/no-conflict only. One public slot exists; contention is shown explicitly.
3. Inspect the Governed Recourse Policy surface. The policy was selected before result exposure.
   For conflict, the precommitted policy selects a **24-hour local protocol-double cure path**;
   for no conflict, it selects record and close.
   Neither branch authorizes settlement.
4. Follow **Verify the completed on-chain recourse** to
   [`/protection/verified-run`](https://mordant-two.vercel.app/protection/verified-run). That separate
   hardened run shows `ReleaseConsumed`, a historical 600-second cure, permissionless finalization
   and both aUSDC claims.

The managed profile prepares both synthetic windows under one eligible test context. Managed
infrastructure receives those demo values during intake/preparation, then performs a real encrypted
evaluation. It is not two independent wallets and it does not execute a fresh aUSDC settlement.

## Qualified institutional privacy profile

The qualified native-CLI profile is a separate supported intake. Each participant prepares and
signs its own case- and role-bound encrypted artifact inside a participant-controlled environment;
the participant-originated coordinator receives authenticated encrypted artifacts rather than raw
claim-window bounds. The profile is opt-in, disabled by default and has no public browser route.

Reviewers can inspect:

- the exact supported boundary in
  [`participant-originated-encryption.md`](participant-originated-encryption.md);
- the retained product-qualification receipt in
  [`participant-originated-encryption-product-qualification.json`](evidence/participant-originated-encryption-product-qualification.json).

This qualification does not relabel the managed public run or direct wallet admission. It does not
establish browser/device BGV, threshold or participant-controlled decryption, commitment/plaintext
semantic equality, production institutional key management or production-cluster readiness.

## Direct participant admission

| Role | Canonical wallet |
| --- | --- |
| Participant A | `0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685` |
| Participant B | `0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9` |

Both held a genuine Cleanverse A-Pass on Monad testnet for the qualified ceremony. The server
refuses any other address for either role under that profile.

When direct admission is enabled:

1. connect Participant A on Monad testnet, chain `10143`;
2. check A-Pass eligibility;
3. enter A's claim and sign the exact role-bound `ParticipantAdmissionV1` payload;
4. deliberately hand off and connect the distinct Participant B wallet;
5. repeat the eligibility and admission steps for B;
6. wait for the governed decryptor to recompute and sign the conflict status.

The same wallet is refused for both roles. Expired nonces and changed payloads are refused. An exact
admission retry reuses the retained signature rather than asking the wallet to sign twice.

Overlapping windows such as 120–420 and 220–520 produce a confirmed conflict in the governed
execution. Disjoint windows produce a governed no-conflict result. The browser does not classify the
geometry, and neither result independently authorizes recourse or settlement.

## Separate historical on-chain execution

The current managed proof continues from governed result through the new precommitted policy and a
bounded local operation. It does not execute aUSDC settlement. A distinct historical architecture
executed real on-chain recourse once on Monad testnet and retained it:

**<https://mordant-two.vercel.app/protection/verified-run>**

Run `e618abc2-0ac7-4d79-b201-44959a54b68c` on adapter
`0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`:

| Evidence | Historical value |
| --- | --- |
| ReleaseConsumed | `0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651` |
| Cure window | A real **600 seconds**, allowed to expire uncured |
| Finalize, permissionless | `0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34` |
| Holder A claim | `0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819` · 0.002400 aUSDC |
| Holder B claim | `0x36296bf9db21123fcd155ec95c8f7a4db31b5158dd42139b79bb81430bfc50` · 0.001600 aUSDC |

This hardened run predates the current managed V2 policy-selection and operation-authorization
chain. Its 600-second configuration is not the managed 24-hour local policy, and neither proof is
presented as a continuation of the other.

## If something goes wrong

**The run is busy.** The public deployment exposes one worker slot and also applies a cooldown and
daily limit. Separate N=2 qualification proves isolated workers can execute concurrently;
production routing or pooling is not deployed here. Wait for the public slot to finish.

**The page says live execution is unavailable.** The worker is not reachable. The product fails
closed; the retained hardened evidence remains independently available.

**You lost the tab mid-run.** The run code in the URL restores durable state. Reopening it does not
start a second run.

**A-Pass check refuses a direct-admission wallet.** Confirm the wallet and Monad testnet chain. The
direct profile accepts only the two canonical addresses above.
