# Reviewer access

> ## The public deployment currently runs the MANAGED live check.
>
> The worker has exactly one BGV execution slot, and the two-wallet
> direct-participant rail claims it exclusively by design, so a visitor cannot
> race a reviewer mid-ceremony. The public submission deployment therefore
> selects the **managed** profile, so that **every** judge can run a real
> encrypted check from the landing page without importing a key.
>
> This is a deployment profile, not a removal:
>
> - the two-wallet direct-participant rail is **implemented, tested and
>   qualified**. Its browser suite and adversarial batteries run in CI on every
>   change;
> - the authoritative hardened two-wallet run remains **publicly verifiable** at
>   [`/protection/verified-run`](https://mordant-two.vercel.app/protection/verified-run),
>   with every Monad transaction linked;
> - re-enabling it is one environment variable
>   (`MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION=enabled`) on the worker
>   and on Vercel, plus a worker redeploy.
>
> **While the managed profile is active the reviewer wallet keys are not
> distributed and are not needed.** The addresses below are published so the
> hardened run's participants can be checked on chain; the private keys stay
> out-of-band and unused.

## What a judge should do today

1. Open <https://mordant-two.vercel.app>.
2. Run the live check on the landing page. It is a real BGV run on a verified
   Cleanverse receivable, and it usually takes about a minute. One slot exists,
   so if someone else is mid-run the page says so explicitly.
3. Follow **See the completed on-chain recourse** to
   [`/protection/verified-run`](https://mordant-two.vercel.app/protection/verified-run)
   for the settled two-wallet run, with `ReleaseConsumed`, the real 600-second
   cure window, the permissionless finalization and both aUSDC claims.

The managed check prepares both pledge windows for the visitor under one eligible
test context. It is a real encrypted decision, and it is **not** two independent
wallets. The two-wallet ceremony is what the hardened run in step 3 records.

## The two wallets

| Role | Address |
| --- | --- |
| Participant A | `0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685` |
| Participant B | `0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9` |

Both hold a genuine Cleanverse A-Pass on Monad testnet. The server refuses any
other address for either role, so these are the only two wallets that can run it.

## Running the two-wallet ceremony (requires the direct-participant profile)

These steps apply when `MORDANT_WORKER_ENABLE_DIRECT_PARTICIPANT_ADMISSION=enabled`.
They are the exact steps the hardened run followed, retained so the qualified
path stays documented rather than folkloric.

1. **Import Participant A** into your wallet, on **Monad testnet (chain 10143)**.
2. Open <https://mordant-two.vercel.app/protection/live> and connect wallet A.
3. **Check A-Pass eligibility.** This reads the Cleanverse registry on chain and
   takes a moment.
4. Enter A's claim window as two whole numbers, active from strictly before
   active until, then **Authorize claim A**. Your wallet asks you to sign a
   typed `ParticipantAdmissionV1` message. Signing costs no gas.
5. **Handoff.** The screen tells you to continue as Participant B. Nothing is
   disconnected for you; you disconnect A yourself, deliberately.
6. **Import or select Participant B**, connect it, check its A-Pass, enter B's
   window, and **Authorize claim B**. The same address is refused for both roles.
7. The private evaluation starts once both admissions are in. Expect **about a
   minute**: retained runs took 53, 56 and 87 seconds from case creation to
   sealed receipt. The screen names each step and counts elapsed seconds. It
   never shows a percentage, because none of these steps reports progress.
8. The result appears only after the governed decryptor has recomputed the
   circuit and signed the answer. Before that signature there is no result to
   show, and the screen will not pretend otherwise.

Choose overlapping windows (for example 120 to 420 and 220 to 520) to see a
confirmed conflict. Choose disjoint windows to see recourse explicitly refused.
Both outcomes are real; neither is a fixture.

## Then see the settled consequence

The live check ends at the governed result. What happens next with real money was
executed once, on Monad testnet, and retained:

**<https://mordant-two.vercel.app/protection/verified-run>**

Run `e618abc2-0ac7-4d79-b201-44959a54b68c` on adapter
`0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`, with every transaction linked to
the public explorer:

| | |
| --- | --- |
| ReleaseConsumed | `0x09b9bbfbab53f1782506850654fe0c7be1e81bf8a1eff692c5b43e0e3936d651` |
| Cure window | a real 600 seconds, allowed to expire uncured |
| Finalize, permissionless | `0xc74051d892a0e2f971e744ac45b159dd19f23b8ff7f649192ab77f2345e4fc34` |
| Holder A claim | `0x4831b0a7aa5bb6c030a6651e3112ee806f0c0d7c61ecbdf376d096b6ecbea819`, 0.002400 aUSDC |
| Holder B claim | `0x36296bf9db21123fcd155ec95c8f7a4db31cbb5158dd42139b79bb81430bfc50`, 0.001600 aUSDC |

## If something goes wrong

**"Connect the wallet for this role on Monad testnet."** The wallet is on another
chain. Switch to Monad testnet, chain id 10143.

**A-Pass check refuses the wallet.** Confirm you connected one of the two
addresses above. Any other address is refused by design, and the refusal names
the reason.

**"This address already holds the other role in this case."** Wallet A is still
connected while you are trying to authorize B. Disconnect and connect B.

**The run does not start, or you are asked to wait.** One case runs at a time,
deliberately: a second concurrent case would break the single-active-case
guarantee the durable journal depends on. There is also a cooldown and a daily
limit. Wait for the current case to finish and try again.

**The page says live execution is unavailable.** The worker is not reachable.
That is fail-closed behaviour rather than an error to work around, and the
retained evidence above is unaffected.

**You lost the tab mid-run.** The case code is in the URL. Reopening that URL
restores the case from durable state; it does not start a second one.
