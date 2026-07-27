# 80-second demo spine

1. **0–10s — Human problem.** One verified invoice has already financed real working capital. The
   first holders should not receive only an alert if the originator breaks exclusivity.
2. **10–25s — Issuance.** Show valid adapter and vault A-Passes plus the funder's holder role/A-Pass,
   then show the real aUSDC policy permit 100 aUSDC of funder-to-vault funding: 90 reaches the
   originator, 10 enters the reserve, and 100 custom CVA units are held 1:1 for two holders.
3. **25–38s — Transfer.** Move the beneficial units to a 60/40 holder split. Show both wallets pass
   direct A-Pass and adapter-deliverability checks, then show the CVA policy approve the exact
   holder-to-holder pair and amount; the adapter and vault fail as holder destinations.
4. **38–52s — Conflict.** Facility B commits, then reveals a second overlapping EIP-712 pledge. The
   record date predates the reveal.
5. **52–68s — Consequence.** Finalize after the short cure window. Holder A claims 6 aUSDC and holder
   B claims 4 aUSDC under holder A-Pass and real aUSDC policy checks, without an unrelated CVA
   delivery probe.
6. **68–76s — Principal continuity.** Their 60 and 40 invoice units remain. Fund 110 redemption and
   show 66/44 cash redemption independently under the aUSDC policy after the 6/4 bond payout.
7. **76–80s — Compression.** “Registries detect the second pledge. Mordant gives it a funded
   consequence.”

## Liveness appendix

Use separate disposable fixtures so the main 80-second spine remains readable:

1. Configure a policy that permits the real 60/40 allocation burns but would reject one 100-unit burn.
   Show base readiness pass on identity/role/custody/policy presence, both per-allocation readiness
   checks pass, duplicate-holder activation fail, and the unique 60/40 activation succeed without a
   false full-supply rejection.
2. Fully escrow cash, make either holder A's complete 60-unit burn or exact 66-aUSDC payout fail its
   policy precheck, then cross default. Show A receive CVA, `cvaReleasedFace` increase by 66, 66
   excess aUSDC accrue as buyer `settlementCredit`, and holder B—whose burn and exact 44-aUSDC payout
   both pass—still redeem the remaining cash.
3. On another fixture, begin with only 20 escrow, let A receive CVA, then show the buyer fund the exact
   residual shortfall of 24 despite `defaultCvaReleaseStarted == true`; B then redeems 44 cash.
4. Expire the buyer before excess credit accrues and the originator before a clean redeem/close.
   Holder actions still complete because refunds and bond returns accrue as pull credits. Restore each
   A-Pass and show the exact `_transferExact` policy precheck pass before `claimSettlementCredit`
   releases the accounted aUSDC.
5. Attempt activation while the originator cannot receive aUSDC. Show the inline net-proceeds transfer
   revert the entire activation, with no funder cash or partially activated state left behind.
6. Transfer mINV into a holder that already has a position and show the adapter probe use the complete
   future balance while the pair check uses only the transfer delta. Partially release CVA, then show
   the next probe use the residual mINV balance and the adapter verify the real transfer delta.

State the boundary explicitly: these checks target monotone balance caps. They may reject a valid
max-per-transaction delta conservatively and cannot guarantee future execution under mutable,
history-dependent or non-monotone policies.

Never describe the synthetic invoice, local mock, or pending sponsor boundary as live production.
