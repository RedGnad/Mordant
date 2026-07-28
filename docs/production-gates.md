# Production gates

The hackathon build is testnet-only. Every item below is a hard gate before real funds:

- named jurisdiction and independent legal opinion;
- authoritative buyer/e-invoice root and amendment process;
- repaired/confirmed Monad launcher compatibility and written Cleanverse approval for standard
  A-Token issuance, separate adapter/vault A-Passes, contract custody, burn authority and recovery;
- sponsor-backed implementation of `ICvaAdapter`, including dedicated supply, custody credit,
  burn/release, adapter-to-holder and exact holder-pair `policy().canTransfer(...)` semantics, and
  per-holder mixed settlement, exact allocation/balance readiness, `cvaReleasedFace` reconciliation
  and upgrade detection;
- verified exact-tuple settlement-policy prechecks for every outgoing aUSDC transfer, including at
  least one `canTransfer(token, from, to, amount)` tuple the deployed policy actually accepts; as of
  block 48667706 the probed tuples were rejected with `ComplianceFailed(address)`;
- sponsor-confirmed policy class or explicit handling for mutable, history-dependent, non-monotone and
  max-per-transaction rules; do not market preflight as universal policy parity;
- two independent facilities under one mandatory platform workflow;
- existing factoring reserve that Mordant replaces or automates;
- paid design partner and measured ROI;
- confidential matching and privacy review;
- external contract audits, invariant fuzzing and bug bounty;
- multisig/timelock, monitoring, reconciliation and incident response;
- monitoring and fail-closed renewal procedures for both the adapter and every vault A-Pass;
- reconciliation and recovery for outstanding buyer/originator `settlementCredit` pull-payments;
- commit-spam controls and a recovery path for CVA credited before an activation that never occurs;
- KYB/AML/sanctions/UBO/related-party controls;
- signed-wallet authorization and rate limiting before exposing Cleanverse-backed read routes;
- shadow pilot meeting agreed coverage and error thresholds.

Failure of one gate is a production `NO-GO`; it does not invalidate the sandbox prototype.
