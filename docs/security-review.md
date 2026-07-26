# Internal adversarial review

This is a prebuild engineering review, not an external audit and not a production-safety claim.

## Findings closed in the prototype

- A buyer-supplied malicious adapter or settlement token is rejected unless the factory owner has
  explicitly allowlisted it.
- A facility cannot choose a record date and acquire an originator signature afterward: the hidden
  commitment includes the exact signature hash.
- Buyer, originator, facilities and holders cannot overlap in the protected vault roles.
- CVA credit, asset identity and dedicated issued supply are checked; an unexpected mint or adapter
  asset change stops state transitions.
- Redemption funding cannot exceed the unpaid face value.
- Default cannot mix CVA withdrawals with cash redemption or strand a funded redemption escrow.
- A transfer after the hidden commit cannot move the historical 60/40 entitlement.
- Protection claims never burn receipts or CVA and cannot consume receivable escrow.

## Findings still open

- The Cleanverse CVI verifier and CVA adapter are interfaces, not sponsor-confirmed production
  implementations.
- One global pending commitment can be used by an allowlisted facility for bounded griefing or to
  delay another reveal. Production needs quotas, a caution or parallel per-facility commitments.
- Factory ownership can change facility membership and thereby censor future reveals or freeze a
  holder later labelled as a facility. Production needs scoped governance, timelock and operating
  rules.
- There is no onchain recovery for an A-Token credited before a financing that never activates.
- A historical holder whose A-Pass is revoked keeps its entitlement in accounting but cannot claim
  until a compliant recovery process exists.
- Deterministic invoice roots leak low-entropy commercial facts unless matching moves to a
  confidential environment.
- The contracts fit Monad's 128 KiB limit reported by the local Foundry build, but exceed Ethereum's
  classic 24 KiB runtime limit. A cross-chain version must split or optimize them.
- No external audit, formal verification, legal opinion, production monitoring or incident response
  exists.

Any one of these remains a production `NO-GO` for real invoices or funds.
