# Private matching — developer documentation

Two mutually authorized parties determine privately whether their submissions
describe the same receivable, and open a governed recourse record only after both
sides consent to disclose it.

This is **controlled Monad testnet evidence**. Test assets only. Nothing here is
a production deployment, and the feature ships disabled.

## What the product flow does

1. **Onboarding.** Each side anchors its receivable under the canonical identity
   scheme. One side is a tokenized `MordantInvoiceVaultV2`; the other is a
   non-vault source registration that publishes only opaque identity fields. Both
   publish independently salted asset commitments, so their public commitments
   differ while the private identity is the same.

2. **Governance.** A governor authorizes a scope for each side: controller,
   controller key id, organization, epoch and version, with a `validFrom` that is
   always the authorizing block. Records are append-only; rotation appends a new
   version and never edits the old one.

3. **Session initiation.** Both controllers and an authorized issuer sign one
   `BilateralSessionIntent` covering 24 fields. Their three signatures are hashed
   into the commitment preimage, so a published commitment proves that bilateral
   initiation and issuer authorization already existed when it was posted.

4. **Commitment.** A policy-authorized non-controller relayer publishes a single
   opaque 32-byte commitment. It receives only `{chainId, sessionCommitment}`,
   verifies its own scope, and signs and broadcasts its own transaction.

5. **Evaluation.** Both sides enroll ciphertexts bound to that commitment. A
   dealerless 2-of-3 threshold ceremony evaluates strict identity equality under
   encryption (`full_fhe_256`) together with the commercial-term conditions. The
   released bit is the conjunction, so a true bit proves identity equality
   without ever releasing it separately.

6. **Quorum and consent.** Validators independently recompute the result core and
   verify on-chain that the commitment predates their signature. Both controllers
   then sign a disclosure consent bound to the result, the session, the match, the
   anchor, the binder, the policy and a one-shot nonce.

7. **Binding.** One atomic transaction reveals the intent, verifies every
   condition, consumes six one-time identities, and opens a non-economic recourse
   record. It moves no value.

## Layout

| Path | What it is |
|---|---|
| `contracts/src/identity/` | Canonical identity, terms model, normalization, issuer and source registries |
| `contracts/src/v4/` | Scope governance, V4 verifier, V4 binder, anchored-receivable interface |
| `contracts/src/MordantInvoiceVaultV2.sol` | Identity-anchored receivable vault |
| `fhe-lab/lattigo/` | BGV library, FullFHE256 identity path, dealerless ceremony, operators, evaluator |
| `fhe-lab/monad-testnet/` | Runner, deployment, signer services, relayer, journaling and recovery |
| `fhe-lab/shared/identity/` | Cross-language identity and digest reference, pinned to Solidity vectors |
| `fhe-lab/privacy-v4/` | Design documents and the leak scanner |
| `docs/evidence/private-matching-v4/` | Published public evidence bundle |
| `docs/provenance/PRIVATE_MATCHING_V4.md` | Where everything came from, and its limits |

## Running the checks

```bash
pnpm verify:frozen        # the 16 frozen sources still match af5baad
pnpm verify:abi           # 401 selectors match the approved manifest
pnpm verify:hygiene       # no large, generated or unlicensed artifact is tracked
pnpm verify:integration   # all three
pnpm fhe:test             # identity, digest, signer and leak-scanner suites
pnpm fhe:go:test          # the Go FHE suite
pnpm fhe:contracts:test   # the complete Foundry suite
```

A live Monad session needs funded accounts and fourteen local processes, and is
deliberately not part of any default script:

```bash
pnpm fhe:priv8:run --receivable 1 --root <work> --journal <journal> --out <evidence>
```

## Feature flags

Everything is off unless explicitly enabled. See
`src/lib/private-matching/config.ts`.

| Variable | Effect |
|---|---|
| `NEXT_PUBLIC_PRIVATE_MATCHING_ENABLED` | Shows the product flow |
| `NEXT_PUBLIC_PRIVATE_MATCHING_EVIDENCE_ENABLED` | Shows the evidence explorer |
| `NEXT_PUBLIC_PRIVATE_MATCHING_DEMO_ENABLED` | Shows the read-only demo |
| `PRIVATE_MATCHING_LIVE_SESSIONS_ENABLED` | Permits a live session |

Only the literal strings `true` and `1` enable a flag. The chain allow-list
contains Monad testnet and nothing else, and it is **not** a flag:
`assertNetworkAllowed` throws for any other chain however the flags are set.

## What may and may not be said

Supported by this evidence:

- private matching between mutually authorized submissions;
- governed recourse after bilateral disclosure consent;
- the evaluator does not receive the submitted identities or commercial terms;
- controlled Monad testnet evidence.

Not supported, and prohibited anywhere in this repository: fraud detection;
market completeness; zero knowledge; trustlessness; private transactions;
private settlement; public proof of correct FHE execution; independent
organizational custody; production readiness.

The prohibited list is enforced as data in `PROHIBITED_CLAIMS` and asserted
against the product copy in `config.test.ts`.

## Known limitations

Carried from the M-PRIV8 report without softening:

- organizational independence was not established: every process ran on one
  machine under one operator;
- correct FHE execution is quorum-attested, not publicly proven;
- no traffic-analysis privacy is claimed, and session volume is public. The
  production target is a multi-relayer authorized pool, which the governance
  registry already models;
- two Vault V2 anchors for one receivable remain correlatable through their
  public economics;
- namespace and profile agreement between platforms is source-attested, not
  cryptographically enforced.
