# M-15: live execution package

    LIVE EXECUTION ENGINE: READY
    EXECUTION INPUTS: INCOMPLETE
    PUBLIC WRITES: NOT AUTHORIZED
    MORDANT SETTLEMENT: NOT PROVEN LIVE

Real transaction engines, decomposed into seventeen resumable sub-actions. They execute for real
against an injected client and are proven end to end on a fork; Monad public is refused.

**The public gate is a source constant**, `PUBLIC_WRITES_AUTHORIZED` in `scripts/m15-engine.mjs`,
deliberately not readable from the environment. Authorizing a public run means editing reviewed
code, not exporting a variable, and a test asserts setting environment variables cannot open it.

    pnpm m15:phase --phase A --check
    node --env-file=.env scripts/m15-phase-b.mjs --check --from docs/evidence/<phase-A>.json

## Seventeen sub-actions, not seven signers

D, E and F are not single-signer steps and are not represented as such. The grant, the mint and the
binding are signed by different wallets, and collapsing them would hide a resume point exactly where
the ceremony is most exposed.

| Phase | Sub-actions | Signers |
| --- | --- | --- |
| A | `A.deploy` | holderA |
| B | `B.apass` | a Cleanverse call |
| C1 | `C1.infra` | holderA |
| C2 | `C2.vault` | buyer |
| D | `D.grant` → `D.mint` → `D.revokeGrant` → `D.bind` | holderA, **issuanceMinter**, holderA, holderA |
| E | `E.sign` → `E.approve` → `E.activate` | originator (offchain), **funder**, **facilityProtected** |
| F | `F.commit` → `F.reveal` → `F.finalize` → `F.markDefault` → `F.releaseA` → `F.releaseB` | challenger, challenger, holderA, holderA, holderA, **holderB** |

Each writes an artifact and stops. None triggers the next.

## The seven entry points

| Phase | Runner | Writes | Signer |
| --- | --- | --- | --- |
| A | `m15-phase-a.mjs` | deploy the adapter | holderA |
| B | `m15-phase-b.mjs` | request the adapter's A-Pass | none, a Cleanverse call |
| C1 | `m15-phase-c1.mjs` | verifier, factory, roles, allowlists, known A-Passes | holderA |
| C2 | `m15-phase-c2.mjs` | create the vault, request its A-Pass | buyer |
| D | `m15-phase-d.mjs` | minter ceremony, exact mint, `bindVault` | holderA |
| E | `m15-phase-e.mjs` | activation | facilityProtected |
| F | `m15-phase-f.mjs` | conflict, finalisation, default, releases | facilityChallenger |

Each is a thin entry point; the plan and the gates live in `m15-phase-runner.mjs` and
`m15-phase-lib.mjs`, so every phase carries the same controls by construction rather than by
repetition.

## Phase independence, and the chain between them

Each phase consumes **exactly** the previous phase's artifact, passed with `--from`, and refuses:

- an artifact from the wrong phase;
- an artifact whose status is not `SUCCESS`, so a `PENDING` or `STOPPED` predecessor is never
  resumed from silently;
- an unreadable or corrupt file, since that might be the very record of a prior attempt.

**No phase triggers the next.** Each ends by naming its successor as a separate deliberate command.

## Mandatory controls

Every writing runner carries all eleven:

`--check` read-only · explicit `--run` · `--out` mandatory when writing · chain id 10143 · the key
must derive the configured address · simulate or estimate before sending · gas ceilings · `PENDING`
written before awaiting the receipt · `PENDING` / `STOPPED` / `SUCCESS` classification · the
preceding manifest verified · refusal to continue automatically.

Ambiguous Cleanverse operations are **never** retried automatically. A request that may have been
accepted is reconciled by hand; a second attempt creates a duplicate credential.

## Configuration

`.env.m15.example` documents the six inputs the owner still owes. **No address is chosen or invented
here**: an absent one is an error, never a default.

The code refuses an address that is absent, malformed, or filling two roles the contracts treat as
mutually exclusive:

| Must differ | Why |
| --- | --- |
| funder, buyer | `_requireHolderRole` rejects a funder that is also the buyer |
| facilityProtected, facilityChallenger | a facility cannot raise a conflict against itself |
| issuanceMinter, either holder | the temporary minter must be disposable, not outlive the ceremony |
| originator, buyer or either facility | `_validatePledge` rejects a caller that is also the originator |

It also refuses a participant without the A-Pass its role needs, without enough MON, or, for the
funder alone, without the aUSDC advance.

## Funding, which is what usually blocks a phase

Every signer needs MON. Six new addresses means six visits to the Monad faucet, one claim per
address per 24 hours, so start early.

Only the funder needs aUSDC, and only the advance. The faucet's aUSDC treasury was last observed
holding less than that, so the source has to be arranged before phase C1 rather than discovered
during it.

## Tests

**74 tests, including a full A to F execution on a fork** that proves the engines really change
state: the adapter is deployed and verified, its credential issued, the infrastructure configured,
the vault created, the supply ceremony run, activation settled at 90000 net proceeds and 10000 bond,
and both holders released their units with the MINV01 supply unchanged.

Also covered: a missing `--from` blocks a sub-action, incomplete inputs or readiness block it, a key
deriving the wrong signer blocks it, a `PENDING` artifact is written before each receipt is awaited,
resumption after each partial transaction, no sub-action triggering the next, and the named
refusals: a wrong contract hash, an unexpected readback, funder equal to buyer, identical
facilities, and an unexpected minter before binding.

Nothing broadcasts publicly.

## A correction the execution surfaced

Verifying a deployment by hashing its runtime bytecode **fails on any contract with `immutable`
fields**. The adapter burns its `token` and `apass` into the runtime at construction, so the
deployed bytes never equal the artifact's `deployedBytecode`, whose immutable slots are zero
placeholders.

`runtimeFingerprint` masks exactly the regions Foundry records before hashing, leaving the code
itself compared byte for byte. The M-14 manifest said "verify the runtime bytecode hash against the
frozen artifact"; taken literally that would have rejected every correct adapter deployment.

## Out of scope, and untouched

No Solidity change, no parameter change, no UI work, no public transaction, no A-Pass requested, and
no grant, mint, binding or deployment executed.
