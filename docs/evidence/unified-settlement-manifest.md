# Unified settlement manifest

One governed case settled end to end on Monad testnet, with every economic term
committed before the case produced a result. Every hash below is complete, and
every step ran through the repository's own tooling.

## What the run proves

A governed Boolean says a conflict exists. It never says who gets paid, how much,
or out of which adapter. Those terms were fixed, and digest-bound, while the case
still had no outcome to react to. The chronology is the proof, so it is recorded
as timestamps on durable artifacts rather than asserted in prose.

## Chronology

| Order | Artifact | Time (UTC) |
|---|---|---|
| 1 | `public/case-binding.json` | `2026-08-10T02:00:38.324Z` |
| 2 | `settlement-profile.json` (commitment) | `2026-08-10T02:00:38.790Z` |
| 3 | `public/governed-conflict-result.json` | `2026-08-10T02:01:11.945Z` |
| 4 | `ReleaseConsumed` | block `52396208`, chain time `1786327583` |
| 5 | cure expiry | `1786328183` (600 seconds) |
| 6 | `finalize` | block `52398372` |
| 7 | Claim A | block `52398375` |
| 8 | Claim B | block `52398377` |

The commitment precedes the result by 33 seconds and precedes both participant
admissions. The store enforces this rather than trusting it: committing is
refused once any result-bearing artifact exists for the run.

## Case

| | |
|---|---|
| Run | `369ed70e-64e1-4427-9fc6-b899051a78a8` |
| Case code | `8AAE11AYNY95XND1` |
| Participant configuration | `docs/evidence/fresh-case-participant-config.json` |
| Configuration sha256 | `3b80cffa91fd251574198dde930defc0c2a0dc324c87195bdeb893494d857833` |
| Holder A | `0xDebC4C4BEF9B70008A9B043f8f6334401147634E` |
| Holder B | `0x3efa4046012Da8DaBfb3145693f7B58e04e86eD0` |
| Bridge attestor | `0x5Ac9373b011cA2b485d97A964Fc1f65eb44C9464` |
| Operator | `0x79C53151315FaD9163f75a65A8Bd4D04a10e1e45` |

Both holders were verified on chain before settlement: `isValidAPass` true and
`isEligible(ROLE_HOLDER)` true, admitted at block `52395083`.

## Committed terms and derived authority

| | |
|---|---|
| `settlementProfileDigest` | `0x4c35cf9d2cfdd2bd4879bee85ad2780e231854971085509061e227bf639465db` |
| Precommitted `releaseAuthorityId` | `sha256:55b7b86af18120998d7d9dcb8c4f287737188ee4250a32e49c5df3c1efe125f6` |
| Committed `caseBindingDigest` | `sha256:1054a779e4cdb903afad3476a240375f837c8d4a2fd30c11e9ce3c99b79ce904` |
| Committed payouts | 1 and 1 atomic aUSDC |
| Committed cure window | 600 seconds |
| Committed adapter | `0x41AA168FD1A288a7Ec63C5c886DD469E96F7c2Aa` |
| `planHash` | `0x76eae944038c7f0412c712969a593afec8fa6e143c4484672f3dd31c4a61bcac` |
| Bridge evidence digest | `sha256:9daca6366d9bf69e398315c03d1c0932bc2b1479efb65d32134f93d4a7fa945f` |

The governed result carried exactly the precommitted authority and the
precommitted case binding. The adapter deployed to exactly the committed address,
which the profile had named before the case produced anything.

## Transactions

| Step | Hash |
|---|---|
| Adapter deployment | `0x32d82d6a2640678d77d1164d03291c7d23f43ab10dc580465eb55b0c600be7f0` |
| aUSDC approve | `0xab03b0553e5981fb817eabc5402a743bf09802eed6a7d93e6a3ee9c39b2087b7` |
| `fundReserve(2)` | `0x430976cfd33edd5bd49a3d499ea31f186ef9893f630842c8b0243f4eb77e6cbc` |
| `ReleaseConsumed` | `0xcb260321131050381229d2ecc501cc07879c1f4101a2ea40311b3d73a5b7b9dc` |
| `finalize` | `0xee16381c920134fb4c3e8815625ebb5f129232c6cce95b8c0dff69c21b25e7e2` |
| Claim A | `0x7e0924d6c3f593bbf9bf06e029c8bb208fa074152153cae1912824a7e9393b9c` |
| Claim B | `0x652b718e335454874c3ca7928a1eff16a9b06367a3cfa16f8ec9acaaac36f995` |

Adapter runtime: `0x41AA168FD1A288a7Ec63C5c886DD469E96F7c2Aa`, reviewed artifact
masked hash `0x0d1cd7dd147bfd6e07d375542fed725a40469919d837e6a9662f7cab68d2e9c2`,
immutables matching the plan.

## Reconciliation

| | |
|---|---|
| Holder A delta | `+1` (expected `+1`) |
| Holder B delta | `+1` (expected `+1`) |
| Adapter delta | `-2` (expected `-2`) |
| `availableReserve` | `0` |
| `openReserved` | `0` |
| `entitledUnpaid` | `0` |
| Case state | `Claimed`, `paidA` and `paidB` true |
| Verdict | **exact** |

## How it ran

Through the repository's own tooling, in this order:

```
scripts/unified-settlement-run.mjs        commit before admissions, then the case
scripts/build-bridge-evidence.mjs         assemble the bridge evidence
scripts/activation-case-adapter.mjs       --plan, --deploy, --configure
scripts/activation-bridge-consume.mjs     prepareDirect -> simulate -> sign
scripts/activation-terminal-recourse.mjs  finalize, Claim A, Claim B, reconcile
```

`activation-bridge-consume` reaches the settlement-authority gate before the
attestor capability is loaded. A paying release with no matching authorization is
refused there, and the refusal happens before any signing material is touched.

## Boundaries

The reviewed-artifact registry is an allowlist of two explicitly reviewed
runtimes, not a rule that tolerates rebuilds. They differ in 32 bytes, all inside
the Solidity CBOR metadata trailer at `10045-10076`; the 10,035 executable bytes
are byte-identical. A third build is refused until it is reviewed and pinned.

The retained participant configuration and its hash are unchanged, and the
managed policy `mordant.managed-demo.facility-protection@1` remains
`settlementAuthorization = NOT_AUTHORIZED`.
