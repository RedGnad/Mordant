# V4 threat model: Private Conflict Discovery

Base commit `e5eac8e`. Mode A (V3, anchored recourse) and every V3 contract, artifact and
transaction are unchanged and remain the shipping path. V4 is parallel.

## Gate 1 — Public-correlation audit

Every field below is readable by anyone with an RPC endpoint, verified against the live anchor
`0x317689100AcBE3b86B0869D522D0D8579Cfed7F1` on Monad testnet.

| Field | Source | Observable |
|---|---|---|
| contract address | deployment | yes |
| `invoiceRoot` | vault immutable **and indexed topic** of `InvoiceVaultCreated` | yes |
| factory binding | `vault.factory()` | yes |
| token name / symbol | `"Mordant Invoice Units"` / `"mINV"` — **constant across every Mordant vault** | yes |
| `buyer` (debtor) | vault immutable + event data | yes |
| `originatorTreasury` (seller) | vault immutable + event data | yes |
| `currency` | vault immutable | yes |
| `faceValue` | vault immutable | yes |
| `advanceAmount`, `initialUnits`, `bondBps` | vault immutables | yes |
| `protectionEnd`, `revealPeriod`, `curePeriod` | vault immutables | yes |
| creation event | `InvoiceVaultCreated(bytes32 indexed invoiceRoot, ...)` | yes |
| transaction sender | receipt | yes |
| policy / consumer config | verifier + consumer readbacks | yes |

Creation event topic0 `0x124b845bb120110fc2cca6ee7c27b47d4a2794fb3a0233418593b45875bfa034`.

### Scenario classification

**Two `MordantInvoiceVault` instances, same `invoiceRoot`** — `invoiceRoot` is an indexed topic. One
`eth_getLogs` filter correlates them. → **PUBLICLY CORRELATABLE. Not implementable.**

**Two `MordantInvoiceVault` instances, different local roots (Candidate B)** — the roots differ, but
the same economic asset forces the same `faceValue`, the same `currency`, and the same debtor. A
join on `(buyer, faceValue, currency)` over all vaults from one factory correlates them without any
cryptography, and `protectionEnd` clustering narrows it further. Withholding the debtor address is
not available: `buyer` is a constructor argument the factory emits and the vault exposes.
→ **PUBLICLY CORRELATABLE.** Rejected, exactly as the owner warned.

**One public anchor + one platform-private pledge (Candidate A)** — there is no second on-chain
object. The anchor exists for its own reason (it was financed on-chain), and the counterparty's
claim lives only inside a second platform's book. An observer has nothing to join against.
→ **GENUINELY PRIVATE MATCH.**

**Both sides private, anchor created after matching (Candidate C)** — also genuinely private, but no
anchor exists at match time, so there is no on-chain position for recourse to protect, and binding
requires a full vault activation (buyer, originator, CVA, settlement) triggered by a match. Lower
customer value, larger lift.
→ **GENUINELY PRIVATE MATCH**, deferred.

**Encrypting the receivable id while both enrollments name the same vault** — the M-PRIV5A/5C
finding: V3 requires a cleartext shared `InputContext.Vault`. → **INVALID DIFFERENTIATOR.**

## Gate 2 — Selected first vertical: Candidate A

**Cross-boundary duplicate financing.** An invoice is financed on-chain through a Mordant vault and
simultaneously pledged to a second platform (a traditional factor, a bank facility, another
tokenization platform) that has no on-chain footprint. This is the dominant real receivables fraud
pattern, and it is the case where no public metadata exists to correlate, because only one side is
public at all.

Candidate A wins on every stated criterion: genuine information hiding (nothing to correlate),
customer value (the actual fraud), credible binding (a real deployed anchor already exists),
compatibility with real workflows (one side is ordinary off-chain factoring), and differentiation
(no access-control design reaches it, see below).

## What equality is computed, and its entropy

Both platforms independently derive a canonical economic-asset identity from invoice facts they each
already hold:

```text
assetId = H(domain ‖ debtorId ‖ sellerId ‖ invoiceNumber ‖ currency ‖ faceValue ‖ issueDate)
```

The FHE circuit computes `assetId_A == assetId_B` over 256-bit encrypted values
(`IdentityFullFHE256`), then ANDs it with the existing confidential policy (currency equality,
strict interval overlap, exclusivity).

**`assetId` is not high-entropy and must not be claimed to be.** Its inputs are structured and
partially guessable. FHE hides it from the evaluator and from the operators; it does not make it
unguessable by someone who knows the invoice. Every anti-probing control therefore carries real
weight — see `V4-ANTI-PROBING.md`.

## Adversaries

| Adversary | Capability | Controlled by |
|---|---|---|
| **Shared evaluator** | sees ciphertexts, enrollments, scope commitments, session pairing | holds no key share (dealerless ceremony); learns only the released Boolean |
| **Threshold operator** | one Shamir share | 2-of-3 needed; a single operator releases nothing |
| **Coalition of 2 operators** | can release the Boolean for a session | learns the Boolean, never the identifiers |
| **Authorized prober** | may submit real, budgeted queries | budgets, mutual-session initiation, one-shot nonces |
| **Public observer** | full chain history | sees one anchor that already existed; no pre-binding artifact |
| **Malicious binder** | holds a valid result | mapping attestation + one-shot match commitment |

## Trust boundary changes versus Mode A

| Property | Mode A (proven) | Mode B |
|---|---|---|
| Evaluator learns the receivable | **yes**, vault in cleartext | no |
| Evaluator learns commercial terms | no | no |
| Same-asset linkage visible pre-evaluation | **yes** | no |
| Public artifact before a positive binding | yes (the recourse tx) | **none** |
| New trusted assertion | none | **issuer maps anchor → assetId commitment** |
| Anti-probing required | no | **yes, load-bearing** |

## Source-truth assumptions

V4 adds exactly one new trusted assertion, and it must be stated plainly:

> **The platform issuer asserts that on-chain anchor `V` corresponds to the canonical economic-asset
> identity committed as `assetIdCommitment`.**

Nothing on-chain can verify that mapping, because the anchor's public `invoiceRoot` is deliberately
*not* equal to `assetId` — if it were, the match would be publicly computable and the whole mode
would collapse to PUBLICLY CORRELATABLE. The issuer is trusted for the mapping only; it is not
trusted for the match itself, which is computed under encryption, nor for the policy result, which
the 2-of-3 quorum attests.

This is a genuine new assumption relative to V3 and requires explicit owner acceptance.

## What FHE provides that encryption and access control cannot

- **Ordinary encryption** requires a decryptor. Whoever holds that key learns both platforms' asset
  identities — precisely the disclosure both refuse.
- **Access control on a shared registry** relocates the same disclosure to the registry operator and
  forces each platform to upload its book into a competitor-adjacent dependency.
- **Plain hashed-identifier exchange** fails on entropy: `assetId` inputs are structured, so an
  unsalted hash is enumerable, and a shared salt is exactly what the parties will not agree.
- **FHE is required because the evaluator must compute an equality over data it may never see**, and
  the operators holding the key shares are not the parties and never see plaintext either. Only a
  bounded Boolean escapes, through a 2-of-3 threshold release.

## Honest scope limit found by this analysis

Open-book screening — "platform 1 asks the network whether anyone already financed invoice X before
financing it" — **is a probing oracle by construction**, because it lets one party test identifiers
against a standing corpus. The defensible first vertical is therefore **bilateral, mutually
initiated dispute resolution**: both platforms already suspect a conflict and agree to test it
without revealing books. This limits the product and is stated rather than hidden. Open-book
screening needs a different primitive (rate-limited PSI with accepted leakage) and is out of scope.
