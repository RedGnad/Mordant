# Monad aUSDC revalidation

Read-only revalidation. No key, no signature, no transfer and no broadcast. A passing read is not a settlement: no transfer has been sent, so the rail stays NOT PROVEN.

Trigger: Confirmation from a Cleanverse internal developer in the community channel that Monad aUSDC now works. Every statement in this artifact is independently re-observed on chain.

| Field | Value |
| --- | --- |
| generatedAt | 2026-07-28T16:09:02.609Z |
| chainId | 10143 |
| blockNumber | 48863446 |
| blockHash | 0x378b7c8696c3df368f76dfc215f84eb268b122d4722a9d5f123ad6a761550be7 |
| aUSDC | 0xaC0893567D43C3E7e6e35a72803df05416C1f20D |
| discovery source | cleanverse query_deposit_atoken_list |
| address changed | false |

## Status

| Statement | Value |
| --- | --- |
| AUSDC ADDRESS | DISCOVERED |
| AUSDC IMPLEMENTATION | UNCHANGED |
| AUSDC VERIFY_APASS | PASSED |
| AUSDC CAN_TRANSFER | PASSED |
| AUSDC READ-ONLY COMPATIBILITY | RESTORED |
| AUSDC SETTLEMENT TRANSFER | NOT PROVEN — NO TRANSACTION SENT |
| CLEANVERSE SETTLEMENT RAIL | NOT PROVEN |

## Contract shape, against the M-01C baseline

| Field | Now | M-01C baseline | Changed |
| --- | --- | --- | --- |
| aUSDC implementation | 0x5a520e9992d30416c33e2dcdc2d8f3befce426da | 0x5a520e9992d30416c33e2dcdc2d8f3befce426da | false |
| policy implementation | 0xc644e79e4c8ee94c4dee49b76f8591e994e58101 | 0xc644e79e4c8ee94c4dee49b76f8591e994e58101 | false |
| getRules length | 0 | 0 | false |
| isTokenRegistered | true | true | false |
| isPaused | false | false | false |

## A-Pass state of the probed wallets

| Wallet | Address | isValidAPass | Status | Tier | SubTier | Expiry | Expired |
| --- | --- | --- | --- | --- | --- | --- | --- |
| burn address | 0x000000000000000000000000000000000000dead | true | 1 | 20 | 0 | 1813232978 | false |
| tier 20 / subTier 50 | 0x1111111111111111111111111111111111111111 | true | 1 | 20 | 50 | 1876052540 | false |
| fee receiver, tier 5 | 0x7f7098632b0258Af07e527015D65e6bc743f4CF5 | true | 1 | 5 | 0 | 0 | null |

## verify_apass

| Token | Wallet | Verdict | Passed |
| --- | --- | --- | --- |
| aUSDC | 0x000000000000000000000000000000000000dead | code 4 "apass verify success" | true |
| aUSDC | 0x1111111111111111111111111111111111111111 | code 4 "apass verify success" | true |
| aUSDC | 0x7f7098632b0258Af07e527015D65e6bc743f4CF5 | code 4 "apass verify success" | true |
| SPT0001 | 0x000000000000000000000000000000000000dead | code 4 "apass verify success" | true |
| SPT0001 | 0x1111111111111111111111111111111111111111 | code 4 "apass verify success" | true |
| SPT0001 | 0x7f7098632b0258Af07e527015D65e6bc743f4CF5 | code 4 "apass verify success" | true |
| mXAUt0 | 0x000000000000000000000000000000000000dead | code 4 "apass verify success" | true |
| mXAUt0 | 0x1111111111111111111111111111111111111111 | code 4 "apass verify success" | true |
| mXAUt0 | 0x7f7098632b0258Af07e527015D65e6bc743f4CF5 | code 4 "apass verify success" | true |
| CCUSD2 | 0x000000000000000000000000000000000000dead | code 4 "apass verify success" | true |
| CCUSD2 | 0x1111111111111111111111111111111111111111 | code 4 "apass verify success" | true |
| CCUSD2 | 0x7f7098632b0258Af07e527015D65e6bc743f4CF5 | code 4 "apass verify success" | true |

## policy().canTransfer(token, from, to, 1)

| Token | Tuple | Verdict | Passed |
| --- | --- | --- | --- |
| aUSDC | A-Pass holder to A-Pass holder | returned true | true |
| aUSDC | A-Pass holder to fee receiver | returned true | true |
| aUSDC | AccessCore to A-Pass holder | revert NoAPass(address) | false |
| SPT0001 | A-Pass holder to A-Pass holder | returned true | true |
| SPT0001 | A-Pass holder to fee receiver | returned true | true |
| SPT0001 | AccessCore to A-Pass holder | revert NoAPass(address) | false |
| mXAUt0 | A-Pass holder to A-Pass holder | returned true | true |
| mXAUt0 | A-Pass holder to fee receiver | returned true | true |
| mXAUt0 | AccessCore to A-Pass holder | revert NoAPass(address) | false |
| CCUSD2 | A-Pass holder to A-Pass holder | returned true | true |
| CCUSD2 | A-Pass holder to fee receiver | returned true | true |
| CCUSD2 | AccessCore to A-Pass holder | revert NoAPass(address) | false |

## Comparison

Before, M-01C at block 48672798: verify_apass ComplianceFailed, canTransfer revert ComplianceFailed(0x8a4e1859).

Now, block 48863446: verify_apass PASSED, canTransfer PASSED.

The read-only surface changed. That is not a settlement: no transfer was sent.

## Historical replay

A pass at head proves nothing by itself. The same call is replayed against historical state, so a genuine change is separated from a probe that merely differs from the M-01C one.

| Replay | Block tag | Verdict | Passed |
| --- | --- | --- | --- |
| aUSDC at the M-01C block | 0x2e6b01e | revert ComplianceFailed(address) | false |
| aUSDC one block before the transition | 0x2e8fd92 | revert ComplianceFailed(address) | false |
| aUSDC at the transition block | 0x2e8fd93 | returned true | true |
| SPT0001 at the M-01C block | 0x2e6b01e | returned true | true |

The M-01C failure reproduces exactly at the M-01C block, so it was not a probe error.

## What changed

| Field | Value |
| --- | --- |
| transaction | 0xbffeda811e919a0205580b950039ace6dc8b7c388c49412452cd34546b2f5c59 |
| block | 48823699 |
| selector | 0x3762dd01 |
| indexed argument | 0xac0893567d43c3e7e6e35a72803df05416c1f20d |
| re-verified this run | true |

OBSERVED: A configuration call sent to the policy, not a code upgrade: both implementation code hashes are unchanged and canTransfer flips at exactly this block.

INFERRED: The six scalar arguments (0, 0, 5, 0, 0, 0) match the documented validator rule shape with min_tier = 5. The selector was not decoded from a published ABI, so the field mapping is INFERRED, not proven.

NOT EXPOSED: getRules(aUSDC) returns an empty array before and after, so the accepting configuration is not readable through getRules.

## Notes

- The AccessCore-as-sender tuple reverts NoAPass(address) for aUSDC and for all three control tokens alike, so it is a property of that sender holding no A-Pass, not of aUSDC.
- The two implementation code hashes are unchanged since M-01C. Behaviour changed without any code changing.
