# Governed recourse bridge, and what the deployed adapter actually pins

Status: **payload prepared, no live bridge transaction sent.**

Read alongside `src/lib/protection/governed-recourse-bridge.ts` and its tests.

## What was inspected

The deployed adapter at `0x27677c837287b060D285d5C90096f06fBe675938` on Monad
testnet (chain 10143) was read directly over RPC on 2026-08-06. Its immutables:

| Adapter immutable | Deployed value | What it actually is |
|---|---|---|
| `assetIdentityDigest` | `0x7613136e…c4c95c` | the real governed asset identity |
| `releaseMode` | `0x29d74d03…9600fa` | `keccak256("governed-decryptor-v1")` |
| `circuitHash` | `0xed716235…1b4f5b` | `keccak256("mordant.identity-full-fhe-256")` |
| `parameterFingerprint` | `0x7cf76ba5…811060` | `keccak256("mordant.bgv.identity-full-fhe-256.n15/v1")` |
| `releaseAuthorityId` | `0x130d6197…2d3651` | **unidentified** |
| `attestor` | `0xEe3260bA47D097DE5a8601107e1b83454593617c` | secp256k1 EIP-712 signer |

The retained A8 governed Ed25519 result carries, for the same case:

| Governed field | Value |
|---|---|
| `assetIdentity` | `sha256:7613136e…c4c95c` |
| `releaseMode` | `governed-decryptor-v1` (a string) |
| `circuitDigest` | `sha256:2c166039…addf2e` |
| `parameterFingerprint` | `sha256:d0f85e99…7c25d6` |
| `releaseAuthorityId` | `sha256:c2127640…665c3d` |
| `releaseAuthorityPublicKey` | `sfww+eg80N03kdzIV1V4aF4FUIHxzUqOhb2vK355AN8=` (Ed25519) |

## The two conventions do not agree

Only `assetIdentityDigest` is the same value on both sides.

`circuitHash` and `parameterFingerprint` pin **keccak hashes of label strings**,
while the governed result carries **sha256 digests of content**. These are
different values, not two spellings of one value. A bridge that put the governed
digest into those fields would be rejected by the adapter; a bridge that put the
keccak label hash in would be asserting the adapter checked the circuit when it
only checked a name. Both are recorded in `reconcileAdapter`, and neither is
silently substituted.

`releaseAuthorityId` matches nothing derivable from the governed authority. All of
the following were computed and none equals `0x130d6197…`:

- the raw 32 bytes of `sha256:c2127640…`
- `keccak256` of that digest, of its `sha256:`-prefixed text, and of its bare hex
- `keccak256` of the raw Ed25519 public key and of its base64 text
- `keccak256` of the attestor address
- `keccak256` of the plausible label strings

## Decision

**Option B — the adapter pins a separate bridge-attestor authority id.**

This is the only interpretation under which a payload can be built at all, and the
module records it on every payload as `authorityInterpretation`. Option A is
refused in code: `reconcileAdapter(release, pins, "PINS_GOVERNED_AUTHORITY")`
returns a mismatch and `buildGovernedBridgePayload` throws `ADAPTER_INCOMPATIBLE`.

**Option B is not confirmed, only permitted.** The constant `0x130d6197…` could
not be derived from anything, so nobody has yet shown it is a deliberate
bridge-attestor identity rather than an arbitrary value. Until the contract agent
states its provenance, treat the deployed adapter as **unconfirmed**, and do not
describe a consumed release as carrying the governed release authority on-chain.

The governed Ed25519 `releaseAuthorityId` is **not** currently carried in the
payload at all. Under option B it must be, and the adapter's twenty-field struct
has no member for it. That is the minimal contract correction below.

## Minimal contract correction (for the contract agent; not applied here)

Either:

1. **Redeploy pinning the real authority.** Construct with
   `initialReleaseAuthorityId = 0xc21276405a249b7c178914508d99e9f0286ce29e5e3bb085ad3697f0cc665c3d`,
   `initialCircuitHash = 0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e`
   and `initialParameterFingerprint = 0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6`.
   Then option A holds, nothing about the struct changes, and the runtime flips one
   argument. This is the smaller change and the honest one.

2. **Or keep the bridge-attestor pin and add one field**, e.g.
   `bytes32 governedReleaseAuthorityId`, to `GovernedRelease`, checked against the
   governed result and covered by the signature. This changes `RELEASE_TYPEHASH`
   and therefore every digest, so the parity vector must be regenerated.

Option 1 is recommended. Option 2 is a schema change under deadline.

## EIP-712 compatibility gate: PASS

One canonical `GovernedRelease` payload was built from the retained governed
result, hashed independently with viem, and compared against the deployed
`hashRelease` view over RPC:

```
viem local    : 0xcaadf3c23d8237f77804d7f9dc4ba2bb490d36a319d54c523dcb24b50e086f3b
solidity view : 0xcaadf3c23d8237f77804d7f9dc4ba2bb490d36a319d54c523dcb24b50e086f3b
BYTE-IDENTICAL: true
```

`RELEASE_TYPEHASH` also matches the deployed constant
(`0x5e5f1a6c601ddff4a7d452bf8cf5c106c0efb68a0d0e17832da59c95a6ac0a8d`), and a
second, independent struct-hash implementation in the module agrees with the
typed-data path. The vector is retained as a regression fixture in
`governed-recourse-bridge.test.ts`, and every one of the twenty fields plus the
chain id and verifying contract is proven to change the digest when mutated.

So the **encoding** is compatible. The **semantics** are not, and that is the open
item.

## What the bridge refuses

- No payload before the Ed25519 governed signature and every cross-reference are
  verified: both are required literal `true` arguments, not computed booleans.
- `conflict` is read from the verified governed result. There is no parameter
  through which a caller, browser or otherwise, could supply it.
- A false Boolean carrying a payout, and a true Boolean without one, are refused.
- No adapter address is hard-coded; a test asserts the module contains no
  40-hex-character address at all.

## Before any live transaction

Not done here, and required first:

1. the contract agent states the provenance of `0x130d6197…`, or redeploys per
   correction 1;
2. the bridge attestor key for `0xEe3260bA…` is held somewhere the runtime can
   sign from, under stated custody;
3. bounded testnet amounts only;
4. `MINV01` is confirmed unchanged before and after;
5. `ReleaseConsumed` and the resulting case state are read back and retained.
