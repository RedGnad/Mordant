# Governed recourse bridge V2

Status: **the reviewed reference deployment and its pins.** A governed release has
since been submitted and consumed for real, on a case-specific deployment of this
same reviewed contract: run `e618abc2-0ac7-4d79-b201-44959a54b68c` on adapter
`0x9cD93089E02d301BDdfC86EaAbB39242272cAfa1`. See
[`direct-participant-bridge-evidence.md`](./direct-participant-bridge-evidence.md).

A case-specific adapter is required rather than optional: the governed release
authority is minted per FHE case and Adapter V2 pins it as an immutable, so each
run needs its own deployment of the reviewed source. That is why the address below
is the reviewed reference rather than the address any given run settles on, and
why identity is carried by masked-bytecode equality plus a deployment proof rather
than by a fixed address.

The reference deployment is `MordantRecourseAdapter` V2 at
`0xbe67DB4F8a1a884C809884eA45c4dD4376B01b18` on Monad testnet (chain `10143`).
The superseded V1 adapter `0x27677c837287b060D285d5C90096f06fBe675938` is retained
only in historical evidence, and the executor refuses it by address.

The authoritative configuration is
`docs/evidence/recourse-v2-demo-config-2026-08-06.json`. The runtime/contract
cross-check and the canonical EIP-712 vector are retained in
`docs/evidence/runtime-contract-handoff-2026-08-06.json`.

## V2 pins

| Adapter field | Required value |
|---|---|
| Chain ID | `10143` |
| Adapter | `0xbe67DB4F8a1a884C809884eA45c4dD4376B01b18` |
| Settlement token | `0xaC0893567D43C3E7e6e35a72803df05416C1f20D` |
| CVI verifier | `0xCFFA4cbF5117718EB7fC0dE2E13E07ce75B840aB` |
| Facility | `0x344412229B3b581C19572f9BF1F5d08d4Ae897E6` |
| Bridge attestor | `0xEe3260bA47D097DE5a8601107e1b83454593617c` |
| Governed authority | `0xc21276405a249b7c178914508d99e9f0286ce29e5e3bb085ad3697f0cc665c3d` |
| Asset identity | `0x7613136ebe7efb777c78cdf8bd73a5a3e5604b005875e05e1427cce9dbc4c95c` |
| Release mode | `0x29d74d033f25761ba7e8fbb0e872d7420cb42498951e9a85e3993b7ef59600fa` |
| Circuit digest | `0x2c16603974671e3de32f9023f0e205bedeb0e0553e663d12c37e42822aaddf2e` |
| Parameter fingerprint | `0xd0f85e99048a71163f218e8a6e12e7c21ddd5188527ae637a3b9cd16ff7c25d6` |

The governed authority is the Ed25519 authority identified by the governed
result. The bridge attestor is a separate secp256k1 signer used only to attest the
EIP-712 payload understood by the EVM. Adapter V2 checks the governed-authority
identifier as signed data; it does not verify the Ed25519 signature itself. The
server must therefore verify that signature and all governed-result cross
references before it can prepare anything for simulation.

## Canonical participants and reserve

The only qualified participant mapping for this preflight is:

- participant A / holder A:
  `0x3883CbE36BE79bd8d1b73ff160B8E7c3CB983685`, payout `2400` atomic aUSDC;
- participant B / holder B:
  `0x3DcF732b35406Cf5C115Bc0f5D40918DFD2aCdc9`, payout `1600` atomic aUSDC;
- facility: `0x344412229B3b581C19572f9BF1F5d08d4Ae897E6`;
- required available reserve: `4000` atomic aUSDC.

The negative control `0x981F6E0Ea94f45fDB8ee7680DC862212E3C720e0`
and uncontrolled A-Pass wallet
`0x911F99f424D47F08a15fcC771e94dcc2f7252B02` are always excluded. A valid
A-Pass alone does not establish wallet control or authorize participation.

## Runtime boundary

Browser input cannot choose the adapter, holders, payouts, terminal Boolean, or
configuration pins. A direct participant case is admissible only when all
server-side capability gates pass and each verified wallet matches its canonical
role. The existing Go pledge schema, BGV circuit, governed-result schema, and V2
protection binding remain unchanged. Verified participant authorization and
claim commitments are carried in the pledge's existing commitment fields.

The bridge loads the committed configuration itself. It refuses configuration
drift, excluded participants, an already-consumed result, failed eligibility,
insufficient reserve, pin mismatches, or a Viem/Solidity `hashRelease` mismatch.
Prepared and simulated values are opaque runtime capabilities rather than
caller-constructible signing inputs.

## Environment and key handling

The server-only bridge recognizes exactly these names:

- `MORDANT_MONAD_RPC_URL`
- `MORDANT_RECOURSE_ADAPTER_ADDRESS`
- `MORDANT_BRIDGE_ATTESTOR_PRIVATE_KEY`

Read-only compatibility checks need only the first two. They must never read the
attestor key. Signing configuration is loaded only inside the server-only signing
path; the key is non-enumerable, non-serializable, and never returned in a report.

RPC retry is bounded and applies only to idempotent reads, simulations, and
receipt polling. A state-changing call is never retried. This integration exposes
no broadcasting operation.

## Capability status

`DIRECT_PARTICIPANT_ADMISSION` defaults off and may be exposed only after every
runtime, canonical-configuration, wallet, and worker-origin gate passes.
`ONCHAIN_RECOURSE_CONNECTED` remains off for this preflight even when the
read-only V2 compatibility report passes. No reserve funding, release
submission, cure, finalization, or claim is performed by the integration.

The canonical vector has byte-identical Viem and Solidity release digests:
`0xdac5763c3e0020e89d83351db246aa27766337176e2091e189a6d6c1100bb88f`.
That proves encoding compatibility for the retained vector; it is not evidence
that a live release was submitted.
