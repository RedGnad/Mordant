# Controlled local adapter acceptance workflow

This is an isolated `controlled-local-anvil` harness. It proves that a complete provider-neutral
public result can be canonically checked, endorsed by a 2-of-3 synthetic validator quorum, accepted
once by `ECDSAQuorumConfidentialPolicyVerifier`, and rejected on a second submission to the **same**
local chain.

It is not a Monad transaction. The Anvil chain is destroyed after each run. The synthetic signers do
not prove that the FHE computation or threshold decryption was correct, do not modify a Mordant vault,
and do not authorize funds. Until the Lattigo proof format is frozen and bound to the attestation,
this harness measures only the public-result-to-local-EVM adapter path.

The harness:

1. validates a strict public success envelope before starting Anvil;
2. starts a fresh loopback Anvil process and suppresses its account output;
3. deploys the Foundry verifier artifact with three Anvil-owned synthetic identities;
4. configures the supplied vault and policy version;
5. independently recomputes `resultCommitment` and rejects a mismatch;
6. signs the nested EIP-712 attestation with two synthetic identities;
7. verifies and accepts the result, checking its event and replay/decision state;
8. submits the exact calldata again and requires that transaction to revert;
9. prints only public receipt data plus aggregate calldata, gas, and latency metrics.

No private key is read by the harness: Anvil signs for unlocked synthetic accounts over loopback RPC.
Anvil stdout/stderr are not forwarded. Provider-specific ciphertext, pledge fields, and private
values are rejected at the JSON boundary and must never be passed to this process.

## Prerequisite

Build the isolated adapter artifact:

```bash
forge build --root fhe-lab/monad-adapter
```

## Explicit fixture run

There is no implicit fixture or fallback. The shared canonical vector is used only with:

```bash
node fhe-lab/workflow/run.mjs --fixture
```

An empty input, provider failure, missing result field, unknown field, plaintext field, ciphertext
field, or mismatched result commitment fails closed with a stable error code.

## Provider input

Use a public JSON file:

```bash
node fhe-lab/workflow/run.mjs --input /tmp/mordant-public-fhe-result.json
```

Or pipe the public result:

```bash
provider-command | node fhe-lab/workflow/run.mjs --stdin
```

The exact success envelope is:

```json
{
  "schemaVersion": "mordant.fhe-provider-output/1",
  "ok": true,
  "result": {
    "schemaVersion": "mordant.confidential-policy-result/1",
    "chainId": "31337",
    "vault": "0x1111111111111111111111111111111111111111",
    "policyId": "0xbd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540",
    "policyVersion": "1",
    "inputCommitmentA": "0x82118156ab9ee2b2c4f500e0ef4ce6e1dd35ebad13421fd5f4ccb78b941f6725",
    "inputCommitmentB": "0x9dc2a7820edf7ac4700c85d114c655081bd799e9104de27e2fff0de7092a07fb",
    "conflictConfirmed": true,
    "responsibleRole": "0xe4e507c0331021261ae219c736aa71977a41f814117a0ea4f6bd31faf50d2674",
    "cureDeadline": "2000003600",
    "nonce": "7",
    "validUntil": "2000000300",
    "resultCommitment": "0x5bb7f768cc7fd197475701d1d8385bd15cac6b6b7dc1f655956c801798355477"
  }
}
```

No field is defaulted. No unknown field is accepted. `chainId` is fixed to the local chain ID
`31337`; a different chain is rejected. Negative results require zero role and deadline, while
positive results require both to be nonzero.

An optional provisional proof reference is accepted only in this strict shape:

```json
{
  "schemaVersion": "mordant.fhe-provider-proof/0",
  "transcriptCommitment": "0x0000000000000000000000000000000000000000000000000000000000000001"
}
```

It is optional, explicitly reported as not bound to the EIP-712 attestation, and establishes no
computation-authenticity claim. Its final format will follow the Lattigo runner rather than being
invented here.

## Public output

Successful stdout conforms to `mordant.fhe-adapter-workflow-metrics/1` and names its environment
`controlled-local-anvil`. It contains:

- the public result commitment and conflict Boolean;
- verifier address, accepted transaction hash and block;
- replay key, decision key, attestation digest, and validator-set ID;
- explicit synthetic 2-of-3 quorum status;
- digest, view, event, state-consumption, and same-chain replay-rejection checks;
- acceptance calldata bytes;
- deployment, policy-configuration, and result-acceptance gas;
- local view, acceptance, and result-to-accept latency.

The receipt fields make the completed local run inspectable, but they do not turn the destroyed
Anvil chain into retained evidence or a Monad receipt. Monad testnet latency remains unmeasured.

Failures print only a stable error code, never a stack, input fragment, RPC body, key, plaintext, or
ciphertext.

## Test

```bash
node --test fhe-lab/workflow/workflow.test.mjs
```
