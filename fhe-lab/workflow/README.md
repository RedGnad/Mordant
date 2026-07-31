# Controlled local adapter acceptance workflow

This isolated `controlled-local-anvil` harness proves that a complete provider-neutral public
result and its provider-proof evidence can be canonically checked, endorsed by a 2-of-3 synthetic
validator quorum, accepted once by `ECDSAQuorumConfidentialPolicyVerifier`, and rejected on a second
submission to the **same** local chain.

It is not a Monad transaction. The Anvil chain is destroyed after each run. The proof commitment
binds the result ciphertext, threshold transcript, threshold session, threshold key epoch and policy
circuit into the signed result. It proves which evidence the validators endorsed; it does not prove
that the FHE evaluator computed honestly, modify a Mordant vault, or authorize funds.

The harness:

1. validates a strict public success envelope before starting Anvil;
2. recomputes the provider-proof and result commitments;
3. starts a fresh loopback Anvil process without forwarding account output;
4. deploys the provider-neutral verifier with three synthetic validator identities;
5. configures the supplied vault and monotone policy version;
6. signs the schema-2 EIP-712 result with two validators;
7. verifies and accepts it while checking event and consumption state;
8. submits the exact calldata again and requires a revert;
9. prints only public receipt and aggregate gas/latency data.

No private key is read by this harness: Anvil signs for unlocked synthetic accounts over loopback
RPC. Provider-specific ciphertext, pledge fields, raw shares and private values are rejected at the
JSON boundary.

## Prerequisite

```bash
forge build --root fhe-lab/monad-adapter
```

## Reproduce

The explicit shared fixture path is:

```bash
node fhe-lab/workflow/run.mjs --fixture
```

The actual Lattigo path is:

```bash
(cd fhe-lab/lattigo && go run ./cmd/workflow) \
  | node fhe-lab/workflow/run.mjs --stdin
```

`cmd/workflow` uses the public-only external client, signed-enrollment binary round trip, exact FHE
policy, two imported threshold operators, real signed threshold responses and the real
transcript/key/circuit commitments. It emits no plaintext pledge, ciphertext or share.

There is no implicit fixture or fallback. File input is also supported:

```bash
node fhe-lab/workflow/run.mjs --input /tmp/mordant-public-fhe-result.json
```

## Strict provider input

The success envelope is schema `mordant.fhe-provider-output/1` and contains exactly:

```text
ok: true
result: mordant.confidential-policy-result/2
providerProof: mordant.fhe-provider-proof/1
```

The public result includes the chain, vault, policy, ordered input commitments, Boolean, public
responsibility/deadline, nonce, expiry, `providerProofCommitment`, and `resultCommitment`. The
mandatory proof includes:

```text
resultCiphertextCommitment
thresholdTranscriptCommitment
thresholdSessionId
thresholdKeyCommitment
policyCircuitCommitment
providerProofCommitment
```

No field is defaulted and no unknown field is accepted. A missing/zero/mutated proof, private field,
ciphertext field, result mismatch, wrong chain, malformed number, inconsistent negative result or
provider failure is rejected before Anvil starts. `chainId` is fixed to `31337` in this local
harness.

## Public output

Successful stdout conforms to `mordant.fhe-adapter-workflow-metrics/2` and contains:

- public result commitment and conflict Boolean;
- verifier, transaction hash and block;
- replay key, decision key, attestation digest and validator-set ID;
- explicit synthetic 2-of-3 quorum status;
- proof binding, view/event/state checks and same-chain replay rejection;
- calldata bytes, gas and local latency.

The receipt is inspectable evidence for the destroyed local run, not a retained Monad receipt.
Failures print only a stable code, never a stack, input fragment, RPC body, plaintext or ciphertext.

## Test

```bash
node --test fhe-lab/workflow/workflow.test.mjs
```
