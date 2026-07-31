# Monad findings

## What Monad provides

Monad preserves EVM bytecode and Ethereum RPC compatibility, so a provider-neutral Solidity
verifier can use ordinary domain-separated hashes and ECDSA signatures without a chain-specific
cryptographic SDK.

- overview and compatibility: <https://docs.monad.xyz/>
- JSON-RPC: <https://docs.monad.xyz/reference/json-rpc/api>
- network IDs and protocol limits: <https://docs.monad.xyz/developer-essentials/changelog>

Current documented chain IDs are `143` for mainnet and `10143` for testnet. The documented
per-transaction gas limit is 30 million gas.

Monad Execution Events can reduce event-to-policy latency for an operator running the required node
configuration:

<https://docs.monad.xyz/guides/execution-events>

They are an event-consumption mechanism. They do not prove that an offchain FHE evaluation or
threshold decryption was correct.

## What the lab must provide

No official Monad primitive found in the reviewed documentation supplies an application FHE
coprocessor, ciphertext ACL, threshold key service, or attestation of arbitrary offchain
computation. EVM compatibility alone does not create those components.

The lab therefore submits only a compact public result and a provider-neutral quorum attestation:

```text
Monad event or authorized input
        -> FHE policy session
        -> one-time threshold decryption
        -> validator quorum over the exact result digest
        -> Monad verifier
```

The verifier binds the result to the live chain ID, verifier contract, vault, versioned policy,
both input commitments, nonce, and expiry. A stateful acceptance method consumes the result digest
and nonce before a future vault adapter can act on it.

## Explicit limitation

Quorum signatures authenticate who endorsed the result; they are not a proof of correct FHE
execution. A production path still needs either independently operated decryptors with governance
and liability, verifiable computation, a defensible TEE attestation, or a coprocessor network with
stronger correctness guarantees.
