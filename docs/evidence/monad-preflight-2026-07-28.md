# Monad deployment preflight

Read-only. No private key was used, nothing was signed and no transaction was broadcast.
A passing gas estimate means the RPC would accept the creation payload; it is not a deployment.

| Field | Value |
| --- | --- |
| generatedAt | 2026-07-28T10:48:59.751Z |
| repositoryCommit | 509c6827f1b804d95356ef7f52c524be36de63e8 |
| compiler | 0.8.28+commit.7893614a |
| rpcEndpoint | https://testnet-rpc.monad.xyz |
| chainId | 10143 |
| blockNumber | 48802500 |
| blockHash | 0x17b37157c8c130a1e715ba3e25016ec2a968c52cc8e4da350e226b4c984b2e0a |

## Status

| Statement | Value |
| --- | --- |
| MONAD SIZE LIMIT | WITHIN DOCUMENTED LIMIT |
| MONAD RPC PREFLIGHT | PASSED |
| MONAD FACTORY CREATION | READ-ONLY RPC SIMULATION |
| MONAD FACTORY → VAULT CREATION | FORK |
| MONAD DEPLOYMENT | NOT PROVEN — NO TRANSACTION BROADCAST |
| STANDARD EVM PORTABILITY | BLOCKED BY EIP-170 |

## Sizes and estimates

| Contract | Init code B | Runtime B | Monad limit | EIP-170 | Estimated gas | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CleanverseAPassVerifier | 3430 | 2902 | within | within | 731686 | PASSED |
| CleanverseCvaAdapter | 9717 | 8904 | within | within | 2061135 | PASSED |
| MordantFactory | 40897 | 40382 | within | EXCEEDS | 8828004 | PASSED |
| MordantInvoiceVault | 35248 | 31312 | within | EXCEEDS | n/a | NOT DIRECTLY CONSTRUCTIBLE |

Monad documented limits: 131072 bytes of runtime code and
262144 bytes of init code. Ethereum EIP-170: 24576 bytes.

## Probes

| Contract | Method | Result | Classification |
| --- | --- | --- | --- |
| CleanverseAPassVerifier | eth_estimateGas | 731686 gas | READ-ONLY RPC SIMULATION |
| CleanverseAPassVerifier | eth_call | returned 2902 bytes of runtime code, matching the compiled runtime | READ-ONLY RPC SIMULATION |
| CleanverseAPassVerifier | debug_traceCall | trace returned | READ-ONLY RPC SIMULATION |
| CleanverseCvaAdapter | eth_estimateGas | 2061135 gas | READ-ONLY RPC SIMULATION |
| CleanverseCvaAdapter | eth_call | returned 8904 bytes of runtime code, matching the compiled runtime | READ-ONLY RPC SIMULATION |
| CleanverseCvaAdapter | debug_traceCall | trace returned | READ-ONLY RPC SIMULATION |
| MordantFactory | eth_estimateGas | 8828004 gas | READ-ONLY RPC SIMULATION |
| MordantFactory | eth_call | returned 40382 bytes of runtime code, matching the compiled runtime | READ-ONLY RPC SIMULATION |
| MordantFactory | debug_traceCall | trace returned | READ-ONLY RPC SIMULATION |
| MordantInvoiceVault | not-attempted | Not directly constructible against a remote RPC: the constructor calls asset() on a CVA adapter that is not deployed on Monad, and inventing one would fabricate state. The vault is created by the factory, which is covered separately. | FAILED |

## Constructor arguments

| Contract | Arguments | Why |
| --- | --- | --- |
| CleanverseAPassVerifier | 0x000000000000000000000000000000000000d341, 0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9, 16 | Owner is the simulation caller; the A-Pass argument is the live Monad A-Pass, which the constructor requires to carry bytecode. |
| CleanverseCvaAdapter | 0x000000000000000000000000000000000000d341, 0x6cbA1135f61BA24867Ef125eFcA46fC7f9FDa835, 0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9 | The token argument is an existing Monad A-Token used only because the constructor requires a code-bearing address. The judged deployment will use the freshly issued invoice A-Token. |
| MordantFactory | 0x000000000000000000000000000000000000d341, 0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9 | The verifier argument is a placeholder that only satisfies the constructor's code-length check. The real deployment passes the CleanverseAPassVerifier deployed one step earlier, whose address cannot exist before that deployment. |
| MordantInvoiceVault | not directly constructible | Not directly constructible against a remote RPC: the constructor calls asset() on a CVA adapter that is not deployed on Monad, and inventing one would fabricate state. The vault is created by the factory, which is covered separately. |
