# Cleanverse integration record

Status: API adapter implemented; one read-only sandbox probe verified; custom CVA mutation not yet
executed.

## Verified on 26 July 2026

The documented UAT base is `https://uatapi.cleanverse.com/api/cooperate`. A read-only call to
`POST /query_deposit_atoken_list` with `{"chain":"monad"}` returned a business-success envelope
(`code = 0000`) and one supported pair:

- USDC `0x534b2f3A21130d7a60830c2Df862319e593943A3`;
- aUSDC `0xaC0893567D43C3E7e6e35a72803df05416C1f20D`;
- AccessCore `0x8F118338a1fa41E7Fa86Be19A4e8B99Ed58A6EcC`;
- A-Pass `0xbA82D189540CaC9DC6FF46B6837CaC1BFdEC58B9`.

These addresses are evidence from that response, not configuration authority. The application uses
runtime discovery and explicit environment configuration.

A reproducible read-only probe, without a key in shell history:

```bash
curl -X POST "${CLEANVERSE_API_BASE_URL}/query_deposit_atoken_list" \
  -H 'Content-Type: application/json' \
  -H "api-id: ${CLEANVERSE_API_ID}" \
  --data '{"chain":"monad"}'
```

## Implemented API surface

- encrypted request bodies: `POST /atoken/launch`, `POST /validator/register`;
- plaintext bodies: supported A-Token discovery, A-Pass query/verification and validator verification;
- bodyless GET: A-Token application status;
- `api-id` and a fresh `X-Request-ID` on every request;
- business-envelope and response-schema validation;
- server-only credentials and public response projections that omit KYC hashes, internal IDs,
  callbacks and upstream error details.

AES-CBC with a zero IV is implemented only because that is the sponsor's documented wire format. It
must not be reused as a general encryption design.

## P0 sponsor questions

Before the judged deployment, Cleanverse must confirm:

1. whether each invoice may receive a dedicated custom A-Token on Monad;
2. how a validator-approved contract or custody account is credited when an ordinary contract has no
   A-Pass;
3. the definitive burn, release and issued-supply interface required by `ICvaAdapter`;
4. the onchain or attested CVI verifier path for buyer, originator, facility and holder roles;
5. how pre-activation custody is recovered if financing never closes;
6. whether final deployment is required on testnet or mainnet.

No production or custom-token claim is made until these paths are observed end to end. The sandbox
key delivered by email must be rotated before it is stored in any durable environment because it was
pasted into a chat transcript.
