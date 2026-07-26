# Mordant build rules

Mordant is a hackathon prototype for synthetic invoices and test assets. It is not approved for real
funds, legal assignment, custody, or production claims.

## Required discipline

- Read the relevant guide in `node_modules/next/dist/docs/` before changing Next.js conventions.
- Keep Cleanverse API credentials server-only. Never use a `NEXT_PUBLIC_` secret and never print a
  credential in logs or fixtures.
- Do not invent Cleanverse ABIs. The on-chain CVA custody boundary stays behind `ICvaAdapter` until
  Cleanverse confirms the deployed A-Token ABI and contract eligibility path.
- One vault represents one immutable buyer-accepted invoice root and one immutable CVA.
- Protection money and receivable redemption money are separate accounting domains.
- A protection claim must never burn or transfer the underlying invoice units.
- The 10% reserve is a demo parameter. It amortizes with outstanding protected principal and is not
  marketed as a production price.
- No claim of universal duplicate-financing detection, legal priority, insurance, or production
  safety.
- Add or update tests for every money-path or state-machine change.

## Validation

```bash
pnpm validate
pnpm test:e2e
```
