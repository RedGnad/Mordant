# Mordant live worker: Railway deployment

The live execution worker runs the existing custom V2 BGV engine as one managed
process. It is the only component that executes native FHE binaries.

## Measured requirements

These come from an instrumented real run of the full custom V2 journey on this
source tree, not from estimates.

| Resource | Measured | Provisioned |
| --- | --- | --- |
| Peak RSS, largest single process (`mordant-fhe-decryptor`) | 380.7 MB | 2 GB |
| Peak RSS, evaluator | 343.7 MB | |
| Engine concurrency | strictly sequential, one binary at a time | 1 replica |
| Completed case on disk | 383 MB | 5 GB volume |
| Retained after pruning (receipt + journal + execution record) | ~34 KB | |
| Wall-clock journey | ~56 s | health timeout 120 s |

Binaries are statically linked (`CGO_ENABLED=0`); all seven cross-compile for
`linux/amd64` from this tree.

## Service settings

| Setting | Value |
| --- | --- |
| Plan | Hobby |
| Replicas | 1 |
| Serverless / app sleeping | disabled |
| Restart policy | Always |
| Memory | 2 GB |
| vCPU | 2 |
| Volume size | 5 GB |
| Volume mount path | `/data/mordant` |
| Health check path | `/health` |
| Builder | Dockerfile |

Horizontal scaling must stay off: a second replica would break the
single-active-case guarantee and the durable journal authority.

## Environment variables

Set on the Railway service:

| Variable | Value |
| --- | --- |
| `MORDANT_WORKER_DATA_ROOT` | `/data/mordant` |
| `MORDANT_WORKER_TOKEN_SECRET` | shared secret, 32+ characters, generated once |
| `MORDANT_WORKER_TOKEN_AUDIENCE` | `MORDANT_RAILWAY_WORKER` |
| `MORDANT_WORKER_ALLOWED_ORIGIN` | the exact Vercel origin, HTTPS |
| `MORDANT_WORKER_MAX_ACTIVE_CASES` | `1` |
| `MORDANT_WORKER_DAILY_CASE_LIMIT` | e.g. `24` |
| `MORDANT_WORKER_DISK_FLOOR_BYTES` | `2187329536` |
| `MORDANT_MONAD_RPC_URL` | the Monad testnet RPC endpoint, HTTPS. **Required.** The worker builds its compliance reader at startup and exits if this is absent, so a missing value is a boot failure rather than an unchecked admission. Server-side only; the value is never committed to this repository |
| `MORDANT_PROTECTION_SOURCE_COMMIT` | the deployed source commit. It stamps `sourceCommit` on every receipt the worker produces, so it must name the commit actually running |
| `PORT` | injected by Railway |

Set on Vercel:

| Variable | Value |
| --- | --- |
| `MORDANT_WORKER_TOKEN_SECRET` | the same shared secret, server-side only |
| `NEXT_PUBLIC_MORDANT_WORKER_ORIGIN` | the public Railway HTTPS origin |
| `MORDANT_PROTECTION_SOURCE_COMMIT` | required by the existing `/protection` page |

`MORDANT_WORKER_TOKEN_SECRET` must never be prefixed `NEXT_PUBLIC_`. Only the
worker origin is public.

## Deployment checklist

1. Generate the shared secret: `openssl rand -hex 32`.
2. Create the Railway project and service from this repository, builder Dockerfile.
3. Add the 5 GB volume, mount path `/data/mordant`.
4. Disable Serverless; set restart policy Always; set replicas to 1.
5. Set memory 2 GB and 2 vCPU.
6. Set the health check to `/health`, timeout 120 s.
7. Set every worker environment variable above.
8. Deploy, then confirm `GET /health` returns `status: READY`, `worker: IDLE`,
   `diskSufficient: true`.
9. Set the Vercel variables and deploy a preview.
10. Open `/protection/live` on the preview and start one overlapping case.
11. Refresh mid-execution and confirm the run resumes from the URL.
12. Confirm the terminal result appears only after governed release.
13. Redeploy or restart the Railway service; confirm the receipt is still
    readable from the volume.

## Rollback

The live page is additive. To disable it without touching the validated
product, remove `NEXT_PUBLIC_MORDANT_WORKER_ORIGIN` from Vercel and redeploy:
`/protection/live` then renders its unavailable state and `/protection`
continues to serve verified A8 evidence unchanged.

To roll the whole product back, redeploy the validated fallback tag
`mordant-v5-hackathon-rc1` (`0e03622241c862f13736229cf08106992520ddc6`).

To roll the worker back, redeploy the previous Railway image; durable state on
the volume is compatible because the engine reconciles from its journal.
