# Mordant live execution worker.
#
# Three stages so the runtime image carries only what the worker executes:
# statically linked Go FHE binaries, the compiled engine, and Node.
#
# Durable state is never written into this image. Everything mutable lives on
# the attached volume at MORDANT_WORKER_DATA_ROOT (/data/mordant on Railway).

# ---------------------------------------------------------------- Go binaries
FROM golang:1.24-bookworm AS fhe
WORKDIR /src
COPY fhe-lab/lattigo/go.mod fhe-lab/lattigo/go.sum ./
RUN go mod download
COPY fhe-lab/lattigo/ ./
# CGO disabled so the binaries are static and portable into the slim runtime.
ENV CGO_ENABLED=0 GOOS=linux
RUN set -eux; \
    for binary in keygen client evaluator decryptor recourse inspect retain; do \
      go build -trimpath -o /out/mordant-fhe-$binary ./cmd/mordant-fhe-$binary; \
    done

# ---------------------------------------------------------------- engine build
FROM node:22-bookworm-slim AS engine
WORKDIR /build
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY tsconfig.json tsconfig.product-tests.json ./
COPY src/ ./src/
COPY test/stubs/ ./test/stubs/
COPY docs/evidence/ ./docs/evidence/
# Emits .product-test-dist, the runnable server build the worker imports.
RUN ./node_modules/.bin/tsc -p tsconfig.product-tests.json

# ---------------------------------------------------------------- runtime
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NODE_PATH=/app/test/stubs \
    MORDANT_WORKER_DATA_ROOT=/data/mordant \
    MORDANT_GOVERNED_FHE_BIN_DIR=/app/bin

# The worker imports only node: builtins, and the compiled engine resolves only
# relative modules plus the `server-only` stub. `next/server` lives solely in the
# API route, which the worker never loads. So no node_modules reaches runtime.
COPY --from=fhe    /out/                       /app/bin/
COPY --from=engine /build/.product-test-dist/  /app/.product-test-dist/
COPY --from=engine /build/test/stubs/          /app/test/stubs/
COPY --from=engine /build/docs/evidence/       /app/docs/evidence/
COPY scripts/mordant-live-worker.mjs           /app/scripts/
COPY package.json                              /app/

# The worker owns the volume mount point; Railway attaches the volume here.
RUN chmod 0755 /app/bin/* && mkdir -p /data/mordant

EXPOSE 8080
# Railway health check targets /health on the injected PORT.
CMD ["node", "/app/scripts/mordant-live-worker.mjs"]
