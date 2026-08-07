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

# --------------------------------------------------------------- runtime deps
# The worker's module graph needs exactly two bare specifiers: `server-only`,
# which the stub directory answers, and `viem`. Nothing else is installed here,
# and the version is read from package.json so it cannot drift from the one the
# application builds against.
FROM node:22-bookworm-slim AS runtimedeps
WORKDIR /deps
COPY package.json ./
RUN set -eux; \
    viem="$(node -p "require('./package.json').dependencies.viem")"; \
    npm install --omit=dev --ignore-scripts --no-audit --no-fund "viem@${viem}"; \
    node -e "require.resolve('viem', { paths: ['/deps/node_modules'] })"

# ---------------------------------------------------------------- runtime
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NODE_PATH=/app/test/stubs \
    MORDANT_WORKER_DATA_ROOT=/data/mordant \
    MORDANT_GOVERNED_FHE_BIN_DIR=/app/bin

# `next/server` lives solely in the API route, which the worker never loads, so
# no framework reaches runtime. The compiled engine does resolve `viem`, through
# the canonical configuration and the typed-data verifier the two-wallet
# admission path needs, so that one package is shipped deliberately rather than
# assumed away.
COPY --from=runtimedeps /deps/node_modules/    /app/node_modules/
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
