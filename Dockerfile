# syntax=docker/dockerfile:1
# Multi-stage static build for supply-core
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /app

# Fetch dependencies before copying source to keep dependency downloads cacheable.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo fetch --locked && \
    rm -rf src

# Build application
COPY src ./src
COPY web ./web
COPY config ./config
RUN cargo build --release --locked

# Minimal hardened runner
FROM alpine:3.20 AS runner

RUN apk add --no-cache ca-certificates curl tzdata && \
    addgroup -S supply && adduser -S supply -G supply

WORKDIR /app

COPY --from=builder /app/target/release/supply-core /usr/local/bin/supply-core
RUN ln -s /usr/local/bin/supply-core /usr/local/bin/supply && \
    mkdir -p /app/artifacts /app/data && \
    chown -R supply:supply /app

USER supply

ENV SUPPLY_SERVICE_NAME="supply-core-official" \
    PORT=4873 \
    HOST=0.0.0.0

EXPOSE 4873

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:4873/health || exit 1

ENTRYPOINT ["supply-core"]
CMD ["serve", "--addr", "0.0.0.0:4873"]

# Daily capture + quarantine publisher for self-hosted docker compose.
FROM runner AS radar

USER root
RUN apk add --no-cache bash git python3
WORKDIR /radar
COPY experiments/run.sh experiments/publish-status.py experiments/docker-entrypoint.sh experiments/policy.yml experiments/scan-quarantine.py /radar/
RUN chmod +x /radar/run.sh /radar/docker-entrypoint.sh && \
    mkdir -p /radar/data && chown -R supply:supply /radar
USER supply
ENV SUPPLY_BIN=/usr/local/bin/supply-core
ENTRYPOINT ["/radar/docker-entrypoint.sh"]

# Pinned OSSGadget build (linux-x64 only).
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim AS ossgadget
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates git python3 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY scripts ./scripts
COPY patches ./patches
RUN sh scripts/install-ossgadget.sh /opt/supply-core/ossgadget

# Linux quarantine scanner with every required engine: static heuristics,
# attested GuardDog and attested OSSGadget, each run inside bubblewrap.
FROM debian:bookworm-slim AS scanner
RUN apt-get update && \
    apt-get install -y --no-install-recommends bubblewrap ca-certificates libicu72 python3 python3-venv tar && \
    rm -rf /var/lib/apt/lists/*
COPY scripts/install-guarddog.sh scripts/write-guarddog-manifest.py scripts/write-ossgadget-manifest.py /opt/supply-core/scripts/
RUN sh /opt/supply-core/scripts/install-guarddog.sh /opt/supply-core/guarddog
COPY --from=ossgadget /opt/supply-core/ossgadget /opt/supply-core/ossgadget
COPY --from=builder /app/target/release/supply-core /usr/local/bin/supply-core
COPY experiments/scan-quarantine.py experiments/policy.yml /radar/
RUN useradd --create-home --uid 1000 scanner && \
    mkdir -p /work /scratch && chown scanner:scanner /work /scratch
USER 1000
WORKDIR /work
ENV SUPPLY_BIN=/usr/local/bin/supply-core \
    GUARDDOG_BIN=/opt/supply-core/guarddog/venv/bin/guarddog \
    GUARDDOG_MANIFEST=/opt/supply-core/guarddog/supply-guarddog-manifest.json \
    OSSGADGET_BIN=/opt/supply-core/ossgadget/ossgadget \
    OSSGADGET_MANIFEST=/opt/supply-core/ossgadget/supply-ossgadget-manifest.json
ENV SUPPLY_SCRATCH_DIR=/scratch
ENTRYPOINT ["python3", "/radar/scan-quarantine.py"]

# Keep the server image as the default (last) stage for plain `docker build`.
FROM runner AS server
