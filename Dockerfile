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
COPY experiments/run.sh experiments/publish-status.py experiments/docker-entrypoint.sh /radar/
RUN chmod +x /radar/run.sh /radar/docker-entrypoint.sh && \
    mkdir -p /radar/data && chown -R supply:supply /radar
USER supply
ENV SUPPLY_BIN=/usr/local/bin/supply-core
ENTRYPOINT ["/radar/docker-entrypoint.sh"]

# Keep the server image as the default (last) stage for plain `docker build`.
FROM runner AS server
