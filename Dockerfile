# syntax=docker/dockerfile:1
# Multi-stage static build for supply-core
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /app

# Cache dependency builds
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release || true && \
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
