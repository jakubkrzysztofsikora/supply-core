# supply-core

`supply-core` is a Rust vertical-slice MVP for a local-first supply-chain dependency firewall.

## What is implemented

- Ports-and-adapters Rust crate layout with domain, application, port, and adapter modules.
- Policy model for npm quarantine, vulnerability blocking, frozen fallback, and GitHub Actions SHA pinning.
- Package evaluator that converts blocked/quarantined/vulnerable npm versions into warnings plus automatic fallback to the latest frozen artifact when available.
- GitHub Actions scanner CLI that flags non-SHA-pinned, Docker, or unknown `uses:` references.
- Minimal HTTP service with `/health` for Docker/local smoke testing.
- Unit tests covering policy decisions, fallback behavior, action classification, workflow scanning, and npm metadata rewrite.

## Quickstart

```bash
cargo test
cargo run -- scan-actions . --json
cargo run -- serve --addr 127.0.0.1:4873
```

## Docker

```bash
docker compose up --build
curl http://localhost:4873/health
```

## Policy example

See [`examples/supply-core.yml`](examples/supply-core.yml).

## MVP plan and review

See [`docs/vertical-slice-mvp-plan.md`](docs/vertical-slice-mvp-plan.md) and [`docs/adversarial-review.md`](docs/adversarial-review.md).
