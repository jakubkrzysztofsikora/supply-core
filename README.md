# supply-core

**Local-first supply-chain security firewall & silent daily vulnerability radar.**

Knows what your code depends on. Tells you what's bad before it ruins your morning.  
No SaaS accounts. No cloud dashboards. No agent daemons. Zero telemetry.

[![CI](https://github.com/jakubkrzysztofsikora/supply-core/actions/workflows/ci.yml/badge.svg)](https://github.com/jakubkrzysztofsikora/supply-core/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)
[![OSV](https://img.shields.io/badge/vulnerability%20source-OSV.dev-blue.svg)](https://osv.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## The 10-Second Pitch (Why You Need This)

Every modern project imports hundreds of third-party dependencies and uses unpinned GitHub Actions:

- **0-Day NPM Poisoning**: Malicious packages sit on the public registry for an average of 48 hours before takedown. `supply-core` automatically quarantines packages published <24h/72h and transparently falls back to known-good frozen versions.
- **Floating GitHub Actions**: If you use `actions/checkout@v4`, anyone compromising that tag gets write tokens in your CI pipeline. `supply-core` catches and flags floating tags in milliseconds.
- **Morning Snapshot**: A passive daily LaunchAgent checks all 100+ repositories across your Mac, inventories lockfiles (`package-lock.json`, `yarn.lock`), checks OSV.dev, and leaves a crisp `report.md` on your desk.

---

## Quickstart

### 1. The One-Line Docker Setup
Run the local caching firewall & health endpoint in one command:

```bash
docker compose up --build
```
> Ready on `http://localhost:4873/health`

### 2. Instant CI Workflow Scan
Check your current repository for unpinned GitHub Actions or dangerous floating tags:

```bash
cargo run -- scan-actions .
```

*Want GitHub Actions annotations?*
```bash
cargo run -- scan-actions . --annotations
```
*Emits escaped GitHub workflow errors and exits `2` on policy findings.*

### 3. Azure DevOps Pipeline Scan
Check your repository for unpinned Azure DevOps tasks, external checkouts, or floating repository resources:

```bash
cargo run -- scan-pipelines .
```

*Want Azure DevOps pipeline annotations?*
```bash
cargo run -- scan-pipelines . --annotations
```
*Emits escaped Azure DevOps error logging commands (`##vso[task.logissue...]`) and exits `2` on policy findings.*

### 4. Machine-Wide Daily Radar (macOS)
Scan **all** git repositories across your machine every morning at 08:30 AM:

```bash
cargo build --release --locked && python3 experiments/install_machine_eval.py --home-scope
```

- Discovers all git checkouts under your home directory.
- Maps and parses `package-lock.json` and Yarn Classic `yarn.lock`.
- Queries OSV.dev with local 24-hour response caching.
- Zero battery drain: runs while logged in, coalesces sleep events.

### 5. Official Server & Self-Hosting
Run `supply-core` as an HTTP microservice with remote scanning and binary distribution endpoints:

```bash
# Start server locally
cargo run -- serve --addr 0.0.0.0:4873

# Or run via docker-compose
docker compose up -d
```

**Whole system with the daily radar (self-hosted):**

```bash
# 1. List your checkouts for the radar (paths are container paths)
cp radar/candidates.example.txt radar/candidates.txt

# 2. Shared token: the server rejects quarantine-status writes without one
echo "SUPPLY_AUTH_TOKEN=$(openssl rand -hex 32)" > .env
echo "SUPPLY_WORKSPACE=$HOME/Repos" >> .env

# 3. Start server + radar
docker compose --profile radar up -d --build
```

The radar container runs the quarantine capture immediately and every 24 h
(`SUPPLY_INTERVAL_SECONDS`), then publishes the dashboard snapshot to the
server over the compose network. Captures land in `radar/data/`. Without the
`radar` profile the server alone needs no token.

**Official Cluster Service (Homelab / Tailscale Funnel):**
- Tailscale MagicDNS: `supply-core.tail5d39b4.ts.net`
- Public HTTPS Funnel: `https://supply-core.tail5d39b4.ts.net`
- Public dashboard: `https://supply-core.tail5d39b4.ts.net/`
- Health check: `curl https://supply-core.tail5d39b4.ts.net/health`
- Pre-built binary download: `curl -sSL https://supply-core.tail5d39b4.ts.net/api/v1/download/supply-core-linux-x86_64 -o supply-core` (falls back to a redirect to GitHub Releases when the artifact cache is empty)
- Remote pipeline scan: set `SUPPLY_AUTH_TOKEN` on the server and include a matching bearer token in scan requests.
- Quarantine dashboard: the daily capture publishes only package name, version, age, and decision using the same token. Store its local configuration outside the repository at `~/.config/supply-core/status-publisher.env`:

  ```bash
  SUPPLY_STATUS_URL=https://supply-core.tail5d39b4.ts.net
  SUPPLY_STATUS_AUTH_TOKEN=the-matching-SUPPLY_AUTH_TOKEN
  ```

  The next successful capture updates the public dashboard; its snapshot contains no repository paths, ranges, or advisory details.

**Deploy to Kubernetes (K3s):**
```bash
# Apply the SOPS-managed cluster secrets from the homelab-cluster repository first
# (tailnet Funnel auth key + the server/publisher SUPPLY_AUTH_TOKEN):
SOPS_AGE_KEY_FILE=~/cluster-migration/.secrets/age-key.txt \
  ~/cluster-migration/homelab-cluster/scripts/secrets-apply.sh \
  ~/cluster-migration/homelab-cluster/secrets/ts-sidecar-auth.enc.yaml \
  ~/cluster-migration/homelab-cluster/secrets/supply-core-auth.enc.yaml
# Then deploy manifests with the Tailscale Funnel sidecar.
kubectl apply -k deploy/k8s
```

---

## Features at a Glance

| Feature | What It Does | Why It Matters |
|---|---|---|
| **Age Quarantine** | Blocks packages younger than policy threshold (e.g. 72h) | Mitigates fresh npm 0-day account takeovers |
| **Frozen Fallback** | Serves latest frozen version satisfying your semver range | Prevents builds from breaking while staying safe |
| **Actions SHA Pinning** | Enforces immutable 40-character commit SHAs in CI | Blocks malicious workflow tag mutability attacks |
| **OSV.dev Integration** | Real-time vulnerability batch query with CVSS & severity | Immediate awareness of newly disclosed CVEs |
| **Passive Machine Scan** | Fast traversal of 100+ repos, worktree deduplication | Total situational awareness of local attack surface |
| **PyPI Quarantine** | `snapshot-pip` checks exact requirements.txt pins: publish age, sha256, OSV advisories | Catches fresh malicious pip uploads before they reach your build |
| **NuGet Quarantine** | `snapshot-nuget` checks resolved `packages.lock.json`: publish age, SHA-512 package hash, OSV | Catches fresh NuGet publishes with the same policy engine |
| **Docker Digest Pinning** | `scan-docker` flags `FROM`/`image:` references that lack an `@sha256:` digest | Mutable tags can be silently replaced under you |
| **100% Local & Airgapped** | Operates strictly on local files and local caching | Your private code and lockfiles never leave your machine |

### Supported ecosystems

| Ecosystem | Inputs | Checks | Command |
|---|---|---|---|
| npm | `package.json` deps | age quarantine, integrity, OSV, frozen fallback | `snapshot-npm` |
| PyPI (pip) | `requirements.txt` exact pins (`==`, `===`) | age quarantine, sha256 integrity, `--hash` validation, OSV | `snapshot-pip` |
| NuGet | `packages.lock.json` | age quarantine, lockfile `contentHash` verified against the SHA-512 package hash, OSV | `snapshot-nuget` |
| Docker images | `Dockerfile*`, `docker-compose*.yml`, `compose.yml` | static `@sha256:<64-hex>` digest pinning | `scan-docker` |
| GitHub Actions | `.github/workflows/*` | full-SHA pinning, `docker://` digest rule | `scan-actions` |
| Azure Pipelines | `azure-pipelines*.yml` | task pinning rules | `scan-pipelines` |

**Not yet supported:** RubyGems, Cargo, Maven/Gradle, Go modules, pnpm/bun
lockfiles, Yarn Berry (classic Yarn is mapped). pip requirements that are ranges
(`>=`, `~=`) or carry markers/URLs are reported as coverage gaps — only exact
pins are evaluated. Docker scanning is static: it does not query registries for
image age or CVEs. NuGet hashes come from nuget.org catalog metadata; pip
hashes come from the PyPI JSON API.

---

## Architecture & Data Flow

```text
[ Developer Machine / CI ]
         │
         ├───► `cargo run -- scan-actions .` ──► Checks .github/workflows/*.yml (SHA-pinned?)
         │
         ├───► `docker compose up` ────────────► Local npm proxy (:4873)
         │                                        ├── Age < 72h? ──► Quarantine + Fallback
         │                                        └── Vulnerable? ──► Block or Warn
         │
         └───► Daily LaunchAgent (08:30) ──────► Discovers all ~/Repos
                                                  ├── Maps lockfiles (npm, Yarn)
                                                  ├── Queries OSV batch API (cached 24h)
                                                  └── Generates runs/<ts>/report.md
```

---

## Morning Report Example

Every morning, open `~/.local/share/supply-core/latest.json` or `runs/<timestamp>/report.md`:

```markdown
# Machine-wide supply-chain evaluation
**Timestamp:** 2026-09-07T18:42:30Z | **Repositories:** 105 | **Exact versions:** 10,201

### Top Findings
- `Repos/dashboard` (yarn.lock): 411 advisory hits (Prototype Pollution, ReDoS)
- `Repos/api` (.github/workflows/deploy.yml): 8 unpinned actions (`actions/checkout@v4`)

### Status
- Cached OSV lookups: 9,840 / 10,201 (96.4% cache hit rate)
- Evaluation runtime: 4.2 seconds
```

---

## Configuration & Policy

Policies are defined in a clean YAML structure (see [`examples/supply-core.yml`](examples/supply-core.yml)):

```yaml
quarantine:
  enabled: true
  minimum_age_days: 7
  cve_keeps_quarantined: true   # overrides block_severities: any CVE, any severity, blocks forever

vulnerabilities:
  block_severities: [High, Critical]

npm:
  require_integrity: true
  fallback_to_frozen: true

github_actions:
  require_full_sha_pin: true
```

---

## Development & Testing

```bash
# Run all unit and integration tests (95 tests)
cargo test

# Run Python machine-eval test suite
python3 -m unittest experiments/test_machine_eval.py

# Run real-world registry E2E tests (hits live npmjs.org)
cargo test -- --ignored
```

CI checks formatting, tests, Clippy, and maintains an 85% library line-coverage floor via `cargo-llvm-cov`.

---

## Deep Dive & Specifications

- [Machine-wide Evaluation Spec](docs/machine-evaluation.md) — Multi-repo discovery, LaunchAgent setup, evidence structure.
- [Threat Model & Security Assumptions](docs/threat-model.md) — Trust boundaries, attack vectors, residual risks.
- [E2E Registry Validation Plan](docs/e2e-npm-plan.md) — Real-world registry testing tier.
- [Vertical Slice MVP Plan](docs/vertical-slice-mvp-plan.md) — Ports & adapters design, application core.
- [Adversarial Security Review](docs/adversarial-review.md) — Edge case analysis and bypass defenses.

---

## License

MIT License. Designed for developers who value security, speed, and clean code.
