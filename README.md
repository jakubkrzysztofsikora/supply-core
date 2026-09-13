# supply-core

**Local-first supply-chain security firewall & silent daily vulnerability radar.**

Knows what your code depends on. Tells you what's bad before it ruins your morning.  
No SaaS accounts. No cloud dashboards. No agent daemons. Zero telemetry.

[![CI](https://github.com/jakubkrzysztofsikora/supply-core/actions/workflows/ci.yml/badge.svg)](https://github.com/jakubkrzysztofsikora/supply-core/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)
[![OSV](https://img.shields.io/badge/vulnerability%20source-OSV.dev-blue.svg)](https://osv.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Live status — quarantined versions, confirmed CVEs, and scan-suspected packages
(rendered on demand by the official server at
`/api/v1/status/card.svg`):

[![supply-core live status](https://supply-core.tail5d39b4.ts.net/api/v1/status/card.svg)](https://supply-core.tail5d39b4.ts.net/api/v1/status)

---

## The 10-Second Pitch (Why You Need This)

Every modern project imports hundreds of third-party dependencies and uses unpinned GitHub Actions:

- **0-Day NPM Poisoning**: Malicious packages sit on the public registry for an average of 48 hours before takedown. `supply-core` automatically quarantines packages published <24h/72h and transparently falls back to known-good frozen versions.
- **Floating GitHub Actions**: If you use `actions/checkout@v4`, anyone compromising that tag gets write tokens in your CI pipeline. `supply-core` catches and flags floating tags in milliseconds.
- **Morning Snapshot**: A passive daily LaunchAgent checks every Git repository under your configured roots, inventories lockfiles (`package-lock.json`, `yarn.lock`, `requirements.txt`, `packages.lock.json`), checks OSV.dev, and leaves a crisp `report.md` on your desk.

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

### 4. Package & Container Policy Scans
Evaluate exact dependency pins before you install them:

```bash
# npm: semver deps -> registry metadata, age quarantine, integrity, OSV
cargo run -- snapshot-npm .

# pip: exact requirements.txt pins -> PyPI age, sha256, --hash validation
cargo run -- snapshot-pip .

# NuGet: packages.lock.json -> nuget.org age, contentHash verification
cargo run -- snapshot-nuget .

# Docker: flag FROM/image references without a sha256 digest
cargo run -- scan-docker .
```

*`snapshot-*` prints a JSON report; `scan-docker` exits `2` when an image is unpinned.*

### 5. Quarantine Content Scanning (0-day and AI-agent threats)

Inspect package bytes **while a version sits in the quarantine window** — before
any advisory exists. The built-in static scanner always runs; GuardDog adds the
external malware engine:

```bash
# Install the external engine once (requires Python >= 3.10)
uv tool install guarddog        # or: pipx install guarddog
# If the default Python has no pygit2 wheel yet: uv tool install --python 3.13 guarddog

# Scan one verified archive (static AI/agent rules + GuardDog)
cargo run -- scan-package npm ./evil.tgz --name evil --version 1.2.3 \
  --guarddog --findings-out findings.jsonl
```

The daily capture wires this automatically: every version held by the
quarantine window is downloaded from the registry, verified against
`dist.integrity` (sha512), scanned, and its findings appended to
`experiments/data/content-findings.jsonl`. That file is then passed to
`snapshot-npm --findings`, so block-level findings turn into `Block`/`Fallback`
decisions on the next capture:

```bash
python3 experiments/scan-quarantine.py experiments/data/2026-09-13 \
  --bin target/release/supply-core    # one capture; the cron wrapper does this daily
```

### 6. Machine-Wide Daily Radar (macOS)
Scan **all** git repositories across your machine every morning at 08:30 AM:

```bash
cargo build --release --locked && python3 experiments/install_machine_eval.py --home-scope
```

- Discovers all git checkouts under your home directory.
- Maps and parses `package-lock.json`, Yarn Classic `yarn.lock`, exact `requirements.txt` pins, and resolved `packages.lock.json` entries.
- Queries OSV.dev with local 24-hour response caching.
- Zero battery drain: runs while logged in, coalesces sleep events.

### 7. Official Server & Self-Hosting
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

**Self-hosted service (optional public endpoint):**
- Service URL (example): `https://supply-core.example.com`
- Local health check: `curl http://localhost:4873/health`
- Pre-built binary download: `curl -sSL https://supply-core.example.com/api/v1/download/supply-core-linux-x86_64 -o supply-core` (falls back to a redirect to GitHub Releases when the artifact cache is empty)
- Remote pipeline scan: set `SUPPLY_AUTH_TOKEN` on the server and include a matching bearer token in scan requests.
- **Status card**: `GET /api/v1/status/card.svg` renders a dynamic SVG with three columns — quarantine-window holds, confirmed CVEs, and packages the content scan suspects. `GET /api/v1/status` returns the same data as JSON. Both are read-only, unauthenticated, and cache for 5 minutes.
- **Status publishing**: the daily capture publishes the snapshot (package names, versions, ages, decisions, advisory ids, and scan scores/rules) using the same token. It contains no repository paths, version ranges, or file contents. Store the publisher configuration outside the repository at `~/.config/supply-core/status-publisher.env`:

  ```bash
  SUPPLY_STATUS_URL=https://supply-core.example.com
  SUPPLY_STATUS_AUTH_TOKEN=the-matching-SUPPLY_AUTH_TOKEN
  ```

  The next successful capture updates the card; the scan runs before publishing, so the snapshot carries the same day's suspected findings.

**Deploy to Kubernetes:**
```bash
# Create the runtime secrets first (Tailscale sidecar auth key + server token):
kubectl create namespace supply-core
kubectl -n supply-core create secret generic ts-sidecar-auth --from-literal=TS_AUTHKEY=<tailscale-auth-key>
kubectl -n supply-core create secret generic supply-core-auth --from-literal=SUPPLY_AUTH_TOKEN=<long-random-token>
# Then deploy the manifests (adjust storageClassName and sizing in deploy/k8s/*.yaml to your cluster):
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
| **Passive Machine Scan** | Fast traversal of your repositories, worktree deduplication; npm, pip and NuGet advisories | Total situational awareness of local attack surface |
| **PyPI Quarantine** | `snapshot-pip` checks exact requirements.txt pins: publish age, sha256, OSV advisories | Catches fresh malicious pip uploads before they reach your build |
| **NuGet Quarantine** | `snapshot-nuget` checks resolved `packages.lock.json`: publish age, SHA-512 package hash, OSV | Catches fresh NuGet publishes with the same policy engine |
| **Docker Digest Pinning** | `scan-docker` flags `FROM`/`image:` references that lack an `@sha256:` digest | Mutable tags can be silently replaced under you |
| **Quarantine Content Scan** | GuardDog plus built-in AI/agent rules over every version held by the quarantine window | Catches malware and prompt-injection payloads that have no CVE yet |
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
         ├───► Daily LaunchAgent (08:30) ──────► Discovers Git repositories under configured roots
         │                                        ├── Maps lockfiles (npm, Yarn, pip, NuGet)
         │                                        ├── Queries OSV batch API (cached 24h)
         │                                        └── Generates runs/<ts>/report.md
         │
         └───► Quarantine content scan (08:45) ─► GuardDog + AI/agent rules over held versions
                                                  ├── findings.jsonl ──► blocks later captures
                                                  └── snapshot ──► server card (/api/v1/status/card.svg)
```

---

## Morning Report Example

Every morning, open `~/.local/share/supply-core/latest.json` or `runs/<timestamp>/report.md`:

```markdown
# Machine-wide supply-chain evaluation
**Timestamp:** 2026-09-07T18:42:30Z | **Repositories:** 24 | **Exact versions:** 1,830

### Top Findings
- `Repos/dashboard` (yarn.lock): 411 advisory hits (Prototype Pollution, ReDoS)
- `Repos/api` (.github/workflows/deploy.yml): 8 unpinned actions (`actions/checkout@v4`)

### Status
- Cached OSV lookups: 1,772 / 1,830 (96.8% cache hit rate)
- Evaluation runtime: 4.2 seconds
```

---

## Quarantine Content Scanning

Time-based quarantine keeps a fresh version out of the build; the content scan
looks *inside* the bytes while upstream has reported nothing yet. `scan-package`
runs two engines over a verified archive:

1. **GuardDog 3.2** (`--guarddog`, uses `$GUARDDOG_BIN` or `guarddog` on PATH) —
   YARA-style heuristics for install hooks, credential access, exfiltration,
   obfuscation, bundled binaries, and typosquat metadata.
2. **Built-in static rules** — capability/threat correlation plus an
   AI/agent-targeting set:

| Rule | Catches |
|---|---|
| `ai-prompt-injection` | Role tokens (`<\|im_start\|>`, `[INST]`, …) or instruction-override text aimed at an agent reading the package |
| `ai-agent-config` | The same payloads inside `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `SKILL.md`, `.mcp.json` |
| `ai-agent-secrets` | Agent state (`~/.claude`, `~/.codex`, `.claude.json`) or hardcoded provider keys combined with exfiltration capability |
| `ai-hidden-instructions` | Zero-width / bidirectional Unicode smuggling around instructions |
| `ai-install-script` | Lifecycle scripts touching agent state or provider credentials |
| `slopsquat-name` | Package name one edit away from a popular package (the LLM-hallucination shape) |

Findings score 0–10 and are enforced per policy: `block_score` (default 8)
blocks or falls back, `review_score` (default 4) warns, and verified npm build
provenance lowers a score by 3. Every extracted file is scored, including test
and coverage paths; dynamic-evaluation signals only escalate when an encoded
payload is present, so ordinary `new Function`/coverage builds stay quiet.

A scan that fails (registry, integrity, GuardDog, timeout) persists a
block-level `scan-incomplete` finding instead of failing open, so the version
stays held even if it leaves the quarantine window before a successful scan.
Failed versions are retried on later captures until a scan with the same
engines succeeds — a static-only run cannot clear a GuardDog-pending hold —
and the passing scan clears the record.

The daily capture scans every version held by the quarantine window through
`experiments/scan-quarantine.py`: it resolves each version on the registry,
verifies the tarball against `dist.integrity` (sha512) before any scanner sees
it, appends findings to `experiments/data/content-findings.jsonl`, and the next
capture loads that file into `snapshot-npm --findings` (enabled by
`experiments/policy.yml`). Confirmed advisories and suspected scan findings are
published with the snapshot and rendered on the status card.
`supply report findings.json --submit` exports OSV records plus the manual
disclosure checklist — nothing is submitted automatically.

The self-hosted radar container runs the same scan after each capture (the
image ships `scan-quarantine.py` and `policy.yml`); install GuardDog into a
derived image or set `GUARDDOG_BIN` to add the external engine — the static
AI/agent rules run either way.

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

pip:
  require_integrity: true
  fallback_to_frozen: true

nuget:
  require_integrity: true
  fallback_to_frozen: true

docker:
  require_digest_pin: true

quarantine_scanner:          # content scan findings, when a --findings file is supplied
  enabled: true
  review_score: 4            # warn at/above this score
  block_score: 8             # block/fall back at/above this score

github_actions:
  require_full_sha_pin: true
```

---

## Development & Testing

```bash
# Run all unit and integration tests
cargo test

# Run the Python experiment suite (machine eval + quarantine scan)
python3 -m unittest discover -s experiments -p 'test_*.py'

# Run real-world registry E2E tests (hits live npmjs.org)
cargo test -- --ignored
```

CI checks formatting, tests, Clippy, and maintains an 85% library line-coverage floor via `cargo-llvm-cov`.

---

## Deep Dive & Specifications

- [Machine-wide Evaluation Spec](docs/machine-evaluation.md) — Multi-repo discovery, LaunchAgent setup, evidence structure.
- [Quarantine Scanning & Public Disclosure](docs/quarantine-scanning-and-disclosure.md) — In-window content scanning for hidden 0-days and how findings get reported.
- [Threat Model & Security Assumptions](docs/threat-model.md) — Trust boundaries, attack vectors, residual risks.
- [E2E Registry Validation Plan](docs/e2e-npm-plan.md) — Real-world registry testing tier.
- [Vertical Slice MVP Plan](docs/vertical-slice-mvp-plan.md) — Ports & adapters design, application core.
- [Adversarial Security Review](docs/adversarial-review.md) — Edge case analysis and bypass defenses.

---

## License

MIT License. Designed for developers who value security, speed, and clean code.
