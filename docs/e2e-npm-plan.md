# E2E Testing Plan — Real npm Package Flow

First real-world example process: take a live npm package through the full
policy pipeline. Doubles as the executable e2e test.

## Goals

1. Prove the ports-and-adapters seams work against the real registry, not just stubs.
2. Exercise the full decision lifecycle: fetch → evaluate → verify integrity → freeze → fallback.
3. Keep default `cargo test` offline and deterministic; network tests are explicit.

## Test tiers

| Tier | Command | Network | CI? |
|------|---------|---------|-----|
| Unit (offline, deterministic) | `cargo test` | no | yes |
| E2E (real registry) | `cargo test -- --ignored` | registry.npmjs.org | no — manual/scheduled |
| Docker smoke | `docker compose up --build` + `/health` | no | later |

## E2E scenario (left-pad 1.3.0)

`left-pad@1.3.0` chosen as fixture: immutable version, ~3 KB tarball,
published 2018-02 (passes the 7-day quarantine window forever), zero
runtime dependencies, no lifecycle scripts.

Steps (each is an assertion in `tests/e2e_npm.rs`):

1. **Fetch + map** — `HttpNpmRegistry.metadata("left-pad")` →
   `package_version_from_metadata` produces a `PackageVersion` with
   integrity, tarball URL, and `published_at`.
2. **Evaluate → Allow** — 2018 publish date clears the 7-day quarantine.
3. **Verified freeze** — `IngestService.freeze_verified` fetches the real
   tarball, verifies sha512 bytes-vs-metadata (production path, not just
   test code), and freezes via `FsArtifactStore` + `MemoryMetadataStore`.
4. **Quarantine → Fallback** — fixed clock at publish-date + 2 days →
   `Decision::Fallback` serving frozen 1.3.0.
5. **Denylist → Block** — denied package with frozen copy available →
   `Decision::Block` (denylist must never serve).

## 0-day simulation (`zero_day_update_quarantined_tamper_blocked`)

Models the CVE-less attack window from the feasibility research: a
malicious version lands, no advisory exists yet, so the vulnerability
source (noop = empty findings, as with a real 0-day) cannot catch it.
Only the quarantine window stands between the build and the payload.

1. **Baseline freeze** of known-good 1.3.0 via verified ingest.
2. **0-day construct** — version `9.9.9`, `published_at` = now − 2 days,
   noop vuln source (nothing to match, exactly like a 0-day).
3. **Upstream tamper** — `TamperRegistry` corrupts real tarball bytes;
   `freeze_verified` must fail with "integrity mismatch" and produce no
   frozen artifact. Freezing never trusts unverified bytes.
4. **Quarantine holds** — 0-day evaluates to `Fallback` on frozen 1.3.0
   with a quarantine warning; the build survives without exposure.
5. **No frozen → Block** — same 0-day against an empty store hard-blocks.
6. **Window expiry** — clock +30 days: same version allows. The cooldown
   is the only CVE-less control; this asserts its actual duration
   semantics rather than assuming them.

## Pass criteria

All 8 steps assert on real data; any registry schema drift (missing
`dist.integrity`, unparseable `time`) fails loudly rather than skipping.

## Non-goals (this tier)

- No real OSV adapter yet (noop by design — next slice).
- No npm client wire compatibility (`npm install --registry`) — requires
  the metadata/tarball HTTP endpoints, next vertical slice.
- No flaky "recently published package" fixture — quarantine coverage
  comes from the fixed clock, not from racing real publish times.

## Future tiers

- Proxy wire test: point `npm install --registry http://127.0.0.1:4873`
  at `serve` once metadata/tarball endpoints land; assert install of an
  allowed package succeeds and a denied one fails with fallback warning.
- GitHub Actions scanner against a fixture repo with pinned/unpinned
  workflows in CI.
- Scheduled nightly e2e (GitHub Actions `schedule:`) so registry drift
  is caught within a day, without slowing PR CI.
