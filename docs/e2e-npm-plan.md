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

1. **Fetch metadata** — `HttpNpmRegistry.metadata("left-pad")` returns
   registry JSON containing `versions["1.3.0"]` and `time["1.3.0"]`.
2. **Map to domain** — `package_version_from_metadata` produces a
   `PackageVersion` with integrity (`sha512-…`), tarball URL, and
   `published_at` parsed from the `time` map.
3. **Evaluate → Allow** — default policy, system clock, noop vuln source:
   2018 publish date clears quarantine → `Decision::Allow`.
4. **Fetch tarball** — `HttpNpmRegistry.tarball(url)` returns bytes.
5. **Verify integrity** — `ShaHasher.verify_npm_integrity(bytes, integrity)`
   must be `true`: proves the real registry round-trip preserves the
   sha512 SRI contract.
6. **Freeze** — sha256 the bytes, `FsArtifactStore.put` writes under
   `artifacts/`, `MemoryMetadataStore.put_frozen` records it.
7. **Quarantine → Fallback** — fixed clock set to publish-date + 2 days:
   re-evaluate the same version → `Decision::Fallback` serving frozen
   1.3.0 (the frozen copy rescues the quarantined request).
8. **Denylist → Block** — policy with `left-pad` denied, frozen copy
   still available → `Decision::Block` (denylist must never serve).

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
