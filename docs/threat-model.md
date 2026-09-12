# Threat Model

Explicit assumptions and the attacks in / out of scope. Originally written for
the npm slice; the PyPI, NuGet, and Docker extensions below inherit the same
trust model.

## Assumptions

1. **Registry immutability.** `registry.npmjs.org` (npm), `pypi.org` (PyPI),
   and `nuget.org` (NuGet) do not allow re-publishing a `(name, version)` with
   different bytes. These are policy guarantees, not cryptographic ones.
   Mirrors, self-hosted registries, and project-local feeds may violate them;
   NuGet additionally allows unlisting without deleting.
2. **Trusted transport.** TLS to the upstream registry is assumed intact
   (CA-pinned system roots, `rustls`). An attacker who breaks TLS
   controls both metadata and tarballs.
3. **Integrity strings are authoritative.** `dist.integrity` (npm),
   `digests.sha256` (PyPI JSON API), and the NuGet registration `packageHash`
   are treated as ground truth. `requirements.txt --hash` values and
   `packages.lock.json contentHash` fields are treated as the caller's pinned
   expectations and are verified against the registry before acceptance; a
   mismatch fails closed. A registry that lies consistently (matching bytes +
   matching hash) is out of scope until signed provenance/attestation checks
   exist. Docker images are content-addressed: a `@sha256:` digest is
   immutable by construction, but the digest's provenance is not verified.
4. **Source inputs are read-only.** Lockfiles, manifests, and Dockerfiles are
   parsed, never executed; the scanners do not run package managers.

## Controls

| Threat | Control |
|---|---|
| Compromised mirror / MITM swaps tarball bytes | `freeze_verified` checks sha512 bytes vs `dist.integrity`; mismatch never freezes |
| Re-publish of same `(name, version)` with different bytes (mirror immutability violation) | Frozen-ledger conflict: `get_frozen` + sha256 comparison → `immutability violation`, ledger keeps original bytes; idempotent re-freeze of identical bytes is allowed |
| 0-day malicious version (no CVE yet) | Quarantine window (`minimum_age_days`, fail-closed on missing `published_at`); fallback serves latest frozen version **satisfying the requested semver range**; no satisfying frozen version → Block |
| Denylisted package | Unconditional Block; frozen fallback can never serve a denied package |
| Known vulnerable version | Severity-threshold block, then range-aware fallback. With `cve_keeps_quarantined` (default) any advisory, any severity, keeps the version blocked permanently |
| Malicious pip artifact swapping (sdist vs wheel) | `--hash`-pinned requirement sets filter candidate artifacts before selection; the newest hash-authorized artifact drives the age check; unpinned or non-sha256 hashes are explicit gaps/errors |
| NuGet lockfile edit or stale resolution | Every resolved lock entry requires a `contentHash`; conflicting hashes across targets are gaps; the lock hash must equal the registry `packageHash` or evaluation fails closed |
| Floating container tag silently replaced | `scan-docker` blocks `FROM`/compose `image:` references without a valid 64-hex `@sha256:` digest; unresolved variable references are blocked too |
| Frozen fallback crossing ecosystems | Frozen-artifact lookups are scoped by ecosystem; an npm artifact can never satisfy a pip/NuGet fallback |

## Residual risks (accepted)

- Registry compromise serving self-consistent metadata + payload for a
  **new** version after the quarantine window expires — needs AST/capability
  diffing per the feasibility research.
- Malicious new version inside the window with **no** frozen history —
  hard Block (availability loss, intentional).
- npm-specific range syntax not covered by `semver::VersionReq`
  (e.g. hyphen ranges, `1.2.x` wildcards) — treated as unparseable and
  fail-closed at the caller. pip requirements ranges/markers are recorded as
  coverage gaps instead of being resolved.
- Docker scanning is static: it verifies pinning syntax, not registry
  existence, image age, or contained CVEs.
- `ArtifactStore::get` still takes caller-supplied paths; constrained
  before the HTTP serve endpoint lands.
