# Threat Model

Explicit assumptions and the attacks in / out of scope for this slice.

## Assumptions

1. **Registry immutability.** `registry.npmjs.org` does not allow
   re-publishing a `(name, version)` with different bytes. This is an
   npm policy guarantee, not a cryptographic one. Mirrors and
   self-hosted registries may violate it.
2. **Trusted transport.** TLS to the upstream registry is assumed intact
   (CA-pinned system roots, `rustls`). An attacker who breaks TLS
   controls both metadata and tarballs.
3. **Integrity strings are authoritative.** `dist.integrity` from the
   registry is treated as ground truth for byte verification. A registry
   that lies consistently (matching bytes + matching integrity) is out of
   scope until signed provenance/attestation checks exist.

## Controls

| Threat | Control |
|---|---|
| Compromised mirror / MITM swaps tarball bytes | `freeze_verified` checks sha512 bytes vs `dist.integrity`; mismatch never freezes |
| Re-publish of same `(name, version)` with different bytes (mirror immutability violation) | Frozen-ledger conflict: `get_frozen` + sha256 comparison → `immutability violation`, ledger keeps original bytes; idempotent re-freeze of identical bytes is allowed |
| 0-day malicious version (no CVE yet) | Quarantine window (`minimum_age_days`, fail-closed on missing `published_at`); fallback serves latest frozen version **satisfying the requested semver range**; no satisfying frozen version → Block |
| Denylisted package | Unconditional Block; frozen fallback can never serve a denied package |
| Known vulnerable version | Severity-threshold block, then range-aware fallback |

## Residual risks (accepted for this slice)

- Registry compromise serving self-consistent metadata + payload for a
  **new** version after the quarantine window expires — needs AST/capability
  diffing per the feasibility research.
- Malicious new version inside the window with **no** frozen history —
  hard Block (availability loss, intentional).
- npm-specific range syntax not covered by `semver::VersionReq`
  (e.g. hyphen ranges, `1.2.x` wildcards) — treated as unparseable and
  fail-closed at the caller.
- `ArtifactStore::get` still takes caller-supplied paths; constrained
  before the HTTP serve endpoint lands.
