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
3. **Integrity strings are authoritative.** npm lock SRI selects its strongest
   supported algorithm and requires every locked digest for that algorithm to
   match registry `dist.integrity`; historical SHA-1 pins use `dist.shasum`.
   A missing matching algorithm fails closed. Full configured npm registry URL
   paths and NuGet feed URLs remain separate source identities, including feeds
   on the same host; report `source` strips credentials, queries, and fragments
   only. PyPI `digests.sha256` and the NuGet registration `packageHash` identify
   published archive bytes. NuGet `packages.lock.json contentHash` excludes the
   `.signature.p7s` entry. `scan-packages` recomputes that signature-independent
   hash from restored package bytes, then checks archive SHA-512 against both
   the cache sidecar and each full NuGet feed identity's registry `packageHash`;
   when a feed's `catalogEntry` is unfetchable (Azure Artifacts commitLog URLs
   404 under basic auth), assessment continues from the same authenticated
   registration leaf, and packages without registry archive metadata fail closed.
   `snapshot-nuget` has no restored archive and does not verify lock
   `contentHash`. A registry that lies consistently (matching bytes + matching
   hash) is out of scope until signed provenance/attestation checks exist.
   Docker images are content-addressed: a `@sha256:` digest is immutable by
   construction, but the digest's provenance is not verified.
4. **Source code is not executed.** Lockfiles, manifests, and Dockerfiles are
   parsed; `scan-packages` invokes npm only to query exact-version metadata and
   does not install packages or execute their contents.

## Controls

| Threat | Control |
|---|---|
| Compromised mirror / MITM swaps tarball bytes | `freeze_verified` checks sha512 bytes vs `dist.integrity`; mismatch never freezes |
| Re-publish of same `(name, version)` with different bytes (mirror immutability violation) | Frozen-ledger conflict: `get_frozen` + sha256 comparison → `immutability violation`, ledger keeps original bytes; idempotent re-freeze of identical bytes is allowed |
| 0-day malicious version (no CVE yet) | Quarantine window (`minimum_age_days`, fail-closed on missing `published_at`); fallback serves latest frozen version **satisfying the requested semver range**; no satisfying frozen version → Block |
| Denylisted package | Unconditional Block; frozen fallback can never serve a denied package |
| Known vulnerable version | Every active OSV advisory blocks regardless of severity, then range-aware fallback. Other sources use the configured severity policy |
| Malicious pip artifact swapping (sdist vs wheel) | `--hash`-pinned requirement sets filter candidate artifacts before selection; the newest hash-authorized artifact drives the age check; unpinned or non-sha256 hashes are explicit gaps/errors |
| NuGet lockfile edit or stale resolution | Every resolved lock entry requires a `contentHash`; `scan-packages` recomputes the signature-excluded NuGet content hash from cached `.nupkg` bytes, then checks archive SHA-512 against the cache sidecar and that full feed's registry `packageHash`; same-host feeds are assessed independently |
| Floating container tag silently replaced | `scan-docker` blocks `FROM`/compose `image:` references without a valid 64-hex `@sha256:` digest; unresolved variable references are blocked too |
| Frozen fallback crossing ecosystems | Frozen-artifact lookups are scoped by ecosystem; an npm artifact can never satisfy a pip/NuGet fallback |
| False-positive approval abuse | Local approval requires matching real/effective Unix UIDs and a private, owner-owned ledger; it binds to one artifact digest, finding ID, engine-policy revision, and expiry |
| Hostile package or image scanner escapes into the host | Linux scanners run under bubblewrap with every namespace unshared, a private scratch directory, and read-only inputs; only `crane` and `cosign` get network access. Each sandbox starts a new session without a controlling terminal, so a scanner cannot inject keystrokes into the operator's terminal (`TIOCSTI`) |
| Signature on one image used to vouch for a multi-image archive | `scan-image` verifies a signature only when the archive holds exactly one image whose manifest, config, and ordered layer digests match the signed reference; multi-image archives report `signature_scope_multiple_images` and stay incomplete |

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
- `scan-docker` is static: it verifies pinning syntax, not registry
  existence, image age, or contained CVEs. `scan-image` covers contents of a
  local archive, but only on Linux, where its sandboxed scanners run.
- The Linux sandbox mounts a private scratch directory over `/tmp`, so scanner
  binaries installed under `/tmp` are unreachable; install them elsewhere.
- NuGet integrity ends at the verified `.nupkg` archive; extracted
  global-packages files are not compared byte-for-byte against it.
- OSSGadget runs with .NET write-xor-execute disabled: the runtime's
  double-mapped JIT file exceeds the scanner file-size limit. The process stays
  in the no-network bubblewrap sandbox with a 4 GiB address-space cap and never
  executes package code.
- GuardDog attestation covers its console script and installed `guarddog`
  package bytes, not the rest of its pinned Python dependency tree.
- Binary members with a wasm, zip, gzip, PNG, JPEG or TrueType header count as
  covered without static content rules. Only headers that are a JavaScript
  syntax error at byte 0 qualify, because Node runs unknown extensions as
  JavaScript; GIF, WOFF and OTF headers parse as identifiers and stay
  incomplete. Contents of nested archives are covered by OSSGadget only.
- `ArtifactStore::get` still takes caller-supplied paths; constrained
  before the HTTP serve endpoint lands.
- Azure Artifacts feeds publish no NuGet catalog, so the registry cannot attest a
  package hash. Mirrored packages are attested against nuget.org's catalog hash.
  Packages matching a `nuget.first_party_packages` prefix are trusted only when
  restored from that entry's exact feed (a prefixed id from any other source is
  refused) and have no independent attestation: the scanner requires that no
  version of the id exists on nuget.org
  (dependency confusion) and verifies the restored archive against the lockfile
  `contentHash` and the bytes the feed serves. A feed that serves consistent but
  altered first-party bytes, paired with a matching lockfile edit, is not detected until
  publish-time digests are verified. The report marks these packages
  `hash_attestation: first-party-feed-bytes`.
