# Quarantine scanning and public disclosure

How the firewall can inspect packages **while they sit in quarantine** for hidden
0-days and malicious content, and — when it finds something — block it like any
other advisory plus report it to the public sources.

## Why

Today's pipeline is time-based and advisory-based:

- The quarantine window blocks versions younger than `minimum_age_days` purely
  on publish age (`is_version_quarantined`, `src/domain/mod.rs`).
- OSV matching catches known advisories only; malicious packages usually have
  no CVE at publish time and OSV sees them days later, if ever.
- The window therefore protects against *upstream takedowns being early*, not
  against *what the code actually does*.

A package can be removed from the registry after it was ingested, or never
reported at all. Scans in the window close that gap.

## What exists locally

- `PackageEvaluator::evaluate` is the single decision point: denylist →
  integrity → advisories → quarantine → allow, with range-aware frozen
  fallback. Any new signal plugs in as another blocking reason.
- `IngestService::freeze_verified` already downloads the tarball and verifies
  `dist.integrity` before freezing; the bytes (and the `ArtifactStore`) are the
  natural substrate for content scanning.
- Snapshot CLIs (`snapshot-npm`, `snapshot-pip`, `snapshot-nuget`) and the
  daily machine radar can surface scan findings next to `status`/`reasons`.
- Dashboard publishing (`PUT /api/v1/status/quarantine`) already sanitizes what
  leaves the machine; findings must stay name/version-level only.

## Experiment: naive heuristics are not enough

A local PoC (`quarantine_triage.py`, ~140 lines) downloaded
`vite@8.3.0` (1.9 days old — inside a 7-day window), diffed it against the
previous release, and scored static signals:

- 37 files, 2.3 MB unpacked; 1 file added, 16 changed vs `8.2.1`
- lifecycle install scripts: none
- regex signals: `child_process`, `eval`, hardcoded URLs, base64, net module…
- suspicion score **45/100 → "review"**, i.e. a false positive on a popular,
  legitimate build tool.

The conclusion from the experiment: raw capability regexes drown in legitimate
tooling behavior. What made the verdict easy to dismiss was the *context*:
verified SLSA provenance attestation (`dist.attestations`,
`predicateType: slsa.dev/provenance/v1`), registry signatures, two maintainers,
repo link matching the package metadata, and a small, reviewable diff. A real
scanner must combine capability + threat indicators + provenance + diff, and
score them together (which is exactly the design GuardDog converged on).

## Proposed pipeline

Stage 0 — intake facts (cheap, always on)
  registry metadata, tarball sha256, publisher/maintainer set, repo URL,
  publish cadence, signature/attestation presence, typosquat distance to
  popular names in the ecosystem, `dist.integrity` (already fetched).

Stage 1 — static content scan (per quarantine-window version)
  Adopt GuardDog as the engine: YARA rules + metadata detectors, capability +
  threat correlation in the same file, risk score 0–10, sandboxed extraction
  (Landlock/Seatbelt), SARIF/JSON output support. Run as a subprocess over the
  frozen tarball; cache by `(ecosystem, name, version, sha256)`.
  For a Rust-native MVP, port only the high-signal rules (install-script
  network/exec, credential paths, obfuscated blobs, native binaries).

Stage 2 — provenance and identity checks
  npm: verify `dist.attestations` (SLSA) via sigstore and compare the attested
  repo/workflow with the package metadata; PyPI: PEP 740 attestations; NuGet:
  repository signatures. Maintainer-set changes, publisher ≠ repo org, or
  first-time publisher of an old package are escalation signals, not proof.

Stage 3 — version diff (high signal, cheap)
  Compare with the previous release: new lifecycle scripts, new binary
  artifacts, new network endpoints, large minified/obfuscated blobs, deleted
  tests, changed install hooks. `diff_vs_baseline` in the PoC is the minimal
  version of this.

Stage 4 — optional dynamic analysis
  Only for versions whose stage-1..3 score exceeds a threshold: run
  `npm install`/`pip install` in a disposable sandbox with syscall and network
  egress monitoring (reuse OpenSSF Package Analysis patterns), or submit the
  package to the public Package Analysis sandbox and consume its results.

Stage 5 — scoring and policy
  Extend `Policy` with `quarantine_scanner { enabled, static, dynamic,
  review_score, block_score, report_score }`. New blocking reason kind
  `content-risk`. A confirmed-malicious decision is permanent (same semantics
  as `cve_keeps_quarantined`) and appends to the denylist with the finding id.

Stage 6 — findings store and reporting surface
  Persist findings next to decisions (state dir JSON + metadata store API).
  Snapshot entries gain `content_findings: [...]`; the public dashboard shows
  only name/version/decision as today.

## Acting like a CVE

- Blocking uses the existing `Decision` path, so the proxy/fallback behavior
  is unchanged; frozen fallback revalidation is extended to content findings,
  the same way advisories are rechecked today.
- Emit an OSV-shaped advisory internally (id, ecosystem, package, affected
  versions, summary, severity, references) so external submission is a
  serialization step, not a rewrite.

## Public disclosure matrix

| Finding kind | First target | Public record |
|---|---|---|
| Malicious npm package (malware, typosquat, dependency confusion) | npm "Report malware" form on the package page | npm advisory + OpenSSF `malicious-packages` PR |
| Malicious PyPI project | PyPI "Report project as malware" (with inspector.pypi.io links) | OSV feed via `ossf/malicious-packages` |
| Vulnerability in a dependency (not malicious) | Maintainers privately (`npm owner ls`, SECURITY.md) | GitHub Advisory Database (GHSA; GitHub is a CNA and can assign a CVE) |
| Malicious NuGet package | nuget.org abuse contact | `ossf/malicious-packages` |
| Confirmed exploitable 0-day without CNA | GitHub Security Advisories for the repo | CVE via a CNA (GitHub) |

OpenSSF `ossf/malicious-packages` accepts PRs of OSV reports, bulk imports
(issue first), and automated feeds from producers with low false-positive
rates (S3/GCS). Withdrawn reports stay in the dataset marked `withdrawn`;
false positives are corrected via issues.

Guardrails before any automated submission:

1. Score threshold plus **human approval**; never auto-publish first-party
   accusations.
2. Cite evidence (file paths, hashes, line references) in the report.
3. Report to the registry before (or together with) the public record so the
   package can be taken down.
4. Keep an audit log of submissions and a withdrawal path.
5. Rate-limit submissions to avoid burning bridges with a noisy false-positive
   stream; fix rules before resubmitting.

## Implementation status (2026-09-12)

0. **Wired path** — `supply scan-package <eco> <archive> --name --version
   [--external <cmd>] [--findings-out <jsonl>]` extracts the archive
   (file/size/traversal-limited, fail-closed on oversized entries), runs the
   static scanner and the optional external scanner, and persists findings.
   `snapshot-npm`, `snapshot-pip` and `snapshot-nuget` accept `--findings
   <jsonl>`; with `quarantine_scanner.enabled` those findings become
   blocks/fallback. The scanner→store→evaluator chain is covered by
   fixture-archive tests, and the external scanner is bounded by a timeout,
   an output cap, and process-group termination.
1. **Policy + finding model** — done. `Policy.quarantine_scanner`
   (`enabled=false`, `review_score=4`, `block_score=8`) and
   `ContentFinding`; the evaluator blocks at/above `block_score`, warns on
   `review_score`, and re-checks frozen fallback candidates.
2. **Finding store** — in-memory store plus `FindingFile` JSONL persistence
   (`append`/`load_into`, array or JSONL input, fails closed on missing or
   malformed files); multiple sources keep the highest score.
3. **Static correlation scanner** — done (`application::scanner`):
   capability + threat correlation per file, install-script network/pipe
   rules, cross-file install-script chain, benign build tooling stays clean
   (fixture-tested).
4. **External scanner adapter** — done (`adapters::command_scanner`):
   normalized `{"score","rules","summary"}` reports plus a **first-class
   GuardDog v3 parser** (`CommandScanner::guarddog`, pinned against GuardDog
   3.2.0 output: `risk_score.score`, matched `results` rules, `errors` fail
   closed). `scan-package --guarddog` runs it via `$GUARDDOG_BIN`; both
   findings persist with their source intact.
5. **Provenance** — done: `has_provenance` (npm `dist.attestations`) plus
   score downgrade via `apply_provenance`/`PROVENANCE_RELIEF` (3 points) and
   the `scan-package --provenance` flag; an attested archive drops from
   Block to a review warning in the evaluator.
6. **Version diff** — done (`diff_package_files`, `scan_version_diff`):
   newly introduced lifecycle scripts score 9 with rule `new-install-script`.
7. **OSV export + CLI** — done: `ContentFinding::to_osv()` and
   `supply report <findings.json> [--submit]` (prints OSV records plus the
   manual disclosure checklist).
8. **Submission** — manual gate by design: the CLI emits the checklist;
   automated registry/OpenSSF submission stays out until the false-positive
   rate is measured on real releases.

## Original plan

1. `Policy.quarantine_scanner` + `ContentFinding` domain type + evaluator test
   matrix (block/fallback/deny interactions).
2. Finding store API (`MetadataStore::save_finding` + read-back) with the
   in-memory store, then file-backed.
3. Static scanner trait + fixture tarballs (an install-script beacon fixture, a
   benign fixture from the PoC) — capability/threat correlation only, no
   regex-only blocks.
4. GuardDog adapter (subprocess, feature-flagged by `scanner.enabled`), with
   output parsing tests and a cache-key test.
5. Provenance stage (npm attestations first; sigstore verification optional).
6. Version-diff stage on top of the existing registry metadata.
7. OSV advisory export + `supply report --dry-run` CLI.
8. Submission workflow (manual approval) for npm/PyPI forms and the OpenSSF PR.

## References

- GuardDog — https://github.com/DataDog/guarddog (YARA + metadata rules,
  risk correlation, sandboxed scanning)
- OpenSSF malicious packages — https://github.com/ossf/malicious-packages
  (OSV-format reports, contribution guide)
- OpenSSF Package Analysis — https://github.com/ossf/package-analysis
  (dynamic sandbox, public data)
- npm malware reporting —
  https://docs.npmjs.com/reporting-malware-in-an-npm-package
- PyPI security policy — https://pypi.org/security/
- OSV.dev FAQ (how records enter OSV) — https://google.github.io/osv.dev/faq/
- npm provenance/attestations — https://docs.npmjs.com/generating-provenance-statements
- OSV schema — https://ossf.github.io/osv-schema/

## Appendix — PoC output (vite@8.3.0, diff vs 8.2.1)

```json
{
  "package": "vite@8.3.0",
  "published": "2026-09-10T11:30:26.283Z",
  "npm_user": "GitHub Actions",
  "maintainer_count": 2,
  "files": 37,
  "lifecycle_scripts": {},
  "suspicious_file_hits": {"hardcoded URL": 11, "process execution": 6, "base64 decoding": 4, "eval": 1},
  "diff_vs_baseline": {"added": 1, "removed": 0, "changed": 16},
  "suspicion_score": 45,
  "verdict": "review"
}
```

Provenance present (`dist.attestations` → SLSA v1) and the diff is small, so a
context-aware score would land well below the review threshold.
