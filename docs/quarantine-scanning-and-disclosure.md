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
  leaves the machine; findings must stay name/version-level only. The server
  renders the stored snapshot as JSON (`/api/v1/status`) and as the dynamic
  status card (`/api/v1/status/card.svg`).

## Experiment: naive heuristics are not enough

A local PoC (`quarantine_triage.py`, ~140 lines) downloaded
`vite@8.3.0` (1.9 days old — inside a 7-day window), diffed it against the
previous release, and scored static signals:

- 37 files, 2.3 MB unpacked; 1 file added, 16 changed vs `8.2.1`
- lifecycle install scripts: none
- regex signals: `child_process`, `eval`, hardcoded URLs, base64, net module…
- suspicion score **45/100 → "review"**, i.e. a false positive on a popular,
  legitimate build tool.

The PoC shows that raw capability regexes can misclassify benign packages.
It did not inspect `dist.attestations`, verify a signature, or validate an
attested build identity. Registry metadata may advertise provenance, but
field presence does not establish verified provenance. A separately
verified, identity-bound statement may inform review; it must not lower
scanner scores by itself.

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

Stage 2 — provenance and identity checks (planned; not implemented here)
  npm: verify `dist.attestations` (SLSA) via Sigstore and compare the attested
  repo/workflow with package metadata; PyPI: verify PEP 740 attestations;
  NuGet: verify repository signatures. Metadata presence alone is not
  verification or score relief.

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
  `content-risk`. Active OSV advisories block regardless of severity. A
  confirmed-malicious decision remains permanent and records its finding id.

Stage 6 — findings store and reporting surface
  Persist findings next to decisions (state dir JSON + metadata store API).
  Snapshot entries gain `content_findings: [...]`; the public snapshot and
  status card publish name/version-level facts only (quarantine holds,
  confirmed advisories, suspected scan scores/rules).
## Durable scanner evidence

Package scan ledger events persist scanner findings separately from CVE findings. Each finding retains its source, rules, summary, decimal score, incomplete flag, and detection time. The package score is the highest score among complete findings; any incomplete or scoreless finding clears the aggregate score and marks overall coverage `Partial`, matching enforcement, which discards scores from incomplete scans. Failed scans retain findings observed before the failure.

Combined scan events use `supply-core` as the event source; each finding retains its scanner source. The reported score remains evidence, not an enforcement verdict.



## Optional OSSGadget engine

`scripts/install-ossgadget.sh <new-install-directory>` builds OSSGadget from
Microsoft commit `4063457b40211c25b41d56465d41783f2d42c5c1`, applies the
maintained coverage patch, and writes a local manifest binding the binary and
`Resources/BackdoorRules` digests. Set `OSSGADGET_BIN` to the installed
executable; `OSSGADGET_MANIFEST` may select its manifest explicitly. The
manifest detects byte changes but is not an independent signature or trust
anchor.

The installer disables NBGV's Git engine for archive builds; its manifest still
records the pinned upstream commit.

The Linux adapter requires bubblewrap. It unshares network access, mounts the
package and scanner installation read-only, and limits memory, runtime, and
output. The patched CLI scans each file separately and reports scanned,
skipped, and diagnostic paths. A file counts as scanned only when its result
identifies that exact file and reports one analyzed input. Missing results,
enumeration errors, malformed output, truncation, or a missing rule bundle
leave coverage partial. OSSGadget findings score 4 for review; its detector
has a high false-positive rate. macOS remains incomplete because the current
adapter cannot enforce its memory limit there.

## Verify local ledger

Run `cargo run -- ledger verify` to check event payloads, contiguous positions,
leaf hashes, the RFC 6962 root, and persisted Merkle nodes. The default path is
`$HOME/.local/share/supply-core/ledger.sqlite`; pass `--ledger-db PATH` to select
another database.

Verification requires an existing database and uses a read-only SQLite
connection. It does not initialize the schema or change journal mode.

This checks internal consistency only. An actor who can rewrite the complete
database can recompute its hashes and root. Detecting a full rewrite requires
comparing against a trusted external checkpoint or witness.

## Approving one scanner finding

For a reviewed false positive, use the exact `artifact_sha256`, finding `id`,
and `engine_policy_revision_sha256` from the scan report:

```sh
cargo run -- approve-rule \
  --artifact-sha256 "$ARTIFACT_SHA256" \
  --finding-id "$FINDING_ID" \
  --policy-sha256 "$ENGINE_POLICY_REVISION_SHA256" \
  --expires-at "$FUTURE_RFC3339" \
  --reason "Reviewed false positive"
```

The command appends a local `RuleApproved` event. It requires matching real
and effective Unix user IDs and a ledger owned by that user. The ledger file
must have mode `0600`; non-Unix platforms fail closed. No remote approval
endpoint exists.

An approval affects only `scan-package`'s decision for the exact finding ID,
artifact digest, and engine-policy revision, and only until expiry. A changed
artifact or engine-policy revision requires a new approval. The original scan
finding remains in evidence. Approval cannot change incomplete coverage to
complete or clear other findings; it does not alter `FindingFile` JSONL records
or `snapshot-*` decisions.

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

## Implementation status (2026-09-13)

0. **Wired path** — `supply scan-package <eco> <archive> --name --version
   [--scratch-dir <dir>] [--external <cmd>] [--findings-out <jsonl>] [--json]`
   requires a real dedicated scratch directory through `--scratch-dir` or
   compressed input is normally capped at 64 MiB. Unix large scans support up to
   2 GiB compressed and 8 GiB expanded data; they require a separate user-owned,
   non-shared scratch volume, one active large scan per scratch directory, and
   10 GiB free space maintained throughout. Other platforms fail closed.
   External engines stay unknown for large scans until their per-scan scratch
   quota can be enforced; built-in findings remain available.
   Incomplete extraction yields partial coverage. JSON mode emits `ArtifactReport` and
   returns 0 for pass/review, 2 for block, and 3 for incomplete/error.
   Archive input must be a regular file; symlinks and special files are rejected.
   Current archive inventory covers npm `.tgz`, PyPI sdist/wheel, and NuGet
   `.nupkg`; `scan-package` accepts `npm`, `pypi`/`pip`, and `nuget`.
   `snapshot-npm`, `snapshot-pip` and `snapshot-nuget` accept `--findings
   <jsonl>`; with `quarantine_scanner.enabled` those findings become
   blocks/fallback. The scanner→store→evaluator chain is covered by
   fixture-archive tests, and external scanning is bounded by timeout, output
   limits, and process-group termination.
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
   NuGet hook detection flags `tools/init.ps1` and inline `CodeTaskFactory`/
   `RoslynCodeTaskFactory` tasks under `build/`, `buildMultiTargeting/`, and
   `buildTransitive/`. DTD/custom entities and malformed XML leave coverage
   incomplete; the scanner never executes package code.
4. **External scanner adapter** — done (`adapters::command_scanner`):
   normalized `{"score","rules","summary"}` reports plus a **first-class
   GuardDog v3 parser** (`CommandScanner::guarddog`, pinned against GuardDog
   3.2.0 output: `risk_score.score`, matched `results` rules, `errors` fail
   closed). `scan-package` automatically attempts it for npm/PyPI via
   `$GUARDDOG_BIN`; findings persist with their source intact.
5. **Provenance** — not implemented. Registry metadata is not verified as
   build provenance and cannot change scan scores or verdicts. Provenance-based
   policy requires cryptographic verification and publisher/workflow identity
   checks before use.
6. **Version diff** — done (`diff_package_files`, `scan_version_diff`):
   newly introduced lifecycle scripts score 9 with rule `new-install-script`.
7. **OSV export + CLI** — done: `ContentFinding::to_osv()` and
   `supply report <findings.json> [--submit]` (prints OSV records plus the
   manual disclosure checklist).
8. **Submission** — manual gate by design: the CLI emits the checklist;
   automated registry/OpenSSF submission stays out until the false-positive
   rate is measured on real releases.
9. **GuardDog installed and wired** — `uv tool install guarddog` (3.2.0,
   Python 3.13); `scan-package` attempts it under a 180 s timeout and an 8 MiB
   output cap. Isolation failures, root execution, or missing engines stay
   incomplete; static-only scans cannot claim clean coverage. The daily
   capture verifies tarballs against `dist.integrity` (sha512) before any
   scanner sees them.
10. **AI/agent-threat rules** — `application::ai_scanner` adds deterministic,
    offline rules: `ai-prompt-injection` (LLM role tokens or
    instruction-override text, with zero-width/bidi normalization),
    `ai-agent-config` (hostile instructions in `CLAUDE.md`, `.cursorrules`,
    `.mcp.json`, …), `ai-agent-secrets` (agent state or hardcoded provider
    keys plus exfiltration capability), `ai-hidden-instructions`,
    `ai-install-script`, and `slopsquat-name` (name one edit from a popular
    package). No LLM sits in the scanning loop — an injected payload could
    steer its own judge. Every extracted file is scored, including test
    paths; the obfuscation rule only escalates when dynamic evaluation
    meets an encoded payload.
11. **Daily enforcement** — `experiments/policy.yml` enables
    `quarantine_scanner`; findings accumulate in
    `experiments/data/content-findings.jsonl` and are loaded by
    `snapshot-npm --findings`, so a block-level finding turns a held version
    into a permanent `Block`/`Fallback` on later captures. A failed or
    skipped scan writes a block-level `scan-incomplete` record (fail closed)
    tagged with the engines that were required; it stays on the retry list
    until a matching scan succeeds — even after the version leaves the
    quarantine window — and a static-only run cannot clear a GuardDog-pending
    hold.
    Versions the capture already blocks on a critical or high advisory are
    scanned every day as *verification only*: their findings are not written,
    because the evaluator weighs a content-scan hold before the OSV query and
    a hold would displace the advisory reason, hiding the confirmed row from
    the published status. A verified complete scan clears every
    `scan-incomplete` record for that version — including digestless ones
    left by fetch failures — since npm tarballs are immutable and a later
    complete scan supersedes them.
11a. **Attested scan runner** — the daily pipeline copies the capture into a
    short-lived pod on the `scanner` image (`SUPPLY_SCAN_IMAGE`, Dockerfile
    stage `scanner`, which sets `SUPPLY_SCRATCH_DIR=/scratch`) through
    `experiments/remote-scan.sh`, runs `scan-quarantine.py` there, and copies
    the scan report, findings file and ledger back. The capture host rebuilds
    only the binary it uses for capture, so scanner-image changes reach
    production through this pod rather than `cargo build`.
12. **Public status surface** — `experiments/publish-status.py` builds the
    snapshot from the day's capture plus `content-scan.json`: quarantine holds,
    confirmed OSV advisories (parsed from evaluator reasons), suspected scan
    findings (score + rules), and incomplete scans. Incomplete findings cap at
    1,000; the JSON API reports the omitted count, while the card shows the
    total and remaining rows. The server stores it behind
    `PUT /api/v1/status/quarantine` (bearer token, size- and shape-validated)
    and serves `GET /api/v1/status` (JSON) and
    `GET /api/v1/status/card.svg` (dynamic SVG with four lists,
    `Cache-Control: public, max-age=300`). Long card rows clip within their
    columns and retain full text in accessible labels. Only name/version-level
    facts are published: no repository paths, ranges, or file contents.
    Older snapshots remain valid; missing fields default to empty lists and
    zero omitted rows.

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

The PoC did not verify provenance. Upstream `dist.attestations` metadata
cannot establish provenance or lower this PoC's score.
