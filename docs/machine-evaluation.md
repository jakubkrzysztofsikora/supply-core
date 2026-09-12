# Machine-wide evaluation

This is an observational evaluation, not an npm proxy or build enforcement.
The harness never installs dependencies or runs project scripts.

## Install and run on macOS

```bash
cargo build --release --locked
python3 experiments/install_machine_eval.py --home-scope
launchctl kickstart gui/$(id -u)/com.supply-core.machine-evaluation
```

The installer copies the binary and runner into a versioned directory under
`~/.local/share/supply-core/releases`. Source edits do not change a scheduled
evaluation until the installer is run again. The LaunchAgent runs at 08:30
local time while the user is logged in. A second agent at 08:45 runs
`experiments/daily-capture.sh`, which captures field-test quarantine snapshots
and publishes them to the server configured in
`~/.config/supply-core/status-publisher.env`. Missed calendar events during
sleep are coalesced by launchd; this is not a system daemon for logged-out users.

Configuration: `~/.local/share/supply-core/config.json`. `roots` lists discovery
roots, `workers` bounds repository concurrency (default 4), and `binary` pins
the scanner. The default root is the current user's home, not other users'
homes or external volumes. Add additional owned project roots explicitly.

Discovery excludes dependency/build/cache directories, Library, media folders,
and selected hidden tool directories. Every inventory records these exclusions.
Linked Git worktrees are listed as excluded duplicates of their common Git
directory; their differing branch contents are not evaluated. Separate clones
remain separate repositories. Discovery prunes a checkout once found and uses
Git metadata for its registered submodules and linked worktrees. Previously
inventoried nested checkouts are retained in configuration `known_repositories`.
Add new unregistered nested checkouts there explicitly. New discovery is bounded
to six directory levels below each root and skips hidden directories except
Git markers and `.deployer`. Add deeper locations as explicit discovery roots.
These limits keep daily discovery bounded; the inventory records them.

## Evidence

Each timestamped `runs/<timestamp>/` directory contains:

- `inventory.json`: selected repos, excluded worktrees, scope, discovery errors and warnings.
- `input-inventory.json`: tracked manifest/lockfile paths by repository, including
  inputs excluded by directory policy, mapped lockfiles, and inspection gaps/errors.
- `repos/*.json`: commit, dirty state, input hashes, lockfile coverage and scanner output.
- `summary.json`: OSV matches, Action policy findings, coverage gaps and errors.
- `report.md`: readable findings and coverage report.

`latest.json` points to the latest completed evaluation through its
`run_directory`. `baseline.json` preserves the first completed run without
evaluation errors (explicit format coverage gaps remain recorded). Failed runs
remain in their run directories. Comparisons are disabled if either run has errors or if discovery
roots, the binary, or runner change. No failed query is treated as a clean
result. Exit 2 means incomplete evaluation; findings alone do not fail an
observational run. Repository-level environment anomalies (unreadable or
mutating checkouts, missing tracked files, unresolved HEAD, slow filesystems)
are recorded as coverage gaps and do not fail the run. Discovery I/O and
submodule-inspection problems are recorded as discovery warnings. An
interrupted run may leave a directory without a summary.

Logs append to `launchd.log` and `launchd.err`. The run lock prevents overlaps.
The installer optionally retires the original `experiments/daily-capture.sh`
cron entry (the agent now schedules the script directly) to avoid duplicate
work: `--retire-legacy-cron` saves the original crontab in the state directory
and removes only the `# supply-core-daily-capture` entry.

## What is measured

Tracked npm package-lock/shrinkwrap versions 1, 2 and 3 supply exact package
versions, including dev and transitive dependencies. Workspace manifests are
mapped to their lockfile entries. Yarn Classic v1 lockfiles also supply exact
registry versions, including transitive and dev dependencies. Package identity
comes from the resolved public registry archive URL so npm aliases are preserved.
Only the manifest beside a Yarn lockfile is mapped; nested workspace manifests
remain explicit gaps until workspace mapping is supported.
Unsupported versions, custom sources, unmapped manifests, and pnpm/bun lockfiles
remain explicit coverage gaps. Yarn Berry is not supported. Missing tracked
files and unresolved HEAD are recorded as coverage gaps without aborting other
inputs.

Python `requirements.txt` exact pins (`==`, `===`) and NuGet `packages.lock.json`
resolved entries are evaluated too; ranges, environment markers, options and
URL requirements in requirements files are recorded as gaps. The input
inventory also lists other common Python, Rust, Go, Ruby and PHP
manifests/lockfiles for adapter prioritization; inventory of those does not mean
they have been checked against advisories. Summary counts exclude paths pruned
by directory policy; the detailed inventory retains them as excluded.

Unique package/version pairs are queried against OSV's fixed public batch API,
100 per request, with a shared 24-hour cache in trusted local state. Only npm,
PyPI and NuGet package names and versions are sent; repository paths and source
contents are not sent. Results are advisory IDs, not severity-filtered policy
decisions. Pagination, response errors, and missing results are incomplete
evaluations.

The Rust scanner evaluates working-tree GitHub workflows, including untracked
ones. Findings are file-level because the parser does not retain source spans.
Workflow inputs have per-file and aggregate size limits and a process timeout.

This run does not measure package age/quarantine, installed-byte integrity,
actual exploitability, or RubyGems/Cargo/Maven/Go ecosystems. Lockfiles describe
declared resolution, not proof of what is running. Repositories can change
during the scan; commit/dirty/hash evidence aids interpretation but is not an
atomic filesystem snapshot. An incomplete bootstrap baseline left by an older
runner is archived before a successful run establishes a usable baseline.

## Verification

```bash
python3 -m unittest discover -s experiments -p test_machine_eval.py
```

Use `--inventory-only` on the installed runner to inspect scope without OSV
requests. Stop scheduling with:

```bash
launchctl bootout gui/$(id -u)/com.supply-core.machine-evaluation
```
