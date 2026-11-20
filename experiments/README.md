# Week-Long Field Test

Real-repo evaluation of supply-core across npm and workflow tracks;
daily captures for ~7 days; report compares baseline to latest.

## What this measures

- **What works:** scanner precision (pin classification vs known repo
  state), quarantine catch rate on genuinely fresh versions, range
  resolution correctness on live registry data.
- **What doesn't:** parser edge cases (block scalars, comments), error
  paths (unparseable ranges, missing metadata) — surfaced as `errors[]`.
- **Efficiency:** per-repo wall time in `*.time` files (sequential
  fetches; parallelism is a next-slice optimization if the slowest
  repo's ~28s hurts).

## Running

```bash
cp candidates.example.txt candidates.txt   # then point entries at your checkouts
./run.sh                    # capture today (baseline = first day)
./run.sh                    # re-run any later day
python3 report.py           # baseline vs latest diff
```

`run.sh` and `report.py` share npm snapshot validation. Every dependency needs a
package name, resolved version, and recognized status; malformed snapshots make
capture incomplete.

`run.sh`, `remote-scan.sh`, and `daily-capture.sh` share a nonblocking lock
within the same checkout. Concurrent runs exit without modifying the capture.
Standalone `scan-quarantine.py` runs and the radar container's full cycle do
not hold this lock. Do not share their files with a concurrent capture.


## Daily auto-capture (GitHub-backed)

The cron wrapper pulls latest from the repo before each run, so editing
`candidates.txt`, `run.sh`, `report.py`, or source code on `main` (or
the checked-out branch) propagates within a day without touching the
cron entry.

```bash
./install-cron.sh           # 08:15 daily
crontab -l | grep supply-core
./uninstall-cron.sh         # remove
```

Log: `experiments/data/cron.log`.

Each daily capture scans package versions held by the quarantine window.
`scan-quarantine.py` verifies registry `sha512` downloads, then requests a
JSON `ArtifactReport` from `supply scan-package`. GuardDog 3.2 and OSSGadget
remain required for complete coverage; missing engines keep versions held.
Per-capture results land in `data/<day>/content-scan.json`. Findings append to
`data/content-findings.jsonl` for later `snapshot-npm --findings` enforcement.

Set `SUPPLY_SCRATCH_DIR` to a dedicated scan volume. The wrapper passes it to
`scan-package`; do not use a boot-disk path. Set `GUARDDOG_BIN` or
`--guarddog-bin` to select the GuardDog executable. There is no static-only
bypass. Incomplete scans remain held and retry later. A block appears in the
report without turning a completed scan into a process error.

`publish-status.py` builds the public snapshot from the same day: quarantine
holds, confirmed advisories, suspected scan findings, and incomplete scans.
Incomplete findings cap at 1,000; JSON reports the omitted count. The official
server renders the snapshot at `/api/v1/status` and as
`/api/v1/status/card.svg`.

## Day-0 baseline observations (2026-08-15)

- `llama.cpp`: 249 action refs — 195 tag-pinned, 18 SHA-pinned, 36 local.
  Real-world hygiene baseline: ~78% unpinned.
- A large web app: 66 deps, 6 quarantined **right now** (`next` age 1d,
  `zustand` 2d, `next-intl` 4d …) — the quarantine window fires on real
  dependency churn without any synthetic fixture.
- A chat service: 51 deps, 3 quarantined, 0 errors.
- Runtimes: scanner 0.03–0.04s/repo (line parser is cheap); npm snapshot
  0.5–28s (registry-bound, sequential).

## After the week

Run `python3 report.py`, read decision flips and new-version volume,
then decide next slice priorities (OSV adapter, npm wire endpoints,
parallel fetches, AST-based workflow parsing) with data instead of vibes.
