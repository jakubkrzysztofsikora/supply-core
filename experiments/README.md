# Week-Long Field Test

Real-repo evaluation of supply-core before the next slice. 12 candidates
across two tracks; daily captures for ~7 days; report compares baseline
to latest.

## What this measures

- **What works:** scanner precision (pin classification vs known repo
  state), quarantine catch rate on genuinely fresh versions, range
  resolution correctness on live registry data.
- **What doesn't:** parser edge cases (block scalars, comments), error
  paths (unparseable ranges, missing metadata) — surfaced as `errors[]`.
- **Efficiency:** per-repo wall time in `*.time` files (sequential
  fetches; parallelism is a next-slice optimization if voxel's ~28s hurts).

## Running

```bash
./run.sh                    # capture today (baseline = first day)
./run.sh                    # re-run any later day
python3 report.py           # baseline vs latest diff
```

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

## Day-0 baseline observations (2026-08-15)

- `llama.cpp`: 249 action refs — 195 tag-pinned, 18 SHA-pinned, 36 local.
  Real-world hygiene baseline: ~78% unpinned.
- `voxel`: 66 deps, 6 quarantined **right now** (`next` age 1d,
  `zustand` 2d, `next-intl` 4d …) — the quarantine window fires on real
  dependency churn without any synthetic fixture.
- `sikoras-chat`: 51 deps, 3 quarantined, 0 errors.
- Runtimes: scanner 0.03–0.04s/repo (line parser is cheap); npm snapshot
  0.5–28s (registry-bound, sequential).

## After the week

Run `python3 report.py`, read decision flips and new-version volume,
then decide next slice priorities (OSV adapter, npm wire endpoints,
parallel fetches, AST-based workflow parsing) with data instead of vibes.
