#!/usr/bin/env python3
"""Compare baseline (oldest) vs latest capture. Week-experiment feedback:
what works, what doesn't, efficiency. Run after `run.sh` on any later day."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE / "data"


def load_days():
    days = sorted(d for d in DATA.iterdir() if d.is_dir())
    if len(days) < 2:
        print("need >= 2 capture days; run ./run.sh again later")
        sys.exit(1)
    return days[0], days[-1]


def npm_index(day_dir, name):
    f = day_dir / f"{name}.npm.json"
    if not f.exists():
        return None
    doc = json.loads(f.read_text())
    return {d["package"]: d for d in doc.get("dependencies", [])}


def actions_index(day_dir, name):
    f = day_dir / f"{name}.actions.json"
    if not f.exists():
        return None
    doc = json.loads(f.read_text())
    return {
        (r["file"], r["line"], r["raw"]): r["pin_kind"]
        for r in doc.get("references", [])
    }, len(doc.get("findings", []))


def main():
    base, last = load_days()
    print(f"# supply-core field report: {base.name} -> {last.name}\n")

    candidates = [line.split("\t") for line in (HERE / "candidates.txt").read_text().splitlines()
                  if line and not line.startswith("#")]

    for name, _, tracks in candidates:
        if "npm" in tracks:
            b, l = npm_index(base, name), npm_index(last, name)
            if b is None or l is None:
                continue
            new_versions, flips, new_quarantined = [], [], []
            for pkg, cur in l.items():
                prev = b.get(pkg)
                if prev is None:
                    continue
                if prev["resolved"] != cur["resolved"]:
                    new_versions.append((pkg, prev["resolved"], cur["resolved"], cur["age_days"]))
                if prev["status"] != cur["status"]:
                    flips.append((pkg, prev["status"], cur["status"]))
                if cur["status"] != "Allow" and prev["status"] == "Allow":
                    new_quarantined.append(pkg)
            errs = sum(1 for _ in l)
            bt = (base / f"{name}.npm.time").read_text().strip()
            lt = (last / f"{name}.npm.time").read_text().strip()
            print(f"## {name} (npm) — {len(l)} deps, runtime {bt} -> {lt}")
            print(f"- upstream new versions: {len(new_versions)}")
            for pkg, old, new, age in new_versions:
                print(f"  - {pkg}: {old} -> {new} (age {age}d)")
            print(f"- decision flips: {len(flips)}")
            for pkg, a, b_ in flips:
                print(f"  - {pkg}: {a} -> {b_}")
            print(f"- newly held (Allow -> Block/Fallback): {len(new_quarantined)}")
            print()

        if "actions" in tracks:
            bi, li = actions_index(base, name), actions_index(last, name)
            if bi is None or li is None:
                continue
            brefs, bblocks = bi
            lrefs, lblocks = li
            added = set(lrefs) - set(brefs)
            removed = set(brefs) - set(lrefs)
            bt = (base / f"{name}.actions.time").read_text().strip()
            lt = (last / f"{name}.actions.time").read_text().strip()
            print(f"## {name} (actions) — {len(brefs)} -> {len(lrefs)} refs, "
                  f"blocks {bblocks} -> {lblocks}, runtime {bt} -> {lt}")
            for f_, ln, raw in sorted(added):
                print(f"  + {raw} ({f_}:{ln}) pin={lrefs[(f_, ln, raw)]}")
            for f_, ln, raw in sorted(removed):
                print(f"  - {raw} ({f_}:{ln})")
            print()


if __name__ == "__main__":
    main()
