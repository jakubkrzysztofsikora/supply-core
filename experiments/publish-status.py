#!/usr/bin/env python3
"""Convert one daily capture into the public status snapshot.

The snapshot is what the official server stores, exposes at
`/api/v1/status`, and renders as the status card (`/api/v1/status/card.svg`):

- `packages`: versions held by the quarantine window (name/version/age/decision)
- `confirmed`: known advisories (OSV) that blocked a version
- `suspected`: content-scan findings (GuardDog + static AI/agent rules)

Only name/version-level facts leave the machine: no repository paths, no
version ranges, no file contents.
"""
import json
import re
import sys
from pathlib import Path

MAX_LIST = 500
MAX_RULES = 8
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
VULNERABILITY_RE = re.compile(
    r"^(?P<severity>critical|high|medium|low) vulnerability (?P<advisory>\S+) from (?P<source>.+)$",
    re.IGNORECASE,
)
SCAN_SCORE_RE = re.compile(r"content scan(?: review)? \(score (?P<score>\d+)\)")


def fail(message):
    raise SystemExit(message)


def load_dependencies(capture_dir):
    files = sorted(capture_dir.glob("*.npm.json"))
    if not files:
        fail("no npm snapshots found")
    captured_at = []
    dependencies = []
    for path in files:
        try:
            report = json.loads(path.read_text())
            captured_at.append(report["captured_at"])
            entries = report["dependencies"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            fail(f"invalid npm snapshot {path}: {error}")
        if not isinstance(entries, list):
            fail(f"invalid dependencies in {path}")
        dependencies.extend(entry for entry in entries if isinstance(entry, dict))
    return max(captured_at), dependencies


def quarantined_packages(dependencies):
    packages = set()
    for dependency in dependencies:
        reasons = dependency.get("reasons", [])
        if not any("inside quarantine window" in str(reason) for reason in reasons):
            continue
        try:
            package = (
                dependency["package"],
                dependency["resolved"],
                dependency["age_days"],
                dependency["status"],
            )
        except KeyError as error:
            fail(f"missing quarantine field: {error}")
        if not package[0] or not package[1] or package[2] < 0:
            fail(f"invalid quarantine package: {package[0]}@{package[1]}")
        packages.add(package)
    return [
        {"name": name, "version": version, "age_days": age_days, "status": status}
        for name, version, age_days, status in sorted(packages)
    ]


def confirmed_findings(dependencies):
    """Known advisories that the evaluator reported as blocking reasons."""
    rows, seen = [], set()
    for dependency in dependencies:
        name, version = dependency.get("package"), dependency.get("resolved")
        for reason in dependency.get("reasons") or []:
            match = VULNERABILITY_RE.match(str(reason))
            if not match or not name or not version:
                continue
            key = (name, version, match.group("advisory"))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "name": name,
                    "version": version,
                    "advisory": match.group("advisory"),
                    "severity": match.group("severity").lower(),
                }
            )
    rows.sort(
        key=lambda row: (SEVERITY_RANK.get(row["severity"], 0), row["name"], row["version"]),
        reverse=True,
    )
    return rows[:MAX_LIST]


def suspected_findings(dependencies, scan_report):
    """Content-scan findings, preferring the structured scan report."""
    rows = {}
    if isinstance(scan_report, dict):
        for entry in scan_report.get("scanned") or []:
            if not isinstance(entry, dict) or int(entry.get("findings", 0)) <= 0:
                continue
            name, version = entry.get("package"), entry.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            rules = [rule for rule in (entry.get("rules") or []) if isinstance(rule, str)]
            rows[(name, version)] = {
                "name": name,
                "version": version,
                "score": int(entry.get("score", 0)),
                "rules": rules[:MAX_RULES],
            }
    for dependency in dependencies:
        name, version = dependency.get("package"), dependency.get("resolved")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        score = None
        for warning in dependency.get("warnings") or []:
            match = SCAN_SCORE_RE.search(str(warning))
            if match:
                score = max(score or 0, int(match.group("score")))
        for reason in dependency.get("reasons") or []:
            if "content scan" not in str(reason):
                continue
            match = SCAN_SCORE_RE.search(str(reason))
            score = max(score or 0, int(match.group("score")) if match else 0)
        if score is not None and (name, version) not in rows:
            rows[(name, version)] = {
                "name": name,
                "version": version,
                "score": score,
                "rules": [],
            }
    ordered = sorted(rows.values(), key=lambda row: (-row["score"], row["name"], row["version"]))
    return ordered[:MAX_LIST]


def build_snapshot(capture_dir):
    captured_at, dependencies = load_dependencies(capture_dir)
    scan_report = None
    scan_path = capture_dir / "content-scan.json"
    if scan_path.exists():
        try:
            scan_report = json.loads(scan_path.read_text())
        except (OSError, json.JSONDecodeError):
            scan_report = None
    return {
        "captured_at": captured_at,
        "packages": quarantined_packages(dependencies),
        "confirmed": confirmed_findings(dependencies),
        "suspected": suspected_findings(dependencies, scan_report),
    }


def main():
    if len(sys.argv) != 2:
        fail("usage: publish-status.py <daily-capture-directory>")
    snapshot = build_snapshot(Path(sys.argv[1]))
    print(json.dumps(snapshot, separators=(",", ":")))


if __name__ == "__main__":
    main()
