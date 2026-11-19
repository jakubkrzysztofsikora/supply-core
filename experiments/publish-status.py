#!/usr/bin/env python3
"""Convert one daily capture into the public status snapshot.

The snapshot is what the official server stores, exposes at
`/api/v1/status`, and renders as the status card (`/api/v1/status/card.svg`):

- `packages`: versions held by the quarantine window (name/version/age/decision)
- `confirmed`: known advisories (OSV) that blocked a version
- `suspected`: content-scan findings, including blocks from partial scans
- `scan_incomplete`: name/version pairs with incomplete coverage, capped at 1,000
- `scan_incomplete_truncated`: omitted count after the 1,000-row cap
- `scan`: capture time, candidate/error counts, and sanitized scanned details when available

Only name/version-level facts leave the machine: no repository paths, no
version ranges, no file contents.
"""
import datetime
import json
import re
import sys
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path

MAX_LIST = 500
MAX_INCOMPLETE_FINDINGS = 1000
MAX_RULES = 8
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
VULNERABILITY_RE = re.compile(
    r"^(?P<severity>critical|high|medium|low) vulnerability (?P<advisory>\S+) from (?P<source>.+)$",
    re.IGNORECASE,
)
SCAN_SCORE_RE = re.compile(r"content scan(?: review)? \(score (?P<score>\d+)\)")
MAX_SCAN_REPORT_BYTES = 1_000_000
MAX_SCAN_ROWS = 1_000
MAX_SCAN_CANDIDATES = 100_000
MAX_SCAN_ERRORS = 100_000
MAX_SCAN_FINDINGS = 100_000
MAX_SCAN_IDENTIFIERS = 16
MAX_SCAN_FIELD_BYTES = 256
MAX_SCAN_IDENTIFIER_BYTES = 120
MAX_SCAN_ERROR_BYTES = 2_048
MAX_SCAN_SCORE_BYTES = 32
SCAN_DECISIONS = {"pass", "review", "block", "incomplete"}
SCAN_COVERAGES = {"complete", "partial", "unknown"}
SCAN_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:")


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


def scan_incomplete_findings(dependencies, scan_report):
    incomplete = set()
    for dependency in dependencies:
        name, version = dependency.get("package"), dependency.get("resolved")
        if (
            isinstance(name, str)
            and isinstance(version, str)
            and any(
                "content scan incomplete" in str(reason).lower()
                for reason in dependency.get("reasons") or []
            )
        ):
            incomplete.add((name, version))
    if isinstance(scan_report, dict):
        for entry in scan_report.get("errors") or []:
            if not isinstance(entry, dict):
                continue
            name, version = entry.get("package"), entry.get("version")
            if isinstance(name, str) and isinstance(version, str):
                incomplete.add((name, version))
    return [
        {"name": name, "version": version, "verdict": "scan_incomplete"}
        for name, version in sorted(incomplete)
    ]


def suspected_findings(dependencies, scan_report):
    """Content-scan findings, preferring the structured scan report."""
    rows = {}
    incomplete = {
        (entry["name"], entry["version"])
        for entry in scan_incomplete_findings(dependencies, scan_report)
    }
    if isinstance(scan_report, dict):
        for entry in scan_report.get("scanned") or []:
            if not isinstance(entry, dict) or int(entry.get("findings", 0)) <= 0:
                continue
            name, version = entry.get("package"), entry.get("version")
            decision = entry.get("decision")
            if (
                not isinstance(name, str)
                or not isinstance(version, str)
                or ((name, version) in incomplete and decision != "block")
            ):
                continue
            raw_score = entry.get("score", 0)
            score_value = Decimal(str(raw_score or 0))
            legacy_score = 0 if raw_score is None else int(score_value)
            rules = [rule for rule in (entry.get("rules") or []) if isinstance(rule, str)]
            row = {
                "name": name,
                "version": version,
                "score": legacy_score,
                "rules": rules[:MAX_RULES],
                "_sort_score": score_value,
            }
            if decision in {"pass", "review", "block", "incomplete"}:
                row["decision"] = decision
            if entry.get("coverage") in {"complete", "partial", "unknown"}:
                row["coverage"] = entry["coverage"]
            rows[(name, version)] = row
    for dependency in dependencies:
        name, version = dependency.get("package"), dependency.get("resolved")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or (name, version) in incomplete
        ):
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
                "_sort_score": Decimal(score),
            }
    ordered = sorted(
        rows.values(),
        key=lambda row: (-row["_sort_score"], row["name"], row["version"]),
    )
    for row in ordered:
        del row["_sort_score"]
    return ordered[:MAX_LIST]


def scan_fail():
    fail("invalid content scan report")


def scan_text_bytes(value):
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        scan_fail()


def scan_timestamp(value):
    if not isinstance(value, str) or scan_text_bytes(value) > 64:
        scan_fail()
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except (ValueError, OverflowError):
        scan_fail()
    if len(value) < 20 or value[10] != "T" or parsed.tzinfo is None:
        scan_fail()
    return value


def scan_identity(value, allow_scope=False):
    if (
        not isinstance(value, str)
        or not value.strip()
        or scan_text_bytes(value) > MAX_SCAN_FIELD_BYTES
        or any(unicodedata.category(character) == "Cc" for character in value)
        or value.startswith(("/", "\\"))
        or WINDOWS_PATH_RE.match(value)
        or value.lower().startswith("file:")
        or "\\" in value
    ):
        scan_fail()
    if allow_scope:
        if value.count("/") > 1 or ("/" in value and not value.startswith("@")):
            scan_fail()
        if "/" in value and any(not part for part in value.split("/")):
            scan_fail()
    elif "/" in value:
        scan_fail()
    return value


def scan_identifiers(value):
    if not isinstance(value, list) or len(value) > MAX_SCAN_IDENTIFIERS:
        scan_fail()
    identifiers = []
    for identifier in value:
        if (
            not isinstance(identifier, str)
            or not identifier
            or scan_text_bytes(identifier) > MAX_SCAN_IDENTIFIER_BYTES
            or not SCAN_IDENTIFIER_RE.fullmatch(identifier)
        ):
            scan_fail()
        identifiers.append(identifier)
    return identifiers


def scan_count(value, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        scan_fail()
    return value


def scan_score(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        scan_fail()
    score = Decimal(value)
    parts = score.as_tuple()
    if (
        not score.is_finite()
        or not 0 <= score <= 10
        or len(parts.digits) > 29
        or max(-parts.exponent, 0) > 28
    ):
        scan_fail()
    text = format(score, "f")
    if len(text) > MAX_SCAN_SCORE_BYTES:
        scan_fail()
    return text


def load_scan_report(path):
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_SCAN_REPORT_BYTES + 1)
    except OSError:
        scan_fail()
    if len(raw) > MAX_SCAN_REPORT_BYTES:
        scan_fail()
    try:
        report = json.loads(raw.decode("utf-8"), parse_float=Decimal)
    except (UnicodeDecodeError, ValueError, InvalidOperation):
        scan_fail()
    if not isinstance(report, dict):
        scan_fail()
    return report


def public_scan_summary(report):
    if report is None:
        return None
    captured_at = scan_timestamp(report.get("captured_at"))
    candidate_count = scan_count(report.get("candidates"), MAX_SCAN_CANDIDATES)
    scanned = report.get("scanned")
    errors = report.get("errors")
    if not isinstance(scanned, list) or len(scanned) > MAX_SCAN_ROWS:
        scan_fail()
    if not isinstance(errors, list) or len(errors) > MAX_SCAN_ERRORS:
        scan_fail()
    rows = []
    for entry in scanned:
        if not isinstance(entry, dict):
            scan_fail()
        name = scan_identity(entry.get("package"), allow_scope=True)
        version = scan_identity(entry.get("version"))
        decision = entry.get("decision")
        coverage = entry.get("coverage")
        if (
            not isinstance(decision, str)
            or decision not in SCAN_DECISIONS
            or not isinstance(coverage, str)
            or coverage not in SCAN_COVERAGES
        ):
            scan_fail()
        rows.append({
            "name": name,
            "version": version,
            "decision": decision,
            "coverage": coverage,
            "findings": scan_count(entry.get("findings"), MAX_SCAN_FINDINGS),
            "score": scan_score(entry.get("score")),
            "rules": scan_identifiers(entry.get("rules")),
            "sources": scan_identifiers(entry.get("sources")),
            "reasons": scan_identifiers(entry.get("reasons", [])),
        })
    for entry in errors:
        if not isinstance(entry, dict):
            scan_fail()
        scan_identity(entry.get("package"), allow_scope=True)
        scan_identity(entry.get("version"))
        error = entry.get("error")
        if (
            not isinstance(error, str)
            or scan_text_bytes(error) > MAX_SCAN_ERROR_BYTES
        ):
            scan_fail()
    if candidate_count < len(rows):
        scan_fail()
    return {
        "captured_at": captured_at,
        "candidate_count": candidate_count,
        "scanned": rows,
        "error_count": len(errors),
    }


def build_snapshot(capture_dir):
    captured_at, dependencies = load_dependencies(capture_dir)
    scan_report = None
    scan_path = capture_dir / "content-scan.json"
    if scan_path.exists():
        scan_report = load_scan_report(scan_path)
    scan = public_scan_summary(scan_report)
    incomplete = scan_incomplete_findings(dependencies, scan_report)
    snapshot = {
        "captured_at": captured_at,
        "packages": quarantined_packages(dependencies),
        "confirmed": confirmed_findings(dependencies),
        "suspected": suspected_findings(dependencies, scan_report),
        "scan_incomplete": incomplete[:MAX_INCOMPLETE_FINDINGS],
        "scan_incomplete_truncated": max(
            0, len(incomplete) - MAX_INCOMPLETE_FINDINGS
        ),
    }
    if scan is not None:
        snapshot["scan"] = scan
    return snapshot


def main():
    if len(sys.argv) != 2:
        fail("usage: publish-status.py <daily-capture-directory>")
    snapshot = build_snapshot(Path(sys.argv[1]))
    print(json.dumps(snapshot, separators=(",", ":")))


if __name__ == "__main__":
    main()
