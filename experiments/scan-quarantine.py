#!/usr/bin/env python3
"""Content-scan the npm versions a daily capture holds in the quarantine window.

For every dependency whose decision carries an "inside quarantine window"
reason, the wrapper:

1. resolves the exact version document on registry.npmjs.org,
2. downloads the tarball and verifies it against `dist.integrity` (sha512),
   so the scanner only ever sees bytes the registry vouched for,
3. runs `supply scan-package` against the verified staged archive and parses its JSON `ArtifactReport`,
4. appends findings to a shared JSONL file.

The JSONL file is what `snapshot-npm --findings` enforces on later captures.
Every candidate is scanned unless `--limit` asks for a subset. Downloads are
cached by name@version. Incomplete scans remain held for retry; blocks are
reported as scan outcomes, not process failures.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

REGISTRY = "https://registry.npmjs.org"
MAX_TARBALL_BYTES = 64 * 1024 * 1024


def quarantined_packages(documents):
    """Unique (name, version) pairs held by the quarantine window.

    Accepts parsed npm snapshot documents; later duplicates lose to the
    first occurrence so the output is stable across days.
    """
    seen, packages = set(), []
    for document in documents:
        dependencies = document.get("dependencies")
        if not isinstance(dependencies, list):
            continue
        for dependency in dependencies:
            reasons = dependency.get("reasons") or []
            if not any("inside quarantine window" in str(reason) for reason in reasons):
                continue
            name = dependency.get("package")
            version = dependency.get("resolved")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            if (name, version) in seen:
                continue
            seen.add((name, version))
            packages.append({"package": name, "version": version})
    return packages


def safe_file_name(name, version):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    digest = hashlib.sha256(name.encode()).hexdigest()[:12]
    return f"{slug}-{digest}-{version}.tgz"


def limited(packages, limit):
    """Apply the optional scan cap; 0 means every package."""
    return packages if limit <= 0 else packages[:limit]


def incomplete_candidates(path):
    """(package, version) pairs that still carry a scan-incomplete record.

    These are retried even after leaving the quarantine window, otherwise a
    transient failure would block a version forever with no path to clearing.
    """
    candidates, seen = [], set()
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return candidates
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(record, dict)
            and INCOMPLETE_RULE in (record.get("rules") or [])
            and isinstance(record.get("package"), str)
            and isinstance(record.get("version"), str)
        ):
            key = (record["package"], record["version"])
            if key not in seen:
                seen.add(key)
                candidates.append({"package": record["package"], "version": record["version"]})
    return candidates


def merge_candidates(window, pending):
    merged = list(window)
    seen = {(item["package"], item["version"]) for item in window}
    for item in pending:
        key = (item["package"], item["version"])
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def version_url(name, version):
    quoted_name = urllib.parse.quote(name, safe="@")
    quoted_version = urllib.parse.quote(version, safe="")
    return f"{REGISTRY}/{quoted_name}/{quoted_version}"


def parse_version_document(document, name, version):
    """Extract (tarball_url, integrity) from a registry version document.

    Fails closed on anything that is not an https registry.npmjs.org
    tarball or a sha512 integrity string.
    """
    if not isinstance(document, dict):
        raise ValueError(f"{name}@{version}: registry document is not an object")
    dist = document.get("dist")
    if not isinstance(dist, dict):
        raise ValueError(f"{name}@{version}: registry document has no dist")
    tarball = dist.get("tarball")
    integrity = dist.get("integrity")
    expected_prefix = f"{REGISTRY}/"
    if not isinstance(tarball, str) or not tarball.startswith(expected_prefix):
        raise ValueError(f"{name}@{version}: unexpected tarball url {tarball!r}")
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise ValueError(f"{name}@{version}: unsupported integrity {integrity!r}")
    return tarball, integrity


def verify_integrity(data, integrity):
    algorithm, _, encoded = integrity.partition("-")
    if algorithm != "sha512":
        raise ValueError(f"unsupported integrity algorithm: {algorithm}")
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    if digest != encoded:
        raise ValueError("tarball bytes do not match dist.integrity")


def fetch(url, limit=MAX_TARBALL_BYTES, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": "supply-core-quarantine-scan/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if not response.geturl().startswith(f"{REGISTRY}/"):
            raise ValueError(f"redirected outside the registry: {response.geturl()}")
        chunks, total = [], 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"download exceeds {limit} bytes")
            chunks.append(chunk)
    return b"".join(chunks)


def fetch_json(url, timeout=30):
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "supply-core-quarantine-scan/1"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if not response.geturl().startswith(f"{REGISTRY}/"):
            raise ValueError(f"redirected outside the registry: {response.geturl()}")
        return json.load(response)


def guarddog_binary(explicit):
    if explicit:
        return explicit
    from_environment = os.environ.get("GUARDDOG_BIN")
    if from_environment:
        return from_environment
    local = Path.home() / ".local/bin/guarddog"
    if local.exists():
        return str(local)
    return shutil.which("guarddog") or "guarddog"



def scan_package(
    binary,
    archive,
    name,
    version,
    findings_path,
    *,
    scratch_dir=None,
    guarddog=None,
    ledger_db=None,
    timeout=900,
):
    ledger_db = ledger_db or Path(
        os.environ.get(
            "SUPPLY_LEDGER_PATH",
            Path.home() / ".local/share/supply-core/ledger.sqlite",
        )
    )
    command = [
        binary, "scan-package", "npm", str(archive),
        f"--name={name}", f"--version={version}",
        f"--findings-out={findings_path}", f"--ledger-db={ledger_db}", "--json",
    ]
    if scratch_dir is not None:
        command.append(f"--scratch-dir={scratch_dir}")
    environment = dict(os.environ)
    if guarddog:
        environment["GUARDDOG_BIN"] = guarddog
    home_bin = str(Path.home() / ".local/bin")
    environment["PATH"] = home_bin + os.pathsep + environment.get("PATH", "")
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, env=environment,
    )
    if completed.returncode not in (0, 2, 3):
        detail = (completed.stderr or completed.stdout).strip()[:2000]
        raise RuntimeError(f"scan-package exited {completed.returncode}: {detail}")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("scan-package did not return a JSON report") from error
    if not isinstance(report, dict):
        raise RuntimeError("scan-package did not return an artifact report")
    expected_exit = {"pass": 0, "review": 0, "block": 2, "incomplete": 3}.get(
        report.get("decision")
    )
    if expected_exit is None or completed.returncode != expected_exit:
        raise RuntimeError("scan-package exit code does not match its report")
    if report.get("coverage") not in {"complete", "partial", "unknown"}:
        raise RuntimeError("scan-package report has invalid coverage")
    return report


def summarize(report):
    engines = report.get("engines") or []
    findings = [
        (engine.get("source", "unknown"), finding)
        for engine in engines
        for finding in engine.get("findings", [])
    ]
    policy_scores = [
        Decimal(str(finding["policy_score"]))
        for _, finding in findings
        if finding.get("policy_score") is not None
    ]
    score = (
        max(policy_scores)
        if policy_scores and all(finding.get("policy_score") is not None for _, finding in findings)
        else None if findings else Decimal(0)
    )
    if score is not None:
        score = int(score) if score == score.to_integral_value() else float(score)
    return {
        "decision": report.get("decision"),
        "coverage": report.get("coverage"),
        "findings": len(findings),
        "score": score,
        "rules": sorted({finding.get("rule", "unknown") for _, finding in findings}),
        "sources": sorted({source for source, _ in findings}),
        "reasons": sorted({
            f"{engine.get('source', 'unknown')}:{engine['reason']}"
            for engine in engines
            if isinstance(engine.get("reason"), str) and engine["reason"]
        }),
    }




INCOMPLETE_RULE = "scan-incomplete"


def incomplete_record(name, version, reason, artifact_sha256=None, policy_sha256=None):
    """Record incomplete scan evidence with its known artifact and policy identity."""
    return {
        "ecosystem": "Npm",
        "package": name,
        "version": version,
        "source": "quarantine-scan",
        "scan_incomplete": True,
        "artifact_sha256": artifact_sha256,
        "policy_sha256": policy_sha256,
        "rules": [INCOMPLETE_RULE],
        "summary": f"quarantine content scan incomplete ({reason[:200]})",
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


def append_record(path, record):
    """Append one JSONL record under the same lock the Rust reader uses."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with path.open("a") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def clear_incomplete(path, name, version, artifact_sha256, policy_sha256):
    """Clear only incomplete holds for the exact artifact and policy revision."""
    if artifact_sha256 is None or policy_sha256 is None:
        return 0
    with path.with_suffix(".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if not path.exists():
                return 0
            kept, removed = [], 0
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    kept.append(stripped)
                    continue
                rules = record.get("rules") if isinstance(record, dict) else None
                is_incomplete = isinstance(rules, list) and INCOMPLETE_RULE in rules
                if (
                    is_incomplete
                    and record.get("package") == name
                    and record.get("version") == version
                    and record.get("artifact_sha256") == artifact_sha256
                    and record.get("policy_sha256") == policy_sha256
                ):
                    removed += 1
                else:
                    kept.append(stripped)
            if removed:
                temporary = path.with_suffix(path.suffix + ".tmp")
                temporary.write_text("\n".join(kept) + "\n" if kept else "")
                os.replace(temporary, path)
            return removed
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def prune_cache(cache, max_age_days=30, now=None):
    """Drop cached tarballs older than max_age_days; failures are ignored."""
    cutoff = (time.time() if now is None else now) - max_age_days * 86400
    removed = 0
    for entry in cache.glob("*.tgz"):
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def write_summary(report, day_dir):
    summary_path = day_dir / "content-scan.json"
    summary_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return summary_path


def ensure_archive(archive, tarball, integrity):
    """Return verified bytes for archive, refetching a corrupted cache entry.

    A cache entry that no longer matches dist.integrity is deleted before the
    refetch so a truncated download cannot wedge the retry loop.
    """
    if archive.exists():
        data = archive.read_bytes()
        try:
            verify_integrity(data, integrity)
            return data
        except ValueError:
            archive.unlink()
    data = fetch(tarball)
    verify_integrity(data, integrity)
    archive.write_bytes(data)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("day_dir", type=Path, help="capture directory (contains *.npm.json)")
    parser.add_argument("--bin", default=None, help="supply-core binary (default: target/release)")
    parser.add_argument("--limit", type=int, default=0,
                        help="maximum packages to scan (0 = all candidates)")
    parser.add_argument("--cache", type=Path, default=None, help="tarball cache directory")
    parser.add_argument("--findings", type=Path, default=None, help="shared findings JSONL")
    parser.add_argument("--guarddog-bin", default=None, help="GuardDog executable")
    parser.add_argument(
        "--scratch-dir",
        type=Path,
        default=Path(os.environ["SUPPLY_SCRATCH_DIR"])
        if os.environ.get("SUPPLY_SCRATCH_DIR")
        else None,
        help="dedicated scan scratch directory (default: SUPPLY_SCRATCH_DIR)",
    )
    parser.add_argument(
        "--ledger-db",
        type=Path,
        default=Path(os.environ.get("SUPPLY_LEDGER_PATH", Path.home() / ".local/share/supply-core/ledger.sqlite")),
        help="durable local ledger outbox",
    )
    args = parser.parse_args()

    if not args.day_dir.is_dir():
        print(f"scan-quarantine: not a directory: {args.day_dir}", file=sys.stderr)
        return 2
    binary = args.bin or str(Path(__file__).resolve().parent.parent / "target/release/supply-core")
    if not Path(binary).exists():
        print(f"scan-quarantine: binary not found: {binary}", file=sys.stderr)
        return 2
    cache = args.cache or Path(__file__).resolve().parent / "data/tarball-cache"
    findings_path = args.findings or (args.day_dir / "content-findings.jsonl")
    guarddog = guarddog_binary(args.guarddog_bin)

    documents = []
    for snapshot in sorted(args.day_dir.glob("*.npm.json")):
        try:
            documents.append(json.loads(snapshot.read_text()))
        except (OSError, json.JSONDecodeError) as error:
            print(f"scan-quarantine: unreadable snapshot {snapshot}: {error}", file=sys.stderr)
    packages = merge_candidates(
        quarantined_packages(documents),
        incomplete_candidates(findings_path),
    )
    packages = limited(packages, max(args.limit, 0))
    cache.mkdir(parents=True, exist_ok=True)
    pruned = prune_cache(cache)
    if pruned:
        print(f"scan-quarantine: pruned {pruned} cached tarballs older than 30 days")

    report = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "ledger_status": "ledger_pending",
        "day": args.day_dir.name,
        "guarddog": guarddog,
        "candidates": len(packages),
        "scanned": [],
        "blocked": [],
        "errors": [],
    }
    for package in packages:
        scan_report = None
        name, version = package["package"], package["version"]
        try:
            tarball, integrity = parse_version_document(
                fetch_json(version_url(name, version)), name, version,
            )
            archive = cache / safe_file_name(name, version)
            ensure_archive(archive, tarball, integrity)
            scan_report = scan_package(
                binary,
                archive,
                name,
                version,
                findings_path,
                scratch_dir=args.scratch_dir,
                guarddog=guarddog,
                ledger_db=args.ledger_db,
            )
            summary = summarize(scan_report)
            report["scanned"].append({"package": name, "version": version, **summary})
            if summary["decision"] == "block":
                report["blocked"].append({"package": name, "version": version})
            if summary["coverage"] != "complete" or summary["decision"] == "incomplete":
                detail = scan_report.get("reason") or "required scanner coverage incomplete"
                report["errors"].append(
                    {"package": name, "version": version, "error": detail}
                )
                append_record(
                    findings_path,
                    incomplete_record(
                        name,
                        version,
                        detail,
                        scan_report.get("artifact_sha256"),
                        scan_report.get("policy_sha256"),
                    ),
                )
            else:
                cleared = clear_incomplete(
                    findings_path,
                    name,
                    version,
                    scan_report.get("artifact_sha256"),
                    scan_report.get("policy_sha256"),
                )
                if cleared:
                    print(f"cleared {cleared} stale scan-incomplete record(s) for {name}@{version}")
            print(
                f"{summary['decision'].upper()} {name}@{version} "
                f"findings={summary['findings']} coverage={summary['coverage']}"
            )
        except Exception as error:  # noqa: BLE001 - every failure is evidence
            detail = str(error)
            report["errors"].append({"package": name, "version": version, "error": detail})
            scan_identity = scan_report if isinstance(scan_report, dict) else {}
            try:
                append_record(
                    findings_path,
                    incomplete_record(
                        name,
                        version,
                        detail,
                        scan_identity.get("artifact_sha256"),
                        scan_identity.get("policy_sha256"),
                    ),
                )
            except OSError as record_error:
                report["errors"].append(
                    {
                        "package": name,
                        "version": version,
                        "error": f"could not persist scan-incomplete: {record_error}",
                    }
                )
            print(f"FAIL {name}@{version}: {error}", file=sys.stderr)

    summary_path = write_summary(report, args.day_dir)
    print(f"content scan: {len(report['scanned'])} scanned, {len(report['errors'])} errors -> {summary_path}")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
