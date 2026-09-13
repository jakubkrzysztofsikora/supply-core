#!/usr/bin/env python3
"""Content-scan the npm versions a daily capture holds in the quarantine window.

For every dependency whose decision carries an "inside quarantine window"
reason, the wrapper:

1. resolves the exact version document on registry.npmjs.org,
2. downloads the tarball and verifies it against `dist.integrity` (sha512),
   so the scanner only ever sees bytes the registry vouched for,
3. runs `supply scan-package npm <archive> --name --version --guarddog ...`,
4. appends the resulting content findings to a shared JSONL file.

The JSONL file is what `snapshot-npm --findings` (and the field-test policy)
enforce on later captures. Every candidate is scanned unless `--limit` asks
for a subset; downloads are cached by name@version; every failure is recorded
in content-scan.json and exits 1.
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


def guarddog_available(binary):
    return Path(binary).exists() or shutil.which(binary) is not None


def scan_package(binary, archive, name, version, findings_path, guarddog, timeout=600):
    command = [
        binary, "scan-package", "npm", str(archive),
        f"--name={name}", f"--version={version}",
        f"--findings-out={findings_path}",
    ]
    if guarddog:
        command.append("--guarddog")
    environment = dict(os.environ)
    if guarddog:
        environment["GUARDDOG_BIN"] = guarddog
    home_bin = str(Path.home() / ".local/bin")
    environment["PATH"] = home_bin + os.pathsep + environment.get("PATH", "")
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, env=environment,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:2000]
        raise RuntimeError(f"scan-package exited {completed.returncode}: {detail}")
    output = completed.stdout.strip()
    if not output.startswith("["):
        return []
    findings = json.loads(output)
    if not isinstance(findings, list):
        raise RuntimeError("scan-package did not return a finding list")
    return findings


def summarize(findings):
    return {
        "findings": len(findings),
        "score": max((finding.get("score", 0) for finding in findings), default=0),
        "rules": sorted({rule for finding in findings for rule in finding.get("rules", [])}),
        "sources": sorted({finding.get("source", "unknown") for finding in findings}),
    }


INCOMPLETE_RULE = "scan-incomplete"
INCOMPLETE_SCORE = 8


def incomplete_record(name, version, reason, guarddog):
    """A block-level record that keeps a version held until a scan completes.

    Fail closed: if a version escapes the quarantine window before any
    successful content scan, this record is what still blocks it. The engine
    tag keeps a static-only run from clearing a GuardDog-pending hold.
    """
    return {
        "ecosystem": "Npm",
        "package": name,
        "version": version,
        "source": "quarantine-scan",
        "score": INCOMPLETE_SCORE,
        "rules": [INCOMPLETE_RULE, "guarddog" if guarddog else "static"],
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


def clear_incomplete(path, name, version, includes_guarddog):
    """Remove stale scan-incomplete records for one package version.

    A static-only run only clears static-tagged records: a GuardDog-pending
    hold survives until a scan that actually includes GuardDog succeeds.
    """
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
                guarddog_pending = is_incomplete and "guarddog" in rules
                if (
                    is_incomplete
                    and record.get("package") == name
                    and record.get("version") == version
                    and (includes_guarddog or not guarddog_pending)
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
    parser.add_argument("--no-guarddog", action="store_true", help="static rules only")
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
        "day": args.day_dir.name,
        "guarddog": None if args.no_guarddog else guarddog,
        "candidates": len(packages),
        "scanned": [],
        "errors": [],
    }

    # Without GuardDog the static rules still run, but the configured scan set
    # is incomplete: hold every candidate until a full scan succeeds.
    if not args.no_guarddog and not guarddog_available(guarddog):
        print(f"scan-quarantine: guarddog not found at {guarddog}", file=sys.stderr)
        for package in packages:
            name, version = package["package"], package["version"]
            report["errors"].append(
                {"package": name, "version": version, "error": "guarddog unavailable"}
            )
            try:
                append_record(
                    findings_path,
                    incomplete_record(name, version, "guarddog unavailable", guarddog=True),
                )
            except OSError as error:
                report["errors"].append(
                    {"package": name, "version": version, "error": f"could not record: {error}"}
                )
        summary_path = write_summary(report, args.day_dir)
        print(f"content scan: 0 scanned, {len(report['errors'])} errors -> {summary_path}")
        return 2

    for package in packages:
        name, version = package["package"], package["version"]
        try:
            tarball, integrity = parse_version_document(
                fetch_json(version_url(name, version)), name, version,
            )
            archive = cache / safe_file_name(name, version)
            ensure_archive(archive, tarball, integrity)
            findings = scan_package(
                binary, archive, name, version, findings_path,
                guarddog=None if args.no_guarddog else guarddog,
            )
            cleared = clear_incomplete(
                findings_path, name, version, includes_guarddog=not args.no_guarddog
            )
            if cleared:
                print(f"cleared {cleared} stale scan-incomplete record(s) for {name}@{version}")
            report["scanned"].append({"package": name, "version": version, **summarize(findings)})
            print(f"OK   {name}@{version} findings={len(findings)}")
        except Exception as error:  # noqa: BLE001 - every failure is evidence
            detail = str(error)
            report["errors"].append({"package": name, "version": version, "error": detail})
            try:
                append_record(
                    findings_path,
                    incomplete_record(name, version, detail, guarddog=not args.no_guarddog),
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
