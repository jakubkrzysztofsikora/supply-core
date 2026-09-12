#!/usr/bin/env python3
"""Quarantine triage PoC: static heuristics over a fresh npm release tarball."""
import io
import json
import re
import sys
import tarfile
import urllib.request
from collections import Counter

SUSPICIOUS = [
    (r"child_process", "child_process module"),
    (r"execSync|execFileSync|spawnSync", "synchronous process execution"),
    (r"\bspawn\(|\bexec\(", "process execution"),
    (r"eval\(", "eval"),
    (r"new Function\(", "Function constructor"),
    (r"https?://[^\s'\"]+", "hardcoded URL"),
    (r"require\(['\"]dns['\"]\)|from ['\"]dns['\"]", "dns module"),
    (r"require\(['\"]net['\"]\)|from ['\"]net['\"]", "net module"),
    (r"atob\(|Buffer\.from\([^)]*base64", "base64 decoding"),
    (r"process\.env\.[A-Z_]{4,}", "env var access"),
    (r"\.ssh|id_rsa|\.aws|credentials", "credential path"),
]
LIFECYCLE = ["preinstall", "install", "postinstall", "preuninstall", "prepare"]


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def registry(name):
    return json.loads(fetch(f"https://registry.npmjs.org/{name}"))


def tarball_files(raw):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            payload = tar.extractfile(member).read()
            files[member.name.split("/", 1)[-1]] = payload
    return files


def longest_line(payload):
    best = 0
    for line in payload.split(b"\n"):
        best = max(best, len(line))
    return best


def analyze(name, version, files, baseline=None):
    package = json.loads(files.get("package.json", b"{}"))
    scripts = package.get("scripts", {})
    lifecycle = {key: scripts[key] for key in LIFECYCLE if key in scripts}

    evidence = []
    hits = Counter()
    for path, payload in files.items():
        if not re.search(r"\.(js|mjs|cjs|ts)$", path):
            continue
        if len(payload) > 2_000_000:
            continue
        text = payload.decode("utf-8", "ignore")
        for pattern, label in SUSPICIOUS:
            if re.search(pattern, text):
                hits[label] += 1
        if longest_line(payload) > 5_000:
            evidence.append(f"long single line ({longest_line(payload)}B) in {path}")

    binaries = [p for p in files if re.search(r"\.(node|so|dylib|exe|dll|wasm)$", p)]
    if binaries:
        evidence.append(f"native/binary artifacts: {binaries[:5]}")

    if lifecycle:
        for key, value in lifecycle.items():
            evidence.append(f"lifecycle script {key}: {value[:160]}")

    added = removed = changed = 0
    if baseline is not None:
        added = len(set(files) - set(baseline))
        removed = len(set(baseline) - set(files))
        changed = sum(1 for p in set(files) & set(baseline) if files[p] != baseline[p])

    meta = registry(name)
    latest = meta["versions"][version]
    npm_user = latest.get("_npmUser", {}).get("name")
    maintainers = [m.get("name") for m in meta.get("maintainers", [])]
    repo = (latest.get("repository") or {}).get("url", "")
    home_page = latest.get("homepage", "")

    findings = {
        "package": f"{name}@{version}",
        "published": meta["time"].get(version),
        "npm_user": npm_user,
        "maintainer_count": len(maintainers),
        "repository": repo,
        "files": len(files),
        "unpacked_bytes": sum(len(p) for p in files.values()),
        "lifecycle_scripts": lifecycle,
        "suspicious_file_hits": dict(hits),
        "override_indicator": bool(evidence),
        "evidence": evidence[:12],
        "diff_vs_baseline": {"added": added, "removed": removed, "changed": changed},
    }
    score = 0
    score += 25 if lifecycle else 0
    score += 20 if binaries else 0
    score += min(30, sum(hits.values()) * 2)
    score += 15 if evidence else 0
    findings["suspicion_score"] = score
    findings["verdict"] = "review" if score >= 40 else "benign-looking"
    return findings


def main():
    name = sys.argv[1]
    version = sys.argv[2]
    baseline_version = sys.argv[3] if len(sys.argv) > 3 else None
    meta = registry(name)
    tarball = meta["versions"][version]["dist"]["tarball"]
    files = tarball_files(fetch(tarball))
    baseline = None
    if baseline_version:
        baseline = tarball_files(fetch(meta["versions"][baseline_version]["dist"]["tarball"]))
    print(json.dumps(analyze(name, version, files, baseline), indent=2))


if __name__ == "__main__":
    main()
