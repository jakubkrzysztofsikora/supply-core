#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

UPSTREAM_COMMIT = "4063457b40211c25b41d56465d41783f2d42c5c1"
MAX_FILES = 10_000
MAX_BYTES = 64 * 1024 * 1024


def open_regular(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"not a regular file: {path}")
    return os.fdopen(descriptor, "rb")


def sha256_file(path):
    digest = hashlib.sha256()
    with open_regular(path) as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_files(directory, files):
    for entry in os.scandir(directory):
        path = Path(entry.path)
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            collect_files(path, files)
        elif stat.S_ISREG(mode):
            files.append(path)
            if len(files) > MAX_FILES:
                raise ValueError("rule bundle has too many files")
        else:
            raise ValueError("rule bundle contains a non-regular file")


def sha256_directory(root):
    mode = root.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise ValueError("rule bundle is not a real directory")
    files = []
    collect_files(root, files)
    files.sort(key=lambda path: path.relative_to(root).as_posix().encode("utf-8"))
    bundle = hashlib.sha256()
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        name = relative.encode("utf-8")
        content = hashlib.sha256()
        size = 0
        with open_regular(path) as source:
            for block in iter(lambda: source.read(64 * 1024), b""):
                size += len(block)
                total_bytes += len(block)
                if total_bytes > MAX_BYTES:
                    raise ValueError("rule bundle exceeds size limit")
                content.update(block)
        bundle.update(len(name).to_bytes(8, "big"))
        bundle.update(name)
        bundle.update(size.to_bytes(8, "big"))
        bundle.update(content.digest())
    return bundle.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-root", required=True, type=Path)
    args = parser.parse_args()
    root = args.install_root.absolute()
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("install root is not a real directory")
        binary = root / "ossgadget"
        rules = root / "Resources" / "BackdoorRules"
        manifest = {
            "format_version": 1,
            "upstream_commit": UPSTREAM_COMMIT,
            "binary_sha256": sha256_file(binary),
            "rule_bundle_sha256": sha256_directory(rules),
        }
        output = root / "supply-ossgadget-manifest.json"
        with output.open("x", encoding="utf-8") as destination:
            json.dump(manifest, destination, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
