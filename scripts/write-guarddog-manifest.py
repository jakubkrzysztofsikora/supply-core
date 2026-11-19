#!/usr/bin/env python3
import argparse
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "ossgadget_manifest", Path(__file__).with_name("write-ossgadget-manifest.py")
)
_hashing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hashing)

VERSION_PATTERN = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")


def single(matches, description):
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {description}, found {len(matches)}")
    return matches[0]


def installed_version(site_packages):
    dist_info = single(sorted(site_packages.glob("guarddog-*.dist-info")), "guarddog dist-info")
    for line in (dist_info / "METADATA").read_text(encoding="utf-8").splitlines():
        if line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
            if VERSION_PATTERN.match(version):
                return version
            break
    raise ValueError("guarddog METADATA has no valid Version")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--install-root", required=True, type=Path)
    args = parser.parse_args()
    root = args.install_root.absolute()
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("install root is not a real directory")
        executable = root / "venv" / "bin" / "guarddog"
        site_packages = single(
            sorted(root.glob("venv/lib/python3*/site-packages")), "site-packages directory"
        )
        package = site_packages / "guarddog"
        manifest = {
            "format_version": 1,
            "guarddog_version": installed_version(site_packages),
            "executable_sha256": _hashing.sha256_file(executable),
            "package_dir": package.relative_to(root).as_posix(),
            "package_sha256": _hashing.sha256_directory(package),
        }
        output = root / "supply-guarddog-manifest.json"
        with output.open("x", encoding="utf-8") as destination:
            json.dump(manifest, destination, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
