#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <new-install-directory>\n' "$0" >&2
    exit 2
fi

[ "$(uname -s)" = Linux ] || { printf 'GuardDog sandbox integration requires Linux.\n' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf 'python3 is required.\n' >&2; exit 2; }

version=3.2.0
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
install_root=$1
case "$install_root" in
    /*) ;;
    *) install_root="$PWD/$install_root" ;;
esac
[ ! -e "$install_root" ] && [ ! -L "$install_root" ] || { printf 'install directory already exists.\n' >&2; exit 2; }
mkdir -p -- "$(dirname -- "$install_root")"

# The venv is built at its final path because console scripts hard-code the interpreter path.
mkdir -- "$install_root"
installed=
trap '[ -n "$installed" ] || { chmod -R u+w "$install_root" 2>/dev/null; rm -rf -- "$install_root"; }' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 -m venv "$install_root/venv"
"$install_root/venv/bin/pip" install --quiet --no-cache-dir --disable-pip-version-check "guarddog==$version"
"$install_root/venv/bin/guarddog" --version >/dev/null
python3 "$script_dir/write-guarddog-manifest.py" --install-root "$install_root"
chmod -R a-w "$install_root"
installed=1
printf 'GUARDDOG_BIN=%s/venv/bin/guarddog\nGUARDDOG_MANIFEST=%s/supply-guarddog-manifest.json\n' "$install_root" "$install_root"
