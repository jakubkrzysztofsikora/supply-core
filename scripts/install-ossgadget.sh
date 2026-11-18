#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <new-install-directory>\n' "$0" >&2
    exit 2
fi

[ "$(uname -s)" = Linux ] || { printf 'OSSGadget sandbox integration requires Linux.\n' >&2; exit 2; }
[ "$(uname -m)" = x86_64 ] || { printf 'OSSGadget installer supports linux-x64 only.\n' >&2; exit 2; }
command -v git >/dev/null 2>&1 || { printf 'git is required.\n' >&2; exit 2; }
command -v dotnet >/dev/null 2>&1 || { printf '.NET 8 SDK is required.\n' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf 'python3 is required.\n' >&2; exit 2; }

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
install_root=$1
case "$install_root" in
    /*) ;;
    *) install_root="$PWD/$install_root" ;;
esac
[ ! -e "$install_root" ] && [ ! -L "$install_root" ] || { printf 'install directory already exists.\n' >&2; exit 2; }
parent=$(dirname -- "$install_root")
mkdir -p -- "$parent"

stage=$(mktemp -d "$parent/.supply-ossgadget.XXXXXX")
build=$(mktemp -d "${TMPDIR:-/tmp}/supply-ossgadget-build.XXXXXX")
cleanup() {
    rm -rf -- "$stage" "$build"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

commit=4063457b40211c25b41d56465d41783f2d42c5c1
source_repo="$build/repository"
mkdir -p -- "$source_repo"
git -C "$source_repo" init -q
git -C "$source_repo" remote add origin https://github.com/microsoft/OSSGadget.git
git -C "$source_repo" fetch -q --depth=1 origin "$commit"
[ "$(git -C "$source_repo" rev-parse FETCH_HEAD)" = "$commit" ] || { printf 'fetched OSSGadget revision does not match pin.\n' >&2; exit 2; }
git -C "$source_repo" archive --format=tar "$commit" | tar -xf - -C "$source_repo"
git -C "$source_repo" apply --check "$repo_root/patches/ossgadget-coverage.patch"
git -C "$source_repo" apply "$repo_root/patches/ossgadget-coverage.patch"

mkdir -p -- "$build/home" "$build/nuget"
cat > "$build/NuGet.Config" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <packageSources>
        <clear />
        <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    </packageSources>
</configuration>
EOF
csproj="$source_repo/src/oss-gadget-cli/oss-gadget-cli.csproj"
env -i PATH="$PATH" HOME="$build/home" NUGET_PACKAGES="$build/nuget" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NBGV_GitEngine=Disabled dotnet restore \
    "$csproj" \
    --runtime linux-x64 \
    --configfile "$build/NuGet.Config"
env -i PATH="$PATH" HOME="$build/home" NUGET_PACKAGES="$build/nuget" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NBGV_GitEngine=Disabled dotnet publish \
    "$csproj" \
    --configuration Release \
    --runtime linux-x64 \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true \
    --no-restore \
    --output "$build/publish"
mkdir -p -- "$build/publish/Resources"
cp -R -- "$source_repo/src/Shared.CLI/Resources/BackdoorRules" "$build/publish/Resources/"

[ -x "$build/publish/ossgadget" ] || { printf 'published OSSGadget executable is missing.\n' >&2; exit 2; }
[ -d "$build/publish/Resources/BackdoorRules" ] || { printf 'published BackdoorRules are missing.\n' >&2; exit 2; }
mkdir -p -- "$stage/install/Resources"
cp -- "$build/publish/ossgadget" "$stage/install/ossgadget"
cp -- "$source_repo/LICENSE.txt" "$stage/install/LICENSE.txt"
cp -R -- "$build/publish/Resources/BackdoorRules" "$stage/install/Resources/BackdoorRules"
python3 "$repo_root/scripts/write-ossgadget-manifest.py" --install-root "$stage/install"
chmod -R a-w "$stage/install"
mv -T -n -- "$stage/install" "$install_root"
[ ! -e "$stage/install" ] || { printf 'install directory appeared during installation.\n' >&2; exit 2; }
printf 'OSSGADGET_BIN=%s/ossgadget\nOSSGADGET_MANIFEST=%s/supply-ossgadget-manifest.json\n' "$install_root" "$install_root"
