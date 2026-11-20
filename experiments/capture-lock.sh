capture_lock() {
  local lock_path="$1"
  mkdir -p "$(dirname "$lock_path")" || return 1
  if [ "${SUPPLY_DAILY_CAPTURE_LOCK_FD:-}" != 9 ]; then
    exec 9>>"$lock_path" || return 1
  fi
  if ! python3 - "$lock_path" <<'PY'
import fcntl, os, sys
try:
    expected = os.stat(sys.argv[1])
    actual = os.fstat(9)
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
        sys.exit("capture lock descriptor does not match lock file")
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit("capture already running")
PY
  then
    return 1
  fi
  export SUPPLY_DAILY_CAPTURE_LOCK_FD=9
}
