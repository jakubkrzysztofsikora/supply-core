#!/bin/sh
set -eu

mkdir -p /radar/data

interval="${SUPPLY_INTERVAL_SECONDS:-86400}"

cycle() {
  day="$(date +%Y-%m-%d)"
  if [ -f /radar-config/candidates.txt ]; then
    cp /radar-config/candidates.txt /radar/candidates.txt
  elif [ ! -f /radar/candidates.txt ]; then
    printf '# mount candidates.txt at /radar-config/candidates.txt\n' > /radar/candidates.txt
  fi
  if ! /radar/run.sh "$day"; then
    echo "ERROR: capture failed" >&2
    return 0
  fi
  if [ -z "${SUPPLY_STATUS_URL:-}" ]; then
    echo "WARN: SUPPLY_STATUS_URL is not set; capture only" >&2
    return 0
  fi
  snapshot="/radar/data/$day/quarantine-status.json"
  if ! python3 /radar/publish-status.py "/radar/data/$day" > "$snapshot"; then
    echo "ERROR: no quarantine snapshot produced" >&2
    return 0
  fi
  set -- --fail --silent --show-error --request PUT \
    --header "Content-Type: application/json" \
    --data-binary "@$snapshot" \
    "${SUPPLY_STATUS_URL%/}/api/v1/status/quarantine"
  if [ -n "${SUPPLY_STATUS_AUTH_TOKEN:-}" ]; then
    set -- --header "Authorization: Bearer $SUPPLY_STATUS_AUTH_TOKEN" "$@"
  fi
  if curl "$@"; then
    echo "published quarantine status"
  else
    echo "ERROR: failed to publish quarantine status" >&2
  fi
  return 0
}

while true; do
  cycle || echo "ERROR: radar cycle failed" >&2
  sleep "$interval"
done
