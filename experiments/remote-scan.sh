#!/usr/bin/env bash
# Run the quarantine content scan on Linux in a short-lived k3s pod, where the
# scanner sandbox, its memory limits and attested engines are available.
#
#   remote-scan.sh <day-dir> <findings.jsonl> <ledger.sqlite>
#
# SUPPLY_SCAN_IMAGE selects the scanner image (Dockerfile target `scanner`).
# SUPPLY_SCAN_NAMESPACE / SUPPLY_SCAN_NODE choose placement. The pod gets copies
# of the day's snapshots, the findings file and the ledger; results are copied
# back only after the scan ran, so this host stays the single writer.
#
# Exit codes: scan-quarantine's own (0 clean, 1 scan errors) after a run;
# 3 when the pod could not run the scan at all (nothing was copied back).
set -euo pipefail

[ "$#" -eq 3 ] || { echo "usage: $0 <day-dir> <findings.jsonl> <ledger.sqlite>" >&2; exit 2; }
day_dir=$1
findings=$2
ledger=$3
image=${SUPPLY_SCAN_IMAGE:?SUPPLY_SCAN_IMAGE is not set}
namespace=${SUPPLY_SCAN_NAMESPACE:-supply-core}
node=${SUPPLY_SCAN_NODE:-k3s-node-1}
pod="supply-core-scan-$(date +%s)"
kube=(kubectl --request-timeout=60s -n "$namespace")

infra_fail() {
  echo "remote-scan: $*" >&2
  exit 3
}
cleanup() {
  "${kube[@]}" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${kube[@]}" apply -f - >/dev/null <<EOF || infra_fail "cannot create pod"
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  labels: {app: supply-core-scan}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  activeDeadlineSeconds: 7200
  nodeSelector: {kubernetes.io/hostname: $node}
  tolerations: [{key: lustro.io/pool, operator: Equal, value: worker, effect: NoExecute}]
  securityContext: {runAsUser: 1000, runAsGroup: 1000, runAsNonRoot: true, fsGroup: 1000}
  containers:
  - name: scan
    image: $image
    imagePullPolicy: IfNotPresent
    command: ["sleep", "7200"]
    resources:
      requests: {cpu: 500m, memory: 1Gi}
      limits: {memory: 6Gi}
    volumeMounts:
    - {name: work, mountPath: /work}
    - {name: scratch, mountPath: /scratch}
  volumes:
  - {name: work, emptyDir: {}}
  - {name: scratch, emptyDir: {}}
EOF
"${kube[@]}" wait --for=condition=Ready "pod/$pod" --timeout=600s >/dev/null \
  || infra_fail "pod did not become ready"

"${kube[@]}" cp "$day_dir" "$pod:/work/day" >/dev/null || infra_fail "cannot copy capture"
if [ -f "$findings" ]; then
  "${kube[@]}" cp "$findings" "$pod:/work/content-findings.jsonl" >/dev/null \
    || infra_fail "cannot copy findings"
fi
if [ -f "$ledger" ]; then
  "${kube[@]}" cp "$ledger" "$pod:/work/ledger.sqlite" >/dev/null || infra_fail "cannot copy ledger"
fi
"${kube[@]}" exec "$pod" -- chmod 600 /work/ledger.sqlite 2>/dev/null || true

scan_rc=0
"${kube[@]}" exec "$pod" -- python3 /radar/scan-quarantine.py /work/day \
  --bin /usr/local/bin/supply-core \
  --cache /work/tarball-cache \
  --findings /work/content-findings.jsonl \
  --ledger-db /work/ledger.sqlite \
  --scratch-dir /scratch || scan_rc=$?
case "$scan_rc" in
  0|1) ;;
  *) infra_fail "scan did not run (exit $scan_rc)" ;;
esac

stage=$(mktemp -d "$(dirname -- "$findings")/.remote-scan.XXXXXX")
trap 'rm -rf -- "$stage"; cleanup' EXIT
"${kube[@]}" cp "$pod:/work/day/content-scan.json" "$stage/content-scan.json" >/dev/null \
  || infra_fail "cannot copy scan summary back"
"${kube[@]}" cp "$pod:/work/content-findings.jsonl" "$stage/content-findings.jsonl" >/dev/null \
  || infra_fail "cannot copy findings back"
"${kube[@]}" cp "$pod:/work/ledger.sqlite" "$stage/ledger.sqlite" >/dev/null \
  || infra_fail "cannot copy ledger back"
for copied in content-scan.json content-findings.jsonl ledger.sqlite; do
  [ -s "$stage/$copied" ] || infra_fail "copied $copied is empty"
done
python3 - "$stage/content-scan.json" <<'PY' || infra_fail "scan summary is not a completed scan report"
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(report, dict) or not isinstance(report.get("scanned"), list) \
        or not isinstance(report.get("errors"), list):
    sys.exit(1)
PY
chmod 600 "$stage/ledger.sqlite"
mv -f "$stage/content-scan.json" "$day_dir/content-scan.json"
mv -f "$stage/content-findings.jsonl" "$findings"
mv -f "$stage/ledger.sqlite" "$ledger"
exit "$scan_rc"
