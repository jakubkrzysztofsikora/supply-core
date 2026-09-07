#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== supply-core Official Server Kubernetes Deployment ==="

# Check if k3s / kubectl is reachable
if ! kubectl cluster-info &>/dev/null; then
  echo "⚠️ Kubernetes cluster is not currently reachable."
  echo "  (Homelab cluster may be offline or sleeping)."
  echo "  Manifests are ready in: $DIR"
  echo "  To deploy once the cluster is online, run:"
  echo "    kubectl apply -k $DIR"
  exit 0
fi

echo "Applying Kubernetes manifests via Kustomize..."
kubectl apply -k "$DIR"
echo "✅ Deployment applied successfully!"
echo "   Namespace:      supply-core"
echo "   Tailscale Node: supply-core"
echo "   Public Funnel:  https://supply-core.tail5d39b4.ts.net"
