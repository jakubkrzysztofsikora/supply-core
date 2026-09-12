#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== supply-core Official Server Kubernetes Deployment ==="

# Check if kubectl can reach a cluster
if ! kubectl cluster-info &>/dev/null; then
  echo "⚠️ Kubernetes cluster is not currently reachable."
  echo "  Manifests are ready in: $DIR"
  echo "  To deploy once the cluster is online, run:"
  echo "    kubectl apply -k $DIR"
  exit 0
fi

echo "Applying Kubernetes manifests via Kustomize..."
kubectl apply -k "$DIR"
echo "✅ Deployment applied successfully!"
echo "   Namespace:      supply-core"
