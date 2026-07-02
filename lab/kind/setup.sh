#!/usr/bin/env bash
# Phase 2 lab: kind cluster + Cilium CNI with kube-proxy replacement.
# No sudo needed — everything runs in docker. `--teardown` deletes the cluster.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"

if [[ "${1:-}" == "--teardown" ]]; then
  kind delete cluster --name ebpfviz
  exit 0
fi

echo "==> Creating kind cluster (2 nodes, no default CNI)..."
kind create cluster --config cluster.yaml

echo "==> Installing Cilium (socket-LB / kube-proxy replacement on)..."
cilium install --set kubeProxyReplacement=true

echo "==> Waiting for Cilium to become ready (can take a few minutes)..."
cilium status --wait

echo "==> Deploying demo workload (nginx + curl loop)..."
kubectl apply -f demo-app.yaml
kubectl rollout status deployment/web deployment/client --timeout=180s

echo
echo "Done. Cilium BPF programs are loaded in the shared WSL kernel and"
echo "visible to the dashboard. Teardown: $0 --teardown"
