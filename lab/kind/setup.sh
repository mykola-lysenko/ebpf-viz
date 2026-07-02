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

# --netkit: use netkit devices instead of veth for pod networking.
# Requires a kernel with CONFIG_NETKIT=y (>= 6.7; stock WSL2 kernels have it
# disabled — see lab/README.md) and Cilium >= 1.16.
DATAPATH_ARGS=()
if [[ "${1:-}" == "--netkit" ]]; then
  DATAPATH_ARGS=(--set bpf.datapathMode=netkit)
  echo "==> netkit datapath mode enabled"
fi

echo "==> Creating kind cluster (2 nodes, no default CNI)..."
kind create cluster --config cluster.yaml

echo "==> Installing Cilium (socket-LB / kube-proxy replacement on)..."
cilium install --set kubeProxyReplacement=true "${DATAPATH_ARGS[@]}"

echo "==> Waiting for Cilium to become ready (can take a few minutes)..."
cilium status --wait

echo "==> Deploying demo workload (nginx + curl loop)..."
kubectl apply -f demo-app.yaml
kubectl rollout status deployment/web deployment/client --timeout=180s

echo
echo "Done. Cilium BPF programs are loaded in the shared WSL kernel and"
echo "visible to the dashboard. Teardown: $0 --teardown"
