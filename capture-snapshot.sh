#!/usr/bin/env bash
# capture-snapshot.sh — Capture a full eBPF Viz snapshot on a production machine.
#
# Requirements: bash, bpftool (any version with -j / --json support), sudo (optional)
# No jq, python, node, or any other runtime required.
#
# Usage:
#   sudo ./capture-snapshot.sh                    # write to current directory
#   sudo ./capture-snapshot.sh -o /tmp/snap.json  # custom output path
#   ./capture-snapshot.sh --no-sudo               # run without sudo (may miss some progs)
#   ./capture-snapshot.sh --help
#
# Output: ebpf-snapshot-<hostname>-<YYYYMMDD-HHMMSS>.json
#
# The JSON format is identical to the EbpfSnapshot produced by the eBPF Viz server,
# so you can upload it directly in the UI (Load Snapshot button).
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
USE_SUDO=1
OUTPUT_FILE=""
VERBOSE=0

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --no-sudo)
      USE_SUDO=0
      shift
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    --help|-h)
      sed -n '2,20p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Run '$0 --help' for usage." >&2
      exit 1
      ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "[capture-snapshot] $*" >&2; }
vlog() { [[ $VERBOSE -eq 1 ]] && echo "[capture-snapshot] $*" >&2 || true; }

# Escape a raw string for embedding inside a JSON string value.
# Handles: backslash, double-quote, newline, carriage-return, tab.
# We do NOT use jq — just sed/tr.
json_escape_string() {
  # 1. escape backslashes first (must be first)
  # 2. escape double-quotes
  # 3. replace newlines with \n literal
  # 4. replace carriage returns with \r literal
  # 5. replace tabs with \t literal
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g' \
    | sed 's/"/\\"/g' \
    | tr '\n' '\001' | sed 's/\001/\\n/g' \
    | tr '\r' '\002' | sed 's/\002/\\r/g' \
    | tr '\t' '\003' | sed 's/\003/\\t/g'
}

# ── Locate bpftool ────────────────────────────────────────────────────────────
find_bpftool() {
  # 1. Explicit env override
  if [[ -n "${BPFTOOL_PATH:-}" && -x "$BPFTOOL_PATH" ]]; then
    echo "$BPFTOOL_PATH"; return
  fi
  # 2. PATH lookup
  if command -v bpftool &>/dev/null; then
    command -v bpftool; return
  fi
  # 3. Common distro locations
  for p in /usr/sbin/bpftool /usr/bin/bpftool /usr/local/sbin/bpftool \
            /usr/local/bin/bpftool /sbin/bpftool; do
    if [[ -x "$p" ]]; then echo "$p"; return; fi
  done
  echo ""
}

BPFTOOL=$(find_bpftool)
if [[ -z "$BPFTOOL" ]]; then
  echo "ERROR: bpftool not found." >&2
  echo "Install it (e.g. 'apt install linux-tools-common') or set BPFTOOL_PATH." >&2
  exit 1
fi
log "Using bpftool: $BPFTOOL"

# ── Build sudo prefix ─────────────────────────────────────────────────────────
SUDO_PREFIX=""
if [[ $USE_SUDO -eq 1 ]]; then
  if command -v sudo &>/dev/null; then
    SUDO_PREFIX="sudo "
  else
    log "Warning: sudo not found, running without it"
  fi
fi

# ── Run a bpftool command, return raw JSON (empty array on failure) ────────────
run_bpftool() {
  local args="$1"
  local fallback="${2:-[]}"
  local out
  # Strip libbpf: warning lines that pollute JSON output
  out=$( ${SUDO_PREFIX}${BPFTOOL} -j ${args} 2>/dev/null \
         | grep -v '^libbpf:' || true )
  if [[ -z "$out" ]]; then
    vlog "bpftool $args → empty, using fallback"
    echo "$fallback"
  else
    echo "$out"
  fi
}

# ── Gather metadata ───────────────────────────────────────────────────────────
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
KERNEL_VERSION=$(uname -r 2>/dev/null || echo "unknown")
TIMESTAMP_MS=$(date +%s)000  # milliseconds
CAPTURE_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")

BPFTOOL_VERSION_RAW=$(${SUDO_PREFIX}${BPFTOOL} version 2>/dev/null | head -1 || echo "unknown")
BPFTOOL_VERSION=$(json_escape_string "$BPFTOOL_VERSION_RAW")

log "Capturing snapshot on $HOSTNAME_VAL (kernel $KERNEL_VERSION)"

# ── Capture bpftool outputs ───────────────────────────────────────────────────
log "Running: bpftool prog list..."
PROGS=$(run_bpftool "prog list" "[]")

log "Running: bpftool map list..."
MAPS=$(run_bpftool "map list" "[]")

log "Running: bpftool net..."
NET=$(run_bpftool "net" "[]")

log "Running: bpftool cgroup tree..."
CGROUPS=$(run_bpftool "cgroup tree" "[]")

# ── Determine output file ─────────────────────────────────────────────────────
if [[ -z "$OUTPUT_FILE" ]]; then
  SAFE_HOST=$(echo "$HOSTNAME_VAL" | tr -cs 'a-zA-Z0-9_-' '_' | sed 's/_*$//')
  TIMESTAMP_SLUG=$(date +"%Y%m%d-%H%M%S")
  OUTPUT_FILE="ebpf-snapshot-${SAFE_HOST}-${TIMESTAMP_SLUG}.json"
fi

# ── Assemble the EbpfSnapshot JSON ────────────────────────────────────────────
# The format matches the EbpfSnapshot interface in shared/ebpf-types.ts.
# We embed the raw bpftool JSON outputs as the "raw" sub-objects so the
# eBPF Viz server-side parser can reconstruct the full typed snapshot.
# Fields that require server-side processing (programs, networkInterfaces,
# cgroupTree, kernelZones, stats) are populated by the server when the
# snapshot is loaded — we include the raw bpftool outputs for that purpose.
log "Writing snapshot to: $OUTPUT_FILE"

cat > "$OUTPUT_FILE" << JSONEOF
{
  "_ebpfVizSnapshot": true,
  "_version": 1,
  "capturedAt": "$CAPTURE_DATE",
  "timestamp": $TIMESTAMP_MS,
  "hostname": "$(json_escape_string "$HOSTNAME_VAL")",
  "kernelVersion": "$(json_escape_string "$KERNEL_VERSION")",
  "bpftoolVersion": "$(json_escape_string "$BPFTOOL_VERSION_RAW")",
  "demoMode": false,
  "raw": {
    "progs": $PROGS,
    "maps": $MAPS,
    "net": $NET,
    "cgroups": $CGROUPS
  }
}
JSONEOF

# ── Print result ──────────────────────────────────────────────────────────────
FILE_SIZE=$(du -sh "$OUTPUT_FILE" 2>/dev/null | cut -f1 || echo "?")
PROG_COUNT=$(echo "$PROGS" | grep -c '"id"' 2>/dev/null || echo "?")
MAP_COUNT=$(echo "$MAPS" | grep -c '"id"' 2>/dev/null || echo "?")

echo ""
echo "=== Snapshot captured ==="
echo "File:     $OUTPUT_FILE"
echo "Size:     $FILE_SIZE"
echo "Programs: ~$PROG_COUNT"
echo "Maps:     ~$MAP_COUNT"
echo "Kernel:   $KERNEL_VERSION"
echo ""
echo "To copy to your Mac:"
echo "  scp $(whoami)@${HOSTNAME_VAL}:$(realpath "$OUTPUT_FILE" 2>/dev/null || echo "$OUTPUT_FILE") ~/Downloads/"
echo ""
echo "Then open eBPF Viz and click 'Load Snapshot' to analyse offline."
