#!/usr/bin/env bash
# capture-snapshot.sh — Capture a full eBPF Viz snapshot on a production machine.
#
# Requirements: bash, bpftool (any version with -j / --json support), sudo (optional)
# No jq, python, node, or any other runtime required.
#
# Usage:
#   sudo ./capture-snapshot.sh                    # write to current directory
#   sudo ./capture-snapshot.sh -o /tmp/snap.json  # custom output path
#   sudo ./capture-snapshot.sh --dump-maps        # also capture map entries (separate file)
#   ./capture-snapshot.sh --no-sudo               # run without sudo (may miss some progs)
#   ./capture-snapshot.sh --help
#
# With --dump-maps, a second file is produced:
#   ebpf-mapdumps-<hostname>-<YYYYMMDD-HHMMSS>.json
# Load both files together in the UI to enable map entry inspection in snapshot mode.
# Cap: 200 entries per map. Unsupported types (ringbuf, perf_event_array, etc.) are skipped.
#
# Output: ebpf-snapshot-<hostname>-<YYYYMMDD-HHMMSS>.json
#
# The JSON format is identical to the EbpfSnapshot produced by the eBPF Viz server,
# so you can upload it directly in the UI (Load Snapshot button).
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
USE_SUDO=1
OUTPUT_FILE=""
DUMP_MAPS=0
DUMP_OUTPUT_FILE=""
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
    --dump-maps)
      DUMP_MAPS=1
      shift
      ;;
    --dump-output)
      DUMP_OUTPUT_FILE="$2"
      shift 2
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
SAFE_HOST=$(echo "$HOSTNAME_VAL" | tr -cs 'a-zA-Z0-9_-' '_' | sed 's/_*$//')
TIMESTAMP_SLUG=$(date +"%Y%m%d-%H%M%S")
if [[ -z "$OUTPUT_FILE" ]]; then
  OUTPUT_FILE="ebpf-snapshot-${SAFE_HOST}-${TIMESTAMP_SLUG}.json"
fi
if [[ -z "$DUMP_OUTPUT_FILE" ]]; then
  DUMP_OUTPUT_FILE="ebpf-mapdumps-${SAFE_HOST}-${TIMESTAMP_SLUG}.json"
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

# ── Optionally capture map entries ───────────────────────────────────────────
if [[ $DUMP_MAPS -eq 1 ]]; then
  log "Capturing map entries (--dump-maps, cap 200 entries/map)..."

  # Map types that bpftool cannot dump
  UNSUPPORTED_TYPES="perf_event_array|ringbuf|user_ringbuf|cgroup_array|prog_array"
  UNSUPPORTED_TYPES="$UNSUPPORTED_TYPES|devmap|devmap_hash|cpumap|xskmap|sockmap|sockhash"
  UNSUPPORTED_TYPES="$UNSUPPORTED_TYPES|reuseport_sockarray|hash_of_maps|array_of_maps"
  UNSUPPORTED_TYPES="$UNSUPPORTED_TYPES|sk_storage|task_storage|struct_ops|stack_trace"

  # Extract map IDs and types from the MAPS JSON using grep/sed (no jq required)
  # Format: "id": N  followed later by "type": "typename"
  # We process the JSON line by line to pair each id with its type
  MAP_DUMPS_JSON="{"
  FIRST_ENTRY=1
  DUMP_COUNT=0
  SKIP_COUNT=0

  # Parse id+type pairs using awk — handles the bpftool map list JSON format
  # Each map object looks like: { "id": 64, "type": "hash", ... }
  MAP_ID_TYPES=$(echo "$MAPS" | awk '
    /"id"[[:space:]]*:/ { match($0, /"id"[[:space:]]*:[[:space:]]*([0-9]+)/, arr); id=arr[1] }
    /"type"[[:space:]]*:/ && id != "" {
      match($0, /"type"[[:space:]]*:[[:space:]]*"([^"]+)"/, arr)
      if (arr[1] != "") { print id ":" arr[1]; id="" }
    }
  ')

  while IFS=: read -r MAP_ID MAP_TYPE; do
    [[ -z "$MAP_ID" || -z "$MAP_TYPE" ]] && continue

    # Skip unsupported types
    if echo "$MAP_TYPE" | grep -qE "^($UNSUPPORTED_TYPES)$"; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
      vlog "Skipping map $MAP_ID ($MAP_TYPE) — unsupported type"
      continue
    fi

    vlog "Dumping map $MAP_ID ($MAP_TYPE)..."
    # Dump up to 200 entries; bpftool returns all entries so we truncate with head
    # We use a temp file to avoid subshell issues with large outputs
    DUMP_OUT=$( ${SUDO_PREFIX}${BPFTOOL} -j map dump id "$MAP_ID" 2>/dev/null \
                | grep -v '^libbpf:' || true )

    # Skip if empty or error
    if [[ -z "$DUMP_OUT" || "$DUMP_OUT" == "null" || "$DUMP_OUT" == "{}" ]]; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
      continue
    fi

    # Truncate to 200 entries: count opening braces at start of lines
    # bpftool outputs one JSON object per line in the array
    # We take the first 200 objects by counting lines that start with '  {'
    TRUNCATED_DUMP=$(echo "$DUMP_OUT" | awk '
      BEGIN { count=0; in_obj=0; buf="["; first=1 }
      /^[[:space:]]*\{/ && !in_obj {
        if (count >= 200) { next }
        count++; in_obj=1
        if (!first) buf = buf ","
        first=0
        buf = buf $0
        next
      }
      in_obj {
        buf = buf $0
        if (/^[[:space:]]*\}/) { in_obj=0 }
        next
      }
      END { print buf "]" }
    ')

    # Validate it looks like a JSON array
    if [[ "$TRUNCATED_DUMP" != \[* ]]; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
      continue
    fi

    if [[ $FIRST_ENTRY -eq 0 ]]; then
      MAP_DUMPS_JSON="$MAP_DUMPS_JSON,"
    fi
    MAP_DUMPS_JSON="$MAP_DUMPS_JSON\"$MAP_ID\": $TRUNCATED_DUMP"
    FIRST_ENTRY=0
    DUMP_COUNT=$((DUMP_COUNT + 1))
  done <<< "$MAP_ID_TYPES"

  MAP_DUMPS_JSON="$MAP_DUMPS_JSON}"

  log "Writing map dumps to: $DUMP_OUTPUT_FILE ($DUMP_COUNT maps dumped, $SKIP_COUNT skipped)"

  cat > "$DUMP_OUTPUT_FILE" << DUMPJSONEOF
{
  "_ebpfVizMapDumps": true,
  "_version": 1,
  "capturedAt": "$CAPTURE_DATE",
  "hostname": "$(json_escape_string "$HOSTNAME_VAL")",
  "snapshotFile": "$(json_escape_string "$OUTPUT_FILE")",
  "mapDumps": $MAP_DUMPS_JSON
}
DUMPJSONEOF

fi

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
if [[ $DUMP_MAPS -eq 1 ]]; then
  DUMP_SIZE=$(du -sh "$DUMP_OUTPUT_FILE" 2>/dev/null | cut -f1 || echo "?")
  echo "Map dumps: $DUMP_OUTPUT_FILE ($DUMP_SIZE, $DUMP_COUNT maps with entries)"
fi
echo ""
echo "To copy to your Mac:"
echo "  scp $(whoami)@${HOSTNAME_VAL}:$(realpath "$OUTPUT_FILE" 2>/dev/null || echo "$OUTPUT_FILE") ~/Downloads/"
if [[ $DUMP_MAPS -eq 1 ]]; then
  echo "  scp $(whoami)@${HOSTNAME_VAL}:$(realpath "$DUMP_OUTPUT_FILE" 2>/dev/null || echo "$DUMP_OUTPUT_FILE") ~/Downloads/"
fi
echo ""
if [[ $DUMP_MAPS -eq 1 ]]; then
  echo "Then open eBPF Viz, click 'Load Snapshot' to load the snapshot file,"
  echo "then click 'Load Map Dumps' to load the map dumps file for entry inspection."
else
  echo "Then open eBPF Viz and click 'Load Snapshot' to analyse offline."
  echo "Tip: re-run with --dump-maps to also capture map entries."
fi
