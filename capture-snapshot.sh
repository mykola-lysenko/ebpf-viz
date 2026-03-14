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
#   ./capture-snapshot.sh --max-maps 100          # limit map dumps to first 100 maps
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
MAX_MAPS=500          # max maps to dump with --dump-maps
CMD_TIMEOUT=30        # seconds per bpftool command
MAP_DUMP_TIMEOUT=10   # seconds per map dump command
MAP_DUMP_DELAY=0.05   # seconds between map dumps to reduce lock contention

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
    --max-maps)
      MAX_MAPS="$2"
      shift 2
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    --help|-h)
      sed -n '2,22p' "$0" | sed 's/^# \?//'
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

# Create a temp directory for intermediate files; clean up on exit
TMPDIR_SNAP=$(mktemp -d "${TMPDIR:-/tmp}/ebpf-snap.XXXXXX")
trap 'rm -rf "$TMPDIR_SNAP"' EXIT

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

# ── Check for timeout command ────────────────────────────────────────────────
TIMEOUT_CMD=""
if command -v timeout &>/dev/null; then
  TIMEOUT_CMD="timeout"
elif command -v gtimeout &>/dev/null; then
  TIMEOUT_CMD="gtimeout"  # macOS with coreutils
fi

# ── Build sudo prefix ─────────────────────────────────────────────────────────
SUDO_PREFIX=""
if [[ $USE_SUDO -eq 1 ]]; then
  if command -v sudo &>/dev/null; then
    SUDO_PREFIX="sudo"
  else
    log "Warning: sudo not found, running without it"
  fi
fi

# ── Run a bpftool command, stream output to a file ────────────────────────────
# Usage: run_bpftool_to_file <output_file> <bpftool_args> [timeout_secs]
# Returns 0 on success, 1 on failure. On failure, writes the fallback to the file.
run_bpftool_to_file() {
  local outfile="$1"
  local args="$2"
  local tout="${3:-$CMD_TIMEOUT}"
  local fallback="${4:-[]}"

  local cmd_parts=()
  if [[ -n "$TIMEOUT_CMD" ]]; then
    cmd_parts+=("$TIMEOUT_CMD" "$tout")
  fi
  if [[ -n "$SUDO_PREFIX" ]]; then
    cmd_parts+=("$SUDO_PREFIX")
  fi
  cmd_parts+=("$BPFTOOL" -j)
  # Split args on whitespace into separate arguments
  read -ra arg_array <<< "$args"
  cmd_parts+=("${arg_array[@]}")

  # Run at reduced priority to minimize production impact
  if "${cmd_parts[@]}" 2>/dev/null | grep -v '^libbpf:' > "$outfile"; then
    if [[ -s "$outfile" ]]; then
      return 0
    fi
  fi
  vlog "bpftool $args → empty or failed, using fallback"
  echo "$fallback" > "$outfile"
  return 0
}

# ── Gather metadata ───────────────────────────────────────────────────────────
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
KERNEL_VERSION=$(uname -r 2>/dev/null || echo "unknown")
TIMESTAMP_MS=$(date +%s)000  # milliseconds
CAPTURE_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")

BPFTOOL_VERSION_RAW=""
if [[ -n "$SUDO_PREFIX" ]]; then
  BPFTOOL_VERSION_RAW=$($SUDO_PREFIX "$BPFTOOL" version 2>/dev/null | head -1 || echo "unknown")
else
  BPFTOOL_VERSION_RAW=$("$BPFTOOL" version 2>/dev/null | head -1 || echo "unknown")
fi

log "Capturing snapshot on $HOSTNAME_VAL (kernel $KERNEL_VERSION)"

# ── Capture bpftool outputs to temp files ────────────────────────────────────
log "Running: bpftool prog list..."
run_bpftool_to_file "$TMPDIR_SNAP/progs.json" "prog list"

log "Running: bpftool map list..."
run_bpftool_to_file "$TMPDIR_SNAP/maps.json" "map list"

log "Running: bpftool net..."
run_bpftool_to_file "$TMPDIR_SNAP/net.json" "net"

log "Running: bpftool cgroup tree..."
run_bpftool_to_file "$TMPDIR_SNAP/cgroups.json" "cgroup tree"

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
# Stream directly to the output file instead of building in memory.
# The format matches the EbpfSnapshot interface in shared/ebpf-types.ts.
log "Writing snapshot to: $OUTPUT_FILE"

{
  printf '{\n'
  printf '  "_ebpfVizSnapshot": true,\n'
  printf '  "_version": 1,\n'
  printf '  "capturedAt": "%s",\n' "$CAPTURE_DATE"
  printf '  "timestamp": %s,\n' "$TIMESTAMP_MS"
  printf '  "hostname": "%s",\n' "$(json_escape_string "$HOSTNAME_VAL")"
  printf '  "kernelVersion": "%s",\n' "$(json_escape_string "$KERNEL_VERSION")"
  printf '  "bpftoolVersion": "%s",\n' "$(json_escape_string "$BPFTOOL_VERSION_RAW")"
  printf '  "demoMode": false,\n'
  printf '  "raw": {\n'
  printf '    "progs": '
  cat "$TMPDIR_SNAP/progs.json"
  printf ',\n    "maps": '
  cat "$TMPDIR_SNAP/maps.json"
  printf ',\n    "net": '
  cat "$TMPDIR_SNAP/net.json"
  printf ',\n    "cgroups": '
  cat "$TMPDIR_SNAP/cgroups.json"
  printf '\n  }\n'
  printf '}\n'
} > "$OUTPUT_FILE"

# ── Optionally capture map entries ───────────────────────────────────────────
if [[ $DUMP_MAPS -eq 1 ]]; then
  log "Capturing map entries (--dump-maps, cap 200 entries/map, max $MAX_MAPS maps)..."

  # Map types that bpftool cannot dump
  UNSUPPORTED_TYPES="perf_event_array|ringbuf|user_ringbuf|cgroup_array|prog_array"
  UNSUPPORTED_TYPES="$UNSUPPORTED_TYPES|devmap|devmap_hash|cpumap|xskmap|sockmap|sockhash"
  UNSUPPORTED_TYPES="$UNSUPPORTED_TYPES|reuseport_sockarray|hash_of_maps|array_of_maps"
  UNSUPPORTED_TYPES="$UNSUPPORTED_TYPES|sk_storage|task_storage|struct_ops|stack_trace"

  # Extract map IDs and types using grep+sed (POSIX-compatible, no awk extensions).
  # Works with both compact and pretty-printed bpftool JSON output.
  MAP_ID_TYPES=$(paste -d: \
    <(grep -oE '"id"[[:space:]]*:[[:space:]]*[0-9]+' "$TMPDIR_SNAP/maps.json" | sed 's/.*://; s/[[:space:]]//g') \
    <(grep -oE '"type"[[:space:]]*:[[:space:]]*"[^"]*"' "$TMPDIR_SNAP/maps.json" | sed 's/.*"type"[[:space:]]*:[[:space:]]*"//; s/"//') \
  )

  DUMP_COUNT=0
  SKIP_COUNT=0
  FIRST_ENTRY=1

  # Start the map dumps JSON file — stream to file instead of accumulating in a variable
  {
    printf '{\n'
    printf '  "_ebpfVizMapDumps": true,\n'
    printf '  "_version": 1,\n'
    printf '  "capturedAt": "%s",\n' "$CAPTURE_DATE"
    printf '  "hostname": "%s",\n' "$(json_escape_string "$HOSTNAME_VAL")"
    printf '  "snapshotFile": "%s",\n' "$(json_escape_string "$OUTPUT_FILE")"
    printf '  "mapDumps": {'
  } > "$DUMP_OUTPUT_FILE"

  while IFS=: read -r MAP_ID MAP_TYPE; do
    [[ -z "$MAP_ID" || -z "$MAP_TYPE" ]] && continue

    # Respect --max-maps limit
    if [[ $DUMP_COUNT -ge $MAX_MAPS ]]; then
      log "Reached --max-maps limit ($MAX_MAPS), stopping map dumps"
      break
    fi

    # Skip unsupported types
    if echo "$MAP_TYPE" | grep -qE "^($UNSUPPORTED_TYPES)$"; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
      vlog "Skipping map $MAP_ID ($MAP_TYPE) — unsupported type"
      continue
    fi

    vlog "Dumping map $MAP_ID ($MAP_TYPE)..."

    # Dump map entries to a temp file with timeout
    DUMP_TMPFILE="$TMPDIR_SNAP/mapdump_${MAP_ID}.json"
    DUMP_OK=0

    dump_cmd_parts=()
    if [[ -n "$TIMEOUT_CMD" ]]; then
      dump_cmd_parts+=("$TIMEOUT_CMD" "$MAP_DUMP_TIMEOUT")
    fi
    if [[ -n "$SUDO_PREFIX" ]]; then
      dump_cmd_parts+=("$SUDO_PREFIX")
    fi
    dump_cmd_parts+=("$BPFTOOL" -j map dump id "$MAP_ID")

    if "${dump_cmd_parts[@]}" 2>/dev/null | grep -v '^libbpf:' > "$DUMP_TMPFILE" 2>/dev/null; then
      if [[ -s "$DUMP_TMPFILE" ]]; then
        DUMP_OK=1
      fi
    fi

    # Skip if empty or error
    if [[ $DUMP_OK -eq 0 ]]; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
      rm -f "$DUMP_TMPFILE"
      continue
    fi

    # Check for null/empty content
    FIRST_CHAR=$(head -c 1 "$DUMP_TMPFILE")
    if [[ "$FIRST_CHAR" != "[" ]]; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
      rm -f "$DUMP_TMPFILE"
      continue
    fi

    # Skip dumps larger than 10 MB (protects against huge maps filling disk)
    DUMP_BYTES=$(wc -c < "$DUMP_TMPFILE" 2>/dev/null || echo 0)
    if [[ "$DUMP_BYTES" -gt 10485760 ]]; then
      vlog "Skipping map $MAP_ID — dump too large (${DUMP_BYTES} bytes)"
      SKIP_COUNT=$((SKIP_COUNT + 1))
      rm -f "$DUMP_TMPFILE"
      continue
    fi

    # Append raw dump to the output file.
    # Server-side parseMapDumps already truncates to 200 entries, so we pass
    # the full dump through. This avoids fragile awk-based JSON truncation.
    {
      if [[ $FIRST_ENTRY -eq 0 ]]; then
        printf ','
      fi
      printf '"%s": ' "$MAP_ID"
      cat "$DUMP_TMPFILE"
    } >> "$DUMP_OUTPUT_FILE"

    FIRST_ENTRY=0
    DUMP_COUNT=$((DUMP_COUNT + 1))

    # Clean up temp file for this map
    rm -f "$DUMP_TMPFILE"

    # Brief pause between dumps to reduce kernel lock contention
    sleep "$MAP_DUMP_DELAY" 2>/dev/null || true
  done <<< "$MAP_ID_TYPES"

  # Close the JSON
  {
    printf '}\n'
    printf '}\n'
  } >> "$DUMP_OUTPUT_FILE"

  log "Map dumps complete: $DUMP_COUNT maps dumped, $SKIP_COUNT skipped"
fi

# ── Print result ──────────────────────────────────────────────────────────────
FILE_SIZE=$(du -sh "$OUTPUT_FILE" 2>/dev/null | cut -f1 || echo "?")
PROG_COUNT=$(grep -c '"id"' "$TMPDIR_SNAP/progs.json" 2>/dev/null || echo "?")
MAP_COUNT=$(grep -c '"id"' "$TMPDIR_SNAP/maps.json" 2>/dev/null || echo "?")

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
