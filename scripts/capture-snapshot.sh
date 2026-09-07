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
# The UI/server displays up to 1000 entries per map. Unsupported types
# (ringbuf, perf_event_array, etc.) are skipped.
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
MAP_DUMP_DISPLAY_LIMIT=1000  # entries displayed per map after upload
SUDO_CMD="${SUDO-sudo}"

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
COLLECTION_FILE="$TMPDIR_SNAP/collection-sources.json"
: > "$COLLECTION_FILE"

# Append one status record. Kept separate from data, so failed commands can use
# empty placeholders without claiming a successful empty inventory.
record_source() { # key label state error [attempt time]
  local key="$1" label="$2" state="$3" error="${4:-}" at="${5:-$(date +%s)000}" success=null
  [[ "$state" == ok ]] && success="$at"
  [[ "$state" != skipped ]] || at=null
  [[ ! -s "$COLLECTION_FILE" ]] || printf ',\n' >> "$COLLECTION_FILE"
  printf '"%s":{"label":"%s","state":"%s","attemptedAt":%s,"lastSuccessAt":%s,"error":"%s"}' \
    "$(json_escape_string "$key")" "$(json_escape_string "$label")" "$state" "$at" "$success" \
    "$(json_escape_string "$error")" >> "$COLLECTION_FILE"
}

capture_command() { # key label output command args...
  local key="$1" label="$2" outfile="$3" at code=0 state=error message
  shift 3
  at=$(date +%s)000
  "$@" > "$outfile.raw" 2> "$outfile.stderr" || code=$?
  sed '/^libbpf:/d' "$outfile.raw" > "$outfile"
  # Full JSON/schema validation happens at import without requiring a JSON
  # runtime on the target. Reject obvious non-array/error responses here.
  if [[ "$code" -eq 0 ]] && [[ "$(sed -n '/[^[:space:]]/{s/^[[:space:]]*//;p;q;}' "$outfile" | head -c 1)" == '[' ]]; then
    record_source "$key" "$label" ok "" "$at"
    return 0
  fi
  message=$(head -c 2048 "$outfile.stderr")
  [[ -n "$message" ]] || message="Command failed (exit $code), returned empty output, or did not return a JSON array"
  if [[ "$code" -eq 127 ]] || [[ "$message" =~ [Nn]ot\ supported|[Cc]ommand\ not\ found ]]; then state=unsupported; fi
  record_source "$key" "$label" "$state" "$message" "$at"
  printf '[]\n' > "$outfile"
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

# ── Check for timeout command ────────────────────────────────────────────────
TIMEOUT_CMD=""
if command -v timeout &>/dev/null; then
  TIMEOUT_CMD="timeout"
elif command -v gtimeout &>/dev/null; then
  TIMEOUT_CMD="gtimeout"  # macOS with coreutils
fi

# ── Build sudo prefix ─────────────────────────────────────────────────────────
SUDO_PREFIX=()
if [[ $USE_SUDO -eq 1 ]]; then
  read -r -a SUDO_PREFIX <<< "$SUDO_CMD"
  if [[ ${#SUDO_PREFIX[@]} -gt 0 ]] && command -v "${SUDO_PREFIX[0]}" &>/dev/null; then
    :
  else
    log "Warning: ${SUDO_PREFIX[0]:-sudo} not found, running without it"
    SUDO_PREFIX=()
  fi
fi

# ── Run a bpftool command, stream output to a file ────────────────────────────
# Usage: run_bpftool_to_file <output_file> <bpftool_args> [timeout_secs]
# Records success/failure separately; on failure writes an empty placeholder.
run_bpftool_to_file() {
  local outfile="$1"
  local args="$2"
  local tout="${3:-$CMD_TIMEOUT}"

  local cmd_parts=()
  if [[ -n "$TIMEOUT_CMD" ]]; then
    cmd_parts+=("$TIMEOUT_CMD" "$tout")
  fi
  if [[ ${#SUDO_PREFIX[@]} -gt 0 ]]; then
    cmd_parts+=("${SUDO_PREFIX[@]}")
  fi
  cmd_parts+=("$BPFTOOL" -j -f)
  # Split args on whitespace into separate arguments
  read -ra arg_array <<< "$args"
  cmd_parts+=("${arg_array[@]}")

  local key label
  key=$(basename "$outfile" .json)
  [[ "$key" == cgroups-effective ]] && key=cgroupsEffective
  label="bpftool $args"
  capture_command "$key" "$label" "$outfile" "${cmd_parts[@]}"

}

# Capture detailed TC filter dumps as grouped records. The parser accepts this
# optional raw.tcFilters field and merges it into the bpftool net snapshot.
collect_tc_filters_to_file() {
  local outfile="$1"
  printf '[' > "$outfile"

  if ! command -v tc &>/dev/null; then
    record_source tcFilters "Detailed TC ordering" unsupported "tc command is unavailable"
    printf ']\n' >> "$outfile"
    return 0
  fi

  local devices=()
  while IFS= read -r dev; do
    [[ -n "$dev" ]] && devices+=("$dev")
  done < <(
    grep -oE '"devname"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMPDIR_SNAP/net.json" \
      | sed 's/.*"devname"[[:space:]]*:[[:space:]]*"//; s/"$//' \
      | sort -u
  )

  local first=1
  for dev in "${devices[@]}"; do
    local safe_dev
    safe_dev=$(printf '%s' "$dev" | tr -cs 'A-Za-z0-9_.-' '_')
    for direction in ingress egress; do
      local dump_tmp="$TMPDIR_SNAP/tc_${safe_dev}_${direction}.json"
      local cmd_parts=()
      if [[ -n "$TIMEOUT_CMD" ]]; then
        cmd_parts+=("$TIMEOUT_CMD" "$CMD_TIMEOUT")
      fi
      if [[ ${#SUDO_PREFIX[@]} -gt 0 ]]; then
        cmd_parts+=("${SUDO_PREFIX[@]}")
      fi
      cmd_parts+=(tc -s -d -j filter show dev "$dev" "$direction")

      capture_command "tc:$dev:$direction" "$dev: TC $direction ordering" "$dump_tmp" "${cmd_parts[@]}"

      if [[ $first -eq 0 ]]; then
        printf ',\n' >> "$outfile"
      fi
      first=0
      printf '    {"devname":"%s","direction":"%s","filters":' \
        "$(json_escape_string "$dev")" "$direction" >> "$outfile"
      cat "$dump_tmp" >> "$outfile"
      printf '}' >> "$outfile"
    done
  done

  printf '\n  ]\n' >> "$outfile"
}

# Capture `bpftool net` inside every reachable non-root network namespace.
# bpftool net is netns-scoped: container/pod datapaths (Cilium netkit/tcx in
# k8s nodes, docker) are invisible from the host netns. Mirrors the server's
# live netns scan; emits the raw.netns array. Requires nsenter + root; on
# systems without either the array is left empty.
collect_netns_to_file() {
  local outfile="$1"
  printf '[' > "$outfile"

  if ! command -v nsenter &>/dev/null || [[ ! -r /proc/self/ns/net ]]; then
    record_source namespaceDiscovery "Namespace discovery" unsupported "nsenter or /proc network namespaces are unavailable"
    printf ']\n' >> "$outfile"
    return 0
  fi

  local host_ino
  host_ino=$(readlink /proc/self/ns/net 2>/dev/null | grep -oE '[0-9]+' || true)
  if [[ -z "$host_ino" ]]; then
    record_source namespaceDiscovery "Namespace discovery" error "Cannot read host network namespace inode"
    printf ']\n' >> "$outfile"
    return 0
  fi

  local first=1 discovered=0 scanned=0 omitted=0 inaccessible=0
  local namespace_limit=64 discovery_at
  discovery_at=$(date +%s)000
  declare -A seen_ino=()
  [[ -n "$host_ino" ]] && seen_ino["$host_ino"]=1

  emit_netns() { # <inode> <label> <nsPath>
    local ino="$1" label="$2" ns_path="$3"
    discovered=$((discovered + 1))
    if [[ "$scanned" -ge "$namespace_limit" ]]; then
      omitted=$((omitted + 1))
      return 0
    fi
    scanned=$((scanned + 1))
    local net_tmp="$TMPDIR_SNAP/netns_${ino}.json"
    local links_tmp="$TMPDIR_SNAP/netns_${ino}_links.json"
    local prefix_parts=()
    if [[ -n "$TIMEOUT_CMD" ]]; then
      prefix_parts+=("$TIMEOUT_CMD" "$CMD_TIMEOUT")
    fi
    if [[ ${#SUDO_PREFIX[@]} -gt 0 ]]; then
      prefix_parts+=("${SUDO_PREFIX[@]}")
    fi
    capture_command "netns:$ino:net" "$label: BPF attachments" "$net_tmp" \
      "${prefix_parts[@]}" nsenter "--net=$ns_path" -- "$BPFTOOL" -j net show
    capture_command "netns:$ino:links" "$label: device topology" "$links_tmp" \
      "${prefix_parts[@]}" nsenter "--net=$ns_path" -- ip -d -j link show
    # Drop namespaces with neither netdev attachments nor a device pair
    if ! grep -qE '"(prog_)?id"[[:space:]]*:[[:space:]]*[0-9]' "$net_tmp" \
       && ! grep -qE '"info_kind"[[:space:]]*:[[:space:]]*"(netkit|veth)"' "$links_tmp"; then
      return 0
    fi
    if [[ $first -eq 0 ]]; then
      printf ',\n' >> "$outfile"
    fi
    first=0
    printf '    {"id":"%s","label":"%s","net":' \
      "$(json_escape_string "$ino")" "$(json_escape_string "$label")" >> "$outfile"
    cat "$net_tmp" >> "$outfile"
    printf ',"links":' >> "$outfile"
    cat "$links_tmp" >> "$outfile"
    printf '}' >> "$outfile"
  }

  # Named namespaces (ip netns add)
  if [[ -d /var/run/netns && ! -r /var/run/netns ]]; then
    record_source namedNamespaceDiscovery "Named namespace discovery" error "Named namespace directory is unreadable"
  fi
  if [[ -d /var/run/netns ]]; then
    local name ino
    for name in $(ls /var/run/netns 2>/dev/null); do
      ino=$(stat -c '%i' "/var/run/netns/$name" 2>/dev/null || true)
      [[ -z "$ino" || -n "${seen_ino[$ino]:-}" ]] && continue
      seen_ino["$ino"]=1
      emit_netns "$ino" "$name" "/var/run/netns/$name"
    done
  fi

  # Process scan: one representative pid per distinct netns inode
  local pid_dir pid ino label
  for pid_dir in /proc/[0-9]*; do
    pid="${pid_dir#/proc/}"
    ino=$(readlink "$pid_dir/ns/net" 2>/dev/null | grep -oE '[0-9]+' || true)
    if [[ -z "$ino" ]]; then
      [[ ! -d "$pid_dir" ]] || inaccessible=$((inaccessible + 1))
      continue
    fi
    [[ -n "${seen_ino[$ino]:-}" ]] && continue
    seen_ino["$ino"]=1
    label=$(cat "$pid_dir/root/etc/hostname" 2>/dev/null | tr -d '[:space:]' || true)
    [[ -z "$label" ]] && label=$(cat "$pid_dir/comm" 2>/dev/null || echo "pid-$pid")
    emit_netns "$ino" "$label" "$pid_dir/ns/net"
  done

  printf '\n  ]\n' >> "$outfile"
  local state=ok detail="Local named/process namespaces scanned"
  if [[ "$omitted" -gt 0 || "$inaccessible" -gt 0 ]]; then
    state=partial
    detail="$omitted namespaces omitted by limit $namespace_limit; $inaccessible process namespace paths unreadable"
  fi
  record_source namespaceDiscovery "Namespace discovery" "$state" "$detail" "$discovery_at"
  record_source dockerDiscovery "Docker namespace discovery" skipped "Capture scans local namespaces only; separate Docker VMs are not scanned" "$discovery_at"
  printf '{"limit":%s,"discovered":%s,"scanned":%s,"skipped":0,"omitted":%s,"discoveryAt":%s}' \
    "$namespace_limit" "$discovered" "$scanned" "$omitted" "$discovery_at" > "$TMPDIR_SNAP/namespace-coverage.json"
}

# ── Gather metadata ───────────────────────────────────────────────────────────
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
KERNEL_VERSION=$(uname -r 2>/dev/null || echo "unknown")
TIMESTAMP_MS=$(date +%s)000  # milliseconds
CAPTURE_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")

BPFTOOL_VERSION_RAW=""
if [[ ${#SUDO_PREFIX[@]} -gt 0 ]]; then
  BPFTOOL_VERSION_RAW=$("${SUDO_PREFIX[@]}" "$BPFTOOL" version 2>/dev/null | head -1 || echo "unknown")
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

log "Running: bpftool link list..."
run_bpftool_to_file "$TMPDIR_SNAP/links.json" "link list"

log "Running: bpftool cgroup tree effective..."
run_bpftool_to_file "$TMPDIR_SNAP/cgroups-effective.json" "cgroup tree /sys/fs/cgroup effective"

log "Running: tc filter show for detailed TC chain ordering..."
collect_tc_filters_to_file "$TMPDIR_SNAP/tc-filters.json"

log "Running: bpftool net in other network namespaces..."
collect_netns_to_file "$TMPDIR_SNAP/netns.json"

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
  printf '  "collection": {"sources": {'
  cat "$COLLECTION_FILE"
  printf '}'
  if [[ -s "$TMPDIR_SNAP/namespace-coverage.json" ]]; then
    printf ',"namespaces":'
    cat "$TMPDIR_SNAP/namespace-coverage.json"
  fi
  printf '},\n'
  printf '  "raw": {\n'
  printf '    "progs": '
  cat "$TMPDIR_SNAP/progs.json"
  printf ',\n    "maps": '
  cat "$TMPDIR_SNAP/maps.json"
  printf ',\n    "net": '
  cat "$TMPDIR_SNAP/net.json"
  printf ',\n    "tcFilters": '
  cat "$TMPDIR_SNAP/tc-filters.json"
  printf ',\n    "cgroups": '
  cat "$TMPDIR_SNAP/cgroups.json"
  printf ',\n    "links": '
  cat "$TMPDIR_SNAP/links.json"
  printf ',\n    "netns": '
  cat "$TMPDIR_SNAP/netns.json"
  printf ',\n    "cgroupsEffective": '
  cat "$TMPDIR_SNAP/cgroups-effective.json"
  printf '\n  }\n'
  printf '}\n'
} > "$OUTPUT_FILE"

# ── Optionally capture map entries ───────────────────────────────────────────
if [[ $DUMP_MAPS -eq 1 ]]; then
  log "Capturing map entries (--dump-maps, max $MAX_MAPS maps; UI displays up to $MAP_DUMP_DISPLAY_LIMIT entries/map)..."

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
    printf '  "_version": 2,\n'
    printf '  "capturedAt": "%s",\n' "$CAPTURE_DATE"
    printf '  "hostname": "%s",\n' "$(json_escape_string "$HOSTNAME_VAL")"
    printf '  "snapshotFile": "%s",\n' "$(json_escape_string "$OUTPUT_FILE")"
    printf '  "mapDumps": {'
  } > "$DUMP_OUTPUT_FILE"

  ATTEMPT_COUNT=0
  while IFS=: read -r MAP_ID MAP_TYPE; do
    [[ -z "$MAP_ID" || -z "$MAP_TYPE" ]] && continue
    DUMP_TMPFILE="$TMPDIR_SNAP/mapdump_${MAP_ID}.json"
    DUMP_ERROR=""
    DUMP_COMPLETE=false
    DUMP_UNSUPPORTED=false
    printf '[]' > "$DUMP_TMPFILE"

    if echo "$MAP_TYPE" | grep -qE "^($UNSUPPORTED_TYPES)$"; then
      DUMP_UNSUPPORTED=true
      DUMP_ERROR="Map type $MAP_TYPE is not collected by this capture script"
    elif [[ $ATTEMPT_COUNT -ge $MAX_MAPS ]]; then
      DUMP_ERROR="Not collected: --max-maps limit ($MAX_MAPS) reached"
    else
      ATTEMPT_COUNT=$((ATTEMPT_COUNT + 1))
      vlog "Dumping map $MAP_ID ($MAP_TYPE)..."
      dump_cmd_parts=()
      if [[ -n "$TIMEOUT_CMD" ]]; then dump_cmd_parts+=("$TIMEOUT_CMD" "$MAP_DUMP_TIMEOUT"); fi
      if [[ ${#SUDO_PREFIX[@]} -gt 0 ]]; then dump_cmd_parts+=("${SUDO_PREFIX[@]}"); fi
      dump_cmd_parts+=("$BPFTOOL" -j map dump id "$MAP_ID")
      DUMP_EXIT=0
      "${dump_cmd_parts[@]}" > "$DUMP_TMPFILE.raw" 2> "$DUMP_TMPFILE.stderr" || DUMP_EXIT=$?
      grep -v '^libbpf:' "$DUMP_TMPFILE.raw" > "$DUMP_TMPFILE" || true
      FIRST_CHAR=$(tr -d '[:space:]' < "$DUMP_TMPFILE" | head -c 1 || true)
      DUMP_BYTES=$(wc -c < "$DUMP_TMPFILE")
      if [[ $DUMP_BYTES -gt 10485760 ]]; then
        DUMP_ERROR="Dump exceeded 10 MB capture limit"
        printf '[]' > "$DUMP_TMPFILE"
      elif [[ "$FIRST_CHAR" != "[" ]]; then
        DUMP_ERROR="Expected a JSON entry array: $(head -c 2048 "$DUMP_TMPFILE.stderr")"
        printf '[]' > "$DUMP_TMPFILE"
      elif [[ $DUMP_EXIT -ne 0 ]]; then
        # Preserve returned observations along with the command failure.
        DUMP_ERROR="Dump command failed (exit $DUMP_EXIT): $(head -c 2048 "$DUMP_TMPFILE.stderr")"
      else
        DUMP_COMPLETE=true
      fi
      sleep "$MAP_DUMP_DELAY" 2>/dev/null || true
    fi

    # Store failure/skip evidence too; an omitted or failed dump is never [].
    {
      if [[ $FIRST_ENTRY -eq 0 ]]; then printf ','; fi
      printf '\n    "%s": {"complete": %s, "unsupported": %s, "error": ' "$MAP_ID" "$DUMP_COMPLETE" "$DUMP_UNSUPPORTED"
      if [[ -n "$DUMP_ERROR" ]]; then printf '"%s"' "$(json_escape_string "$DUMP_ERROR")"; else printf 'null'; fi
      printf ', "entries": '
      cat "$DUMP_TMPFILE"
      printf '}'
    } >> "$DUMP_OUTPUT_FILE"
    FIRST_ENTRY=0
    if [[ "$DUMP_COMPLETE" == true ]]; then DUMP_COUNT=$((DUMP_COUNT + 1)); else SKIP_COUNT=$((SKIP_COUNT + 1)); fi
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
