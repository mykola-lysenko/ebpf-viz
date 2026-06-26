#!/usr/bin/env bash
set -uo pipefail

BPFTOOL="${BPFTOOL:-bpftool}"
SUDO_CMD="${SUDO-sudo}"
PROFILE="${PROFILE:-network}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-45}"
MAX_TAIL_CALL_DEPTH="${MAX_TAIL_CALL_DEPTH:-8}"
MAX_PROGRAMS="${MAX_PROGRAMS:-0}"
MAX_PROG_ARRAY_MAPS="${MAX_PROG_ARRAY_MAPS:-0}"
MAX_TC_DEVS="${MAX_TC_DEVS:-0}"
INCLUDE_XLATED="${INCLUDE_XLATED:-1}"
INCLUDE_TEXT="${INCLUDE_TEXT:-1}"
INCLUDE_JITED="${INCLUDE_JITED:-1}"
DUMP_PROG_ARRAY_MAPS="${DUMP_PROG_ARRAY_MAPS:-1}"
RUN_NICE="${RUN_NICE:-1}"
NICE_VALUE="${NICE_VALUE:-10}"
RUN_IONICE="${RUN_IONICE:-1}"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-/tmp/ebpf-viz-l3-capture-${TS}}"
ARCHIVE="${ARCHIVE:-/tmp/ebpf-viz-l3-latest.tar.gz}"

case "$PROFILE" in
  inventory|network|l3|cgroup|all)
    ;;
  *)
    echo "Unsupported PROFILE=$PROFILE. Use inventory, network, cgroup, or all." >&2
    exit 2
    ;;
esac

for numeric_value in TIMEOUT_SECONDS MAX_TAIL_CALL_DEPTH MAX_PROGRAMS MAX_PROG_ARRAY_MAPS MAX_TC_DEVS NICE_VALUE; do
  value="${!numeric_value}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$numeric_value must be numeric, got: $value" >&2
    exit 2
  fi
done

for bool_value in INCLUDE_XLATED INCLUDE_TEXT INCLUDE_JITED DUMP_PROG_ARRAY_MAPS RUN_NICE RUN_IONICE; do
  value="${!bool_value}"
  if [ "$value" != "0" ] && [ "$value" != "1" ]; then
    echo "$bool_value must be 0 or 1, got: $value" >&2
    exit 2
  fi
done

if [ -n "$SUDO_CMD" ]; then
  read -r -a SUDO_PREFIX <<< "$SUDO_CMD"
else
  SUDO_PREFIX=()
fi

mkdir -p "$OUT/prog" "$OUT/map" "$OUT/tc" "$OUT/cgroup"
touch "$OUT/dumped-program-ids.txt" "$OUT/dumped-map-ids.txt"

run_capture() {
  local stdout="$1"
  local stderr="$2"
  shift 2

  local cmd=("$@")
  if [ "$RUN_NICE" = "1" ] && command -v nice >/dev/null 2>&1; then
    cmd=(nice -n "$NICE_VALUE" "${cmd[@]}")
  fi
  if [ "$RUN_IONICE" = "1" ] && command -v ionice >/dev/null 2>&1; then
    cmd=(ionice -c3 "${cmd[@]}")
  fi

  if command -v timeout >/dev/null 2>&1; then
    timeout "$TIMEOUT_SECONDS" "${cmd[@]}" >"$stdout" 2>"$stderr" || true
  else
    "${cmd[@]}" >"$stdout" 2>"$stderr" || true
  fi
}

safe_name() {
  printf '%s' "${1:-unnamed}" | tr -c 'A-Za-z0-9_.-' '_'
}

already_dumped() {
  local id="$1"
  local file="$2"
  grep -Fxq "$id" "$file" 2>/dev/null
}

record_dumped() {
  local id="$1"
  local file="$2"
  if ! already_dumped "$id" "$file"; then
    printf '%s\n' "$id" >> "$file"
  fi
}

refresh_state() {
  local mode="$1"
  python3 - "$OUT" "$mode" "$PROFILE" "$MAX_PROGRAMS" "$MAX_PROG_ARRAY_MAPS" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
profile = sys.argv[3]
max_programs = int(sys.argv[4])
max_prog_array_maps = int(sys.argv[5])
L3_TYPES = {"sched_cls", "sched_act", "netfilter", "flow_dissector"}
CGROUP_TYPES = {
    "cgroup_skb",
    "cgroup_sock",
    "cgroup_sock_addr",
    "cgroup_sockopt",
    "sock_ops",
}
CGROUP_NETWORK_ATTACH_TYPES = {
    "cgroup_inet_ingress",
    "cgroup_inet_egress",
    "cgroup_inet4_bind",
    "cgroup_inet6_bind",
    "cgroup_inet4_connect",
    "cgroup_inet6_connect",
    "cgroup_inet4_post_bind",
    "cgroup_inet6_post_bind",
    "cgroup_inet4_getpeername",
    "cgroup_inet6_getpeername",
    "cgroup_inet4_getsockname",
    "cgroup_inet6_getsockname",
    "cgroup_udp4_sendmsg",
    "cgroup_udp6_sendmsg",
    "cgroup_udp4_recvmsg",
    "cgroup_udp6_recvmsg",
    "cgroup_sock_create",
    "cgroup_inet_sock_create",
    "cgroup_sock_ops",
    "cgroup_getsockopt",
    "cgroup_setsockopt",
}

def load_json(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None

def items_from_json(path, keys):
    data = load_json(path)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        result = data.get("result")
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
    return []

def read_ids(name):
    path = out / name
    ids = set()
    if not path.exists():
        return ids
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.isdigit():
            ids.add(int(line))
    return ids

def write_ids(name, ids):
    (out / name).write_text("".join(f"{value}\n" for value in sorted(ids)))

def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None

def int_from_bytes(value):
    if not isinstance(value, list):
        return None
    total = 0
    for shift, item in enumerate(value):
        if not isinstance(item, str):
            return None
        try:
            byte = int(item.replace("0x", ""), 16)
        except ValueError:
            return None
        total |= byte << (shift * 8)
    return total

def int_from_object(value, fields):
    if not isinstance(value, dict):
        return None
    for field in fields:
        parsed = as_int(value.get(field))
        if parsed is not None:
            return parsed
    return None

def first(*values):
    for value in values:
        if value is not None:
            return value
    return None

def int_from_raw(value):
    return first(int_from_bytes(value), as_int(value))

def map_type(map_obj):
    return str(map_obj.get("type", "")).replace("-", "_").lower()

def prog_id(prog):
    return as_int(prog.get("id"))

def map_id(map_obj):
    return as_int(map_obj.get("id"))

def program_map_ids(prog):
    values = prog.get("map_ids") or []
    if not isinstance(values, list):
        return []
    result = []
    for value in values:
        parsed = as_int(value)
        if parsed is not None:
            result.append(parsed)
    return result

def parse_prog_array_entry(raw):
    formatted = raw.get("formatted")
    formatted_key = formatted.get("key") if isinstance(formatted, dict) else None
    formatted_value = formatted.get("value") if isinstance(formatted, dict) else None
    key = raw.get("key")
    value = raw.get("value")

    slot = first(
        int_from_raw(formatted_key),
        int_from_object(formatted_key, ["slot", "index", "key"]),
        int_from_raw(key),
        int_from_object(key, ["slot", "index", "key"]),
    )
    target = first(
        int_from_raw(formatted_value),
        int_from_object(formatted_value, ["prog_id", "progId", "program_id", "id"]),
        int_from_raw(value),
        int_from_object(value, ["prog_id", "progId", "program_id", "id"]),
    )
    return slot, target

progs = items_from_json(out / "prog-show.json", ["programs", "progs"])
maps = items_from_json(out / "map-show.json", ["maps"])
cgroups = items_from_json(out / "cgroup-tree.json", ["cgroups"])
prog_by_id = {pid: prog for prog in progs if (pid := prog_id(prog)) is not None}
map_by_id = {mid: map_obj for map_obj in maps if (mid := map_id(map_obj)) is not None}

seed_ids = {
    pid
    for pid, prog in prog_by_id.items()
    if str(prog.get("type", "")).replace("-", "_").lower() in L3_TYPES
}
cgroup_seed_ids = {
    pid
    for pid, prog in prog_by_id.items()
    if str(prog.get("type", "")).replace("-", "_").lower() in CGROUP_TYPES
}
for cg in cgroups:
    for attached in cg.get("programs") or []:
        if not isinstance(attached, dict):
            continue
        attach_type = str(attached.get("attach_type", "")).replace("-", "_").lower()
        pid = as_int(attached.get("id"))
        if pid is not None and attach_type in CGROUP_NETWORK_ATTACH_TYPES:
            cgroup_seed_ids.add(pid)
previous_ids = read_ids("all-program-ids.txt")
if profile == "inventory":
    initial_seed_ids = set()
elif profile == "cgroup":
    initial_seed_ids = cgroup_seed_ids
elif profile == "all":
    initial_seed_ids = set(prog_by_id)
else:
    initial_seed_ids = seed_ids | cgroup_seed_ids
all_ids = set(previous_ids or initial_seed_ids)

targets = []
target_ids = set()
for dump_path in sorted((out / "map").glob("*.dump.json")):
    try:
        current_map_id = int(dump_path.name.split("_", 1)[0])
    except ValueError:
        continue
    entries = load_json(dump_path)
    if not isinstance(entries, list):
        continue
    for entry_index, raw in enumerate(entries):
        if not isinstance(raw, dict):
            continue
        slot, target_id = parse_prog_array_entry(raw)
        if slot is None or target_id is None:
            continue
        targets.append((current_map_id, slot, target_id, entry_index))
        target_ids.add(target_id)

if mode in {"targets", "summary"}:
    all_ids |= target_ids

if max_programs > 0 and len(all_ids) > max_programs:
    all_ids = set(sorted(all_ids)[:max_programs])

prog_array_map_ids = set()
for pid in all_ids:
    prog = prog_by_id.get(pid)
    if not prog:
        continue
    for mid in program_map_ids(prog):
        map_obj = map_by_id.get(mid)
        if map_obj and map_type(map_obj) == "prog_array":
            prog_array_map_ids.add(mid)

if max_prog_array_maps > 0 and len(prog_array_map_ids) > max_prog_array_maps:
    prog_array_map_ids = set(sorted(prog_array_map_ids)[:max_prog_array_maps])

def prog_row(pid, relation):
    prog = prog_by_id.get(pid, {})
    return (
        pid,
        str(prog.get("type", "unknown")),
        str(prog.get("name", f"prog_{pid}") or f"prog_{pid}"),
        relation,
    )

with (out / "seed-l3-programs.tsv").open("w") as handle:
    for pid in sorted(seed_ids):
        handle.write("\t".join(map(str, prog_row(pid, "l3-seed"))) + "\n")

with (out / "seed-cgroup-programs.tsv").open("w") as handle:
    for pid in sorted(cgroup_seed_ids):
        handle.write("\t".join(map(str, prog_row(pid, "cgroup-seed"))) + "\n")

with (out / "all-programs.tsv").open("w") as handle:
    for pid in sorted(all_ids):
        if pid in seed_ids and pid in cgroup_seed_ids:
            relation = "l3+cgroup-seed"
        elif pid in seed_ids:
            relation = "l3-seed"
        elif pid in cgroup_seed_ids:
            relation = "cgroup-seed"
        else:
            relation = "tail-call-target"
        handle.write("\t".join(map(str, prog_row(pid, relation))) + "\n")

with (out / "prog-array-maps.tsv").open("w") as handle:
    for mid in sorted(prog_array_map_ids):
        map_obj = map_by_id.get(mid, {})
        handle.write(
            f"{mid}\t{map_obj.get('type', 'unknown')}\t{map_obj.get('name', f'map_{mid}')}\n"
        )

with (out / "tail-call-targets.tsv").open("w") as handle:
    for mid, slot, target_id, entry_index in sorted(targets):
        prog = prog_by_id.get(target_id, {})
        handle.write(
            f"{mid}\t{slot}\t{target_id}\t{entry_index}\t"
            f"{prog.get('type', 'unknown')}\t{prog.get('name', f'prog_{target_id}')}\n"
        )

write_ids("all-program-ids.txt", all_ids)
write_ids("prog-array-map-ids.txt", prog_array_map_ids)

changed = all_ids != previous_ids
(out / "state-changed").write_text("1\n" if changed else "0\n")

if mode == "summary":
    summary = [
        f"Output directory: {out}",
        f"Profile: {profile}",
        f"L3 seed programs: {len(seed_ids)}",
        f"Cgroup networking seed programs: {len(cgroup_seed_ids)}",
        f"All collected programs: {len(all_ids)}",
        f"Prog-array maps: {len(prog_array_map_ids)}",
        f"Resolved tail-call entries: {len(targets)}",
        f"Max programs: {max_programs or 'unbounded'}",
        f"Max prog-array maps: {max_prog_array_maps or 'unbounded'}",
        "",
        "L3 program types: sched_cls, sched_act, netfilter, flow_dissector",
        "Cgroup attach types: inet ingress/egress, bind/connect, sendmsg/recvmsg, sockops, sockopt",
    ]
    (out / "collection-summary.txt").write_text("\n".join(summary) + "\n")
PY
}

dump_programs() {
  while IFS=$'\t' read -r id type name relation; do
    [ -n "${id:-}" ] || continue
    if already_dumped "$id" "$OUT/dumped-program-ids.txt"; then
      continue
    fi

    local safe
    safe="$(safe_name "$name")"
    local prefix="$OUT/prog/${id}_${type}_${safe}"
    echo "Dumping program $id ($type $name, $relation)"

    run_capture "$prefix.show.json" "$prefix.show.err" \
      ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp prog show id "$id"
    if [ "$INCLUDE_XLATED" = "1" ]; then
      run_capture "$prefix.xlated-linum.json" "$prefix.xlated-linum.err" \
        ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp prog dump xlated id "$id" linum
      run_capture "$prefix.xlated.json" "$prefix.xlated.err" \
        ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp prog dump xlated id "$id"
      if [ "$INCLUDE_TEXT" = "1" ]; then
        run_capture "$prefix.xlated-linum.txt" "$prefix.xlated-linum.txt.err" \
          ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" prog dump xlated id "$id" linum
      fi
    fi
    if [ "$INCLUDE_JITED" = "1" ]; then
      run_capture "$prefix.jited.json" "$prefix.jited.err" \
        ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp prog dump jited id "$id"
      if [ "$INCLUDE_TEXT" = "1" ]; then
        run_capture "$prefix.jited.txt" "$prefix.jited.txt.err" \
          ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" prog dump jited id "$id"
      fi
    fi

    record_dumped "$id" "$OUT/dumped-program-ids.txt"
  done < "$OUT/all-programs.tsv"
}

dump_prog_array_maps() {
  if [ "$DUMP_PROG_ARRAY_MAPS" != "1" ]; then
    return
  fi

  while IFS=$'\t' read -r id type name; do
    [ -n "${id:-}" ] || continue
    if already_dumped "$id" "$OUT/dumped-map-ids.txt"; then
      continue
    fi

    local safe
    safe="$(safe_name "$name")"
    local prefix="$OUT/map/${id}_${safe}"
    echo "Dumping prog-array map $id ($name)"

    run_capture "$prefix.show.json" "$prefix.show.err" \
      ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp map show id "$id"
    run_capture "$prefix.dump.json" "$prefix.dump.err" \
      ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp map dump id "$id"

    record_dumped "$id" "$OUT/dumped-map-ids.txt"
  done < "$OUT/prog-array-maps.tsv"
}

dump_tc_filters() {
  if ! command -v ip >/dev/null 2>&1 || ! command -v tc >/dev/null 2>&1; then
    return
  fi

  local count=0
  ip -json link show >"$OUT/ip-link.json" 2>"$OUT/ip-link.err" || true
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | sort -u |
    while IFS= read -r dev; do
      [ -n "$dev" ] || continue
      count=$((count + 1))
      if [ "$MAX_TC_DEVS" -gt 0 ] && [ "$count" -gt "$MAX_TC_DEVS" ]; then
        printf '%s\n' "$dev" >> "$OUT/tc/skipped-devices.txt"
        continue
      fi
      local safe
      safe="$(safe_name "$dev")"
      run_capture "$OUT/tc/${safe}.ingress.json" "$OUT/tc/${safe}.ingress.err" \
        ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} tc -s -d -j filter show dev "$dev" ingress
      run_capture "$OUT/tc/${safe}.egress.json" "$OUT/tc/${safe}.egress.err" \
        ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} tc -s -d -j filter show dev "$dev" egress
    done
}

echo "Collecting eBPF BPF program data into $OUT (profile: $PROFILE)"
{
  date
  uname -srmo
  "$BPFTOOL" version 2>/dev/null || true
  ip -V 2>/dev/null || true
  tc -V 2>/dev/null || true
} >"$OUT/environment.txt" 2>"$OUT/environment.err"

{
  printf 'BPFTOOL=%s\n' "$BPFTOOL"
  printf 'SUDO=%s\n' "$SUDO_CMD"
  printf 'PROFILE=%s\n' "$PROFILE"
  printf 'TIMEOUT_SECONDS=%s\n' "$TIMEOUT_SECONDS"
  printf 'MAX_TAIL_CALL_DEPTH=%s\n' "$MAX_TAIL_CALL_DEPTH"
  printf 'MAX_PROGRAMS=%s\n' "$MAX_PROGRAMS"
  printf 'MAX_PROG_ARRAY_MAPS=%s\n' "$MAX_PROG_ARRAY_MAPS"
  printf 'MAX_TC_DEVS=%s\n' "$MAX_TC_DEVS"
  printf 'INCLUDE_XLATED=%s\n' "$INCLUDE_XLATED"
  printf 'INCLUDE_TEXT=%s\n' "$INCLUDE_TEXT"
  printf 'INCLUDE_JITED=%s\n' "$INCLUDE_JITED"
  printf 'DUMP_PROG_ARRAY_MAPS=%s\n' "$DUMP_PROG_ARRAY_MAPS"
  printf 'RUN_NICE=%s\n' "$RUN_NICE"
  printf 'NICE_VALUE=%s\n' "$NICE_VALUE"
  printf 'RUN_IONICE=%s\n' "$RUN_IONICE"
} >"$OUT/collection-config.txt"

run_capture "$OUT/prog-show.json" "$OUT/prog-show.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp prog show
run_capture "$OUT/map-show.json" "$OUT/map-show.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp map show
run_capture "$OUT/net-show.json" "$OUT/net-show.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp net show
run_capture "$OUT/cgroup-tree.json" "$OUT/cgroup-tree.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp cgroup tree
run_capture "$OUT/cgroup-tree-effective.json" "$OUT/cgroup-tree-effective.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" -jp cgroup tree /sys/fs/cgroup effective
run_capture "$OUT/cgroup-tree.txt" "$OUT/cgroup-tree.txt.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" cgroup tree
run_capture "$OUT/cgroup-tree-effective.txt" "$OUT/cgroup-tree-effective.txt.err" \
  ${SUDO_PREFIX[@]+"${SUDO_PREFIX[@]}"} "$BPFTOOL" cgroup tree /sys/fs/cgroup effective
dump_tc_filters

refresh_state init
if [ "$PROFILE" != "inventory" ]; then
  if [ "$MAX_TAIL_CALL_DEPTH" -gt 0 ]; then
    for depth in $(seq 1 "$MAX_TAIL_CALL_DEPTH"); do
      echo "Discovery pass $depth/$MAX_TAIL_CALL_DEPTH"
      dump_programs
      refresh_state maps
      dump_prog_array_maps
      refresh_state targets
      if [ "$(cat "$OUT/state-changed" 2>/dev/null || echo 0)" = "0" ]; then
        break
      fi
    done
  fi
  dump_programs
fi
refresh_state summary

if ! tar -C "$(dirname "$OUT")" -czf "$ARCHIVE" "$(basename "$OUT")"; then
  echo "Failed to create archive: $ARCHIVE" >&2
  exit 1
fi
echo "Created: $ARCHIVE"
cat "$OUT/collection-summary.txt"
