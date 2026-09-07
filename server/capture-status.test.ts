import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { snapshotUploadSchema } from "../shared/snapshot-validation";

// Exercise the actual target-side shell script without bpftool, sudo, or
// entering namespaces. All external collection commands are fixture tools.
describe("capture collection metadata", () => {
  it.each(["failure", "malformed", "empty"])("records %s without mislabelling a failed empty inventory", mode => {
    const dir = mkdtempSync(join(tmpdir(), "ebpf-capture-test-"));
    try {
      const tool = (name: string, body: string) => writeFileSync(join(dir, name), `#!/bin/bash\n${body}\n`, { mode: 0o755 });
      tool("bpftool", `
if [[ "$*" == version ]]; then echo 'bpftool v7.8.0'; exit; fi
if [[ "$*" == *'prog list'* ]]; then
  case "$CAPTURE_TEST_MODE" in
    failure) echo 'permission denied' >&2; exit 1;;
    malformed) echo '{"error":"bad output"}'; exit;;
  esac
fi
echo '[]'`);
      tool("tc", "echo '[]'");
      tool("nsenter", "echo '[]'");
      tool("readlink", "echo 'net:[1]'");
      const out = join(dir, "snapshot.json");
      execFileSync("bash", [resolve("scripts/capture-snapshot.sh"), "--no-sudo", "--output", out], {
        env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, BPFTOOL_PATH: join(dir, "bpftool"), CAPTURE_TEST_MODE: mode },
        timeout: 20_000, stdio: "pipe",
      });
      const parsed = snapshotUploadSchema.parse(JSON.parse(readFileSync(out, "utf8")));
      expect(parsed.raw?.progs).toEqual([]);
      const status = parsed.collection!.sources.progs;
      expect(status.state).toBe(mode === "empty" ? "ok" : "error");
      expect(status.lastSuccessAt === null).toBe(mode !== "empty");
      expect(parsed.collection!.sources.maps.state).toBe("ok");
      expect(parsed.collection!.sources.dockerDiscovery.state).toBe("skipped");
      expect(parsed.collection!.sources.dockerDiscovery.attemptedAt).toBeNull();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

// Map dump v2 records distinguish successful emptiness, command failure,
// unsupported collection policy, and budget omissions in the actual script.
describe("capture map dump evidence", () => {
  it("writes map failures and skip reasons instead of silently omitting maps", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ebpf-map-capture-test-"));
    try {
      const tool = (name: string, body: string) => writeFileSync(join(dir, name), `#!/bin/bash\n${body}\n`, { mode: 0o755 });
      tool("bpftool", `
if [[ "$*" == version ]]; then echo 'bpftool v7.8.0'; exit; fi
if [[ "$*" == *'map list'* ]]; then
  echo '[{"id":1,"type":"hash"},{"id":2,"type":"hash"},{"id":3,"type":"ringbuf"},{"id":4,"type":"hash"}]'; exit
fi
if [[ "$*" == *'map dump id 1'* ]]; then
  echo '[{"key":["0x01"],"value":["0x02"]}]'; echo 'permission denied' >&2; exit 1
fi
echo '[]'`);
      tool("tc", "echo '[]'"); tool("nsenter", "echo '[]'"); tool("readlink", "echo 'net:[1]'");
      const out = join(dir, "snapshot.json"), dumps = join(dir, "dumps.json");
      execFileSync("bash", [resolve("scripts/capture-snapshot.sh"), "--no-sudo", "--output", out, "--dump-maps", "--dump-output", dumps, "--max-maps", "2"], {
        env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, BPFTOOL_PATH: join(dir, "bpftool") }, timeout: 20_000, stdio: "pipe",
      });
      const { mapDumpsUploadSchema } = await import("../shared/snapshot-validation");
      const parsed = mapDumpsUploadSchema.parse(JSON.parse(readFileSync(dumps, "utf8")));
      expect(parsed._version).toBe(2);
      expect(parsed.mapDumps[1]).toMatchObject({ complete: false, entries: [{ key: ["0x01"], value: ["0x02"] }] });
      expect((parsed.mapDumps[1] as { error: string }).error).toContain("permission denied");
      expect(parsed.mapDumps[2]).toMatchObject({ complete: true, entries: [], error: null });
      expect(parsed.mapDumps[3]).toMatchObject({ complete: false, unsupported: true });
      expect((parsed.mapDumps[4] as { error: string }).error).toContain("--max-maps limit");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
