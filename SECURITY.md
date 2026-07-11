# Security model

ebpf-viz is a **local research/debugging tool**, not a hardened multi-tenant
service. It runs `bpftool` (usually via `sudo`), reads kernel BPF state — program
bytecode, JIT disassembly, and **map contents, which routinely hold real data**
(connection tuples, PIDs, config) — and can lower sysctls for the duration of a
dump. The intended deployment is: you run it on your own machine, use it, and
shut it down.

Given that, most classic web hardening is intentionally out of scope: there is
no user auth beyond an optional operator token, no request rate limiting worth
relying on, and no DoS budget for the snapshot parser. Those defend against
*untrusted parties reaching the tool over the network* — which a local tool you
start and stop doesn't have.

## What we DO defend against

One class of attack does not require the attacker to be on your network — it
only requires you to have the dashboard running while you browse the web:
**DNS rebinding / cross-origin requests from a malicious web page.** Such a page
can point its own domain at `127.0.0.1` and, because the browser then treats the
request as same-origin, read your kernel's entire BPF state through your browser.

Two defenses close this, both on by default:

1. **Host-header allowlist.** Every request (except `/healthz`) must carry a
   `Host` header of `localhost` / `127.0.0.1` / `[::1]` (any port). A rebound
   attacker page still sends `Host: attacker.example`, which is rejected with
   `403`. A missing Host header is also rejected.

2. **Loopback bind by default.** With `HOST` unset the server binds to
   `127.0.0.1`, so an accidental run never exposes the tool to the LAN or the
   WSL bridge.

## Binding wider on purpose

If you deliberately want to reach the dashboard from another machine (bind to a
LAN IP), set **both**:

```bash
HOST=0.0.0.0 \
EBPF_VIZ_ALLOWED_HOSTS="my-dev-box.local,10.0.0.5" \
  <run command>
```

`EBPF_VIZ_ALLOWED_HOSTS` is a comma-separated allowlist of extra hostnames/IPs
the Host guard will accept (loopback is always allowed). Without it, wider binds
still 403 every non-loopback client. Doing this puts sensitive kernel state on
the network with no authentication — only do it on a trusted network, and
consider setting `EBPF_VIZ_ADMIN_TOKEN` so the mutating endpoints require it.

## Optional operator token

`EBPF_VIZ_ADMIN_TOKEN` (or `ADMIN_TOKEN`) gates the mutating/expensive endpoints
for non-loopback clients. Loopback is always trusted as operator. This is only
relevant when you have intentionally bound beyond loopback.
