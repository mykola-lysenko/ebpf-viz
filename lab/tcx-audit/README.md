# TCX ordering audit

This loader creates an isolated veth pair, loads three TCX programs in reverse
execution order, then attaches them using Head/AfterLink anchors. A legacy TC
classifier follows on the same device and direction. A shared map records the
execution sequence for one synthetic Ethernet frame.

Four cases cover ingress/egress and TCX continuation/terminal PASS. With every
TCX program returning NEXT, the sequence is `1234` (three TCX, then legacy).
With the second TCX program returning PASS, it is `12` (third TCX and legacy
are skipped). Each case checks BPF_PROG_QUERY order and a revision increment
of three, then captures bpftool inventories and detailed TC filter output.

Requires Go 1.25+, bpftool with TCX support, iproute2, and a UML kernel with
BPF, veth, TCX, and clsact enabled. The Go dependency versions match the
existing netkit lab. No host sudo or host network changes are needed:

```bash
UML_BIN=/path/to/uml/linux BPFTOOL_PATH=/path/to/bpftool \
  ./lab/tcx-audit/run-uml.sh /tmp/tcx-audit
```

UML needs ptrace permission. Output contains each case's `snapshot.json` and
`evidence.json`, plus the console log and result code. The loader deletes its
veth pair and closes all BPF resources on exit. Its standalone binary must only
be run in a disposable guest or isolated network namespace with BPF privileges.

The checked-in captures and verdict are documented in
[the A.3 audit report](../../docs/tcx-audit.md). They use a patched UML guest;
they do not claim validation on the host WSL kernel or every kernel version.
