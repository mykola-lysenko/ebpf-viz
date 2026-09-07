// Controlled TCX audit. Run in a disposable network namespace or UML guest.
// Uses the existing lab dependencies, creates only a private veth pair, and
// closes all links/programs/maps and deletes that pair on return.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	must(err)
	must(os.WriteFile(path, append(data, '\n'), 0644))
}
func command(bin string, args ...string) json.RawMessage {
	data, err := exec.Command(bin, args...).Output()
	must(err)
	return json.RawMessage(data)
}
func program(name string, digit int32, action int32, m *ebpf.Map) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{
		asm.LoadMapPtr(asm.R1, m.FD()), asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "out"), asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord), asm.Mul.Imm(asm.R1, 10), asm.Add.Imm(asm.R1, digit), asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, action).WithSymbol("out"), asm.Return()}})
	must(err)
	return p
}
func main() {
	out := flag.String("out", ".", "capture output directory")
	bpftool := flag.String("bpftool", "bpftool", "bpftool executable")
	flag.Parse()
	must(os.MkdirAll(*out, 0755))
	v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "a3-send"}, PeerName: "a3-recv"}
	must(netlink.LinkAdd(v))
	defer netlink.LinkDel(v)
	send, err := netlink.LinkByName("a3-send")
	must(err)
	recv, err := netlink.LinkByName("a3-recv")
	must(err)
	must(netlink.LinkSetUp(send))
	must(netlink.LinkSetUp(recv))
	// Avoid unsolicited IPv6 setup traffic in this disposable namespace.
	for _, name := range []string{"a3-send", "a3-recv"} {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+name+"/disable_ipv6", []byte("1"), 0644)
	}
	time.Sleep(100 * time.Millisecond)
	for _, direction := range []string{"ingress", "egress"} {
		for _, terminal := range []bool{false, true} {
			run(*out, *bpftool, send, recv, direction, terminal)
		}
	}
	fmt.Println("PASS: ingress/egress query ordering, revisions, mixed legacy TC execution, TCX terminal bypass")
}
func run(out, bpftool string, send, recv netlink.Link, direction string, terminal bool) {
	target := recv
	attach := ebpf.AttachTCXIngress
	parent := uint32(netlink.HANDLE_MIN_INGRESS)
	if direction == "egress" {
		target = send
		attach = ebpf.AttachTCXEgress
		parent = netlink.HANDLE_MIN_EGRESS
	}
	name := direction + "-next"
	if terminal {
		name = direction + "-pass"
	}
	out = filepath.Join(out, name)
	must(os.MkdirAll(out, 0755))
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "a3_sequence", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	must(err)
	defer m.Close()
	// Load in reverse execution order so IDs cannot masquerade as ordering.
	lastAction := int32(-1)
	if terminal {
		lastAction = 0
	}
	p3 := program("a3_third", 3, -1, m)
	defer p3.Close()
	p2 := program("a3_second", 2, lastAction, m)
	defer p2.Close()
	p1 := program("a3_first", 1, -1, m)
	defer p1.Close()
	p4 := program("a3_legacy", 4, 0, m)
	defer p4.Close()
	query := func() *link.QueryResult {
		q, err := link.QueryPrograms(link.QueryOptions{Target: target.Attrs().Index, Attach: attach})
		must(err)
		return q
	}
	before := query()
	l3, err := link.AttachTCX(link.TCXOptions{Interface: target.Attrs().Index, Program: p3, Attach: attach})
	must(err)
	defer l3.Close()
	l1, err := link.AttachTCX(link.TCXOptions{Interface: target.Attrs().Index, Program: p1, Attach: attach, Anchor: link.Head()})
	must(err)
	defer l1.Close()
	l2, err := link.AttachTCX(link.TCXOptions{Interface: target.Attrs().Index, Program: p2, Attach: attach, Anchor: link.AfterLink(l1)})
	must(err)
	defer l2.Close()
	q := query()
	expected := []ebpf.ProgramID{}
	for _, p := range []*ebpf.Program{p1, p2, p3} {
		info, err := p.Info()
		must(err)
		id, _ := info.ID()
		expected = append(expected, id)
	}
	if len(q.Programs) != 3 {
		panic("wrong TCX count")
	}
	for i, p := range q.Programs {
		if p.ID != expected[i] {
			panic("wrong TCX order")
		}
	}
	if q.Revision != before.Revision+3 {
		panic(fmt.Sprintf("revision %d -> %d", before.Revision, q.Revision))
	}
	qdisc := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: target.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"}
	must(netlink.QdiscAdd(qdisc))
	defer netlink.QdiscDel(qdisc)
	must(netlink.FilterAdd(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: target.Attrs().Index, Parent: parent, Handle: 1, Priority: 10, Protocol: unix.ETH_P_ALL}, Fd: p4.FD(), Name: "a3_legacy", DirectAction: true}))
	// Capture while all fd-backed attachments remain alive.
	net := command(bpftool, "-j", "net")
	filters := command("tc", "-j", "-s", "-d", "filter", "show", "dev", target.Attrs().Name, direction)
	write(filepath.Join(out, "snapshot.json"), map[string]any{"_ebpfVizSnapshot": true, "hostname": "tcx-audit-uml", "capturedAt": time.Now().UTC().Format(time.RFC3339), "raw": map[string]any{
		"progs": command(bpftool, "-j", "prog", "list"), "maps": command(bpftool, "-j", "map", "list"), "net": net, "links": command(bpftool, "-j", "link", "list"), "cgroups": []any{}, "tcFilters": []any{map[string]any{"devname": target.Attrs().Name, "ifindex": target.Attrs().Index, "direction": direction, "filters": filters}}}})
	zero := uint32(0)
	must(m.Update(zero, uint64(0), ebpf.UpdateAny))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int((unix.ETH_P_ALL>>8)|(unix.ETH_P_ALL<<8)&0xffff))
	must(err)
	defer unix.Close(fd)
	frame := make([]byte, 60)
	copy(frame[0:6], recv.Attrs().HardwareAddr)
	copy(frame[6:12], send.Attrs().HardwareAddr)
	frame[12] = 0x88
	frame[13] = 0xb5
	must(unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: send.Attrs().Index, Halen: 6}))
	var sequence uint64
	for i := 0; i < 100; i++ {
		must(m.Lookup(zero, &sequence))
		if sequence != 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	want := uint64(1234)
	if terminal {
		want = 12
	}
	if sequence != want {
		panic(fmt.Sprintf("%s got sequence %d want %d", name, sequence, want))
	}
	write(filepath.Join(out, "evidence.json"), map[string]any{"direction": direction, "terminalTCX": terminal, "query": q, "revisionBefore": before.Revision, "expectedProgramIds": expected, "observedExecution": sequence, "expectedExecution": want, "kernel": string(commandText("uname", "-r")), "bpftool": string(commandText(bpftool, "version"))})
	fmt.Printf("%s: programs %v, revision %d -> %d, packet sequence %d\n", name, expected, before.Revision, q.Revision, sequence)
}
func commandText(bin string, args ...string) []byte {
	data, err := exec.Command(bin, args...).Output()
	must(err)
	return data
}
