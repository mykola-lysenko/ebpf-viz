// netkitctl — create netkit device pairs across network namespaces and attach
// sched_cls BPF programs to them via netkit links, the way Cilium's datapath
// does (but with no Kubernetes, no Cilium, just netlink + libbpf).
//
// For each pod it:
//   - creates a netkit pair: primary "<pod>" in the node netns, peer "eth0"
//     inside the pod netns (L3, policy forward)
//   - addresses both ends (node 10.244.<i>.1/24, pod 10.244.<i>.2/24) and adds
//     the pod's default route via the node
//   - attaches nk_to_pod (primary hook) and nk_from_pod (peer hook), both
//     created against the primary ifindex as the kernel requires
//   - pins both links under /sys/fs/bpf/nklab so the programs survive exit
//
// Run as root in the host mount namespace (NOT under `ip netns exec`, which
// remounts /sys and would shadow the /sys/fs/bpf mount the pins live in). The
// loader switches only the *network* namespace internally:
//   ./netkitctl -obj netkit_lab.bpf.o -pin /sys/fs/bpf/nklab \
//     -node /var/run/netns/nklab-node \
//     -pod pod1=/var/run/netns/nklab-pod1 -pod pod2=...
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type podFlag map[string]string

func (p podFlag) String() string { return fmt.Sprintf("%v", map[string]string(p)) }
func (p podFlag) Set(v string) error {
	name, path, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("expected name=/path/to/netns, got %q", v)
	}
	p[name] = path
	return nil
}

func main() {
	objPath := flag.String("obj", "netkit_lab.bpf.o", "compiled BPF object")
	pinDir := flag.String("pin", "/sys/fs/bpf/nklab", "bpffs dir for link pins")
	nodePath := flag.String("node", "", "path to the node netns (/var/run/netns/<ns>)")
	pods := podFlag{}
	flag.Var(&pods, "pod", "pod as name=/var/run/netns/<ns> (repeatable)")
	flag.Parse()

	if *nodePath == "" {
		log.Fatal("need -node /var/run/netns/<ns>")
	}
	if len(pods) == 0 {
		log.Fatal("need at least one -pod name=/path/to/netns")
	}
	if err := run(*objPath, *pinDir, *nodePath, pods); err != nil {
		log.Fatalf("netkitctl: %v", err)
	}
}

func run(objPath, pinDir, nodePath string, pods podFlag) error {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return fmt.Errorf("mkdir pin dir: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load BPF object %s: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF programs into kernel: %w", err)
	}
	defer coll.Close()

	toPod := coll.Programs["nk_to_pod"]
	fromPod := coll.Programs["nk_from_pod"]
	if toPod == nil || fromPod == nil {
		return fmt.Errorf("object is missing nk_to_pod / nk_from_pod programs")
	}

	// Deterministic ordering so subnets are stable across runs.
	names := make([]string, 0, len(pods))
	for name := range pods {
		names = append(names, name)
	}
	sort.Strings(names)

	nodeNs, err := netns.GetFromPath(nodePath)
	if err != nil {
		return fmt.Errorf("open node netns %s: %w", nodePath, err)
	}
	defer nodeNs.Close()

	for i, name := range names {
		subnet := i + 1 // 10.244.<subnet>.0/24
		if err := wirePod(name, pods[name], subnet, nodeNs, toPod, fromPod, pinDir); err != nil {
			return fmt.Errorf("pod %s: %w", name, err)
		}
		log.Printf("pod %s: netkit pair up on 10.244.%d.0/24, programs attached + pinned", name, subnet)
	}
	return nil
}

func wirePod(
	name, nsPath string, subnet int,
	nodeNs netns.NsHandle,
	toPod, fromPod *ebpf.Program,
	pinDir string,
) error {
	podNs, err := netns.GetFromPath(nsPath)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", nsPath, err)
	}
	defer podNs.Close()

	primaryName := "nk-" + name

	// Node side: create the netkit pair (primary here, peer moved into the pod
	// netns), address the primary, and attach BOTH programs — all inside the
	// node netns. Both attachments target the PRIMARY ifindex: the kernel
	// routes BPF_NETKIT_PEER to the peer device itself and refuses (-EACCES)
	// link creation against the peer's own ifindex (netkit_dev_fetch: "only
	// the primary device can be used").
	if err := inNetns(nodeNs, func() error {
		nk := &netlink.Netkit{
			LinkAttrs:  netlink.LinkAttrs{Name: primaryName},
			Mode:       netlink.NETKIT_MODE_L3,
			Policy:     netlink.NETKIT_POLICY_FORWARD,
			PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
		}
		peer := netlink.LinkAttrs{Name: "eth0", Namespace: netlink.NsFd(int(podNs))}
		nk.SetPeerAttrs(&peer)
		if err := netlink.LinkAdd(nk); err != nil {
			return fmt.Errorf("create netkit pair: %w", err)
		}
		primary, err := netlink.LinkByName(primaryName)
		if err != nil {
			return fmt.Errorf("find primary %s: %w", primaryName, err)
		}
		if err := addrUp(primary, fmt.Sprintf("10.244.%d.1/24", subnet)); err != nil {
			return fmt.Errorf("address node side: %w", err)
		}
		primIdx := primary.Attrs().Index
		if err := attachAndPin(toPod, primIdx, ebpf.AttachNetkitPrimary,
			filepath.Join(pinDir, name+"-to_pod")); err != nil {
			return err
		}
		return attachAndPin(fromPod, primIdx, ebpf.AttachNetkitPeer,
			filepath.Join(pinDir, name+"-from_pod"))
	}); err != nil {
		return err
	}

	// Pod side: address + up + default route, inside the pod netns.
	if err := inNetns(podNs, func() error {
		peerLink, err := netlink.LinkByName("eth0")
		if err != nil {
			return fmt.Errorf("find peer eth0: %w", err)
		}
		if err := addrUp(peerLink, fmt.Sprintf("10.244.%d.2/24", subnet)); err != nil {
			return err
		}
		if lo, err := netlink.LinkByName("lo"); err == nil {
			_ = netlink.LinkSetUp(lo)
		}
		gw := net.ParseIP(fmt.Sprintf("10.244.%d.1", subnet))
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: peerLink.Attrs().Index,
			Dst:       nil, // default route
			Gw:        gw,
		}); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("configure pod side: %w", err)
	}
	return nil
}

func attachAndPin(prog *ebpf.Program, ifindex int, attach ebpf.AttachType, pinPath string) error {
	_ = os.Remove(pinPath) // replace a stale pin from a previous run
	l, err := link.AttachNetkit(link.NetkitOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attach,
	})
	if err != nil {
		return fmt.Errorf("AttachNetkit(ifindex=%d): %w", ifindex, err)
	}
	if err := l.Pin(pinPath); err != nil {
		l.Close()
		return fmt.Errorf("pin link at %s: %w", pinPath, err)
	}
	return nil
}

func addrUp(l netlink.Link, cidr string) error {
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(l, addr); err != nil {
		return fmt.Errorf("add addr %s: %w", cidr, err)
	}
	return netlink.LinkSetUp(l)
}

// inNetns runs fn with the calling OS thread switched into ns, restoring the
// original namespace afterwards. The thread is locked so the switch is safe.
func inNetns(ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("enter netns: %w", err)
	}
	defer netns.Set(orig)
	return fn()
}

