//go:build linux

package desktopnetwork

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

var networkNativePeer struct {
	command   *exec.Cmd
	namespace string
}

func networkNativeStartPeer(t *testing.T) {
	t.Helper()
	command := exec.Command("/usr/bin/unshare", "--net", "/usr/bin/sleep", "40")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait(); networkNativePeer.command = nil })
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		peer, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))
		if err == nil && peer != current && peer != os.Getenv("ROUTERVPN_NETWORK_PARENT_NAMESPACE") {
			networkNativePeer.command, networkNativePeer.namespace = command, peer
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fixture peer did not enter its own independently isolated namespace")
}

func networkNativeIP(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("isolated network fixture ip %v: %v: %s", args, err, output)
	}
}

func networkNativeIsolation(t *testing.T) {
	t.Helper()
	if os.Getenv("ROUTERVPN_NATIVE_NETWORK_EVENTS") != "1" {
		t.Skip("requires explicit native network event gate")
	}
	parent := os.Getenv("ROUTERVPN_NETWORK_PARENT_NAMESPACE")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || parent == "" || current == parent || os.Geteuid() != 0 {
		t.Fatal("native network mutation requires an independently isolated owned namespace", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Name != "lo" {
			t.Fatal("fresh fixture namespace contains an unowned interface", iface.Name)
		}
	}
}

func networkNativeLink(t *testing.T, name, address string, mtu int) int {
	t.Helper()
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatal("fixture refused an existing interface name")
	}
	peer := networkNativePeer.command
	if peer == nil || peer.Process == nil {
		t.Fatal("fixture has no original isolated peer process")
	}
	peerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", peer.Process.Pid))
	if err != nil || peerNS != networkNativePeer.namespace {
		t.Fatal("fixture peer namespace was replaced", err)
	}
	hash := sha256.Sum256([]byte(name))
	peerName := fmt.Sprintf("rvpnp%x", hash[:4])
	networkNativeIP(t, "link", "add", "dev", name, "type", "veth", "peer", "name", peerName, "netns", strconv.Itoa(peer.Process.Pid))
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	index := iface.Index
	t.Cleanup(func() {
		current, err := net.InterfaceByName(name)
		if err != nil {
			return
		}
		if current.Index != index {
			t.Error("fixture preserves a replacement interface")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, "/usr/sbin/ip", "link", "delete", "dev", name).CombinedOutput(); err != nil {
			t.Errorf("owned namespace cleanup: %v %s", err, output)
		}
	})
	networkNativeIP(t, "link", "set", "dev", name, "addrgenmode", "none")
	networkNativeIP(t, "link", "set", "dev", name, "mtu", fmt.Sprint(mtu))
	if address != "" {
		networkNativeIP(t, "address", "add", address, "dev", name)
	}
	networkNativeIP(t, "link", "set", "dev", name, "up")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net="+fmt.Sprintf("/proc/%d/ns/net", peer.Process.Pid), "/usr/sbin/ip", "link", "set", "dev", peerName, "up").CombinedOutput()
	if err != nil {
		t.Fatalf("owned peer link startup: %v %s", err, output)
	}
	return index
}

func networkNativeOwner(t *testing.T, ctx context.Context) (*Tracker, *linuxObserver) {
	t.Helper()
	owner, err := Open(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	native, ok := owner.native.(*linuxObserver)
	if !ok {
		t.Fatal("fixture did not install the shipping Linux observer")
	}
	return owner, native
}

// This is an explicit component boundary: the fixture supplies a receipt for
// its own newly-created veth interface/routing calls. It proves the shipping
// observer against real kernel events, not the native VPN factory or TUN proof.
// The generated native TUN gate separately checks the real factory projection.
func networkNativeFixtureReceipt(t *testing.T, ctx context.Context, native *linuxObserver, index int) DesktopNetworkReceipt {
	t.Helper()
	snapshot, err := native.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := DesktopNetworkReceipt{Schema: 1, TargetOS: "linux", Incarnation: strings.Repeat("d", 32), Index: uint32(index)}
	for _, link := range snapshot.Links {
		if link.Index == r.Index {
			r.Name, r.MTU = link.Name, link.MTU
		}
	}
	for _, address := range snapshot.Addresses {
		if address.Index == r.Index {
			r.Addresses = append(r.Addresses, address.Prefix)
		}
	}
	for _, object := range snapshot.Objects {
		if object.Index == r.Index || object.Kind == "rule" && object.Table == 2022 && object.Priority == 11000 {
			r.Objects = append(r.Objects, object)
		}
	}
	SortDesktopNetworkObjects(r.Objects)
	if r.Validate() != nil {
		t.Fatal("fixture failed to capture its exact actual kernel objects")
	}
	return r
}

func TestLinuxNativeNetworkCohortEvents(t *testing.T) {
	networkNativeIsolation(t)
	networkNativeStartPeer(t)
	networkNativeLink(t, "rvpn-physical", "192.0.2.2/24", 1500)
	networkNativeIP(t, "route", "add", "default", "via", "192.0.2.1", "dev", "rvpn-physical")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t.Run("ipv6-rule-away-and-back", func(t *testing.T) {
		networkNativeIPv6RuleObserver(t, ctx)
	})
	t.Run("joined-original-routing-absence", func(t *testing.T) {
		o, native := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		index := networkNativeLink(t, "rvpn-retire", "10.10.0.2/24", 1376)
		networkNativeIP(t, "route", "add", "table", "2022", "default", "dev", "rvpn-retire")
		networkNativeIP(t, "rule", "add", "priority", "11000", "lookup", "2022")
		created := networkNativeFixtureReceipt(t, ctx, native, index)
		if err := o.End(ctx, &created); err != nil {
			t.Fatal(err)
		}
		retired := DesktopNetworkRetirementReceipt{Schema: 1, TargetOS: "linux", Created: true, Incarnation: created.Incarnation, Name: created.Name, Index: created.Index, Objects: created.Objects}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		if err := o.RoutingAbsent(ctx, &retired); err == nil {
			t.Fatal("original native interface fabricated cleanup absence")
		}
		networkNativeIP(t, "link", "delete", "dev", "rvpn-retire")
		if err := o.RoutingAbsent(ctx, &retired); err == nil {
			t.Fatal("original native rule survived joined-interface absence")
		}
		networkNativeIP(t, "rule", "delete", "priority", "11000", "lookup", "2022")
		if err := o.RoutingAbsent(ctx, &retired); err != nil {
			t.Fatal("actual original route/rule cleanup", err)
		}
		networkNativeIP(t, "route", "add", "203.0.113.0/24", "via", "192.0.2.1", "dev", "rvpn-physical")
		if err := o.RoutingAbsent(ctx, &retired); err != nil {
			t.Fatal("disjoint foreign route stranded original native cleanup", err)
		}
		foreign, err := native.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, object := range foreign.Objects {
			found = found || object.Kind == "route" && object.Destination == "203.0.113.0/24"
		}
		if !found {
			t.Fatal("retirement altered a disjoint foreign route")
		}
		networkNativeIP(t, "route", "delete", "203.0.113.0/24", "via", "192.0.2.1", "dev", "rvpn-physical")
		if err := o.RoutingAbsent(ctx, &retired); err != nil {
			t.Fatal("original inventory was not restored", err)
		}
		if err := o.Current(); err == nil {
			t.Fatal("retirement readback restarted original epoch")
		}
	})

	t.Run("unchanged-physical-owner", func(t *testing.T) {
		o, _ := networkNativeOwner(t, ctx)
		if err := o.Current(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("gateway-away-and-back", func(t *testing.T) {
		o, _ := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		networkNativeIP(t, "route", "replace", "default", "via", "192.0.2.99", "dev", "rvpn-physical")
		networkNativeIP(t, "route", "replace", "default", "via", "192.0.2.1", "dev", "rvpn-physical")
		if err := o.End(ctx, nil); err == nil {
			t.Fatal("actual default gateway away/back was absorbed")
		}
		if err := o.Current(); err == nil {
			t.Fatal("physical gateway restoration cleared the latch")
		}
	})
	t.Run("address-away-and-back", func(t *testing.T) {
		o, _ := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		networkNativeIP(t, "address", "add", "192.0.2.3/24", "dev", "rvpn-physical")
		networkNativeIP(t, "address", "delete", "192.0.2.3/24", "dev", "rvpn-physical")
		if err := o.End(ctx, nil); err == nil {
			t.Fatal("actual address away/back was absorbed")
		}
	})
	t.Run("mtu-away-and-back", func(t *testing.T) {
		o, _ := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		networkNativeIP(t, "link", "set", "dev", "rvpn-physical", "mtu", "1400")
		networkNativeIP(t, "link", "set", "dev", "rvpn-physical", "mtu", "1500")
		if err := o.End(ctx, nil); err == nil {
			t.Fatal("actual link MTU away/back was absorbed")
		}
	})
	t.Run("unclaimed-virtual-start-and-stop", func(t *testing.T) {
		o, _ := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		networkNativeLink(t, "rvpn-unknown", "10.9.0.2/24", 1376)
		networkNativeIP(t, "link", "delete", "dev", "rvpn-unknown")
		if err := o.End(ctx, nil); err == nil {
			t.Fatal("unclaimed virtual route effects were hidden by final absence")
		}
	})
	t.Run("owned-interface-route-rule-and-drain", func(t *testing.T) {
		o, native := networkNativeOwner(t, ctx)
		identity := o.Identity()
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		index := networkNativeLink(t, "rvpn-trial", "10.8.0.2/24", 1376)
		networkNativeIP(t, "route", "add", "table", "2022", "default", "dev", "rvpn-trial")
		networkNativeIP(t, "rule", "add", "priority", "11000", "lookup", "2022")
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = exec.CommandContext(ctx, "/usr/sbin/ip", "rule", "delete", "priority", "11000", "lookup", "2022").Run()
		})
		r := networkNativeFixtureReceipt(t, ctx, native, index)
		if err := o.End(ctx, &r); err != nil {
			o.mu.Lock()
			for _, event := range o.events {
				if !eventOwnedBy(event, &r) {
					t.Logf("unclaimed actual startup event: %#v; captured objects: %#v", event, r.Objects)
				}
			}
			o.mu.Unlock()
			t.Fatal("actual captured owned startup events failed", err)
		}
		if err := o.Current(); err != nil {
			t.Fatal(err)
		}
		if err := o.Begin(ctx, &r); err != nil {
			t.Fatal(err)
		}
		networkNativeIP(t, "rule", "delete", "priority", "11000", "lookup", "2022")
		networkNativeIP(t, "link", "delete", "dev", "rvpn-trial")
		if err := o.End(ctx, nil); err != nil {
			t.Fatal("actual captured owned teardown events failed", err)
		}
		if o.Identity() != identity || o.Current() != nil {
			t.Fatal("owned routing effects rebased the physical identity")
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-native.joined:
		default:
			t.Fatal("native callback reader was not joined")
		}
		raw, err := native.file.SyscallConn()
		if err == nil {
			err = raw.Control(func(uintptr) { t.Error("closed observer exposed its old native descriptor") })
		}
		if err == nil {
			t.Fatal("closed observer retained its original native socket", err)
		}
	})
	t.Run("foreign-rule-without-interface-key", func(t *testing.T) {
		o, _ := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		networkNativeIP(t, "rule", "add", "priority", "11000", "lookup", "2023")
		networkNativeIP(t, "rule", "delete", "priority", "11000", "lookup", "2023")
		if err := o.End(ctx, nil); err == nil {
			t.Fatal("same-priority unknown rule had no score-disqualifying event")
		}
	})
	t.Run("proved-transient-closes-before-final-off", func(t *testing.T) {
		o, native := networkNativeOwner(t, ctx)
		if err := o.Begin(ctx, nil); err != nil {
			t.Fatal(err)
		}
		index := networkNativeLink(t, "rvpn-transient", "10.7.0.2/24", 1376)
		r := networkNativeFixtureReceipt(t, ctx, native, index)
		if err := o.Record(r); err != nil {
			t.Fatal(err)
		}
		networkNativeIP(t, "link", "delete", "dev", "rvpn-transient")
		if err := o.End(ctx, nil); err != nil {
			o.mu.Lock()
			for _, event := range o.events {
				if !eventOwnedBy(event, &r) {
					t.Logf("unclaimed actual transient event: %#v; captured objects: %#v", event, r.Objects)
				}
			}
			o.mu.Unlock()
			t.Fatal("captured transient could not classify its actual joined kernel effects", err)
		}
	})
}
