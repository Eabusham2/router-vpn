//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func bootstrapGroupReceiptFixture(t *testing.T) (*DesktopLinuxBootstrapDNSGroup, *desktopLinuxBootstrapGrant) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "original-netlink-capability")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	n := &desktopLinuxBaselineNetlink{file: file, port: 72, seq: 200}
	grant := bootstrapGrantWireFixture(t)
	grant.owner, grant.file, grant.port, grant.sent = n, file, 72, true
	g := &DesktopLinuxBootstrapDNSGroup{owner: &DesktopLinuxStandardProtection{baseline: &DesktopLinuxNodeBaseline{netlink: n}}, generation: 91, acknowledged: map[*desktopLinuxBootstrapGrant]bool{}}
	return g, grant
}
func TestLinuxStandardBootstrapGroupOriginalGeneration(t *testing.T) {
	for _, fault := range []string{"original", "partial", "wrong-owner", "foreign-generation", "rejected", "unsent"} {
		t.Run(fault, func(t *testing.T) {
			g, grant := bootstrapGroupReceiptFixture(t)
			messages := bootstrapGrantEchoes(t, grant)
			if fault == "partial" {
				messages = messages[:1]
			}
			for _, raw := range messages {
				if err := grant.datagram(raw, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}, 0, 72); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "wrong-owner":
				copy := *grant.owner
				grant.owner = &copy
			case "foreign-generation":
				g.generation++
			case "rejected":
				grant.rejected = true
			case "unsent":
				grant.sent = false
			}
			before := g.generation
			err := g.acknowledge(grant)
			if fault != "original" {
				if err == nil || g.generation != before {
					t.Fatal("unowned/uncertain generation adopted", fault, err)
				}
				return
			}
			if err != nil || g.generation != 92 {
				t.Fatal("original creation did not advance once", err)
			}
			if err = g.acknowledge(grant); err != nil || g.generation != 92 {
				t.Fatal("receipt observation renewed generation", err)
			}
			removal, err := grant.owner.newBootstrapRemoval(92, grant)
			if err != nil {
				t.Fatal(err)
			}
			last := removal.requests[len(removal.requests)-1]
			ack := make([]byte, 36)
			binary.NativeEndian.PutUint32(ack, 36)
			binary.NativeEndian.PutUint16(ack[4:], syscall.NLMSG_ERROR)
			copy(ack[8:16], last[8:16])
			copy(ack[20:], last[:16])
			removal.sent = true
			if err = removal.datagram(ack, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}, 0, 72); err != nil {
				t.Fatal(err)
			}
			if err = g.acknowledge(removal); err != nil || g.generation != 93 {
				t.Fatal("original exact retirement did not advance once", err)
			}
		})
	}
}
func TestLinuxStandardBootstrapGroupCapacity(t *testing.T) {
	g := &DesktopLinuxBootstrapDNSGroup{initialDescriptors: 32, inventoryBytes: 16 << 10}
	// Full captured cohort fits when the actual process provides sufficient FDs.
	for i := 0; i < 257; i++ {
		if err := g.capacityFor(32+2*i, 4096); err != nil {
			t.Fatal("complete scope cohort lost", i, err)
		}
		g.members = append(g.members, nil)
		g.active++
		g.inventoryBytes += desktopLinuxBootstrapGroupGrantBytes
	}
	if err := g.capacityFor(546, 4096); err == nil {
		t.Fatal("active cohort bound ignored")
	}
	g.active = 0
	if err := g.capacityFor(546, 1024); err != nil {
		t.Fatal("retained cohort exhausted unexpectedly", err)
	}
	g.initialDescriptors = 1000
	if err := g.capacityFor(32, 1024); err == nil {
		t.Fatal("unopened admitted descriptor reservations ignored")
	}
	g.initialDescriptors = 0
	g.inventoryBytes = desktopLinuxBootstrapGroupInventory - desktopLinuxBootstrapGroupGrantBytes + 1
	if err := g.capacityFor(32, 4096); err == nil {
		t.Fatal("full native inventory can exceed nft bound")
	}
}
func TestLinuxStandardBootstrapGroupInventory(t *testing.T) {
	b, first, rows, _, echo := bootstrapNativeFixture(t)
	var packet map[string]any
	if err := json.Unmarshal(echo, &packet); err != nil {
		t.Fatal(err)
	}
	rule := packet["nftables"].([]any)[0].(map[string]any)["add"].(map[string]any)["rule"].(map[string]any)
	first.grant = bootstrapGrantWireFixture(t)
	first.grant.ruleHandle = first.handle
	first.grant.setHandle = 80
	first.mark = 0x92345678
	second := *first
	copyGrant := *first.grant
	second.grant = &copyGrant
	second.handle = first.handle + 100
	second.grant.ruleHandle = second.handle
	second.grant.setHandle = 180
	second.grant.set = "rvb_1123456789abcdef01"
	full := append([]map[string]any{}, rows...)
	for _, member := range []*desktopLinuxStandardBootstrap{first, &second} {
		raw, _ := json.Marshal(rule)
		var owned map[string]any
		_ = json.Unmarshal(raw, &owned)
		owned["handle"] = float64(member.handle)
		set := map[string]any{"family": "inet", "table": b.nft.table(), "name": member.grant.set, "handle": float64(member.grant.setHandle), "type": "mark", "flags": []any{"timeout"}, "timeout": float64(1)}
		full = append(full, map[string]any{"rule": owned}, map[string]any{"set": set})
	}
	g := &DesktopLinuxBootstrapDNSGroup{members: []*desktopLinuxStandardBootstrap{first, &second}}
	if err := g.inventory(b, full); err != nil {
		t.Fatal("two expired but owned grants rejected", err)
	}
	for _, fault := range []string{"extra-rule", "missing-set", "duplicate-rule", "retired-reappears"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(full)
			var changed []map[string]any
			_ = json.Unmarshal(raw, &changed)
			switch fault {
			case "extra-rule":
				changed = append(changed, map[string]any{"rule": map[string]any{"handle": float64(999)}})
			case "missing-set":
				changed = changed[:len(changed)-1]
			case "duplicate-rule":
				changed = append(changed, changed[len(changed)-2])
			case "retired-reappears":
				second.retired = true
				defer func() { second.retired = false }()
			}
			if err := g.inventory(b, changed); err == nil {
				t.Fatal("foreign/unpaired inventory adopted", fault)
			}
		})
	}
}
func TestLinuxStandardBootstrapGroupRejectsDetachedCapability(t *testing.T) {
	var empty DesktopLinuxBootstrapDNSGroup
	if _, err := empty.Exchange(context.Background(), DesktopLinuxBootstrapDNSUpstream{}, nil); err == nil {
		t.Fatal("empty group exchanged")
	}
	if err := empty.Close(context.Background()); err == nil {
		t.Fatal("empty group closed as owner")
	}
	// Filter refactor must not mutate caller's retained full baseline inventory.
	b, p, rows, _, _ := bootstrapNativeFixture(t)
	before, _ := json.Marshal(rows)
	_, _, _ = p.filterInventory(b, rows)
	after, _ := json.Marshal(rows)
	if !bytes.Equal(before, after) {
		t.Fatal("inventory filter rewrote original observation")
	}
}

func TestLinuxStandardBootstrapGroupFailedJoinRetainsOwner(t *testing.T) {
	original, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &DesktopLinuxStandardProtection{baseline: &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: "bootstrap"}}
	g := &DesktopLinuxBootstrapDNSGroup{owner: p, ctx: original, cancel: cancel, reserved: true}
	p.bootstrap = &desktopLinuxStandardBootstrap{group: g}
	p.bootstrapGroup.Store(g)
	// A real held worker has seen cancellation but has not joined yet. Cleanup
	// cannot release the original reservation merely because the caller timed out.
	release := make(chan struct{})
	seen := make(chan struct{})
	g.wg.Add(1)
	go func() { defer g.wg.Done(); <-original.Done(); close(seen); <-release }()
	cleanup, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	err := g.Close(cleanup)
	if !errors.Is(err, context.DeadlineExceeded) || p.bootstrapGroup.Load() != g || p.bootstrap == nil || !g.reserved || len(p.baseline.gate) != 0 {
		t.Error("failed join released original reservation", err)
	}
	<-seen
	close(release)
	<-g.joined
	if g.closed || p.bootstrapGroup.Load() != g {
		t.Fatal("joining IO alone discarded unproved original cleanup")
	}
}

func TestLinuxStandardBootstrapGroupNativeInventoryBudget(t *testing.T) {
	route := desktopLinuxBootstrapRoute{Interface: net.Interface{Name: "abcdefghijklmno", Index: 2147483647}, Address: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")}
	source := netip.AddrPortFrom(route.Address, 65535)
	remote := netip.MustParseAddrPort("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
	expressions := desktopLinuxBootstrapExpressions(route, source, remote, ^uint32(0), "tcp")
	expressions = append(expressions, map[string]any{"match": map[string]any{"op": "in", "left": map[string]any{"meta": map[string]any{"key": "mark"}}, "right": "@rvb_ffffffffffffffffff"}})
	rows := []any{
		map[string]any{"rule": map[string]any{"family": "inet", "table": "router_vpn_standard_ffffffffffffffffffffffffffffffff", "chain": "output", "handle": uint64(1<<53 - 1), "expr": expressions}},
		map[string]any{"set": map[string]any{"family": "inet", "table": "router_vpn_standard_ffffffffffffffffffffffffffffffff", "name": "rvb_ffffffffffffffffff", "handle": uint64(1<<53 - 1), "type": "mark", "flags": []string{"timeout"}, "timeout": 2, "elem": []any{map[string]any{"elem": map[string]any{"val": uint64(1<<32 - 1), "timeout": 2, "expires": 2}}}}},
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	// nft json_dumpf flags=0 inserts at most one separator space per compact
	// punctuation byte. Double compact size also covers the wrapper separators.
	if len(raw)*2 > desktopLinuxBootstrapGroupGrantBytes {
		t.Fatal("group permits more native inventory than reserved", len(raw)*2)
	}
}
