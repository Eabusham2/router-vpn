//go:build linux

package mobiletor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func bootstrapGrantWireFixture(t *testing.T) *desktopLinuxBootstrapGrant {
	t.Helper()
	route := desktopLinuxBootstrapRoute{Interface: net.Interface{Name: "eth0", Index: 2}, Address: netip.MustParseAddr("192.0.2.2")}
	rule, err := desktopLinuxBootstrapRuleWire(route, netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("192.0.2.53:53"), 0x92345678, "udp", "rvb_0123456789abcdef01")
	if err != nil {
		t.Fatal(err)
	}
	requests, err := desktopLinuxBootstrapCreateRequests(91, linuxBootstrapTransactionTable(), "rvb_0123456789abcdef01", rule, 0x92345678, time.Second, 100, 72)
	if err != nil {
		t.Fatal(err)
	}
	return &desktopLinuxBootstrapGrant{requests: requests, table: linuxBootstrapTransactionTable(), set: "rvb_0123456789abcdef01", duration: time.Second}
}
func bootstrapGrantEchoes(t *testing.T, g *desktopLinuxBootstrapGrant) [][]byte {
	t.Helper()
	set, _ := desktopLinuxBootstrapAttributeMap(g.requests[1][20:], 0)
	sa := bootstrapAttrs(bootstrapString(1, g.table), bootstrapString(2, g.set), bootstrapU32(3, 0x10), bootstrapU32(4, 19), bootstrapU32(5, 4), bootstrapU64(11, uint64(g.duration/time.Millisecond)), bootstrapU64(16, 80), bootstrapNest(9))
	if !bytes.Equal(set[11], bootstrapBE64(uint64(g.duration/time.Millisecond))) {
		t.Fatal("fixture timer lost request")
	}
	rule, _ := desktopLinuxBootstrapAttributeMap(g.requests[3][20:], 0)
	ra := bootstrapAttrs(bootstrapString(1, g.table), bootstrapString(2, "output"), bootstrapU64(3, 81), bootstrapAttr(4, rule[4]))
	last := g.requests[4]
	ack := make([]byte, 36)
	binary.NativeEndian.PutUint32(ack, 36)
	binary.NativeEndian.PutUint16(ack[4:], syscall.NLMSG_ERROR)
	copy(ack[8:16], last[8:16])
	copy(ack[20:], last[:16])
	return [][]byte{desktopLinuxBaselineMessage(desktopLinuxNFTNewSet, 0, 101, 72, 1, 92, sa), desktopLinuxBaselineMessage(desktopLinuxNFTNewRule, 0, 103, 72, 1, 92, ra), ack}
}
func TestLinuxStandardBootstrapGrantKernelBoundWire(t *testing.T) {
	g := bootstrapGrantWireFixture(t)
	if len(g.requests) != 5 {
		t.Fatal("creation was not one atomic set/element/rule batch")
	}
	for i, r := range g.requests {
		if binary.NativeEndian.Uint32(r[8:]) != uint32(100+i) || binary.NativeEndian.Uint32(r[12:]) != 72 {
			t.Fatal("lost original sequence/port")
		}
	}
	element, _ := desktopLinuxBootstrapAttributeMap(g.requests[2][20:], 0)
	list, _ := desktopLinuxBootstrapAttributes(element[3])
	fields, _ := desktopLinuxBootstrapAttributeMap(list[0].value, 0)
	if !bytes.Equal(fields[4], bootstrapBE64(1000)) {
		t.Fatal("kernel element has no finite original timeout")
	}
	rule, _ := desktopLinuxBootstrapAttributeMap(g.requests[3][20:], 0)
	shape, err := desktopLinuxBootstrapExpressionShape(rule[4])
	if err != nil {
		t.Fatal(err)
	}
	lookup := 0
	for _, v := range shape {
		name := v.([]any)[0].(string)
		if name == "lookup" {
			lookup++
		}
		if name == "dynset" {
			t.Fatal("traffic renews original expiry")
		}
	}
	if lookup != 1 || shape[len(shape)-1].([]any)[0] != "immediate" {
		t.Fatal("accept lost mandatory expiring membership")
	}
	for _, remaining := range []time.Duration{40 * time.Millisecond, time.Second, 4 * time.Second, time.Hour} {
		d, err := desktopLinuxBootstrapPermitDuration(remaining)
		if err != nil || d > remaining/2 || d > desktopLinuxBootstrapMaxPermit || d%(20*time.Millisecond) != 0 {
			t.Fatal("permit renewed or exceeded original bound", d, err)
		}
	}
	for _, remaining := range []time.Duration{-1, 0, 39 * time.Millisecond} {
		if _, err := desktopLinuxBootstrapPermitDuration(remaining); err == nil {
			t.Fatal("unbounded/expired operation admitted")
		}
	}
}
func TestLinuxStandardBootstrapGrantRequiresOriginalEchoAndCommit(t *testing.T) {
	kernel := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	for _, order := range [][]int{{0, 1, 2}, {2, 0, 1}, {1, 2, 0}} {
		g := bootstrapGrantWireFixture(t)
		messages := bootstrapGrantEchoes(t, g)
		for i, index := range order {
			if err := g.datagram(messages[index], kernel, 0, 72); err != nil {
				t.Fatal(err)
			}
			if g.complete() != (i == 2) {
				t.Fatal("partial receipt became committed ownership")
			}
		}
		if g.ruleHandle != 81 || g.setHandle != 80 {
			t.Fatal("echo lost original handles")
		}
	}
	for _, fault := range []string{"sequence", "port", "userspace", "truncated", "extra", "timeout", "set-name", "rule-scope", "early-ack", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			g := bootstrapGrantWireFixture(t)
			m := bootstrapGrantEchoes(t, g)
			source := syscall.Sockaddr(kernel)
			data := bytes.Clone(m[0])
			switch fault {
			case "sequence":
				binary.NativeEndian.PutUint32(data[8:], 1001)
			case "port":
				binary.NativeEndian.PutUint32(data[12:], 73)
			case "userspace":
				source = &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: 55}
			case "truncated":
				data = data[:len(data)-1]
			case "extra":
				data = append(data, 1)
			case "timeout":
				data = bytes.Replace(data, bootstrapU64(11, 1000), bootstrapU64(11, 2000), 1)
			case "set-name":
				data = bytes.Replace(data, []byte(g.set), []byte("rvb_1123456789abcdef01"), 1)
			case "rule-scope":
				data = bytes.Replace(m[1], bootstrapNative32(0x92345678), bootstrapNative32(0x92345679), 1)
			case "early-ack":
				data = bytes.Clone(m[2])
				copy(data[8:16], g.requests[1][8:16])
				copy(data[20:], g.requests[1][:16])
			case "duplicate":
				if err := g.datagram(data, source, 0, 72); err != nil {
					t.Fatal(err)
				}
			}
			if err := g.datagram(data, source, 0, 72); err == nil {
				t.Fatal("changed native receipt acquired authority", fault)
			}
			if g.complete() {
				t.Fatal("invalid receipt completed grant")
			}
		})
	}
}
func TestLinuxStandardBootstrapGrantPartialRecoveryKeepsSameRequests(t *testing.T) {
	g := bootstrapGrantWireFixture(t)
	messages := bootstrapGrantEchoes(t, g)
	original := bytes.Join(g.requests, nil)
	kernel := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := g.datagram(messages[0], kernel, 0, 72); err != nil {
		t.Fatal(err)
	}
	if g.complete() || g.ruleHandle != 0 || g.setHandle != 80 {
		t.Fatal("lost original partial echo")
	}
	// A canceled observer does not fabricate a second transaction. Later queued
	// replies complete the same receipt object, without invoking a sender.
	if err := g.datagram(append(messages[1], messages[2]...), kernel, 0, 72); err != nil {
		t.Fatal(err)
	}
	if !g.complete() || !bytes.Equal(original, bytes.Join(g.requests, nil)) {
		t.Fatal("recovery renewed original permit")
	}
	deletion, err := desktopLinuxBootstrapDeleteGrantRequests(92, g.table, g.ruleHandle, g.setHandle, 200, 72)
	if err != nil {
		t.Fatal(err)
	}
	rule, _ := desktopLinuxBootstrapAttributeMap(deletion[1][20:], 0)
	set, _ := desktopLinuxBootstrapAttributeMap(deletion[2][20:], 0)
	if len(set) != 2 || set[2] != nil || !bytes.Equal(rule[3], bootstrapBE64(81)) || !bytes.Equal(set[16], bootstrapBE64(80)) {
		t.Fatal("cleanup adopted by name instead of both exact handles")
	}
}

func TestLinuxStandardBootstrapGrantKeepsOriginalEndpoint(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "retained-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	otherFile, err := os.CreateTemp(t.TempDir(), "replacement-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer otherFile.Close()
	original := &desktopLinuxBaselineNetlink{file: file, port: 72, seq: 200}
	g := bootstrapGrantWireFixture(t)
	g.owner, g.file, g.port = original, file, 72
	kernel := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	for _, m := range bootstrapGrantEchoes(t, g) {
		if err := g.datagram(m, kernel, 0, 72); err != nil {
			t.Fatal(err)
		}
	}
	for _, replacement := range []*desktopLinuxBaselineNetlink{{file: file, port: 72}, {file: otherFile, port: 72}, {file: file, port: 73}} {
		if err := replacement.bootstrapExchange(context.Background(), g); err == nil {
			t.Fatal("complete receipt adopted by replacement endpoint")
		}
		if _, err := replacement.newBootstrapRemoval(92, g); err == nil {
			t.Fatal("replacement endpoint acquired original handles")
		}
		if err := replacement.observeBootstrapGrant(context.Background(), g); err == nil {
			t.Fatal("replacement endpoint observed as original authority")
		}
	}
	original.file = otherFile
	if err := original.bootstrapExchange(context.Background(), g); err == nil {
		t.Fatal("retained pointer adopted a reopened descriptor")
	}
	original.file = file
	removal, err := original.newBootstrapRemoval(92, g)
	if err != nil || !removal.owns(original) {
		t.Fatal("original removal lost endpoint capability", err)
	}
	if err := original.bootstrapExchange(context.Background(), g); err != nil {
		t.Fatal("original complete receipt lost safe retry", err)
	}
}

func TestLinuxStandardBootstrapGrantInventoryKeepsExpiredObjectsOwned(t *testing.T) {
	b, p, rows, _, echo := bootstrapNativeFixture(t)
	var packet map[string]any
	if err := json.Unmarshal(echo, &packet); err != nil {
		t.Fatal(err)
	}
	rule := packet["nftables"].([]any)[0].(map[string]any)["add"].(map[string]any)["rule"].(map[string]any)
	p.grant = bootstrapGrantWireFixture(t)
	p.grant.ruleHandle = p.handle
	p.grant.setHandle = 80
	p.mark = 0x92345678
	set := map[string]any{"family": "inet", "table": b.nft.table(), "name": p.grant.set, "handle": float64(80), "type": "mark", "flags": []any{"timeout"}, "timeout": float64(1), "elem": []any{map[string]any{"elem": map[string]any{"val": float64(p.mark), "timeout": float64(1), "expires": float64(1)}}}}
	original := append(append([]map[string]any{}, rows...), map[string]any{"rule": rule}, map[string]any{"set": set})
	if present, err := p.inventory(b, original); err != nil || !present || !p.grantLive {
		t.Fatal("original complete finite inventory", present, err)
	}
	set["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["expires"] = float64(0)
	if _, err := p.inventory(b, original); err != nil || !p.grantLive {
		t.Fatal("decreasing expiry was compared byte-for-byte", err)
	}
	delete(set, "elem")
	if present, err := p.inventory(b, original); err != nil || !present || p.grantLive {
		t.Fatal("expired membership discarded still-owned kernel objects", present, err)
	}
	for _, fault := range []string{"set-replaced", "extra-element", "renewed-timeout", "unpaired-rule", "unpaired-set", "survived-retirement"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var changed []map[string]any
			_ = json.Unmarshal(raw, &changed)
			pending := *p
			actual := changed[len(changed)-1]["set"].(map[string]any)
			switch fault {
			case "set-replaced":
				actual["handle"] = float64(82)
			case "extra-element":
				actual["elem"] = []any{float64(p.mark), float64(p.mark + 1)}
			case "renewed-timeout":
				actual["timeout"] = float64(2)
			case "unpaired-rule":
				changed = append(changed[:len(changed)-2], changed[len(changed)-1])
			case "unpaired-set":
				changed = changed[:len(changed)-1]
			case "survived-retirement":
				pending.retired = true
			}
			if _, err := pending.inventory(b, changed); err == nil {
				t.Fatal("foreign or residual grant inventory became baseline", fault)
			}
		})
	}
	p.retired = true
	if present, err := p.inventory(b, rows); err != nil || present || p.grantLive {
		t.Fatal("exact paired absence did not restore original baseline", present, err)
	}
}

func TestLinuxStandardBootstrapGrantDeadlineDoesNotRenew(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "original-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	n := &desktopLinuxBaselineNetlink{file: file, port: 72}
	g := bootstrapGrantWireFixture(t)
	g.owner, g.file, g.port = n, file, 72
	g.originalDeadline = time.Now().Add(-time.Second)
	before := bytes.Join(g.requests, nil)
	originalDuration := g.duration
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err = n.bootstrapExchange(canceled, g); err == nil || g.sent || n.bootstrap != nil {
		t.Fatal("expired/canceled caller sent a new original transaction", err)
	}
	if !bytes.Equal(before, bytes.Join(g.requests, nil)) || g.duration != originalDuration {
		t.Fatal("retry recomputed relative expiry")
	}
	// A sent pending operation cannot be replaced even by its own endpoint.
	g.sent = true
	n.bootstrap = g
	if _, err = n.newBootstrapGrant(91, g.table, g.set, g.requests[3][20:], 0x92345678, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("pending original transaction created a renewed grant")
	}
	if !bytes.Equal(before, bytes.Join(g.requests, nil)) || g.duration != originalDuration {
		t.Fatal("pending refusal changed frozen timeout")
	}
}

func TestLinuxStandardBootstrapGrantSequenceReservationNeverReuses(t *testing.T) {
	for _, outcome := range []string{"unsent", "rejected", "committed"} {
		t.Run(outcome, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "original-endpoint")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			n := &desktopLinuxBaselineNetlink{file: file, port: 72, seq: 1000}
			fixture := bootstrapGrantWireFixture(t)
			attrs, _ := desktopLinuxBootstrapAttributeMap(fixture.requests[3][20:], 0)
			grant, err := n.newBootstrapGrant(91, fixture.table, fixture.set, bootstrapAttr(4, attrs[4]), 0x92345678, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			check := func(requests [][]byte) {
				t.Helper()
				last := binary.NativeEndian.Uint32(requests[len(requests)-1][8:12])
				if n.seq < last {
					t.Fatal("reservation ended before original batch")
				}
				next, err := n.nextSequence()
				if err != nil || next <= last {
					t.Fatal("fresh read reused original mutation sequence", next, last, err)
				}
			}
			switch outcome {
			case "rejected":
				grant.sent = true
				grant.rejected = true
			case "committed":
				grant.sent = true
				grant.committed = true
				grant.ruleHandle = 81
				grant.setHandle = 80
			}
			check(grant.requests)
			// Exercise cleanup reservations independently of the tested creation result.
			grant.sent, grant.rejected, grant.committed, grant.ruleHandle, grant.setHandle = true, false, true, 81, 80
			removal, err := n.newBootstrapRemoval(92, grant)
			if err != nil {
				t.Fatal(err)
			}
			switch outcome {
			case "rejected":
				removal.sent = true
				removal.rejected = true
			case "committed":
				removal.sent = true
				removal.committed = true
			}
			check(removal.requests)
		})
	}
}
