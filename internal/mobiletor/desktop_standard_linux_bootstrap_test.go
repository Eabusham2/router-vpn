//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func bootstrapNativeFixture(t *testing.T) (*DesktopLinuxNodeBaseline, *desktopLinuxStandardBootstrap, []map[string]any, map[string]any, []byte) {
	t.Helper()
	c, ends, raw := standardCreationReceipt(t, false)
	request, e := desktopLinuxStandardRequest(c, ends, false)
	if e != nil {
		t.Fatal(e)
	}
	n := desktopLinuxNFTForCapture(c, true)
	n.TableName = desktopLinuxStandardTable(c)
	n, e = desktopLinuxBaselineReceipt(raw, c, request, n)
	if e != nil {
		t.Fatal(e)
	}
	var decoded struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if e = json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	var rows []map[string]any
	for i, row := range decoded.NFTables {
		verb, kind := "add", "rule"
		if i == 0 {
			verb, kind = "create", "table"
		}
		if i == 1 {
			kind = "chain"
		}
		op := row[verb].(map[string]any)
		obj := op[kind].(map[string]any)
		if h, ok := op["handle"]; ok {
			obj["handle"] = h
		}
		rows = append(rows, map[string]any{kind: obj})
	}
	route := desktopLinuxBootstrapRoute{Interface: net.Interface{Name: "eth0", Index: 2}, Address: netip.MustParseAddr("192.0.2.2")}
	expr := desktopLinuxBootstrapExpressions(route, netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("192.0.2.53:53"), 0x92345678)
	pending := &desktopLinuxStandardBootstrap{handle: 55, expression: expr}
	rule := map[string]any{"family": "inet", "table": n.table(), "chain": "output", "expr": expr}
	req := map[string]any{"nftables": []any{map[string]any{"add": map[string]any{"rule": rule}}}}
	body, _ := json.Marshal(req)
	var echo map[string]any
	_ = json.Unmarshal(body, &echo)
	echo["nftables"].([]any)[0].(map[string]any)["add"].(map[string]any)["rule"].(map[string]any)["handle"] = float64(55)
	body, _ = json.Marshal(echo)
	return &DesktopLinuxNodeBaseline{nft: n}, pending, rows, req, body
}
func TestLinuxStandardBootstrapGrantRequiresExactCreation(t *testing.T) {
	_, _, _, request, echo := bootstrapNativeFixture(t)
	if h, e := desktopLinuxBootstrapEcho(echo, request); e != nil || h != 55 {
		t.Fatal(h, e)
	}
	for _, name := range []string{"tuple", "mark", "uid", "interface", "handle", "duplicate", "trailing", "foreign-operation"} {
		t.Run(name, func(t *testing.T) {
			s := string(echo)
			switch name {
			case "tuple":
				s = strings.ReplaceAll(s, "192.0.2.53", "192.0.2.54")
			case "mark":
				s = strings.Replace(s, "2452903544", "2452903545", 1)
			case "uid":
				s = strings.Replace(s, `"right":0`, `"right":1`, 1)
			case "interface":
				s = strings.Replace(s, "eth0", "eth1", 1)
			case "handle":
				s = strings.Replace(s, `"handle":55,`, "", 1)
			case "duplicate":
				s = strings.Replace(s, `"handle":55`, `"handle":55,"handle":55`, 1)
			case "trailing":
				s += "{}"
			case "foreign-operation":
				s = strings.Replace(s, `"add":`, `"replace":`, 1)
			}
			if s == string(echo) {
				t.Fatal("causal fixture did not change source")
			}
			if _, e := desktopLinuxBootstrapEcho([]byte(s), request); e == nil {
				t.Fatal("foreign grant became original authority")
			}
		})
	}
}
func TestLinuxStandardBootstrapInventoryRetainsOriginalBaseline(t *testing.T) {
	b, p, rows, _, echo := bootstrapNativeFixture(t)
	var packet map[string]any
	_ = json.Unmarshal(echo, &packet)
	rule := packet["nftables"].([]any)[0].(map[string]any)["add"].(map[string]any)["rule"].(map[string]any)
	rows = append(rows, map[string]any{"rule": rule})
	if present, e := p.inventory(b, rows); e != nil || !present {
		t.Fatal(present, e)
	}
	if present, e := p.inventory(b, rows[:len(rows)-1]); e != nil || present {
		t.Fatal("exact removal failed", present, e)
	}
	for _, name := range []string{"replacement", "broader", "foreign-extra", "baseline-loss", "unknown-echo"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(rows)
			var changed []map[string]any
			_ = json.Unmarshal(raw, &changed)
			pending := *p
			switch name {
			case "replacement":
				changed[len(changed)-1]["rule"].(map[string]any)["handle"] = float64(56)
			case "broader":
				changed[len(changed)-1]["rule"].(map[string]any)["expr"] = []any{map[string]any{"accept": nil}}
			case "foreign-extra":
				changed = append(changed, changed[len(changed)-1])
			case "baseline-loss":
				changed = append(changed[:2], changed[3:]...)
			case "unknown-echo":
				pending.handle = 0
			}
			if _, e := pending.inventory(b, changed); e == nil {
				t.Fatal("changed or unacknowledged native inventory accepted")
			}
		})
	}
}
func TestLinuxStandardBootstrapHeldGateKeepsOriginalDeadline(t *testing.T) {
	b := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: "bootstrap"}
	p := &DesktopLinuxStandardProtection{baseline: b, acknowledged: true, bootstrap: &desktopLinuxStandardBootstrap{}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := p.CleanupBootstrap(ctx, nil); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if p.bootstrap == nil || b.crossTransfer != "bootstrap" {
		t.Fatal("expired observation discarded original cleanup")
	}
	b.gate <- struct{}{}
	if e := p.Close(context.Background()); e == nil {
		t.Fatal("pending original socket lost its native creator")
	}
	b.complete = true
	if _, e := p.Receipt(context.Background()); e == nil {
		t.Fatal("pending grant became a closed baseline receipt")
	}
}
func TestLinuxStandardBootstrapRejectsArbitraryQuestions(t *testing.T) {
	q := []byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 'n', 'o', 'd', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	if e := desktopLinuxBootstrapQuestion(q); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"many", "extra", "txt", "compressed", "trailing", "invalid-label"} {
		t.Run(name, func(t *testing.T) {
			r := append([]byte(nil), q...)
			switch name {
			case "many":
				r[5] = 2
			case "extra":
				r[11] = 1
			case "txt":
				r[len(r)-3] = 16
			case "compressed":
				r[12] = 0xc0
			case "trailing":
				r = append(r, 0)
			case "invalid-label":
				r[13] = '*'
			}
			if e := desktopLinuxBootstrapQuestion(r); e == nil {
				t.Fatal("arbitrary resolver channel admitted")
			}
		})
	}
}

// This tests only the actual descriptor finalizer, not modeled firewall removal.
// Production reaches it only after the original handle is independently absent.
func TestLinuxStandardBootstrapCloseJoinsOriginalObjects(t *testing.T) {
	for _, mode := range []string{"connection", "file", "both"} {
		t.Run(mode, func(t *testing.T) {
			conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			file, e := conn.File()
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			original := &desktopLinuxStandardBootstrap{conn: conn, file: file}
			if mode == "connection" || mode == "both" {
				if e = conn.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "file" || mode == "both" {
				if e = file.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if e = original.closeSocket(); e != nil {
				t.Fatal("exact completed close could not settle", e)
			}
			if original.conn != nil || original.file != nil {
				t.Fatal("original descriptors remained retained after join")
			}
			if e = original.closeSocket(); e != nil {
				t.Fatal("completed finalizer repeated native work", e)
			}
		})
	}
}
