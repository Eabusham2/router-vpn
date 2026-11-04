//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func standardCreationReceipt(t *testing.T, lan bool) (DesktopSocketCapture, []netip.Addr, []byte) {
	t.Helper()
	capture := desktopSocketFixtureCapture()
	endpoints := []netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("2001:db8::2")}
	request, err := desktopLinuxStandardRequest(capture, endpoints, lan)
	if err != nil {
		t.Fatal(err)
	}
	for index, row := range request {
		if index == 0 {
			row["create"].(map[string]any)["handle"] = float64(100)
			continue
		}
		kind := "rule"
		if index == 1 {
			kind = "chain"
		}
		row["add"].(map[string]any)[kind].(map[string]any)["handle"] = float64(index)
	}
	raw, err := json.Marshal(map[string]any{"nftables": request})
	if err != nil {
		t.Fatal(err)
	}
	return capture, endpoints, raw
}
func TestLinuxStandardCreationReceiptRetainsExactEndpointPolicy(t *testing.T) {
	for _, lan := range []bool{false, true} {
		capture, endpoints, raw := standardCreationReceipt(t, lan)
		request, err := desktopLinuxStandardRequest(capture, endpoints, lan)
		if err != nil {
			t.Fatal(err)
		}
		original := desktopLinuxNFTForCapture(capture, true)
		original.TableName = desktopLinuxStandardTable(capture)
		n, err := desktopLinuxBaselineReceipt(raw, capture, request, original)
		if err != nil || n.TableName != desktopLinuxStandardTable(capture) || n.TableHandle != 100 || len(n.Baseline) != len(request)-2 {
			t.Fatal("standard creator lost original exact native inventory", err)
		}
		for name, change := range map[string]func(string) string{
			"Node scope": func(s string) string {
				return strings.ReplaceAll(s, desktopLinuxStandardTable(capture), desktopLinuxNodeTable(capture))
			},
			"foreign endpoint":      func(s string) string { return strings.ReplaceAll(s, "198.18.0.2", "198.18.0.3") },
			"missing native handle": func(s string) string { return strings.Replace(s, `"handle":100,`, "", 1) },
			"nonexclusive creation": func(s string) string { return strings.Replace(s, `"create":`, `"add":`, 1) },
			"duplicate field":       func(s string) string { return strings.Replace(s, `"handle":100`, `"handle":100,"handle":100`, 1) },
			"unrequested accept":    func(s string) string { return strings.Replace(s, `"policy":"drop"`, `"policy":"accept"`, 1) },
		} {
			t.Run(name, func(t *testing.T) {
				candidate := desktopLinuxNFTForCapture(capture, true)
				candidate.TableName = desktopLinuxStandardTable(capture)
				if _, err := desktopLinuxBaselineReceipt([]byte(change(string(raw))), capture, request, candidate); err == nil {
					t.Fatal("changed native receipt became original standard creator")
				}
			})
		}
	}
}
func TestLinuxStandardCreationScopeAndPartialAuthority(t *testing.T) {
	capture := desktopSocketFixtureCapture()
	for _, endpoints := range [][]netip.Addr{nil, {netip.Addr{}}, {netip.MustParseAddr("0.0.0.0")}, {netip.MustParseAddr("ff02::1")}, {netip.MustParseAddr("::ffff:192.0.2.1")}, {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")}} {
		if _, err := desktopLinuxStandardRequest(capture, endpoints, false); err == nil {
			t.Fatal("invalid physical selection created an exemption", endpoints)
		}
	}
	for _, p := range []*DesktopLinuxStandardProtection{nil, {}, {baseline: &DesktopLinuxNodeBaseline{}}} {
		if _, err := p.Receipt(context.Background()); err == nil {
			t.Fatal("partial/saved record acquired creation authority")
		}
		if err := p.Release(context.Background(), nil); err == nil {
			t.Fatal("partial creator acquired release authority")
		}
	}
	for _, name := range []string{desktopLinuxStandardTable(capture), desktopLinuxNodeTable(capture)} {
		if !desktopLinuxOwnedTableName(name) {
			t.Fatal("strict native table scope rejected", name)
		}
	}
	for _, name := range []string{"router_vpn_standard_", desktopLinuxNFTTable, "router_vpn_standard_" + strings.Repeat("z", 32)} {
		if desktopLinuxOwnedTableName(name) {
			t.Fatal("foreign or malformed name entered standard scope", name)
		}
	}
}
