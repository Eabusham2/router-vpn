//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func linuxNodeCreationReceipt(t *testing.T, homeLAN bool) (DesktopSocketCapture, DesktopLinuxSocketOptions, []byte) {
	t.Helper()
	capture, options := desktopSocketFixtureCapture(), DesktopLinuxSocketOptions{}
	if homeLAN {
		options.LANPrefixes = []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24"), netip.MustParsePrefix("fd50::/64")}
	}
	request := desktopLinuxNodeBaselineRequest(capture, options)
	for index, row := range request {
		if index == 0 {
			row["create"].(map[string]any)["handle"] = float64(101)
			continue
		}
		kind := "rule"
		if index == 1 {
			kind = "chain"
		}
		row["add"].(map[string]any)[kind].(map[string]any)["handle"] = float64(index)
	}
	body, err := json.Marshal(map[string]any{"nftables": request})
	if err != nil {
		t.Fatal(err)
	}
	return capture, options, body
}

func TestLinuxBaselineNodeCreationReceiptRequiresExactOperations(t *testing.T) {
	for _, homeLAN := range []bool{false, true} {
		capture, options, body := linuxNodeCreationReceipt(t, homeLAN)
		n, err := desktopLinuxNodeBaselineReceipt(body, capture, options)
		if err != nil || n.TableHandle != 101 || n.ChainHandle != 1 || len(n.Baseline) != len(desktopLinuxBaselineExpressions(options)) || n.TableName != desktopLinuxNodeTable(capture) {
			t.Fatal("complete native create receipt lost its exact session inventory", err)
		}
		for name, change := range map[string]func(string) string{
			"table name": func(s string) string {
				return strings.ReplaceAll(s, desktopLinuxNodeTable(capture), desktopLinuxNFTTable)
			},
			"source marker":    func(s string) string { return strings.ReplaceAll(s, capture.SourceSHA256, strings.Repeat("a", 64)) },
			"drop policy":      func(s string) string { return strings.Replace(s, `"policy":"drop"`, `"policy":"accept"`, 1) },
			"exclusive create": func(s string) string { return strings.Replace(s, `"create":`, `"add":`, 1) },
			"no table handle":  func(s string) string { return strings.Replace(s, `"handle":101,`, "", 1) },
			"two table handles": func(s string) string {
				return strings.Replace(s, `"table":{"family":`, `"table":{"handle":101,"family":`, 1)
			},
			"inexact handle": func(s string) string { return strings.Replace(s, `"handle":101`, `"handle":9007199254740992`, 1) },
			"duplicate key":  func(s string) string { return strings.Replace(s, `"handle":101`, `"handle":101,"handle":101`, 1) },
			"trailing JSON":  func(s string) string { return s + `{}` },
			"unexpected root": func(s string) string {
				return strings.Replace(s, `{"nftables":`, `{"foreign":true,"nftables":`, 1)
			},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := desktopLinuxNodeBaselineReceipt([]byte(change(string(body))), capture, options); err == nil {
					t.Fatal("changed create receipt became original baseline ownership")
				}
			})
		}
	}
}

func TestLinuxBaselineNodeScopeAndAbsence(t *testing.T) {
	capture := desktopSocketFixtureCapture()
	fixed := desktopLinuxNFTForCapture(capture, false)
	node := desktopLinuxNFTForCapture(capture, true)
	if fixed.table() != desktopLinuxNFTTable || fixed.TableName != "" || node.table() != desktopLinuxNodeTable(capture) {
		t.Fatal("Node scope changed the fixed Tor/global namespace")
	}
	for _, table := range []string{desktopLinuxNFTTable, "router_vpn_node_", "router_vpn_node_INVALID", "router_vpn_node_" + strings.Repeat("e", 32)} {
		rows := []map[string]any{{"table": map[string]any{"family": "inet", "name": table, "handle": float64(3)}}}
		if err := desktopLinuxTableListAbsent(rows, func(name string) bool {
			return name == desktopLinuxNFTTable || strings.HasPrefix(name, desktopLinuxNodeTablePrefix)
		}); err == nil {
			t.Fatal("reserved or malformed Node table was converted into initial absence", table)
		}
	}
	p, _, _ := desktopLinuxProtectionFixture(t)
	record, err := p.protectionRecord()
	if err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(record)
	if strings.Contains(string(original), "table_name") {
		t.Fatal("fixed Tor/global record changed canonical encoding")
	}
	record.TableName = node.table()
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{desktopLinuxNFTTable, "router_vpn_node_INVALID", "router_vpn_node_" + strings.Repeat("e", 32)} {
		record.TableName = name
		if err := record.Validate(); err == nil {
			t.Fatal("a record selected another table namespace", name)
		}
	}
}

func TestLinuxBaselineNodePartialOwnerCannotMutate(t *testing.T) {
	ctx := context.Background()
	for _, b := range []*DesktopLinuxNodeBaseline{nil, {}, {gate: make(chan struct{}, 1)}} {
		if b != nil && b.gate != nil {
			b.gate <- struct{}{}
		}
		if err := b.Release(ctx); err == nil {
			t.Fatal("partial creator authorized a native deletion")
		}
		if err := b.Supersede(ctx, b); err == nil {
			t.Fatal("partial creator authorized self-succession")
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if b, err := NewDesktopLinuxNodeBaseline(cancelled, desktopSocketFixtureCapture(), false); b != nil || err == nil {
		t.Fatal("cancelled constructor returned native creation authority")
	}
}
