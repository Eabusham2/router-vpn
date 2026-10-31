//go:build linux

package mobiletor

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// These parser cases exercise native JSON shape, not a kernel substitute.
// The tagged guardian cases independently run both public observations against
// the actual nft namespace, native descriptor lifecycle and real peer traffic.
func desktopLinuxProtectionFixture(t *testing.T) (*DesktopLinuxSocketPolicy, []map[string]any, []map[string]any) {
	t.Helper()
	capture, owner := desktopSocketFixtureCapture(), desktopSocketFixturePolicy().owner
	n := &desktopLinuxNFT{Capture: capture, UID: 10001, Prefix: "rvpn_" + strings.Repeat("a", 20), TableHandle: 1, ChainHandle: 2,
		Baseline: make(map[uint64]any), Rules: make(map[string]uint64), Sets: make(map[string]uint64)}
	rows := []map[string]any{
		{"metainfo": map[string]any{"version": "fixture", "json_schema_version": float64(1)}},
		{"table": map[string]any{"family": "inet", "name": desktopLinuxNFTTable, "handle": float64(1)}},
		{"chain": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "name": "output", "handle": float64(2), "type": "filter", "hook": "output", "prio": float64(-310), "policy": "drop", "comment": "routervpn-owned-baseline:" + capture.SessionID + ":" + capture.SourceSHA256}},
	}
	for i, expressions := range desktopLinuxBaselineExpressions(DesktopLinuxSocketOptions{}) {
		handle := uint64(10 + i)
		n.Baseline[handle] = expressions
		rows = append(rows, map[string]any{"rule": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "chain": "output", "handle": float64(handle), "expr": expressions}})
	}
	retired := desktopLinuxProtectionCopyRows(t, rows)
	for i, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		n.Rules[kind], n.Sets[kind] = uint64(100+2*i), uint64(101+2*i)
		addressType := "ipv4_addr"
		if kind[3] == '6' {
			addressType = "ipv6_addr"
		}
		rows = append(rows,
			map[string]any{"rule": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "chain": "output", "handle": float64(n.Rules[kind]), "comment": n.comment(kind), "expr": n.ruleExpressions(kind)}},
			map[string]any{"set": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "name": n.Prefix + "_" + kind, "handle": float64(n.Sets[kind]), "type": []any{"iface_index", addressType, "inet_service", addressType, "inet_service"}, "flags": []any{"timeout"}, "timeout": float64(9), "size": float64(4096)}},
		)
	}
	p := &DesktopLinuxSocketPolicy{capture: capture, owner: owner, uid: n.UID, nft: n, command: &exec.Cmd{Process: &os.Process{Pid: int(owner.ProcessID)}}}
	return p, rows, retired
}

func desktopLinuxProtectionCopyRows(t *testing.T, rows []map[string]any) []map[string]any {
	t.Helper()
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDesktopLinuxProtectionCapturedRecord(t *testing.T) {
	p, prepared, retired := desktopLinuxProtectionFixture(t)
	first, err := p.protectionRecord()
	if err != nil || first.Validate() != nil {
		t.Fatal("complete captured Linux baseline did not produce an observation identity", err)
	}
	for _, rows := range [][]map[string]any{prepared, retired} {
		if err = desktopLinuxProtectionRows(p.nft, rows, len(rows) == len(prepared)); err != nil {
			t.Fatal("complete prepared/retired fixture failed native JSON validation", err)
		}
	}
	second, err := p.protectionRecord()
	if err != nil || first != second {
		t.Fatal("unchanged source changed its stable baseline identity", err)
	}
	p.options.LANPrefixes = []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}
	if _, err = p.protectionRecord(); err == nil {
		t.Fatal("changed selected LAN policy adopted the old baseline")
	}
	p.options.LANPrefixes = nil
	p.nft.Baseline[10] = []any{map[string]any{"accept": nil}}
	if _, err = p.protectionRecord(); err == nil {
		t.Fatal("unselected broad exemption became a captured baseline")
	}
}

func TestDesktopLinuxProtectionRowsRejectSubstitution(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		state := "retired"
		if prepared {
			state = "prepared"
		}
		t.Run(state, func(t *testing.T) {
			p, activeRows, retiredRows := desktopLinuxProtectionFixture(t)
			original := retiredRows
			if prepared {
				original = activeRows
			}
			for name, mutate := range map[string]func([]map[string]any) []map[string]any{
				"missing-table":      func(r []map[string]any) []map[string]any { return append(r[:1], r[2:]...) },
				"missing-baseline":   func(r []map[string]any) []map[string]any { return append(r[:3], r[4:]...) },
				"duplicate-table":    func(r []map[string]any) []map[string]any { return append(r, r[1]) },
				"duplicate-chain":    func(r []map[string]any) []map[string]any { return append(r, r[2]) },
				"duplicate-rule":     func(r []map[string]any) []map[string]any { return append(r, r[3]) },
				"duplicate-metadata": func(r []map[string]any) []map[string]any { return append(r, r[0]) },
				"replaced-table-handle": func(r []map[string]any) []map[string]any {
					r[1]["table"].(map[string]any)["handle"] = float64(40)
					return r
				},
				"replaced-chain-handle": func(r []map[string]any) []map[string]any {
					r[2]["chain"].(map[string]any)["handle"] = float64(41)
					return r
				},
				"replaced-rule-handle": func(r []map[string]any) []map[string]any {
					r[3]["rule"].(map[string]any)["handle"] = float64(42)
					return r
				},
				"dormant-table": func(r []map[string]any) []map[string]any {
					r[1]["table"].(map[string]any)["flags"] = []any{"dormant"}
					return r
				},
				"malformed-flags": func(r []map[string]any) []map[string]any { r[1]["table"].(map[string]any)["flags"] = nil; return r },
				"changed-capture": func(r []map[string]any) []map[string]any {
					r[2]["chain"].(map[string]any)["comment"] = "routervpn-owned-baseline:" + strings.Repeat("f", 32) + ":" + p.capture.SourceSHA256
					return r
				},
				"changed-priority": func(r []map[string]any) []map[string]any {
					r[2]["chain"].(map[string]any)["prio"] = float64(-309)
					return r
				},
				"changed-policy": func(r []map[string]any) []map[string]any {
					r[2]["chain"].(map[string]any)["policy"] = "accept"
					return r
				},
				"broad-exemption": func(r []map[string]any) []map[string]any {
					r[3]["rule"].(map[string]any)["expr"] = []any{map[string]any{"accept": nil}}
					return r
				},
				"foreign-empty-set": func(r []map[string]any) []map[string]any {
					return append(r, map[string]any{"set": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "name": "unselected", "handle": float64(90), "type": "ipv4_addr"}})
				},
				"foreign-empty-chain": func(r []map[string]any) []map[string]any {
					return append(r, map[string]any{"chain": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "name": "unselected", "handle": float64(91)}})
				},
				"unknown-object": func(r []map[string]any) []map[string]any {
					return append(r, map[string]any{"flowtable": map[string]any{}})
				},
				"ambiguous-object": func(r []map[string]any) []map[string]any { r[0]["table"] = r[1]["table"]; return r },
				"malformed-object": func(r []map[string]any) []map[string]any { return append(r, map[string]any{"set": "unknown"}) },
			} {
				t.Run(name, func(t *testing.T) {
					changed := mutate(desktopLinuxProtectionCopyRows(t, original))
					if err := desktopLinuxProtectionRows(p.nft, changed, prepared); err == nil {
						t.Fatal("closed native observation accepted changed, additional or missing kernel objects")
					}
				})
			}
		})
	}
}

func TestDesktopLinuxProtectionPreparedInventory(t *testing.T) {
	p, original, retired := desktopLinuxProtectionFixture(t)
	for name, mutate := range map[string]func(map[string]any){
		"active-element": func(s map[string]any) {
			s["elem"] = []any{map[string]any{"concat": []any{"if0", "192.168.1.1", float64(1234), "192.168.1.2", float64(2345)}}}
		},
		"malformed-element": func(s map[string]any) { s["elem"] = "unknown" },
		"null-element":      func(s map[string]any) { s["elem"] = nil },
		"replaced-set":      func(s map[string]any) { s["handle"] = float64(999) },
		"changed-set-type":  func(s map[string]any) { s["type"] = "ipv4_addr" },
		"unknown-set-field": func(s map[string]any) { s["map"] = "verdict" },
	} {
		t.Run(name, func(t *testing.T) {
			rows := desktopLinuxProtectionCopyRows(t, original)
			mutate(rows[8]["set"].(map[string]any))
			if desktopLinuxProtectionRows(p.nft, rows, true) == nil {
				t.Fatal("prepared observation accepted an active or substituted tuple set")
			}
		})
	}
	empty := desktopLinuxProtectionCopyRows(t, original)
	empty[8]["set"].(map[string]any)["elem"] = []any{}
	if err := desktopLinuxProtectionRows(p.nft, empty, true); err != nil {
		t.Fatal("explicit empty kernel set was not accepted", err)
	}
	if desktopLinuxProtectionRows(p.nft, original, false) == nil || desktopLinuxProtectionRows(p.nft, retired, true) == nil || desktopLinuxProtectionRows(p.nft, nil, false) == nil {
		t.Fatal("prepared/retired/missing native inventories were conflated")
	}
	if !reflect.DeepEqual(original[8]["set"].(map[string]any)["elem"], nil) {
		t.Fatal("parser test mutated the baseline fixture")
	}
}
