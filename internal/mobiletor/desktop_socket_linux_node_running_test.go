//go:build linux

package mobiletor

import (
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func linuxRunningFixture(t *testing.T) (*desktopLinuxNFT, []map[string]any, DesktopLinuxNodeRunningSelection) {
	t.Helper()
	p, rows, _ := desktopLinuxProtectionFixture(t)
	selection := DesktopLinuxNodeRunningSelection{Interfaces: []DesktopLinuxSocketInterface{
		{Name: "rvpn-test", Index: 7, Address: netip.MustParseAddr("198.18.0.1")},
		{Name: "rvpn-test", Index: 7, Address: netip.MustParseAddr("fd50::1")},
	}}
	for i, kind := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		local, remote := "198.18.0.1", "198.18.0.2"
		if kind[3] == '6' {
			local, remote = "fd50::1", "fd50::2"
		}
		selection.Destinations = append(selection.Destinations, DesktopLinuxSocketDestination{
			Network: kind[:3], Address: netip.AddrPortFrom(netip.MustParseAddr(remote), 8443),
		})
		for _, row := range rows {
			if set, ok := row["set"].(map[string]any); ok && set["name"] == p.nft.Prefix+"_"+kind {
				set["elem"] = []any{map[string]any{"elem": map[string]any{
					"val":     map[string]any{"concat": []any{"rvpn-test", local, float64(40000 + i), remote, float64(8443)}},
					"timeout": float64(9), "expires": float64(8), "comment": fmt.Sprintf("%032x:1", i+1),
				}}}
			}
		}
	}
	return p.nft, rows, selection
}

func linuxRunningSet(rows []map[string]any, suffix string) map[string]any {
	for _, row := range rows {
		if set, ok := row["set"].(map[string]any); ok && strings.HasSuffix(set["name"].(string), "_"+suffix) {
			return set
		}
	}
	panic("fixture lost its native set")
}

func linuxRunningFirst(rows []map[string]any) map[string]any {
	return linuxRunningSet(rows, "tcp4")["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)
}

func TestDesktopLinuxRunningPolicyPreservesClosedInventory(t *testing.T) {
	n, rows, selection := linuxRunningFixture(t)
	original := desktopLinuxProtectionCopyRows(t, rows)
	if err := desktopLinuxRunningRows(n, rows, selection); err != nil {
		t.Fatal("complete captured live inventory was refused", err)
	}
	if !reflect.DeepEqual(rows, original) {
		t.Fatal("running observation changed its native read result")
	}
	if desktopLinuxProtectionRows(n, rows, true) == nil || desktopLinuxProtectionRows(n, rows, false) == nil {
		t.Fatal("running elements became proof of closed protection")
	}
	for _, row := range rows {
		if set, ok := row["set"].(map[string]any); ok {
			delete(set, "elem")
		}
	}
	if err := desktopLinuxRunningRows(n, rows, selection); err != nil {
		t.Fatal("live source with no currently active socket was refused", err)
	}
	if err := desktopLinuxProtectionRows(n, rows, true); err != nil {
		t.Fatal("original empty prepared inventory changed", err)
	}
}

func TestDesktopLinuxRunningPolicyRejectsUncapturedElements(t *testing.T) {
	mutations := map[string]func([]map[string]any) []map[string]any{
		"foreign-counter": func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"counter": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "name": "unowned"}})
		},
		"unknown-set": func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"set": map[string]any{"family": "inet", "table": desktopLinuxNFTTable, "name": "unowned"}})
		},
		"changed-baseline": func(r []map[string]any) []map[string]any {
			r[3]["rule"].(map[string]any)["expr"] = []any{map[string]any{"accept": nil}}
			return r
		},
		"replaced-set": func(r []map[string]any) []map[string]any {
			linuxRunningSet(r, "tcp4")["handle"] = float64(9001)
			return r
		},
		"duplicate-set": func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"set": linuxRunningSet(r, "tcp4")})
		},
		"malformed-elements": func(r []map[string]any) []map[string]any {
			linuxRunningSet(r, "tcp4")["elem"] = nil
			return r
		},
		"unselected-interface": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)[0] = "another-device"
			return r
		},
		"unselected-source": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)[1] = "198.18.0.10"
			return r
		},
		"unselected-destination": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)[3] = "198.18.0.9"
			return r
		},
		"unselected-port": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)[4] = float64(8444)
			return r
		},
		"wrong-family": func(r []map[string]any) []map[string]any {
			v := linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)
			v[1], v[3] = "fd50::1", "fd50::2"
			return r
		},
		"unbound-source-port": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)[2] = float64(0)
			return r
		},
		"fractional-port": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"].(map[string]any)["concat"].([]any)[2] = float64(40000.5)
			return r
		},
		"timeout-extended": func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["timeout"] = float64(10); return r },
		"expiry-extended":  func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["expires"] = float64(10); return r },
		"expired":          func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["expires"] = float64(0); return r },
		"expiry-absent":    func(r []map[string]any) []map[string]any { delete(linuxRunningFirst(r), "expires"); return r },
		"expiry-nan":       func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["expires"] = math.NaN(); return r },
		"expiry-infinite":  func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["expires"] = math.Inf(1); return r },
		"unknown-property": func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["accept"] = nil; return r },
		"interval": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["val"] = map[string]any{"range": []any{1, 65535}}
			return r
		},
		"missing-socket": func(r []map[string]any) []map[string]any { linuxRunningFirst(r)["comment"] = "missing:1"; return r },
		"sequence-zero": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["comment"] = fmt.Sprintf("%032x:0", 1)
			return r
		},
		"sequence-noncanonical": func(r []map[string]any) []map[string]any {
			linuxRunningFirst(r)["comment"] = fmt.Sprintf("%032x:01", 1)
			return r
		},
		"duplicate-tuple": func(r []map[string]any) []map[string]any {
			s := linuxRunningSet(r, "tcp4")
			e := s["elem"].([]any)
			s["elem"] = append(e, e[0])
			return r
		},
		"replayed-socket-sequence": func(r []map[string]any) []map[string]any {
			linuxRunningSet(r, "udp4")["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)["comment"] = linuxRunningFirst(r)["comment"]
			return r
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			n, rows, selection := linuxRunningFixture(t)
			if err := desktopLinuxRunningRows(n, mutate(rows), selection); err == nil {
				t.Fatal("running observation accepted unowned native inventory", name)
			}
		})
	}
}

func TestDesktopLinuxRunningPolicySelectionAndCapacity(t *testing.T) {
	for _, scenario := range []string{"no-interfaces", "no-destinations", "interface-reused", "destination-repeated", "interface-index-zero", "socket-capacity", "peer-capacity"} {
		t.Run(scenario, func(t *testing.T) {
			n, rows, selection := linuxRunningFixture(t)
			switch scenario {
			case "no-interfaces":
				selection.Interfaces = nil
			case "no-destinations":
				selection.Destinations = nil
			case "interface-reused":
				selection.Interfaces = append(selection.Interfaces, selection.Interfaces[0])
			case "destination-repeated":
				selection.Destinations = append(selection.Destinations, selection.Destinations[0])
			case "interface-index-zero":
				selection.Interfaces[0].Index = 0
			case "socket-capacity", "peer-capacity":
				count := DesktopSocketLimit + 1
				if scenario == "peer-capacity" {
					count = DesktopSocketPeerLimit + 1
				}
				elements := make([]any, 0, count)
				for i := 0; i < count; i++ {
					socket := i + 10
					if scenario == "peer-capacity" {
						socket = 10
					}
					elements = append(elements, map[string]any{"elem": map[string]any{
						"val":     map[string]any{"concat": []any{"rvpn-test", "198.18.0.1", float64(41000 + i), "198.18.0.2", float64(8443)}},
						"timeout": float64(9), "expires": float64(8), "comment": fmt.Sprintf("%032x:%d", socket, i+1),
					}})
				}
				linuxRunningSet(rows, "tcp4")["elem"] = elements
			}
			if desktopLinuxRunningRows(n, rows, selection) == nil {
				t.Fatal("running inventory accepted a substituted selection or excess native capacity", scenario)
			}
		})
	}
}
