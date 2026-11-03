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

func linuxRunningSOCKSFixture(t *testing.T, family string, private bool) (*desktopLinuxNFT, []map[string]any, DesktopLinuxNodeRunningSelection) {
	t.Helper()
	n, rows, selection := linuxRunningFixture(t)
	parent := linuxRunningFirst(rows)
	parent["comment"] = fmt.Sprintf("%032x:3", 1)
	control := netip.MustParseAddrPort("198.18.0.2:8443")
	if private {
		control = netip.MustParseAddrPort("10.0.0.2:8443")
		parent["val"].(map[string]any)["concat"].([]any)[3] = control.Addr().String()
		selection.Destinations[0].Address = control
	}
	selection.SOCKSControls = []DesktopLinuxSocketDestination{{Network: "tcp", Address: control}}
	child := linuxRunningSet(rows, family)["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)
	child["comment"] = fmt.Sprintf("%032x:5:socks:%032x:2", 22, 1)
	child["timeout"], child["expires"] = float64(4), float64(3)
	tuple := child["val"].(map[string]any)["concat"].([]any)
	tuple[3], tuple[4] = "198.51.100.84", float64(54084)
	if family == "udp6" {
		tuple[3] = "2001:db8::84"
	} else if private {
		tuple[3] = control.Addr().String()
	}
	return n, rows, selection
}

func linuxRunningSOCKSChild(rows []map[string]any, family string) map[string]any {
	return linuxRunningSet(rows, family)["elem"].([]any)[0].(map[string]any)["elem"].(map[string]any)
}

func TestDesktopLinuxRunningSOCKSChecksOriginalControlWithoutChangingInventory(t *testing.T) {
	for _, scenario := range []string{"different-public", "cross-family-public", "same-private", "other-private-home-lan", "other-private-selected-static", "child-before-control", "renewed-parent"} {
		t.Run(scenario, func(t *testing.T) {
			family := "udp4"
			if scenario == "cross-family-public" {
				family = "udp6"
			}
			private := strings.Contains(scenario, "private")
			n, rows, selection := linuxRunningSOCKSFixture(t, family, private)
			child := linuxRunningSOCKSChild(rows, family)
			if scenario == "other-private-home-lan" || scenario == "other-private-selected-static" {
				child["val"].(map[string]any)["concat"].([]any)[3] = "10.0.0.3"
				if scenario == "other-private-selected-static" {
					selection.Destinations = append(selection.Destinations, DesktopLinuxSocketDestination{Network: "udp", Address: netip.MustParseAddrPort("10.0.0.3:54084")})
				}
			}
			if scenario == "child-before-control" {
				first, second := -1, -1
				for i, row := range rows {
					if set, ok := row["set"].(map[string]any); ok {
						if set["name"] == n.Prefix+"_tcp4" {
							first = i
						}
						if set["name"] == n.Prefix+"_udp4" {
							second = i
						}
					}
				}
				rows[first], rows[second] = rows[second], rows[first]
			}
			if scenario == "renewed-parent" {
				linuxRunningFirst(rows)["comment"] = fmt.Sprintf("%032x:99", 1)
			}
			original := desktopLinuxProtectionCopyRows(t, rows)
			if err := desktopLinuxRunningRowsWithLAN(n, rows, selection, scenario == "other-private-home-lan"); err != nil {
				t.Fatal("owned dynamic relay lost original exact native comparison", err)
			}
			if !reflect.DeepEqual(rows, original) {
				t.Fatal("association observation mutated actual kernel inventory")
			}
			if desktopLinuxProtectionRows(n, rows, true) == nil {
				t.Fatal("active association became proof of closed protection")
			}
		})
	}
}

func TestDesktopLinuxRunningSOCKSRejectsUnownedAndExpiredAssociations(t *testing.T) {
	for _, fault := range []string{"unmarked", "marker-kind", "marker-extra", "child-zero", "parent-zero", "future-parent", "parent-self", "parent-absent", "parent-not-selected", "parent-duplicate", "child-duplicate", "two-children", "wrong-control-tuple", "other-private", "link-local", "loopback", "wrong-source", "expires-after-parent", "expired", "timeout-zero", "timeout-fraction", "timeout-long", "wrong-protocol", "control-not-static", "duplicate-control"} {
		t.Run(fault, func(t *testing.T) {
			n, rows, selection := linuxRunningSOCKSFixture(t, "udp4", true)
			child := linuxRunningSOCKSChild(rows, "udp4")
			parent := linuxRunningFirst(rows)
			tuple := child["val"].(map[string]any)["concat"].([]any)
			switch fault {
			case "unmarked":
				child["comment"] = fmt.Sprintf("%032x:5", 22)
				child["timeout"] = float64(9)
			case "marker-kind":
				child["comment"] = fmt.Sprintf("%032x:5:other:%032x:2", 22, 1)
			case "marker-extra":
				child["comment"] = child["comment"].(string) + ":extra"
			case "child-zero":
				child["comment"] = fmt.Sprintf("%032x:0:socks:%032x:2", 22, 1)
			case "parent-zero":
				child["comment"] = fmt.Sprintf("%032x:5:socks:%032x:0", 22, 1)
			case "future-parent":
				child["comment"] = fmt.Sprintf("%032x:5:socks:%032x:4", 22, 1)
			case "parent-self":
				child["comment"] = fmt.Sprintf("%032x:5:socks:%032x:2", 22, 22)
			case "parent-absent":
				delete(linuxRunningSet(rows, "tcp4"), "elem")
			case "parent-not-selected":
				selection.SOCKSControls = nil
			case "parent-duplicate":
				set := linuxRunningSet(rows, "tcp4")
				set["elem"] = append(set["elem"].([]any), set["elem"].([]any)[0])
			case "child-duplicate":
				set := linuxRunningSet(rows, "udp4")
				set["elem"] = append(set["elem"].([]any), set["elem"].([]any)[0])
			case "two-children":
				second := linuxRunningSOCKSChild(rows, "udp6")
				second["comment"] = fmt.Sprintf("%032x:1:socks:%032x:2", 23, 1)
				second["timeout"], second["expires"] = float64(4), float64(3)
			case "wrong-control-tuple":
				parent["val"].(map[string]any)["concat"].([]any)[4] = float64(1080)
			case "other-private":
				tuple[3] = "10.0.0.3"
			case "link-local":
				tuple[3] = "169.254.1.2"
			case "loopback":
				tuple[3] = "127.0.0.1"
			case "wrong-source":
				tuple[1] = "198.18.0.9"
			case "expires-after-parent":
				parent["expires"] = float64(2)
			case "expired":
				child["expires"] = float64(0)
			case "timeout-zero":
				child["timeout"] = float64(0)
			case "timeout-fraction":
				child["timeout"] = float64(4.5)
			case "timeout-long":
				child["timeout"] = float64(10)
			case "wrong-protocol":
				parent["comment"] = child["comment"]
			case "control-not-static":
				selection.Destinations = selection.Destinations[1:]
			case "duplicate-control":
				selection.SOCKSControls = append(selection.SOCKSControls, selection.SOCKSControls[0])
			}
			if desktopLinuxRunningRows(n, rows, selection) == nil {
				t.Fatal("unowned dynamic relay became a running proof", fault)
			}
		})
	}
}
