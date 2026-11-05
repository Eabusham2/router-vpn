//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func nodeStandardClosedSnapshotFixture(t *testing.T, standard bool) DesktopLinuxClosedTransferSnapshot {
	t.Helper()
	c := desktopSocketFixtureCapture()
	n := desktopLinuxNFTForCapture(c, true)
	n.TableHandle = 11
	n.ChainHandle = 12
	s := DesktopLinuxClosedTransferSnapshot{Standard: standard, NamespaceDevice: 1, NamespaceInode: 2, Capture: c}
	request := desktopLinuxNodeBaselineRequest(c, DesktopLinuxSocketOptions{})
	if standard {
		s.Endpoints = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
		var err error
		request, err = desktopLinuxStandardRequest(c, s.Endpoints, false)
		if err != nil {
			t.Fatal(err)
		}
		n.TableName = desktopLinuxStandardTable(c)
	}
	handle := uint64(100)
	for _, row := range request {
		if add, ok := row["add"].(map[string]any); ok {
			if rule, ok := add["rule"].(map[string]any); ok {
				n.Baseline[handle] = rule["expr"]
				handle++
			}
		}
	}
	s.Inventory, _ = json.Marshal(n)
	return s
}
func TestLinuxNodeStandardTransferClosedInventory(t *testing.T) {
	for _, kind := range []string{"node", "standard"} {
		t.Run(kind, func(t *testing.T) {
			for _, scenario := range []string{"original", "handle-zero", "capture", "endpoint", "wide-rule", "extra-set", "noncanonical", "namespace"} {
				t.Run(scenario, func(t *testing.T) {
					s := nodeStandardClosedSnapshotFixture(t, kind == "standard")
					var n desktopLinuxNFT
					_ = json.Unmarshal(s.Inventory, &n)
					switch scenario {
					case "handle-zero":
						n.TableHandle = 0
					case "capture":
						n.Capture.SessionID = strings.Repeat("f", 32)
					case "endpoint":
						s.Endpoints = []netip.Addr{netip.MustParseAddr("203.0.113.8")}
					case "wide-rule":
						n.Baseline[100] = []any{map[string]any{"accept": nil}}
					case "extra-set":
						n.Sets = map[string]uint64{"foreign": 88}
					case "namespace":
						s.NamespaceInode = 0
					}
					s.Inventory, _ = json.Marshal(n)
					if scenario == "noncanonical" {
						s.Inventory = append([]byte(" "), s.Inventory...)
					}
					err := s.Validate()
					if (err == nil) != (scenario == "original") {
						t.Fatal("closed original inventory comparison", err)
					}
				})
			}
		})
	}
}
func TestLinuxNodeStandardTransferCancellationKeepsBothPins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id := strings.Repeat("a", 32)
	source := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: id}
	source.gate <- struct{}{}
	tfr := &DesktopLinuxNodeStandardTransfer{source: source, id: id}
	if committed, err := tfr.Finish(ctx); err == nil || committed || tfr.finished || source.crossTransfer != id {
		t.Fatal("expired source observation discarded original reservation", err)
	}
	successor := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: id}
	successor.gate <- struct{}{}
	pin := &DesktopLinuxStandardSuccessorPin{owner: &DesktopLinuxStandardProtection{baseline: successor}, id: id}
	if err := pin.Resolve(ctx, nodeStandardClosedSnapshotFixture(t, false), true); err == nil || pin.released || successor.crossTransfer != id {
		t.Fatal("expired successor observation discarded original pin", err)
	}
}
