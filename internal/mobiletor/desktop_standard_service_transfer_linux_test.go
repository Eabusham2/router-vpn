//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func imageTransferSnapshotFixture(t *testing.T, session string, homeLAN bool, endpoints ...string) DesktopLinuxClosedTransferSnapshot {
	t.Helper()
	c := desktopSocketFixtureCapture()
	c.SessionID = session
	c.NetworkID = session
	s := DesktopLinuxClosedTransferSnapshot{Standard: true, NamespaceDevice: 1, NamespaceInode: 2, Capture: c, HomeLAN: homeLAN}
	for _, endpoint := range endpoints {
		s.Endpoints = append(s.Endpoints, netip.MustParseAddr(endpoint))
	}
	request, err := desktopLinuxStandardRequest(c, s.Endpoints, homeLAN)
	if err != nil {
		t.Fatal(err)
	}
	n := desktopLinuxNFTForCapture(c, true)
	n.TableName = desktopLinuxStandardTable(c)
	n.TableHandle = 11
	n.ChainHandle = 12
	handle := uint64(100)
	for _, row := range request {
		if add, ok := row["add"].(map[string]any); ok {
			if rule, ok := add["rule"].(map[string]any); ok {
				n.Baseline[handle] = rule["expr"]
				handle++
			}
		}
	}
	s.Inventory, err = json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestLinuxStandardImageTransferPolicy(t *testing.T) {
	for _, scenario := range []string{"original", "endpoint-order", "multiple-address-order", "different-endpoint", "home-lan", "same-session", "namespace", "node-source", "node-successor", "widened-rule"} {
		t.Run(scenario, func(t *testing.T) {
			a := imageTransferSnapshotFixture(t, strings.Repeat("a", 32), true, "203.0.113.7", "2001:db8::7")
			b := imageTransferSnapshotFixture(t, strings.Repeat("b", 32), true, "203.0.113.7", "2001:db8::7")
			switch scenario {
			case "endpoint-order":
				b = imageTransferSnapshotFixture(t, strings.Repeat("b", 32), true, "2001:db8::7", "203.0.113.7")
			case "multiple-address-order":
				a = imageTransferSnapshotFixture(t, strings.Repeat("a", 32), true, "198.18.0.20", "198.18.0.3", "2001:db8::20", "2001:db8::3")
				b = imageTransferSnapshotFixture(t, strings.Repeat("b", 32), true, "2001:db8::3", "198.18.0.3", "2001:db8::20", "198.18.0.20")
			case "different-endpoint":
				b = imageTransferSnapshotFixture(t, strings.Repeat("b", 32), true, "203.0.113.8", "2001:db8::7")
			case "home-lan":
				b = imageTransferSnapshotFixture(t, strings.Repeat("b", 32), false, "203.0.113.7", "2001:db8::7")
			case "same-session":
				b = a
			case "namespace":
				b.NamespaceInode++
			case "node-source":
				a = nodeStandardClosedSnapshotFixture(t, false)
			case "node-successor":
				b = nodeStandardClosedSnapshotFixture(t, false)
			case "widened-rule":
				var n desktopLinuxNFT
				_ = json.Unmarshal(b.Inventory, &n)
				n.Baseline[100] = []any{map[string]any{"accept": nil}}
				b.Inventory, _ = json.Marshal(n)
			}
			err := desktopLinuxImagePair(a, b)
			if (err == nil) != (scenario == "original" || scenario == "endpoint-order" || scenario == "multiple-address-order") {
				t.Fatal("image transfer accepted changed captured policy", err)
			}
		})
	}
}
func TestLinuxStandardImageTransferOriginalEndpointInventory(t *testing.T) {
	for _, home := range []bool{false, true} {
		s := imageTransferSnapshotFixture(t, strings.Repeat("a", 32), home, "2001:db8::20", "198.18.0.20", "2001:db8::3", "198.18.0.3")
		n, err := s.inventory()
		if err != nil {
			t.Fatal(err)
		}
		actual, err := desktopLinuxImageEndpoints(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(actual) != 4 || actual[0].String() != "198.18.0.3" || actual[1].String() != "198.18.0.20" || actual[2].String() != "2001:db8::3" || actual[3].String() != "2001:db8::20" {
			t.Fatal("original closed allowance extraction included LAN rules or lost endpoints", actual)
		}
		s.Endpoints = actual
		if err = s.Validate(); err != nil {
			t.Fatal("derived comparison data lost complete original inventory", err)
		}
	}
}

type imageTransferEnteredContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
}

func (c *imageTransferEnteredContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}
func TestLinuxStandardImageTransferCancellationKeepsOriginalPins(t *testing.T) {
	for _, scenario := range []string{"source-snapshot", "commit", "result", "finish", "successor-snapshot", "resolve"} {
		t.Run(scenario, func(t *testing.T) {
			id := strings.Repeat("d", 32)
			source := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: id, standard: true}
			target := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: id, standard: true}
			a := imageTransferSnapshotFixture(t, strings.Repeat("a", 32), false, "203.0.113.7")
			b := imageTransferSnapshotFixture(t, strings.Repeat("b", 32), false, "203.0.113.7")
			transfer := &DesktopLinuxStandardImageTransfer{source: source, id: id, snapshot: a}
			pin := &DesktopLinuxStandardImageSuccessorPin{owner: &DesktopLinuxStandardProtection{baseline: target}, id: id, snapshot: b}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &imageTransferEnteredContext{Context: base, entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				var err error
				switch scenario {
				case "source-snapshot":
					_, err = transfer.Snapshot(ctx)
				case "commit":
					err = transfer.Commit(ctx, b, nil)
				case "result":
					_, err = transfer.Result(ctx)
				case "finish":
					_, err = transfer.Finish(ctx)
				case "successor-snapshot":
					_, err = pin.Snapshot(ctx)
				case "resolve":
					err = pin.Resolve(ctx, a, true)
				}
				done <- err
			}()
			select {
			case <-ctx.entered:
			case <-time.After(time.Second):
				t.Fatal("actual method did not enter original held gate")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("original caller cancellation lost", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled observation remained behind original gate")
			}
			if source.crossTransfer != id || target.crossTransfer != id || transfer.finished || pin.released || source.removed || target.removed {
				t.Fatal("pure observer cancellation discarded original creator or pin")
			}
		})
	}
}

func TestLinuxStandardImageTransferUnknownResultRetainsOriginalPin(t *testing.T) {
	id := strings.Repeat("a", 32)
	unknown := errors.New("original conditional removal has no acknowledged result")
	b := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: id, standard: true, uncertain: unknown}
	b.gate <- struct{}{}
	transfer := &DesktopLinuxStandardImageTransfer{source: b, id: id}
	for _, observe := range []func(context.Context) (bool, error){transfer.Result, transfer.Finish} {
		committed, err := observe(context.Background())
		if committed || !errors.Is(err, unknown) || transfer.finished || b.crossTransfer != id {
			t.Fatal("unknown original removal manufactured a releasable result", committed, err)
		}
	}
}
