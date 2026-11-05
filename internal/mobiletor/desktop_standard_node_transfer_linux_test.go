//go:build linux

package mobiletor

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func standardNodeSnapshotFixture(t *testing.T) DesktopLinuxNodeTransferSnapshot {
	t.Helper()
	c := desktopSocketFixtureCapture()
	n := desktopLinuxNFTForCapture(c, true)
	n.TableName = desktopLinuxNodeTable(c)
	n.TableHandle = 11
	n.ChainHandle = 12
	n.UID = 55001
	n.Prefix = "rvpn_" + strings.Repeat("a", 20)
	n.Rules = map[string]uint64{"tcp4": 21, "udp4": 22, "tcp6": 23, "udp6": 24}
	n.Sets = map[string]uint64{"tcp4": 31, "udp4": 32, "tcp6": 33, "udp6": 34}
	n.Baseline = map[uint64]any{}
	for i, expression := range desktopLinuxBaselineExpressions(DesktopLinuxSocketOptions{}) {
		n.Baseline[uint64(i+100)] = expression
	}
	baseline, _ := json.Marshal(n.Baseline)
	raw, _ := json.Marshal(n)
	record := DesktopLinuxProtectionRecord{Capture: c, Owner: desktopSocketFixturePolicy().owner, UID: n.UID, PermitPrefix: n.Prefix, TableName: n.TableName, TableHandle: n.TableHandle, ChainHandle: n.ChainHandle, BaselineSHA256: desktopLinuxBaselineDigest(baseline)}
	return DesktopLinuxNodeTransferSnapshot{Record: record, Inventory: raw}
}
func TestLinuxStandardNodeTransferRejectsChangedInventory(t *testing.T) {
	for _, name := range []string{"original", "session", "handle", "uid", "baseline", "home-lan", "unknown-field", "noncanonical", "widened-baseline"} {
		t.Run(name, func(t *testing.T) {
			snapshot := standardNodeSnapshotFixture(t)
			switch name {
			case "session":
				snapshot.Record.Capture.SessionID = strings.Repeat("f", 32)
			case "handle":
				snapshot.Record.TableHandle++
			case "uid":
				snapshot.Record.UID++
			case "baseline":
				snapshot.Record.BaselineSHA256 = strings.Repeat("f", 64)
			case "home-lan":
				snapshot.HomeLAN = true
			case "unknown-field":
				snapshot.Inventory = append(snapshot.Inventory[:len(snapshot.Inventory)-1], []byte(`,"unowned":true}`)...)
			case "noncanonical":
				snapshot.Inventory = append([]byte(" "), snapshot.Inventory...)
			case "widened-baseline":
				var n desktopLinuxNFT
				_ = json.Unmarshal(snapshot.Inventory, &n)
				n.Baseline[100] = []any{map[string]any{"accept": nil}}
				raw, _ := json.Marshal(n.Baseline)
				snapshot.Record.BaselineSHA256 = desktopLinuxBaselineDigest(raw)
				snapshot.Inventory, _ = json.Marshal(n)
			}
			_, err := snapshot.inventory()
			if (err == nil) != (name == "original") {
				t.Fatal("changed original destination accepted", err)
			}
		})
	}
}
func TestLinuxStandardNodeTransferUnknownResultRetainsPins(t *testing.T) {
	for _, name := range []string{"unknown-removal", "cancelled-finish", "closed-creator"} {
		t.Run(name, func(t *testing.T) {
			b := &DesktopLinuxNodeBaseline{gate: make(chan struct{}, 1), crossTransfer: strings.Repeat("a", 32)}
			b.gate <- struct{}{}
			x := &DesktopLinuxStandardNodeTransfer{source: &DesktopLinuxStandardProtection{baseline: b}, id: b.crossTransfer}
			ctx := context.Background()
			switch name {
			case "unknown-removal":
				b.uncertain = errors.New("original unacknowledged kernel outcome")
			case "closed-creator":
				b.closed = true
			case "cancelled-finish":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if committed, err := x.Finish(ctx); err == nil || committed || x.finished || b.crossTransfer != x.id {
				t.Fatal("unknown result fabricated settlement", committed, err)
			}
		})
	}
}
