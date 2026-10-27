package multihoprelay

import (
	"math"
	"testing"
	"time"
)

func TestTorPaddingReceiptRequiresActualBoundedFreshChannelAccounting(t *testing.T) {
	capture, receipt, now := torReceiptFixture(t)
	receipt.HeartbeatAt, receipt.ProofAt = now.UnixMilli(), now.UnixMilli()
	receipt.Padding = &TorPaddingReceipt{Direction: "outgoing", Accounting: "tor-link-cell", Generation: 1, RateKbps: 192, ChannelCells: 5, ChannelBytes: 2570, ObservedAt: now.Add(-time.Millisecond).UnixMilli(), ExpiresAt: now.Add(2 * time.Second).UnixMilli()}
	if err := ValidateTorReceipt(receipt, capture, receipt.Nonce, now, now); err != nil {
		t.Fatal("valid authenticated outgoing-cover receipt rejected", err)
	}
	for name, mutate := range map[string]func(*TorReceipt){
		"bidirectional":         func(r *TorReceipt) { r.Padding.Direction = "both" },
		"physical-delivery":     func(r *TorReceipt) { r.Padding.Accounting = "wire" },
		"zero-generation":       func(r *TorReceipt) { r.Padding.Generation = 0 },
		"overflow-generation":   func(r *TorReceipt) { r.Padding.Generation = math.MaxUint64 },
		"small-rate":            func(r *TorReceipt) { r.Padding.RateKbps = 31 },
		"large-rate":            func(r *TorReceipt) { r.Padding.RateKbps = 193 },
		"no-channel":            func(r *TorReceipt) { r.Padding.ChannelCells = 0; r.Padding.ChannelBytes = 0 },
		"overflow-cells":        func(r *TorReceipt) { r.Padding.ChannelCells = math.MaxUint64 },
		"undersized-cells":      func(r *TorReceipt) { r.Padding.ChannelBytes = 2558 },
		"oversized-cells":       func(r *TorReceipt) { r.Padding.ChannelBytes = 2572 },
		"odd-cell-byte-count":   func(r *TorReceipt) { r.Padding.ChannelBytes = 2561 },
		"missing-observation":   func(r *TorReceipt) { r.Padding.ObservedAt = 0 },
		"future-observation":    func(r *TorReceipt) { r.Padding.ObservedAt = now.Add(time.Millisecond).UnixMilli() },
		"cached-observation":    func(r *TorReceipt) { r.Padding.ObservedAt = now.Add(-6 * time.Second).UnixMilli() },
		"expired":               func(r *TorReceipt) { r.Padding.ExpiresAt = now.UnixMilli() },
		"overlong-native-grant": func(r *TorReceipt) { r.Padding.ExpiresAt = now.Add(11 * time.Second).UnixMilli() },
		"outlived-path-proof":   func(r *TorReceipt) { r.ProofAt = now.Add(-29 * time.Second).UnixMilli() },
		"pending-cover": func(r *TorReceipt) {
			r.Phase = TorPending
			r.TrafficAllowed = false
			r.IsTor = false
			r.DNSProven = false
			r.ProofAt = 0
			r.ExitIP = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad, padding := receipt, *receipt.Padding
			bad.Padding = &padding
			mutate(&bad)
			if ValidateTorReceipt(bad, capture, receipt.Nonce, now, now) == nil {
				t.Fatal("unproved, unbounded or stale cover receipt gained traffic authority")
			}
		})
	}
}
