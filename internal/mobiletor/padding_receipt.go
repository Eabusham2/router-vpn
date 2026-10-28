package mobiletor

import (
	"errors"
	"math"
	"time"
)

const (
	PaddingProofMaxAge   = 30 * time.Second
	PaddingReceiptMaxAge = 5 * time.Second
)

// PaddingReceipt reports outgoing Tor link-cell accounting from one native
// lease. It is not physical delivery, a remote response or bidirectional cover.
// Hosts authenticate the containing session before accepting these fields.
type PaddingReceipt struct {
	Direction     string `json:"direction"`
	Accounting    string `json:"accounting"`
	SessionSHA256 string `json:"session_sha256"`
	SourceSHA256  string `json:"source_sha256"`
	Generation    uint64 `json:"generation"`
	RateKbps      int    `json:"rate_kbps"`
	ChannelCells  uint64 `json:"channel_cells"`
	ChannelBytes  uint64 `json:"channel_cell_bytes"`
	ObservedAt    int64  `json:"observed_at"`
	ExpiresAt     int64  `json:"expires_at"`
}

// ValidatePaddingReceipt checks an already authenticated native receipt
// against its exact source, session and selected rate. proofUntil must come
// from the completed path and selected-DNS proof, never a synthetic now+TTL.
// Success grants no authority to advance a previously observed generation or
// counters; the host also retains and compares its prior receipt on refresh.
func ValidatePaddingReceipt(receipt *PaddingReceipt, policy TorPaddingPolicy, sessionSHA, sourceSHA string, proofUntil, now time.Time) error {
	bad := errors.New("Tor padding receipt differs from its captured policy, native owner or proof lifetime")
	if policy.RateKbps != 0 && (policy.RateKbps < PaddingMinRateKbps || policy.RateKbps > PaddingMaxRateKbps) {
		return bad
	}
	if !policy.Enabled {
		if receipt != nil {
			return bad
		}
		return nil
	}
	if receipt == nil || policy.RateKbps == 0 || !paddingHex(sessionSHA, 64) || !paddingHex(sourceSHA, 64) ||
		receipt.Direction != "outgoing" || receipt.Accounting != "tor-link-cell" || receipt.SessionSHA256 != sessionSHA || receipt.SourceSHA256 != sourceSHA ||
		receipt.Generation == 0 || receipt.Generation > math.MaxInt64 || receipt.RateKbps != policy.RateKbps || receipt.ChannelCells == 0 || receipt.ChannelCells > math.MaxUint64/514 ||
		receipt.ChannelBytes < receipt.ChannelCells*512 || receipt.ChannelBytes > receipt.ChannelCells*514 || receipt.ChannelBytes%2 != 0 || receipt.ObservedAt <= 0 || receipt.ExpiresAt <= 0 || now.IsZero() || proofUntil.IsZero() {
		return bad
	}
	observed, expires := time.UnixMilli(receipt.ObservedAt), time.UnixMilli(receipt.ExpiresAt)
	if observed.After(now) || now.Sub(observed) > PaddingReceiptMaxAge || !expires.After(now) ||
		expires.After(observed.Add(PaddingMaxTTL)) || expires.After(proofUntil) {
		return bad
	}
	return nil
}

// NativeReceipt retains the actual observation and grant deadlines instead of
// relabeling a cached counter as fresh. It returns a copy, never the lease's
// mutable status, and cannot make an unstarted or retired owner healthy.
func (l *PaddingLease) NativeReceipt() (*PaddingReceipt, bool) {
	status, observed, expires, valid := l.Receipt()
	if !valid {
		return nil, false
	}
	receipt := &PaddingReceipt{Direction: "outgoing", Accounting: "tor-link-cell",
		SessionSHA256: status.Identity.SessionSHA256, SourceSHA256: status.Identity.SourceSHA256, Generation: status.Identity.Generation,
		RateKbps: status.RateKbps, ChannelCells: status.ChannelCells, ChannelBytes: status.ChannelBytes,
		ObservedAt: observed.UnixMilli(), ExpiresAt: expires.UnixMilli()}
	policy := TorPaddingPolicy{Enabled: true, RateKbps: l.options.RateKbps}
	if ValidatePaddingReceipt(receipt, policy, l.options.SessionSHA256, l.options.SourceSHA256, l.options.ProofValidUntil(), time.Now()) != nil {
		return nil, false
	}
	return receipt, true
}
