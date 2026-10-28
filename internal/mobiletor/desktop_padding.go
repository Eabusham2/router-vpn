package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

const (
	DesktopTorPaddingOutboundType   = "routervpn-desktop-tor-padding"
	DesktopTorPaddingDNSType        = "routervpn-desktop-tor-padding-dns"
	DesktopTorPaddingDNSUpstreamTag = "routervpn-tor-dns-transport"
)

// DesktopBridgePaddingProof keeps repeated path/DNS verification separate from
// the immutable initial connection proof. Each observation belongs to the same
// captured native source; its deadline uses the older completed measurement.
type DesktopBridgePaddingProof struct {
	Proof        Proof     `json:"proof"`
	DNSCheckedAt time.Time `json:"dns_checked_at"`
}

func (m DesktopBridgeMetadata) PaddingProofUntil(proof *DesktopBridgePaddingProof, started, now time.Time) (time.Time, error) {
	bad := errors.New("desktop Tor padding has no fresh captured exit and selected-DNS proof")
	if proof == nil || !m.Padding.Enabled || m.Execution != "" || started.IsZero() || now.IsZero() ||
		proof.Proof.SessionID != m.SessionID || !proof.Proof.IsTor || !proof.Proof.DNSProven ||
		proof.DNSCheckedAt.IsZero() || proof.Proof.CheckedAt.IsZero() || proof.DNSCheckedAt.Before(started.Add(-time.Second)) ||
		proof.DNSCheckedAt.After(now) || proof.Proof.CheckedAt.Before(proof.DNSCheckedAt) || proof.Proof.CheckedAt.After(now) {
		return time.Time{}, bad
	}
	address, err := netip.ParseAddr(proof.Proof.IP)
	if err != nil || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.String() != proof.Proof.IP {
		return time.Time{}, bad
	}
	until := proof.DNSCheckedAt.Add(PaddingProofMaxAge)
	if !until.After(now) {
		return time.Time{}, bad
	}
	return until, nil
}

// ValidatePaddingProof is shared by the native command and its independent
// desktop controller. Server cover retains its separate authenticated lease
// receipt; neither Server nor Off may borrow a Local native padding receipt.
func (m DesktopBridgeMetadata) ValidatePaddingProof(receipt *PaddingReceipt, proof *DesktopBridgePaddingProof, started, now time.Time) error {
	if m.Execution == "server" || !m.Padding.Enabled {
		if receipt != nil || proof != nil {
			return errors.New("unrequested desktop Local Tor padding receipt")
		}
		return nil
	}
	until, err := m.PaddingProofUntil(proof, started, now)
	if err != nil {
		return err
	}
	return ValidatePaddingReceipt(receipt, m.Padding, desktopDigest([]byte(m.SessionID)), m.SourceSHA256, until, now)
}

// ValidateDesktopPaddingProgress rejects a replacement generation or an older
// observation after an independently authenticated receipt has been retained.
// Repeated snapshots are permitted; they never extend their actual deadlines.
func ValidateDesktopPaddingProgress(previous, current *PaddingReceipt, oldProof, newProof *DesktopBridgePaddingProof) error {
	if previous == nil {
		return nil
	}
	if current == nil || oldProof == nil || newProof == nil || current.SessionSHA256 != previous.SessionSHA256 || current.SourceSHA256 != previous.SourceSHA256 ||
		current.Generation != previous.Generation || current.RateKbps != previous.RateKbps || current.ObservedAt < previous.ObservedAt ||
		current.ChannelCells < previous.ChannelCells || current.ChannelBytes < previous.ChannelBytes ||
		newProof.DNSCheckedAt.Before(oldProof.DNSCheckedAt) || newProof.Proof.CheckedAt.Before(oldProof.Proof.CheckedAt) {
		return errors.New("desktop Tor padding receipt or fresh proof regressed or changed native owner")
	}
	return nil
}

// PaddingLease binds the actual standalone child's isolation credentials and
// one immutable Local policy. Construction sends no command and proves no
// path: the native host supplies its real completed proof and retains the
// lease until control work and the exact child process have been joined.
func (s *DesktopBridgeSession) PaddingLease(parent context.Context, options PaddingLeaseOptions) (*PaddingLease, error) {
	if s == nil || s.owner == nil || s.metadata.Execution != "" || !s.metadata.Padding.Enabled || options.Current == nil ||
		options.SessionSHA256 != desktopDigest([]byte(s.metadata.SessionID)) || options.SourceSHA256 != s.metadata.SourceSHA256 || options.RateKbps != s.metadata.Padding.RateKbps ||
		options.Username != "" && options.Username != s.metadata.SessionID || options.Password != "" && options.Password != s.isolation {
		return nil, errors.New("desktop Tor padding requires its exact captured source, rate and SOCKS isolation")
	}
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if !s.Current() || s.paddingClaimed {
		return nil, errors.New("desktop Tor padding belongs to an unavailable or already claimed child")
	}
	current := options.Current
	options.Current = func() bool { return s.Current() && current() }
	options.Username, options.Password = s.metadata.SessionID, s.isolation
	lease, err := NewPaddingLease(parent, s.owner.control, options)
	if err != nil {
		return nil, err
	}
	s.paddingClaimed = true
	s.padding = lease
	return lease, nil
}
