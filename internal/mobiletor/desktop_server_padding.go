package mobiletor

import (
	"context"
	"errors"
)

// PaddingLease binds the generic native owner to this already authenticated,
// enabled standalone child and its exact private source. It does not expose a
// control socket or allow the caller to select a different source/rate.
func (s *ServerTorSession) PaddingLease(parent context.Context, options PaddingLeaseOptions) (*PaddingLease, error) {
	if s == nil || s.owner == nil || s.policy == nil || !s.policy.Padding().Enabled || options.SourceSHA256 != s.policy.SourceSHA256() || options.RateKbps != s.policy.Padding().RateKbps || options.Current == nil {
		return nil, errors.New("server Tor cover requires its exact captured source and rate")
	}
	s.owner.operation.Lock()
	defer s.owner.operation.Unlock()
	if !s.Current() || s.paddingClaimed {
		return nil, errors.New("server Tor cover belongs to an unavailable or already claimed child")
	}
	current := options.Current
	options.Current = func() bool { return s.Current() && current() }
	lease, err := NewPaddingLease(parent, s.owner.control, options)
	if err != nil {
		return nil, err
	}
	s.paddingClaimed = true
	return lease, nil
}
