//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/systembootstrap"
	"time"
)

// The original machine NSS/hosts/direct resolver capture is independent of
// selected in-tunnel DNS. Local resolved stubs require their authenticated
// per-link policy; an upstream-file list is never an equivalent substitute.
type linuxBootResolver struct {
	policy *systembootstrap.Capture
	helper *linuxResolvedHelper
}

func captureLinuxBootResolver(ctx context.Context, hostname string) (*linuxBootResolver, error) {
	policy, e := systembootstrap.CaptureSystemResolved(ctx, hostname)
	if e != nil {
		return nil, e
	}
	return &linuxBootResolver{policy: policy}, nil
}
func captureLinuxBootResolverAt(ctx context.Context, hostname string, paths [3]string) (*linuxBootResolver, error) {
	policy, e := systembootstrap.CaptureFiles(ctx, hostname, paths)
	if e != nil {
		return nil, e
	}
	return &linuxBootResolver{policy: policy}, nil
}
func (r *linuxBootResolver) current(ctx context.Context) error {
	if r == nil || r.policy == nil {
		return errors.New("bootstrap resolver capture is incomplete")
	}
	if err := r.policy.Current(ctx); err != nil {
		return err
	}
	if r.helper != nil {
		return r.helper.current(ctx)
	}
	return nil
}
func (r *linuxBootResolver) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return r.closeContext(ctx)
}
func (r *linuxBootResolver) closeContext(ctx context.Context) error {
	if r == nil || r.policy == nil {
		return nil
	}
	if r.helper != nil {
		if err := r.helper.Close(ctx); err != nil {
			return err
		}
	}
	return r.policy.Close()
}
