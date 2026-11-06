//go:build linux

package main

import (
	"context"
	"errors"
	"router-vpn/internal/standardengine"
	"testing"
	"time"
)

type resolvedDNSSECOwnerFixture struct {
	policy               standardengine.ResolvedPolicy
	reads, observations  int
	changed, lost, local bool
	stop                 context.CancelFunc
}

func (o *resolvedDNSSECOwnerFixture) observeScoped(ctx, original context.Context, name string) (standardengine.ResolvedPolicy, standardengine.ResolvedLocalResult, error) {
	o.observations++
	if o.lost {
		return o.policy, standardengine.ResolvedLocalResult{}, errors.New("original daemon disappeared")
	}
	return o.policy, standardengine.ResolvedLocalResult{Local: o.local}, ctx.Err()
}
func (o *resolvedDNSSECOwnerFixture) anchorScoped(ctx, original context.Context, index int32, name string, kind uint16) (standardengine.ResolvedAnchorResult, error) {
	o.reads++
	raw, _ := o.policy.Canonical()
	row := standardengine.ResolvedAnchorResult{PolicySHA256: standardengine.ResolvedPolicySHA256(raw), Index: index, Name: name, Type: kind}
	if o.changed && name == "." && kind == 43 {
		row.Present = true
		row.Flags = standardengine.ResolvedAnchorFlags
		row.Records = [][]byte{append([]byte{0, 0, 43, 0, 1, 0, 0, 0, 0, 0, 36, 0x4f, 0x66, 8, 2}, make([]byte, 32)...)}
	}
	if o.stop != nil {
		o.stop()
		o.stop = nil
	}
	return row, ctx.Err()
}
func TestResolvedDNSSECCollectorOriginalOwner(t *testing.T) {
	for _, name := range []string{"all-suffixes-and-absence", "absent-anchor-changed", "daemon-lost", "local-decision-changed", "cancelled-original"} {
		t.Run(name, func(t *testing.T) {
			original, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			policy := resolvedAdapterPolicy()
			policy.Manager.DNSSEC = "yes"
			owner := &resolvedDNSSECOwnerFixture{policy: policy}
			if name == "cancelled-original" {
				owner.stop = stop
			}
			plan, err := captureLinuxResolvedDNSSECPlan(original, original, owner, policy, "vpn.example", 0)
			if name == "cancelled-original" {
				if err == nil || plan != nil {
					t.Fatal("cancelled original yielded plan")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if owner.reads != 6 || owner.observations != 2 {
				t.Fatal("exact suffix/original-policy observations omitted", owner.reads, owner.observations)
			}
			switch name {
			case "absent-anchor-changed":
				owner.changed = true
			case "daemon-lost":
				owner.lost = true
			case "local-decision-changed":
				owner.local = true
			}
			err = recheckLinuxResolvedDNSSECPlan(original, original, owner, policy, plan)
			if name == "all-suffixes-and-absence" {
				if err != nil || owner.reads != 12 || owner.observations != 4 {
					t.Fatal("full original recheck omitted", err, owner.reads, owner.observations)
				}
			} else if err == nil {
				t.Fatal("changed original authority accepted")
			}
		})
	}
}

func TestResolvedDNSSECAnchorCancelledAdmission(t *testing.T) {
	original, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	scope, cancel := context.WithCancel(original)
	defer cancel()
	helper := &linuxResolvedHelper{}
	helper.mu.Lock()
	locked := true
	defer func() {
		if locked {
			helper.mu.Unlock()
		}
	}()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() { close(started); _, err := helper.anchorScoped(scope, original, 0, ".", 43); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled scope entered shared anchor stream", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("cancelled scope waited on original-operation frame lock")
	}
	if helper.failure != nil || helper.sequence != 0 {
		t.Fatal("unadmitted cancellation tainted or advanced helper")
	}
	helper.mu.Unlock()
	locked = false
}
