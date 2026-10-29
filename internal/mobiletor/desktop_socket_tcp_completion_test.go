package mobiletor

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDesktopSocketTCPPendingWaitsForCompletionBeforePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	remote := netip.MustParseAddrPort("198.51.100.32:443")
	entered, complete, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var completed atomic.Bool
	var statusCalls, peerCalls atomic.Int32
	go func() {
		done <- desktopSocketCompleteTCP(ctx, true, remote, func(ctx context.Context) error {
			close(entered)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-complete:
				completed.Store(true)
				return nil
			}
		}, func() error {
			statusCalls.Add(1)
			if !completed.Load() {
				return errors.New("SO_ERROR read before writable completion")
			}
			return nil
		}, func() (netip.AddrPort, error) {
			peerCalls.Add(1)
			// A provider can already expose the intended target. That cached
			// address is deliberately valid even while Connect is pending.
			return remote, nil
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("pending connect skipped its completion witness: %v", err)
	case <-ctx.Done():
		t.Fatal("pending connect never entered its completion wait")
	}
	if statusCalls.Load() != 0 || peerCalls.Load() != 0 {
		t.Fatal("pending connect inspected status or peer before completion")
	}
	select {
	case err := <-done:
		t.Fatalf("pending connect completed while its kernel witness was held: %v", err)
	default:
	}
	close(complete)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("completed connect did not join")
	}
	if statusCalls.Load() != 1 || peerCalls.Load() != 1 {
		t.Fatal("connected peer bypassed exactly one status and peer readback")
	}
}

func TestDesktopSocketTCPCompletionRejectsEveryFailedStage(t *testing.T) {
	remote := netip.MustParseAddrPort("[2001:db8::32]:443")
	failed := errors.New("captured native failure")
	for _, tc := range []struct {
		name     string
		pending  bool
		fail     string
		cancelAt string
		want     []string
	}{
		{"immediate", false, "", "", []string{"status", "peer"}},
		{"pending", true, "", "", []string{"wait", "status", "peer"}},
		{"poll_failure", true, "wait", "", []string{"wait"}},
		{"socket_failure", true, "status", "", []string{"wait", "status"}},
		{"peer_failure", true, "peer", "", []string{"wait", "status", "peer"}},
		{"wrong_peer", true, "target", "", []string{"wait", "status", "peer"}},
		{"cancel_before", true, "", "before", nil},
		{"cancel_wait", true, "", "wait", []string{"wait"}},
		{"cancel_status", true, "", "status", []string{"wait", "status"}},
		{"cancel_peer", true, "", "peer", []string{"wait", "status", "peer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelAt == "before" {
				cancel()
			}
			var observed []string
			stage := func(name string) error {
				observed = append(observed, name)
				if tc.cancelAt == name {
					cancel()
				}
				if tc.fail == name {
					return failed
				}
				return nil
			}
			err := desktopSocketCompleteTCP(ctx, tc.pending, remote, func(context.Context) error {
				return stage("wait")
			}, func() error {
				return stage("status")
			}, func() (netip.AddrPort, error) {
				actual := remote
				if tc.fail == "target" {
					actual = netip.MustParseAddrPort("[2001:db8::33]:443")
				}
				return actual, stage("peer")
			})
			if !reflect.DeepEqual(observed, tc.want) {
				t.Fatalf("completion continued across an unproved stage: got %v want %v", observed, tc.want)
			}
			switch {
			case tc.cancelAt != "":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled completion returned %v", err)
				}
			case tc.fail == "target":
				if err == nil || !strings.Contains(err.Error(), "connected peer changed") {
					t.Fatalf("wrong peer completed: %v", err)
				}
			case tc.fail != "":
				if !errors.Is(err, failed) {
					t.Fatalf("native completion error was lost: %v", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
