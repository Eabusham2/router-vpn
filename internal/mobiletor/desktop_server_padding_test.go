package mobiletor

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerTorPaddingLeaseUsesOnlyEnabledAuthenticatedExactSource(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge"} {
		t.Run(mode, func(t *testing.T) {
			source := serverTorSource(mode)
			source["padding"] = map[string]any{"enabled": true, "rate_kbps": 192}
			policy := serverTorPolicy(t, source)
			var starts atomic.Int32
			f := newServerTorSessionFixture(t, mode, func(command, reply string) string {
				if command == "ROUTERVPN_PADDING INFO" {
					return paddingTestReply(paddingTestCapability)
				}
				if !strings.HasPrefix(command, "ROUTERVPN_PADDING ") {
					return reply
				}
				state := "running"
				if strings.HasPrefix(command, "ROUTERVPN_PADDING START ") {
					starts.Add(1)
					if !strings.Contains(command, policy.SourceSHA256()) || !strings.HasSuffix(command, " "+strings.Repeat("c", 64)+" "+strings.Repeat("d", 64)) {
						t.Error("native padding command changed captured source or actual SOCKS identity")
					}
				}
				if strings.HasPrefix(command, "ROUTERVPN_PADDING STOP ") {
					state = "stopped"
				}
				return paddingTestReply(paddingTestReplace(paddingTestStatus(state), "source", policy.SourceSHA256()))
			}, policy)
			until := time.Now().Add(30 * time.Second)
			var retired atomic.Bool
			options := PaddingLeaseOptions{SessionSHA256: paddingTestIdentity.SessionSHA256, SourceSHA256: policy.SourceSHA256(), RateKbps: 192,
				Username: strings.Repeat("c", 64), Password: strings.Repeat("d", 64), Current: f.session.Current,
				ProofValidUntil: func() time.Time { return until }, Retire: func(error) { retired.Store(true) }}
			before := len(f.wire.snapshot())
			if _, err := f.session.PaddingLease(t.Context(), options); err == nil || len(f.wire.snapshot()) != before {
				t.Fatal("disabled/unproved child admitted a cover owner or issued a command")
			}
			f.start(t)
			before = len(f.wire.snapshot())
			for name, change := range map[string]func(*PaddingLeaseOptions){
				"source":       func(o *PaddingLeaseOptions) { o.SourceSHA256 = strings.Repeat("f", 64) },
				"rate":         func(o *PaddingLeaseOptions) { o.RateKbps = 32 },
				"front-secret": func(o *PaddingLeaseOptions) { o.Username = strings.Repeat("c", 48) },
				"no-witness":   func(o *PaddingLeaseOptions) { o.Current = nil },
			} {
				wrong := options
				change(&wrong)
				if _, err := f.session.PaddingLease(t.Context(), wrong); err == nil || len(f.wire.snapshot()) != before {
					t.Fatal("unowned cover selection reached the authenticated child", name)
				}
			}
			lease, err := f.session.PaddingLease(t.Context(), options)
			if err != nil || len(f.wire.snapshot()) != before {
				t.Fatal("capturing the policy unexpectedly performed network I/O", err)
			}
			if _, err := f.session.PaddingLease(t.Context(), options); err == nil {
				t.Fatal("second cover controller borrowed the owned child")
			}
			f.mutate.Store(true)
			if err := lease.Start(t.Context()); err != nil || !lease.Healthy() || starts.Load() != 1 {
				t.Fatal("exact authenticated wire receipt did not reach cover owner", err)
			}
			lease.Cancel()
			if err := f.session.Quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(context.Background()); err != nil || lease.Healthy() || retired.Load() {
				t.Fatal("owned quiescence/STOP did not drain normal cover cancellation", err)
			}
		})
	}
}

func TestServerTorPaddingOffCannotBorrowAnEnabledRuntimeOwner(t *testing.T) {
	f := newServerTorSessionFixture(t, "tor", nil)
	f.start(t)
	options := PaddingLeaseOptions{SessionSHA256: paddingTestIdentity.SessionSHA256, SourceSHA256: f.session.SourceSHA256(), RateKbps: 192,
		Username: strings.Repeat("c", 64), Password: strings.Repeat("d", 64), Current: f.session.Current,
		ProofValidUntil: func() time.Time { return time.Time{} }, Retire: func(error) {}}
	before := len(f.wire.snapshot())
	if _, err := f.session.PaddingLease(t.Context(), options); err == nil || len(f.wire.snapshot()) != before {
		t.Fatal("Off source acquired an unrequested native cover lease")
	}
}
