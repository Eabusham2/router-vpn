package multihoprelay

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestCancelledLeaseRequestHasNoStartOrRenewalEffects(t *testing.T) {
	for _, renew := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			t.Run(map[bool]string{false: "create", true: "renew"}[renew]+"/"+map[bool]string{false: "cancelled", true: "deadline"}[expired], func(t *testing.T) {
				m, runner := manager(t)
				defer m.Close(context.Background())
				now := time.Unix(1000, 0)
				m.now = func() time.Time { return now }
				peer := netip.MustParseAddr("10.77.0.2")
				var original Lease
				if renew {
					var err error
					original, err = m.Create(context.Background(), peer, req())
					if err != nil {
						t.Fatal(err)
					}
				}
				starts := runner.starts
				now = now.Add(5 * time.Second)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				want := context.Canceled
				if expired {
					ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer cancel()
					want = context.DeadlineExceeded
				}
				lease, err := m.Create(ctx, peer, req())
				if !errors.Is(err, want) || lease != (Lease{}) {
					t.Fatalf("cancelled operation returned lease or wrong error: %v", err)
				}
				if runner.starts != starts {
					t.Fatal("cancelled operation started an engine")
				}
				if renew {
					if m.leases[PeerKey(peer)].Lease != original || !runner.processes[0].alive || runner.processes[0].stops != 0 {
						t.Fatal("cancelled renewal altered the existing lease")
					}
				} else if len(m.leases) != 0 {
					t.Fatal("cancelled creation retained new ownership")
				}
			})
		}
	}
}

type cancelAfterStop struct {
	*process
	cancel context.CancelFunc
}

func (p *cancelAfterStop) Stop(ctx context.Context) error {
	err := p.process.Stop(ctx)
	p.cancel()
	return err
}

func TestCancellationDuringExpiryCleanupDoesNotStartAnotherEngine(t *testing.T) {
	m, runner := manager(t)
	defer m.Close(context.Background())
	now := time.Unix(1000, 0)
	m.now = func() time.Time { return now }
	peer := netip.MustParseAddr("10.77.0.2")
	if _, err := m.Create(context.Background(), peer, req()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.leases[PeerKey(peer)].p = &cancelAfterStop{runner.processes[0], cancel}
	now = now.Add(time.Minute)
	if _, err := m.Create(ctx, peer.Next(), req()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request resumed after cleanup", err)
	}
	if runner.starts != 1 || runner.processes[0].alive || len(m.leases) != 0 {
		t.Fatal("cancelled request created a replacement or retained an expired engine")
	}
}

type cancellingRunner struct {
	process *process
	cancel  context.CancelFunc
	starts  int
}

func (r *cancellingRunner) Start(context.Context, []byte, Lease) (Process, error) {
	r.starts++
	r.cancel()
	return r.process, nil
}

func TestCancellationDuringStartupStillOwnsUnconfirmedCleanup(t *testing.T) {
	for _, stopFails := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		p := &process{alive: true, stopFail: stopFails}
		r := &cancellingRunner{process: p, cancel: cancel}
		m, err := New(config(), req().EntryNodeID, r)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if lease, err := m.Create(ctx, netip.MustParseAddr("10.77.0.2"), req()); err == nil || lease != (Lease{}) {
			t.Fatal("cancelled startup returned a successful lease")
		}
		cancel()
		if r.starts != 1 || p.stops != 1 || p.alive != stopFails || (len(m.leases) == 1) != stopFails {
			t.Fatal("cancelled startup lost ownership before cleanup was confirmed")
		}
		p.stopFail = false
		if err := m.Close(context.Background()); err != nil || p.alive || len(m.leases) != 0 {
			t.Fatal("cancelled startup cleanup could not be completed", err)
		}
	}
}
