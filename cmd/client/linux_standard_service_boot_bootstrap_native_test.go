//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLinuxStandardServiceBootBootstrapServiceKeepsOriginalAdmission(t *testing.T) {
	for _, name := range []string{"no-boot", "image-reserved", "image-frozen", "image-settled", "failed-boot", "pending-transfer", "cross-scope", "cancel-before-admission", "held-gate", "cleanup-tombstone"} {
		t.Run(name, func(t *testing.T) {
			peer, channel, _ := linuxStandardPeerFixture(t)
			defer channel.Close()
			defer peer.Close()
			image, _ := os.Stat("/proc/self/exe")
			namespace, _ := os.Stat("/proc/thread-self/ns/net")
			s := newLinuxStandardService(t.TempDir(), image, namespace)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			q := bootBootstrapRequestFixture()
			switch name {
			case "image-reserved":
				s.imageUpgrade = &linuxStandardImageUpgrade{phase: "reserved"}
			case "image-frozen":
				s.imageUpgrade = &linuxStandardImageUpgrade{phase: "frozen"}
			case "image-settled":
				s.imageUpgrade = &linuxStandardImageUpgrade{phase: "settled"}
			case "failed-boot":
				s.bootFailure = errors.New("original failed boot")
			case "pending-transfer":
				s.transfer = &linuxStandardServiceTransfer{}
			case "cross-scope":
				q.MTU = &linuxStandardServiceMTURequest{}
			case "cancel-before-admission":
				cancel()
			case "held-gate":
				<-s.gate
				defer func() { s.gate <- struct{}{} }()
				short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
				defer stop()
				ctx = short
			case "cleanup-tombstone":
				q.Action = "boot-bootstrap-cleanup"
			}
			out, e := s.bootBootstrapRequest(ctx, peer, q)
			if name == "no-boot" || name == "image-settled" {
				if e != nil || out == nil || !out.NoBoot || !out.Clean || len(out.Addresses) != 0 {
					t.Fatal(out, e)
				}
			} else if name == "cleanup-tombstone" {
				if e != nil || out == nil || !out.Clean {
					t.Fatal(out, e)
				}
				q.Action = "boot-bootstrap"
				if _, e = s.bootBootstrapRequest(ctx, peer, q); e == nil {
					t.Fatal("overtaken query restarted after original cleanup")
				}
			} else {
				if e == nil || out != nil {
					t.Fatal("unadmitted request became hostname evidence", out, e)
				}
				if name == "held-gate" && !errors.Is(e, context.DeadlineExceeded) {
					t.Fatal(e)
				}
			}
			if s.bootstrap != nil {
				t.Fatal("refused/absent boot allocated native authority")
			}
		})
	}
}

type bootPeerCancelDuringClose struct {
	context.Context
	cancel context.CancelFunc
	reads  int
}

func (c *bootPeerCancelDuringClose) Err() error {
	c.reads++
	if c.reads == 2 {
		c.cancel()
	}
	return c.Context.Err()
}
func TestLinuxStandardServiceBootBootstrapPeerCleanupRetainsAcknowledgedClose(t *testing.T) {
	for _, name := range []string{"cancel-before-close", "partial-close"} {
		t.Run(name, func(t *testing.T) {
			peer, channel, _ := linuxStandardPeerFixture(t)
			defer channel.Close()
			defer peer.Close()
			originalTask, command, pidfd := peer.task, peer.command, peer.pidfd
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			var call context.Context = parent
			if name == "cancel-before-close" {
				cancel()
			} else {
				call = &bootPeerCancelDuringClose{Context: parent, cancel: cancel}
			}
			a := &app{}
			b := &linuxStandardBootBootstrapClient{app: a, peer: peer, attempted: true, cleanupAcknowledged: true}
			linuxStandardBootBootstraps.Store(a, b)
			defer linuxStandardBootBootstraps.Delete(a)
			if e := b.cleanup(call); !errors.Is(e, context.Canceled) {
				t.Fatal("original close cancellation changed", e)
			}
			if b.closed.Load() || peer.task != originalTask || peer.command != command || peer.pidfd != pidfd {
				t.Fatal("expired close discarded retained original descriptors")
			}
			if name == "cancel-before-close" {
				ctx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if e := peer.Current(ctx); e != nil {
					t.Fatal("canceled admission damaged live peer", e)
				}
			}
			// No parent/RPC capability is installed in this local finalization fixture.
			// Repeating network cleanup or lookup would fail instead of joining these
			// actual original descriptors after the authenticated clean milestone.
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if e := b.cleanup(ctx); e != nil {
				t.Fatal("acknowledged original close could not finish locally", e)
			}
			if !b.closed.Load() || peer.task != nil || peer.command != nil || peer.pidfd != nil {
				t.Fatal("partial original close did not join")
			}
			if _, ok := linuxStandardBootBootstraps.Load(a); ok {
				t.Fatal("joined close retained admission")
			}
		})
	}
}

func TestLinuxStandardServiceBootBootstrapDeadPeerCleanupClock(t *testing.T) {
	for _, mode := range []string{"live", "retired", "cancelled-observer", "expired-retirement", "foreign-pidfd"} {
		t.Run(mode, func(t *testing.T) {
			peer, _, stop := linuxStandardPeerFixture(t)
			original := &linuxStandardServiceBootBootstrap{peer: peer}
			if mode != "live" {
				stop()
			}
			// The observation begins after actual child join; child shutdown
			// is not allowed to consume or renew the retirement call budget.
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "cancelled-observer" {
				cancel()
			}
			if mode == "foreign-pidfd" {
				old := peer.pidfd
				peer.pidfd = nil
				defer func() { peer.pidfd = old }()
			}
			if mode == "expired-retirement" {
				original.retirementDeadline = time.Now().Add(-time.Second)
			}
			before := original.retirementDeadline
			ctx, finish, e := original.retirementContext(parent)
			if finish != nil {
				defer finish()
			}
			switch mode {
			case "live":
				if ctx != nil || e != nil || !original.retirementDeadline.IsZero() {
					t.Fatal("live peer admitted cleanup", e)
				}
			case "cancelled-observer", "foreign-pidfd":
				if ctx != nil || e == nil || !original.retirementDeadline.IsZero() {
					t.Fatal("unproved retirement created cleanup authority", e)
				}
			case "expired-retirement":
				if ctx != nil || !errors.Is(e, context.DeadlineExceeded) || original.retirementDeadline != before {
					t.Fatal("retirement renewed expired cleanup", e)
				}
			case "retired":
				if e != nil || ctx == nil {
					t.Fatal("actual joined original peer cannot retire cleanup", e)
				}
				first := original.retirementDeadline
				bound, _ := ctx.Deadline()
				outer, _ := parent.Deadline()
				if bound != outer || first.Before(outer) || first.After(time.Now().Add(30*time.Second)) {
					t.Fatal("cleanup ignored original caller or implementation cap")
				}
				next, release, e := original.retirementContext(parent)
				if release != nil {
					defer release()
				}
				if e != nil || next == nil || original.retirementDeadline != first {
					t.Fatal("retry renewed original retirement clock", e)
				}
			}
		})
	}
}
