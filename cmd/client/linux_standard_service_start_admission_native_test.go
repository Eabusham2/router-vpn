//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The existing fixture retains real source files, original process peers and
// startup observers. Held metadata locks are explicit synchronization models;
// no RPC or native constructor is allowed to escape these admission cases.
func TestLinuxStandardServiceStartKeepsOriginalAdmission(t *testing.T) {
	for _, mode := range []string{"application", "prior-owner", "post-reply"} {
		t.Run(mode, func(t *testing.T) {
			_, f, owner, _, original := linuxStandardControllerEpochFixture(t)
			var calls atomic.Int32
			owner.exchange = func(context.Context, linuxStandardServiceRequest, *os.File, func()) (linuxStandardServiceResponse, error) {
				calls.Add(1)
				return linuxStandardServiceResponse{}, errors.New("unexpected RPC beyond held original admission")
			}
			var held *sync.Mutex
			var prior *linuxStandardServiceLaunch
			var peer *linuxStandardServicePeer
			if mode == "prior-owner" {
				peer, _, _ = linuxStandardPeerFixture(t)
				prior = &linuxStandardServiceLaunch{app: f.a, joined: true, peer: peer}
				linuxStandardServiceOwners.Store(f.a, prior)
				held = &prior.mu
			} else {
				held = &f.a.mu
			}
			if mode == "post-reply" {
				owner.registered = true
				f.a.cmd = owner.Command()
				linuxStandardServiceOwners.Store(f.a, owner)
			}
			ctx, cancel := context.WithTimeout(original, 100*time.Millisecond)
			defer cancel()
			f.a.connectionContext = ctx
			held.Lock()
			done := make(chan error, 1)
			go func() {
				if mode == "post-reply" {
					_, err := owner.finishStartContext(ctx, ctx)
					done <- err
					return
				}
				done <- owner.Start(ctx)
			}()
			// The held lock is released only after bounded completion is observed, or
			// after the diagnostic barrier proves the old unbounded admission remains.
			<-ctx.Done()
			var err error
			bounded := false
			select {
			case err = <-done:
				bounded = true
			case <-time.After(time.Second):
			}
			held.Unlock()
			if !bounded {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("held admission failed to join after explicit release")
				}
				t.Fatal("original Start admission waited for held lock after caller expired")
			}
			if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 0 {
				t.Fatal("held admission lost original deadline or sent new RPC", err, calls.Load())
			}
			if mode == "prior-owner" {
				actual, ok := linuxStandardServiceOwners.Load(f.a)
				if !ok || actual != prior || prior.peer != peer || owner.peer != nil || owner.registered || f.a.cmd != nil {
					t.Fatal("expired prior admission orphaned original peer or published replacement")
				}
			} else if mode == "application" && owner.registered {
				t.Fatal("expired application admission published replacement")
			}
		})
	}
}
