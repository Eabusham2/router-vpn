//go:build windows

package mobiletor

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWindowsPolicyAdmissionPreservesOriginalCancellation(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "healthy-owner"
		if retired {
			name = "confirmed-owner-loss"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			p := &DesktopWindowsSocketPolicy{ctx: context.Background(), gate: make(chan struct{}, 1)}
			p.retired.Store(retired)
			p.gate <- struct{}{}
			called := false
			_, err := desktopWindowsPolicyCall(p, ctx, false, func() (struct{}, error) { called = true; return struct{}{}, nil })
			if !errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) != retired || called || len(p.gate) != 1 {
				t.Fatal("expired original caller changed admission or owner-loss evidence", err, called)
			}
		})
	}
}

type windowsPolicyGateContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *windowsPolicyGateContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestWindowsPolicyAdmissionRechecksOriginalOwnerAfterGate(t *testing.T) {
	for _, cleanup := range []bool{false, true} {
		name := "work"
		if cleanup {
			name = "owned-cleanup"
		}
		t.Run(name, func(t *testing.T) {
			p := &DesktopWindowsSocketPolicy{ctx: context.Background(), gate: make(chan struct{}, 1)}
			ctx := &windowsPolicyGateContext{Context: t.Context(), entered: make(chan struct{})}
			called := make(chan struct{}, 1)
			done := make(chan error, 1)
			go func() {
				_, err := desktopWindowsPolicyCall(p, ctx, cleanup, func() (struct{}, error) { called <- struct{}{}; return struct{}{}, nil })
				done <- err
			}()
			select {
			case <-ctx.entered:
			case <-time.After(time.Second):
				t.Fatal("original policy did not wait for its gate")
			}
			p.retired.Store(true)
			p.gate <- struct{}{}
			select {
			case err := <-done:
				if cleanup {
					if err != nil || len(called) != 1 {
						t.Fatal("original retired policy lost its owned cleanup", err)
					}
				} else if !errors.Is(err, net.ErrClosed) || len(called) != 0 {
					t.Fatal("retired owner admitted new native work after gate wait", err)
				}
			case <-time.After(time.Second):
				t.Fatal("original policy did not finish gate admission")
			}
			select {
			case <-p.gate:
			case <-time.After(time.Second):
				t.Fatal("rejected or joined operation lost the original gate")
			}
		})
	}
}

func identityCurrentFixture(t *testing.T) (*DesktopWindowsSocketIdentity, DesktopSocketKernelOwner) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	p := &DesktopWindowsSocketIdentity{ctx: ctx, cancel: cancel, capture: DesktopSocketCapture{SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64), NetworkID: strings.Repeat("c", 32)}}
	owner := DesktopSocketKernelOwner{Kind: "windows-isolated-token", IdentitySHA256: strings.Repeat("d", 64), Generation: 7, ProcessID: 99}
	p.owner.Store(&owner)
	p.current.Store(true)
	p.observed.Store(time.Now().UnixMilli())
	return p, owner
}

func TestWindowsIdentityCurrentDoesNotWaitForPublicationMutex(t *testing.T) {
	p, original := identityCurrentFixture(t)
	p.mu.Lock()
	result := make(chan error, 1)
	go func() {
		if !p.Current(p.capture, original) {
			result <- errors.New("original current identity lost")
			return
		}
		copy, err := p.Owner()
		if err == nil && copy != original {
			err = errors.New("original published owner changed")
		}
		copy.Generation++
		result <- err
	}()
	select {
	case err := <-result:
		p.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		p.mu.Unlock()
		<-result
		t.Fatal("native identity observation waited for publication mutex")
	}
	if owner, err := p.Owner(); err != nil || owner != original {
		t.Fatal("observation mutated original owner", err)
	}
}

func TestWindowsIdentityCurrentKeepsExactOriginalState(t *testing.T) {
	for _, defect := range []string{"capture", "owner", "unpublished", "retired", "closing", "cancelled", "unobserved", "stale", "future"} {
		t.Run(defect, func(t *testing.T) {
			p, owner := identityCurrentFixture(t)
			capture := p.capture
			switch defect {
			case "capture":
				capture.NetworkID = strings.Repeat("e", 32)
			case "owner":
				owner.Generation++
			case "unpublished":
				p.owner.Store(nil)
			case "retired":
				p.current.Store(false)
			case "closing":
				p.closing.Store(true)
			case "cancelled":
				p.cancel()
			case "unobserved":
				p.observed.Store(0)
			case "stale":
				p.observed.Store(time.Now().Add(-DesktopSocketReadbackAge - time.Second).UnixMilli())
			case "future":
				p.observed.Store(time.Now().Add(time.Minute).UnixMilli())
			}
			if p.Current(capture, owner) {
				t.Fatal("changed native identity accepted", defect)
			}
			if defect != "capture" && defect != "owner" {
				if _, err := p.Owner(); !errors.Is(err, net.ErrClosed) {
					t.Fatal("unavailable owner published", defect, err)
				}
			}
		})
	}
}
