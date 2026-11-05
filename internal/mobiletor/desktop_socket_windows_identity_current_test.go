//go:build windows

package mobiletor

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

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
