package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

// Existing fixture constructors and slot succession execute unchanged; only
// the kernel protection backend is modeled. These are not native BFE tests.
func TestDesktopNodeCapturedReleaseKeepsCallerLockBounds(t *testing.T) {
	for _, fault := range []string{"nil", "cancelled", "app-lock", "slot-lock"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffPolicyFixture(t, "on-connect")
			reads, releases := f.kernel.reads, f.kernel.releases
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			want := error(context.DeadlineExceeded)
			unlock := func() {}
			switch fault {
			case "nil":
				ctx = nil
			case "cancelled":
				cancel()
				want = context.Canceled
			case "app-lock":
				f.a.mu.Lock()
				unlock = f.a.mu.Unlock
			case "slot-lock":
				f.slot.mu.Lock()
				unlock = f.slot.mu.Unlock
			}
			done := make(chan error, 1)
			go func() { done <- f.a.releaseCapturedDesktopNodeProtectionContext(ctx, f.slot) }()
			select {
			case err := <-done:
				unlock()
				if err == nil || fault != "nil" && !errors.Is(err, want) {
					t.Fatal("captured release lost original caller refusal", err)
				}
			case <-time.After(time.Second):
				unlock()
				<-done
				t.Fatal("captured release exceeded original lock deadline")
			}
			if f.a.nodeProtection != f.slot || f.kernel.reads != reads || f.kernel.releases != releases || !reflect.DeepEqual(f.kernel.target, &f.target) {
				t.Fatal("unadmitted release changed original protection")
			}
		})
	}
}

type desktopCapturedReleaseBoundary struct {
	original desktopNodeProtectionRelease
	wait     func(context.Context) error
}

func (b *desktopCapturedReleaseBoundary) Close(ctx context.Context) error {
	if err := b.wait(ctx); err != nil {
		return err
	}
	return b.original.Close(ctx)
}

func TestDesktopNodeCapturedReleaseForwardsOriginalBackendCaller(t *testing.T) {
	for _, phase := range []string{"release", "close", "absence-read"} {
		t.Run(phase, func(t *testing.T) {
			f := newDesktopProtectionOffPolicyFixture(t, "on-connect")
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			entered := make(chan context.Context, 1)
			escape := make(chan struct{})
			wait := func(call context.Context) error {
				entered <- call
				select {
				case <-call.Done():
					return call.Err()
				case <-escape:
					return errors.New("test released a caller-independent backend")
				}
			}
			read, release := f.slot.backend.read, f.slot.backend.release
			switch phase {
			case "release":
				f.slot.backend.release = func(call context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
					return nil, wait(call)
				}
			case "close":
				f.slot.backend.release = func(call context.Context, target mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
					owner, err := release(call, target)
					if err != nil {
						return owner, err
					}
					return &desktopCapturedReleaseBoundary{original: owner, wait: wait}, nil
				}
			case "absence-read":
				f.slot.backend.read = func(call context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
					if target == nil {
						return wait(call)
					}
					return read(call, target)
				}
			}
			done := make(chan error, 1)
			go func() { done <- f.a.releaseCapturedDesktopNodeProtectionContext(ctx, f.slot) }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("backend lost original caller deadline", err)
				}
			case <-time.After(time.Second):
				close(escape)
				<-done
				t.Fatal("backend release received a fresh cleanup budget")
			}
			select {
			case actual := <-entered:
				if actual != ctx {
					t.Fatal("backend did not receive the original caller")
				}
			default:
				t.Fatal("actual native boundary was not exercised")
			}
			if f.a.nodeProtection != f.slot || f.slot.target == nil || phase == "close" && f.slot.retirement == nil {
				t.Fatal("expired backend released its retryable original authority")
			}
		})
	}
}

func TestDesktopNodeCapturedReleaseRequiresExactAbsenceAndCurrentSlot(t *testing.T) {
	for _, fault := range []string{"replaced-before", "replaced-after-absence", "cancel-after-absence", "failed-absence"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopProtectionOffPolicyFixture(t, "on-connect")
			replacement := &desktopNodeProtectionSlot{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			read := f.slot.backend.read
			if fault == "replaced-before" {
				f.a.nodeProtection = replacement
			}
			f.slot.backend.read = func(call context.Context, target *mobiletor.DesktopWindowsProtectionTarget) error {
				if target != nil {
					return read(call, target)
				}
				if fault == "failed-absence" {
					return errors.New("independent absence read failed")
				}
				if err := read(call, target); err != nil {
					return err
				}
				if fault == "cancel-after-absence" {
					cancel()
				}
				if fault == "replaced-after-absence" {
					f.a.mu.Lock()
					f.a.nodeProtection = replacement
					f.a.mu.Unlock()
				}
				return nil
			}
			if err := f.a.releaseCapturedDesktopNodeProtectionContext(ctx, f.slot); err == nil {
				t.Fatal("captured release acknowledged missing absence or changed owner")
			}
			if fault == "replaced-before" || fault == "replaced-after-absence" {
				if f.a.nodeProtection != replacement || replacement.known || replacement.target != nil {
					t.Fatal("old release cleared or adopted replacement slot")
				}
				if fault == "replaced-before" && f.kernel.releases != 0 {
					t.Fatal("replaced slot entered native release")
				}
				return
			}
			if f.a.nodeProtection != f.slot || f.slot.retirement == nil || f.slot.target == nil {
				t.Fatal("failed proof lost exact original release owner")
			}
			owner := f.slot.retirement
			f.slot.backend.read = read
			if err := f.a.releaseCapturedDesktopNodeProtectionContext(context.Background(), f.slot); err != nil || f.a.nodeProtection != nil || f.kernel.releases != 1 || f.kernel.target != nil {
				t.Fatal("exact original proof retry did not complete retained release", err)
			}
			if owner == nil {
				t.Fatal("retry lacked an original release handle")
			}
		})
	}
}

func TestDesktopNodeCapturedReleasePreservesPolicyAndFailedOwner(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newDesktopProtectionOffPolicyFixture(t, policy)
			f.kernel.closeFail = true
			if err := f.a.releaseCapturedDesktopNodeProtectionContext(context.Background(), f.slot); err == nil {
				t.Fatal("failed exact release was acknowledged")
			}
			owner := f.slot.retirement
			if owner == nil || f.a.nodeProtection != f.slot || !reflect.DeepEqual(f.kernel.target, &f.target) {
				t.Fatal("failed release lost original target or cleanup owner")
			}
			f.kernel.closeFail = false
			if err := f.a.releaseCapturedDesktopNodeProtectionContext(context.Background(), f.slot); err != nil || f.kernel.releases != 1 {
				t.Fatal("retry reacquired a different native release", err)
			}
			if policy == "always" {
				if f.a.nodeProtection != f.slot || !reflect.DeepEqual(f.kernel.target, &f.target) || !reflect.DeepEqual(f.slot.target, &f.target) {
					t.Fatal("normal release removed retained Always protection")
				}
			} else if f.a.nodeProtection != nil || f.kernel.target != nil || !f.slot.provedEmpty() {
				t.Fatal("On-connect release failed to prove exact absence")
			}
		})
	}
}

func TestDesktopNodeCapturedReleasePendingOffKeepsOriginalCaller(t *testing.T) {
	f := newDesktopProtectionOffFixture(t)
	capture := f.capture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	var actual context.Context
	escape := make(chan struct{})
	f.beforeClose = func(call context.Context) error {
		actual = call
		select {
		case <-call.Done():
			return call.Err()
		case <-escape:
			return errors.New("test released caller-independent pending Off")
		}
	}
	done := make(chan error, 1)
	go func() { done <- f.a.releaseCapturedDesktopNodeProtectionContext(ctx, f.slot) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("pending Off lost its original caller", err)
		}
	case <-time.After(time.Second):
		close(escape)
		<-done
		t.Fatal("pending Off received a fresh cleanup budget")
	}
	if actual != ctx || f.slot.pendingOff() != capture || f.a.nodeProtection != f.slot || len(f.owners) != 1 || f.owners[0].closed {
		t.Fatal("pending Off substituted or discarded its retained cleanup owner")
	}
	f.beforeClose = nil
	if err := f.a.releaseCapturedDesktopNodeProtectionContext(context.Background(), f.slot); err != nil || f.a.nodeProtection != nil || f.kernel.target != nil || f.calls != 1 || !f.owners[0].closed || f.a.profiles.Profiles[0].KillSwitchPolicy != "off" {
		t.Fatal("pending Off retry lost original native/save transaction", err)
	}
}
