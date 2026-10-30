package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/mobiletor"
)

// Native preparation can enter its own exclusive lock before returning an
// error. Closing that unarmed owner joins the entered work and releases only
// its lock; it cannot remove or adopt the baseline that happened to survive.
type desktopNodeProtectionUnarmedFixture struct {
	kernel  *desktopNodeProtectionFixture
	joinErr error
	closes  int
	closed  bool
}

func (p *desktopNodeProtectionUnarmedFixture) Close(ctx context.Context) error {
	p.closes++
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.joinErr != nil {
		return p.joinErr
	}
	if !p.closed {
		p.kernel.locked = false
		p.closed = true
	}
	return nil
}

type desktopNodeProtectionRetryFixture struct {
	kernel         *desktopNodeProtectionFixture
	slot           *desktopNodeProtectionSlot
	target         mobiletor.DesktopWindowsProtectionTarget
	partial        *desktopNodeProtectionUnarmedFixture
	prepareErr     error
	originalProofs int
}

func newDesktopNodeProtectionRetryFixture(t *testing.T, policyName string) *desktopNodeProtectionRetryFixture {
	t.Helper()
	policy := desktopNodeProtectionPolicy(t, "1", policyName, 0)
	target := desktopNodeProtectionInstalled(policy)
	f := &desktopNodeProtectionRetryFixture{
		target: target, prepareErr: errors.New("fixture native release preparation did not arm"),
		kernel: &desktopNodeProtectionFixture{target: copyDesktopNodeProtectionTarget(&target)},
	}
	f.partial = &desktopNodeProtectionUnarmedFixture{kernel: f.kernel}
	backend := f.kernel.backend()
	read, release := backend.read, backend.release
	backend.read = func(ctx context.Context, expected *mobiletor.DesktopWindowsProtectionTarget) error {
		err := read(ctx, expected)
		if err == nil && ctx.Err() == nil && expected != nil && *expected == f.target {
			f.originalProofs++
		}
		return err
	}
	backend.release = func(ctx context.Context, expected mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
		if f.kernel.releases == 0 {
			f.kernel.releases++
			f.kernel.locked = true
			return f.partial, f.prepareErr
		}
		if !f.partial.closed || f.originalProofs == 0 {
			t.Fatal("fresh release preceded joined unchanged-target proof")
		}
		return release(ctx, expected)
	}
	f.slot = &desktopNodeProtectionSlot{backend: backend, known: true, target: copyDesktopNodeProtectionTarget(&target)}
	return f
}

func (f *desktopNodeProtectionRetryFixture) failPreparation(t *testing.T) {
	t.Helper()
	if err := f.slot.release(context.Background()); !errors.Is(err, f.prepareErr) || f.slot.retirement != f.partial ||
		f.kernel.releases != 1 || f.partial.closed || !f.kernel.locked || !reflect.DeepEqual(f.slot.target, &f.target) {
		t.Fatal("failed native preparation lost its original partial owner or target", err)
	}
}

func TestDesktopNodeProtectionReleaseRetriesUnarmedPreparation(t *testing.T) {
	for _, policyName := range []string{"on-connect", "always"} {
		t.Run(policyName, func(t *testing.T) {
			f := newDesktopNodeProtectionRetryFixture(t, policyName)
			f.failPreparation(t)
			f.partial.joinErr = errors.New("fixture native preparation is still entered")
			if err := f.slot.release(context.Background()); err == nil || f.slot.retirement != f.partial ||
				f.kernel.releases != 1 || f.partial.closes != 1 || f.partial.closed || !f.kernel.locked {
				t.Fatal("failed partial join replaced or forgot its exact release owner", err)
			}
			f.partial.joinErr = nil
			f.kernel.readFail = true
			if err := f.slot.release(context.Background()); err == nil || f.slot.retirement != f.partial ||
				f.kernel.releases != 1 || !f.partial.closed || f.originalProofs != 0 {
				t.Fatal("failed unchanged-target proof discarded or rearmed the partial owner", err)
			}
			f.kernel.readFail = false
			if err := f.slot.release(context.Background()); err != nil || f.slot.retirement != nil || f.kernel.releases != 2 || f.originalProofs == 0 {
				t.Fatal("joined unchanged partial release did not prepare and finish one exact retry", err)
			}
			if (f.slot.target != nil) != (policyName == "always") || !reflect.DeepEqual(f.slot.target, f.kernel.target) {
				t.Fatal("retried normal release changed Always or invented absence")
			}
		})
	}
}

func TestDesktopNodeProtectionReleaseUnarmedRejectsChangedTarget(t *testing.T) {
	for _, fault := range []string{"absent", "session", "source", "network", "policy", "digest"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeProtectionRetryFixture(t, "on-connect")
			f.failPreparation(t)
			replacement := f.target
			switch fault {
			case "absent":
				f.kernel.target = nil
			case "session":
				replacement.Capture.SessionID = strings.Repeat("2", 32)
			case "source":
				replacement.Capture.SourceSHA256 = strings.Repeat("2", 64)
			case "network":
				replacement.Capture.NetworkID = strings.Repeat("2", 32)
			case "policy":
				replacement.Policy = "always"
			case "digest":
				replacement.BaselineSHA256 = strings.Repeat("2", 64)
			}
			if fault != "absent" {
				f.kernel.target = &replacement
			}
			before := copyDesktopNodeProtectionTarget(f.kernel.target)
			if err := f.slot.release(context.Background()); err == nil || f.slot.retirement != f.partial || f.kernel.releases != 1 ||
				!f.partial.closed || f.originalProofs != 0 || !reflect.DeepEqual(f.kernel.target, before) || !reflect.DeepEqual(f.slot.target, &f.target) {
				t.Fatal("partial release adopted missing or replaced protection", fault, err)
			}
			// A later exact observation may unblock the same pending cleanup;
			// failed readback itself never changes the captured expectation.
			f.kernel.target = copyDesktopNodeProtectionTarget(&f.target)
			if err := f.slot.release(context.Background()); err != nil || f.kernel.releases != 2 || f.slot.target != nil {
				t.Fatal("restored exact target could not finish its retained retry", err)
			}
		})
	}
}

func TestDesktopNodeProtectionReleaseSuccessfulConstructorStaysArmedAfterCancellation(t *testing.T) {
	policy := desktopNodeProtectionPolicy(t, "1", "on-connect", 0)
	target := desktopNodeProtectionInstalled(policy)
	kernel := &desktopNodeProtectionFixture{target: copyDesktopNodeProtectionTarget(&target)}
	backend := kernel.backend()
	release := backend.release
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend.release = func(ctx context.Context, expected mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
		owner, err := release(ctx, expected)
		cancel() // The actual constructor already returned an armed owner.
		return owner, err
	}
	slot := &desktopNodeProtectionSlot{backend: backend, known: true, target: copyDesktopNodeProtectionTarget(&target)}
	if err := slot.release(ctx); !errors.Is(err, context.Canceled) || slot.retirement == nil || kernel.releases != 1 || kernel.closes != 0 {
		t.Fatal("late cancellation discarded the successful native constructor", err)
	}
	if err := slot.release(context.Background()); err != nil || slot.retirement != nil || slot.target != nil || kernel.target != nil || kernel.releases != 1 || kernel.closes != 1 {
		t.Fatal("late cancellation misclassified an armed owner as unprepared", err)
	}
}

func TestDesktopNodeProtectionReleaseUnarmedCancelledReadRetainsOwner(t *testing.T) {
	f := newDesktopNodeProtectionRetryFixture(t, "on-connect")
	f.failPreparation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	read := f.slot.backend.read
	f.slot.backend.read = func(ctx context.Context, expected *mobiletor.DesktopWindowsProtectionTarget) error {
		err := read(ctx, expected)
		cancel()
		return err
	}
	if err := f.slot.release(ctx); !errors.Is(err, context.Canceled) || f.slot.retirement != f.partial || f.kernel.releases != 1 || !f.partial.closed {
		t.Fatal("cancelled unchanged-target read forgot or rearmed the partial owner", err)
	}
	f.slot.backend.read = read
	if err := f.slot.release(context.Background()); err != nil || f.kernel.releases != 2 || f.slot.target != nil {
		t.Fatal("same partial owner could not retry its cancelled read", err)
	}
}

func TestDesktopNodeProtectionReleaseFailedRearmRetainsNewPartialOwner(t *testing.T) {
	f := newDesktopNodeProtectionRetryFixture(t, "on-connect")
	f.failPreparation(t)
	second := &desktopNodeProtectionUnarmedFixture{kernel: f.kernel}
	normal := f.kernel.backend().release
	secondErr := errors.New("fixture second native preparation did not arm")
	f.slot.backend.release = func(ctx context.Context, expected mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error) {
		if f.kernel.releases == 1 {
			if !f.partial.closed || f.originalProofs == 0 {
				t.Fatal("second constructor started before prior partial cleanup proof")
			}
			f.kernel.releases++
			f.kernel.locked = true
			return second, secondErr
		}
		if !second.closed || f.originalProofs < 2 {
			t.Fatal("third constructor started before second partial cleanup proof")
		}
		return normal(ctx, expected)
	}
	if err := f.slot.release(context.Background()); !errors.Is(err, secondErr) || f.slot.retirement != second || f.kernel.releases != 2 || second.closed {
		t.Fatal("failed fresh constructor lost its new partial owner or retried in a loop", err)
	}
	second.joinErr = errors.New("fixture second preparation is still entered")
	if err := f.slot.release(context.Background()); err == nil || f.slot.retirement != second || f.kernel.releases != 2 || second.closed {
		t.Fatal("failed second partial join revived the first release owner", err)
	}
	second.joinErr = nil
	if err := f.slot.release(context.Background()); err != nil || f.slot.retirement != nil || f.slot.target != nil || f.kernel.releases != 3 || !second.closed {
		t.Fatal("second exact partial owner could not finish its own retry", err)
	}
}
