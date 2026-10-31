//go:build linux

package mobiletor

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestLinuxBaselineRetentionRequiresOriginalUnusedSource(t *testing.T) {
	capture := desktopSocketFixtureCapture()
	for _, source := range []*DesktopLinuxSocketPolicy{nil, {}, {capture: capture}} {
		for _, policy := range []string{"", "off", "always", "on-connect", "Always"} {
			if retained, err := source.RetainProtection(context.Background(), capture, policy); retained != nil || err == nil {
				t.Fatal("missing or retired native source created a protection capability", retained, err)
			}
		}
	}
	for _, context := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		if retained, err := (&DesktopLinuxSocketPolicy{capture: capture}).RetainProtection(context, capture, "always"); retained != nil || err == nil {
			t.Fatal("cancelled capture created a protection capability")
		}
	}
}

func TestLinuxBaselineRetentionPartialCloseOwnsOnlyOriginalDescriptors(t *testing.T) {
	open := func() *os.File {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		return file
	}
	first, second, replacement := open(), open(), open()
	defer replacement.Close()
	b := &desktopLinuxRetainedProtection{gate: make(chan struct{}, 1), namespace: first,
		netlink: &desktopLinuxBaselineNetlink{file: second}}
	b.gate <- struct{}{}
	if _, err := b.Prepared(context.Background()); err == nil {
		t.Fatal("incomplete source issued prepared proof")
	}
	if _, err := b.Retired(context.Background()); err == nil {
		t.Fatal("incomplete source issued retired proof")
	}
	if err := b.Release(context.Background()); err == nil {
		t.Fatal("incomplete source attempted table removal")
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{first, second} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("partial retention left an original descriptor open", err)
		}
	}
	if _, err := replacement.Stat(); err != nil {
		t.Fatal("partial retention closed an unrelated owner", err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxBaselineRetentionCancelledWaitCannotEnterAnotherOperation(t *testing.T) {
	b := &desktopLinuxRetainedProtection{gate: make(chan struct{}, 1), complete: true}
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	finished := make(chan error, 1)
	go func() { close(entered); finished <- b.Release(ctx) }()
	<-entered
	cancel()
	if err := <-finished; err == nil {
		t.Fatal("cancelled retention entered a native operation owned by another caller")
	}
	if b.removed || b.closed || b.uncertain != nil || len(b.gate) != 0 {
		t.Fatal("cancelled queued operation mutated the retained owner")
	}
	b.gate <- struct{}{}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
